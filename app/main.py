
import threading
import time
from datetime import datetime
from typing import Literal, NoReturn

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, ValidationError

from app.agent.identity_agent import IdentityNotFoundError, run_investigation
from app.audit.audit_logger import (
    has_executed_removal,
    has_simulated_removal,
    log_investigation_event,
    log_remediation_event,
    log_verification_event,
    read_audit_events,
)
from app.authentication import get_current_user
from app.config import (
    ACCESS_TEST_BLOB,
    ACCESS_TEST_CONTAINER,
    ACTIVE_DEVELOPER_OBJECT_ID,
    REMEDIATION_DELETE_ENABLED,
)
from app.connectors.entra_client import search_identity
from app.connectors.rbac_client import get_role_assignments
from app.connectors.resource_client import (
    get_project_assignment,
    get_project_resources,
)
from app.models.approval import RemediationApproval
from app.models.finding import IdentityFinding
from app.remediation.access_test import (
    access_test_result,
    get_access_test_credential,
    run_controlled_access_test,
)
from app.remediation.approval_service import (
    ApprovalNotFoundError,
    create_approval,
    get_approval,
    list_approvals_for_owner,
    mark_approval_executed,
    update_approval_status,
)
from app.remediation.executor import remove_role_assignment
from app.remediation.remediation_identity import (
    confirm_target_with_remediation_identity,
    delete_role_assignment_with_remediation_identity,
)
from app.remediation.verification import (
    check_legitimate_access,
    verify_remediation,
)


_remediation_lock = threading.Lock()

# After a real deletion Azure can take a few seconds to stop listing the
# assignment, so verification re-reads it briefly before reporting.
_VERIFY_RETRIES = 5
_VERIFY_RETRY_SECONDS = 2


class InvestigationRequest(BaseModel):
    identity_id: str = Field(min_length=1)
    request: str = Field(
        default="Investigate this identity.",
        min_length=1,
    )


class ApprovalCreateRequest(BaseModel):
    approval_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    role_assignment_id: str = Field(min_length=1)
    identity_id: str = Field(min_length=1)
    resource_scope: str = Field(min_length=1)
    expires_at: datetime


class ApprovalDecisionRequest(BaseModel):
    status: Literal["APPROVED", "REJECTED", "INVESTIGATION_REQUESTED"]


class RemediationRequest(BaseModel):
    approval_id: str = Field(min_length=1)


def _normalize(value: object) -> str:
    return str(value or "").rstrip("/").casefold()


def _assignment_view(assignments: list[dict]) -> list[dict]:
    """Assignment fields shown in the before-and-after permission view."""
    return [
        {
            "id": item.get("id"),
            "principal_id": item.get("principal_id"),
            "role_definition_id": item.get("role_definition_id"),
            "scope": item.get("scope"),
            "assignment_source": item.get("assignment_source"),
        }
        for item in assignments
    ]


def _active_developer_assignments() -> list[dict] | None:
    """Direct role assignments the active developer holds on active projects."""

    if not ACTIVE_DEVELOPER_OBJECT_ID:
        return None

    try:
        assignments: list[dict] = []

        for project in get_project_assignment(ACTIVE_DEVELOPER_OBJECT_ID):
            if _normalize(project.get("status")) != "active":
                continue

            for resource in get_project_resources(project["project_id"]):
                assignments.extend(
                    get_role_assignments(
                        identity_id=ACTIVE_DEVELOPER_OBJECT_ID,
                        scope=resource["resource_id"],
                    )
                )

        return assignments

    except Exception:
        return None


app = FastAPI()


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/investigate", response_model=IdentityFinding)
def investigate_identity(
    payload: InvestigationRequest,
    current_user: dict = Depends(get_current_user),
):
    audit_context = {
        "action": "IDENTITY_INVESTIGATION",
        "identity_id": payload.identity_id,
        "requested_by": current_user.get("user_id"),
    }

    def fail(status_code: int, detail: str, exc: Exception) -> NoReturn:
        log_investigation_event({
            **audit_context,
            "status": "FAILED",
            "reason": detail,
        })
        raise HTTPException(status_code=status_code, detail=detail) from exc

    try:
        result = run_investigation(
            identity_id=payload.identity_id,
            request=payload.request,
        )
        finding = IdentityFinding.model_validate(result)

    except IdentityNotFoundError as exc:
        fail(404, str(exc), exc)

    except ValidationError as exc:
        fail(502, "Investigation returned an invalid response.", exc)

    except ValueError as exc:
        fail(400, str(exc), exc)

    except RuntimeError as exc:
        fail(502, "The AI investigation did not complete.", exc)

    except Exception as exc:
        fail(500, "Investigation failed.", exc)

    log_investigation_event({
        **audit_context,
        "status": "COMPLETED",
        "identity_name": finding.identity,
        "identity_profile": finding.evidence.get("identity"),
        "findings": [item.model_dump(mode="json") for item in finding.findings],
        "investigation_summary": finding.investigation_summary,
        "evidence_records": finding.evidence.get("evidence_records", []),
        "collection_errors": len(finding.collection_errors),
    })

    return finding


@app.get("/investigations/latest")
def latest_investigations(current_user: dict = Depends(get_current_user)):
    """
    The most recent completed investigation for each identity. A newer
    completed investigation replaces the earlier one in this view; the audit
    log itself stays append-only.
    """
    latest: dict[str, dict] = {}

    for event in read_audit_events():
        if (
            event.get("event_type") == "INVESTIGATION"
            and event.get("status") == "COMPLETED"
        ):
            latest[event.get("identity_id")] = event

    return list(latest.values())


@app.get("/audit/events")
def audit_events(current_user: dict = Depends(get_current_user)):
    """All audit events in the order they were recorded, read from the backend."""
    return read_audit_events()


@app.post("/approvals", response_model=RemediationApproval)
def create_approval_request(
    payload: ApprovalCreateRequest,
    current_user: dict = Depends(get_current_user),
):
    try:
        return create_approval(
            approval_id=payload.approval_id,
            incident_id=payload.incident_id,
            project_id=payload.project_id,
            role_assignment_id=payload.role_assignment_id,
            identity_id=payload.identity_id,
            resource_scope=payload.resource_scope,
            expires_at=payload.expires_at,
            requested_by=current_user.get("user_id"),
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Approval creation failed.",
        ) from exc


@app.get("/approvals", response_model=list[RemediationApproval])
def list_owned_approvals(current_user: dict = Depends(get_current_user)):
    """Approvals whose registered resource owner is the signed-in user."""
    return list_approvals_for_owner(current_user.get("user_id"))


@app.get("/identities/search")
def search_identities(
    q: str = Query(min_length=1),
    current_user: dict = Depends(get_current_user),
):
    """Read-only lookup of Entra users and service principals."""
    try:
        return search_identity(q)

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Identity search failed.",
        ) from exc


@app.get("/approvals/{approval_id}", response_model=RemediationApproval)
def read_approval(
    approval_id: str,
    current_user: dict = Depends(get_current_user),
):
    try:
        return get_approval(
            approval_id,
            current_user.get("user_id"),
        )

    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post(
    "/approvals/{approval_id}/decision",
    response_model=RemediationApproval,
)
def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    current_user: dict = Depends(get_current_user),
):
    try:
        return update_approval_status(
            approval_id=approval_id,
            status=payload.status,
            acting_approver_object_id=current_user.get("user_id"),
        )

    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/remediate")
def remediate(
    payload: RemediationRequest,
    current_user: dict = Depends(get_current_user),
):
    acting_user_id = current_user.get("user_id")

    def reject(status_code: int, reason: str) -> NoReturn:
        log_remediation_event({
            "action": "ROLE_ASSIGNMENT_REMOVAL",
            "approval_id": payload.approval_id,
            "acting_user_id": acting_user_id,
            "status": "REJECTED",
            "reason": reason,
        })
        raise HTTPException(status_code=status_code, detail=reason)

    try:
        approval = get_approval(payload.approval_id, acting_user_id)
    except ApprovalNotFoundError as exc:
        reject(404, str(exc))
    except PermissionError as exc:
        reject(403, str(exc))

    if approval.status != "APPROVED":
        reject(400, "Approval has not been granted.")

    assignment_id = approval.role_assignment_id
    identity_id = approval.identity_id
    scope = approval.resource_scope

    try:
        with _remediation_lock:
            investigation = IdentityFinding.model_validate(
                run_investigation(
                    identity_id=identity_id,
                    request="Reassess access eligibility before remediation.",
                )
            )

            finding = next(
                (
                    item for item in investigation.findings
                    if _normalize(item.project_id) == _normalize(approval.project_id)
                    and _normalize(item.role_assignment_id)
                    == _normalize(assignment_id)
                    and _normalize(item.resource_scope) == _normalize(scope)
                    and item.finding_type == "STALE_PRODUCTION_ACCESS"
                    and _normalize(item.project_status) == "completed"
                ),
                None,
            )

            if finding is None or not finding.approval_eligible:
                reject(
                    400,
                    "No currently eligible finding exists for this approval.",
                )

            role_assignment = next(
                (
                    item for item in get_role_assignments(
                        identity_id=identity_id,
                        scope=scope,
                    )
                    if _normalize(item.get("id")) == _normalize(assignment_id)
                    and _normalize(item.get("principal_id"))
                    == _normalize(identity_id)
                    and item.get("assignment_source") == "DIRECT"
                    and _normalize(item.get("scope")) == _normalize(scope)
                ),
                None,
            )

            if role_assignment is None:
                reject(400, "The approved direct role assignment was not found.")

            legitimate_before = _active_developer_assignments()
            assignments_before = get_role_assignments(
                identity_id=identity_id,
                scope=scope,
            )

            # The remediation identity confirms the target. It deletes only
            # when REMEDIATION_DELETE_ENABLED is on; otherwise the run is
            # simulated and nothing is deleted.
            delete_enabled = REMEDIATION_DELETE_ENABLED

            execution_result = remove_role_assignment(
                approval=approval.model_dump(mode="python"),
                role_assignment=role_assignment,
                approver_authorized=(
                    _normalize(acting_user_id) == _normalize(approval.approver)
                ),
                evidence_complete=finding.approval_eligible,
                project_status=finding.project_status or "",
                assignment_type=role_assignment["assignment_source"],
                already_executed=(
                    has_executed_removal(assignment_id)
                    if delete_enabled
                    else has_simulated_removal(assignment_id)
                ),
                audit_log=log_remediation_event,
                confirm_target=confirm_target_with_remediation_identity,
                delete_target=(
                    delete_role_assignment_with_remediation_identity
                    if delete_enabled
                    else None
                ),
            )

        if execution_result["status"] == "FAILED":
            raise HTTPException(status_code=503, detail=execution_result)

        if execution_result["status"] not in ("SIMULATED", "EXECUTED"):
            raise HTTPException(status_code=400, detail=execution_result)

        executed = execution_result["status"] == "EXECUTED"

        if executed:
            mark_approval_executed(approval.approval_id)

        current_assignments = get_role_assignments(
            identity_id=identity_id,
            scope=scope,
        )

        if executed:
            for _ in range(_VERIFY_RETRIES):
                if not any(
                    _normalize(item.get("id")) == _normalize(assignment_id)
                    for item in current_assignments
                ):
                    break

                time.sleep(_VERIFY_RETRY_SECONDS)
                current_assignments = get_role_assignments(
                    identity_id=identity_id,
                    scope=scope,
                )

        target_role = role_assignment.get("role_definition_id")

        other_access_paths = [
            item for item in current_assignments
            if _normalize(item.get("id")) != _normalize(assignment_id)
            and _normalize(item.get("role_definition_id"))
            == _normalize(target_role)
        ]

        access_test = run_controlled_access_test(
            resource_scope=scope,
            container=ACCESS_TEST_CONTAINER,
            blob_name=ACCESS_TEST_BLOB,
            credential=get_access_test_credential(identity_id),
        )

        legitimate_access = check_legitimate_access(
            legitimate_before,
            _active_developer_assignments(),
        )

        verification = verify_remediation(
            target_assignment_id=assignment_id,
            current_role_assignments=current_assignments,
            other_access_paths=other_access_paths,
            access_test_result=access_test_result(access_test),
            simulated=not executed,
        )

        role_assignments_before = _assignment_view(assignments_before)
        role_assignments_after = _assignment_view(current_assignments)

        mode = "EXECUTION" if executed else "SIMULATION"

        verification.update({
            "mode": mode,
            "verified_scope": (
                "Direct role assignments at the approved resource scope. "
                "Group-inherited access is not evaluated."
            ),
            "other_access_paths": [item.get("id") for item in other_access_paths],
            "controlled_access_test": access_test,
            "legitimate_access": legitimate_access,
            "role_assignments_before": role_assignments_before,
            "role_assignments_after": role_assignments_after,
        })

        log_verification_event({
            "action": "REMEDIATION_VERIFICATION",
            "approval_id": approval.approval_id,
            "role_assignment_id": assignment_id,
            "identity_id": identity_id,
            "resource_scope": scope,
            "status": verification["status"],
            "message": verification["message"],
            "controlled_access_test": access_test["status"],
            "legitimate_access": legitimate_access["status"],
            "role_assignments_before": role_assignments_before,
            "role_assignments_after": role_assignments_after,
            "mode": mode,
        })

        return {
            "execution": execution_result,
            "verification": verification,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        reject(400, str(exc))

    except Exception as exc:
        log_remediation_event({
            "action": "ROLE_ASSIGNMENT_REMOVAL",
            "approval_id": payload.approval_id,
            "acting_user_id": acting_user_id,
            "status": "FAILED",
            "reason": "Remediation failed.",
        })
        raise HTTPException(
            status_code=500,
            detail="Remediation failed.",
        ) from exc
