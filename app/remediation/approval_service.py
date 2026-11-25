
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

from app.agent.identity_agent import run_investigation
from app.audit.audit_logger import log_approval_event
from app.connectors.rbac_client import get_role_assignments
from app.connectors.resource_client import get_resource_owner_record
from app.models.approval import RemediationApproval

PROJECT_ROOT = Path(__file__).resolve().parents[2]
APPROVALS_PATH = PROJECT_ROOT / "data" / "remediation_approvals.json"

DECISION_STATUSES = {"APPROVED", "REJECTED", "INVESTIGATION_REQUESTED"}

_approvals_lock = threading.Lock()


class ApprovalNotFoundError(ValueError):
    """The requested approval record does not exist."""


def _normalize(value: object) -> str:
    return str(value or "").rstrip("/").casefold()


def _load_approvals() -> list[RemediationApproval]:
    if not APPROVALS_PATH.exists():
        return []

    data = json.loads(APPROVALS_PATH.read_text(encoding="utf-8"))
    return [RemediationApproval.model_validate(item) for item in data]


def _save_approvals(approvals: list[RemediationApproval]) -> None:
    APPROVALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = [item.model_dump(mode="json") for item in approvals]

    APPROVALS_PATH.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def _resolve_resource_owner(project_id: str, resource_scope: str) -> dict:
    record = get_resource_owner_record(resource_scope, project_id)

    if not record or not record.get("owner_object_id"):
        raise ValueError(
            "No resource owner is registered for this project and resource."
        )

    return record


def _validate_approver(
    approval: RemediationApproval,
    acting_approver_object_id: str | None,
) -> None:
    if (
        not acting_approver_object_id
        or _normalize(acting_approver_object_id) != _normalize(approval.approver)
    ):
        raise PermissionError(
            "Only the registered resource owner can act on this approval."
        )


def _find_approval(
    approvals: list[RemediationApproval],
    approval_id: str,
) -> RemediationApproval:
    approval = next(
        (item for item in approvals if item.approval_id == approval_id),
        None,
    )

    if approval is None:
        raise ApprovalNotFoundError("Approval record not found.")

    return approval


def _validate_role_assignment(
    identity_id: str,
    role_assignment_id: str,
    resource_scope: str,
) -> None:
    assignments = get_role_assignments(
        identity_id=identity_id,
        scope=resource_scope,
    )

    matching_assignment = next(
        (
            item for item in assignments
            if _normalize(item.get("id")) == _normalize(role_assignment_id)
            and _normalize(item.get("principal_id")) == _normalize(identity_id)
            and item.get("assignment_source") == "DIRECT"
            and _normalize(item.get("scope")) == _normalize(resource_scope)
        ),
        None,
    )

    if matching_assignment is None:
        raise ValueError(
            "The specified direct role assignment was not found "
            "for this identity and resource scope."
        )


def _validate_eligible_finding(
    identity_id: str,
    project_id: str,
    role_assignment_id: str,
    resource_scope: str,
) -> None:
    result = run_investigation(
        identity_id=identity_id,
        request="Reassess access eligibility for approval.",
    )

    if not isinstance(result, dict):
        raise ValueError("Investigation result is invalid.")

    findings = result.get("findings", [])
    evidence = result.get("evidence", {})
    projects = evidence.get("projects", [])

    eligible_finding = any(
        isinstance(finding, dict)
        and _normalize(finding.get("project_id", project_id))
        == _normalize(project_id)
        and _normalize(finding.get("role_assignment_id"))
        == _normalize(role_assignment_id)
        and _normalize(finding.get("resource_scope"))
        == _normalize(resource_scope)
        and finding.get("finding_type") == "STALE_PRODUCTION_ACCESS"
        and finding.get("approval_required") is True
        and finding.get("approval_status") == "PENDING_APPROVAL"
        and _normalize(finding.get("project_status")) == "completed"
        for finding in findings
    )

    matching_project_resource = False

    for project_evidence in projects:
        project = project_evidence.get("project", {})

        if project.get("project_id") != project_id:
            continue

        if _normalize(project.get("status")) != "completed":
            continue

        for resource in project_evidence.get("resources", []):
            resource_record = resource.get("resource_record", {})

            if _normalize(resource_record.get("resource_id")) != _normalize(
                resource_scope
            ):
                continue

            for item in resource.get("role_assignments", []):
                assignment = item.get("assignment", {})

                if (
                    _normalize(assignment.get("id"))
                    == _normalize(role_assignment_id)
                    and _normalize(assignment.get("principal_id"))
                    == _normalize(identity_id)
                ):
                    matching_project_resource = True

    if not eligible_finding or not matching_project_resource:
        raise ValueError(
            "No eligible finding exists for this identity, project, "
            "resource scope, and role assignment."
        )


def get_approval(
    approval_id: str,
    acting_approver_object_id: str | None,
) -> RemediationApproval:
    approval = _find_approval(_load_approvals(), approval_id)
    _validate_approver(approval, acting_approver_object_id)

    return approval


def list_approvals_for_owner(
    acting_approver_object_id: str | None,
) -> list[RemediationApproval]:
    """Only approvals registered to this resource owner are returned."""

    if not acting_approver_object_id:
        return []

    return [
        item for item in _load_approvals()
        if _normalize(item.approver) == _normalize(acting_approver_object_id)
    ]


def create_approval(
    approval_id: str,
    incident_id: str,
    project_id: str,
    role_assignment_id: str,
    identity_id: str,
    resource_scope: str,
    expires_at: datetime,
    requested_by: str | None = None,
) -> RemediationApproval:

    audit_context = {
        "approval_id": approval_id,
        "incident_id": incident_id,
        "project_id": project_id,
        "identity_id": identity_id,
        "role_assignment_id": role_assignment_id,
        "resource_scope": resource_scope,
        "requested_by": requested_by,
    }

    try:
        if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
            raise ValueError(
                "Approval expiry must be a future timezone-aware datetime."
            )

        owner = _resolve_resource_owner(project_id, resource_scope)

        with _approvals_lock:
            if any(
                item.approval_id == approval_id
                for item in _load_approvals()
            ):
                raise ValueError("Approval ID already exists.")

        _validate_role_assignment(
            identity_id,
            role_assignment_id,
            resource_scope,
        )

        _validate_eligible_finding(
            identity_id,
            project_id,
            role_assignment_id,
            resource_scope,
        )

        approval = RemediationApproval(
            approval_id=approval_id,
            incident_id=incident_id,
            project_id=project_id,
            role_assignment_id=role_assignment_id,
            identity_id=identity_id,
            resource_scope=resource_scope,
            approver=owner["owner_object_id"],
            approver_name=owner.get("owner"),
            status="PENDING",
            created_at=datetime.now(UTC),
            expires_at=expires_at,
        )

        with _approvals_lock:
            approvals = _load_approvals()

            if any(item.approval_id == approval_id for item in approvals):
                raise ValueError("Approval ID already exists.")

            approvals.append(approval)
            _save_approvals(approvals)

    except ValueError as exc:
        log_approval_event({
            **audit_context,
            "action": "APPROVAL_CREATION_REJECTED",
            "status": "REJECTED",
            "reason": str(exc),
        })
        raise

    log_approval_event({
        **audit_context,
        "action": "APPROVAL_CREATED",
        "approver": approval.approver,
        "approver_name": approval.approver_name,
        "status": "PENDING",
    })

    return approval


def mark_approval_executed(approval_id: str) -> RemediationApproval:
    """
    Called by the backend only after a real role-assignment deletion succeeds.
    Remediation history keeps the record of the run; this only stops the
    approval from still looking ready for remediation.
    """

    with _approvals_lock:
        approvals = _load_approvals()
        approval = _find_approval(approvals, approval_id)
        approval.status = "EXECUTED"
        _save_approvals(approvals)

    return approval


def update_approval_status(
    approval_id: str,
    status: str,
    acting_approver_object_id: str | None,
) -> RemediationApproval:

    normalized_status = (status or "").upper()

    with _approvals_lock:
        approvals = _load_approvals()
        approval = _find_approval(approvals, approval_id)

        try:
            _validate_approver(approval, acting_approver_object_id)
        except PermissionError as exc:
            log_approval_event({
                "action": "APPROVAL_DECISION_DENIED",
                "approval_id": approval_id,
                "acting_approver_object_id": acting_approver_object_id,
                "requested_status": normalized_status,
                "status": "DENIED",
                "reason": str(exc),
            })
            raise

        if approval.status != "PENDING":
            raise ValueError("Only pending approvals can be updated.")

        if approval.expires_at <= datetime.now(UTC):
            raise ValueError("Approval has expired.")

        if normalized_status not in DECISION_STATUSES:
            raise ValueError(
                "Status must be APPROVED, REJECTED or INVESTIGATION_REQUESTED."
            )

        approval.status = normalized_status
        _save_approvals(approvals)

    log_approval_event({
        "action": f"APPROVAL_{normalized_status}",
        "approval_id": approval.approval_id,
        "project_id": approval.project_id,
        "identity_id": approval.identity_id,
        "role_assignment_id": approval.role_assignment_id,
        "resource_scope": approval.resource_scope,
        "acting_approver_object_id": acting_approver_object_id,
        "status": approval.status,
    })

    return approval
