
from collections.abc import Callable
from datetime import UTC, datetime

from app.policy.remediation_policy import is_remediation_eligible
from app.policy.validators import validate_remediation_request
from app.remediation.remediation_identity import RemediationIdentityError


def _same_id(left: object, right: object) -> bool:
    return (
        isinstance(left, str)
        and isinstance(right, str)
        and left.rstrip("/").casefold() == right.rstrip("/").casefold()
    )


def remove_role_assignment(
    approval: dict,
    role_assignment: dict,
    approver_authorized: bool,
    evidence_complete: bool,
    project_status: str,
    assignment_type: str,
    already_executed: bool,
    audit_log: Callable[[dict], None],
    confirm_target: Callable[[str, str], dict],
    delete_target: Callable[[str, str], dict] | None = None,
) -> dict:
    """
    Validate an approved removal and hand it to the remediation identity.

    confirm_target authenticates as the remediation identity and confirms the
    assignment. When delete_target is supplied it then deletes exactly that
    assignment (status EXECUTED). Without it nothing is deleted and the result
    is SIMULATED.
    """

    approval = approval or {}
    role_assignment = role_assignment or {}

    def reject(reason: str) -> dict:
        audit_log({
            "action": "ROLE_ASSIGNMENT_REMOVAL",
            "approval_id": approval.get("approval_id"),
            "role_assignment_id": (
                role_assignment.get("id")
                or approval.get("role_assignment_id")
            ),
            "identity_id": approval.get("identity_id"),
            "resource_scope": approval.get("resource_scope"),
            "status": "REJECTED",
            "reason": reason,
            "timestamp": datetime.now(UTC).isoformat(),
        })

        return {
            "status": "REJECTED",
            "reason": reason,
        }

    if not approval or not role_assignment:
        return reject("Approval or role assignment is missing.")

    if approval.get("status") != "APPROVED":
        return reject("Approval not granted.")

    assignment_id = role_assignment.get("id")

    if not isinstance(assignment_id, str) or not assignment_id.strip():
        return reject("Valid role assignment ID is required.")

    validation = validate_remediation_request(
        assignment_id,
        already_executed,
    )

    if not validation["valid"]:
        return reject(validation["reason"])

    if not approver_authorized:
        return reject("Approver not authorized.")

    raw_expires_at = approval.get("expires_at")

    if isinstance(raw_expires_at, str):
        try:
            expires_at = datetime.fromisoformat(raw_expires_at)
        except ValueError:
            return reject("Approval expiry format is invalid.")
    elif isinstance(raw_expires_at, datetime):
        expires_at = raw_expires_at
    else:
        return reject("Approval expiry is missing or invalid.")

    if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
        return reject("Approval expired or invalid.")

    if not _same_id(approval.get("role_assignment_id"), assignment_id):
        return reject("Role assignment mismatch.")

    if not _same_id(
        approval.get("identity_id"),
        role_assignment.get("principal_id"),
    ):
        return reject("Principal mismatch.")

    if not _same_id(
        approval.get("resource_scope"),
        role_assignment.get("scope"),
    ):
        return reject("Scope mismatch.")

    eligibility = is_remediation_eligible(
        approval_status=approval["status"],
        project_status=project_status,
        evidence_complete=evidence_complete,
        assignment_type=assignment_type,
        role_assignment_id=assignment_id,
    )

    if not eligibility["eligible"]:
        return reject(eligibility["reason"])

    try:
        confirmation = confirm_target(assignment_id, approval["resource_scope"])
    except RemediationIdentityError as exc:
        audit_log({
            "action": "ROLE_ASSIGNMENT_REMOVAL",
            "role_assignment_id": assignment_id,
            "identity_id": approval["identity_id"],
            "resource_scope": approval["resource_scope"],
            "approval_id": approval.get("approval_id"),
            "status": "FAILED",
            "reason": str(exc),
            "timestamp": datetime.now(UTC).isoformat(),
        })

        return {
            "status": "FAILED",
            "reason": str(exc),
        }

    if delete_target is not None:
        try:
            deletion = delete_target(assignment_id, approval["resource_scope"])
        except RemediationIdentityError as exc:
            audit_log({
                "action": "ROLE_ASSIGNMENT_REMOVAL",
                "role_assignment_id": assignment_id,
                "identity_id": approval["identity_id"],
                "resource_scope": approval["resource_scope"],
                "approval_id": approval.get("approval_id"),
                "status": "FAILED",
                "reason": str(exc),
                "timestamp": datetime.now(UTC).isoformat(),
            })

            return {
                "status": "FAILED",
                "reason": str(exc),
            }

        audit_log({
            "action": "ROLE_ASSIGNMENT_REMOVAL",
            "role_assignment_id": assignment_id,
            "identity_id": approval["identity_id"],
            "resource_scope": approval["resource_scope"],
            "approval_id": approval.get("approval_id"),
            "remediation_identity": deletion.get("remediation_identity"),
            "status": "EXECUTED",
            "timestamp": datetime.now(UTC).isoformat(),
        })

        return {
            "status": "EXECUTED",
            "role_assignment_id": assignment_id,
            "remediation_identity": deletion.get("remediation_identity"),
            "message": (
                "The remediation identity deleted the approved role "
                "assignment."
            ),
        }

    audit_log({
        "action": "ROLE_ASSIGNMENT_REMOVAL",
        "role_assignment_id": assignment_id,
        "identity_id": approval["identity_id"],
        "resource_scope": approval["resource_scope"],
        "approval_id": approval.get("approval_id"),
        "remediation_identity": confirmation.get("remediation_identity"),
        "status": "SIMULATED",
        "timestamp": datetime.now(UTC).isoformat(),
    })

    return {
        "status": "SIMULATED",
        "role_assignment_id": assignment_id,
        "remediation_identity": confirmation.get("remediation_identity"),
        "message": (
            "The remediation identity confirmed the approved assignment. "
            "Real deletion is switched off (REMEDIATION_DELETE_ENABLED); "
            "no Azure role assignment was deleted."
        ),
    }
