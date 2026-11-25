
from datetime import UTC, datetime, timedelta

from app.remediation.executor import remove_role_assignment
from app.remediation.remediation_identity import RemediationIdentityError


def get_approval():
    return {
        "status": "APPROVED",
        "approval_id": "APP-001",
        "role_assignment_id": "assignment-001",
        "identity_id": "identity-001",
        "resource_scope": "/subscriptions/demo/resourceGroups/apollo",
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
    }


def get_role_assignment():
    return {
        "id": "assignment-001",
        "principal_id": "identity-001",
        "scope": "/subscriptions/demo/resourceGroups/apollo",
        "assignment_source": "DIRECT",
    }


class RecordingIdentity:
    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def __call__(self, role_assignment_id, resource_scope):
        self.calls.append((role_assignment_id, resource_scope))

        if self.error:
            raise self.error

        return {
            "remediation_identity": "remediation-mi",
            "role_assignment_id": role_assignment_id,
        }


def execute_remediation(
    approval=None,
    role_assignment=None,
    approver_authorized=True,
    already_executed=False,
    identity=None,
    delete_target=None,
):
    audit_events = []

    result = remove_role_assignment(
        approval=approval or get_approval(),
        role_assignment=role_assignment or get_role_assignment(),
        approver_authorized=approver_authorized,
        evidence_complete=True,
        project_status="completed",
        assignment_type="DIRECT",
        already_executed=already_executed,
        audit_log=audit_events.append,
        confirm_target=identity or RecordingIdentity(),
        delete_target=delete_target,
    )

    return result, audit_events


def test_deletes_the_exact_approved_assignment_after_confirming_it():
    confirm = RecordingIdentity()
    delete = RecordingIdentity()

    result, audit_events = execute_remediation(
        identity=confirm,
        delete_target=delete,
    )

    scope = "/subscriptions/demo/resourceGroups/apollo"
    assert result["status"] == "EXECUTED"
    assert result["role_assignment_id"] == "assignment-001"
    assert result["remediation_identity"] == "remediation-mi"
    assert confirm.calls == [("assignment-001", scope)]
    assert delete.calls == [("assignment-001", scope)]
    assert [event["status"] for event in audit_events] == ["EXECUTED"]


def test_failed_deletion_is_reported_and_audited():
    delete = RecordingIdentity(error=RemediationIdentityError("Delete refused."))

    result, audit_events = execute_remediation(delete_target=delete)

    assert result == {"status": "FAILED", "reason": "Delete refused."}
    assert [event["status"] for event in audit_events] == ["FAILED"]


def test_failed_confirmation_never_reaches_deletion():
    confirm = RecordingIdentity(error=RemediationIdentityError("Not visible."))
    delete = RecordingIdentity()

    result, _ = execute_remediation(identity=confirm, delete_target=delete)

    assert result["status"] == "FAILED"
    assert delete.calls == []


def test_rejected_request_never_deletes():
    approval = get_approval()
    approval["status"] = "PENDING"
    delete = RecordingIdentity()

    result, _ = execute_remediation(approval=approval, delete_target=delete)

    assert result["status"] == "REJECTED"
    assert delete.calls == []


def test_simulate_approved_role_assignment():
    result, audit_events = execute_remediation()

    assert result["status"] == "SIMULATED"
    assert result["role_assignment_id"] == "assignment-001"
    assert result["remediation_identity"] == "remediation-mi"
    assert "no Azure role assignment was deleted" in result["message"]
    assert audit_events[0]["remediation_identity"] == "remediation-mi"

    assert audit_events[0]["status"] == "SIMULATED"
    assert audit_events[0]["action"] == "ROLE_ASSIGNMENT_REMOVAL"


def test_reject_unapproved_request():
    approval = get_approval()
    approval["status"] = "PENDING"

    result, _ = execute_remediation(approval=approval)

    assert result["status"] == "REJECTED"
    assert result["reason"] == "Approval not granted."


def test_reject_expired_approval():
    approval = get_approval()
    approval["expires_at"] = datetime.now(UTC) - timedelta(hours=1)

    result, _ = execute_remediation(approval=approval)

    assert result["status"] == "REJECTED"
    assert result["reason"] == "Approval expired or invalid."


def test_reject_unauthorized_approver():
    result, _ = execute_remediation(approver_authorized=False)

    assert result["status"] == "REJECTED"
    assert result["reason"] == "Approver not authorized."


def test_reject_role_assignment_mismatch():
    role_assignment = get_role_assignment()
    role_assignment["id"] = "assignment-002"

    result, _ = execute_remediation(role_assignment=role_assignment)

    assert result["status"] == "REJECTED"
    assert result["reason"] == "Role assignment mismatch."


def test_reject_principal_mismatch():
    role_assignment = get_role_assignment()
    role_assignment["principal_id"] = "identity-002"

    result, _ = execute_remediation(role_assignment=role_assignment)

    assert result["status"] == "REJECTED"
    assert result["reason"] == "Principal mismatch."


def test_reject_scope_mismatch():
    role_assignment = get_role_assignment()
    role_assignment["scope"] = "/subscriptions/demo/resourceGroups/other"

    result, _ = execute_remediation(role_assignment=role_assignment)

    assert result["status"] == "REJECTED"
    assert result["reason"] == "Scope mismatch."


def test_reject_duplicate_execution():
    result, _ = execute_remediation(already_executed=True)

    assert result["status"] == "REJECTED"


def test_rejections_are_audited():
    approval = get_approval()
    approval["status"] = "PENDING"

    result, audit_events = execute_remediation(approval=approval)

    assert result["status"] == "REJECTED"
    assert audit_events == [
        {
            **audit_events[0],
            "action": "ROLE_ASSIGNMENT_REMOVAL",
            "status": "REJECTED",
            "reason": "Approval not granted.",
            "approval_id": "APP-001",
        }
    ]


def test_reject_wildcard_assignment():
    approval = get_approval()
    approval["role_assignment_id"] = "*"
    role_assignment = get_role_assignment()
    role_assignment["id"] = "*"

    result, _ = execute_remediation(
        approval=approval,
        role_assignment=role_assignment,
    )

    assert result["status"] == "REJECTED"
    assert result["reason"] == "Wildcard operations are not allowed"


def test_remediation_identity_receives_only_the_approved_target():
    identity = RecordingIdentity()

    execute_remediation(identity=identity)

    assert identity.calls == [
        ("assignment-001", "/subscriptions/demo/resourceGroups/apollo")
    ]


def test_rejected_requests_never_reach_remediation_identity():
    identity = RecordingIdentity()

    execute_remediation(approver_authorized=False, identity=identity)

    assert identity.calls == []


def test_remediation_identity_failure_is_reported_and_audited():
    identity = RecordingIdentity(
        error=RemediationIdentityError("Managed identity unavailable.")
    )

    result, audit_events = execute_remediation(identity=identity)

    assert result == {
        "status": "FAILED",
        "reason": "Managed identity unavailable.",
    }
    assert audit_events[-1]["status"] == "FAILED"
