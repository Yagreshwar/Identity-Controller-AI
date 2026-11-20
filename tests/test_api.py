from datetime import UTC, datetime, timedelta

import pytest
from fakes import (
    ALEX_ASSIGNMENT,
    ALEX_ID,
    APOLLO_SCOPE,
    OTHER_USER_ID,
    OWNER_ID,
    PRIYA_ASSIGNMENT,
    PRIYA_ID,
    SECURITY_OPERATOR_ID,
    assignment_id,
)

from app import main
from app.models.approval import RemediationApproval
from app.remediation import approval_service


def approval_payload(**overrides) -> dict:
    payload = {
        "approval_id": "APP-001",
        "incident_id": "IC-1001",
        "project_id": "APOLLO-001",
        "role_assignment_id": ALEX_ASSIGNMENT,
        "identity_id": ALEX_ID,
        "resource_scope": APOLLO_SCOPE,
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    payload.update(overrides)
    return payload


def store_approval(**overrides) -> None:
    data = {
        "approval_id": "APP-001",
        "incident_id": "IC-1001",
        "project_id": "APOLLO-001",
        "role_assignment_id": ALEX_ASSIGNMENT,
        "identity_id": ALEX_ID,
        "resource_scope": APOLLO_SCOPE,
        "approver": OWNER_ID,
        "status": "APPROVED",
        "created_at": datetime.now(UTC),
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
    }
    data.update(overrides)
    approval_service._save_approvals([RemediationApproval(**data)])


def events_with(audit_events, **criteria) -> list[dict]:
    return [
        event for event in audit_events()
        if all(event.get(key) == value for key, value in criteria.items())
    ]


@pytest.fixture
def operator(current_user):
    current_user.user_id = SECURITY_OPERATOR_ID
    return current_user


# ----------------------------------------------------------------------
# /investigate
# ----------------------------------------------------------------------

def test_investigate_returns_findings_and_audits(
    api_client, operator, fake_azure, fake_ai, audit_events
):
    response = api_client.post("/investigate", json={"identity_id": ALEX_ID})

    assert response.status_code == 200
    assert response.json()["findings"][0]["approval_status"] == "PENDING_APPROVAL"

    [event] = events_with(audit_events, event_type="INVESTIGATION")
    assert event["status"] == "COMPLETED"
    assert event["requested_by"] == SECURITY_OPERATOR_ID
    assert event["findings"][0]["role_assignment_id"] == ALEX_ASSIGNMENT


def test_investigate_unknown_identity_returns_404(
    api_client, operator, fake_azure, fake_ai, audit_events
):
    response = api_client.post("/investigate", json={"identity_id": "missing"})

    assert response.status_code == 404
    assert events_with(audit_events, event_type="INVESTIGATION", status="FAILED")


@pytest.mark.parametrize(
    ("error", "status_code"),
    [
        (ValueError("bad input"), 400),
        (RuntimeError("tool loop"), 502),
        (KeyError("unexpected"), 500),
    ],
)
def test_investigate_maps_errors(
    api_client, operator, monkeypatch, audit_events, error, status_code
):
    def fail(**kwargs):
        raise error

    monkeypatch.setattr(main, "run_investigation", fail)

    response = api_client.post("/investigate", json={"identity_id": ALEX_ID})

    assert response.status_code == status_code
    assert events_with(audit_events, event_type="INVESTIGATION", status="FAILED")


def test_investigate_rejects_empty_identity(api_client, operator):
    response = api_client.post("/investigate", json={"identity_id": ""})

    assert response.status_code == 422


# ----------------------------------------------------------------------
# Approvals
# ----------------------------------------------------------------------

def test_approval_is_routed_to_registered_resource_owner(
    api_client, operator, fake_azure, fake_ai, audit_events
):
    response = api_client.post("/approvals", json=approval_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["approver"] == OWNER_ID
    assert body["approver_name"] == "apollo-owner@contoso-demo.com"
    assert body["status"] == "PENDING"
    assert body["created_at"]

    [event] = events_with(audit_events, action="APPROVAL_CREATED")
    assert event["requested_by"] == SECURITY_OPERATOR_ID


def test_shared_resource_uses_project_specific_owner(
    api_client, operator, fake_azure, fake_ai
):
    record = approval_service._resolve_resource_owner("NOVA-003", APOLLO_SCOPE)

    assert record["owner_object_id"] == OTHER_USER_ID


def test_approval_rejected_for_legitimate_active_access(
    api_client, operator, fake_azure, fake_ai, audit_events
):
    response = api_client.post(
        "/approvals",
        json=approval_payload(
            project_id="ORION-002",
            role_assignment_id=PRIYA_ASSIGNMENT,
            identity_id=PRIYA_ID,
            resource_scope=PRIYA_ASSIGNMENT.split("/providers/Microsoft.Authorization")[0],
        ),
    )

    assert response.status_code == 400
    assert events_with(audit_events, action="APPROVAL_CREATION_REJECTED")


def test_approval_rejected_for_unknown_assignment(
    api_client, operator, fake_azure, fake_ai
):
    response = api_client.post(
        "/approvals",
        json=approval_payload(
            role_assignment_id=assignment_id(APOLLO_SCOPE, "not-real"),
        ),
    )

    assert response.status_code == 400


def test_approval_rejected_when_already_expired(
    api_client, operator, fake_azure, fake_ai
):
    response = api_client.post(
        "/approvals",
        json=approval_payload(
            expires_at=(datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        ),
    )

    assert response.status_code == 400


def test_duplicate_approval_id_rejected(api_client, operator, fake_azure, fake_ai):
    assert api_client.post("/approvals", json=approval_payload()).status_code == 200
    assert api_client.post("/approvals", json=approval_payload()).status_code == 400


def test_read_approval_only_by_owner(api_client, current_user, fake_azure):
    store_approval(status="PENDING")

    current_user.user_id = OTHER_USER_ID
    assert api_client.get("/approvals/APP-001").status_code == 403

    current_user.user_id = OWNER_ID
    assert api_client.get("/approvals/APP-001").status_code == 200

    assert api_client.get("/approvals/missing").status_code == 404


def test_non_owner_cannot_decide(
    api_client, current_user, fake_azure, audit_events
):
    store_approval(status="PENDING")
    current_user.user_id = SECURITY_OPERATOR_ID

    response = api_client.post(
        "/approvals/APP-001/decision",
        json={"status": "APPROVED"},
    )

    assert response.status_code == 403
    assert approval_service._load_approvals()[0].status == "PENDING"
    assert events_with(audit_events, action="APPROVAL_DECISION_DENIED")


@pytest.mark.parametrize(
    "decision",
    ["APPROVED", "REJECTED", "INVESTIGATION_REQUESTED"],
)
def test_owner_decisions_are_recorded(
    api_client, current_user, fake_azure, audit_events, decision
):
    store_approval(status="PENDING")
    current_user.user_id = OWNER_ID

    response = api_client.post(
        "/approvals/APP-001/decision",
        json={"status": decision},
    )

    assert response.status_code == 200
    assert response.json()["status"] == decision
    assert events_with(audit_events, action=f"APPROVAL_{decision}")


def test_decision_rules(api_client, current_user, fake_azure):
    current_user.user_id = OWNER_ID

    store_approval(status="APPROVED")
    assert api_client.post(
        "/approvals/APP-001/decision", json={"status": "REJECTED"}
    ).status_code == 400

    store_approval(
        status="PENDING",
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    assert api_client.post(
        "/approvals/APP-001/decision", json={"status": "APPROVED"}
    ).status_code == 400

    assert api_client.post(
        "/approvals/APP-001/decision", json={"status": "DELETE"}
    ).status_code == 422

    assert api_client.post(
        "/approvals/missing/decision", json={"status": "APPROVED"}
    ).status_code == 404


# ----------------------------------------------------------------------
# /remediate
# ----------------------------------------------------------------------

def test_remediation_requires_approved_status(
    api_client, current_user, fake_azure, fake_ai, audit_events
):
    store_approval(status="REJECTED")
    current_user.user_id = OWNER_ID

    response = api_client.post("/remediate", json={"approval_id": "APP-001"})

    assert response.status_code == 400
    assert events_with(audit_events, event_type="REMEDIATION", status="REJECTED")


def test_remediation_by_non_owner_forbidden(
    api_client, current_user, fake_azure, fake_ai, audit_events
):
    store_approval()
    current_user.user_id = SECURITY_OPERATOR_ID

    response = api_client.post("/remediate", json={"approval_id": "APP-001"})

    assert response.status_code == 403
    assert events_with(audit_events, event_type="REMEDIATION", status="REJECTED")


def test_remediation_unknown_approval_returns_404(
    api_client, current_user, fake_azure
):
    current_user.user_id = OWNER_ID

    response = api_client.post("/remediate", json={"approval_id": "missing"})

    assert response.status_code == 404


def test_expired_approval_is_rejected_at_execution(
    api_client, current_user, fake_azure, fake_ai, audit_events
):
    store_approval(expires_at=datetime.now(UTC) - timedelta(minutes=1))
    current_user.user_id = OWNER_ID

    response = api_client.post("/remediate", json={"approval_id": "APP-001"})

    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "Approval expired or invalid."
    assert events_with(
        audit_events,
        event_type="REMEDIATION",
        status="REJECTED",
        reason="Approval expired or invalid.",
    )


def test_approval_cannot_authorize_a_different_assignment(
    api_client, current_user, fake_azure, fake_ai
):
    store_approval(role_assignment_id=assignment_id(APOLLO_SCOPE, "other"))
    current_user.user_id = OWNER_ID

    response = api_client.post("/remediate", json={"approval_id": "APP-001"})

    assert response.status_code == 400


def test_remediation_rejected_when_finding_no_longer_eligible(
    api_client, current_user, fake_azure, fake_ai
):
    store_approval()
    fake_azure.post_project_activity[ALEX_ID] = "ACTIVITY_CONFIRMED"
    current_user.user_id = OWNER_ID

    response = api_client.post("/remediate", json={"approval_id": "APP-001"})

    assert response.status_code == 400
    assert "No currently eligible finding" in response.json()["detail"]


def test_remediation_rejected_when_assignment_already_gone(
    api_client, current_user, fake_azure, fake_ai, monkeypatch
):
    store_approval()
    current_user.user_id = OWNER_ID
    monkeypatch.setattr(main, "get_role_assignments", lambda **kwargs: [])

    response = api_client.post("/remediate", json={"approval_id": "APP-001"})

    assert response.status_code == 400
    assert "not found" in response.json()["detail"]


def test_unexpected_remediation_error_returns_500(
    api_client, current_user, fake_azure, fake_ai, monkeypatch, audit_events
):
    store_approval()
    current_user.user_id = OWNER_ID

    def broken(**kwargs):
        raise KeyError("boom")

    monkeypatch.setattr(main, "run_investigation", broken)

    response = api_client.post("/remediate", json={"approval_id": "APP-001"})

    assert response.status_code == 500
    assert events_with(audit_events, event_type="REMEDIATION", status="FAILED")
