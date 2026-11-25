from datetime import UTC, datetime, timedelta

from fakes import (
    ALEX_ASSIGNMENT,
    ALEX_ID,
    APOLLO_SCOPE,
    OWNER_ID,
    PRIYA_ID,
    SECURITY_OPERATOR_ID,
)

from app import main


def _create_and_approve(api_client, current_user, approval_id):
    current_user.user_id = SECURITY_OPERATOR_ID
    created = api_client.post(
        "/approvals",
        json={
            "approval_id": approval_id,
            "incident_id": "IC-2001",
            "project_id": "APOLLO-001",
            "role_assignment_id": ALEX_ASSIGNMENT,
            "identity_id": ALEX_ID,
            "resource_scope": APOLLO_SCOPE,
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert created.status_code == 200

    current_user.user_id = OWNER_ID
    decided = api_client.post(
        f"/approvals/{approval_id}/decision", json={"status": "APPROVED"}
    )
    assert decided.status_code == 200


def test_identity_search_is_read_only_and_authenticated(
    api_client, current_user, monkeypatch
):
    calls = []

    def fake_search(term):
        calls.append(term)
        return [{"object_id": ALEX_ID, "display_name": "Alex Morgan"}]

    monkeypatch.setattr(main, "search_identity", fake_search)

    current_user.user_id = SECURITY_OPERATOR_ID
    response = api_client.get("/identities/search", params={"q": "Alex Morgan"})

    assert response.status_code == 200
    assert response.json() == [{"object_id": ALEX_ID, "display_name": "Alex Morgan"}]
    assert calls == ["Alex Morgan"]


def test_identity_search_requires_a_term(api_client, current_user):
    current_user.user_id = SECURITY_OPERATOR_ID

    assert api_client.get("/identities/search", params={"q": ""}).status_code == 422


def test_identity_search_errors_are_reported(api_client, current_user, monkeypatch):
    def failing_search(term):
        raise RuntimeError("Graph unavailable")

    monkeypatch.setattr(main, "search_identity", failing_search)
    current_user.user_id = SECURITY_OPERATOR_ID

    response = api_client.get("/identities/search", params={"q": "alex"})

    assert response.status_code == 502
    assert "Graph unavailable" not in response.text


def test_approvals_list_shows_only_the_owners_requests(
    api_client, current_user, fake_azure, fake_ai
):
    _create_and_approve(api_client, current_user, "APP-LIST")

    current_user.user_id = OWNER_ID
    owner_view = api_client.get("/approvals").json()
    assert [item["approval_id"] for item in owner_view] == ["APP-LIST"]

    current_user.user_id = PRIYA_ID
    assert api_client.get("/approvals").json() == []


def test_investigation_audit_keeps_report_detail(
    api_client, current_user, fake_azure, fake_ai, audit_events
):
    current_user.user_id = SECURITY_OPERATOR_ID
    response = api_client.post("/investigate", json={"identity_id": ALEX_ID})
    assert response.status_code == 200

    completed = [
        event for event in audit_events()
        if event["event_type"] == "INVESTIGATION"
        and event.get("status") == "COMPLETED"
    ][-1]

    assert completed["identity_name"]
    assert completed["identity_profile"]["object_id"] == ALEX_ID
    assert completed["investigation_summary"]["summary"]
    assert "alternative_explanations" in completed["investigation_summary"]
    assert completed["evidence_records"]
    assert completed["findings"][0]["recommended_action"]
    assert completed["findings"][0]["resource_scope"] == APOLLO_SCOPE


def test_latest_investigation_replaces_the_previous_one_for_an_identity(
    api_client, current_user, fake_azure, fake_ai, audit_events
):
    current_user.user_id = SECURITY_OPERATOR_ID

    for _ in range(2):
        assert api_client.post(
            "/investigate", json={"identity_id": ALEX_ID}
        ).status_code == 200

    completed = [
        event for event in audit_events()
        if event["event_type"] == "INVESTIGATION"
        and event.get("status") == "COMPLETED"
    ]
    assert len(completed) == 2

    latest = api_client.get("/investigations/latest").json()

    assert len(latest) == 1
    assert latest[0]["identity_id"] == ALEX_ID
    assert latest[0]["recorded_at"] == completed[-1]["recorded_at"]
    assert latest[0]["investigation_summary"]["summary"]
    assert latest[0]["evidence_records"]


def test_audit_events_endpoint_returns_backend_events(
    api_client, current_user, fake_azure, fake_ai
):
    current_user.user_id = SECURITY_OPERATOR_ID
    api_client.post("/investigate", json={"identity_id": ALEX_ID})

    events = api_client.get("/audit/events").json()

    assert any(
        e["event_type"] == "INVESTIGATION" and e["status"] == "COMPLETED"
        for e in events
    )


def test_latest_investigations_exclude_failed_runs(
    api_client, current_user, fake_azure, fake_ai
):
    current_user.user_id = SECURITY_OPERATOR_ID

    assert api_client.get("/investigations/latest").json() == []

    api_client.post("/investigate", json={"identity_id": "not-a-real-identity"})

    assert api_client.get("/investigations/latest").json() == []


def test_remediation_verification_records_before_and_after_assignments(
    api_client, current_user, fake_azure, fake_ai, audit_events
):
    _create_and_approve(api_client, current_user, "APP-BA")

    current_user.user_id = OWNER_ID
    body = api_client.post("/remediate", json={"approval_id": "APP-BA"}).json()

    before = body["verification"]["role_assignments_before"]
    after = body["verification"]["role_assignments_after"]

    # Simulation mode: nothing is deleted, so the snapshots match.
    assert before == after
    assert any(item["id"] == ALEX_ASSIGNMENT for item in before)

    verification_event = [
        event for event in audit_events()
        if event["event_type"] == "VERIFICATION"
    ][-1]
    assert verification_event["role_assignments_before"] == before
    assert verification_event["role_assignments_after"] == after
