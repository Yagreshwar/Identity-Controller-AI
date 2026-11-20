import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fakes import (
    ALEX_ASSIGNMENT,
    ALEX_ID,
    APOLLO_SCOPE,
    OWNER_ID,
    PRIYA_ASSIGNMENT,
    PRIYA_ID,
    REMEDIATION_MI_CLIENT_ID,
    SECURITY_OPERATOR_ID,
    FakeTestIdentityCredential,
)

from app import main
from app.connectors import rbac_client

APP_DIR = Path(__file__).resolve().parents[1] / "app"


def create_approved_alex_approval(api_client, current_user, approval_id):
    current_user.user_id = SECURITY_OPERATOR_ID
    created = api_client.post(
        "/approvals",
        json={
            "approval_id": approval_id,
            "incident_id": "IC-1004",
            "project_id": "APOLLO-001",
            "role_assignment_id": ALEX_ASSIGNMENT,
            "identity_id": ALEX_ID,
            "resource_scope": APOLLO_SCOPE,
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert created.status_code == 200

    current_user.user_id = OWNER_ID
    approved = api_client.post(
        f"/approvals/{approval_id}/decision", json={"status": "APPROVED"}
    )
    assert approved.status_code == 200


def test_alex_full_workflow_is_simulated_verified_and_audited(
    api_client, current_user, fake_azure, fake_ai, audit_events, monkeypatch
):
    monkeypatch.setattr(main, "get_access_test_credential", FakeTestIdentityCredential)
    original_assignments = [dict(item) for item in fake_azure.assignments[ALEX_ID]]

    # 1. Security operator investigates Alex.
    current_user.user_id = SECURITY_OPERATOR_ID
    investigation = api_client.post(
        "/investigate",
        json={"identity_id": ALEX_ID, "request": "Investigate Alex Morgan."},
    )
    assert investigation.status_code == 200
    finding = investigation.json()["findings"][0]
    assert finding["finding_type"] == "STALE_PRODUCTION_ACCESS"
    assert finding["approval_status"] == "PENDING_APPROVAL"

    # 2. Operator raises an approval for the exact assignment.
    created = api_client.post(
        "/approvals",
        json={
            "approval_id": "APP-1001",
            "incident_id": "IC-1001",
            "project_id": finding["project_id"],
            "role_assignment_id": finding["role_assignment_id"],
            "identity_id": ALEX_ID,
            "resource_scope": finding["resource_scope"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert created.status_code == 200
    assert created.json()["approver"] == OWNER_ID

    # 3. Only the resource owner can approve.
    denied = api_client.post(
        "/approvals/APP-1001/decision", json={"status": "APPROVED"}
    )
    assert denied.status_code == 403

    current_user.user_id = OWNER_ID
    approved = api_client.post(
        "/approvals/APP-1001/decision", json={"status": "APPROVED"}
    )
    assert approved.status_code == 200

    # 4. Simulated remediation followed by verification.
    remediation = api_client.post("/remediate", json={"approval_id": "APP-1001"})
    assert remediation.status_code == 200
    body = remediation.json()

    assert body["execution"]["status"] == "SIMULATED"
    assert body["execution"]["role_assignment_id"] == ALEX_ASSIGNMENT
    assert body["verification"]["status"] == "ACCESS_STILL_PRESENT"
    assert body["verification"]["mode"] == "SIMULATION"
    assert "Simulation mode" in body["verification"]["message"]
    assert body["verification"]["other_access_paths"] == []

    # The remediation identity (not discovery) confirmed the target, read-only.
    assert body["execution"]["remediation_identity"] == REMEDIATION_MI_CLIENT_ID
    assert fake_azure.remediation_calls == [("get_by_id", ALEX_ASSIGNMENT)]

    # Controlled access test: simulation leaves Alex's access in place.
    access_test = body["verification"]["controlled_access_test"]
    assert access_test["status"] == "ACCESS_ALLOWED"
    assert ("get_blob_properties", {"identity_id": ALEX_ID}) in fake_azure.calls

    # Priya's legitimate access is unchanged.
    assert body["verification"]["legitimate_access"]["status"] == "INTACT"

    # 5. No assignment was changed for Alex or anyone else.
    assert fake_azure.assignments[ALEX_ID] == original_assignments
    assert fake_azure.assignments[PRIYA_ID][0]["id"] == PRIYA_ASSIGNMENT

    # 6. A second execution of the same assignment is refused.
    duplicate = api_client.post("/remediate", json={"approval_id": "APP-1001"})
    assert duplicate.status_code == 400
    assert duplicate.json()["detail"]["reason"] == (
        "Duplicate execution is not allowed"
    )

    # 7. The audit trail covers each stage in order.
    trail = [
        (event["event_type"], event.get("action"), event.get("status"))
        for event in audit_events()
    ]

    expected = [
        ("INVESTIGATION", "IDENTITY_INVESTIGATION", "COMPLETED"),
        ("APPROVAL", "APPROVAL_CREATED", "PENDING"),
        ("APPROVAL", "APPROVAL_DECISION_DENIED", "DENIED"),
        ("APPROVAL", "APPROVAL_APPROVED", "APPROVED"),
        ("REMEDIATION", "ROLE_ASSIGNMENT_REMOVAL", "SIMULATED"),
        ("VERIFICATION", "REMEDIATION_VERIFICATION", "ACCESS_STILL_PRESENT"),
        ("REMEDIATION", "ROLE_ASSIGNMENT_REMOVAL", "REJECTED"),
    ]
    assert trail == expected


def test_priya_negative_path_keeps_legitimate_access(
    api_client, current_user, fake_azure, fake_ai
):
    current_user.user_id = SECURITY_OPERATOR_ID

    investigation = api_client.post("/investigate", json={"identity_id": PRIYA_ID})
    assert investigation.status_code == 200
    finding = investigation.json()["findings"][0]
    assert finding["recommended_action"] == "NO_REMOVAL_RECOMMENDED"

    created = api_client.post(
        "/approvals",
        json={
            "approval_id": "APP-PRIYA",
            "incident_id": "IC-1002",
            "project_id": "ORION-002",
            "role_assignment_id": PRIYA_ASSIGNMENT,
            "identity_id": PRIYA_ID,
            "resource_scope": finding["resource_scope"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert created.status_code == 400
    assert fake_azure.assignments[PRIYA_ID][0]["id"] == PRIYA_ASSIGNMENT


def test_residual_access_through_another_direct_assignment_is_reported(
    api_client, current_user, fake_azure, fake_ai
):
    fake_azure.assignments[ALEX_ID].append({
        **fake_azure.assignments[ALEX_ID][0],
        "id": f"{APOLLO_SCOPE}/providers/Microsoft.Authorization/roleAssignments/second",
    })

    current_user.user_id = SECURITY_OPERATOR_ID
    created = api_client.post(
        "/approvals",
        json={
            "approval_id": "APP-RESIDUAL",
            "incident_id": "IC-1003",
            "project_id": "APOLLO-001",
            "role_assignment_id": ALEX_ASSIGNMENT,
            "identity_id": ALEX_ID,
            "resource_scope": APOLLO_SCOPE,
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert created.status_code == 200

    current_user.user_id = OWNER_ID
    api_client.post("/approvals/APP-RESIDUAL/decision", json={"status": "APPROVED"})

    body = api_client.post(
        "/remediate", json={"approval_id": "APP-RESIDUAL"}
    ).json()

    assert body["verification"]["other_access_paths"] == [
        f"{APOLLO_SCOPE}/providers/Microsoft.Authorization/roleAssignments/second"
    ]


def test_controlled_access_test_not_performed_without_credential(
    api_client, current_user, fake_azure, fake_ai
):
    create_approved_alex_approval(api_client, current_user, "APP-NOCRED")

    body = api_client.post("/remediate", json={"approval_id": "APP-NOCRED"}).json()

    assert body["verification"]["controlled_access_test"]["status"] == (
        "NOT_PERFORMED"
    )
    assert body["verification"]["status"] == "ACCESS_STILL_PRESENT"


def test_unavailable_remediation_identity_returns_503_and_is_audited(
    api_client, current_user, fake_azure, fake_ai, audit_events
):
    create_approved_alex_approval(api_client, current_user, "APP-NOMI")
    fake_azure.remediation_identity_available = False

    response = api_client.post("/remediate", json={"approval_id": "APP-NOMI"})

    assert response.status_code == 503
    assert audit_events()[-1]["event_type"] == "REMEDIATION"
    assert audit_events()[-1]["status"] == "FAILED"
    assert not any(e["event_type"] == "VERIFICATION" for e in audit_events())


def test_discovery_and_remediation_use_separate_managed_identities():
    from app.connectors import credentials
    from app.remediation import remediation_identity

    credentials_source = Path(credentials.__file__).read_text(encoding="utf-8")
    remediation_source = Path(remediation_identity.__file__).read_text(
        encoding="utf-8"
    )

    assert "DISCOVERY_MANAGED_IDENTITY_CLIENT_ID" in credentials_source
    assert "ManagedIdentityCredential(" in remediation_source
    assert "REMEDIATION_MANAGED_IDENTITY_CLIENT_ID" in remediation_source

    for connector in APP_DIR.joinpath("connectors").glob("*_client.py"):
        assert "REMEDIATION_" not in connector.read_text(encoding="utf-8")


def test_backend_has_no_write_capable_azure_code_path():
    assert not hasattr(rbac_client, "delete_role_assignment")
    assert not hasattr(rbac_client, "remediation_client")

    forbidden_calls = {
        "delete",
        "delete_by_id",
        "begin_delete",
        "create",
        "create_or_update",
    }
    forbidden_names = {"ClientSecretCredential"}

    for source_file in APP_DIR.rglob("*.py"):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                assert node.id not in forbidden_names, source_file

            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in forbidden_calls
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "role_assignments"
            ):
                raise AssertionError(f"Role assignment write in {source_file}")


def test_configuration_has_no_remediation_secret():
    from app import config

    assert not any(
        "SECRET" in name or "PASSWORD" in name for name in vars(config)
    )
