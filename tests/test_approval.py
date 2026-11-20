
from datetime import UTC, datetime, timedelta

from app.remediation import approval_service


def test_create_approval(monkeypatch, tmp_path):
    identity_id = "9a115c2b-c0fb-4328-b6c1-5b99fa3a7849"
    role_assignment_id = "4afcdf28-de48-4da8-814b-240f808c3593"
    project_id = "APOLLO-001"

    resource_scope = (
        "/subscriptions/75b564c9-ef4f-4c27-9324-2e93f95b8470"
        "/resourceGroups/identity-commander"
        "/providers/Microsoft.Storage/storageAccounts/identitycommanderstorage"
    )

    monkeypatch.setattr(
        approval_service,
        "APPROVALS_PATH",
        tmp_path / "remediation_approvals.json",
    )

    monkeypatch.setattr(
        approval_service,
        "get_role_assignments",
        lambda identity_id, scope: [
            {
                "id": role_assignment_id,
                "principal_id": identity_id,
                "scope": scope,
                "assignment_source": "DIRECT",
            }
        ],
    )

    monkeypatch.setattr(
        approval_service,
        "run_investigation",
        lambda identity_id, request: {
            "findings": [
                {
                    "role_assignment_id": role_assignment_id,
                    "resource_scope": resource_scope,
                    "finding_type": "STALE_PRODUCTION_ACCESS",
                    "approval_required": True,
                    "approval_status": "PENDING_APPROVAL",
                    "project_status": "completed",
                }
            ],
            "evidence": {
                "projects": [
                    {
                        "project": {
                            "project_id": project_id,
                            "status": "completed",
                        },
                        "resources": [
                            {
                                "resource_record": {
                                    "resource_id": resource_scope,
                                },
                                "role_assignments": [
                                    {
                                        "assignment": {
                                            "id": role_assignment_id,
                                            "principal_id": identity_id,
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
        },
    )

    monkeypatch.setattr(
        approval_service,
        "get_resource_owner_record",
        lambda resource_id, project_id: {
            "project_id": project_id,
            "resource_id": resource_id,
            "owner": "apollo-owner@contoso-demo.com",
            "owner_object_id": "owner-object-id",
        },
    )

    monkeypatch.setattr(
        approval_service,
        "log_approval_event",
        lambda event: None,
    )

    approval = approval_service.create_approval(
        approval_id="APP-001",
        incident_id="INC-001",
        project_id=project_id,
        role_assignment_id=role_assignment_id,
        identity_id=identity_id,
        resource_scope=resource_scope,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    assert approval.approval_id == "APP-001"
    assert approval.project_id == project_id
    assert approval.identity_id == identity_id
    assert approval.status == "PENDING"
    assert approval.approver == "owner-object-id"
    assert approval.approver_name == "apollo-owner@contoso-demo.com"
    assert approval.created_at is not None


def test_create_approval_requires_registered_owner(monkeypatch):
    monkeypatch.setattr(
        approval_service,
        "get_resource_owner_record",
        lambda resource_id, project_id: None,
    )
    monkeypatch.setattr(approval_service, "log_approval_event", lambda event: None)

    try:
        approval_service.create_approval(
            approval_id="APP-002",
            incident_id="INC-002",
            project_id="UNKNOWN",
            role_assignment_id="assignment",
            identity_id="identity",
            resource_scope="/subscriptions/demo",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    except ValueError as exc:
        assert "No resource owner" in str(exc)
    else:
        raise AssertionError("Approval without a registered owner was created.")
