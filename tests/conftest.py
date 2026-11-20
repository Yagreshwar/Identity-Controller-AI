import os
import sys
from pathlib import Path

# Module-level clients read configuration at import time. These values must be
# set before any app module is imported so tests never use real credentials.
_TEST_ENVIRONMENT = {
    "AZURE_SUBSCRIPTION_ID": "00000000-0000-0000-0000-000000000000",
    "AZURE_TENANT_ID": "99999999-9999-9999-9999-999999999999",
    "ENTRA_CLIENT_ID": "api://identity-commander-tests",
    "AZURE_AI_ENDPOINT": "https://example.invalid/openai/v1/",
    "AZURE_AI_FOUNDRY_API_KEY": "test-key",
    "AZURE_AI_DEPLOYMENT_NAME": "test-deployment",
    "LOG_ANALYTICS_WORKSPACE_ID": "test-workspace",
}

for key, value in _TEST_ENVIRONMENT.items():
    os.environ[key] = value

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402
from fakes import (  # noqa: E402
    APOLLO_SCOPE,
    DISCOVERY_MI_CLIENT_ID,
    PRIYA_ID,
    REMEDIATION_MI_CLIENT_ID,
    REMEDIATION_MI_PRINCIPAL_ID,
    FakeAIClient,
    FakeAzure,
)
from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from app.agent import identity_agent  # noqa: E402
from app.audit import audit_logger  # noqa: E402
from app.authentication import get_current_user  # noqa: E402
from app.remediation import (  # noqa: E402
    access_test,
    approval_service,
    remediation_identity,
)


@pytest.fixture(autouse=True)
def isolated_storage(monkeypatch, tmp_path):
    """Keep audit and approval files out of the real project directories."""
    monkeypatch.setattr(
        audit_logger,
        "AUDIT_LOG_PATH",
        tmp_path / "logs" / "remediation_audit.jsonl",
    )
    monkeypatch.setattr(
        approval_service,
        "APPROVALS_PATH",
        tmp_path / "data" / "remediation_approvals.json",
    )


@pytest.fixture
def fake_azure(monkeypatch):
    azure = FakeAzure()

    for name, function in azure.tools().items():
        monkeypatch.setitem(identity_agent.INVESTIGATION_TOOLS, name, function)

    monkeypatch.setattr(
        approval_service,
        "get_role_assignments",
        azure.get_role_assignments,
    )
    monkeypatch.setattr(
        approval_service,
        "get_resource_owner_record",
        azure.get_resource_owner_record,
    )
    monkeypatch.setattr(main, "get_role_assignments", azure.get_role_assignments)
    monkeypatch.setattr(main, "get_project_assignment", azure.get_project_assignment)
    monkeypatch.setattr(main, "get_project_resources", azure.get_project_resources)
    monkeypatch.setattr(main, "ACTIVE_DEVELOPER_OBJECT_ID", PRIYA_ID)
    monkeypatch.setattr(main, "ACCESS_TEST_CONTAINER", "access-test")
    monkeypatch.setattr(main, "ACCESS_TEST_BLOB", "alex-test.txt")

    # Remediation identity: real validation logic, fake Azure endpoints.
    for name, value in {
        "AZURE_STORAGE_SCOPE": APOLLO_SCOPE,
        "DISCOVERY_MANAGED_IDENTITY_CLIENT_ID": DISCOVERY_MI_CLIENT_ID,
        "REMEDIATION_MANAGED_IDENTITY_CLIENT_ID": REMEDIATION_MI_CLIENT_ID,
        "REMEDIATION_MANAGED_IDENTITY_PRINCIPAL_ID": REMEDIATION_MI_PRINCIPAL_ID,
    }.items():
        monkeypatch.setattr(remediation_identity, name, value)

    monkeypatch.setattr(
        remediation_identity,
        "get_principal_role_assignments",
        azure.get_principal_role_assignments,
    )
    monkeypatch.setattr(
        remediation_identity,
        "get_role_definition",
        azure.get_role_definition,
    )
    monkeypatch.setattr(
        remediation_identity,
        "get_remediation_client",
        azure.remediation_client,
    )

    monkeypatch.setattr(access_test, "BlobClient", azure.blob_client_factory())

    return azure


@pytest.fixture
def fake_ai(monkeypatch):
    client = FakeAIClient()
    monkeypatch.setattr(identity_agent, "client", client)
    return client


class _CurrentUser:
    def __init__(self):
        self.user_id: str | None = None

    def __call__(self) -> dict:
        return {
            "user_id": self.user_id,
            "username": "tester@contoso-demo.com",
            "name": "Tester",
            "tenant_id": _TEST_ENVIRONMENT["AZURE_TENANT_ID"],
        }


@pytest.fixture
def current_user():
    user = _CurrentUser()
    main.app.dependency_overrides[get_current_user] = user
    yield user
    main.app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def api_client():
    return TestClient(main.app)


@pytest.fixture
def audit_events():
    return audit_logger.read_audit_events
