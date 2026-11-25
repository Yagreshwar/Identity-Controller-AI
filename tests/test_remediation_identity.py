import pytest
from fakes import (
    ALEX_ASSIGNMENT,
    ALEX_ID,
    APOLLO_SCOPE,
    CONTRIBUTOR_ROLE,
    DISCOVERY_MI_CLIENT_ID,
    ORION_SCOPE,
    PRIYA_ASSIGNMENT,
    REMEDIATION_MI_CLIENT_ID,
    SBDC_ROLE,
    assignment_id,
)

from app.remediation import remediation_identity
from app.remediation.remediation_identity import (
    RemediationIdentityError,
    confirm_target_with_remediation_identity,
    delete_role_assignment_with_remediation_identity,
)


def test_confirms_target_as_remediation_identity_without_deleting(fake_azure):
    result = confirm_target_with_remediation_identity(ALEX_ASSIGNMENT, APOLLO_SCOPE)

    assert result == {
        "remediation_identity": REMEDIATION_MI_CLIENT_ID,
        "role_assignment_id": ALEX_ASSIGNMENT,
    }
    assert fake_azure.remediation_calls == [("get_by_id", ALEX_ASSIGNMENT)]
    assert fake_azure.find_assignment(ALEX_ASSIGNMENT) is not None


def test_deletes_only_the_exact_approved_assignment(fake_azure):
    fake_azure.allow_deletion = True
    other = assignment_id(APOLLO_SCOPE, "someone-else")
    fake_azure.assignments[ALEX_ID].append({
        "id": other,
        "principal_id": ALEX_ID,
        "role_definition_id": SBDC_ROLE,
        "role_name": None,
        "scope": APOLLO_SCOPE,
    })

    result = delete_role_assignment_with_remediation_identity(
        ALEX_ASSIGNMENT, APOLLO_SCOPE
    )

    assert result == {
        "remediation_identity": REMEDIATION_MI_CLIENT_ID,
        "role_assignment_id": ALEX_ASSIGNMENT,
    }
    assert fake_azure.remediation_calls == [("delete_by_id", ALEX_ASSIGNMENT)]
    assert fake_azure.find_assignment(ALEX_ASSIGNMENT) is None
    assert fake_azure.find_assignment(other) is not None


def test_deletion_outside_demo_scope_is_refused(fake_azure):
    fake_azure.allow_deletion = True

    with pytest.raises(RemediationIdentityError, match="dedicated demo scope"):
        delete_role_assignment_with_remediation_identity(PRIYA_ASSIGNMENT, ORION_SCOPE)

    assert fake_azure.remediation_calls == []
    assert fake_azure.find_assignment(PRIYA_ASSIGNMENT) is not None


def test_deletion_requires_the_approved_scope(fake_azure):
    fake_azure.allow_deletion = True

    with pytest.raises(RemediationIdentityError, match="does not belong"):
        delete_role_assignment_with_remediation_identity(PRIYA_ASSIGNMENT, APOLLO_SCOPE)

    assert fake_azure.remediation_calls == []


def test_azure_refusing_the_deletion_is_reported(fake_azure):
    fake_azure.allow_deletion = True
    fake_azure.delete_fails = True

    with pytest.raises(RemediationIdentityError, match="could not delete"):
        delete_role_assignment_with_remediation_identity(
            ALEX_ASSIGNMENT, APOLLO_SCOPE
        )

    assert fake_azure.find_assignment(ALEX_ASSIGNMENT) is not None


def test_deleting_an_assignment_that_is_already_gone_is_reported(fake_azure):
    fake_azure.allow_deletion = True
    gone = assignment_id(APOLLO_SCOPE, "already-gone")

    with pytest.raises(RemediationIdentityError, match="nothing was deleted"):
        delete_role_assignment_with_remediation_identity(gone, APOLLO_SCOPE)


def test_other_resource_in_demo_group_is_confirmed(fake_azure):
    group_scope = APOLLO_SCOPE.split("/providers/")[0]
    other_scope = (
        f"{group_scope}/providers/Microsoft.Storage/storageAccounts/apollobackup"
    )
    other_assignment = assignment_id(other_scope, "alex-backup-sbdc")
    fake_azure.assignments[ALEX_ID].append({
        "id": other_assignment,
        "principal_id": ALEX_ID,
        "role_definition_id": SBDC_ROLE,
        "role_name": None,
        "scope": other_scope,
    })

    result = confirm_target_with_remediation_identity(other_assignment, other_scope)

    assert result["role_assignment_id"] == other_assignment
    assert fake_azure.remediation_calls == [("get_by_id", other_assignment)]


@pytest.mark.parametrize(
    "setting",
    [
        "REMEDIATION_MANAGED_IDENTITY_CLIENT_ID",
        "REMEDIATION_MANAGED_IDENTITY_PRINCIPAL_ID",
        "AZURE_STORAGE_SCOPE",
    ],
)
def test_missing_configuration_blocks_remediation(fake_azure, monkeypatch, setting):
    monkeypatch.setattr(remediation_identity, setting, None)

    with pytest.raises(RemediationIdentityError, match="not configured"):
        confirm_target_with_remediation_identity(ALEX_ASSIGNMENT, APOLLO_SCOPE)

    assert fake_azure.remediation_calls == []


def test_remediation_identity_must_differ_from_discovery_identity(
    fake_azure, monkeypatch
):
    monkeypatch.setattr(
        remediation_identity,
        "REMEDIATION_MANAGED_IDENTITY_CLIENT_ID",
        DISCOVERY_MI_CLIENT_ID,
    )

    with pytest.raises(RemediationIdentityError, match="distinct"):
        confirm_target_with_remediation_identity(ALEX_ASSIGNMENT, APOLLO_SCOPE)


def test_target_outside_demo_scope_is_refused(fake_azure):
    with pytest.raises(RemediationIdentityError, match="dedicated demo scope"):
        confirm_target_with_remediation_identity(PRIYA_ASSIGNMENT, ORION_SCOPE)

    assert fake_azure.remediation_calls == []


def test_assignment_id_must_belong_to_demo_scope(fake_azure):
    with pytest.raises(RemediationIdentityError, match="does not belong"):
        confirm_target_with_remediation_identity(PRIYA_ASSIGNMENT, APOLLO_SCOPE)


def test_identity_with_access_outside_demo_scope_is_refused(fake_azure):
    fake_azure.remediation_identity_assignments[0]["scope"] = ORION_SCOPE

    with pytest.raises(RemediationIdentityError, match="outside the dedicated"):
        confirm_target_with_remediation_identity(ALEX_ASSIGNMENT, APOLLO_SCOPE)

    assert fake_azure.remediation_calls == []


def test_identity_with_broad_permissions_is_refused(fake_azure):
    fake_azure.remediation_identity_assignments[0]["role_definition_id"] = (
        CONTRIBUTOR_ROLE
    )

    with pytest.raises(RemediationIdentityError, match="broader permissions"):
        confirm_target_with_remediation_identity(ALEX_ASSIGNMENT, APOLLO_SCOPE)


def test_identity_without_assignments_is_refused(fake_azure):
    fake_azure.remediation_identity_assignments.clear()

    with pytest.raises(RemediationIdentityError, match="no role assignment"):
        confirm_target_with_remediation_identity(ALEX_ASSIGNMENT, APOLLO_SCOPE)


def test_unavailable_managed_identity_is_reported(fake_azure):
    fake_azure.remediation_identity_available = False

    with pytest.raises(RemediationIdentityError, match="could not access"):
        confirm_target_with_remediation_identity(ALEX_ASSIGNMENT, APOLLO_SCOPE)


def test_remediation_client_uses_managed_identity_credential(monkeypatch):
    remediation_identity.get_remediation_client.cache_clear()
    monkeypatch.setattr(
        remediation_identity,
        "REMEDIATION_MANAGED_IDENTITY_CLIENT_ID",
        REMEDIATION_MI_CLIENT_ID,
    )
    monkeypatch.setattr(
        remediation_identity,
        "REMEDIATION_MANAGED_IDENTITY_PRINCIPAL_ID",
        "principal",
    )
    monkeypatch.setattr(remediation_identity, "AZURE_STORAGE_SCOPE", APOLLO_SCOPE)
    monkeypatch.setattr(
        remediation_identity,
        "DISCOVERY_MANAGED_IDENTITY_CLIENT_ID",
        DISCOVERY_MI_CLIENT_ID,
    )

    captured = {}

    class RecordingCredential:
        def __init__(self, client_id):
            captured["client_id"] = client_id

    monkeypatch.setattr(
        remediation_identity,
        "ManagedIdentityCredential",
        RecordingCredential,
    )
    monkeypatch.setattr(
        remediation_identity,
        "AuthorizationManagementClient",
        lambda credential, subscription: ("client", credential, subscription),
    )

    client = remediation_identity.get_remediation_client()
    remediation_identity.get_remediation_client.cache_clear()

    assert captured["client_id"] == REMEDIATION_MI_CLIENT_ID
    assert isinstance(client[1], RecordingCredential)
