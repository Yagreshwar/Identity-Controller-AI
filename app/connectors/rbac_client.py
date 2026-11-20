
import os

from app.connectors.credentials import discovery_credential
from azure.mgmt.authorization import AuthorizationManagementClient

subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

if not subscription_id:
    raise ValueError("AZURE_SUBSCRIPTION_ID is not configured")

# Discovery identity: read-only operations. Write access belongs only to the
# separate remediation identity in app.remediation.remediation_identity.
credential = discovery_credential

authorization_client = AuthorizationManagementClient(
    credential,
    subscription_id
)


def _normalize_scope(scope: str) -> str:
    return scope.rstrip("/").casefold()


def get_role_assignments(
    identity_id: str,
    scope: str | None = None
) -> list[dict]:
    """
    Retrieve direct Azure RBAC role assignments for a principal
    at the exact resource scope.
    """

    if not identity_id:
        raise ValueError("An identity ID is required.")

    if not scope:
        raise ValueError("A resource scope is required.")

    assignments = authorization_client.role_assignments.list_for_scope(
        scope,
        filter=f"principalId eq '{identity_id}'"
    )

    results = []

    for assignment in assignments:
        principal_id = getattr(assignment, "principal_id", None)
        assignment_scope = getattr(assignment, "scope", None)

        if not principal_id or (
            principal_id.casefold() != identity_id.casefold()
        ):
            continue

        if not assignment_scope:
            continue

        if _normalize_scope(assignment_scope) != _normalize_scope(scope):
            continue

        results.append({
            "id": getattr(assignment, "id", None),
            "principal_id": principal_id,
            "role_definition_id": getattr(
                assignment,
                "role_definition_id",
                None
            ),
            "role_name": None,
            "scope": assignment_scope,
            "assignment_source": "DIRECT"
        })

    return results


def get_principal_role_assignments(principal_id: str) -> list[dict]:
    """Retrieve every role assignment held by a principal in the subscription."""

    if not principal_id:
        raise ValueError("A principal ID is required.")

    assignments = authorization_client.role_assignments.list_for_subscription(
        filter=f"principalId eq '{principal_id}'"
    )

    return [
        {
            "id": getattr(assignment, "id", None),
            "principal_id": getattr(assignment, "principal_id", None),
            "role_definition_id": getattr(assignment, "role_definition_id", None),
            "scope": getattr(assignment, "scope", None),
        }
        for assignment in assignments
        if str(getattr(assignment, "principal_id", "")).casefold()
        == principal_id.casefold()
    ]


def get_role_definition(role_definition_id: str) -> dict:
    """Retrieve role permissions and applicable data actions."""

    if not role_definition_id:
        raise ValueError("A role definition ID is required.")

    role_definition_guid = (
        role_definition_id.rstrip("/").rsplit("/", 1)[-1]
    )

    definition = authorization_client.role_definitions.get(
        f"/subscriptions/{subscription_id}",
        role_definition_guid
    )

    permissions = []

    for permission in definition.permissions or []:
        permissions.append({
            "actions": getattr(permission, "actions", None) or [],
            "not_actions": getattr(permission, "not_actions", None) or [],
            "data_actions": getattr(permission, "data_actions", None) or [],
            "not_data_actions": getattr(
                permission,
                "not_data_actions",
                None
            ) or []
        })

    return {
        "id": definition.id,
        "name": definition.role_name,
        "permissions": permissions
    }
