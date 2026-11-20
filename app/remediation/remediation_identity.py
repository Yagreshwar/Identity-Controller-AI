import re
from functools import lru_cache

from azure.core.exceptions import AzureError
from azure.identity import ManagedIdentityCredential
from azure.mgmt.authorization import AuthorizationManagementClient

from app.config import (
    AZURE_STORAGE_SCOPE,
    AZURE_SUBSCRIPTION_ID,
    DISCOVERY_MANAGED_IDENTITY_CLIENT_ID,
    REMEDIATION_MANAGED_IDENTITY_CLIENT_ID,
    REMEDIATION_MANAGED_IDENTITY_PRINCIPAL_ID,
)
from app.connectors.rbac_client import (
    get_principal_role_assignments,
    get_role_definition,
)
from app.investigation.permission_analysis import analyze_permissions


class RemediationIdentityError(RuntimeError):
    """The remediation managed identity is unavailable or misconfigured."""


_ROLE_ASSIGNMENT_MARKER = "/providers/microsoft.authorization/roleassignments/"


def _normalize(value: object) -> str:
    return str(value or "").rstrip("/").casefold()


def _demo_resource_group_scope() -> str:
    """
    The dedicated demo resource group that contains AZURE_STORAGE_SCOPE.
    Remediation is limited to this group, not to one resource inside it.
    """
    match = re.match(
        r"^(/subscriptions/[^/]+/resourcegroups/[^/]+)(/|$)",
        _normalize(AZURE_STORAGE_SCOPE),
    )
    if not match:
        raise RemediationIdentityError(
            "AZURE_STORAGE_SCOPE must point to a resource inside a resource group."
        )
    return match.group(1)


def _is_within(scope: object, boundary: str) -> bool:
    normalized = _normalize(scope)
    return normalized == boundary or normalized.startswith(f"{boundary}/")


def _validate_configuration() -> None:
    if not REMEDIATION_MANAGED_IDENTITY_CLIENT_ID:
        raise RemediationIdentityError(
            "REMEDIATION_MANAGED_IDENTITY_CLIENT_ID is not configured."
        )

    if not REMEDIATION_MANAGED_IDENTITY_PRINCIPAL_ID:
        raise RemediationIdentityError(
            "REMEDIATION_MANAGED_IDENTITY_PRINCIPAL_ID is not configured."
        )

    if not AZURE_STORAGE_SCOPE:
        raise RemediationIdentityError("AZURE_STORAGE_SCOPE is not configured.")

    _demo_resource_group_scope()

    if _normalize(REMEDIATION_MANAGED_IDENTITY_CLIENT_ID) == _normalize(
        DISCOVERY_MANAGED_IDENTITY_CLIENT_ID
    ):
        raise RemediationIdentityError(
            "The remediation managed identity must be distinct from the "
            "discovery managed identity."
        )


@lru_cache(maxsize=1)
def get_remediation_client() -> AuthorizationManagementClient:
    """Authorization client authenticated only as the remediation identity."""

    _validate_configuration()

    credential = ManagedIdentityCredential(
        client_id=REMEDIATION_MANAGED_IDENTITY_CLIENT_ID
    )

    return AuthorizationManagementClient(credential, AZURE_SUBSCRIPTION_ID)


def validate_remediation_permissions() -> None:
    """
    Confirm the remediation identity holds only narrowly scoped access
    restricted to the dedicated demo scope.
    """

    demo_group = _demo_resource_group_scope()

    try:
        assignments = get_principal_role_assignments(
            REMEDIATION_MANAGED_IDENTITY_PRINCIPAL_ID
        )
    except Exception as exc:
        raise RemediationIdentityError(
            "Could not verify the remediation identity's role assignments."
        ) from exc

    if not assignments:
        raise RemediationIdentityError(
            "The remediation identity has no role assignment at the demo scope."
        )

    for assignment in assignments:
        if not _is_within(assignment.get("scope"), demo_group):
            raise RemediationIdentityError(
                "The remediation identity has access outside the dedicated "
                "demo scope."
            )

        try:
            role_definition = get_role_definition(
                assignment.get("role_definition_id")
            )
        except Exception as exc:
            raise RemediationIdentityError(
                "Could not verify the remediation identity's role definition."
            ) from exc

        if analyze_permissions(role_definition).get("permission_level") == "BROAD":
            raise RemediationIdentityError(
                "The remediation identity holds broader permissions than the "
                "demo requires."
            )


def confirm_target_with_remediation_identity(
    role_assignment_id: str,
    resource_scope: str,
) -> dict:
    """
    Authenticate as the remediation identity and confirm the approved role
    assignment is within the demo scope and visible to it. Role-assignment
    deletion is disabled for this POC, so no write operation is performed.
    """

    _validate_configuration()

    demo_group = _demo_resource_group_scope()

    if not _is_within(resource_scope, demo_group):
        raise RemediationIdentityError(
            "Remediation is restricted to the dedicated demo scope."
        )

    assignment_scope, _, assignment_name = _normalize(
        role_assignment_id
    ).rpartition(_ROLE_ASSIGNMENT_MARKER)

    if not assignment_scope or not assignment_name or "/" in assignment_name:
        raise RemediationIdentityError(
            "The role assignment does not belong to the dedicated demo scope."
        )

    if not _is_within(assignment_scope, demo_group):
        raise RemediationIdentityError(
            "The role assignment does not belong to the dedicated demo scope."
        )

    if assignment_scope != _normalize(resource_scope):
        raise RemediationIdentityError(
            "The role assignment does not belong to the approved resource scope."
        )

    validate_remediation_permissions()

    try:
        assignment = get_remediation_client().role_assignments.get_by_id(
            role_assignment_id
        )
    except AzureError as exc:
        raise RemediationIdentityError(
            "The remediation identity could not access the approved role "
            "assignment."
        ) from exc

    if _normalize(getattr(assignment, "id", None)) != _normalize(
        role_assignment_id
    ):
        raise RemediationIdentityError(
            "The remediation identity returned a different role assignment."
        )

    return {
        "remediation_identity": REMEDIATION_MANAGED_IDENTITY_CLIENT_ID,
        "role_assignment_id": assignment.id,
    }
