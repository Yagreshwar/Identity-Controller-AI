import os

from dotenv import load_dotenv

load_dotenv()


AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

AZURE_AI_FOUNDRY_ENDPOINT = os.getenv("AZURE_AI_ENDPOINT")
AZURE_AI_FOUNDRY_API_KEY = os.getenv("AZURE_AI_FOUNDRY_API_KEY")
AZURE_AI_MODEL_DEPLOYMENT_NAME = os.getenv("AZURE_AI_DEPLOYMENT_NAME")

LOG_ANALYTICS_WORKSPACE_ID = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")

# A resource inside the dedicated demo resource group. Remediation is
# restricted to that resource group.
AZURE_STORAGE_SCOPE = os.getenv("AZURE_STORAGE_SCOPE")

# Discovery identity: read-only access to directory, resource and RBAC data.
DISCOVERY_MANAGED_IDENTITY_CLIENT_ID = os.getenv(
    "DISCOVERY_MANAGED_IDENTITY_CLIENT_ID"
)

# Remediation identity: separate managed identity with narrowly scoped
# write access to the dedicated demo scope.
REMEDIATION_MANAGED_IDENTITY_CLIENT_ID = os.getenv(
    "REMEDIATION_MANAGED_IDENTITY_CLIENT_ID"
)
REMEDIATION_MANAGED_IDENTITY_PRINCIPAL_ID = os.getenv(
    "REMEDIATION_MANAGED_IDENTITY_PRINCIPAL_ID"
)

if (
    DISCOVERY_MANAGED_IDENTITY_CLIENT_ID
    and REMEDIATION_MANAGED_IDENTITY_CLIENT_ID
    and DISCOVERY_MANAGED_IDENTITY_CLIENT_ID.casefold()
    == REMEDIATION_MANAGED_IDENTITY_CLIENT_ID.casefold()
):
    raise ValueError(
        "The remediation managed identity must be distinct from the "
        "discovery managed identity."
    )

# Controlled access test: a designated blob that the identity under test was
# previously permitted to read.
ACCESS_TEST_CONTAINER = os.getenv("ACCESS_TEST_CONTAINER")
ACCESS_TEST_BLOB = os.getenv("ACCESS_TEST_BLOB")

# Active developer whose legitimate access must remain intact.
ACTIVE_DEVELOPER_OBJECT_ID = (
    os.getenv("ACTIVE_DEVELOPER_OBJECT_ID")
    or os.getenv("PRIYA_OBJECT_ID")
)

# Microsoft Entra ID authentication
ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")
ENTRA_TENANT_ID = os.getenv("AZURE_TENANT_ID")
ENTRA_AUTHORITY = (
    f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}"
    if ENTRA_TENANT_ID
    else None
)
