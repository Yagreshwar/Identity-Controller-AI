from azure.identity import DefaultAzureCredential

from app.config import DISCOVERY_MANAGED_IDENTITY_CLIENT_ID

# Read-only discovery identity shared by all investigation connectors.
# In Azure it resolves to the discovery user-assigned managed identity.
discovery_credential = DefaultAzureCredential(
    managed_identity_client_id=DISCOVERY_MANAGED_IDENTITY_CLIENT_ID
)
