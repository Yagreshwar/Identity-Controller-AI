
#!/usr/bin/env bash

set -euo pipefail

# Required Azure configuration
: "${AZURE_SUBSCRIPTION_ID:?Set AZURE_SUBSCRIPTION_ID}"
: "${AZURE_LOCATION:?Set AZURE_LOCATION}"
: "${AZURE_RESOURCE_GROUP:?Set AZURE_RESOURCE_GROUP}"
: "${AZURE_STORAGE_ACCOUNT:?Set AZURE_STORAGE_ACCOUNT}"
: "${AZURE_WORKSPACE_NAME:?Set AZURE_WORKSPACE_NAME}"

# Required tools
for command in az jq; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $command"
        exit 1
    fi
done

# Verify Azure login
if ! az account show >/dev/null 2>&1; then
    echo "ERROR: Azure login required. Run az login."
    exit 1
fi

# Select subscription
az account set --subscription "$AZURE_SUBSCRIPTION_ID"

echo "Creating demo environment..."

# Create dedicated resource group
az group create \
    --name "$AZURE_RESOURCE_GROUP" \
    --location "$AZURE_LOCATION" \
    --output none

# Create storage account if it does not exist
if ! az storage account show \
    --name "$AZURE_STORAGE_ACCOUNT" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    >/dev/null 2>&1; then

    az storage account create \
        --name "$AZURE_STORAGE_ACCOUNT" \
        --resource-group "$AZURE_RESOURCE_GROUP" \
        --location "$AZURE_LOCATION" \
        --sku Standard_LRS \
        --kind StorageV2 \
        --https-only true \
        --min-tls-version TLS1_2 \
        --allow-blob-public-access false \
        --output none
fi

# Create Log Analytics workspace
if ! az monitor log-analytics workspace show \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --workspace-name "$AZURE_WORKSPACE_NAME" \
    >/dev/null 2>&1; then

    az monitor log-analytics workspace create \
        --resource-group "$AZURE_RESOURCE_GROUP" \
        --workspace-name "$AZURE_WORKSPACE_NAME" \
        --location "$AZURE_LOCATION" \
        --output none
fi

# Configure Blob Storage diagnostic logging
STORAGE_ID=$(az storage account show \
    --name "$AZURE_STORAGE_ACCOUNT" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --query id -o tsv)

WORKSPACE_ID=$(az monitor log-analytics workspace show \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --workspace-name "$AZURE_WORKSPACE_NAME" \
    --query id -o tsv)

BLOB_SERVICE_ID="${STORAGE_ID}/blobServices/default"

CATEGORIES=$(az monitor diagnostic-settings categories list \
    --resource "$BLOB_SERVICE_ID" \
    --output json)

LOGS_JSON=$(echo "$CATEGORIES" | jq -c '
    [(.value // .)[] |
    select(.categoryType == "Logs") |
    select(.name == "StorageRead"
        or .name == "StorageWrite"
        or .name == "StorageDelete") |
    {category: .name, enabled: true}]
')

if [[ "$LOGS_JSON" == "[]" ]]; then
    echo "ERROR: No supported Blob diagnostic categories found."
    exit 1
fi

az monitor diagnostic-settings create \
    --name "identity-commander-storage-logs" \
    --resource "$BLOB_SERVICE_ID" \
    --workspace "$WORKSPACE_ID" \
    --logs "$LOGS_JSON" \
    --output none

echo "Demo infrastructure setup completed."
echo "Resource Group: $AZURE_RESOURCE_GROUP"
echo "Storage Account: $AZURE_STORAGE_ACCOUNT"
echo "Log Analytics Workspace: $AZURE_WORKSPACE_NAME"
