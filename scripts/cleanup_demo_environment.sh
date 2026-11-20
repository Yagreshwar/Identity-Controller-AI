
#!/usr/bin/env bash

set -euo pipefail

: "${AZURE_SUBSCRIPTION_ID:?Set AZURE_SUBSCRIPTION_ID}"
: "${AZURE_RESOURCE_GROUP:?Set AZURE_RESOURCE_GROUP}"

if ! command -v az >/dev/null 2>&1; then
    echo "ERROR: Azure CLI is required."
    exit 1
fi

if ! az account show >/dev/null 2>&1; then
    echo "ERROR: Azure login required. Run az login."
    exit 1
fi

az account set --subscription "$AZURE_SUBSCRIPTION_ID"

echo "WARNING: This will permanently delete the resource group:"
echo "$AZURE_RESOURCE_GROUP"
echo "Subscription: $AZURE_SUBSCRIPTION_ID"

read -r -p "Type the exact resource group name to confirm deletion: " confirmation

if [[ "$confirmation" != "$AZURE_RESOURCE_GROUP" ]]; then
    echo "Deletion cancelled."
    exit 0
fi

az group delete \
    --name "$AZURE_RESOURCE_GROUP" \
    --subscription "$AZURE_SUBSCRIPTION_ID" \
    --yes

echo "Demo resource group deletion requested."
