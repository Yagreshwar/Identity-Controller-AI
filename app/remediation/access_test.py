from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError, HttpResponseError
from azure.storage.blob import BlobClient

ACCESS_ALLOWED = "ACCESS_ALLOWED"
ACCESS_DENIED = "ACCESS_DENIED"
INCONCLUSIVE = "INCONCLUSIVE"
NOT_PERFORMED = "NOT_PERFORMED"


def get_access_test_credential(identity_id: str) -> TokenCredential | None:
    """
    Credential used to act as the identity under test. No credential source
    is configured yet, so the controlled access test reports NOT_PERFORMED.
    """

    return None


def storage_account_url(resource_scope: str) -> str:
    parts = resource_scope.rstrip("/").split("/")
    lowered = [part.casefold() for part in parts]

    try:
        account_name = parts[lowered.index("storageaccounts") + 1]
    except (ValueError, IndexError) as exc:
        raise ValueError(
            "The resource scope is not an Azure Storage account."
        ) from exc

    return f"https://{account_name}.blob.core.windows.net"


def run_controlled_access_test(
    resource_scope: str,
    container: str | None,
    blob_name: str | None,
    credential: TokenCredential | None,
) -> dict:
    """
    Attempt the previously permitted storage operation (reading the
    designated test blob's properties) as the identity under test.
    The operation is read-only and never modifies the blob.
    """

    if credential is None:
        return {
            "status": NOT_PERFORMED,
            "reason": "No credential is available for the identity under test.",
        }

    if not container or not blob_name:
        return {
            "status": NOT_PERFORMED,
            "reason": "The controlled access test blob is not configured.",
        }

    blob = BlobClient(
        account_url=storage_account_url(resource_scope),
        container_name=container,
        blob_name=blob_name,
        credential=credential,
    )

    try:
        blob.get_blob_properties()
    except HttpResponseError as exc:
        if exc.status_code == 403:
            return {
                "status": ACCESS_DENIED,
                "reason": "The storage operation was denied.",
            }

        return {
            "status": INCONCLUSIVE,
            "reason": f"The storage operation returned HTTP {exc.status_code}.",
        }
    except AzureError:
        return {
            "status": INCONCLUSIVE,
            "reason": "The storage operation could not be completed.",
        }

    return {
        "status": ACCESS_ALLOWED,
        "reason": "The storage operation succeeded.",
    }


def access_test_result(test: dict) -> bool | None:
    """Map a controlled access test to verify_remediation's input."""

    if test.get("status") == ACCESS_ALLOWED:
        return True

    if test.get("status") == ACCESS_DENIED:
        return False

    return None
