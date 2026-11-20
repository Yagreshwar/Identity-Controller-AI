import uuid

import requests
from app.connectors.credentials import discovery_credential

GRAPH_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
REQUEST_TIMEOUT = 30

credential = discovery_credential


def _get_headers() -> dict:
    token = credential.get_token(GRAPH_SCOPE).token
    return {"Authorization": f"Bearer {token}"}


def _escape_odata(value: str) -> str:
    return value.replace("'", "''")


def _is_guid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _get_all_pages(
    url: str,
    headers: dict,
    params: dict | None = None,
) -> list[dict]:
    """Retrieve all pages returned by Microsoft Graph."""
    results = []

    while url:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        data = response.json()
        results.extend(data.get("value", []))

        url = data.get("@odata.nextLink")
        params = None

    return results


def get_identity_details(identity_id: str) -> dict:
    """
    Retrieve user or service principal details
    from Microsoft Entra ID.
    """
    if not identity_id or not identity_id.strip():
        raise ValueError("Identity ID cannot be empty.")

    headers = _get_headers()

    response = requests.get(
        f"{GRAPH_URL}/users/{identity_id}",
        headers=headers,
        params={
            "$select": (
                "id,displayName,userPrincipalName,"
                "accountEnabled,department"
            )
        },
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code == 404:
        response = requests.get(
            f"{GRAPH_URL}/servicePrincipals/{identity_id}",
            headers=headers,
            params={
                "$select": "id,displayName,accountEnabled,appId"
            },
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()
        identity = response.json()

        return {
            "object_id": identity.get("id"),
            "display_name": identity.get("displayName"),
            "user_principal_name": None,
            "account_enabled": identity.get("accountEnabled"),
            "identity_type": "SERVICE_PRINCIPAL",
            "department": None,
        }

    response.raise_for_status()
    identity = response.json()

    return {
        "object_id": identity.get("id"),
        "display_name": identity.get("displayName"),
        "user_principal_name": identity.get("userPrincipalName"),
        "account_enabled": identity.get("accountEnabled"),
        "identity_type": "USER",
        "department": identity.get("department"),
    }


def search_identity(name: str) -> list[dict]:
    """
    Search Entra users and service principals by
    exact display name, email, UPN or application ID.
    """
    if not name or not name.strip():
        raise ValueError("Search term cannot be empty.")

    search_term = name.strip()
    escaped_term = _escape_odata(search_term)
    headers = _get_headers()

    results = []

    # Search users by display name, UPN or email.
    user_filter = (
        f"displayName eq '{escaped_term}' "
        f"or userPrincipalName eq '{escaped_term}' "
        f"or mail eq '{escaped_term}'"
    )

    users = _get_all_pages(
        f"{GRAPH_URL}/users",
        headers,
        {
            "$filter": user_filter,
            "$select": (
                "id,displayName,userPrincipalName,"
                "accountEnabled,department"
            ),
        },
    )

    for item in users:
        results.append({
            "object_id": item["id"],
            "display_name": item.get("displayName"),
            "user_principal_name": item.get("userPrincipalName"),
            "account_enabled": item.get("accountEnabled"),
            "identity_type": "USER",
            "department": item.get("department"),
        })

    # appId only accepts a GUID. A name or email in that clause makes
    # Microsoft Graph reject the whole search.
    service_principal_filter = f"displayName eq '{escaped_term}'"
    if _is_guid(search_term):
        service_principal_filter += f" or appId eq '{escaped_term}'"

    service_principals = _get_all_pages(
        f"{GRAPH_URL}/servicePrincipals",
        headers,
        {
            "$filter": service_principal_filter,
            "$select": "id,displayName,accountEnabled,appId",
        },
    )

    for item in service_principals:
        results.append({
            "object_id": item["id"],
            "display_name": item.get("displayName"),
            "user_principal_name": None,
            "account_enabled": item.get("accountEnabled"),
            "identity_type": "SERVICE_PRINCIPAL",
            "department": None,
        })

    return results


