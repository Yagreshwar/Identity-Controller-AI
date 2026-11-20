
import requests
from app.connectors.credentials import discovery_credential

GRAPH_URL = "https://graph.microsoft.com/v1.0"
credential = discovery_credential


def get_identity_memberships(identity_id: str) -> list:
    """
    Retrieve group memberships for a user or service principal.
    """
    token = credential.get_token(
        "https://graph.microsoft.com/.default"
    ).token

    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(
        f"{GRAPH_URL}/users/{identity_id}/memberOf",
        headers=headers,
        params={"$select": "id,displayName"},
        timeout=30
    )

    if response.status_code == 404:
        response = requests.get(
            f"{GRAPH_URL}/servicePrincipals/{identity_id}/memberOf",
            headers=headers,
            params={"$select": "id,displayName"},
            timeout=30
        )

    response.raise_for_status()

    return [
        {
            "group_id": item.get("id"),
            "group_name": item.get("displayName")
        }
        for item in response.json().get("value", [])
        if item.get("@odata.type") == "#microsoft.graph.group"
    ]
