
def analyze_identity(identity: dict) -> dict:
    """
    Extract relevant identity details
    returned by Microsoft Entra ID.
    """

    return {
        "object_id": identity.get("id"),
        "display_name": identity.get("displayName"),
        "user_principal_name": identity.get("userPrincipalName"),
        "account_enabled": identity.get("accountEnabled"),
        "identity_type": identity.get("identity_type"),
        "department": identity.get("department")
    }
