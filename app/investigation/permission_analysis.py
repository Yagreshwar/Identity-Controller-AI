
def _is_write_capable(capability: str) -> bool:
    normalized = capability.casefold()

    return "*" in normalized or normalized.endswith(("/write", "/delete"))


def analyze_permissions(role_definition: dict) -> dict:
    """
    Analyze Azure RBAC role permissions, including exclusions.
    """

    if not role_definition:
        return {
            "status": "ROLE_DEFINITION_UNAVAILABLE",
            "permission_level": None,
            "write_capable": None,
            "capabilities": [],
            "excluded_capabilities": []
        }

    capabilities = []
    excluded_capabilities = []

    for permission in role_definition.get("permissions", []):
        capabilities.extend(permission.get("actions") or [])
        capabilities.extend(permission.get("data_actions") or [])

        excluded_capabilities.extend(
            permission.get("not_actions") or []
        )
        excluded_capabilities.extend(
            permission.get("not_data_actions") or []
        )

    capabilities = list(dict.fromkeys(capabilities))
    excluded_capabilities = list(
        dict.fromkeys(excluded_capabilities)
    )

    if not capabilities:
        return {
            "status": "NO_PERMISSION_DETAILS",
            "permission_level": None,
            "write_capable": None,
            "capabilities": [],
            "excluded_capabilities": excluded_capabilities
        }

    has_wildcard = any(
        "*" in capability
        for capability in capabilities
    )

    permission_level = (
        "BROAD" if has_wildcard else "SPECIFIC"
    )

    excluded = {item.casefold() for item in excluded_capabilities}

    write_capable = any(
        _is_write_capable(capability)
        and capability.casefold() not in excluded
        for capability in capabilities
    )

    return {
        "status": "ANALYZED",
        "permission_level": permission_level,
        "write_capable": write_capable,
        "capabilities": capabilities,
        "excluded_capabilities": excluded_capabilities
    }
