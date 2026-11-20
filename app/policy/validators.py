
def validate_remediation_request(
    role_assignment_id: str,
    already_executed: bool
) -> dict:
    """
    Validate that a remediation request targets
    one specific role assignment.
    """

    if not role_assignment_id:
        return {
            "valid": False,
            "reason": "Role assignment ID is required"
        }

    if role_assignment_id == "*":
        return {
            "valid": False,
            "reason": "Wildcard operations are not allowed"
        }

    if already_executed:
        return {
            "valid": False,
            "reason": "Duplicate execution is not allowed"
        }

    return {
        "valid": True,
        "reason": "Remediation request is valid"
    }
