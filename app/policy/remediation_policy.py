def is_remediation_eligible(
    approval_status: str,
    project_status: str,
    evidence_complete: bool,
    assignment_type: str,
    role_assignment_id: str
) -> dict:
    """
    Determine whether a specific role assignment
    is eligible for remediation.
    """

    if not role_assignment_id or role_assignment_id == "*":
        return {
            "eligible": False,
            "reason": "A specific role assignment ID is required."
        }

    if (approval_status or "").upper() != "APPROVED":
        return {
            "eligible": False,
            "reason": "Valid human approval is required."
        }

    if (project_status or "").lower() == "active":
        return {
            "eligible": False,
            "reason": "Active project access must not be revoked."
        }

    if not evidence_complete:
        return {
            "eligible": False,
            "reason": "Missing evidence blocks remediation."
        }

    if (assignment_type or "").lower() != "direct":
        return {
            "eligible": False,
            "reason": "Only direct role assignments are eligible."
        }

    return {
        "eligible": True,
        "reason": "Eligible for specific role-assignment remediation."
    }
