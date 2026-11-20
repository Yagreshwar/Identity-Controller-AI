
def _normalize(value: object) -> str:
    return str(value or "").rstrip("/").casefold()


def check_legitimate_access(
    before: list | None,
    after: list | None,
) -> dict:
    """Confirm the active developer's role assignments are unchanged."""

    if before is None or after is None:
        return {
            "status": "UNKNOWN",
            "message": "The active developer's access could not be checked.",
        }

    missing = {
        _normalize(item.get("id")) for item in before
    } - {
        _normalize(item.get("id")) for item in after
    }

    if missing:
        return {
            "status": "CHANGED",
            "message": "One or more of the active developer's role assignments are missing.",
        }

    return {
        "status": "INTACT",
        "message": "The active developer's role assignments remain intact.",
    }


def verify_remediation(
    target_assignment_id: str,
    current_role_assignments: list | None,
    other_access_paths: list | None,
    access_test_result: bool | None,
    simulated: bool = False,
) -> dict:
    """
    Verify removal of the target assignment and check
    supported alternative access paths.
    """

    if not target_assignment_id:
        return {
            "status": "VERIFICATION_INCONCLUSIVE",
            "message": "Target assignment ID is missing."
        }

    if current_role_assignments is None:
        return {
            "status": "VERIFICATION_INCONCLUSIVE",
            "message": "Unable to retrieve current role assignments."
        }

    target = _normalize(target_assignment_id)

    if any(
        _normalize(assignment.get("id")) == target
        for assignment in current_role_assignments
    ):
        return {
            "status": "ACCESS_STILL_PRESENT",
            "message": (
                "Simulation mode: the target role assignment was intentionally "
                "left in place and still exists."
                if simulated
                else "Target role assignment still exists."
            )
        }

    if other_access_paths is None or access_test_result is None:
        return {
            "status": "REMEDIATION_EXECUTED_VERIFICATION_PENDING",
            "message": "Target assignment is absent, but complete access verification is pending."
        }

    if other_access_paths or access_test_result:
        return {
            "status": "ACCESS_STILL_PRESENT",
            "message": "Access remains through another supported access path or the access test."
        }

    return {
        "status": "REMEDIATION_VERIFIED",
        "message": "Target assignment is absent and supported access checks confirm access denial."
    }
