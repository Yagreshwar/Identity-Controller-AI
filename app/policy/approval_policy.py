def evaluate_approval_eligibility(
    risk_result: dict,
    evidence_complete: bool,
    project_status: str,
    assignment_type: str,
) -> dict:
    """Determine whether a finding can proceed to administrator approval."""

    def result(eligible: bool, status: str, reason: str) -> dict:
        return {
            "eligible": eligible,
            "approval_required": eligible,
            "status": status,
            "reason": reason,
        }

    if not evidence_complete:
        return result(False, "REVIEW_ONLY", "Missing or incomplete evidence.")

    if not risk_result:
        return result(False, "REVIEW_ONLY", "Risk assessment is unavailable.")

    if (project_status or "").casefold() != "completed":
        return result(False, "REVIEW_ONLY", "Only completed projects are eligible.")

    if (assignment_type or "").upper() != "DIRECT":
        return result(False, "REVIEW_ONLY", "Only direct role assignments are eligible.")

    if (
        risk_result.get("risk_level") == "HIGH"
        and risk_result.get("status") == "REVIEW_REQUIRED"
        and risk_result.get("finding_type") == "STALE_PRODUCTION_ACCESS"
    ):
        return result(
            True,
            "PENDING_APPROVAL",
            "Stale production access requires authorized administrator approval.",
        )

    return result(False, "REVIEW_ONLY", "Finding does not meet approval criteria.")
