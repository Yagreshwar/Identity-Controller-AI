
def classify_activity(
    activity_observed: bool,
    telemetry_available: bool,
    coverage_complete: bool
) -> str:
    """
    Classify available access activity evidence.
    """

    if activity_observed:
        return "ACTIVITY_CONFIRMED"

    if not telemetry_available:
        return "TELEMETRY_UNAVAILABLE"

    if not coverage_complete:
        return "INSUFFICIENT_COVERAGE"

    return "NO_ACTIVITY_OBSERVED"
