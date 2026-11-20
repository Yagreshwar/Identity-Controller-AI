
from datetime import UTC, date, datetime, time, timedelta


def _get_value(data, key, default=None):
    if isinstance(data, dict):
        return data.get(key, default)
    return getattr(data, key, default)


def _get_identity_type(identity):
    identity_type = (
        _get_value(identity, "identity_type")
        or _get_value(identity, "type")
        or ""
    )
    return str(identity_type).strip().upper().replace("-", "_")


def _result(risk_level, finding_type, status, reason):
    return {
        "risk_level": risk_level,
        "finding_type": finding_type,
        "status": status,
        "reason": reason
    }


def evaluate_access_risk(identity, project, assignment, activity):
    if not assignment:
        return _result(
            "UNKNOWN",
            "NO_DIRECT_ASSIGNMENT",
            "REVIEW_ONLY",
            "No direct role assignment was found at the investigated scope."
        )

    identity_type = _get_identity_type(identity)

    # Service principals remain review-only in the initial POC.
    if identity_type in {"SERVICE_PRINCIPAL", "APPLICATION"}:
        return _result(
            "UNKNOWN",
            "SERVICE_IDENTITY_ACCESS",
            "REVIEW_ONLY",
            "Service identity access requires review of application dependencies before remediation."
        )

    project_status = str(
        _get_value(project, "status", "")
    ).strip().lower()

    activity_status = str(
        _get_value(activity, "status", "")
    ).strip().upper()

    if project_status == "active":
        return _result(
            "LOW",
            "ACTIVE_PROJECT_ACCESS",
            "REVIEW_ONLY",
            "The associated project is active. No access removal is recommended."
        )

    if project_status != "completed":
        return _result(
            "UNKNOWN",
            "INSUFFICIENT_PROJECT_CONTEXT",
            "REVIEW_ONLY",
            "Project status is missing or unrecognized."
        )

    end_date_value = _get_value(project, "end_date")

    if not end_date_value:
        return _result(
            "UNKNOWN",
            "MISSING_PROJECT_END_DATE",
            "REVIEW_ONLY",
            "The completed project's end date is unavailable."
        )

    try:
        if isinstance(end_date_value, str):
            project_end_date = date.fromisoformat(end_date_value)
        elif isinstance(end_date_value, datetime):
            project_end_date = end_date_value.date()
        elif isinstance(end_date_value, date):
            project_end_date = end_date_value
        else:
            raise ValueError("Unsupported project end-date format.")
    except (TypeError, ValueError):
        return _result(
            "UNKNOWN",
            "INVALID_PROJECT_END_DATE",
            "REVIEW_ONLY",
            "The project end date is invalid."
        )

    observation_start = datetime.combine(
        project_end_date + timedelta(days=1),
        time.min,
        tzinfo=UTC
    )

    if datetime.now(UTC) < observation_start:
        return _result(
            "UNKNOWN",
            "POST_PROJECT_WINDOW_NOT_STARTED",
            "REVIEW_ONLY",
            "The post-project observation period has not started."
        )

    if activity_status == "NO_ACTIVITY_OBSERVED":
        return _result(
            "HIGH",
            "STALE_PRODUCTION_ACCESS",
            "REVIEW_REQUIRED",
            "No successful activity was observed after project completion in the configured diagnostic logs. This is evidence for owner review, not proof that access is unnecessary."
        )

    if activity_status == "ACTIVITY_CONFIRMED":
        return _result(
            "HIGH",
            "POST_PROJECT_ACTIVITY",
            "REVIEW_REQUIRED",
            "Successful activity was observed after project completion and requires investigation."
        )

    return _result(
        "UNKNOWN",
        "INSUFFICIENT_EVIDENCE",
        "REVIEW_ONLY",
        "Activity telemetry is unavailable or coverage is incomplete."
    )
