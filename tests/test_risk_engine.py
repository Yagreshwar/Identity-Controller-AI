from datetime import date, timedelta
from types import SimpleNamespace

from app.investigation.risk_engine import evaluate_access_risk


def test_no_direct_assignment():
    result = evaluate_access_risk(None, None, None, None)

    assert result["finding_type"] == "NO_DIRECT_ASSIGNMENT"
    assert result["status"] == "REVIEW_ONLY"


def test_completed_project_no_activity():
    project = SimpleNamespace(
        status="completed",
        end_date=date.today() - timedelta(days=2),
    )
    activity = SimpleNamespace(status="NO_ACTIVITY_OBSERVED")

    result = evaluate_access_risk(None, project, True, activity)

    assert result["risk_level"] == "HIGH"
    assert result["finding_type"] == "STALE_PRODUCTION_ACCESS"
    assert result["status"] == "REVIEW_REQUIRED"


def test_telemetry_unavailable():
    project = SimpleNamespace(
        status="completed",
        end_date=date.today() - timedelta(days=2),
    )
    activity = SimpleNamespace(status="TELEMETRY_UNAVAILABLE")

    result = evaluate_access_risk(None, project, True, activity)

    assert result["finding_type"] == "INSUFFICIENT_EVIDENCE"
    assert result["status"] == "REVIEW_ONLY"


def test_insufficient_coverage():
    project = SimpleNamespace(
        status="completed",
        end_date=date.today() - timedelta(days=2),
    )
    activity = SimpleNamespace(status="INSUFFICIENT_COVERAGE")

    result = evaluate_access_risk(None, project, True, activity)

    assert result["finding_type"] == "INSUFFICIENT_EVIDENCE"
    assert result["status"] == "REVIEW_ONLY"


def test_active_project():
    project = SimpleNamespace(status="active")
    activity = SimpleNamespace(status="NO_ACTIVITY_OBSERVED")

    result = evaluate_access_risk(None, project, True, activity)

    assert result["finding_type"] == "ACTIVE_PROJECT_ACCESS"
    assert result["status"] == "REVIEW_ONLY"


def completed_project(days_ago=2):
    return SimpleNamespace(
        status="completed",
        end_date=date.today() - timedelta(days=days_ago),
    )


def test_service_principal_is_review_only():
    identity = {"identity_type": "SERVICE_PRINCIPAL"}
    activity = SimpleNamespace(status="NO_ACTIVITY_OBSERVED")

    result = evaluate_access_risk(identity, completed_project(), True, activity)

    assert result["finding_type"] == "SERVICE_IDENTITY_ACCESS"
    assert result["status"] == "REVIEW_ONLY"


def test_post_project_data_activity_requires_review():
    activity = SimpleNamespace(status="ACTIVITY_CONFIRMED")

    result = evaluate_access_risk(None, completed_project(), True, activity)

    assert result["finding_type"] == "POST_PROJECT_ACTIVITY"
    assert result["status"] == "REVIEW_REQUIRED"


def test_post_project_window_not_started():
    project = SimpleNamespace(status="completed", end_date=date.today())
    activity = SimpleNamespace(status="NO_ACTIVITY_OBSERVED")

    result = evaluate_access_risk(None, project, True, activity)

    assert result["finding_type"] == "POST_PROJECT_WINDOW_NOT_STARTED"


def test_missing_project_status_is_insufficient_context():
    result = evaluate_access_risk(None, SimpleNamespace(status=""), True, None)

    assert result["finding_type"] == "INSUFFICIENT_PROJECT_CONTEXT"
