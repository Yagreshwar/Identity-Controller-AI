
from app.investigation.activity_analysis import classify_activity


def test_activity_confirmed():
    assert classify_activity(True, True, True) == "ACTIVITY_CONFIRMED"


def test_telemetry_unavailable():
    assert classify_activity(False, False, False) == "TELEMETRY_UNAVAILABLE"


def test_insufficient_coverage():
    assert classify_activity(False, True, False) == "INSUFFICIENT_COVERAGE"


def test_no_activity_observed():
    assert classify_activity(False, True, True) == "NO_ACTIVITY_OBSERVED"
