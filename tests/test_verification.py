
from app.remediation.verification import verify_remediation


def test_remediation_verified():
    current_role_assignments = [
        {"id": "assignment-002"},
        {"id": "assignment-003"}
    ]

    result = verify_remediation(
        "assignment-001",
        current_role_assignments,
        [],
        False
    )

    assert result["status"] == "REMEDIATION_VERIFIED"


def test_access_still_present():
    current_role_assignments = [
        {"id": "assignment-001"},
        {"id": "assignment-002"}
    ]

    result = verify_remediation(
        "assignment-001",
        current_role_assignments,
        [],
        False
    )

    assert result["status"] == "ACCESS_STILL_PRESENT"


def test_verification_inconclusive():
    result = verify_remediation(
        "assignment-001",
        None,
        None,
        None
    )

    assert result["status"] == "VERIFICATION_INCONCLUSIVE"


def test_verification_with_none():
    result = verify_remediation(
        "assignment-001",
        None,
        [],
        False
    )

    assert result["status"] == "VERIFICATION_INCONCLUSIVE"


def test_assignment_ids_compare_case_insensitively():
    result = verify_remediation(
        "/Subscriptions/Demo/RoleAssignments/A1",
        [{"id": "/subscriptions/demo/roleassignments/a1/"}],
        [],
        False,
    )

    assert result["status"] == "ACCESS_STILL_PRESENT"


def test_simulation_reports_assignment_left_in_place():
    result = verify_remediation(
        "assignment-001",
        [{"id": "assignment-001"}],
        [],
        None,
        simulated=True,
    )

    assert result["status"] == "ACCESS_STILL_PRESENT"
    assert "Simulation mode" in result["message"]


def test_residual_access_path_reported():
    result = verify_remediation(
        "assignment-001",
        [{"id": "assignment-002"}],
        [{"id": "assignment-002"}],
        False,
    )

    assert result["status"] == "ACCESS_STILL_PRESENT"


def test_pending_when_access_test_not_run():
    result = verify_remediation(
        "assignment-001",
        [],
        [],
        None,
    )

    assert result["status"] == "REMEDIATION_EXECUTED_VERIFICATION_PENDING"


def test_legitimate_access_intact():
    from app.remediation.verification import check_legitimate_access

    before = [{"id": "/a/1"}]

    assert check_legitimate_access(before, [{"id": "/A/1/"}])["status"] == "INTACT"
    assert check_legitimate_access(before, [])["status"] == "CHANGED"
    assert check_legitimate_access(None, [])["status"] == "UNKNOWN"
