import pytest

from app.policy.approval_policy import evaluate_approval_eligibility
from app.policy.remediation_policy import is_remediation_eligible
from app.policy.validators import validate_remediation_request

STALE_HIGH = {
    "risk_level": "HIGH",
    "status": "REVIEW_REQUIRED",
    "finding_type": "STALE_PRODUCTION_ACCESS",
}


def test_stale_high_direct_completed_requires_approval():
    result = evaluate_approval_eligibility(STALE_HIGH, True, "completed", "DIRECT")

    assert result["eligible"] is True
    assert result["approval_required"] is True
    assert result["status"] == "PENDING_APPROVAL"


@pytest.mark.parametrize(
    ("risk", "evidence_complete", "project_status", "assignment_type"),
    [
        (STALE_HIGH, False, "completed", "DIRECT"),
        ({}, True, "completed", "DIRECT"),
        (STALE_HIGH, True, "active", "DIRECT"),
        (STALE_HIGH, True, "completed", "INHERITED"),
        ({**STALE_HIGH, "risk_level": "MEDIUM"}, True, "completed", "DIRECT"),
        ({**STALE_HIGH, "finding_type": "POST_PROJECT_ACTIVITY"}, True, "completed", "DIRECT"),
    ],
    ids=[
        "missing-evidence",
        "no-risk",
        "active-project",
        "not-direct",
        "medium-risk",
        "post-project-activity",
    ],
)
def test_ineligible_findings_remain_review_only(
    risk, evidence_complete, project_status, assignment_type
):
    result = evaluate_approval_eligibility(
        risk, evidence_complete, project_status, assignment_type
    )

    assert result["eligible"] is False
    assert result["status"] == "REVIEW_ONLY"


def test_remediation_policy_accepts_specific_approved_direct_assignment():
    result = is_remediation_eligible("APPROVED", "completed", True, "DIRECT", "id-1")

    assert result["eligible"] is True


@pytest.mark.parametrize(
    ("approval_status", "project_status", "evidence_complete", "assignment_type", "assignment_id", "reason"),
    [
        ("APPROVED", "completed", True, "DIRECT", "*", "specific role assignment"),
        ("PENDING", "completed", True, "DIRECT", "id-1", "approval"),
        ("APPROVED", "active", True, "DIRECT", "id-1", "Active project"),
        ("APPROVED", "completed", False, "DIRECT", "id-1", "Missing evidence"),
        ("APPROVED", "completed", True, "GROUP", "id-1", "direct role"),
    ],
)
def test_remediation_policy_rejections(
    approval_status, project_status, evidence_complete, assignment_type, assignment_id, reason
):
    result = is_remediation_eligible(
        approval_status, project_status, evidence_complete, assignment_type, assignment_id
    )

    assert result["eligible"] is False
    assert reason in result["reason"]


def test_validator_rejects_missing_wildcard_and_duplicate():
    assert validate_remediation_request("", False)["valid"] is False
    assert validate_remediation_request("*", False)["valid"] is False
    assert validate_remediation_request("id-1", True)["valid"] is False
    assert validate_remediation_request("id-1", False)["valid"] is True
