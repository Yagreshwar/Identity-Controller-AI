
from typing import Any

from pydantic import BaseModel, Field


class AccessRiskFinding(BaseModel):
    project_id: str | None = None
    resource: str | None = None
    resource_owner: str | None = None
    role: str | None = None
    role_assignment_id: str | None = None
    resource_scope: str | None = None
    project_status: str | None = None
    activity_status: str | None = None
    risk_level: str
    finding_type: str
    recommended_action: str
    human_review_required: bool = True
    approval_required: bool = True
    approval_eligible: bool = False
    approval_status: str = "REVIEW_ONLY"
    confidence: str
    evidence_ids: list[str] = Field(default_factory=list)


class IdentityFinding(BaseModel):
    identity: str
    findings: list[AccessRiskFinding] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    investigation_summary: dict[str, Any] = Field(default_factory=dict)
    collection_errors: list[dict[str, Any]] = Field(default_factory=list)
