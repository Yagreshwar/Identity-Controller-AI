from datetime import datetime

from pydantic import BaseModel


class RemediationApproval(BaseModel):
    approval_id: str
    incident_id: str
    project_id: str
    role_assignment_id: str
    identity_id: str
    resource_scope: str
    proposed_action: str = "DELETE_ROLE_ASSIGNMENT"
    approver: str
    approver_name: str | None = None
    status: str
    created_at: datetime | None = None
    expires_at: datetime
