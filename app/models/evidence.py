from datetime import datetime

from pydantic import BaseModel


class Evidence(BaseModel):
    evidence_id: str
    source: str
    description: str
    observed_at: datetime | None
    resource_id: str | None
    confidence: str