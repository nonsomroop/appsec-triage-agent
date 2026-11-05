from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import AwareDatetime, BaseModel, Field, model_validator

from .finding import Finding


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    scanner: str
    scanner_version: str | None = None
    started_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: AwareDatetime | None = None
    status: Literal["running", "completed", "partial", "failed"] = "running"
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def ordered_times(self) -> "Scan":
        if self.completed_at and self.completed_at < self.started_at:
            raise ValueError("completed_at precedes started_at")
        return self
