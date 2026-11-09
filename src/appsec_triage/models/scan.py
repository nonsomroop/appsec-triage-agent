from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import AwareDatetime, BaseModel, Field, JsonValue, model_validator

from .finding import Finding


class Dependency(BaseModel):
    file_path: str
    ecosystem: str
    name: str
    version: str
    relationship: str = "unknown"


class Coverage(BaseModel):
    scope: str
    files: list[str] | None = None
    files_label: str = "Files reported as scanned"
    inventory_files: list[str] | None = None
    inventory_complete: bool = False
    skipped: dict[str, str] = Field(default_factory=dict)
    rules: list[str] | None = None
    packages: list[Dependency] | None = None
    database: dict[str, JsonValue] = Field(default_factory=dict)
    analysis_status: Literal["no_known_vulnerabilities", "vulnerabilities_detected",
                             "partial", "unsupported", "unconfirmed", "failed"] | None = None
    limitations: list[str] = Field(default_factory=list)


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    scanner: str
    scanner_version: str | None = None
    scanner_statuses: dict[str, Literal["completed", "partial", "failed", "running"]] = Field(default_factory=dict)
    started_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: AwareDatetime | None = None
    status: Literal["running", "completed", "partial", "failed"] = "running"
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    # Coverage gaps that do not invalidate the scan, such as files Semgrep could only partly parse.
    warnings: list[str] = Field(default_factory=list)
    coverage: dict[str, Coverage] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ordered_times(self) -> "Scan":
        if self.completed_at and self.completed_at < self.started_at:
            raise ValueError("completed_at precedes started_at")
        return self
