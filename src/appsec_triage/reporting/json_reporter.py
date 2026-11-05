from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field, computed_field

from appsec_triage.models.assessment import Assessment
from appsec_triage.models.scan import Scan


class FailedAssessment(BaseModel):
    finding_id: str
    error: str


class Report(BaseModel):
    schema_version: str = "1.0"
    scan: Scan
    triage_enabled: bool = False
    assessments: list[Assessment] = Field(default_factory=list)
    failed_assessments: list[FailedAssessment] = Field(default_factory=list)

    @computed_field
    @property
    def finding_counts(self) -> dict[str, int]:
        return {"total": len(self.scan.findings), **dict(Counter(f.severity for f in self.scan.findings))}

    @computed_field
    @property
    def assessment_counts(self) -> dict[str, int]:
        return {"completed": len(self.assessments), "failed": len(self.failed_assessments),
                "not_assessed": len(self.scan.findings) - len(self.assessments) - len(self.failed_assessments)}


def write_report(report: Report, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
