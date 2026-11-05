from pathlib import Path
from typing import Protocol

from appsec_triage.models.assessment import Assessment
from appsec_triage.models.finding import Finding
from appsec_triage.reporting.json_reporter import FailedAssessment, Report
from appsec_triage.scanners.base import Scanner


class Assessor(Protocol):
    async def assess(self, finding: Finding) -> Assessment: ...


class Pipeline:
    def __init__(self, scanner: Scanner, triage: Assessor | None = None):
        self.scanner = scanner
        self.triage = triage

    async def run(self, target: str | Path, max_findings: int = 20) -> Report:
        if max_findings < 0:
            raise ValueError("max_findings must be non-negative")
        report = Report(scan=self.scanner.scan(target), triage_enabled=self.triage is not None)
        if self.triage:
            for finding in report.scan.findings[:max_findings]:
                try:
                    assessment = await self.triage.assess(finding)
                    if assessment.finding_id != finding.id:
                        raise ValueError("Assessment finding ID mismatch")
                    report.assessments.append(assessment)
                except Exception as exc:
                    # Exception text from remote providers can contain input/code.
                    report.failed_assessments.append(FailedAssessment(
                        finding_id=finding.id, error=f"Assessment failed ({type(exc).__name__})",
                    ))
        return report
