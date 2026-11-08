from pathlib import Path
from typing import Protocol

from appsec_triage.models.assessment import Assessment
from appsec_triage.models.finding import Finding
from appsec_triage.progress import Progress, location, short_rule
from appsec_triage.reporting.json_reporter import FailedAssessment, Report
from appsec_triage.scanners.base import Scanner


def failure_reason(exc: Exception, timeout: float | None = None) -> str:
    """A short, safe reason: exception type and status code only, never provider text."""
    if isinstance(exc, TimeoutError):
        return f"timed out after {timeout:g} s" if timeout else "timed out"
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if isinstance(status, int):
        kind = "rate limited" if status == 429 else "provider server error" if status >= 500 else "provider rejected the request"
        return f"{kind}, HTTP {status}"
    if type(exc).__name__ == "ValidationError":
        return "the model's answer did not match the required format"
    return type(exc).__name__


class Assessor(Protocol):
    async def assess(self, finding: Finding) -> Assessment: ...


class Pipeline:
    def __init__(self, scanner: Scanner, triage: Assessor | None = None, progress: Progress | None = None):
        self.scanner = scanner
        self.triage = triage
        self.progress = progress or Progress()

    async def run(self, target: str | Path, max_findings: int = 20) -> Report:
        if max_findings < 0:
            raise ValueError("max_findings must be non-negative")
        report = Report(scan=self.scanner.scan(target), triage_enabled=self.triage is not None)
        if self.triage:
            selected = [f for f in report.scan.findings if f.category == "sast"][:max_findings]
            if not selected:
                self.progress.emit("triage", "skipped", detail="No code findings to review")
            else:
                self.progress.emit("triage", "start", current=0, total=len(selected))
            for index, finding in enumerate(selected, 1):
                where = f"{short_rule(finding.rule_id)} · {location(finding)}"
                self.progress.emit("triage", "progress", current=index - 1, total=len(selected),
                                   detail=f"Reviewing {where}")
                try:
                    assessment = await self.triage.assess(finding)
                    if assessment.finding_id != finding.id:
                        raise ValueError("Assessment finding ID mismatch")
                    report.assessments.append(assessment)
                    result = assessment.verdict
                except Exception as exc:
                    # Exception text from remote providers can contain input/code, so only the reason is kept.
                    reason = failure_reason(exc, getattr(self.triage, "timeout", None))
                    report.failed_assessments.append(FailedAssessment(finding_id=finding.id, error=f"Assessment failed ({reason})"))
                    result = f"failed ({reason})"
                self.progress.emit("triage", "item", current=index, total=len(selected), detail=where, result=result)
            if selected:
                failed = len(report.failed_assessments)
                self.progress.emit("triage", "warning" if failed else "done", current=len(selected),
                                   total=len(selected), count=len(report.assessments),
                                   detail=f"{len(report.assessments)} reviewed" + (f", {failed} failed" if failed else ""))
        return report
