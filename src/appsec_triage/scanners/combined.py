from datetime import datetime, timezone
from pathlib import Path

from appsec_triage.models.scan import Scan
from .base import Scanner


class CombinedScanner:
    def __init__(self, scanners: list[Scanner]):
        if not scanners:
            raise ValueError("At least one scanner is required")
        self.scanners = scanners

    def scan(self, target: str | Path) -> Scan:
        combined = Scan(target=str(target), scanner="semgrep+trivy")
        statuses, names = [], []
        for scanner in self.scanners:
            result = scanner.scan(target)
            names.append(result.scanner)
            statuses.append(result.status)
            combined.scanner_statuses[result.scanner] = result.status
            combined.findings.extend(result.findings)
            combined.coverage.update(result.coverage)
            combined.errors.extend(f"{result.scanner}: {error}" for error in result.errors)
            combined.warnings.extend(f"{result.scanner}: {warning}" for warning in result.warnings)
            if result.status != "completed" and not result.errors:
                combined.errors.append(f"{result.scanner}: scan {result.status}")
        combined.scanner = "+".join(dict.fromkeys(names))
        combined.status = ("completed" if not combined.errors else
                           "failed" if all(s == "failed" for s in statuses) else "partial")
        combined.completed_at = datetime.now(timezone.utc)
        return combined
