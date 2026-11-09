from pathlib import Path
from typing import Protocol

from appsec_triage.models.scan import Scan

SCAN_LABELS = {"semgrep": "Semgrep code scan", "trivy": "Trivy dependency scan",
               "gitleaks-files": "Gitleaks current files", "gitleaks-history": "Gitleaks Git history"}
SCAN_CHOICES = (*SCAN_LABELS, "all")


def validate_target(target: str | Path) -> Path:
    root = Path(target).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Target must be a directory")
    return root


class Scanner(Protocol):
    def scan(self, target: str | Path) -> Scan: ...
