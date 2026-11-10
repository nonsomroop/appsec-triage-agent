from pathlib import Path
from typing import Protocol

from appsec_triage.models.scan import Scan

SCAN_LABELS = {"semgrep": "Semgrep code scan", "trivy": "Trivy dependency scan",
               "gitleaks-files": "Gitleaks current files", "gitleaks-history": "Gitleaks Git history"}
SCAN_CHOICES = (*SCAN_LABELS, "all")
SCAN_ORDER = tuple(SCAN_LABELS)


def parse_scanners(spec: str) -> list[str]:
    """Scanner names from a selection: one name, 'all' (code + dependencies), or names joined
    with '+', e.g. 'semgrep+trivy+gitleaks-files'. Returned in a stable order."""
    if spec == "all":
        return ["semgrep", "trivy"]
    names = spec.split("+") if isinstance(spec, str) and spec else []
    if not names or any(name not in SCAN_LABELS for name in names) or len(set(names)) != len(names):
        raise ValueError("Choose scanners from: " + ", ".join(SCAN_LABELS))
    if {"gitleaks-files", "gitleaks-history"} <= set(names):
        raise ValueError("Scan secrets in current files or in Git history, not both")
    return sorted(names, key=SCAN_ORDER.index)


def scanner_spec(spec: str) -> str:
    """The canonical '+'-joined form of a scanner selection."""
    return "+".join(parse_scanners(spec))


def validate_target(target: str | Path) -> Path:
    root = Path(target).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Target must be a directory")
    return root


class Scanner(Protocol):
    def scan(self, target: str | Path) -> Scan: ...
