from pathlib import Path
from typing import Protocol

from appsec_triage.models.scan import Scan


def validate_target(target: str | Path) -> Path:
    root = Path(target).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Target must be a directory")
    return root


class Scanner(Protocol):
    def scan(self, target: str | Path) -> Scan: ...
