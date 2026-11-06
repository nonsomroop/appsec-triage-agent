"""Dependency vulnerability scanning; never executes package installation."""
import hashlib
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from appsec_triage.models.finding import Finding
from appsec_triage.models.scan import Scan
from appsec_triage.utils.source_reader import excluded_path
from .base import validate_target
from .semgrep import ScannerError, run_semgrep


def parse_trivy(payload: dict, root: Path) -> tuple[list[Finding], list[str]]:
    if not isinstance(payload, dict) or payload.get("SchemaVersion") != 2:
        raise ScannerError("Unsupported Trivy JSON structure (expected schema 2)")
    results = payload.get("Results", [])
    if not isinstance(results, list):
        raise ScannerError("Invalid Trivy results structure")
    findings, errors, seen = [], [], set()
    for index, result in enumerate(results):
        try:
            if not isinstance(result, dict):
                raise ValueError()
            if result.get("Class") != "lang-pkgs":
                continue
            path = Path(result["Target"])
            if ".." in path.parts or path.is_absolute() or ":" in str(path):
                raise ValueError()
            relative = path.as_posix()
            if excluded_path(path):
                continue
            vulnerabilities = result.get("Vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            errors.append(f"Could not normalise Trivy target {index}")
            continue
        for number, vuln in enumerate(vulnerabilities):
            try:
                advisory, package, installed = (vuln[key] for key in
                    ("VulnerabilityID", "PkgName", "InstalledVersion"))
                if not all(isinstance(v, str) and v for v in (advisory, package, installed)):
                    raise ValueError()
                identity = ["trivy", relative, advisory, package, installed, vuln.get("PkgPath", "")]
                finding_id = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
                severity = str(vuln.get("Severity", "unknown")).lower()
                finding = Finding(
                    id=finding_id, scanner="trivy", category="sca", rule_id=advisory,
                    title=vuln.get("Title") or advisory,
                    message=vuln.get("Description") or vuln.get("Title") or advisory,
                    severity=severity if severity in {"critical", "high", "medium", "low", "info"} else "unknown",
                    file_path=relative, package_name=package, installed_version=installed,
                    fixed_version=vuln.get("FixedVersion") or None, vulnerability_id=advisory,
                    cwe=vuln.get("CweIDs") or [],
                    metadata={"ecosystem": result.get("Type"), "primary_url": vuln.get("PrimaryURL"),
                              "status": vuln.get("Status")},
                )
                if finding_id not in seen:
                    findings.append(finding)
                    seen.add(finding_id)
            except (KeyError, TypeError, ValueError, ValidationError):
                errors.append(f"Could not normalise Trivy vulnerability {index}:{number}")
    return findings, errors


class TrivyScanner:
    def __init__(self, timeout: int = 300, max_output_bytes: int = 20_000_000):
        if min(timeout, max_output_bytes) < 1:
            raise ValueError("Scanner limits must be positive")
        self.timeout, self.max_output_bytes = timeout, max_output_bytes

    def scan(self, target: str | Path) -> Scan:
        scan = Scan(target=str(target), scanner="trivy")
        try:
            root = validate_target(target)
            scan.target = str(root)
            executable = shutil.which("trivy")
            if not executable:
                raise ScannerError("Trivy executable not found; install Trivy and add it to PATH")
            executable = str(Path(executable).resolve())
            # Run outside the repository so its trivy.yaml cannot change scan policy.
            with tempfile.TemporaryDirectory(prefix="appsec-trivy-") as directory:
                config = Path(directory) / "config.yaml"
                config.write_text("{}", encoding="utf-8")
                ignorefile = Path(directory) / "empty.trivyignore"
                ignorefile.touch()
                command = [executable, "fs", "--config", str(config), "--scanners", "vuln",
                           "--pkg-types", "library", "--format", "json", "--quiet",
                           "--ignorefile", str(ignorefile),
                           "--list-all-pkgs=false", "--exit-code", "0", "--timeout", f"{self.timeout}s",
                           "--", str(root)]
                code, output = run_semgrep(command, Path(directory), self.timeout, self.max_output_bytes)
            try:
                scan.findings, scan.errors = parse_trivy(json.loads(output), root)
            except (json.JSONDecodeError, ScannerError):
                raise ScannerError(f"Trivy returned invalid JSON (exit code {code})") from None
            if code:
                scan.errors.append(f"Trivy exited with code {code}")
            scan.status = ("partial" if scan.findings else "failed") if scan.errors else "completed"
        except (ScannerError, OSError, ValueError) as exc:
            message = str(exc).replace("Semgrep", "Trivy") if isinstance(exc, ScannerError) else "Invalid or inaccessible target directory"
            scan.errors.append(message)
            scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        return scan
