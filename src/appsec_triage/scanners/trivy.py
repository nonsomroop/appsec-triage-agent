"""Dependency vulnerability scanning; never executes package installation."""
import hashlib
import json
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from appsec_triage.models.finding import Finding
from appsec_triage.models.scan import Coverage, Dependency, Scan
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
                              "status": vuln.get("Status"), "data_source": vuln.get("DataSource"),
                              "vendor_ids": vuln.get("VendorIDs") or []},
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
        scan.coverage["trivy"] = Coverage(
            scope="Supported dependency manifests and lockfiles. Source files are outside this scan's scope.",
            files_label="Dependency files reported", analysis_status="unconfirmed",
            limitations=["Matches are limited to Trivy's advisory sources and version matching. "
                         "A parsed dependency and zero matches do not establish that it is vulnerability-free."])
        coverage = scan.coverage["trivy"]
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
                           "--pkg-types", "library", "--format", "json", "--no-progress",
                           "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--ignore-unfixed=false",
                           "--ignore-status", "",
                           "--ignorefile", str(ignorefile),
                           "--list-all-pkgs=true", "--exit-code", "0", "--timeout", f"{self.timeout}s",
                           "--", str(root)]
                diagnostics = []
                code, output = run_semgrep(command, Path(directory), self.timeout, self.max_output_bytes,
                                           stderr_lines=diagnostics)
                # Capture the actual scanner/database version after its normal database update.
                try:
                    version_code, version_output = run_semgrep(
                        [executable, "version", "--format", "json"], Path(directory), min(self.timeout, 10), 100_000)
                    version = json.loads(version_output)
                    if version_code or not isinstance(version, dict) or not isinstance(version.get("Version"), str):
                        raise ValueError()
                    scan.scanner_version = version.get("Version") if isinstance(version.get("Version"), str) else None
                    database = version.get("VulnerabilityDB")
                    if isinstance(database, dict):
                        coverage.database = {key: database[key] for key in
                                             ("Version", "UpdatedAt", "NextUpdate", "DownloadedAt") if key in database}
                    else:
                        coverage.limitations.append("Vulnerability database metadata is unavailable.")
                except (ScannerError, ValueError, OSError):
                    coverage.limitations.append("Scanner/database version metadata could not be read.")
            try:
                payload = json.loads(output)
                scan.findings, scan.errors = parse_trivy(payload, root)
                scan.coverage["trivy"].files = sorted({
                    result["Target"] for result in payload.get("Results", [])
                    if isinstance(result, dict) and result.get("Class") == "lang-pkgs"
                    and isinstance(result.get("Target"), str)
                })
                coverage.packages, package_errors = parse_packages(payload)
                scan.errors.extend(package_errors)
            except (json.JSONDecodeError, ScannerError):
                raise ScannerError(f"Trivy returned invalid JSON (exit code {code})") from None
            if code:
                scan.errors.append(f"Trivy exited with code {code}")
            native_warnings = [line for line in diagnostics if re.search(r"\b(WARN|ERROR)\b", line)]
            unsupported = any("support" in line.lower() and "vulnerability" in line.lower()
                              for line in native_warnings)
            if native_warnings:
                scan.warnings.append("Trivy reported unsupported vulnerability analysis." if unsupported else
                                     "Trivy reported scanner warnings. Dependency analysis may be incomplete.")
            if coverage.files == []:
                scan.warnings.append("Trivy reported zero dependency files. Dependency coverage is unconfirmed.")
            if coverage.packages is None:
                scan.warnings.append("Trivy did not provide a complete dependency inventory.")
            scan.status = ("partial" if scan.findings or coverage.packages else "failed") if scan.errors else (
                "partial" if scan.warnings else "completed")
            coverage.analysis_status = (
                "failed" if scan.status == "failed" else
                "unsupported" if unsupported and not scan.findings else
                "unconfirmed" if not coverage.files and not scan.errors else
                "partial" if scan.status == "partial" else
                "vulnerabilities_detected" if scan.findings else
                "no_known_vulnerabilities" if coverage.packages else "unconfirmed")
        except (ScannerError, OSError, ValueError) as exc:
            message = str(exc).replace("Semgrep", "Trivy") if isinstance(exc, ScannerError) else "Invalid or inaccessible target directory"
            scan.errors.append(message)
            scan.status = "failed"
            coverage.analysis_status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        return scan


def parse_packages(payload: dict) -> tuple[list[Dependency] | None, list[str]]:
    """Retain exact versions and dependency relationships without evaluating advisories."""
    packages, errors = [], []
    complete = True
    for result in payload.get("Results", []):
        if not isinstance(result, dict) or result.get("Class") != "lang-pkgs":
            continue
        entries = result.get("Packages")
        if not isinstance(entries, list):
            complete = False
            errors.append("Trivy omitted the package inventory for a dependency file")
            continue
        for entry in entries:
            try:
                if not isinstance(entry, dict):
                    raise ValueError()
                name, version = entry["Name"], entry["Version"]
                path = Path(result["Target"])
                if path.is_absolute() or ".." in path.parts or ":" in str(path):
                    raise ValueError()
                if not all(isinstance(value, str) and value for value in (name, version)):
                    raise ValueError()
                relationship = entry.get("Relationship", "indirect" if entry.get("Indirect") else "unknown")
                packages.append(Dependency(file_path=result["Target"], ecosystem=result["Type"],
                                           name=name, version=version, relationship=relationship))
            except (KeyError, TypeError, ValueError):
                errors.append("Could not normalize a Trivy dependency")
    return (packages if complete or packages else None), errors
