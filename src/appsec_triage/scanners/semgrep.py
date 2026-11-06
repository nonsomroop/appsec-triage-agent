import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from appsec_triage.models.finding import Finding
from appsec_triage.models.scan import Scan
from appsec_triage.utils.source_reader import SECRET_DIRECTORIES, SECRET_PATTERNS, SourceReader, SourceReadError
from .base import validate_target


class ScannerError(RuntimeError):
    pass


def run_semgrep(command: list[str], root: Path, timeout: int,
                max_output_bytes: int) -> tuple[int, str]:
    if command[0] == "semgrep":
        executable = shutil.which("semgrep")
        if executable is None:
            raise ScannerError("Semgrep executable not found; install Semgrep CE and add it to PATH")
        command = [str(Path(executable).resolve()), *command[1:]]
    # Disk-backed streams avoid unbounded memory capture; poll output limits.
    env = {key: value for key, value in os.environ.items()
           if not any(word in key.upper() for word in ("TOKEN", "SECRET", "PASSWORD", "API_KEY"))}
    env["SEMGREP_SEND_METRICS"] = "auto" if "--metrics=auto" in command else "off"
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, shell=False,
                                       start_new_session=os.name != "nt")
        except FileNotFoundError:
            raise ScannerError("Semgrep executable not found; install Semgrep CE and add it to PATH") from None
        except OSError:
            raise ScannerError("Could not start Semgrep") from None
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise ScannerError("Semgrep execution timed out")
                if any(os.fstat(s.fileno()).st_size > max_output_bytes for s in (stdout, stderr)):
                    raise ScannerError("Semgrep output exceeded configured limit")
                time.sleep(0.05)
            if any(os.fstat(s.fileno()).st_size > max_output_bytes for s in (stdout, stderr)):
                raise ScannerError("Semgrep output exceeded configured limit")
            stdout.seek(0)
            return process.returncode, stdout.read(max_output_bytes).decode("utf-8", errors="replace")
        finally:
            if process.poll() is None:
                if os.name == "nt":
                    taskkill = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/taskkill.exe"
                    try:
                        subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=10, check=False, shell=False)
                    except (OSError, subprocess.TimeoutExpired):
                        process.kill()
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    process.kill()
            process.wait()


def parse_semgrep(payload: dict, root: Path) -> tuple[list[Finding], list[str]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ScannerError("Invalid Semgrep JSON structure")
    reader = SourceReader(root, context_lines=3, max_context_chars=6000)
    findings = []
    errors = []
    severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "info",
                    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    for index, result in enumerate(payload["results"]):
        try:
            extra = result["extra"]
            metadata = extra.get("metadata") or {}
            path = Path(result["path"])
            if not path.is_absolute():
                path = root / path
            path = path.resolve().relative_to(root).as_posix()
            cwe = metadata.get("cwe", [])
            if isinstance(cwe, str):
                cwe = [cwe]
            identity = ["semgrep", result["check_id"], path, result["start"], result["end"]]
            finding_id = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
            finding = Finding(
                id=finding_id, scanner="semgrep", rule_id=result["check_id"],
                title=metadata.get("shortDescription") or result["check_id"],
                severity=severity_map.get(str(extra.get("severity", "")).upper(), "unknown"),
                message=extra.get("message", ""), file_path=path,
                start_line=result["start"]["line"], end_line=result["end"]["line"], cwe=cwe,
                metadata={"rule_metadata": metadata, "original_severity": extra.get("severity"),
                          "start": result["start"], "end": result["end"],
                          "fingerprint": extra.get("fingerprint"), "engine_kind": extra.get("engine_kind")},
            )
            try:
                finding.source_snippet = reader.read(path, finding.start_line, finding.end_line)
            except SourceReadError as exc:
                finding.source_error = str(exc)
            findings.append(finding)
        except (KeyError, TypeError, ValueError, AttributeError, OSError, ValidationError):
            errors.append(f"Could not normalise Semgrep result {index}")
    scanner_errors = payload.get("errors", [])
    if not isinstance(scanner_errors, list):
        errors.append("Invalid Semgrep errors structure")
    else:
        # Do not copy diagnostics that may embed source or secret values.
        errors.extend(f"Semgrep reported scan error {index}" for index, _ in enumerate(scanner_errors))
    return findings, errors


class SemgrepScanner:
    def __init__(self, configs: tuple[str, ...] = ("auto",), timeout: int = 300,
                 max_output_bytes: int = 20_000_000):
        if not configs or any(not config.strip() for config in configs):
            raise ValueError("At least one ruleset is required")
        if min(timeout, max_output_bytes) < 1:
            raise ValueError("Scanner limits must be positive")
        self.configs = configs
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def scan(self, target: str | Path) -> Scan:
        scan = Scan(target=str(target), scanner="semgrep")
        try:
            root = validate_target(target)
            scan.target = str(root)
            # Resolve before changing cwd so a target-local executable cannot be selected.
            executable = shutil.which("semgrep") or "semgrep"
            metrics = "auto" if "auto" in self.configs else "off"
            command = [executable, "scan", "--json", "--oss-only", f"--metrics={metrics}",
                       "--disable-version-check", "--jobs=1", "--max-memory=512",
                       "--max-target-bytes=1000000", "--timeout=10"]
            for config in self.configs:
                command.extend(["--config", config])
            for pattern in (*SECRET_PATTERNS, *sorted(SECRET_DIRECTORIES)):
                command.extend(["--exclude", pattern])
            command.extend(["--", "."])
            code, output = run_semgrep(command, root, self.timeout, self.max_output_bytes)
            try:
                payload = json.loads(output)
                scan.findings, scan.errors = parse_semgrep(payload, root)
                version = payload.get("version")
                scan.scanner_version = version if isinstance(version, str) else None
            except (json.JSONDecodeError, ScannerError):
                raise ScannerError(f"Semgrep returned invalid JSON (exit code {code})") from None
            if code != 0:
                scan.errors.append(f"Semgrep exited with code {code}")
            scan.status = ("partial" if scan.findings else "failed") if scan.errors else "completed"
        except (ScannerError, OSError, ValueError) as exc:
            scan.errors.append(str(exc) if isinstance(exc, ScannerError) else "Invalid or inaccessible target directory")
            scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        return scan
