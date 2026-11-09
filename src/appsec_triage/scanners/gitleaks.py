"""Scan for credentials and retain only finding locations and rule IDs."""
import hashlib
import json
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from appsec_triage.models.finding import Finding
from appsec_triage.models.scan import Coverage, Scan
from .base import validate_target
from .semgrep import ScannerError, run_semgrep


class GitleaksScanner:
    def __init__(self, scope: str, timeout: int = 300):
        self.scope = scope
        self.timeout = timeout

    def scan(self, target: str | Path) -> Scan:
        scan = Scan(target=str(target), scanner=f"gitleaks-{self.scope}")
        scan.coverage[scan.scanner] = Coverage(scope=(
            "Patches in commits reachable from available Git refs. Remote scans cover the selected branch. "
            "Uncommitted files and unavailable history are outside this scope."
            if self.scope == "history" else
            "Current files in the selected folder, including uncommitted files."
        ) + " Gitleaks rules and ignore entries limit coverage. A complete scanned-file list is unavailable.")
        try:
            root = validate_target(target)
            scan.target = str(root)
            executable = shutil.which("gitleaks")
            if not executable:
                raise ScannerError("Gitleaks executable not found; install Gitleaks and add it to PATH")
            history = self.scope == "history"
            if history and (not shutil.which("git") or not (root / ".git").exists()):
                raise ScannerError("Git history scanning requires Git and the root of a checkout with accessible Git metadata")
            with tempfile.TemporaryDirectory(prefix="appsec-gitleaks-") as directory:
                config = Path(directory) / "rules.toml"
                config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
                # Request metadata only, so the subprocess report itself contains no source excerpts.
                template = Path(directory) / "report.tmpl"
                template.write_text(
                    '[{{range $i, $f := .}}{{if $i}},{{end}}'
                    '{{dict "RuleID" $f.RuleID "File" $f.File "StartLine" $f.StartLine '
                    '"EndLine" $f.EndLine "Commit" $f.Commit | toJson}}{{end}}]',
                    encoding="utf-8",
                )
                command = [str(Path(executable).resolve()), "git" if history else "dir",
                           "--config", str(config),
                           "--ignore-gitleaks-allow", "--no-banner", "--redact=100",
                           "--report-format=template", "--report-template", str(template),
                           "--report-path=-", "--exit-code=10"]
                env = None
                if history:
                    command.append("--log-opts=--full-history --all --diff-filter=tuxdb --no-ext-diff --no-textconv")
                    env = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory",
                           "GIT_CONFIG_VALUE_0": str(root), "GIT_NO_LAZY_FETCH": "1",
                           "GIT_OPTIONAL_LOCKS": "0"}
                code, output = run_semgrep([*command, "--", str(root)], Path(directory),
                                           self.timeout, 20_000_000, git_env=env)
            if code not in (0, 10):
                raise ScannerError(f"Gitleaks exited with code {code}. Check that the target and its Git metadata are readable.")
            results = json.loads(output)
            if not isinstance(results, list) or (code == 10 and not results):
                raise ScannerError("Gitleaks returned an invalid findings report")
            findings = {}
            for result in results:
                try:
                    finding = normalize_finding(result, root, scan.scanner)
                    findings[finding.id] = finding
                except (KeyError, TypeError, ValueError):
                    scan.errors.append("Could not normalize a Gitleaks finding")
            scan.findings = list(findings.values())
            if history and (root / ".git" / "shallow").is_file():
                scan.warnings.append("Shallow clone: only locally available commits were scanned")
            scan.status = ("partial" if scan.findings else "failed") if scan.errors else "completed"
        except ScannerError as exc:
            scan.errors.append(str(exc).replace("Semgrep", "Gitleaks"))
            scan.status = "failed"
        except (OSError, ValueError):
            scan.errors.append("Gitleaks could not read the target or returned invalid JSON")
            scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        return scan


def normalize_finding(result: dict, root: Path, scanner: str) -> Finding:
    rule = result["RuleID"]
    if not isinstance(rule, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", rule):
        raise ValueError("Invalid rule ID")
    path = Path(result["File"])
    if path.is_absolute():
        path = path.relative_to(root)
    if path == Path(".") or path.anchor or ".." in path.parts:
        raise ValueError("Invalid finding path")
    start, end = result["StartLine"], result["EndLine"]
    if type(start) is not int or type(end) is not int:
        raise ValueError("Invalid line bounds")
    commit = result.get("Commit", "")
    if not isinstance(commit, str) or (commit and not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", commit)):
        raise ValueError("Invalid commit hash")
    relative = path.as_posix()
    identity = json.dumps([scanner, rule, relative, start, end, commit])
    return Finding(id=hashlib.sha256(identity.encode()).hexdigest(), scanner=scanner,
                   category="secret", rule_id=rule, title=f"Potential secret · {rule}",
                   severity="unknown", message="Gitleaks detected a possible credential.",
                   file_path=relative, start_line=start, end_line=end,
                   metadata={"commit": commit} if commit else {})
