import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_triage.cli import main
from appsec_triage.models.scan import Scan
from appsec_triage.scanners import trivy
from appsec_triage.scanners.combined import CombinedScanner
from appsec_triage.scanners.semgrep import ScannerError
from appsec_triage.services.pipeline import Pipeline


@pytest.fixture
def payload():
    return {"SchemaVersion": 2, "Results": [{"Target": "requirements.txt", "Class": "lang-pkgs",
        "Type": "pip", "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-0001", "PkgName": "example",
        "InstalledVersion": "1.0", "FixedVersion": "2.0", "Severity": "HIGH", "Title": "Example issue"}]}]}


def test_normalisation_and_deduplication(tmp_path, payload):
    payload["Results"][0]["Vulnerabilities"] *= 2
    findings, errors = trivy.parse_trivy(payload, tmp_path)
    assert not errors and len(findings) == 1
    f = findings[0]
    assert f.category == "sca" and f.start_line is None and f.end_line is None
    assert (f.package_name, f.installed_version, f.fixed_version) == ("example", "1.0", "2.0")
    assert f.id == trivy.parse_trivy(payload, tmp_path)[0][0].id


def test_missing_fix_unknown_severity_and_invalid_entry(tmp_path, payload):
    vuln = payload["Results"][0]["Vulnerabilities"][0]
    vuln.pop("FixedVersion")
    vuln["Severity"] = "unexpected"
    payload["Results"][0]["Vulnerabilities"].append({})
    findings, errors = trivy.parse_trivy(payload, tmp_path)
    assert len(findings) == len(errors) == 1
    assert findings[0].fixed_version is None and findings[0].severity == "unknown"


@pytest.mark.parametrize("payload", [[], {}, {"SchemaVersion": 2, "Results": {}}])
def test_invalid_reports(tmp_path, payload):
    with pytest.raises(ScannerError):
        trivy.parse_trivy(payload, tmp_path)


def test_unsafe_target(tmp_path, payload):
    payload["Results"][0]["Target"] = "../outside.lock"
    findings, errors = trivy.parse_trivy(payload, tmp_path)
    assert not findings and errors


def test_runner_and_cli(monkeypatch, tmp_path, payload, capsys):
    monkeypatch.setattr(trivy.shutil, "which", lambda _: str(tmp_path / "trivy"))
    def run(command, cwd, timeout, limit):
        assert command[1] == "fs" and command[command.index("--scanners") + 1] == "vuln"
        assert Path(command[command.index("--ignorefile") + 1]).read_bytes() == b""
        assert cwd != tmp_path and command[-1] == str(tmp_path.resolve())
        return 0, json.dumps(payload)
    monkeypatch.setattr(trivy, "run_semgrep", run)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main(["scan", str(tmp_path), "--scanner", "trivy"]) == 0
    assert json.loads(capsys.readouterr().out)["scan"]["findings"][0]["package_name"] == "example"


def test_missing_executable(monkeypatch, tmp_path):
    monkeypatch.setattr(trivy.shutil, "which", lambda _: None)
    scan = trivy.TrivyScanner().scan(tmp_path)
    assert scan.status == "failed" and "Trivy executable not found" in scan.errors[0]


def test_combined_partial_and_sca_not_assessed(tmp_path, payload):
    findings, _ = trivy.parse_trivy(payload, tmp_path)
    good = SimpleNamespace(scan=lambda _: Scan(target=".", scanner="trivy", status="completed", findings=findings))
    bad = SimpleNamespace(scan=lambda _: Scan(target=".", scanner="semgrep", status="failed", errors=["missing"]))
    scanner = CombinedScanner([bad, good])
    result = scanner.scan(tmp_path)
    assert result.status == "partial" and result.findings and result.errors
    class Assessor:
        async def assess(self, finding):
            pytest.fail("SCA must not be passed to source-based AI assessment")
    report = asyncio.run(Pipeline(scanner, Assessor()).run(tmp_path))
    assert not report.assessments and not report.failed_assessments


def test_nonzero_exit_preserves_findings(monkeypatch, tmp_path, payload):
    monkeypatch.setattr(trivy.shutil, "which", lambda _: str(tmp_path / "trivy"))
    monkeypatch.setattr(trivy, "run_semgrep", lambda *args: (1, json.dumps(payload)))
    scan = trivy.TrivyScanner().scan(tmp_path)
    assert scan.status == "partial" and scan.findings and scan.errors
