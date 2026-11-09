import asyncio
import json
import os
import shutil
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
        "Packages": [{"Name": "example", "Version": "1.0", "Relationship": "direct"}],
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
    def run(command, cwd, timeout, limit, **kwargs):
        if command[1] == "version":
            return 0, json.dumps({"Version": "0.76.0", "VulnerabilityDB": {"Version": 2, "UpdatedAt": "2026-11-08T18:58:44Z"}})
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
    monkeypatch.setattr(trivy, "run_semgrep", lambda *args, **kwargs: (1, json.dumps(payload)))
    scan = trivy.TrivyScanner().scan(tmp_path)
    assert scan.status == "partial" and scan.findings and scan.errors


def mock_output(monkeypatch, payload, diagnostics=(), code=0):
    monkeypatch.setattr(trivy.shutil, "which", lambda _: "/usr/bin/trivy")

    def run(command, cwd, timeout, limit, **kwargs):
        if command[1] == "version":
            return 0, json.dumps({"Version": "0.76.0", "VulnerabilityDB": {
                "Version": 2, "UpdatedAt": "2026-11-08T18:58:44Z"}})
        assert "--list-all-pkgs=true" in command
        assert command[command.index("--severity") + 1] == "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
        assert "--ignore-unfixed=false" in command
        kwargs["stderr_lines"].extend(diagnostics)
        return code, json.dumps(payload)

    monkeypatch.setattr(trivy, "run_semgrep", run)


def test_low_findings_survive_cli_export_and_history(monkeypatch, tmp_path, payload, capsys):
    from appsec_triage.history import History

    # Exercise the adapter contract with a low finding, without claiming the native
    # scanner detected the Flutter advisory that is absent from its database.
    payload["Results"][0]["Target"] = "secrets/requirements.txt"
    payload["Results"][0]["Vulnerabilities"][0]["Severity"] = "LOW"
    mock_output(monkeypatch, payload)
    output = tmp_path / "report.json"
    assert main(["scan", str(tmp_path), "--scanner", "trivy", "--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["scan"]["findings"][0]["severity"] == "low"
    assert report["finding_counts"]["low"] == 1
    assert report["scan"]["coverage"]["trivy"]["analysis_status"] == "vulnerabilities_detected"
    history = History(tmp_path / "history")
    try:
        project = history.project("test", "local", str(tmp_path), "", "")
        run = history.start(project, "trivy", "scan")
        history.finish(run, {"report": report}, None)
        with history.connection() as db:
            saved = json.loads(db.execute("SELECT report FROM runs WHERE id=?", (run,)).fetchone()["report"])
        assert saved == report
    finally:
        history.lease.close()


@pytest.mark.parametrize("ecosystem,target", [("pub", "pubspec.lock"), ("pip", "requirements.txt"), ("npm", "package-lock.json")])
def test_zero_findings_preserves_package_and_database_evidence(monkeypatch, tmp_path, ecosystem, target):
    payload = {"SchemaVersion": 2, "Results": [{"Target": target, "Class": "lang-pkgs",
        "Type": ecosystem, "Packages": [{"Name": "example", "Version": "0.8.12+3",
                                         "Indirect": True, "Relationship": "indirect"}]}]}
    mock_output(monkeypatch, payload)
    scan = trivy.TrivyScanner().scan(tmp_path)
    coverage = scan.coverage["trivy"]
    assert scan.status == "completed" and not scan.findings
    assert coverage.analysis_status == "no_known_vulnerabilities" and coverage.limitations
    assert coverage.packages[0].version == "0.8.12+3"
    assert coverage.packages[0].relationship == "indirect"
    assert coverage.database["UpdatedAt"] == "2026-11-08T18:58:44Z"
    assert scan.scanner_version == "0.76.0"


@pytest.mark.parametrize("diagnostics,outcome", [
    (["WARN could not parse a dependency file"], "partial"),
    (["WARN The library type is not supported for vulnerability scanning"], "unsupported"),
])
def test_native_warnings_do_not_claim_complete_analysis(monkeypatch, tmp_path, payload, diagnostics, outcome):
    payload["Results"][0]["Vulnerabilities"] = []
    mock_output(monkeypatch, payload, diagnostics)
    scan = trivy.TrivyScanner().scan(tmp_path)
    assert scan.status == "partial"
    assert scan.coverage["trivy"].analysis_status == outcome
    assert scan.coverage["trivy"].packages and scan.warnings


def test_no_dependency_target_is_unconfirmed(monkeypatch, tmp_path):
    mock_output(monkeypatch, {"SchemaVersion": 2, "Results": []})
    scan = trivy.TrivyScanner().scan(tmp_path)
    assert scan.coverage["trivy"].analysis_status == "unconfirmed"
    assert scan.warnings and not scan.findings


def test_partial_inventory_keeps_valid_packages(monkeypatch, tmp_path, payload):
    payload["Results"].append({"Target": "other.lock", "Class": "lang-pkgs", "Type": "pub"})
    mock_output(monkeypatch, payload)
    scan = trivy.TrivyScanner().scan(tmp_path)
    assert scan.status == "partial"
    assert scan.coverage["trivy"].packages[0].name == "example"
    assert scan.errors and scan.findings


@pytest.mark.skipif(os.getenv("APPSEC_TRIVY_INTEGRATION") != "1" or not shutil.which("trivy"),
                    reason="Opt-in native Trivy test requires its binary and vulnerability database")
def test_native_flutter_lockfile_parses_direct_and_transitive_packages(tmp_path):
    shutil.copy(Path(__file__).parent / "fixtures/flutter/pubspec.lock", tmp_path / "pubspec.lock")
    scan = trivy.TrivyScanner().scan(tmp_path)
    assert scan.status == "completed", scan.errors
    packages = {package.name: package for package in scan.coverage["trivy"].packages}
    assert packages["image_picker"].version == "1.1.2"
    assert packages["image_picker"].relationship == "direct"
    assert packages["image_picker_android"].version == "0.8.12+3"
    assert packages["image_picker_android"].relationship == "indirect"
    # Advisory coverage changes with the database. Do not invent an expected native finding.
