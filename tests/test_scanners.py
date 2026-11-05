import json
import subprocess
import sys

import pytest

from appsec_triage.scanners import semgrep
from appsec_triage.scanners.semgrep import ScannerError, SemgrepScanner, parse_semgrep, run_semgrep


def test_normalisation(tmp_path, semgrep_payload):
    findings, errors = parse_semgrep(semgrep_payload, tmp_path)
    assert errors == []
    assert findings[0].severity == "high"
    assert findings[0].cwe == ["CWE-89"]
    assert findings[0].file_path == "app.py"
    assert findings[0].metadata["rule_metadata"]["confidence"] == "HIGH"
    assert "DO NOT COPY SOURCE" not in findings[0].model_dump_json()
    assert findings[0].id == parse_semgrep(semgrep_payload, tmp_path)[0][0].id


def test_invalid_result_retains_good_findings(tmp_path, semgrep_payload):
    semgrep_payload["results"].append({"path": "../outside.py"})
    findings, errors = parse_semgrep(semgrep_payload, tmp_path)
    assert len(findings) == len(errors) == 1


def test_outside_path(tmp_path, semgrep_payload):
    semgrep_payload["results"][0]["path"] = "../outside.py"
    findings, errors = parse_semgrep(semgrep_payload, tmp_path)
    assert not findings and errors


@pytest.mark.parametrize("payload", [[], {}, {"results": {}}])
def test_invalid_json_structure(tmp_path, payload):
    with pytest.raises(ScannerError):
        parse_semgrep(payload, tmp_path)


def test_empty_scan(monkeypatch, tmp_path):
    def execute(command, root, timeout, limit):
        assert command[-2:] == ["--", "."]
        assert "--oss-only" in command and "--metrics=auto" in command
        assert root == tmp_path
        return 0, '{"results": [], "errors": [], "version": "test"}'
    monkeypatch.setattr(semgrep, "run_semgrep", execute)
    scan = SemgrepScanner().scan(tmp_path)
    assert scan.status == "completed" and scan.findings == []
    assert scan.scanner_version == "test" and scan.completed_at


@pytest.mark.parametrize("result", [(2, "bad json"), (2, '{"results": [], "errors": []}')])
def test_execution_failure(monkeypatch, tmp_path, result):
    monkeypatch.setattr(semgrep, "run_semgrep", lambda *args: result)
    scan = SemgrepScanner().scan(tmp_path)
    assert scan.status == "failed" and scan.errors


def test_partial_scan(monkeypatch, tmp_path, semgrep_payload):
    monkeypatch.setattr(semgrep, "run_semgrep", lambda *args: (2, json.dumps(semgrep_payload)))
    scan = SemgrepScanner().scan(tmp_path)
    assert scan.status == "partial" and len(scan.findings) == 1


def test_invalid_target(tmp_path):
    assert SemgrepScanner().scan(tmp_path / "absent").status == "failed"
    file = tmp_path / "file"
    file.touch()
    assert SemgrepScanner().scan(file).status == "failed"


def test_missing_executable(monkeypatch, tmp_path):
    def missing(*args, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["stdin"] == subprocess.DEVNULL
        raise FileNotFoundError
    monkeypatch.setattr(semgrep.subprocess, "Popen", missing)
    with pytest.raises(ScannerError, match="not found"):
        run_semgrep(["missing"], tmp_path, 1, 1000)


def test_real_subprocess_limits(tmp_path):
    with pytest.raises(ScannerError, match="timed out"):
        run_semgrep([sys.executable, "-c", "import time; time.sleep(10)"], tmp_path, 0.1, 1000)
    with pytest.raises(ScannerError, match="limit"):
        run_semgrep([sys.executable, "-c", "print('x' * 2000)"], tmp_path, 5, 1000)
