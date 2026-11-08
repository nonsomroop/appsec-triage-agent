import json
import subprocess
import sys

import pytest

from appsec_triage.scanners import semgrep
from appsec_triage.scanners.semgrep import ScannerError, SemgrepScanner, parse_semgrep, run_semgrep


def test_normalisation(tmp_path, semgrep_payload):
    findings, errors, _ = parse_semgrep(semgrep_payload, tmp_path)
    assert errors == []
    assert findings[0].severity == "high"
    assert findings[0].cwe == ["CWE-89"]
    assert findings[0].file_path == "app.py"
    assert findings[0].metadata["rule_metadata"]["confidence"] == "HIGH"
    assert "DO NOT COPY SOURCE" not in findings[0].model_dump_json()
    assert findings[0].id == parse_semgrep(semgrep_payload, tmp_path)[0][0].id


def test_invalid_result_retains_good_findings(tmp_path, semgrep_payload):
    semgrep_payload["results"].append({"path": "../outside.py"})
    findings, errors, _ = parse_semgrep(semgrep_payload, tmp_path)
    assert len(findings) == len(errors) == 1


def test_outside_path(tmp_path, semgrep_payload):
    semgrep_payload["results"][0]["path"] = "../outside.py"
    findings, errors, _ = parse_semgrep(semgrep_payload, tmp_path)
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


def test_source_excerpt_survives_report_export(tmp_path, semgrep_payload):
    (tmp_path / "app.py").write_text("query = input()\nexecute(query)\n", encoding="utf-8")
    findings, errors, _ = parse_semgrep(semgrep_payload, tmp_path)
    assert not errors
    assert findings[0].source_snippet == "1: query = input()\n2: execute(query)"
    assert findings[0].source_error is None
    assert "execute(query)" in findings[0].model_dump_json()


def test_unavailable_excerpt_preserves_finding(tmp_path, semgrep_payload):
    findings, errors, _ = parse_semgrep(semgrep_payload, tmp_path)
    assert not errors and len(findings) == 1
    assert findings[0].source_snippet is None
    assert findings[0].source_error


def test_excluded_source_is_not_embedded(tmp_path, semgrep_payload):
    (tmp_path / ".env").write_text("SECRET=value\nOTHER=value\n", encoding="utf-8")
    semgrep_payload["results"][0]["path"] = ".env"
    findings, errors, _ = parse_semgrep(semgrep_payload, tmp_path)
    assert not errors
    assert findings[0].source_snippet is None
    assert findings[0].source_error == "Source path is excluded"


def test_semgrep_problems_become_safe_readable_warnings(tmp_path, semgrep_payload):
    semgrep_payload["errors"] = [
        {"level": "warn", "type": ["PartialParsing", [{"path": "x"}]], "path": "src/HomePage.tsx",
         "message": "Syntax error at line 3: const SECRET = 'hunter2'", "spans": [{"file": "src/HomePage.tsx"}]},
        {"level": "warn", "type": "Syntax error", "path": str(tmp_path / "data" / "loc.json"), "message": "token 'AKIA123'"},
        {"level": "error", "type": "Timeout", "path": "big.js", "rule_id": "javascript.lang.rule-x", "message": "slow"},
        {"level": "error", "type": "<script>alert(1)</script>", "message": "weird"},
        "not a dict",
    ]
    findings, errors, warnings = parse_semgrep(semgrep_payload, tmp_path)
    assert warnings == ["src/HomePage.tsx was only partly parsed; some code in it was not analysed",
                        "data/loc.json could not be parsed and was skipped"]
    assert errors == ["big.js timed out for at least one rule; it may be incompletely analysed (rule javascript.lang.rule-x)",
                      "Semgrep reported “Unknown problem”", "Semgrep reported scan error 4"]
    text = " ".join(errors + warnings)
    assert "hunter2" not in text and "AKIA123" not in text and "<script>" not in text


def test_warnings_alone_keep_scan_completed(monkeypatch, tmp_path):
    payload = {"results": [], "version": "1", "errors": [{"level": "warn", "type": "PartialParsing", "path": "a.tsx"}]}
    monkeypatch.setattr(semgrep, "run_semgrep", lambda *args: (0, json.dumps(payload)))
    scan = SemgrepScanner().scan(tmp_path)
    assert scan.status == "completed" and scan.errors == [] and len(scan.warnings) == 1
