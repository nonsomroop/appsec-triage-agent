import json
import subprocess
import sys

import pytest

from appsec_triage.cli import main
from appsec_triage.config import Settings
from appsec_triage.scanners import semgrep


def test_scan_cli_without_credentials(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.setattr(semgrep, "run_semgrep", lambda *args: (0, '{"results": [], "errors": []}'))
    assert main(["scan", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["scan"]["status"] == "completed"
    output = tmp_path / "reports" / "scan.json"
    assert main(["scan", str(tmp_path), "--output", str(output), "--verbose"]) == 0
    assert output.exists()


def test_missing_credentials(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        main(["triage", str(tmp_path)])
    assert exc.value.code == 2


def test_cli_invalid_target(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "absent")]) == 1
    assert json.loads(capsys.readouterr().out)["scan"]["errors"]


def test_cli_process():
    result = subprocess.run([sys.executable, "-m", "appsec_triage.cli", "--help"],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and "triage" in result.stdout


def test_config_precedence(monkeypatch, tmp_path):
    config = tmp_path / "settings.toml"
    config.write_text('max_findings = 4\nsemgrep_config = ["rules.yaml"]\n')
    (tmp_path / "rules.yaml").touch()
    monkeypatch.setenv("MAX_FINDINGS", "2")
    monkeypatch.delenv("SEMGREP_CONFIG", raising=False)
    settings = Settings.load(config)
    assert settings.max_findings == 2
    assert settings.semgrep_config == (str(tmp_path / "rules.yaml"),)


def test_invalid_limit(tmp_path):
    assert main(["scan", str(tmp_path), "--max-findings", "-1"]) == 2


def test_triage_cli_mocked_sdk(monkeypatch, tmp_path, semgrep_payload, capsys):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from agents import Runner
    from appsec_triage.models.assessment import AssessmentContent

    monkeypatch.setenv("OPENAI_API_KEY", "dummy-offline-test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")
    (tmp_path / "app.py").write_text("query = input()\nexecute(query)\n")
    monkeypatch.setattr(semgrep, "run_semgrep", lambda *args: (0, json.dumps(semgrep_payload)))
    output = AssessmentContent(verdict="needs_review", confidence=0.4,
                               reasoning_summary="Trust boundary unknown", evidence=["app.py:2 executes query"],
                               impact="Potential injection", remediation="Parameterise SQL")
    monkeypatch.setattr(Runner, "run", AsyncMock(return_value=SimpleNamespace(final_output=output)))
    assert main(["triage", str(tmp_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["assessments"][0]["verdict"] == "needs_review"
    assert report["finding_counts"]["total"] == 1
