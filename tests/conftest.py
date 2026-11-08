import pytest

from appsec_triage.models.finding import Finding
from appsec_triage.services.providers import PROVIDERS


@pytest.fixture(autouse=True)
def isolated_credentials(tmp_path, monkeypatch):
    """Never touch the real keychain, ~/.appsec-triage or the developer's provider keys."""
    monkeypatch.setenv("APPSEC_SECRET_BACKEND", "file")
    monkeypatch.setenv("APPSEC_DATA_DIR", str(tmp_path / "appsec-data"))
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    for provider in PROVIDERS.values():
        for name in (*provider.key_env, provider.model_env):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def finding():
    return Finding(id="finding-1", scanner="semgrep", rule_id="python.sql",
                   title="SQL injection", severity="high", message="Untrusted SQL",
                   file_path="app.py", start_line=1, end_line=1, cwe=["CWE-89"])


@pytest.fixture
def semgrep_payload():
    return {"version": "1.150.0", "results": [{
        "check_id": "python.sql", "path": "app.py",
        "start": {"line": 1, "col": 1}, "end": {"line": 2, "col": 10},
        "extra": {"severity": "ERROR", "message": "Unsafe query",
                  "metadata": {"cwe": "CWE-89", "confidence": "HIGH"},
                  "lines": "DO NOT COPY SOURCE"},
    }], "errors": []}
