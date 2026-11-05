import pytest

from appsec_triage.models.finding import Finding


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
