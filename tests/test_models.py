from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from appsec_triage.models.assessment import Assessment
from appsec_triage.models.finding import Finding
from appsec_triage.models.scan import Scan


@pytest.mark.parametrize("change", [
    {"start_line": 0}, {"end_line": 0}, {"start_line": 2, "end_line": 1},
    {"severity": "urgent"}, {"id": ""}, {"unexpected": True},
])
def test_invalid_finding(finding, change):
    with pytest.raises(ValidationError):
        Finding.model_validate({**finding.model_dump(), **change})


@pytest.mark.parametrize("change", [{"confidence": 1.1}, {"confidence": -0.1},
                                        {"verdict": "confirmed"}, {"assessed_at": "2026-01-01T00:00:00"}])
def test_invalid_assessment(change):
    data = dict(finding_id="id", verdict="needs_review", confidence=0.5,
                reasoning_summary="Missing context", evidence=[], impact="Unknown",
                remediation="Review", model_name="test", assessed_at=datetime.now(timezone.utc))
    with pytest.raises(ValidationError):
        Assessment(**{**data, **change})


def test_scan_timestamps():
    with pytest.raises(ValidationError):
        Scan(target=".", scanner="test", started_at="2026-02-01T00:00:00Z",
             completed_at="2026-01-01T00:00:00Z")
