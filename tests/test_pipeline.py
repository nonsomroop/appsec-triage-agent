import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from appsec_triage.models.scan import Scan
from appsec_triage.reporting.json_reporter import write_report
from appsec_triage.services.pipeline import Pipeline


def test_scan_without_triage_and_json(tmp_path, finding):
    scan = Scan(target=str(tmp_path), scanner="test", status="completed", findings=[finding])
    report = asyncio.run(Pipeline(SimpleNamespace(scan=lambda target: scan)).run(tmp_path))
    path = tmp_path / "reports" / "scan.json"
    write_report(report, path)
    result = json.loads(path.read_text())
    assert result["scan"]["id"] == scan.id
    assert result["finding_counts"] == {"total": 1, "high": 1}
    assert result["triage_enabled"] is False


def test_failures_keep_findings_and_limit(tmp_path, finding):
    findings = [finding.model_copy(update={"id": str(i)}) for i in range(3)]
    scan = Scan(target=str(tmp_path), scanner="test", status="completed", findings=findings)
    triage = SimpleNamespace(assess=AsyncMock(side_effect=RuntimeError("sensitive payload")))
    report = asyncio.run(Pipeline(SimpleNamespace(scan=lambda target: scan), triage).run(tmp_path, 2))
    assert len(report.scan.findings) == 3 and len(report.failed_assessments) == 2
    assert triage.assess.call_count == 2
    assert "sensitive payload" not in report.model_dump_json()
    assert report.assessment_counts == {"completed": 0, "failed": 2, "not_assessed": 1}


def test_zero_limit(tmp_path, finding):
    scan = Scan(target=str(tmp_path), scanner="test", findings=[finding])
    triage = SimpleNamespace(assess=AsyncMock())
    report = asyncio.run(Pipeline(SimpleNamespace(scan=lambda target: scan), triage).run(tmp_path, 0))
    triage.assess.assert_not_called()
    assert report.scan.findings == [finding]
