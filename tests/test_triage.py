import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from appsec_triage.models.assessment import AssessmentContent
from appsec_triage.services.triage import AgentsBackend, TriageService
from appsec_triage.utils.source_reader import SourceReader


def content(**changes):
    return dict(verdict="likely_true_positive", confidence=0.8,
                reasoning_summary="Observed concatenation; input trust is an assumption.",
                evidence=["app.py:1 concatenates SQL"], impact="SQL injection",
                remediation="Use bound parameters", **changes)


def test_mocked_assessment(tmp_path, finding):
    (tmp_path / "app.py").write_text("query = 'SELECT ' + user_input")
    backend = SimpleNamespace(assess=AsyncMock(return_value=content()))
    assessment = asyncio.run(TriageService(SourceReader(tmp_path), "test-model", backend).assess(finding))
    assert assessment.finding_id == finding.id
    assert assessment.model_name == "test-model"
    assert assessment.verdict == "likely_true_positive"
    assert "source_context" in backend.assess.call_args.args[0]


def test_missing_context_never_calls_model(tmp_path, finding):
    backend = SimpleNamespace(assess=AsyncMock())
    assessment = asyncio.run(TriageService(SourceReader(tmp_path), "test", backend).assess(finding))
    assert assessment.verdict == "needs_review" and assessment.model_name == "not_called"
    backend.assess.assert_not_called()


def test_invalid_model_output(tmp_path, finding):
    (tmp_path / "app.py").write_text("pass")
    backend = SimpleNamespace(assess=AsyncMock(return_value={"verdict": "safe"}))
    with pytest.raises(ValidationError):
        asyncio.run(TriageService(SourceReader(tmp_path), "test", backend).assess(finding))


def test_empty_evidence_requires_review(tmp_path, finding):
    (tmp_path / "app.py").write_text("pass")
    response = {**content(), "evidence": [], "verdict": "likely_false_positive"}
    backend = SimpleNamespace(assess=AsyncMock(return_value=response))
    result = asyncio.run(TriageService(SourceReader(tmp_path), "test", backend).assess(finding))
    assert result.verdict == "needs_review"


def test_timeout(tmp_path, finding):
    (tmp_path / "app.py").write_text("pass")
    async def slow(prompt):
        await asyncio.sleep(1)
    backend = SimpleNamespace(assess=slow)
    with pytest.raises(TimeoutError):
        asyncio.run(TriageService(SourceReader(tmp_path), "test", backend, timeout=0.01).assess(finding))


def test_sdk_adapter(monkeypatch):
    from agents import Runner
    response = AssessmentContent(**content())
    run = AsyncMock(return_value=SimpleNamespace(final_output=response))
    monkeypatch.setattr(Runner, "run", run)
    backend = AgentsBackend("test-model")
    assert asyncio.run(backend.assess("untrusted")) == response
    assert backend.agent.tools == []
    assert backend.agent.model_settings.store is False
    assert run.call_args.kwargs["max_turns"] == 1
    assert run.call_args.kwargs["run_config"].tracing_disabled is True
