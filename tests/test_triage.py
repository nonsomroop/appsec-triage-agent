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


def test_anthropic_adapter(monkeypatch):
    from appsec_triage.services.triage import INSTRUCTIONS, AnthropicBackend
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy-offline-test-key")
    response = AssessmentContent(**content())
    backend = AnthropicBackend("claude-opus-5-5")
    parse = AsyncMock(return_value=SimpleNamespace(stop_reason="end_turn", parsed_output=response))
    monkeypatch.setattr(backend.client.beta.messages, "parse", parse)
    assert asyncio.run(backend.assess("untrusted")) == response
    kwargs = parse.call_args.kwargs
    assert kwargs["system"] == INSTRUCTIONS and kwargs["output_format"] is AssessmentContent
    assert kwargs["fallbacks"] == "default" and "tools" not in kwargs
    parse.return_value = SimpleNamespace(stop_reason="refusal", parsed_output=None)
    with pytest.raises(ValueError, match="refusal"):
        asyncio.run(backend.assess("untrusted"))


def test_anthropic_adapter_older_model_skips_fallbacks(monkeypatch):
    from appsec_triage.services.triage import AnthropicBackend
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy-offline-test-key")
    backend = AnthropicBackend("claude-haiku-4-5")
    parse = AsyncMock(return_value=SimpleNamespace(stop_reason="end_turn", parsed_output=AssessmentContent(**content())))
    monkeypatch.setattr(backend.client.beta.messages, "parse", parse)
    asyncio.run(backend.assess("untrusted"))
    assert "fallbacks" not in parse.call_args.kwargs and "output_config" not in parse.call_args.kwargs


def test_gemini_adapter(monkeypatch):
    import json
    from appsec_triage.services.triage import INSTRUCTIONS, GeminiBackend
    monkeypatch.setenv("GEMINI_API_KEY", "dummy-offline-test-key")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    backend = GeminiBackend("gemini-3.8-flash")
    generate = AsyncMock(return_value=SimpleNamespace(text=json.dumps(content())))
    monkeypatch.setattr(backend.client.aio.models, "generate_content", generate)
    assert asyncio.run(backend.assess("untrusted")).verdict == "likely_true_positive"
    retry = backend.client._api_client._http_options.retry_options
    assert retry.attempts == 3 and 503 in retry.http_status_codes
    config = generate.call_args.kwargs["config"]
    assert config.system_instruction == INSTRUCTIONS and config.response_mime_type == "application/json"
    assert not config.tools
    generate.return_value = SimpleNamespace(text='{"verdict": "safe"}')
    with pytest.raises(ValidationError):
        asyncio.run(backend.assess("untrusted"))


def test_create_backend():
    from appsec_triage.services.triage import create_backend
    with pytest.raises(ValueError):
        create_backend("unknown", "model")
