import asyncio
import json
import os
import stat

import pytest

from appsec_triage.secrets_store import KeyStore, Preferences, resolve_key
from appsec_triage.services import key_check
from appsec_triage.services.providers import PROVIDERS

KEY = "sk-ant-api03-offline-test-key-abcd1234"


def test_file_store_is_private_and_atomic(tmp_path):
    store = KeyStore(tmp_path / "data", backend="file")
    store.set("anthropic", KEY)
    store.set("openai", "sk-offline-openai-test-key-0000")
    store.delete("openai")
    assert json.loads(store.file.read_text()) == {"anthropic": KEY}
    assert not list(store.file.parent.glob(".tmp-*"))
    if os.name != "nt":
        assert stat.S_IMODE(store.file.stat().st_mode) == 0o600
        assert stat.S_IMODE(store.file.parent.stat().st_mode) == 0o700
        os.chmod(store.file, 0o644)
        assert store.get("anthropic") == KEY
        assert stat.S_IMODE(store.file.stat().st_mode) == 0o600


def test_store_rejects_bad_input_and_symlinks(tmp_path):
    store = KeyStore(tmp_path, backend="file")
    for provider, key in (("unknown", KEY), ("anthropic", "short"), ("anthropic", KEY + " x")):
        with pytest.raises(ValueError):
            store.set(provider, key)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(json.dumps({"anthropic": KEY}))
    store.file.symlink_to(elsewhere)
    assert store.get("anthropic") is None


def test_tests_never_use_the_real_keychain():
    assert KeyStore().backend == "file"


def test_environment_takes_precedence(tmp_path, monkeypatch):
    store = KeyStore(tmp_path, backend="file")
    store.set("gemini", "AIzaSy-stored-gemini-key-000000000")
    assert resolve_key(PROVIDERS["gemini"], store) == ("AIzaSy-stored-gemini-key-000000000", "file")
    monkeypatch.setenv("GOOGLE_API_KEY", "AIzaSy-environment-key-0000000000")
    assert resolve_key(PROVIDERS["gemini"], store) == ("AIzaSy-environment-key-0000000000", "environment")


def test_preferences(tmp_path, monkeypatch):
    prefs = Preferences(tmp_path)
    prefs.save("anthropic", {"anthropic": "claude-sonnet-5-5"})
    assert prefs.load() == {"provider": "anthropic", "models": {"anthropic": "claude-sonnet-5-5"}}
    assert prefs.model(PROVIDERS["anthropic"]) == "claude-sonnet-5-5"
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-5-5")
    assert prefs.model(PROVIDERS["anthropic"]) == "claude-opus-5-5"
    prefs.save(models={"anthropic": ""})
    assert prefs.load()["models"] == {}
    with pytest.raises(ValueError):
        prefs.save(models={"anthropic": "-x"})


class StatusError(Exception):
    def __init__(self, status):
        super().__init__("provider said: key sk-ant-secret is wrong")
        self.status_code = status


class APIConnectionError(Exception):
    pass


@pytest.mark.parametrize("error,status", [
    (StatusError(401), "invalid"), (StatusError(400), "invalid"), (StatusError(403), "invalid"),
    (StatusError(429), "valid"), (StatusError(503), "unreachable"),
    (APIConnectionError("dns"), "unreachable"), (TimeoutError(), "unreachable"),
    (type("ClientError", (Exception,), {"code": 400})(), "invalid"),
])
def test_failures_map_without_echoing_provider_text(error, status):
    result = key_check.describe_failure(error)
    assert result.status == status
    assert "sk-ant-secret" not in result.message


def test_check_key_reports_model_availability(monkeypatch):
    async def models(key):
        assert key == KEY
        return ["claude-sonnet-5-5", "claude-opus-5-5", "claude-opus-5-5"]
    monkeypatch.setitem(key_check.LISTERS, "anthropic", models)
    ok = asyncio.run(key_check.check_key("anthropic", KEY, "claude-opus-5-5"))
    assert ok.status == "valid" and ok.model_available and ok.models == ["claude-opus-5-5", "claude-sonnet-5-5"]
    missing = asyncio.run(key_check.check_key("anthropic", KEY, "claude-missing"))
    assert missing.status == "valid" and missing.model_available is False

    async def fails(key):
        raise StatusError(401)
    monkeypatch.setitem(key_check.LISTERS, "anthropic", fails)
    assert asyncio.run(key_check.check_key("anthropic", KEY)).status == "invalid"


def test_cli_uses_stored_key_and_preferences(monkeypatch, tmp_path, semgrep_payload, capsys):
    from unittest.mock import AsyncMock
    from appsec_triage.cli import main
    from appsec_triage.scanners import semgrep
    from appsec_triage.services import triage

    seen = []
    class FakeBackend:
        def __init__(self, model):
            seen.append((model, os.environ.get("ANTHROPIC_API_KEY")))
        assess = AsyncMock(return_value=dict(verdict="needs_review", confidence=0.4, reasoning_summary="Unknown",
                                              evidence=["app.py:2"], impact="Possible", remediation="Review"))
    monkeypatch.setitem(triage.BACKENDS, "anthropic", FakeBackend)
    KeyStore().set("anthropic", KEY)
    Preferences().save("anthropic", {"anthropic": "claude-sonnet-5-5"})
    (tmp_path / "app.py").write_text("query = input()\nexecute(query)\n")
    monkeypatch.setattr(semgrep, "run_semgrep", lambda *args: (0, json.dumps(semgrep_payload)))
    assert main(["triage", str(tmp_path)]) == 0
    assert seen == [("claude-sonnet-5-5", KEY)]
    assert KEY not in capsys.readouterr().out
