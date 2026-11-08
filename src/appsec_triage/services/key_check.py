"""Check an AI provider key with a free model-listing call.

Listing models proves the key authenticates and shows which models it can use,
without spending tokens. It does not prove billing or quota for generation.
Provider error text is never returned because it can echo request details.
"""
import asyncio
from dataclasses import asdict, dataclass, field

MAX_MODELS = 200
TIMEOUT = 15


@dataclass
class KeyCheck:
    status: str  # valid, invalid, unreachable
    message: str
    models: list[str] = field(default_factory=list)
    model_available: bool | None = None

    def public(self) -> dict:
        return asdict(self)


async def _openai_models(key: str) -> list[str]:
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=key, timeout=TIMEOUT, max_retries=0)
    return [model.id async for model in client.models.list()]


async def _anthropic_models(key: str) -> list[str]:
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic(api_key=key, timeout=TIMEOUT, max_retries=0)
    return [model.id async for model in client.models.list(limit=100)]


async def _gemini_models(key: str) -> list[str]:
    from google import genai

    client = genai.Client(api_key=key)
    names = []
    async for model in await client.aio.models.list(config={"page_size": 100}):
        if not model.supported_actions or "generateContent" in model.supported_actions:
            names.append((model.name or "").removeprefix("models/"))
    return [name for name in names if name]


LISTERS = {"openai": _openai_models, "anthropic": _anthropic_models, "gemini": _gemini_models}


def describe_failure(exc: Exception) -> KeyCheck:
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    name = type(exc).__name__
    if status in (400, 401):
        return KeyCheck("invalid", "The provider rejected this key. Check that it was copied completely and has not been revoked.")
    if status == 403:
        return KeyCheck("invalid", "The key was recognised but lacks permission to list models. Check its project or workspace permissions.")
    if status == 429:
        return KeyCheck("valid", "The key works, but the provider is rate limiting it or the account is out of quota.")
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or "Timeout" in name or "Connection" in name:
        return KeyCheck("unreachable", "Could not reach the provider. Check your network or proxy and try again.")
    if isinstance(status, int) and status >= 500:
        return KeyCheck("unreachable", f"The provider returned a server error ({status}). Try again shortly.")
    return KeyCheck("unreachable", f"The key could not be checked ({name}).")


async def check_key(provider: str, key: str, model: str = "") -> KeyCheck:
    if provider not in LISTERS:
        raise ValueError("Unknown provider")
    try:
        async with asyncio.timeout(TIMEOUT * 2):
            models = sorted(set(await LISTERS[provider](key)))[:MAX_MODELS]
    except Exception as exc:
        return describe_failure(exc)
    if not model:
        return KeyCheck("valid", f"Key is valid. {len(models)} models available.", models)
    if model in models:
        return KeyCheck("valid", f"Key is valid and can use {model}.", models, True)
    return KeyCheck("valid", f"Key is valid, but {model} is not in the models this key can use. Pick one from the list.",
                    models, False)


def run_check(provider: str, key: str, model: str = "") -> KeyCheck:
    return asyncio.run(check_key(provider, key, model))
