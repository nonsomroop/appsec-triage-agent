"""AI provider metadata. Key lookup and storage live in appsec_triage.secrets_store."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    name: str
    label: str
    key_env: tuple[str, ...]
    model_env: str
    default_model: str = ""
    key_url: str = ""


PROVIDERS = {
    "openai": Provider("openai", "OpenAI", ("OPENAI_API_KEY",), "OPENAI_MODEL",
                       key_url="https://platform.openai.com/api-keys"),
    "anthropic": Provider("anthropic", "Anthropic Claude", ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
                          "ANTHROPIC_MODEL", "claude-opus-5-5", "https://platform.claude.com/settings/keys"),
    "gemini": Provider("gemini", "Google Gemini", ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
                       "GEMINI_MODEL", "gemini-3.8-flash", "https://aistudio.google.com/apikey"),
}
