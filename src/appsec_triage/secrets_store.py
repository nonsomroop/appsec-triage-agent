"""Local storage for AI provider keys and non-secret AI preferences.

Keys go to the OS credential store (macOS Keychain, Windows Credential Manager,
Linux Secret Service) when one is available. Otherwise, as in containers, they
go to a JSON file that only the current user can read, like other CLI tools'
credential files. Keys are never logged, written to scan history or reports,
or returned to the browser.
"""
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from appsec_triage.services.providers import PROVIDERS, Provider

SERVICE = "appsec-triage"
# Printable ASCII without spaces; provider keys are 30-200 characters in practice.
KEY_FORMAT = re.compile(r"[\x21-\x7e]{20,512}")
MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}")


def data_dir() -> Path:
    return Path(os.getenv("APPSEC_DATA_DIR") or Path.home() / ".appsec-triage")


def read_private(path: Path) -> dict:
    """Read a JSON object, tightening permissions and refusing symlinks."""
    try:
        if path.is_symlink():
            return {}
        if os.name != "nt" and path.stat().st_mode & 0o077:
            os.chmod(path, 0o600)
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_private(path: Path, data: dict) -> None:
    """Atomically replace a JSON file with owner-only permissions."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkstemp creates the file with mode 0600 before any content is written.
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


class KeyStore:
    def __init__(self, directory: Path | None = None, backend: str | None = None):
        self.file = Path(directory or data_dir()) / "credentials.json"
        self.backend = backend or self._detect()

    @staticmethod
    def _detect() -> str:
        if os.getenv("APPSEC_SECRET_BACKEND", "").lower() == "file" or os.getenv("APPSEC_CONTAINER") == "1":
            return "file"
        try:
            import keyring

            keyring.get_password(SERVICE, "__probe__")
            return "keychain"
        except Exception:
            return "file"

    def describe(self) -> str:
        if self.backend == "keychain":
            return {"darwin": "macOS Keychain", "win32": "Windows Credential Manager"}.get(
                sys.platform, "the system keyring")
        return f"{self.file} (readable only by your user account)"

    def get(self, provider: str) -> str | None:
        if self.backend == "keychain":
            import keyring

            return keyring.get_password(SERVICE, provider)
        value = read_private(self.file).get(provider)
        return value if isinstance(value, str) else None

    def set(self, provider: str, key: str) -> None:
        if provider not in PROVIDERS or not KEY_FORMAT.fullmatch(key):
            raise ValueError("Invalid provider or key format")
        if self.backend == "keychain":
            import keyring

            keyring.set_password(SERVICE, provider, key)
            return
        data = read_private(self.file)
        data[provider] = key
        write_private(self.file, data)

    def delete(self, provider: str) -> None:
        if self.backend == "keychain":
            import keyring
            from keyring.errors import PasswordDeleteError

            try:
                keyring.delete_password(SERVICE, provider)
            except PasswordDeleteError:
                pass
            return
        data = read_private(self.file)
        if data.pop(provider, None) is not None:
            write_private(self.file, data)


def env_key(provider: Provider) -> tuple[str, str] | None:
    for name in provider.key_env:
        value = os.environ.get(name, "").strip()
        if value:
            return name, value
    return None


def resolve_key(provider: Provider, store: KeyStore) -> tuple[str | None, str | None]:
    """Environment variables take precedence over stored keys."""
    found = env_key(provider)
    if found:
        return found[1], "environment"
    try:
        key = store.get(provider.name)
    except Exception:
        key = None
    return (key, store.backend) if key else (None, None)


class Preferences:
    def __init__(self, directory: Path | None = None):
        self.file = Path(directory or data_dir()) / "preferences.json"

    def load(self) -> dict:
        data = read_private(self.file)
        provider = data.get("provider")
        models = data.get("models") if isinstance(data.get("models"), dict) else {}
        return {"provider": provider if provider in PROVIDERS else None,
                "models": {name: model for name, model in models.items()
                           if name in PROVIDERS and isinstance(model, str) and MODEL_ID.fullmatch(model)}}

    def save(self, provider: str | None = None, models: dict | None = None) -> dict:
        data = self.load()
        if provider is not None:
            if provider not in PROVIDERS:
                raise ValueError("Unknown provider")
            data["provider"] = provider
        for name, model in (models or {}).items():
            if name not in PROVIDERS or not isinstance(model, str):
                raise ValueError("Invalid model preference")
            model = model.strip()
            if model and not MODEL_ID.fullmatch(model):
                raise ValueError("Invalid model ID")
            if model:
                data["models"][name] = model
            else:
                data["models"].pop(name, None)
        write_private(self.file, data)
        return data

    def model(self, provider: Provider) -> str:
        return (os.environ.get(provider.model_env, "").strip()
                or self.load()["models"].get(provider.name) or provider.default_model)
