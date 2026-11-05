import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    semgrep_config: tuple[str, ...] = ("auto",)
    scan_timeout: int = Field(default=300, ge=1, le=86400)
    max_findings: int = Field(default=20, ge=0)
    openai_model: str = ""
    log_level: str = "INFO"

    @classmethod
    def load(cls, config: Path | None = None) -> "Settings":
        values = {}
        if config:
            with config.open("rb") as stream:
                values = tomllib.load(stream)
        for key in cls.model_fields:
            value = os.environ.get(key.upper())
            if value:
                values[key] = [value] if key == "semgrep_config" else value
        if isinstance(values.get("semgrep_config"), str):
            values["semgrep_config"] = [values["semgrep_config"]]
        settings = cls.model_validate(values)
        # Resolve local rules relative to the config file, before changing scanner cwd.
        base = config.resolve().parent if config else Path.cwd()
        settings.semgrep_config = tuple(
            str((base / item).resolve()) if (base / item).exists() else item
            for item in settings.semgrep_config
        )
        return settings
