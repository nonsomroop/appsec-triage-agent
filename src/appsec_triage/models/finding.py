from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    scanner: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"]
    message: str
    file_path: str = Field(min_length=1)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    category: Literal["sast", "sca", "secret"] = "sast"
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    vulnerability_id: str | None = None
    source_snippet: str | None = None
    source_error: str | None = None
    cwe: list[str] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ordered_lines(self) -> "Finding":
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("Both source line bounds must be provided together")
        if self.start_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line must be at least start_line")
        return self
