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
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    cwe: list[str] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ordered_lines(self) -> "Finding":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be at least start_line")
        return self
