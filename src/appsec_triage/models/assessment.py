from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class AssessmentContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Literal["likely_true_positive", "likely_false_positive", "needs_review"]
    confidence: float = Field(ge=0, le=1)
    reasoning_summary: str = Field(min_length=1, max_length=8000)
    evidence: list[str] = Field(max_length=30)
    impact: str = Field(min_length=1, max_length=4000)
    remediation: str = Field(min_length=1, max_length=4000)


class Assessment(AssessmentContent):
    finding_id: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    assessed_at: AwareDatetime
