"""Investigation report: the System Two output.

`limitations` is a required field, not decoration. An investigation report that
lists evidence without listing what it could not see is the exact failure mode
that makes an LLM dangerous in a SOC — it reads as authoritative and it is not.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class InvestigationReport(BaseModel):
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    attack_hypothesis: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.summary and not self.evidence
