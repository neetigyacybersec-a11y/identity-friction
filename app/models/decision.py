"""Decision model.

Whatever backend produces a judgement, it arrives as a `Decision`. The rest of
the application only ever reads this shape, which is the entire point of the
`DecisionEngine` interface in app/decision/engine.py.

Names are deliberately narrow. See CONTEXT.md: this is a *signal*, not a
confirmed attack, and no field here claims otherwise.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AttackType(str, Enum):
    """A short, closed taxonomy.

    Thirty classes would be thirty classes nobody could calibrate against.
    Each of these needs a definition an analyst can argue with, and that is
    the real constraint.
    """

    BENIGN = "benign"
    PASSWORD_SPRAY = "password_spray"
    MFA_FATIGUE = "mfa_fatigue"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    OAUTH_ABUSE = "oauth_abuse"
    ACCOUNT_COMPROMISE = "account_compromise"
    UNKNOWN = "unknown"


class ConfidenceBand(str, Enum):
    """Confidence mapped onto behaviour, following TypeSafe's documented
    confidence-routing pattern: a floor, then a per-stakes threshold.

    A low band is a normal outcome, not an error. It means the system is
    declining to act on its own guess, which is the correct thing to do.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DecisionSource(str, Enum):
    JEV = "jev"
    RULES = "rules"
    UNAVAILABLE = "unavailable"


class Decision(BaseModel):
    """A structured judgement about one candidate."""

    suspicious: bool = False
    suspicion_score: float = Field(default=0.0, ge=0.0, le=1.0)

    attack_type: AttackType = AttackType.UNKNOWN
    severity: int = Field(default=1, ge=1, le=10)

    escalate: bool = False
    needs_analyst_review: bool = False

    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    band: ConfidenceBand = ConfidenceBand.LOW

    source: DecisionSource = DecisionSource.UNAVAILABLE
    reasoning: str = ""
    raw_response: dict[str, Any] | None = None

    def recompute_band(self, high: float, medium: float) -> "Decision":
        """Fill in `band` from `confidence` and the configured thresholds.

        Kept as a method rather than done once at parse time so the bands stay
        in one place if the thresholds change.
        """
        if self.confidence >= high:
            self.band = ConfidenceBand.HIGH
        elif self.confidence >= medium:
            self.band = ConfidenceBand.MEDIUM
        else:
            self.band = ConfidenceBand.LOW
            # Below the floor we will not act on the classification, whatever it says.
            self.needs_analyst_review = True
        return self
