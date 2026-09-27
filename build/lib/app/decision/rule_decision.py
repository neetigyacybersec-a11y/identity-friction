"""The offline decision engine.

This is the fallback that keeps the project demonstrable with no API key, and it
is a real implementation rather than a placeholder. It derives a judgement from
the detection evidence already computed: the severities the detectors assigned,
how many independent rules fired, and which attack types are in play.

Two rules about what it will not do:

1. It never invents evidence. Every number it reports comes from the incident.
2. It never claims higher confidence than the evidence supports. Agreement
   between two deterministic rules is a stronger signal than one, and absence of
   agreement is a weaker one, so confidence is derived rather than asserted.
"""

from __future__ import annotations

import hashlib
import json

from app.config import Settings
from app.decision.engine import DecisionEngine, DecisionRequest
from app.models.decision import (
    AttackType,
    ConfidenceBand,
    Decision,
    DecisionSource,
)
from app.models.incident import Incident, describe

# The lowest confidence this engine will ever report. A rule-only judgement with
# no model behind it is a weak claim, and reporting 0.95 because two rules agreed
# would misrepresent what a deterministic pipeline can know.
MAX_RULE_CONFIDENCE = 0.70

# Base confidence for a single detection, before corroboration.
SINGLE_DETECTION_CONFIDENCE = 0.45


class RuleDecisionEngine(DecisionEngine):
    """Decides from detection evidence, offline and deterministically."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def decide(self, request: DecisionRequest) -> Decision:
        incident = request.incident
        detections = sorted(
            {finding.detection.value for finding in incident.detections}
        )
        count = len(detections)

        if count == 0:
            return Decision(
                suspicious=False,
                suspicion_score=0.0,
                attack_type=AttackType.BENIGN,
                severity=1,
                confidence=0.0,
                band=ConfidenceBand.LOW,
                source=DecisionSource.RULES,
                reasoning="No detection fired for this incident.",
            )

        # Corroboration: two independent rules firing on the same incident is
        # materially stronger than one, and the gain tapers because a third rule
        # on an already-compromised account is expected.
        confidence = min(
            MAX_RULE_CONFIDENCE,
            SINGLE_DETECTION_CONFIDENCE + 0.20 * (count - 1),
        )

        severity = self._severity(incident.severity, count)
        score = min(1.0, round(severity / 10, 2))

        return Decision(
            suspicious=True,
            suspicion_score=score,
            attack_type=incident.attack_type,
            severity=severity,
            escalate=severity >= 8 or incident.attack_type is AttackType.ACCOUNT_COMPROMISE,
            needs_analyst_review=True,
            confidence=round(confidence, 2),
            band=ConfidenceBand.LOW,
            source=DecisionSource.RULES,
            reasoning=self._reasoning(incident, detections, severity),
            raw_response=self._evidence(incident, detections),
        )

    def describe(self) -> str:
        return "RuleDecisionEngine (offline, deterministic)"

    @staticmethod
    def _severity(detector_severity: int, detection_count: int) -> int:
        """The detectors set the floor; agreement between rules adds a little.

        Capped at 10. Adding to the detector's own score rather than
        recomputing from scratch keeps the two layers consistent: the rule engine
        is not a second opinion that can disagree with the detection it is
        summarising.
        """
        bonus = 1 if detection_count > 1 else 0
        return max(1, min(10, detector_severity + bonus))

    @staticmethod
    def _reasoning(
        incident, detections: list[str], severity: int
    ) -> str:
        """Explain the judgement in terms a junior reader can follow.

        The same sentence an analyst would say out loud: what fired, on what, and
        what that implies.
        """
        subject = describe(incident)
        parts = [
            f"{len(detections)} detection rule(s) fired on {subject}: "
            f"{', '.join(detections)}.",
            f"Highest detector severity was {incident.severity}; "
            f"corroboration across rules sets the assessed severity to {severity}.",
        ]
        if incident.attack_type is AttackType.ACCOUNT_COMPROMISE:
            parts.append(
                "A successful sign-in from the same source as the failures means a "
                "foothold may exist, which is why this is assessed as account "
                "compromise rather than an unresolved attempt."
            )
        else:
            parts.append(
                "No successful sign-in from the attacking source was observed, so "
                "this remains a detected signal rather than a confirmed compromise."
            )
        parts.append(
            "Derived from deterministic detection evidence only; no model was "
            "consulted. Requires analyst confirmation before any response action."
        )
        return " ".join(parts)

    @staticmethod
    def _evidence(incident, detections: list[str]) -> dict:
        """A JSON-serialisable snapshot of what the decision was based on.

        Stored on the decision so a reviewer can see the inputs, not just the
        output. It is deterministic apart from the fingerprint below, which
        exists so two otherwise identical incidents are distinguishable.
        """
        return {
            "backend": "rules",
            "detections": detections,
            "event_count": incident.event_count,
            "first_seen": incident.first_seen.isoformat(),
            "last_seen": incident.last_seen.isoformat(),
            "signal_summary": incident.signal_summary,
            "incident_fingerprint": hashlib.sha256(
                json.dumps(
                    {
                        "uid": incident.incident_id,
                        "attack_type": incident.attack_type.value,
                        "events": incident.event_count,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()[:12],
        }
