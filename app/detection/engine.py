"""The detection engine.

Runs every registered detection over one batch of events and returns whatever
they found. No network, no clock, no database: the whole point is that this is
the deterministic half of the system and it stays testable in isolation.
"""

from __future__ import annotations

import logging
from datetime import datetime

from app.config import Settings
from app.detection.base import Detection, DetectionContext
from app.detection.impossible_travel import ImpossibleTravelDetection
from app.detection.mfa_fatigue import MfaFatigueDetection
from app.detection.oauth_consent import OAuthConsentDetection
from app.detection.password_spray import PasswordSprayDetection
from app.models.event import NormalizedEvent
from app.models.incident import DetectionResult

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Holds the detection list and runs it."""

    def __init__(self, detections: list[Detection] | None = None) -> None:
        self.detections: list[Detection] = detections or default_detections()

    def run(
        self,
        events: list[NormalizedEvent],
        settings: Settings,
        now: datetime | None = None,
    ) -> list[DetectionResult]:
        """Evaluate every detection and return only the findings.

        `now` is a parameter rather than a call to the system clock so a test
        can pin it. It is passed to detections that need an upper bound; none of
        the current four do, but the interface should not have to change when
        one does.
        """
        results: list[DetectionResult] = []

        for detection in self.detections:
            try:
                outcomes = detection.evaluate(
                    events, DetectionContext(settings=settings, now=now or datetime.now().astimezone())
                )
            except Exception:
                # One broken rule must not take down the analysis. The others
                # still have something to say, and a detection that always
                # throws is a bug to fix in tests, not a reason to lose the
                # password spray finding.
                logger.exception("detection %s raised; skipping it", detection.name)
                continue

            for outcome in outcomes:
                if outcome.fired:
                    logger.info(
                        "detection %s fired: %s", detection.name, outcome.title
                    )
                results.append(outcome)

        return _collapse_duplicates(results)

    def fired(self, results: list[DetectionResult]) -> list[DetectionResult]:
        """Just the findings, without the "checked and stayed quiet" entries."""
        return [result for result in results if result.fired]


def _collapse_duplicates(results: list[DetectionResult]) -> list[DetectionResult]:
    """Keep one finding per dedupe_key, the one covering the most evidence.

    Sliding windows overlap by design, so the same underlying signal gets
    reported from several window positions. The widest finding wins because it
    is the one with the most complete picture, with severity as a tie-break.
    """
    best: dict[str, DetectionResult] = {}
    order: list[str] = []
    passthrough: list[DetectionResult] = []

    for result in results:
        if result.dedupe_key is None:
            passthrough.append(result)
            continue
        if result.dedupe_key not in best:
            best[result.dedupe_key] = result
            order.append(result.dedupe_key)
            continue
        incumbent = best[result.dedupe_key]
        challenger = result
        if (len(challenger.event_ids), challenger.base_severity) > (
            len(incumbent.event_ids),
            incumbent.base_severity,
        ):
            best[result.dedupe_key] = challenger

    collapsed = [best[key] for key in order]
    return passthrough + collapsed


def default_detections() -> list[Detection]:
    """The four core detections, in no particular order.

    The optional token/session anomaly rule is not here. It is described in the
    README as a stretch goal precisely because naming it correctly, without
    implying token theft, is the hard part.
    """
    return [
        PasswordSprayDetection(),
        MfaFatigueDetection(),
        ImpossibleTravelDetection(),
        OAuthConsentDetection(),
    ]
