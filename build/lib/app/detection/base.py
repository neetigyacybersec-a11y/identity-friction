"""Detection interface.

A detection is a deterministic rule. It reads normalized events, compares them
against configured thresholds, and either fires or does not.

Three rules the whole project depends on:

1. No network. A detection may not call a model, an API, or a database. This is
   what lets the detection tests run with no credentials.
2. No clock. "Now" is a parameter. A detection that reads the system clock cannot
   be tested against a fixture recorded last Tuesday.
3. `limitations` is mandatory. A detection that cannot say what it cannot see is
   hiding something. See docs/adr/0002-signal-not-proof.md.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.config import Settings
from app.models.incident import DetectionName, DetectionResult


@dataclass(frozen=True)
class DetectionContext:
    """Everything a detection is allowed to see.

    `settings` is passed in rather than imported so a test can drive thresholds
    without touching the environment. `now` is a parameter for the same reason.
    """

    settings: Settings
    now: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


class Detection(abc.ABC):
    """Base class for the deterministic rules."""

    name: DetectionName
    title: str
    limitations: str

    @abc.abstractmethod
    def evaluate(
        self, events: list[Any], context: DetectionContext
    ) -> list[DetectionResult]:
        """Return one DetectionResult per signal found, or an empty list.

        Returning a list rather than a single result matters: a single ingest
        can contain two unrelated spray clusters from two source IPs, and
        collapsing them into one finding would hide the second one.
        """

    def not_fired(self) -> DetectionResult:
        """A result for the "checked, nothing found" case.

        Returned so the dashboard can show which rules ran and stayed quiet,
        instead of a rule silently vanishing from the output.
        """
        return DetectionResult(
            detection=self.name,
            fired=False,
            title=self.title,
            finding="",
            limitations=self.limitations,
        )
