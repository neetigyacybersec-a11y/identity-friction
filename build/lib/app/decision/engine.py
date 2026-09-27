"""The decision interface.

System One asks four fast questions about a candidate: is this suspicious, which
attack type fits, how severe, and should it escalate. Whatever answers them, the
rest of the application only ever sees a `Decision`.

Nothing in this file knows that JEV exists, or that OpenRouter exists, or that
a rule engine exists. That is the whole design. Two implementations ship:

* `JevDecisionEngine` in `jev.py` — the model-backed one.
* `RuleDecisionEngine` in `rule_decision.py` — the deterministic fallback.

The fallback is not a stub. It is a real decision from the detection evidence
already in hand, and it is what the project runs whenever a model is
unavailable, so the system never goes dark.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass

from app.config import Settings
from app.models.decision import Decision, DecisionSource
from app.models.incident import Incident

logger = logging.getLogger(__name__)


class DecisionUnavailable(RuntimeError):
    """A backend could not produce a judgement.

    Distinguished from a model answering "this is benign", which is a successful
    call. Callers catch this and fall back rather than treating the failure as a
    low-severity decision.
    """


@dataclass(frozen=True)
class DecisionRequest:
    """What a backend is asked to judge.

    The incident and its timeline are passed rather than the raw telemetry,
    because the backend should see the same summarised, ordered view an analyst
    sees. Handing over every raw event invites a model to reason from a field
    no rule in the project looks at.
    """

    incident: Incident


class DecisionEngine(abc.ABC):
    """Base class for decision backends."""

    @abc.abstractmethod
    def decide(self, request: DecisionRequest) -> Decision:
        """Return a judgement, or raise `DecisionUnavailable`.

        Implementations must not return a fabricated low-confidence decision on
        failure. Raising keeps "we could not ask" distinguishable from "we asked
        and the answer was benign", which matters when an analyst reads the
        difference as an absence of risk.
        """

    def describe(self) -> str:
        """One line naming the backend, for the UI and the logs."""
        return type(self).__name__


def build_decision_engine(settings: Settings) -> DecisionEngine:
    """Pick a backend from configuration.

    Returns the offline rule engine when no key is present. This is not a
    degraded mode to apologise for: the deterministic detections already ran,
    and the rule engine derives its decision from them rather than replacing
    them.
    """
    from app.decision.rule_decision import RuleDecisionEngine

    if not settings.openrouter_configured:
        logger.info("no OpenRouter key configured; using the rule decision engine")
        return RuleDecisionEngine()

    from app.decision.jev import JevDecisionEngine

    logger.info("using JEV over OpenRouter (model %s)", settings.jev_model_name)
    return JevDecisionEngine()


def decide_or_fallback(
    engine: DecisionEngine, request: DecisionRequest, settings: Settings
) -> tuple[Decision, str | None]:
    """Run a backend, degrading to the rule engine if it fails.

    Returns the decision and an error message when a fallback happened, so the
    incident can record that a model-backed layer failed instead of quietly
    presenting rules as if they were JEV. See CONTEXT.md on degradation.
    """
    from app.decision.rule_decision import RuleDecisionEngine

    try:
        return engine.decide(request), None
    except DecisionUnavailable as error:
        logger.warning("decision backend failed, falling back to rules: %s", error)
        fallback = RuleDecisionEngine().decide(request)
        fallback.source = DecisionSource.RULES
        return fallback, str(error)
