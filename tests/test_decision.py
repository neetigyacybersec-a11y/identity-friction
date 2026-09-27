"""Decision and investigation tests.

Every model call here is a fake. The point of these tests is not that JEV works
— it is that the system behaves correctly when JEV is unavailable, malformed, or
absent, which is the situation this project will actually be in most of the time.

The invariant under test throughout: a model failure must never cost a
deterministic result.
"""

from __future__ import annotations

import json

import pytest

from app.config import Settings
from app.correlation import CorrelationEngine
from app.database.repository import Repository
from app.decision.engine import (
    DecisionRequest,
    DecisionUnavailable,
    build_decision_engine,
    decide_or_fallback,
)
from app.decision.jev import JevDecisionEngine
from app.decision.rule_decision import MAX_RULE_CONFIDENCE, RuleDecisionEngine
from app.detection.engine import DetectionEngine
from app.investigation.engine import InvestigationEngine, InvestigationUnavailable
from app.models.decision import (
    AttackType,
    ConfidenceBand,
    Decision,
    DecisionSource,
)
from tests.conftest import FakePostClient, FakeResponse, openrouter_body

GOOD_REPLY = json.dumps(
    {
        "suspicious": True,
        "suspicion_score": 0.91,
        "attack_type": "account compromise",
        "severity": 12,
        "escalate": True,
        "confidence": 0.88,
        "reasoning": "Spray failures followed by a success from one source.",
    }
)


def build_incident(events, settings):
    engine = DetectionEngine()
    findings = engine.fired(engine.run(events, settings))
    incidents = CorrelationEngine(settings).correlate(
        findings, {event.event_id: event for event in events}
    )
    return incidents[0]


@pytest.fixture
def incident(events_from, settings):
    return build_incident(events_from["mfa_fatigue"], settings)


# -- backend selection ------------------------------------------------------


def test_no_api_key_selects_the_offline_engine():
    """The project must be demonstrable with no credentials at all."""
    engine = build_decision_engine(Settings(openrouter_api_key=""))
    assert isinstance(engine, RuleDecisionEngine)
    assert "offline" in engine.describe()


def test_an_api_key_selects_jev():
    engine = build_decision_engine(Settings(openrouter_api_key="test-key"))
    assert isinstance(engine, JevDecisionEngine)


# -- the offline engine -----------------------------------------------------


def test_rule_engine_never_claims_high_confidence(incident, settings):
    """A deterministic pipeline should not imply it knows more than it does."""
    decision = RuleDecisionEngine(settings).decide(DecisionRequest(incident=incident))

    assert decision.source is DecisionSource.RULES
    assert decision.confidence <= MAX_RULE_CONFIDENCE
    assert decision.band is ConfidenceBand.LOW
    # An analyst is required regardless.
    assert decision.needs_analyst_review is True


def test_rule_engine_explains_its_own_reasoning(incident, settings):
    decision = RuleDecisionEngine(settings).decide(DecisionRequest(incident=incident))

    # The reasoning names the detection that fired, since that is the evidence
    # the judgement rests on.
    assert incident.detections[0].detection.value in decision.reasoning
    assert "no model was consulted" in decision.reasoning
    # It must not read as a confirmed attack.
    assert "may exist" in decision.reasoning


def test_corroboration_raises_confidence(events_from, settings):
    """Two independent rules agreeing is stronger evidence than one."""
    single = build_incident(events_from["mfa_fatigue"], settings)
    both = build_incident(
        events_from["mfa_fatigue"] + events_from["oauth_consent"], settings
    )

    engine = RuleDecisionEngine(settings)
    one = engine.decide(DecisionRequest(incident=single))
    two = engine.decide(DecisionRequest(incident=both))

    assert two.confidence > one.confidence
    assert two.severity >= one.severity


# -- JEV parsing ------------------------------------------------------------


def test_jev_parses_a_well_formed_reply(incident, settings):
    client = FakePostClient(FakeResponse(200, openrouter_body(GOOD_REPLY)))
    engine = JevDecisionEngine(
        Settings(openrouter_api_key="k", jev_model_name="typesafe/jev-router"),
        client=client,
    )
    decision = engine.decide(DecisionRequest(incident=incident))

    assert decision.attack_type is AttackType.ACCOUNT_COMPROMISE
    # A human-readable string with a space maps onto the closed taxonomy.
    assert decision.suspicion_score == 0.91
    # Out of range, so clamped rather than rejected: the rest of the reply was
    # sound and a model disagreeing with the taxonomy is not a transport error.
    assert decision.severity == 10
    assert decision.band is ConfidenceBand.HIGH
    # The model's own confidence is kept but is not what routing uses.
    assert decision.raw_response["model_reported_confidence"] == 0.88


def test_jev_handles_a_fenced_code_block(incident, settings):
    """Models wrap JSON in fences often enough to be worth handling."""
    client = FakePostClient(
        FakeResponse(200, openrouter_body(f"```json\n{GOOD_REPLY}\n```"))
    )
    engine = JevDecisionEngine(Settings(openrouter_api_key="k"), client=client)
    assert engine.decide(DecisionRequest(incident=incident)).suspicious is True


@pytest.mark.parametrize(
    "content, reason",
    [
        ("This looks suspicious to me.", "prose instead of JSON"),
        (json.dumps({"suspicious": True}), "missing keys"),
        (GOOD_REPLY.replace("0.91", "9.5"), "score out of range"),
        (GOOD_REPLY.replace('"severity": 12', '"severity": "high"'), "severity not numeric"),
    ],
)
def test_jev_refuses_an_unusable_reply(incident, settings, content, reason):
    """Every malformed reply must surface, not crash and not be trusted."""
    client = FakePostClient(FakeResponse(200, openrouter_body(content)))
    engine = JevDecisionEngine(Settings(openrouter_api_key="k"), client=client)

    with pytest.raises(DecisionUnavailable):
        engine.decide(DecisionRequest(incident=incident))


def test_jev_maps_an_unknown_attack_type_to_unknown(incident, settings):
    client = FakePostClient(
        FakeResponse(200, openrouter_body(GOOD_REPLY.replace("account compromise", "wat")))
    )
    engine = JevDecisionEngine(Settings(openrouter_api_key="k"), client=client)
    decision = engine.decide(DecisionRequest(incident=incident))

    assert decision.attack_type is AttackType.UNKNOWN


def test_jev_never_sees_raw_telemetry(incident, settings):
    """The prompt must carry the summary, not the raw event payloads."""
    client = FakePostClient(FakeResponse(200, openrouter_body(GOOD_REPLY)))
    engine = JevDecisionEngine(Settings(openrouter_api_key="k"), client=client)
    engine.decide(DecisionRequest(incident=incident))

    payload = client.content_of_last_request()
    user_message = payload["messages"][1]["content"]
    assert "timeline" in user_message
    assert "authenticationDetails" not in user_message
    assert "raw" not in user_message


# -- degradation ------------------------------------------------------------


def test_a_failed_backend_falls_back_to_rules(incident, settings):
    """The whole point: no API key, no model, and the incident still gets a
    decision, sourced honestly."""

    class Broken:
        def decide(self, request):
            raise DecisionUnavailable("simulated outage")

        def describe(self):
            return "Broken"

    decision, error = decide_or_fallback(
        Broken(), DecisionRequest(incident=incident), settings
    )

    assert error == "simulated outage"
    assert decision.source is DecisionSource.RULES
    assert decision.suspicious is True


def test_jev_without_a_key_raises_rather_than_faking_a_decision(incident, settings):
    engine = JevDecisionEngine(Settings(openrouter_api_key=""))
    with pytest.raises(DecisionUnavailable):
        engine.decide(DecisionRequest(incident=incident))


def test_a_persistent_http_error_is_reported(incident, settings, monkeypatch):
    import app.decision.jev as jev_module

    monkeypatch.setattr(jev_module, "RETRY_BACKOFF_SECONDS", 0)
    client = FakePostClient(FakeResponse(500, {}))
    engine = JevDecisionEngine(Settings(openrouter_api_key="k"), client=client)

    with pytest.raises(DecisionUnavailable):
        engine.decide(DecisionRequest(incident=incident))
    # One retry, then give up rather than hanging on an outage.
    assert len(client.requests) == 2


# -- persistence of decisions -----------------------------------------------


def test_a_decision_and_its_failure_reason_are_stored(
    incident, settings, repository: Repository
):
    """The dashboard has to be able to say a model layer was down."""
    repository.upsert_events([])
    repository.upsert_incident(incident)

    decision = Decision(
        suspicious=True,
        attack_type=AttackType.ACCOUNT_COMPROMISE,
        severity=8,
        source=DecisionSource.RULES,
    )
    repository.save_decision(incident.incident_id, decision)
    repository.save_incident_error(incident.incident_id, "simulated outage")

    stored = repository.get_incident(incident.incident_id)
    assert stored["decision"]["source"] == DecisionSource.RULES
    assert stored["decision_error"] == "simulated outage"


# -- investigation ----------------------------------------------------------


REPORT = json.dumps(
    {
        "summary": "MFA pressure followed by a success and a consent grant.",
        "evidence": ["10:01 four MFA denials", "10:06 sign-in succeeded"],
        "attack_hypothesis": "MFA fatigue leading to a consent grant.",
        "mitre_techniques": ["T1621 MFA"],
        "investigation_steps": ["Check whether the app is sanctioned"],
        "recommended_actions": ["Revoke the consent grant"],
        "limitations": ["No risk-based detection data was available."],
    }
)


def test_investigation_produces_a_report_with_limitations(incident, settings):
    client = FakePostClient(FakeResponse(200, openrouter_body(REPORT)))
    engine = InvestigationEngine(Settings(openrouter_api_key="k"), client=client)
    report = engine.investigate(incident)

    assert "MFA pressure" in report.summary
    assert report.mitre_techniques == ["T1621 MFA"]
    assert not report.is_empty
    # The detector's own caveats are present alongside the model's.
    assert any("Heuristic" in item for item in report.limitations)
    assert any("risk-based" in item for item in report.limitations)


def test_investigation_without_a_key_raises(incident, settings):
    with pytest.raises(InvestigationUnavailable):
        InvestigationEngine(Settings(openrouter_api_key="")).investigate(incident)


def test_investigation_refuses_prose_instead_of_json(incident, settings):
    client = FakePostClient(FakeResponse(200, openrouter_body("Here is my analysis.")))
    engine = InvestigationEngine(Settings(openrouter_api_key="k"), client=client)

    with pytest.raises(InvestigationUnavailable):
        engine.investigate(incident)
