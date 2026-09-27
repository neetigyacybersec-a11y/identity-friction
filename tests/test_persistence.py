"""Persistence and correlation tests.

The database is where claims become durable, so these tests check the two
properties that matter: re-ingesting the same telemetry does not inflate
anything, and an incident can be read back with its timeline intact.
"""

from __future__ import annotations

from app.correlation import CorrelationEngine
from app.detection.engine import DetectionEngine
from app.models.decision import AttackType


def test_events_are_ingested_once(repository, events_from):
    events = events_from["password_spray"]
    assert repository.upsert_events(events) == len(events)
    assert repository.count_events() == len(events)

    # Re-ingesting the same file must add nothing, or the event counts on the
    # dashboard drift upward on every run.
    assert repository.upsert_events(events) == 0
    assert repository.count_events() == len(events)


def test_incident_roundtrips_with_its_timeline(repository, events_from, settings):
    events = events_from["mfa_fatigue"]
    repository.upsert_events(events)

    engine = DetectionEngine()
    findings = engine.fired(engine.run(events, settings))
    incidents = CorrelationEngine(settings).correlate(
        findings, {event.event_id: event for event in events}
    )
    assert len(incidents) == 1

    stored_uid = repository.upsert_incident(incidents[0])
    stored = repository.get_incident(incidents[0].incident_id)

    assert stored is not None
    assert stored["incident_uid"] == incidents[0].incident_id
    assert stored["id"] == stored_uid
    assert stored["attack_type"] == AttackType.ACCOUNT_COMPROMISE.value
    # Five events: four MFA denials and the success that followed them.
    assert stored["event_count"] == len(stored["timeline"]) == 5
    assert stored["limitations"], "an incident must record what it cannot show"


def test_timeline_is_ordered_by_timestamp(repository, events_from, settings):
    """Order is the product. A chain read out of sequence is not a chain."""
    events = events_from["mfa_fatigue"]
    repository.upsert_events(events)

    engine = DetectionEngine()
    findings = engine.fired(engine.run(events, settings))
    incidents = CorrelationEngine(settings).correlate(
        findings, {event.event_id: event for event in events}
    )
    repository.upsert_incident(incidents[0])

    timeline = repository.get_incident(incidents[0].incident_id)["timeline"]
    timestamps = [entry["timestamp"] for entry in timeline]
    assert timestamps == sorted(timestamps)


def test_correlation_merges_two_rules_on_one_account(events_from, settings):
    """MFA fatigue and OAuth consent on the same user are one story.

    Two separate incidents would send an analyst to two places for what is one
    sequence: pressure, then success, then a consent grant.
    """
    events = events_from["mfa_fatigue"] + events_from["oauth_consent"]
    engine = DetectionEngine()
    findings = engine.fired(engine.run(events, settings))
    incidents = CorrelationEngine(settings).correlate(
        findings, {event.event_id: event for event in events}
    )

    assert len(incidents) == 1
    assert len(incidents[0].detections) == 2
    assert set(incidents[0].signal_summary["detections"]) == {
        "mfa_fatigue",
        "oauth_consent",
    }


def test_a_spray_is_named_for_its_source_not_a_victim(
    events_from, settings
):
    """A spray touches many accounts, so naming one of them is misleading."""
    events = events_from["password_spray"]
    engine = DetectionEngine()
    findings = engine.fired(engine.run(events, settings))
    incidents = CorrelationEngine(settings).correlate(
        findings, {event.event_id: event for event in events}
    )

    incident = incidents[0]
    assert "203.0.113.77" in incident.subject
    # The victims belong in the evidence, not in the incident's identity.
    assert incident.user_key is not None
    assert "source 203.0.113.77" in incident.title


def test_clearing_an_incident_removes_its_event_links(repository, events_from, settings):
    """The join table must not outlive the incident it belongs to."""
    events = events_from["mfa_fatigue"]
    repository.upsert_events(events)
    engine = DetectionEngine()
    incidents = CorrelationEngine(settings).correlate(
        engine.fired(engine.run(events, settings)),
        {event.event_id: event for event in events},
    )
    repository.upsert_incident(incidents[0])

    with repository.connect() as connection:
        before = connection.execute(
            "SELECT COUNT(*) AS n FROM incident_events"
        ).fetchone()["n"]
        connection.execute("DELETE FROM incidents")

    assert before > 0, "the incident should have linked events"
    with repository.connect() as connection:
        after = connection.execute(
            "SELECT COUNT(*) AS n FROM incident_events"
        ).fetchone()["n"]
    assert after == 0
    # The events themselves are independent of any incident.
    assert repository.count_events() == len(events)
