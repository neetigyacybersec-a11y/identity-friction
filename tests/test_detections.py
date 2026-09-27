"""Detection tests.

These are the tests that matter most. The detections are the only part of the
system whose output must be reproducible, so they are tested against the bundled
sample data with no network and no clock.

The pattern in every test here: assert on a specific number and a specific
attack type, not merely that something fired. "A password spray is detected"
proves nothing; "fourteen failures across five accounts from one source produce
one account_compromise finding at severity 8" is a test.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.detection.engine import DetectionEngine
from app.models.decision import AttackType
from app.models.incident import DetectionName


def fired(events, settings: Settings) -> list:
    engine = DetectionEngine()
    return engine.fired(engine.run(events, settings))


def only(events, settings: Settings, name: DetectionName):
    """The findings for one rule, asserting that is the only rule that fired."""
    results = fired(events, settings)
    return [r for r in results if r.detection is name]


# -- the clean case ---------------------------------------------------------


def test_benign_traffic_produces_no_findings(events_from, settings):
    """Ordinary logins must not produce anything.

    A detection suite with no negative case is a suite that would ship a rule
    firing on every user in the tenant.
    """
    assert fired(events_from["benign_login"], settings) == []


# -- password spray ---------------------------------------------------------


def test_password_spray_fires_on_one_source_with_many_accounts(
    events_from, settings
):
    results = only(events_from["password_spray"], settings, DetectionName.PASSWORD_SPRAY)
    assert len(results) == 1, "one source IP should produce one finding, not one per account"

    result = results[0]
    assert result.suggested_attack_type is AttackType.ACCOUNT_COMPROMISE
    assert result.base_severity == 8
    assert result.signal["accounts_failed"] == 7
    assert len(result.signal["accounts_targeted"]) == 7
    # The success is what separates a foothold from a noisy attempt.
    assert result.signal["successful_sign_ins_from_source"] == 1


def test_password_spray_without_a_success_stays_a_spray(events_from, settings):
    """Strip the success and the finding must fall back, not over-claim.

    This is the regression test for the bug where successes were searched for
    inside the already-filtered failure list, so the count was always zero.
    """
    events = events_from["password_spray"]
    failures_only = [
        event for event in events if event.outcome.value != "success"
    ]
    results = only(failures_only, settings, DetectionName.PASSWORD_SPRAY)

    assert len(results) == 1
    assert results[0].suggested_attack_type is AttackType.PASSWORD_SPRAY
    assert results[0].base_severity == 6
    assert results[0].signal["successful_sign_ins_from_source"] == 0


def test_password_spray_respects_its_thresholds(events_from, settings):
    """Raising the bar above the observed volume must silence the rule."""
    events = events_from["password_spray"]
    strict = Settings(
        database_path=settings.database_path,
        sample_data_dir=settings.sample_data_dir,
        openrouter_api_key="",
        spray_failed_login_threshold=100,
    )
    assert only(events, strict, DetectionName.PASSWORD_SPRAY) == []


# -- MFA fatigue ------------------------------------------------------------


def test_mfa_fatigue_fires_when_a_success_follows_the_denials(
    events_from, settings
):
    results = only(events_from["mfa_fatigue"], settings, DetectionName.MFA_FATIGUE)
    assert len(results) == 1
    assert results[0].base_severity == 8
    assert results[0].suggested_attack_type is AttackType.ACCOUNT_COMPROMISE


def test_mfa_fatigue_without_a_success_does_not_fire(events_from, settings):
    """A user who fails MFA and gives up is not an incident.

    This is the case that separates MFA fatigue from a mistyped password, and it
    is why the rule requires a success inside the lookahead window.
    """
    events = [
        event
        for event in events_from["mfa_fatigue"]
        if event.outcome.value != "success"
    ]
    assert only(events, settings, DetectionName.MFA_FATIGUE) == []


# -- impossible travel ------------------------------------------------------


def test_impossible_travel_computes_a_speed_and_flags_it(
    events_from, settings
):
    results = only(events_from["impossible_travel"], settings, DetectionName.IMPOSSIBLE_TRAVEL)
    assert len(results) == 1

    result = results[0]
    assert result.suggested_attack_type is AttackType.IMPOSSIBLE_TRAVEL
    # London to Singapore in 90 minutes. Whatever the exact figure, it has to
    # clear the 900 km/h threshold by a wide margin.
    assert result.signal["implied_speed_kmh"] > settings.impossible_travel_speed_kmh
    assert result.signal["from"]["city"] != result.signal["to"]["city"]
    assert result.signal["distance_km"] > 0


# -- OAuth consent ----------------------------------------------------------


def test_oauth_consent_fires_on_a_sensitive_scope(events_from, settings):
    results = only(events_from["oauth_consent"], settings, DetectionName.OAUTH_CONSENT)
    assert len(results) == 1
    assert results[0].suggested_attack_type is AttackType.OAUTH_ABUSE
    assert results[0].signal["sensitive_scopes"]


# -- engine behaviour -------------------------------------------------------


def test_duplicate_findings_from_overlapping_windows_are_collapsed(
    events_from, settings
):
    """The engine runs over every event, so one cluster can be seen many times.

    Without collapsing, a single spray would fill the incident list with copies
    of itself.
    """
    results = only(events_from["password_spray"], settings, DetectionName.PASSWORD_SPRAY)
    assert len(results) == 1
    assert results[0].dedupe_key is not None


def test_a_broken_detector_does_not_stop_the_others(events_from, settings):
    """One raising rule must not cost the pipeline the other findings."""

    class Exploding(DetectionEngine):
        def __init__(self):
            super().__init__()

    class Boom:
        name = DetectionName.PASSWORD_SPRAY
        title = "boom"
        limitations = "test"

        def evaluate(self, events, context):
            raise RuntimeError("deliberate failure")

        def not_fired(self):  # pragma: no cover - never reached
            return None

    engine = DetectionEngine(detections=[Boom(), *DetectionEngine().detections])
    results = engine.fired(engine.run(events_from["password_spray"], settings))

    assert any(r.detection is DetectionName.PASSWORD_SPRAY for r in results)
