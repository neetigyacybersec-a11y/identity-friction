"""Pipeline, config and API tests.

The end-to-end tests assert the property the whole project is built around: a
model failure degrades the run and says so, but never loses a deterministic
result.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.decision.engine import DecisionUnavailable
from app.models.decision import AttackType
from app.pipeline import analyze_demo, analyze_events, load_demo_events
from tests.conftest import FakePostClient, FakeResponse, openrouter_body


class BrokenEngine:
    """A decision backend that always fails."""

    def decide(self, request):
        raise DecisionUnavailable("simulated model outage")

    def describe(self):
        return "BrokenEngine"


# -- config -----------------------------------------------------------------


def test_list_settings_accept_comma_separated_values():
    """A .env file invites comma-separated values; they must work."""
    settings = Settings(
        oauth_suspicious_activities="Consent to application,Add member to role",
        mfa_denial_error_codes="53001, 53002",
    )
    assert settings.oauth_suspicious_activities == [
        "Consent to application",
        "Add member to role",
    ]
    assert settings.mfa_denial_error_codes == [53001, 53002]


def test_list_settings_also_accept_json():
    settings = Settings(oauth_suspicious_activities='["Consent to application"]')
    assert settings.oauth_suspicious_activities == ["Consent to application"]


# -- the demo pipeline ------------------------------------------------------


def test_demo_run_produces_incidents_without_credentials(settings, repository):
    result = analyze_demo(settings, repository=repository)

    assert result.source == "demo"
    assert result.events_ingested == 35
    assert result.findings == 4
    assert len(result.incidents) == 3
    assert result.decisions_made == 3
    assert result.complete
    assert repository.count_incidents() == 3


def test_a_model_outage_keeps_every_deterministic_result(
    settings, repository
):
    """The governing property of the whole design.

    With the decision backend failing, the incidents must survive intact, each
    carrying a rule-based decision, and the failure must be recorded rather
    than hidden.
    """
    result = analyze_demo(
        settings, repository=repository, decision_engine=BrokenEngine()
    )

    assert len(result.incidents) == 3
    assert result.decisions_fallback == 3
    assert "decision" in result.degraded

    stored = repository.list_incidents()
    assert len(stored) == 3
    for incident in stored:
        detail = repository.get_incident(incident["incident_uid"])
        assert detail["decision"] is not None
        assert detail["decision"]["source"] == "rules"
        assert "simulated model outage" in detail["decision_error"]


def test_rerunning_the_demo_does_not_duplicate_anything(settings, repository):
    """Ids are unique, so a second run is a no-op rather than double-counting."""
    first = analyze_demo(settings, repository=repository)
    second = analyze_demo(settings, repository=repository)

    assert first.events_new == 35
    assert second.events_new == 0
    assert repository.count_events() == 35
    assert repository.count_incidents() == 3


def test_investigation_is_off_by_default_and_reported_when_requested(
    settings, repository
):
    """Bulk runs skip the model stage; asking for it without a key says so."""
    result = analyze_demo(settings, repository=repository, run_investigation=True)

    assert "no OpenRouter API key configured" in result.degraded["investigation"]
    assert result.investigations_written == 0
    assert repository.count_incidents() == 3


def test_demo_events_are_all_marked_synthetic(settings):
    """A demo event must never be able to pass as real telemetry."""
    events = load_demo_events(settings)
    assert len(events) == 35
    assert {event.data_origin.value for event in events} == {"synthetic"}


# -- the failure mode this project exists to avoid --------------------------


def test_an_empty_sample_directory_raises_rather_than_reporting_zero_findings(
    settings, tmp_path
):
    """A run over no data must not look like a clean tenant.

    Reporting zero findings from zero events is indistinguishable from a
    genuinely quiet tenant, and `ensure_directories` used to create the missing
    directory, which is how an empty run could happen at all.
    """
    empty = tmp_path / "no-sample-data"
    empty.mkdir()
    settings = Settings(
        database_path=tmp_path / "x.db", sample_data_dir=empty, openrouter_api_key=""
    )

    settings.ensure_directories()
    with pytest.raises(FileNotFoundError, match="no sample data files"):
        load_demo_events(settings)


def test_a_missing_sample_directory_raises(settings, tmp_path):
    settings = Settings(
        database_path=tmp_path / "y.db",
        sample_data_dir=tmp_path / "absent",
        openrouter_api_key="",
    )
    with pytest.raises(FileNotFoundError, match="not found"):
        load_demo_events(settings)


# -- the API ----------------------------------------------------------------


@pytest.fixture
def client(settings, repository, monkeypatch):
    """A test client wired to the temporary database."""
    import app.main as main_module

    monkeypatch.setattr(main_module, "get_settings", lambda: settings)
    with TestClient(main_module.app) as test_client:
        yield test_client


def test_health_reports_what_is_not_configured(client):
    body = client.get("/api/health").json()

    assert body["status"] == "ok"
    assert body["mode"] == "demo"
    # The signal/proof boundary travels with the data.
    assert "not a confirmed attack" in body["note"]
    assert body["graph_configured"] is False
    assert "GRAPH_TENANT_ID" in body["missing_graph_env"]


def test_live_analysis_refuses_rather_than_returning_an_empty_success(client):
    """Zero incidents from a misconfigured tenant looks like a quiet tenant."""
    response = client.post("/api/analyze/live")

    assert response.status_code == 400
    assert "not configured" in response.json()["detail"]


def test_investigate_endpoint_explains_the_missing_key(client, settings, repository):
    analyze_demo(settings, repository=repository)
    incident = repository.list_incidents(limit=1)[0]

    response = client.post(f"/api/incidents/{incident['incident_uid']}/investigate")

    assert response.status_code == 400
    assert "no OpenRouter API key" in response.json()["detail"]


def test_incident_detail_returns_its_timeline(client, settings, repository):
    analyze_demo(settings, repository=repository)
    incident = repository.list_incidents(limit=1)[0]

    body = client.get(f"/api/incidents/{incident['incident_uid']}").json()

    assert body["incident_uid"] == incident["incident_uid"]
    assert body["timeline"]
    assert body["decision"]["source"] == "rules"
    assert body["limitations"]


def test_unknown_incident_is_a_404(client):
    assert client.get("/api/incidents/does-not-exist").status_code == 404


def test_an_invalid_filter_is_rejected_with_the_accepted_values(client):
    response = client.get("/api/incidents?status=nonsense")

    assert response.status_code == 400
    assert "open" in response.json()["detail"]


def test_both_dashboard_pages_render_with_the_boundary_notice(
    client, settings, repository
):
    analyze_demo(settings, repository=repository)
    incident = repository.list_incidents(limit=1)[0]

    for path in ("/", f"/incidents/{incident['incident_uid']}"):
        response = client.get(path)
        assert response.status_code == 200
        assert "Detected signal, not confirmed attack" in response.text
        assert "{{" not in response.text, "an unrendered Jinja tag reached the page"
