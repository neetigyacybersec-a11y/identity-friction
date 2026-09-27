"""Pipeline, config and API tests.

The end-to-end tests assert the property the whole project is built around: a
model failure degrades the run and says so, but never loses a deterministic
result.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.config import PROJECT_ROOT, Settings
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


def test_list_settings_accept_comma_separated_environment_variables(monkeypatch):
    """The same values, arriving the way a .env file actually delivers them.

    pydantic-settings JSON-decodes a complex field while reading the
    environment, and that happens *before* a field validator runs, so a
    comma-separated value used to raise SettingsError here even though the
    identical value passed as a keyword argument. Testing the keyword form alone
    is what let that ship. `NoDecode` is the fix; this test is the guard.
    """
    monkeypatch.setenv("OAUTH_SUSPICIOUS_ACTIVITIES", "Consent to application,Add member to role")
    monkeypatch.setenv("OAUTH_SENSITIVE_SCOPES", "Mail.Read,Files.ReadWrite.All")
    monkeypatch.setenv("MFA_DENIAL_ERROR_CODES", "53001, 53002")
    monkeypatch.setenv("MFA_METHOD_TYPES", "Phone,SoftwareOath")

    settings = Settings()

    assert settings.oauth_suspicious_activities == [
        "Consent to application",
        "Add member to role",
    ]
    assert settings.oauth_sensitive_scopes == ["Mail.Read", "Files.ReadWrite.All"]
    assert settings.mfa_denial_error_codes == [53001, 53002]
    assert settings.mfa_method_types == ["Phone", "SoftwareOath"]


def test_list_settings_accept_json_environment_variables(monkeypatch):
    monkeypatch.setenv("OAUTH_SENSITIVE_SCOPES", '["Mail.Read","Files.ReadWrite.All"]')
    assert Settings().oauth_sensitive_scopes == ["Mail.Read", "Files.ReadWrite.All"]


def test_every_value_in_env_example_parses(monkeypatch, tmp_path):
    """`.env.example` is documentation people copy, so it must actually work.

    Every list-valued variable in the shipped example is replayed into the
    environment, because a file that looks right and fails on load is worse than
    no file.
    """
    for line in (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if value:
            monkeypatch.setenv(key.strip(), value)

    settings = Settings()

    assert settings.oauth_suspicious_activities
    assert settings.oauth_sensitive_scopes
    assert settings.mfa_denial_error_codes
    # Unset secrets stay empty, so demo mode is the default rather than a
    # half-configured live mode that would try and fail to reach a tenant.
    assert settings.graph_configured is False


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


def test_incident_titles_use_the_label_not_the_enum_value(settings, repository):
    """A person reading the dashboard must never be told a person moved impossibly.

    The incident title reaches the API, the dashboard and the CLI, so this
    checks the end of the chain rather than the enum in isolation.
    """
    result = analyze_demo(settings, repository=repository)
    titles = [incident.title for incident in result.incidents]

    assert any("Geographically anomalous authentication" in title for title in titles)
    assert not any("Impossible Travel" in title for title in titles)

    # A single-detection incident names itself with the label. A chain may still
    # list rule identifiers, because an analyst correlating two rules wants the
    # stable names, so the wording check above is the one that matters.
    for incident in result.incidents:
        if len(incident.detections) == 1:
            assert incident.attack_type.label in incident.title


def test_json_mode_emits_one_valid_json_document(settings, repository, capsys):
    """`--json` has to be parseable, which it was not.

    It printed the summary, then appended the human incident list, so
    `entra-analyze --json | jq` failed on trailing text. It also reported counts
    only, so the incidents were reachable from that flag solely as prose.
    """
    from scripts.run_analysis import main

    db = settings.database_path
    exit_code = main(["--demo", "--json", "--db", str(db)])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["incidents"] == 3
    assert len(payload["incident_details"]) == 3
    assert payload["events_ingested"] == 35
    # A key must not mean a count in one method and a list in another.
    assert isinstance(payload["incidents"], int)
    # The signal/proof note has to reach a machine consumer too, or the only
    # reader who sees the caveat is a human looking at a terminal.
    assert "not a confirmed attack" in payload["note"]
    assert all("Impossible Travel" not in i["title"] for i in payload["incident_details"])


def test_human_mode_still_prints_incidents(settings, repository, capsys):
    from scripts.run_analysis import main

    exit_code = main(["--demo", "--db", str(settings.database_path)])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "3 incident(s):" in out
    assert "not confirmed attacks" in out
