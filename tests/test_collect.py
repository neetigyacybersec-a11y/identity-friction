"""Graph collector tests.

No tenant, no network. The client and the token getter are both injected, so
these tests exercise the parts that are easy to get quietly wrong: pagination,
a rejected filter, and a partial failure.

Every one of those is a case where the naive implementation looks like it
worked.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.collect.graph import (
    DIRECTORY_AUDITS_PATH,
    GRAPH_BASE_URL,
    SIGN_INS_PATH,
    GraphCollectionError,
    GraphCollector,
)
from app.config import Settings
from tests.conftest import FakeGetClient, FakeResponse


def sign_in(index: int) -> dict:
    return {
        "id": f"signin-{index}",
        "createdDateTime": "2026-09-20T10:00:00Z",
        "ipAddress": "203.0.113.9",
        "user": {"id": f"u{index}", "userPrincipalName": f"u{index}@contoso.com"},
        "appDisplayName": "Microsoft Office 365 Portal",
        "location": {"city": "Lagos", "countryOrRegion": "NG"},
        "status": {"errorCode": 0},
    }


def audit(index: int = 1, days_ago: int = 0) -> dict:
    """An audit entry timestamped inside the collector's 24-hour window.

    Built relative to now rather than hard-coded, because the collector filters
    on the lookback window and a fixed past date would be filtered out.
    """
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {
        "id": f"audit-{index}",
        "activityDateTime": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "activityDisplayName": "Consent to application",
        "activityResult": "Success",
        "initiatedBy": {"user": {"userPrincipalName": "daniel.reyes@contoso.com"}},
    }


@pytest.fixture
def live_settings() -> Settings:
    return Settings(
        graph_tenant_id="tenant",
        graph_client_id="client",
        graph_client_secret="secret",
        openrouter_api_key="",
    )


def test_follows_pagination_to_the_last_page(live_settings):
    """A 24-hour window routinely spans several pages.

    Reading only the first page analyses a fraction of the activity and produces
    output that looks complete.
    """
    client = FakeGetClient(
        [
            {"value": [sign_in(1)], "@odata.nextLink": f"{GRAPH_BASE_URL}/next?$skiptoken=A"},
            {"value": [sign_in(2)], "@odata.nextLink": f"{GRAPH_BASE_URL}/next?$skiptoken=B"},
            {"value": [sign_in(3)]},
            {"value": [audit()]},
        ]
    )
    result = GraphCollector(live_settings, client=client, get_token=lambda: "t").collect()

    assert result.sign_in_count == 3
    assert result.audit_count == 1
    assert result.complete
    # The next link is used verbatim and carries its own parameters.
    assert client.calls[1]["url"].endswith("$skiptoken=A")
    assert client.calls[1]["params"] is None


def test_sign_ins_are_filtered_server_side(live_settings):
    client = FakeGetClient([{"value": []}, {"value": []}])
    GraphCollector(live_settings, client=client, get_token=lambda: "t").collect()

    params = client.calls[0]["params"]
    assert "$filter" in params
    assert "createdDateTime ge" in params["$filter"]


def test_a_rejected_audit_filter_falls_back_to_local_filtering(live_settings):
    """A 400 on the time filter is a tenant quirk, not a coverage gap.

    The data arrives complete either way, so this is not recorded as an error.
    """
    client = FakeGetClient(
        [
            {"value": []},
            FakeResponse(400, {"error": {"message": "Filter not supported"}}),
            {"value": [audit()]},
            # Well outside the window, and must not be counted.
            {"value": [audit(2, days_ago=30)]},
        ]
    )
    result = GraphCollector(live_settings, client=client, get_token=lambda: "t").collect()

    assert result.audit_count == 1
    assert result.complete, "a rejected filter that was worked around is not a gap"
    assert all(event.event_id != "audit-2" for event in result.events)


def test_one_log_type_failing_is_reported_without_losing_the_other(
    live_settings,
):
    """A tenant without the directory audit licence still has sign-in activity.

    Analysing half the telemetry is worth doing, provided the gap is visible.
    """
    client = FakeGetClient(
        [
            {"value": [sign_in(1)]},
            FakeResponse(403, {"error": {"message": "Insufficient privileges"}}),
        ]
    )
    result = GraphCollector(live_settings, client=client, get_token=lambda: "t").collect()

    assert result.sign_in_count == 1
    assert result.audit_count == 0
    assert not result.complete
    assert any("directoryAudits" in error for error in result.errors)
    assert "AuditLog.Read.All" in result.errors[0]


def test_pagination_that_does_not_terminate_is_bounded(live_settings):
    """An infinite nextLink loop is a bug upstream, and must not hang the run."""
    client = FakeGetClient(
        [{"value": [], "@odata.nextLink": f"{GRAPH_BASE_URL}/loop"}] * 200
    )
    result = GraphCollector(live_settings, client=client, get_token=lambda: "t").collect()

    assert not result.complete
    assert any("did not terminate" in error for error in result.errors)


def test_unconfigured_live_mode_names_the_missing_variables():
    with pytest.raises(GraphCollectionError) as raised:
        GraphCollector(Settings(openrouter_api_key=""), get_token=lambda: "t").collect()

    message = str(raised.value)
    assert "GRAPH_TENANT_ID" in message
    assert "GRAPH_CLIENT_ID" in message
    assert "GRAPH_CLIENT_SECRET" in message


def test_secrets_never_reach_the_result(live_settings):
    """A client secret must not end up in an event, a log line or a summary."""
    client = FakeGetClient([{"value": [sign_in(1)]}, {"value": []}])
    result = GraphCollector(live_settings, client=client, get_token=lambda: "t").collect()

    assert "secret" not in str(result.summary())
    for event in result.events:
        assert "secret" not in str(event.raw)
