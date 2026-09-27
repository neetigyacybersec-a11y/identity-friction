"""Live collection from Microsoft Graph.

Pulls sign-in logs and directory audit logs from a tenant and hands them to the
same normalizer the demo data uses, so a live event and a synthetic one travel
identical code paths. The only difference is the `data_origin` value.

What this module has to get right, because getting it wrong is silent:

* **Pagination.** Graph returns a `@odata.nextLink` and stops. Reading only the
  first page of a 24-hour window silently analyses a fraction of the activity,
  and nothing in the output would say so. Every page is followed.
* **The time filter.** `createdDateTime` is filterable; `activityDateTime` is not.
  Audit logs are filtered on `activityDateTime` server-side where the filter
  supports it and skipped with a warning where it does not, because dropping
  the OAuth consent events would disable a whole detection silently.
* **Partial failure.** A sign-in fetch that succeeds and an audit fetch that
  fails is a real outcome, not a fatal error. The result records which half is
  missing so the pipeline can show a coverage gap rather than a clean bill.
* **No secrets in logs.** Client secrets and tokens are never logged, and the
  collector never puts a credential into a `NormalizedEvent`.

Permissions required on the app registration: `AuditLog.Read.All`, as an
application permission. Admin consent is needed to grant it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator

import httpx

from app.config import Settings, missing_graph_env_vars
from app.models.event import DataOrigin, NormalizedEvent
from app.normalize import normalize_many

logger = logging.getLogger(__name__)

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

SIGN_INS_PATH = "/auditLogs/signIns"
DIRECTORY_AUDITS_PATH = "/auditLogs/directoryAudits"

REQUEST_TIMEOUT_SECONDS = 30.0
# Guard against a follow-nextLink loop. Graph paginates correctly, so hitting
# this ceiling means something is wrong upstream and the caller should be told
# rather than left in an infinite loop.
MAX_PAGES = 50

# The sign-in fields the detectors read. Asking for only these keeps responses
# small and, more importantly, keeps new Graph fields the project has never been
# tested against out of the pipeline.
SIGN_IN_FIELDS = [
    "id",
    "createdDateTime",
    "ipAddress",
    "user",
    "appDisplayName",
    "deviceDetail",
    "location",
    "status",
    "authenticationDetails",
    "appliedConditionalAccessPolicies",
    "isInteractive",
    "correlationId",
]

DIRECTORY_AUDIT_FIELDS = [
    "id",
    "activityDateTime",
    "activityDisplayName",
    "activityResult",
    "initiatedBy",
    "targetResources",
    "category",
    "correlationId",
]


class GraphCollectionError(RuntimeError):
    """Collection could not complete.

    Carries the reason, which is surfaced in the API's /health response so a
    user can tell a wrong tenant id from a missing permission.
    """


@dataclass
class CollectionResult:
    """What one collection run produced, and what it could not get."""

    events: list[NormalizedEvent] = field(default_factory=list)
    sign_in_count: int = 0
    audit_count: int = 0
    # Human-readable coverage gaps. An empty list means full coverage; a
    # non-empty list means the analysis ran on incomplete telemetry, and saying
    # so is the difference between an honest dashboard and a misleading one.
    errors: list[str] = field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None

    @property
    def complete(self) -> bool:
        return not self.errors

    def summary(self) -> dict[str, Any]:
        return {
            "events": len(self.events),
            "sign_ins": self.sign_in_count,
            "directory_audits": self.audit_count,
            "complete": self.complete,
            "errors": self.errors,
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
        }


class GraphCollector:
    """Reads sign-in and audit logs from a tenant.

    `client` is injectable so the tests can drive pagination, HTTP errors and
    malformed bodies without a tenant. `get_token` is injectable for the same
    reason: the tests must never need credentials.
    """

    def __init__(
        self,
        settings: Settings,
        client: httpx.Client | None = None,
        get_token: Callable[[], str] | None = None,
    ) -> None:
        self._settings = settings
        self._client = client
        self._get_token = get_token or self._default_token

    def collect(self) -> CollectionResult:
        """Fetch both log types over the configured lookback window."""
        self._require_configuration()

        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=self._settings.graph_lookback_hours)
        result = CollectionResult(window_start=start, window_end=end)

        # Both halves are attempted even if the first fails. A tenant where
        # directoryAudits returns 403 is common — the API needs a licence — and
        # the sign-in detections are still worth running.
        for label, path, fields, fetch in (
            ("signIns", SIGN_INS_PATH, SIGN_IN_FIELDS, self._fetch_sign_ins),
            ("directoryAudits", DIRECTORY_AUDITS_PATH, DIRECTORY_AUDIT_FIELDS, self._fetch_directory_audits),
        ):
            try:
                payloads = fetch(start, end, fields)
            except GraphCollectionError as exc:
                logger.warning("Graph %s collection failed: %s", label, exc)
                result.errors.append(f"{label}: {exc}")
                continue

            events = normalize_many(payloads, DataOrigin.LIVE_TENANT)
            result.events.extend(events)
            if label == "signIns":
                result.sign_in_count = len(events)
            else:
                result.audit_count = len(events)
            logger.info("collected %s %s events", len(events), label)

        return result

    # -- per-log-type fetches --------------------------------------------

    def _fetch_sign_ins(
        self, start: datetime, end: datetime, fields: list[str]
    ) -> list[dict[str, Any]]:
        """Sign-in logs, filtered server-side on `createdDateTime`.

        This is the filter Graph supports on this endpoint, and it is what keeps
        a 24-hour request to one page of results instead of the tenant's whole
        retained history.
        """
        query = {
            "$filter": (
                f"createdDateTime ge {start.strftime('%Y-%m-%dT%H:%M:%SZ')} "
                f"and createdDateTime le {end.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            ),
            "$orderby": "createdDateTime desc",
            "$top": str(self._settings.graph_page_size),
            "$select": ",".join(fields),
        }
        return list(self._paginate(SIGN_INS_PATH, query))

    def _fetch_directory_audits(
        self, start: datetime, end: datetime, fields: list[str]
    ) -> list[dict[str, Any]]:
        """Directory audit logs.

        `activityDateTime` is filterable on this endpoint, but the filter is not
        supported on every tenant configuration and Graph answers a rejected
        filter with 400. If the filtered query fails, this retries unfiltered
        and filters locally, recording nothing as an error — the data is
        complete either way, it just cost more pages. A failure that is *not* a
        rejected filter propagates.
        """
        query = {
            "$filter": (
                f"activityDateTime ge {start.strftime('%Y-%m-%dT%H:%M:%SZ')} "
                f"and activityDateTime le {end.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            ),
            "$orderby": "activityDateTime desc",
            "$top": str(self._settings.graph_page_size),
            "$select": ",".join(fields),
        }

        try:
            return list(self._paginate(DIRECTORY_AUDITS_PATH, query))
        except GraphCollectionError as exc:
            if "HTTP 400" not in str(exc):
                raise
            logger.info(
                "directoryAudits rejected the time filter; retrying unfiltered "
                "and filtering locally"
            )
            unfiltered = {
                "$orderby": "activityDateTime desc",
                "$top": str(self._settings.graph_page_size),
                "$select": ",".join(fields),
            }
            payloads = list(self._paginate(DIRECTORY_AUDITS_PATH, unfiltered))
            return [
                payload
                for payload in payloads
                if _in_window(payload.get("activityDateTime"), start, end)
            ]

    # -- pagination ------------------------------------------------------

    def _paginate(
        self, path: str, query: dict[str, str] | None
    ) -> Iterator[dict[str, Any]]:
        """Follow `@odata.nextLink` to the end.

        The next link is used verbatim, including its own embedded `$skip` and
        `$filter`. Reconstructing the URL from the original parameters is a
        common bug: Graph decides the paging, not this code.
        """
        url = f"{GRAPH_BASE_URL}{path}"
        params: dict[str, str] | None = query
        pages = 0

        while url:
            if pages >= MAX_PAGES:
                raise GraphCollectionError(
                    f"stopped after {MAX_PAGES} pages; pagination did not terminate"
                )
            body = self._get(url, params)
            pages += 1

            for item in body.get("value") or []:
                if isinstance(item, dict):
                    yield item

            url = body.get("@odata.nextLink")
            # The next link carries its own parameters.
            params = None

    def _get(self, url: str, params: dict[str, str] | None) -> dict[str, Any]:
        token = self._get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        client = self._client or httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS)

        try:
            response = client.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise GraphCollectionError(f"request failed: {exc}") from exc

        if response.status_code == 200:
            try:
                body = response.json()
            except ValueError as exc:
                raise GraphCollectionError(f"response was not JSON: {exc}") from exc
            if not isinstance(body, dict):
                raise GraphCollectionError(
                    f"expected a JSON object, got {type(body).__name__}"
                )
            return body

        # The status code is the useful part of an error here: 401 is a bad
        # secret, 403 is usually a missing application permission, 400 is
        # usually a rejected filter. The response body may contain tenant data
        # or a request id, so only the code and a short reason are kept.
        raise GraphCollectionError(f"HTTP {response.status_code} {_reason(response)}")

    # -- credentials -----------------------------------------------------

    def _default_token(self) -> str:
        """Acquire an app-only token with azure-identity.

        Imported lazily so the demo path never needs the dependency or the
        credentials. Raises with the names of the variables that are missing,
        because "configure live mode" is not a useful error message.
        """
        missing = missing_graph_env_vars()
        if missing:
            raise GraphCollectionError(
                f"missing configuration: {', '.join(missing)}"
            )

        try:
            from azure.identity import ClientSecretCredential
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise GraphCollectionError(
                "azure-identity is required for live collection: "
                "pip install azure-identity"
            ) from exc

        credential = ClientSecretCredential(
            tenant_id=self._settings.graph_tenant_id,
            client_id=self._settings.graph_client_id,
            client_secret=self._settings.graph_client_secret,
        )
        # The secret is held by azure-identity and never read into a log line
        # or an event payload.
        return credential.get_token(GRAPH_SCOPE).token

    def _require_configuration(self) -> None:
        if not self._settings.graph_configured:
            missing = missing_graph_env_vars()
            raise GraphCollectionError(
                "live mode needs graph_tenant_id, graph_client_id and "
                f"graph_client_secret; missing: {', '.join(missing) or 'all three'}"
            )


# -- helpers ----------------------------------------------------------------


def _in_window(value: Any, start: datetime, end: datetime) -> bool:
    """True when a Graph timestamp falls inside the requested window.

    Written defensively: an unparseable timestamp is kept rather than dropped,
    because silently discarding an audit entry is worse than showing one the
    normalizer will reject with a log line.
    """
    if not isinstance(value, str) or not value:
        return True
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return start <= moment <= end


def _reason(response: httpx.Response) -> str:
    """A short, safe description of a failed response.

    Graph's error body contains a request id and sometimes echoed request
    parameters. Neither belongs in a log line, so only the message is read and
    it is truncated.
    """
    explanation = {
        400: "the query was rejected, often an unsupported $filter",
        401: "authentication failed; check the tenant, client id and secret",
        403: "the app lacks the required permission, usually AuditLog.Read.All "
             "with admin consent",
        404: "endpoint not available on this tenant or subscription",
        429: "throttled by Graph",
    }.get(response.status_code, "unexpected response")

    try:
        body = response.json()
        message = body.get("error", {}).get("message")
        if isinstance(message, str) and message:
            explanation = f"{explanation} ({message[:160]})"
    except ValueError:
        pass

    return explanation
