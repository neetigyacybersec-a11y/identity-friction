"""FastAPI application.

Exposes the pipeline over HTTP and serves a small dashboard. Two audiences:

* **The dashboard**, a Jinja page showing incidents, their timelines and their
  decisions, so the project is demonstrable by opening a browser.
* **The API**, JSON endpoints for the same data, so the pipeline is scriptable
  and testable without a browser.

Deliberately absent: authentication, multi-tenancy, and a job queue. This is a
single-user analyst tool. Saying so in the README is more honest than implying
it is a service, and adding auth nobody asked for would bury the parts worth
reading.

The one rule this layer enforces: **it never hides a degraded run.** Every
response that can be affected by a failing stage carries the degradation in its
body, so a screenshot of the dashboard cannot imply a clean analysis.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import (
    Settings,
    configure_logging,
    get_settings,
    missing_graph_env_vars,
)
from app.database.repository import Repository
from app.models.event import DataOrigin
from app.models.incident import IncidentStatus
from app.pipeline import analyze_demo, analyze_live, investigate_incident
from app.collect.graph import GraphCollectionError
from app.investigation.engine import InvestigationUnavailable

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

app = FastAPI(
    title="Identity Friction",
    description=(
        "Deterministic identity attack detection over Microsoft Entra ID "
        "telemetry, with model-backed decisions and investigation. A detected "
        "signal is not a confirmed attack."
    ),
    version="0.1.0",
    lifespan=lambda application: _lifespan(application),
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@asynccontextmanager
async def _lifespan(application: FastAPI):
    """Startup logging and directory setup.

    A lifespan handler rather than `on_event("startup")`, which FastAPI has
    deprecated.
    """
    settings = get_settings()
    configure_logging(settings)
    settings.ensure_directories()
    logger.info(
        "started in %s mode; decision backend: %s",
        settings.mode,
        "JEV over OpenRouter" if settings.openrouter_configured else "offline rules",
    )
    yield


def _repository() -> Repository:
    return Repository(get_settings().database_path)


def _degradation_note(result: Any) -> dict[str, Any]:
    """The degradation block every run-derived response carries.

    Repeated deliberately rather than wrapped in a helper on the response model:
    the alternative is a response type whose fields are optional, which is
    exactly how a missing warning becomes invisible.
    """
    return {
        "complete": result.complete,
        "degraded_stages": result.degraded,
    }


# -- dashboard --------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> Any:
    settings = get_settings()
    repository = _repository()

    incidents = repository.list_incidents(limit=50)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "settings": settings,
            "incidents": incidents,
            "event_count": repository.count_events(),
            "incident_count": repository.count_incidents(),
            "by_attack_type": repository.incidents_by_attack_type(),
            "live_configured": settings.graph_configured,
            "openrouter_configured": settings.openrouter_configured,
            "missing_graph_env": missing_graph_env_vars(),
            "last_run": _last_run(repository),
        },
    )


@app.get("/incidents/{incident_uid}", response_class=HTMLResponse)
def incident_detail(request: Request, incident_uid: str) -> Any:
    repository = _repository()
    incident = repository.get_incident(incident_uid)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")

    return templates.TemplateResponse(
        request, "incident.html", {"incident": incident}
    )


# -- read API ---------------------------------------------------------------


@app.get("/api/health")
def health() -> dict[str, Any]:
    """Configuration and coverage state.

    Reports what is *not* configured rather than only what is. A green health
    check on a system that has never talked to a tenant would be misleading.
    """
    settings = get_settings()
    try:
        repository = _repository()
        event_count = repository.count_events()
        incident_count = repository.count_incidents()
        database_ok = True
    except Exception as error:  # the health endpoint must answer even when broken
        logger.exception("health check could not open the database")
        event_count = incident_count = 0
        database_ok = False
        return {
            "status": "degraded",
            "mode": settings.mode,
            "database_ok": False,
            "error": str(error),
            "decision_backend": "rules" if not settings.openrouter_configured else "jev",
            "graph_configured": settings.graph_configured,
        }

    return {
        "status": "ok",
        "mode": settings.mode,
        "database_ok": database_ok,
        "events": event_count,
        "incidents": incident_count,
        "open_incidents": repository.count_incidents(IncidentStatus.OPEN),
        "by_attack_type": repository.incidents_by_attack_type(),
        "decision_backend": "jev" if settings.openrouter_configured else "rules",
        "investigation_available": settings.openrouter_configured,
        "graph_configured": settings.graph_configured,
        "missing_graph_env": missing_graph_env_vars(),
        # A reminder that travels with the data rather than only in the README.
        "note": (
            "A detected signal is not a confirmed attack. Every incident here "
            "requires analyst review before any response action."
        ),
    }


@app.get("/api/incidents")
def list_incidents(
    limit: int = Query(default=50, ge=1, le=200),
    status: str | None = None,
    data_origin: str | None = None,
) -> dict[str, Any]:
    repository = _repository()

    status_enum: IncidentStatus | None = None
    if status:
        try:
            status_enum = IncidentStatus(status)
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=f"unknown status {status!r}; expected one of "
                f"{[s.value for s in IncidentStatus]}",
            ) from error

    origin_enum: DataOrigin | None = None
    if data_origin:
        try:
            origin_enum = DataOrigin(data_origin)
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=f"unknown data_origin {data_origin!r}; expected one of "
                f"{[o.value for o in DataOrigin]}",
            ) from error

    return {
        "incidents": repository.list_incidents(
            limit=limit, status=status_enum, data_origin=origin_enum
        ),
        "count": len(repository.list_incidents(limit=limit)),
        "total": repository.count_incidents(),
    }


@app.get("/api/incidents/{incident_uid}")
def get_incident(incident_uid: str) -> dict[str, Any]:
    incident = _repository().get_incident(incident_uid)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@app.get("/api/events")
def list_events(
    limit: int = Query(default=100, ge=1, le=500),
    data_origin: str | None = None,
) -> dict[str, Any]:
    origin_enum: DataOrigin | None = None
    if data_origin:
        try:
            origin_enum = DataOrigin(data_origin)
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=f"unknown data_origin {data_origin!r}",
            ) from error

    repository = _repository()
    return {
        "events": repository.get_events(limit=limit, data_origin=origin_enum),
        "total": repository.count_events(),
    }


# -- actions ----------------------------------------------------------------


@app.post("/api/analyze/demo")
def run_demo_analysis(
    run_investigation: bool = Query(default=False),
) -> dict[str, Any]:
    """Analyze the synthetic sample data.

    The default demo path. It needs no credentials and no network, which is what
    makes the project demonstrable on a laptop and in CI.
    """
    result = analyze_demo(get_settings(), run_investigation=run_investigation)
    return {**result.summary(), **_degradation_note(result)}


@app.post("/analyze/demo")
def run_demo_from_dashboard() -> RedirectResponse:
    """Run the demo analysis from the dashboard's own button, then go back.

    This exists so the browser path does not have to POST to a JSON endpoint and
    land the reader on a wall of raw JSON. The API route above is for scripts;
    this one is for whoever just opened localhost:8000 and found it empty.
    """
    analyze_demo(get_settings(), run_investigation=False)
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/analyze/live")
def run_live_analysis(
    run_investigation: bool = Query(default=False),
) -> dict[str, Any]:
    """Collect from Microsoft Graph and analyze.

    Returns 400 with the collection error when nothing arrived, rather than a
    successful-looking response describing an empty analysis. An empty result
    from a misconfigured tenant is indistinguishable from a quiet tenant, and
    that ambiguity is the failure mode worth designing against.
    """
    settings = get_settings()
    if not settings.graph_configured:
        missing = missing_graph_env_vars()
        raise HTTPException(
            status_code=400,
            detail=(
                "live mode is not configured. Set "
                f"{', '.join(missing) or 'the graph credentials'} and restart. "
                "The demo endpoint needs nothing."
            ),
        )

    try:
        result = analyze_live(settings, run_investigation=run_investigation)
    except GraphCollectionError as error:
        raise HTTPException(
            status_code=502,
            detail=f"Microsoft Graph collection failed: {error}",
        ) from error

    return {**result.summary(), **_degradation_note(result)}


@app.post("/api/incidents/{incident_uid}/investigate")
def run_investigation(incident_uid: str) -> dict[str, Any]:
    """Write an investigation report for one incident.

    On demand rather than automatic: it costs a model call, and an analyst wants
    a report for the incident in front of them, not for all of them at once.
    """
    settings = get_settings()
    if not settings.openrouter_configured:
        raise HTTPException(
            status_code=400,
            detail=(
                "no OpenRouter API key configured, so no investigation model is "
                "available. The incident's detection and decision are unaffected."
            ),
        )

    try:
        report = investigate_incident(incident_uid, settings, _repository())
    except InvestigationUnavailable as error:
        raise HTTPException(
            status_code=502, detail=f"investigation failed: {error}"
        ) from error

    if report is None:
        raise HTTPException(status_code=404, detail="incident not found")

    return {"incident_uid": incident_uid, "investigation": report}


def _last_run(repository: Repository) -> dict[str, Any] | None:
    """A rough picture of the most recent analysis.

    Derived from stored data rather than a run table, so it stays truthful when
    the database was written by the CLI rather than the API.
    """
    incidents = repository.list_incidents(limit=1)
    if not incidents:
        return None
    newest = incidents[0]
    return {
        "last_seen": newest["last_seen"],
        "incidents": repository.count_incidents(),
    }
