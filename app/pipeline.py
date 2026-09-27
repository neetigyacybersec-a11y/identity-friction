"""The analysis pipeline.

One function that takes events and returns incidents, with every stage's
failure recorded rather than raised. This is the piece the CLI, the API and the
tests all call, so there is exactly one order of operations in the project.

The order is the design:

    collect -> normalize -> store events -> detect -> correlate
            -> store incidents -> decide -> investigate

Detection runs before correlation because detections are per-event and
correlation needs their results. Decisions run after correlation because a
decision judges an incident, not a finding. Investigation runs last because it
is the only stage that may fail without changing the outcome.

The rule that shapes the error handling: **the pipeline never loses a
deterministic result to a model failure.** If JEV is unreachable the incident
still has its detection severity; if the investigation model is down the
incident still has its decision and is marked as not investigated. A portfolio
project that only works with an API key is not demonstrable, and worse, it is
not honest about which part of the system is doing the work.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from app.config import Settings, get_settings
from app.correlation import CorrelationEngine
from app.database.repository import Repository
from app.decision.engine import (
    DecisionEngine,
    DecisionRequest,
    DecisionUnavailable,
    build_decision_engine,
    decide_or_fallback,
)
from app.detection.engine import DetectionEngine
from app.investigation.engine import InvestigationEngine, InvestigationUnavailable
from app.models.event import DataOrigin, NormalizedEvent
from app.models.incident import Incident
from app.normalize import normalize_many_strict

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Everything one run produced, including what it could not do."""

    events_ingested: int = 0
    events_new: int = 0
    findings: int = 0
    incidents: list[Incident] = field(default_factory=list)
    decisions_made: int = 0
    decisions_fallback: int = 0
    investigations_written: int = 0
    # Coverage gaps, keyed by stage. An empty dict means every stage completed.
    degraded: dict[str, str] = field(default_factory=dict)
    source: str = "demo"
    duration_seconds: float = 0.0

    @property
    def complete(self) -> bool:
        return not self.degraded

    def summary(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "events_ingested": self.events_ingested,
            "events_new": self.events_new,
            "findings": self.findings,
            "incidents": len(self.incidents),
            "decisions_made": self.decisions_made,
            "decisions_fallback": self.decisions_fallback,
            "investigations_written": self.investigations_written,
            "degraded": self.degraded,
            "complete": self.complete,
            "duration_seconds": round(self.duration_seconds, 3),
        }


def analyze_events(
    events: list[NormalizedEvent],
    settings: Settings | None = None,
    repository: Repository | None = None,
    decision_engine: DecisionEngine | None = None,
    investigation_engine: InvestigationEngine | None = None,
    source: str = "demo",
    run_investigation: bool = True,
) -> PipelineResult:
    """Run the deterministic half, then the model-backed half.

    Detection, correlation and persistence are the deterministic half and have
    no external dependencies. Decisions and investigation may call a model and
    are each wrapped so their failure is recorded, not propagated.
    """
    started = time.monotonic()
    settings = settings or get_settings()
    result = PipelineResult(events_ingested=len(events), source=source)

    repository = repository or Repository(settings.database_path)

    # 1. Events. Re-ingesting a file adds nothing, so a repeat run does not
    #    inflate the counts the dashboard shows.
    result.events_new = repository.upsert_events(events)

    # 2. Detection. Never fails the run: the engine already isolates a detector
    #    that raises.
    detection_engine = DetectionEngine()
    results = detection_engine.run(events, settings)
    fired = detection_engine.fired(results)
    result.findings = len(fired)

    events_by_id = {event.event_id: event for event in events}

    # 3. Correlation.
    incidents = CorrelationEngine(settings).correlate(fired, events_by_id)
    result.incidents = incidents

    # 4. Persist incidents before deciding, so a decision has something to
    #    attach to even if the model layer is down.
    for incident in incidents:
        repository.upsert_incident(incident)

    # 5. Decisions.
    decision_engine = decision_engine or build_decision_engine(settings)
    decisions: dict[str, Any] = {}
    for incident in incidents:
        decision, error = decide_or_fallback(
            decision_engine, DecisionRequest(incident=incident), settings
        )
        if error:
            result.degraded["decision"] = error
            result.decisions_fallback += 1
            repository.save_incident_error(incident.incident_id, error)
        else:
            result.decisions_made += 1

        repository.save_decision(incident.incident_id, decision)
        decisions[incident.incident_id] = decision
        incident.decision = decision

    # 6. Investigation. Off by default for bulk runs: it is the slow, token-costly
    #    stage, and an analyst opens one incident at a time. The API turns it on
    #    for a single incident.
    if run_investigation and incidents and settings.openrouter_configured:
        investigation_engine = investigation_engine or InvestigationEngine(settings)
        for incident in incidents:
            try:
                report = investigation_engine.investigate(
                    incident, decisions.get(incident.incident_id)
                )
            except InvestigationUnavailable as error:
                result.degraded["investigation"] = str(error)
                logger.warning("no investigation for %s: %s", incident.incident_id, error)
                continue
            except Exception as error:  # a bug here must not lose the incidents
                logger.exception("investigation raised for %s", incident.incident_id)
                result.degraded["investigation"] = f"unexpected error: {error}"
                continue

            incident.investigation = report.model_dump()
            repository.save_decision(
                incident.incident_id,
                decisions[incident.incident_id],
                investigation=report.model_dump(),
            )
            result.investigations_written += 1
    elif run_investigation and incidents:
        result.degraded["investigation"] = "no OpenRouter API key configured"

    result.duration_seconds = time.monotonic() - started
    return result


def load_demo_events(settings: Settings | None = None) -> list[NormalizedEvent]:
    """Read every synthetic dataset from the sample directory.

    Demo mode uses the strict normalizer. A malformed sample file is a bug in
    this repository, and failing loudly beats silently analysing four scenarios
    out of five and reporting a clean result.
    """
    settings = settings or get_settings()
    directory: Path = settings.sample_data_dir
    if not directory.exists():
        raise FileNotFoundError(
            f"sample data directory not found: {directory}. "
            "Run scripts/generate_demo_data.py to create it."
        )

    import json

    events: list[NormalizedEvent] = []
    for path in sorted(directory.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        events.extend(
            normalize_many_strict(payload.get("events", []), DataOrigin.SYNTHETIC)
        )

    logger.info("loaded %s demo events from %s files", len(events), directory)
    return events


def analyze_demo(
    settings: Settings | None = None,
    repository: Repository | None = None,
    run_investigation: bool = False,
    decision_engine: DecisionEngine | None = None,
    investigation_engine: InvestigationEngine | None = None,
) -> PipelineResult:
    """Convenience wrapper: load the sample data and analyze it.

    Investigation defaults to off here. Running it over every demo incident on
    every page load would spend tokens re-deriving the same report, and the
    reports are for a human to request.
    """
    settings = settings or get_settings()
    events = load_demo_events(settings)
    return analyze_events(
        events,
        settings=settings,
        repository=repository,
        source="demo",
        run_investigation=run_investigation,
        decision_engine=decision_engine,
        investigation_engine=investigation_engine,
    )


def analyze_live(
    settings: Settings | None = None,
    repository: Repository | None = None,
    run_investigation: bool = False,
    decision_engine: DecisionEngine | None = None,
    investigation_engine: InvestigationEngine | None = None,
) -> PipelineResult:
    """Collect from Graph, then analyze.

    A collection gap is recorded in `degraded` and the events that did arrive
    are still analyzed. Partial telemetry is worth analysing, provided the gap
    is visible.
    """
    from app.collect.graph import GraphCollector, GraphCollectionError

    settings = settings or get_settings()
    collector = GraphCollector(settings)

    try:
        collection = collector.collect()
    except GraphCollectionError as error:
        # Nothing arrived at all, so there is nothing to analyze. Raising here is
        # correct: an empty analysis would look like a quiet tenant.
        raise

    result = analyze_events(
        collection.events,
        settings=settings,
        repository=repository,
        source="live",
        run_investigation=run_investigation,
        decision_engine=decision_engine,
        investigation_engine=investigation_engine,
    )
    if collection.errors:
        result.degraded["collection"] = "; ".join(collection.errors)
    return result


def investigate_incident(
    incident_uid: str,
    settings: Settings | None = None,
    repository: Repository | None = None,
    investigation_engine: InvestigationEngine | None = None,
) -> dict[str, Any] | None:
    """Write an investigation report for one already-stored incident.

    The on-demand path an analyst triggers. Returns the stored report, or None
    when the incident is unknown. Raises `InvestigationUnavailable` so the
    caller can show a real reason rather than an empty panel.
    """
    settings = settings or get_settings()
    repository = repository or Repository(settings.database_path)

    stored = repository.get_incident(incident_uid)
    if stored is None:
        return None

    # Rebuild the incident the engine needs. The stored row is a dict, and
    # re-deriving the model from it keeps the two paths from drifting.
    incident = _incident_from_row(stored)
    engine = investigation_engine or InvestigationEngine(settings)
    report = engine.investigate(incident, incident.decision)

    repository.save_decision(incident_uid, incident.decision or _rules_decision(incident), investigation=report.model_dump())
    return report.model_dump()


def _rules_decision(incident: Incident):
    from app.models.decision import Decision

    return Decision()


def _incident_from_row(stored: dict[str, Any]) -> Incident:
    """Rehydrate an Incident from a stored row.

    Only the fields the investigation prompt needs are restored. The timeline
    and signal summary are present on the row; the underlying detection objects
    are not, and the prompt is written not to require them.
    """
    from app.models.decision import AttackType, Decision
    from app.models.incident import IncidentStatus, TimelineEntry

    timeline = [
        TimelineEntry(
            timestamp=entry["timestamp"],
            event_id=entry["event_id"],
            label=_label_for(entry),
            detail=_detail_for(entry),
            outcome=entry.get("outcome", "unknown"),
            source_ip=entry.get("source_ip"),
            raw_event_type=entry.get("raw_event_type", "sign_in"),
        )
        for entry in stored.get("timeline", [])
    ]

    decision = None
    if stored.get("decision"):
        decision = Decision(**_decision_kwargs(stored["decision"]))

    return Incident(
        incident_id=stored["incident_uid"],
        attack_type=AttackType(stored["attack_type"]),
        status=IncidentStatus(stored["status"]),
        severity=stored["severity"],
        user_key=stored.get("user_key"),
        source_ip=stored.get("source_ip"),
        application=stored.get("application"),
        subject=stored.get("subject"),
        data_origin=DataOrigin(stored["data_origin"]),
        first_seen=stored["first_seen"],
        last_seen=stored["last_seen"],
        event_count=stored["event_count"],
        title=stored.get("title", ""),
        signal_summary=stored.get("signal_summary", {}),
        limitations=stored.get("limitations", ""),
        timeline=timeline,
        decision=decision,
    )


def _label_for(entry: dict[str, Any]) -> str:
    """Rebuild a timeline label from the stored columns.

    The label is derived rather than stored: it is presentational, and storing it
    would mean a wording change needed a data migration.
    """
    if entry.get("activity"):
        return entry["activity"]
    if entry.get("outcome") == "success":
        return "Sign-in succeeded"
    return "Sign-in failed"


def _detail_for(entry: dict[str, Any]) -> str:
    parts = [entry.get("application") or "sign-in"]
    if entry.get("city"):
        parts.append(f"{entry['city']}, {entry.get('country') or '?'}")
    if entry.get("status_error_code"):
        parts.append(f"code {entry['status_error_code']}")
    return " - ".join(parts)


def _decision_kwargs(row: dict[str, Any]) -> dict[str, Any]:
    """Strip the row's display-only keys so the model can validate it."""
    return {
        key: value
        for key, value in row.items()
        if key
        in {
            "suspicious",
            "suspicion_score",
            "attack_type",
            "severity",
            "escalate",
            "needs_analyst_review",
            "confidence",
            "band",
            "source",
            "reasoning",
        }
    }
