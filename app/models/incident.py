"""Incident and detection-result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from app.models.decision import AttackType, Decision
from app.models.event import DataOrigin, NormalizedEvent


class DetectionName(str, Enum):
    PASSWORD_SPRAY = "password_spray"
    MFA_FATIGUE = "mfa_fatigue"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    OAUTH_CONSENT = "oauth_consent"


class DetectionResult(BaseModel):
    """The output of a deterministic rule that fired.

    A DetectionResult is a *signal*. It is not a finding, an incident, or an
    attack. See docs/adr/0002-signal-not-proof.md.
    """

    detection: DetectionName
    fired: bool
    title: str
    finding: str
    signal: dict[str, Any] = Field(default_factory=dict)
    # The specific numbers the rule compared against, so the dashboard can show
    # "12 >= 10" instead of just "fired".
    evidence: dict[str, Any] = Field(default_factory=dict)
    # Always populated. A detection that cannot say what it cannot see is
    # hiding something.
    limitations: str
    event_ids: list[str] = Field(default_factory=list)
    events: list[NormalizedEvent] = Field(default_factory=list)
    suggested_attack_type: AttackType = AttackType.UNKNOWN
    base_severity: int = Field(default=3, ge=1, le=10)

    # Identity of the underlying signal, not of this particular finding.
    # A sliding window will see the same spray cluster from several start
    # times, so detectors set a key here and the engine collapses the
    # duplicates. Two findings that describe the same activity are one
    # activity, and an incident list with five copies of one finding is
    # useless to an analyst.
    dedupe_key: str | None = None


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class TimelineEntry(BaseModel):
    """One line of an incident timeline.

    Attack chains read in sequence — denied, denied, denied, accepted, consent
    granted — so ordering is the point and `timestamp` is never optional here.
    """

    timestamp: datetime
    event_id: str
    label: str
    detail: str
    outcome: str
    source_ip: str | None = None
    raw_event_type: str = "sign_in"


class Incident(BaseModel):
    incident_id: str
    attack_type: AttackType = AttackType.UNKNOWN
    status: IncidentStatus = IncidentStatus.OPEN
    severity: int = Field(default=1, ge=1, le=10)

    user_key: str | None = None
    source_ip: str | None = None
    application: str | None = None
    data_origin: DataOrigin = DataOrigin.SYNTHETIC

    first_seen: datetime
    last_seen: datetime
    event_count: int = 0

    title: str = ""
    signal_summary: dict[str, Any] = Field(default_factory=dict)
    limitations: str = ""

    detections: list[DetectionResult] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    decision: Decision | None = None
    investigation: dict[str, Any] | None = None
