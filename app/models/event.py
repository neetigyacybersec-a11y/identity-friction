"""Internal event model.

Every event the project handles, from Microsoft Graph or from the synthetic
demo files, becomes a NormalizedEvent. Detectors only ever see this shape, so
none of them has to know or care where the event came from.

The original payload is kept in `raw`. That is deliberate: if normalization ever
drops a field a detector needed, the raw event is how you prove it.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DataOrigin(str, Enum):
    """Where an event came from. The dashboard always shows this.

    A demo screenshot and a production screenshot must never be confusable.
    """

    SYNTHETIC = "synthetic"
    LIVE_TENANT = "live_tenant"


class RawEventType(str, Enum):
    SIGN_IN = "sign_in"
    AUDIT_LOG = "audit_log"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class AuthenticationStep(BaseModel):
    """One step of a multi-factor sign-in, lifted from Graph's authenticationDetails.

    Kept as a small model rather than a bare dict so detectors can rely on
    `succeeded` and `method` being present-or-None instead of guessing at keys.
    """

    method: str | None = None
    succeeded: bool | None = None
    failure_reason: str | None = None


class NormalizedEvent(BaseModel):
    """The one internal event shape. Field names are stable; values may be None.

    None means "the source did not tell us". It never means "false" or "zero".
    That distinction matters: a missing latitude is not the same as latitude 0,
    and a missing conditional access status is not a pass.
    """

    event_id: str
    timestamp: datetime
    raw_event_type: RawEventType
    data_origin: DataOrigin

    user_id: str | None = None
    user_principal_name: str | None = None
    source_ip: str | None = None

    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None

    application: str | None = None
    device: str | None = None

    outcome: EventOutcome = EventOutcome.UNKNOWN
    status_error_code: int | None = None
    status_failure_reason: str | None = None

    authentication_requirement: str | None = None
    authentication_details: list[AuthenticationStep] = Field(default_factory=list)
    conditional_access: list[dict[str, Any]] = Field(default_factory=list)

    # Audit logs only. Sign-in logs have no equivalent fields.
    activity: str | None = None
    audit_category: str | None = None
    granted_scopes: list[str] = Field(default_factory=list)
    target_resources: list[dict[str, Any]] = Field(default_factory=list)

    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.outcome is EventOutcome.SUCCESS

    @property
    def is_failure(self) -> bool:
        return self.outcome is EventOutcome.FAILURE

    @property
    def user_key(self) -> str | None:
        """The value incidents are grouped by, when present.

        userPrincipalName is preferred because it is human-readable in the
        dashboard, with the immutable user id as a fallback.
        """
        return self.user_principal_name or self.user_id
