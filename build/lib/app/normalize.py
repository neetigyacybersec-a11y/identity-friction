"""Raw payload -> NormalizedEvent.

One normalizer serves both modes. The synthetic demo files are deliberately
written in Microsoft Graph's own JSON shape, so a demo event travels through
exactly the same code path as a live one. The only difference is the
`data_origin` value, which the normalizer never infers from the payload
structure — the caller states it.

Two things this module does on purpose:

* Every field is optional except the four that make an event identifiable.
  A missing latitude is None, not 0.0, because 0.0 is a real place.
* `raw` is carried through untouched. Normalization is lossy by nature, and
  the raw event is how you check whether it lost something.
"""

from __future__ import annotations

import logging
from typing import Any

from app.models.event import (
    AuthenticationStep,
    DataOrigin,
    EventOutcome,
    NormalizedEvent,
    RawEventType,
)

logger = logging.getLogger(__name__)


class NormalizationError(ValueError):
    """Raised when a payload cannot be read as an event at all.

    Deliberately narrow. A malformed event is a real error worth surfacing; a
    missing optional field is not.
    """


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _looks_like_audit_log(raw: dict[str, Any]) -> bool:
    return "activityDateTime" in raw or "activityDisplayName" in raw


def _sign_in_outcome(raw: dict[str, Any]) -> EventOutcome:
    """Graph reports success as an absent or zero error code.

    An absent error code is success. A missing `status` block entirely is not
    the same thing, and returns UNKNOWN rather than guessing success.
    """
    status = raw.get("status")
    if not isinstance(status, dict):
        return EventOutcome.UNKNOWN
    error_code = _as_int(status.get("errorCode"))
    if error_code is None or error_code == 0:
        return EventOutcome.SUCCESS
    return EventOutcome.FAILURE


def _audit_outcome(raw: dict[str, Any]) -> EventOutcome:
    result = _as_str(raw.get("activityResult"))
    if result is None:
        return EventOutcome.UNKNOWN
    if result.lower() == "success":
        return EventOutcome.SUCCESS
    return EventOutcome.FAILURE


def _authentication_steps(raw: dict[str, Any]) -> list[AuthenticationStep]:
    details = raw.get("authenticationDetails")
    if not isinstance(details, list):
        return []

    steps: list[AuthenticationStep] = []
    for entry in details:
        if not isinstance(entry, dict):
            continue
        succeeded = entry.get("succeeded")
        steps.append(
            AuthenticationStep(
                method=_as_str(entry.get("authenticationMethodType")),
                succeeded=bool(succeeded) if succeeded is not None else None,
                failure_reason=_as_str(entry.get("failureReason")),
            )
        )
    return steps


def _conditional_access(raw: dict[str, Any]) -> list[dict[str, Any]]:
    policies = raw.get("appliedConditionalAccessPolicies")
    if not isinstance(policies, list):
        return []
    return [policy for policy in policies if isinstance(policy, dict)]


def _granted_scopes(raw: dict[str, Any]) -> list[str]:
    """Pull delegated permissions out of an audit entry's target resources.

    A consent audit record carries the granted permissions as an added property
    named "Permission". Anything we cannot read is skipped rather than guessed.
    """
    scopes: list[str] = []
    for resource in raw.get("targetResources") or []:
        if not isinstance(resource, dict):
            continue
        for prop in resource.get("addedProperties") or []:
            if not isinstance(prop, dict):
                continue
            if _as_str(prop.get("name")) == "Permission":
                value = _as_str(prop.get("value"))
                if value:
                    scopes.append(value)
    return scopes


def _target_resources(raw: dict[str, Any]) -> list[dict[str, Any]]:
    resources = raw.get("targetResources")
    if not isinstance(resources, list):
        return []
    return [resource for resource in resources if isinstance(resource, dict)]


def normalize_event(
    raw: dict[str, Any],
    data_origin: DataOrigin = DataOrigin.LIVE_TENANT,
) -> NormalizedEvent:
    """Map a Graph-shaped payload onto the internal event shape.

    Pass `data_origin` explicitly. Do not let it be inferred from the payload:
    whether telemetry is real is a fact the caller knows, not something the
    structure of a JSON object can tell you.
    """
    if not isinstance(raw, dict):
        raise NormalizationError(f"expected a JSON object, got {type(raw).__name__}")

    is_audit = _looks_like_audit_log(raw)

    event_id = _as_str(raw.get("id")) or _as_str(raw.get("correlationId"))
    timestamp = _as_str(raw.get("activityDateTime")) or _as_str(raw.get("createdDateTime"))
    if not event_id or not timestamp:
        raise NormalizationError("event is missing an id or a timestamp")

    user = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    location = raw.get("location") if isinstance(raw.get("location"), dict) else {}
    device = raw.get("deviceDetail") if isinstance(raw.get("deviceDetail"), dict) else {}
    status = raw.get("status") if isinstance(raw.get("status"), dict) else {}
    initiated_by = (
        raw.get("initiatedBy") if isinstance(raw.get("initiatedBy"), dict) else {}
    )
    initiated_user = (
        initiated_by.get("user")
        if isinstance(initiated_by.get("user"), dict)
        else {}
    )

    # Sign-in logs describe the signing-in user. Audit logs describe whoever
    # performed the action, under `initiatedBy`. Same field, two places.
    user_id = _as_str(user.get("id")) or _as_str(initiated_user.get("id"))
    user_upn = _as_str(user.get("userPrincipalName")) or _as_str(
        initiated_user.get("userPrincipalName")
    )

    try:
        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            raw_event_type=RawEventType.AUDIT_LOG if is_audit else RawEventType.SIGN_IN,
            data_origin=data_origin,
            user_id=user_id,
            user_principal_name=user_upn,
            source_ip=_as_str(raw.get("ipAddress")),
            country=_as_str(location.get("countryOrRegion")),
            city=_as_str(location.get("city")),
            latitude=_as_float(location.get("latitude")),
            longitude=_as_float(location.get("longitude")),
            application=_as_str(raw.get("appDisplayName")),
            device=_as_str(device.get("displayName")),
            outcome=(
                _audit_outcome(raw) if is_audit else _sign_in_outcome(raw)
            ),
            status_error_code=_as_int(status.get("errorCode")),
            status_failure_reason=_as_str(status.get("failureReason")),
            authentication_requirement=_as_str(
                raw.get("isInteractive") or raw.get("isNonInteractive")
            ),
            authentication_details=_authentication_steps(raw),
            conditional_access=_conditional_access(raw),
            activity=_as_str(raw.get("activityDisplayName")),
            audit_category=_as_str(raw.get("category")),
            granted_scopes=_granted_scopes(raw),
            target_resources=_target_resources(raw),
            raw=raw,
        )
    except NormalizationError:
        raise
    except Exception as exc:  # pydantic raises ValidationError, which is noisy here
        raise NormalizationError(f"could not normalize event {event_id}: {exc}") from exc


def normalize_many(
    payloads: list[dict[str, Any]],
    data_origin: DataOrigin = DataOrigin.LIVE_TENANT,
) -> list[NormalizedEvent]:
    """Normalize a batch, skipping entries that cannot be read.

    One unreadable record in a 500-event page should not discard the other 499,
    so failures are logged and counted rather than raised. Callers that need to
    know use `normalize_many_strict`.
    """
    events: list[NormalizedEvent] = []
    for payload in payloads:
        try:
            events.append(normalize_event(payload, data_origin))
        except NormalizationError as exc:
            logger.warning("skipping unnormalizable event: %s", exc)
    return events


def normalize_many_strict(
    payloads: list[dict[str, Any]],
    data_origin: DataOrigin = DataOrigin.LIVE_TENANT,
) -> list[NormalizedEvent]:
    """Normalize a batch, raising on the first bad record.

    Demo mode uses this: a broken synthetic file is a bug in the repo, and it
    should fail loudly rather than quietly analyze 4 scenarios out of 5.
    """
    return [normalize_event(payload, data_origin) for payload in payloads]
