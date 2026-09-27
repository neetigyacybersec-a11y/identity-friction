"""Deterministic feature extraction.

Every function here is a pure function of its arguments. No clock, no network,
no randomness, no config reads. That is what makes the detection path testable
with no credentials, no tenant and no API key, and it is why nothing in this
module is allowed to import a client.

Features are plain dataclasses rather than pydantic models because they are
intermediate values that never cross the API boundary, and a frozen dataclass
makes the "computed once, read many" contract obvious.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.models.event import NormalizedEvent

EARTH_RADIUS_KM = 6371.0


@dataclass(frozen=True)
class WindowStats:
    """Counts over a time window, grouped by user and by source IP.

    `by_user` and `by_ip` are kept separately because they answer different
    questions. A spray looks modest per user and extreme per IP; a single user
    locking themselves out looks the opposite way round.
    """

    window_start: datetime
    window_end: datetime
    total: int
    failures: int
    successes: int
    unique_users: int
    unique_ips: int
    by_user: dict[str, int] = field(default_factory=dict)
    by_ip: dict[str, int] = field(default_factory=dict)


def sort_by_time(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Chronological order. Returns a new list; does not mutate the input."""
    return sorted(events, key=lambda event: event.timestamp)


def filter_window(
    events: list[NormalizedEvent],
    start: datetime,
    end: datetime,
) -> list[NormalizedEvent]:
    """Events whose timestamp falls inside [start, end], inclusive both ends.

    Timestamps arrive timezone-aware from both Graph and the synthetic files, so
    the comparison is safe. A naive datetime would raise, which is the correct
    outcome: a mixed-awareness comparison silently produces wrong windows.
    """
    return [
        event for event in events if start <= event.timestamp <= end
    ]


def window_stats(
    events: list[NormalizedEvent],
    start: datetime,
    end: datetime,
) -> WindowStats:
    """Count and group the events inside a window."""
    inside = filter_window(events, start, end)

    by_user: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    failures = 0

    for event in inside:
        user_key = event.user_key or "<unknown-user>"
        by_user[user_key] = by_user.get(user_key, 0) + 1
        ip = event.source_ip or "<unknown-ip>"
        by_ip[ip] = by_ip.get(ip, 0) + 1
        if event.is_failure:
            failures += 1

    return WindowStats(
        window_start=start,
        window_end=end,
        total=len(inside),
        failures=failures,
        successes=sum(1 for event in inside if event.is_success),
        unique_users=len({event.user_key for event in inside if event.user_key}),
        unique_ips=len({event.source_ip for event in inside if event.source_ip}),
        by_user=by_user,
        by_ip=by_ip,
    )


def sliding_windows(
    events: list[NormalizedEvent],
    minutes: int,
    step_seconds: int = 60,
) -> list[tuple[datetime, datetime, list[NormalizedEvent]]]:
    """Walk a window of `minutes` across the event range, returning the content.

    A single fixed window would miss an attack that straddles its boundary, so
    the window slides. The step is deliberately coarse: one minute is fine
    granularity for identity telemetry and keeps this cheap enough to run on
    every analysis.

    The walk stops once the window start passes the last event, so trailing
    windows that reach beyond the data are still produced but the loop always
    terminates. A bad `step_seconds` would otherwise spin forever, hence the
    guard.
    """
    if step_seconds <= 0:
        raise ValueError("step_seconds must be positive")

    ordered = sort_by_time(events)
    if not ordered:
        return []

    first = ordered[0].timestamp
    last = ordered[-1].timestamp
    span = timedelta(minutes=minutes)
    step = timedelta(seconds=step_seconds)

    results: list[tuple[datetime, datetime, list[NormalizedEvent]]] = []
    cursor = first
    while cursor <= last:
        window_end = cursor + span
        content = filter_window(ordered, cursor, window_end)
        if content:
            results.append((cursor, window_end, content))
        cursor += step
    return results


def haversine_km(
    lat1: float, lon1: float, lat2: float, lon2: float
) -> float:
    """Great-circle distance in kilometres.

    Nine lines of trigonometry is a worse dependency than numpy would be, and
    this keeps the geography explainable in a sentence.
    """
    lat1_rad, lon1_rad = math.radians(lat1), math.radians(lon1)
    lat2_rad, lon2_rad = math.radians(lat2), math.radians(lon2)

    delta_lat = lat2_rad - lat1_rad
    delta_lon = lon2_rad - lon1_rad

    a = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def travel_speed_kmh(
    first: NormalizedEvent,
    second: NormalizedEvent,
) -> float | None:
    """Implied travel speed between two events, or None if it cannot be computed.

    Returns None rather than 0 or infinity when coordinates or elapsed time are
    missing, so a caller cannot mistake "unknown" for "impossible".
    """
    points = [first, second]
    if any(point.latitude is None or point.longitude is None for point in points):
        return None

    distance = haversine_km(
        first.latitude, first.longitude, second.latitude, second.longitude
    )
    elapsed_hours = (second.timestamp - first.timestamp).total_seconds() / 3600.0
    if elapsed_hours <= 0:
        return None
    return distance / elapsed_hours


def is_mfa_failure(event: NormalizedEvent, denial_codes: list[int]) -> bool:
    """Whether an event looks like a second-factor failure rather than a bad password.

    Two independent signals, either of which is enough. The error code is the
    cheap check; the authentication detail is the one that survives a tenant
    using a different code, and it is what actually distinguishes "the password
    was wrong" from "the second factor was refused".
    """
    if event.is_success:
        return False

    if event.status_error_code in denial_codes:
        return True

    return any(step.succeeded is False for step in event.authentication_details)


def is_invalid_credentials(
    event: NormalizedEvent, invalid_codes: list[int]
) -> bool:
    """Whether the failure is a rejected username or password.

    An event that failed on the second factor is not counted here. Conflating
    the two would let MFA fatigue inflate the password spray counters.
    """
    if not event.is_failure:
        return False
    if event.status_error_code not in invalid_codes:
        return False
    return not is_mfa_failure(event, denial_codes=[])
