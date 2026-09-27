"""Incident correlation.

Detection runs per event, but nobody investigates an event. An analyst
investigates a story, and a story is a sequence: denied, denied, denied,
accepted, consent granted.

This module groups findings that plausibly belong to the same activity and
builds an incident with an ordered timeline.

The grouping keys, in priority order:

1. **Same user** — the strongest signal. One account under attack is one story.
2. **Same source IP** — a spray against many accounts is one story told from
   the attacker's side rather than the victim's.
3. **Same application** — the weakest, and only used to merge a finding that
   shares neither a user nor an IP with another.

On top of the key match, two findings only join if they are within the
configured incident window. Without that, a user's activity this morning and
this afternoon would never correlate, and neither would two findings that share
a user but describe unrelated events weeks apart.

No graph database. Two hops of parent-child between four tables is what SQL was
built for.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from app.config import Settings
from app.features import sort_by_time
from app.models.decision import AttackType
from app.models.event import DataOrigin, EventOutcome, NormalizedEvent
from app.models.incident import (
    DetectionResult,
    Incident,
    TimelineEntry,
)

logger = logging.getLogger(__name__)


class CorrelationEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def correlate(
        self,
        findings: list[DetectionResult],
        events_by_id: dict[str, NormalizedEvent],
    ) -> list[Incident]:
        """Group findings into incidents.

        `events_by_id` supplies the events behind each finding so the timeline
        can be built in timestamp order rather than in detection order.
        """
        if not findings:
            return []

        window = timedelta(minutes=self.settings.incident_window_minutes)
        groups: list[list[DetectionResult]] = []
        assigned: set[int] = set()

        for index, finding in enumerate(findings):
            if index in assigned:
                continue

            group = [finding]
            assigned.add(index)
            anchor = self._time_span(finding, events_by_id)

            for other_index in range(index + 1, len(findings)):
                if other_index in assigned:
                    continue
                other = findings[other_index]
                other_span = self._time_span(other, events_by_id)

                if not self._shares_a_key(finding, other):
                    continue
                # Overlapping in time, or close enough to be the same story.
                if not self._overlaps(anchor, other_span, window):
                    continue

                group.append(other)
                assigned.add(other_index)
                anchor = self._merge_spans(anchor, other_span)

            groups.append(group)

        return [self._build_incident(group, events_by_id) for group in groups]

    # -- grouping helpers ------------------------------------------------

    @staticmethod
    def _shares_a_key(left: DetectionResult, right: DetectionResult) -> bool:
        if left.dedupe_key and left.dedupe_key == right.dedupe_key:
            return True

        left_users = CorrelationEngine._users(left)
        right_users = CorrelationEngine._users(right)
        if left_users & right_users:
            return True

        left_ips = CorrelationEngine._ips(left)
        right_ips = CorrelationEngine._ips(right)
        if left_ips & right_ips:
            return True

        left_apps = CorrelationEngine._apps(left)
        right_apps = CorrelationEngine._apps(right)
        return bool(left_apps & right_apps)

    @staticmethod
    def _time_span(
        finding: DetectionResult, events_by_id: dict[str, NormalizedEvent]
    ) -> tuple[datetime, datetime] | None:
        timestamps = [
            events_by_id[event_id].timestamp
            for event_id in finding.event_ids
            if event_id in events_by_id
        ]
        if not timestamps:
            return None
        return min(timestamps), max(timestamps)

    @staticmethod
    def _merge_spans(
        left: tuple[datetime, datetime] | None,
        right: tuple[datetime, datetime] | None,
    ) -> tuple[datetime, datetime] | None:
        if left is None:
            return right
        if right is None:
            return left
        return min(left[0], right[0]), max(left[1], right[1])

    @staticmethod
    def _overlaps(
        left: tuple[datetime, datetime] | None,
        right: tuple[datetime, datetime] | None,
        window: timedelta,
    ) -> bool:
        if left is None or right is None:
            # A finding with no resolvable timestamps cannot be placed in time.
            # Joining it would be a guess, so it stays on its own.
            return False
        return left[0] - window <= right[1] and right[0] - window <= left[1]

    @staticmethod
    def _users(finding: DetectionResult) -> set[str]:
        return {event.user_key for event in finding.events if event.user_key}

    @staticmethod
    def _ips(finding: DetectionResult) -> set[str]:
        return {event.source_ip for event in finding.events if event.source_ip}

    @staticmethod
    def _apps(finding: DetectionResult) -> set[str]:
        return {
            event.application
            for event in finding.events
            if event.application and event.application != "Unknown"
        }

    # -- incident construction -------------------------------------------

    def _build_incident(
        self,
        group: list[DetectionResult],
        events_by_id: dict[str, NormalizedEvent],
    ) -> Incident:
        # One event appearing in two findings should appear once on the
        # timeline, or the story reads as if it happened twice.
        seen: set[str] = set()
        timeline_events: list[NormalizedEvent] = []
        for finding in group:
            for event_id in finding.event_ids:
                if event_id in seen or event_id not in events_by_id:
                    continue
                seen.add(event_id)
                timeline_events.append(events_by_id[event_id])

        timeline_events = sort_by_time(timeline_events)

        attack_type = self._dominant_attack_type(group)
        severity = max(finding.base_severity for finding in group)
        user_key = self._most_common(self._users_for(group))
        source_ip = self._most_common(self._ips_for(group))
        application = self._most_common(self._apps_for(group))
        scope, subject = self._choose_scope(group, user_key, source_ip, application)

        origins = {event.data_origin for event in timeline_events}
        data_origin = (
            DataOrigin.LIVE_TENANT
            if DataOrigin.LIVE_TENANT in origins
            else DataOrigin.SYNTHETIC
        )

        limitations = " ".join(
            dict.fromkeys(finding.limitations for finding in group if finding.limitations)
        )

        uid = self._make_uid(attack_type, group, scope, source_ip, application)

        return Incident(
            incident_id=uid,
            attack_type=attack_type,
            severity=severity,
            user_key=user_key,
            source_ip=source_ip,
            application=application,
            data_origin=data_origin,
            subject=subject,
            first_seen=timeline_events[0].timestamp,
            last_seen=timeline_events[-1].timestamp,
            event_count=len(timeline_events),
            title=self._make_title(attack_type, group, scope, subject, user_key, source_ip),
            signal_summary={
                "detections": [finding.detection.value for finding in group],
                "detail": {finding.detection.value: finding.signal for finding in group},
            },
            limitations=limitations,
            detections=group,
            timeline=[self._timeline_entry(event) for event in timeline_events],
        )

    @staticmethod
    def _dominant_attack_type(group: list[DetectionResult]) -> AttackType:
        """The most severe finding's type wins.

        Severity first, then the order the detections run in. An MFA fatigue
        finding and an OAuth consent finding on the same account are one
        incident, and "account_compromise" describes that story better than
        either finding alone.
        """
        return max(group, key=lambda finding: finding.base_severity).suggested_attack_type

    @staticmethod
    def _most_common(values: list[str]) -> str | None:
        if not values:
            return None
        counts: dict[str, int] = {}
        for value in values:
            counts[value] = counts.get(value, 0) + 1
        # Ties resolve alphabetically so the uid is stable across runs.
        return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]

    @staticmethod
    def _users_for(group: list[DetectionResult]) -> list[str]:
        return [value for finding in group for value in CorrelationEngine._users(finding)]

    @staticmethod
    def _ips_for(group: list[DetectionResult]) -> list[str]:
        return [value for finding in group for value in CorrelationEngine._ips(finding)]

    @staticmethod
    def _apps_for(group: list[DetectionResult]) -> list[str]:
        return [value for finding in group for value in CorrelationEngine._apps(finding)]

    @staticmethod
    def _choose_scope(
        group: list[DetectionResult],
        user_key: str | None,
        source_ip: str | None,
        application: str | None,
    ) -> tuple[str, str]:
        """Pick what the incident is *about*, as a (uid scope, human label) pair.

        A password spray is an attack on a source, not on a victim: it touches
        many accounts, so any single user would be a misleading label. MFA fatigue
        and OAuth consent are attacks on one account, so the user is right there.
        """
        users = {value for finding in group for value in CorrelationEngine._users(finding)}

        if len(users) > 1 and source_ip:
            return f"ip:{source_ip}", f"source {source_ip}"
        if user_key:
            return f"user:{user_key}", user_key
        if source_ip:
            return f"ip:{source_ip}", f"source {source_ip}"
        if application:
            return f"app:{application}", application
        return "unknown", "unknown source"

    @staticmethod
    def _make_uid(
        attack_type: AttackType,
        group: list[DetectionResult],
        scope: str,
        source_ip: str | None,
        application: str | None,
    ) -> str:
        """Identity of the incident, stable across runs.

        Built from the attack type and the chosen scope. The type is part of the
        uid so an MFA fatigue burst and a later spray against the same user are
        two incidents rather than one merged blob.
        """
        from app.database.repository import make_incident_uid

        return make_incident_uid([attack_type.value, scope])

    @staticmethod
    def _make_title(
        attack_type: AttackType,
        group: list[DetectionResult],
        scope: str,
        subject: str,
        user_key: str | None,
        source_ip: str | None,
    ) -> str:
        detections = sorted({finding.detection.value for finding in group})
        if len(detections) == 1:
            return f"{attack_type.value.replace('_', ' ').title()} detected for {subject}"
        return f"Identity attack chain for {subject}: {', '.join(detections)}"

    @staticmethod
    def _timeline_entry(event: NormalizedEvent) -> TimelineEntry:
        if event.raw_event_type.value == "audit_log":
            label = event.activity or "audit activity"
            detail = event.activity or "audit log entry"
        elif event.is_success:
            label = "Sign-in succeeded"
            detail = event.application or "sign-in"
        elif any(step.method and "authenticator" in step.method.lower() for step in event.authentication_details):
            label = "MFA challenge failed"
            detail = f"{event.application or 'sign-in'} (code {event.status_error_code})"
        else:
            label = "Sign-in failed"
            detail = f"{event.application or 'sign-in'} (code {event.status_error_code})"

        if event.outcome is EventOutcome.FAILURE and event.status_failure_reason:
            detail = f"{detail} - {event.status_failure_reason}"

        return TimelineEntry(
            timestamp=event.timestamp,
            event_id=event.event_id,
            label=label,
            detail=detail,
            outcome=event.outcome.value,
            source_ip=event.source_ip,
            raw_event_type=event.raw_event_type.value,
        )
