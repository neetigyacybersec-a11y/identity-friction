"""MFA fatigue detection.

The pattern is repeated second-factor failures against one account, followed by
a success. The success is what makes the finding interesting: a user fumbling
their own authenticator eventually succeeds on their own, usually within a
minute or two. Four denials spread over minutes and then an acceptance, from a
device the account does not normally use, reads as someone who was not the user
and who was willing to keep pushing notifications at them.

The detection is defensive. It reads telemetry that already exists in a tenant;
it generates no notifications, sends no push, and contacts no user.
"""

from __future__ import annotations

from datetime import timedelta

from app.config import Settings
from app.detection.base import Detection, DetectionContext
from app.detection.password_spray import MAX_FINDINGS_PER_DETECTION
from app.features import is_mfa_failure, sliding_windows
from app.models.decision import AttackType
from app.models.event import NormalizedEvent
from app.models.incident import DetectionName, DetectionResult


class MfaFatigueDetection(Detection):
    name = DetectionName.MFA_FATIGUE
    title = "MFA fatigue"

    limitations = (
        "Heuristic. A genuine user who has lost a phone, or who is travelling "
        "with no signal, produces the same denials and then a success. The rule "
        "does not know the difference, and does not attempt to: the device and "
        "source IP comparisons it reports are context for a human, not "
        "conclusions. The detection also only fires when a success follows, so "
        "a patient attacker who never gets the push accepted is not detected "
        "here."
    )

    def evaluate(
        self, events: list[NormalizedEvent], context: DetectionContext
    ) -> list[DetectionResult]:
        settings: Settings = context.settings

        mfa_failures = [
            event for event in events if is_mfa_failure(event, settings.mfa_denial_error_codes)
        ]
        if not mfa_failures:
            return [self.not_fired()]

        findings: list[DetectionResult] = []
        for start, end, window_events in sliding_windows(
            mfa_failures, minutes=settings.mfa_window_minutes
        ):
            if len(window_events) < settings.mfa_failure_threshold:
                continue

            # Group by account. Fatigue targets one person at a time; spraying
            # a second factor across many accounts is a different attack.
            by_user: dict[str, list[NormalizedEvent]] = {}
            for event in window_events:
                by_user.setdefault(event.user_key or "<unknown-user>", []).append(event)

            for user_key, user_events in sorted(by_user.items()):
                if len(user_events) < settings.mfa_failure_threshold:
                    continue

                latest_denial = max(event.timestamp for event in user_events)
                success_deadline = latest_denial + timedelta(
                    minutes=settings.mfa_success_lookahead_minutes
                )

                # The success has to be the same user, after the denials.
                following_successes = [
                    event
                    for event in events
                    if event.is_success
                    and event.user_key == user_key
                    and latest_denial < event.timestamp <= success_deadline
                ]
                if not following_successes:
                    continue

                success = min(following_successes, key=lambda event: event.timestamp)
                timeline_events = sorted(
                    [*user_events, success], key=lambda event: event.timestamp
                )
                source_ips = sorted(
                    {e.source_ip for e in timeline_events if e.source_ip}
                )
                devices = sorted({e.device for e in timeline_events if e.device})

                findings.append(
                    DetectionResult(
                        detection=self.name,
                        fired=True,
                        title=(
                            f"MFA fatigue against {user_key}: "
                            f"{len(user_events)} denials then an accepted challenge"
                        ),
                        finding=(
                            f"{len(user_events)} MFA failures for {user_key} between "
                            f"{start.strftime('%H:%M')} and "
                            f"{latest_denial.strftime('%H:%M')}, then a successful sign-in "
                            f"at {success.timestamp.strftime('%H:%M')} from "
                            f"{', '.join(source_ips) or 'an unknown source'}. The pattern "
                            "stopped on acceptance, which is the part that separates this "
                            "from a user struggling with their own second factor."
                        ),
                        signal={
                            "user": user_key,
                            "mfa_failures": len(user_events),
                            "success_at": success.timestamp.isoformat(),
                            "source_ips": source_ips,
                            "devices": devices,
                            "mfa_error_codes": sorted(
                                {
                                    e.status_error_code
                                    for e in user_events
                                    if e.status_error_code is not None
                                }
                            ),
                        },
                        evidence={
                            "failures": len(user_events),
                            "failure_threshold": settings.mfa_failure_threshold,
                            "window_minutes": settings.mfa_window_minutes,
                            "success_within_minutes": settings.mfa_success_lookahead_minutes,
                        },
                        limitations=self.limitations,
                        event_ids=[e.event_id for e in timeline_events],
                        events=timeline_events,
                        suggested_attack_type=AttackType.ACCOUNT_COMPROMISE,
                        base_severity=8,
                        dedupe_key=f"mfa_fatigue:{user_key}",
                    )
                )

                if len(findings) >= MAX_FINDINGS_PER_DETECTION:
                    return findings

        if not findings:
            return [self.not_fired()]
        return findings
