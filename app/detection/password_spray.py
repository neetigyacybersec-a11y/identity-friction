"""Password spray detection.

A spray tries one or two common passwords against many accounts, so no single
account looks attacked while the source IP looks busy. The rule therefore counts
across accounts grouped by source IP, over a sliding window, and fires when both
a failure count and a distinct-user count clear their thresholds.

The distinct-user requirement is what separates a spray from a single locked
account and from credential stuffing against one known username.
"""

from __future__ import annotations

from app.config import Settings
from app.detection.base import Detection, DetectionContext
from app.features import is_invalid_credentials, sliding_windows, window_stats
from app.models.event import NormalizedEvent
from app.models.incident import DetectionName, DetectionResult
from app.models.decision import AttackType

# The maximum number of findings one ingest may produce. Without a cap, a large
# live collection with a busy NAT gateway could emit thousands of near-identical
# findings and make the incident list unusable.
MAX_FINDINGS_PER_DETECTION = 20


class PasswordSprayDetection(Detection):
    name = DetectionName.PASSWORD_SPRAY
    title = "Password spray"

    limitations = (
        "Heuristic. IP geolocation and shared egress mean one IP is not one "
        "attacker, and a corporate proxy or VPN can concentrate a whole "
        "office behind a single address, which produces this signal harmlessly. "
        "A spray that rotates IPs, or that stays under the failure threshold, "
        "is invisible here. Thresholds are tuned for demo-scale volumes and "
        "would need recalibrating against real tenant baselines before use."
    )

    def evaluate(
        self, events: list[NormalizedEvent], context: DetectionContext
    ) -> list[DetectionResult]:
        settings: Settings = context.settings
        invalid_codes = settings.invalid_credentials_error_codes

        # Only credential rejections define the spray. A second-factor failure
        # is a different attack and belongs to the MFA fatigue rule.
        failures = [
            event for event in events if is_invalid_credentials(event, invalid_codes)
        ]
        if not failures:
            return [self.not_fired()]

        successes_by_ip = _successes_by_ip(events)

        findings: list[DetectionResult] = []
        for start, end, window_events in sliding_windows(
            failures, minutes=settings.spray_window_minutes
        ):
            stats = window_stats(window_events, start, end)

            if stats.failures < settings.spray_failed_login_threshold:
                continue
            if stats.unique_users < settings.spray_unique_user_threshold:
                continue

            # One finding per source IP inside the window, so a busy attacker
            # does not produce a separate finding for every user they touched.
            for source_ip in sorted(stats.by_ip):
                ip_failures = [e for e in window_events if e.source_ip == source_ip]
                if not ip_failures:
                    continue

                # Did the spray get in anywhere? A success from the spray's own
                # source inside the same window turns "noisy" into "a foothold
                # exists", and is what justifies calling this a compromise
                # rather than a spray.
                #
                # The successes are looked up in the full event list rather than
                # in the window, because a success is not a credential rejection
                # and so was never in the window to begin with. Both are reported
                # because the success is evidence for the same incident.
                successes = [
                    event
                    for event in successes_by_ip.get(source_ip, [])
                    if start <= event.timestamp <= end
                ]
                evidence_events = [*ip_failures, *successes]
                succeeded = bool(successes)
                affected_users = sorted({e.user_key for e in evidence_events if e.user_key})
                failed_accounts = sorted({e.user_key for e in ip_failures if e.user_key})
                succeeded_accounts = sorted({e.user_key for e in successes if e.user_key})

                findings.append(
                    DetectionResult(
                        detection=self.name,
                        fired=True,
                        title=(
                            f"Password spray from {source_ip}: "
                            f"{len(ip_failures)} failures against {len(affected_users)} accounts"
                        ),
                        finding=(
                            f"Source {source_ip} produced {len(ip_failures)} failed "
                            f"sign-ins across {len(affected_users)} distinct accounts in "
                            f"{settings.spray_window_minutes} minutes. "
                            + (
                                f"A sign-in from this source succeeded for "
                                f"{', '.join(succeeded_accounts)} in the same window."
                                if succeeded
                                else "No sign-in from this source succeeded."
                            )
                        ),
                        signal={
                            "source_ip": source_ip,
                            "window_start": start.isoformat(),
                            "window_end": end.isoformat(),
                            "accounts_failed": len(failed_accounts),
                            "accounts_targeted": affected_users,
                            "successful_sign_ins_from_source": len(successes),
                            "accounts_succeeded": succeeded_accounts,
                        },
                        evidence={
                            "failed_sign_ins": len(ip_failures),
                            "failure_threshold": settings.spray_failed_login_threshold,
                            "unique_users": len(affected_users),
                            "unique_user_threshold": settings.spray_unique_user_threshold,
                            "window_minutes": settings.spray_window_minutes,
                        },
                        limitations=self.limitations,
                        event_ids=[e.event_id for e in evidence_events],
                        events=evidence_events,
                        suggested_attack_type=(
                            AttackType.ACCOUNT_COMPROMISE
                            if succeeded
                            else AttackType.PASSWORD_SPRAY
                        ),
                        base_severity=8 if succeeded else 6,
                        dedupe_key=f"password_spray:{source_ip}",
                    )
                )

                if len(findings) >= MAX_FINDINGS_PER_DETECTION:
                    return findings

        if not findings:
            return [self.not_fired()]
        return findings


def _successes_by_ip(events: list[NormalizedEvent]) -> dict[str, list[NormalizedEvent]]:
    """Successful sign-ins grouped by source IP.

    Grouped once up front because the sliding-window loop runs many times over
    the same list, and a linear scan per window would be wasteful.
    """
    grouped: dict[str, list[NormalizedEvent]] = {}
    for event in events:
        if event.is_success and event.source_ip:
            grouped.setdefault(event.source_ip, []).append(event)
    return grouped
