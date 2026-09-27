"""Geographically anomalous authentication.

Two successful sign-ins for one account imply a travel speed no commercial
flight achieves. That is a real signal and it is a weak one: IP geolocation is
approximate, VPNs and proxies place a sign-in wherever the exit node is, mobile
networks hand off between towers and countries, and corporate egress can
present a stable address for an entire office.

The finding is therefore named for what the evidence supports. The attack type
label is `impossible_travel` because that is the established name for the
technique, but nothing in this module asserts that a person travelled, or that
an account was compromised.
"""

from __future__ import annotations

from app.config import Settings
from app.detection.base import Detection, DetectionContext
from app.detection.password_spray import MAX_FINDINGS_PER_DETECTION
from app.features import haversine_km, sort_by_time, travel_speed_kmh
from app.models.decision import AttackType
from app.models.event import NormalizedEvent
from app.models.incident import DetectionName, DetectionResult


class ImpossibleTravelDetection(Detection):
    name = DetectionName.IMPOSSIBLE_TRAVEL
    title = "Geographically anomalous authentication"

    limitations = (
        "Heuristic, and the weakest of the four detectors. IP geolocation is "
        "inaccurate at the city level and occasionally at the country level. "
        "VPNs, corporate proxies and mobile network handoffs all produce "
        "anomalous-looking jumps with no attacker involved, so a false positive "
        "here is expected rather than exceptional. Geolocation is derived from "
        "the source IP only: no device, badge or network telemetry is available "
        "to corroborate it, and a NAT gateway makes many real users look like "
        "one."
    )

    def evaluate(
        self, events: list[NormalizedEvent], context: DetectionContext
    ) -> list[DetectionResult]:
        settings: Settings = context.settings

        # Only successful sign-ins establish a baseline. A failed attempt from
        # a distant country is what a spray looks like, and counting it here
        # would double-report the same activity under two attack types.
        sign_ins = [event for event in events if event.is_success and event.latitude is not None]
        if len(sign_ins) < 2:
            return [self.not_fired()]

        by_user: dict[str, list[NormalizedEvent]] = {}
        for event in sort_by_time(sign_ins):
            by_user.setdefault(event.user_key or "<unknown-user>", []).append(event)

        findings: list[DetectionResult] = []
        for user_key, user_events in sorted(by_user.items()):
            for earlier, later in zip(user_events, user_events[1:]):
                speed = travel_speed_kmh(earlier, later)
                if speed is None:
                    continue

                distance = haversine_km(
                    earlier.latitude, earlier.longitude, later.latitude, later.longitude
                )

                # Short hops are inside geolocation noise. A 5 km discrepancy
                # between two IP databases is not a detection.
                if distance < settings.impossible_travel_min_distance_km:
                    continue
                if speed <= settings.impossible_travel_speed_kmh:
                    continue

                elapsed_minutes = (later.timestamp - earlier.timestamp).total_seconds() / 60
                pair = [earlier, later]

                findings.append(
                    DetectionResult(
                        detection=self.name,
                        fired=True,
                        title=(
                            f"Geographically anomalous authentication for {user_key}: "
                            f"{earlier.city or earlier.country or 'unknown'} to "
                            f"{later.city or later.country or 'unknown'} in "
                            f"{elapsed_minutes:.0f} minutes"
                        ),
                        finding=(
                            f"{user_key} signed in from "
                            f"{earlier.city or earlier.country or 'an unknown location'} "
                            f"({earlier.source_ip}) and then "
                            f"{later.city or later.country or 'an unknown location'} "
                            f"({later.source_ip}) {elapsed_minutes:.0f} minutes later. "
                            f"The implied speed is {speed:,.0f} km/h over "
                            f"{distance:,.0f} km. No commercial flight does that. "
                            "This is a geolocation anomaly, not proof that anyone "
                            "travelled; a VPN or corporate egress would look the same."
                        ),
                        signal={
                            "user": user_key,
                            "from": {
                                "city": earlier.city,
                                "country": earlier.country,
                                "ip": earlier.source_ip,
                                "at": earlier.timestamp.isoformat(),
                            },
                            "to": {
                                "city": later.city,
                                "country": later.country,
                                "ip": later.source_ip,
                                "at": later.timestamp.isoformat(),
                            },
                            "distance_km": round(distance, 1),
                            "implied_speed_kmh": round(speed, 1),
                            "elapsed_minutes": round(elapsed_minutes, 1),
                        },
                        evidence={
                            "implied_speed_kmh": round(speed, 1),
                            "speed_threshold_kmh": settings.impossible_travel_speed_kmh,
                            "distance_km": round(distance, 1),
                            "min_distance_km": settings.impossible_travel_min_distance_km,
                        },
                        limitations=self.limitations,
                        event_ids=[e.event_id for e in pair],
                        events=pair,
                        suggested_attack_type=AttackType.IMPOSSIBLE_TRAVEL,
                        # Left moderate on purpose. This rule is the most
                        # false-positive-prone of the four, and a detector that
                        # cries wolf trains analysts to ignore it.
                        base_severity=4,
                        dedupe_key=f"impossible_travel:{user_key}:{earlier.event_id}",
                    )
                )

                if len(findings) >= MAX_FINDINGS_PER_DETECTION:
                    return findings

        if not findings:
            return [self.not_fired()]
        return findings
