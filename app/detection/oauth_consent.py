"""Suspicious OAuth consent.

A tenant audit log records consent grants, delegated permission grants and role
assignments. Each of those is also what ordinary admin work looks like. A wide
set of mail and file permissions granted to an unfamiliar application, minutes
after an account authenticated somewhere unusual, is worth an analyst's time.
The grant itself is not evidence of malice, and this module does not claim it is.

Sources, both verified against current Microsoft documentation:

* Endpoint `GET /v1.0/auditLogs/directoryAudits`, least-privileged application
  permission `AuditLog.Read.All`.
* Activity names from the Entra audit activity reference: audit category
  `ApplicationManagement` with activities `Consent to application`,
  `Add delegated permission grant`, `Add member to role`, and the eligible and
  scoped variants.
"""

from __future__ import annotations

from app.config import Settings
from app.detection.base import Detection, DetectionContext
from app.models.decision import AttackType
from app.models.event import NormalizedEvent
from app.models.incident import DetectionName, DetectionResult

# A grant carrying this many of the configured sensitive scopes is worth
# attention on its own. Below it, the grant is still reported, just at a lower
# severity, because a consent event is a normal thing to find in a real tenant.
MANY_SENSITIVE_SCOPES = 2


class OAuthConsentDetection(Detection):
    name = DetectionName.OAUTH_CONSENT
    title = "Suspicious OAuth consent"

    limitations = (
        "Signal, not accusation. A consent grant is indistinguishable from a "
        "sanctioned integration, and this rule has no allow-list of approved "
        "applications to compare against, so it cannot tell the two apart. The "
        "sensitive-scope list is a static judgement about broadly-powerful "
        "permissions, not a tenant-specific baseline, and it will need tuning. "
        "Coverage depends entirely on the tenant: directory audit logs are "
        "licence- and configuration-dependent, and tenant audit logging may "
        "simply be off, in which case this detector sees nothing and reports "
        "no findings. A clean result here means 'no evidence', never 'no risk'."
    )

    def evaluate(
        self, events: list[NormalizedEvent], context: DetectionContext
    ) -> list[DetectionResult]:
        settings: Settings = context.settings
        wanted = {name.lower() for name in settings.oauth_suspicious_activities}
        sensitive = {scope.lower() for scope in settings.oauth_sensitive_scopes}

        audit_events = [event for event in events if event.activity is not None]
        if not audit_events:
            return [self.not_fired()]

        findings: list[DetectionResult] = []
        for event in audit_events:
            if (event.activity or "").lower() not in wanted:
                continue

            granted = [scope for scope in event.granted_scopes if scope.lower() in sensitive]
            is_role_assignment = "role" in (event.activity or "").lower()
            target = self._target_name(event)

            if is_role_assignment:
                significance = "role assignment"
            elif len(granted) >= MANY_SENSITIVE_SCOPES:
                significance = f"{len(granted)} broadly-powerful permissions"
            else:
                significance = "consent grant"

            severity = 7 if is_role_assignment else (6 if granted else 3)

            findings.append(
                DetectionResult(
                    detection=self.name,
                    fired=True,
                    title=(
                        f"{significance.capitalize()} for {target or 'an application'} "
                        f"by {event.user_principal_name or 'an unknown actor'}"
                    ),
                    finding=(
                        f"Audit activity '{event.activity}' was recorded for "
                        f"{target or 'an application'}"
                        + (f" by {event.user_principal_name}" if event.user_principal_name else "")
                        + ". "
                        + (
                            f"It carried {len(granted)} broadly-powerful permissions: "
                            f"{', '.join(granted)}."
                            if granted
                            else "No broadly-powerful permissions were recorded with this grant."
                        )
                        + " A permission grant is not evidence of a malicious application; "
                        "it is also what a legitimate integration looks like."
                    ),
                    signal={
                        "activity": event.activity,
                        "category": event.audit_category,
                        "actor": event.user_principal_name,
                        "target": target,
                        "granted_scopes": event.granted_scopes,
                        "sensitive_scopes": granted,
                        "is_role_assignment": is_role_assignment,
                        "at": event.timestamp.isoformat(),
                    },
                    evidence={
                        "activity": event.activity,
                        "granted_scope_count": len(event.granted_scopes),
                        "sensitive_scope_count": len(granted),
                        "many_sensitive_scopes_threshold": MANY_SENSITIVE_SCOPES,
                    },
                    limitations=self.limitations,
                    event_ids=[event.event_id],
                    events=[event],
                    suggested_attack_type=AttackType.OAUTH_ABUSE,
                    base_severity=severity,
                    dedupe_key=f"oauth_consent:{event.event_id}",
                )
            )

        if not findings:
            return [self.not_fired()]
        return findings

    @staticmethod
    def _target_name(event: NormalizedEvent) -> str | None:
        for resource in event.target_resources:
            name = resource.get("displayName")
            if isinstance(name, str) and name:
                return name
        return None
