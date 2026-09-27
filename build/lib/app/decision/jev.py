"""JEV over OpenRouter.

TypeSafe's JEV is System One: unstructured state in, typed probabilistic
decision out. This project reaches it as `typesafe/jev-router` on OpenRouter
rather than through the native `typesafe-sdk`, because early-access API access
was not available. See docs/adr/0001-jev-behind-decision-engine-interface.md.

What that costs, stated plainly:

* **No schema guarantee.** The native API returns a validated typed decision.
  OpenRouter returns text in JSON mode, so this adapter parses defensively and
  treats every field as suspect.
* **No calibrated confidence.** JEV's own confidence is not comparable across
  backends. The model-reported number is kept as `raw_response` for the record,
  and the band this project acts on is computed from `suspicion_score` instead.

Everything here is confined to this file. Detectors never import it, and the
`DecisionEngine` interface never mentions it.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

from app.config import Settings, get_settings
from app.decision.engine import DecisionEngine, DecisionRequest, DecisionUnavailable
from app.models.decision import (
    AttackType,
    ConfidenceBand,
    Decision,
    DecisionSource,
)

logger = logging.getLogger(__name__)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# A decision is not worth a long wait. The user is waiting on a dashboard, and a
# slow model that eventually answers is a slower system than a fast one that
# falls back to rules.
REQUEST_TIMEOUT_SECONDS = 20.0
MAX_ATTEMPTS = 2
RETRY_BACKOFF_SECONDS = 1.0

# The prompt asks for exactly these keys and nothing else. A narrow contract is
# what makes defensive parsing tractable.
EXPECTED_KEYS = {
    "suspicious",
    "suspicion_score",
    "attack_type",
    "severity",
    "escalate",
    "confidence",
    "reasoning",
}


class JevDecisionEngine(DecisionEngine):
    """Calls JEV through OpenRouter and maps the reply onto `Decision`."""

    def __init__(
        self,
        settings: Settings | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client

    def describe(self) -> str:
        return f"JevDecisionEngine (OpenRouter, {self._settings.jev_model_name})"

    def decide(self, request: DecisionRequest) -> Decision:
        if not self._settings.openrouter_configured:
            raise DecisionUnavailable("no OpenRouter API key configured")

        payload = self._build_payload(request)
        raw = self._call(payload)
        return self._parse(raw, request)

    # -- transport -------------------------------------------------------

    def _call(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST to OpenRouter, retrying once on a transient failure.

        A 429 or a 5xx is worth one retry. A 401 or a 400 is not, and neither is
        a malformed reply, so those go straight to the fallback.
        """
        headers = {
            "Authorization": f"Bearer {self._settings.openrouter_api_key}",
            "Content-Type": "application/json",
        }
        client = self._client or httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS)

        last_error: Exception | None = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = client.post(OPENROUTER_URL, headers=headers, json=payload)
            except httpx.HTTPError as error:
                last_error = error
                logger.warning("JEV call failed (attempt %s): %s", attempt, error)
            else:
                if response.status_code == 200:
                    return self._extract(response.json())
                last_error = JevResponseError(
                    f"OpenRouter returned HTTP {response.status_code}"
                )
                if response.status_code not in (429, 500, 502, 503, 504):
                    raise DecisionUnavailable(str(last_error))
                logger.warning("JEV call returned HTTP %s", response.status_code)

            if attempt < MAX_ATTEMPTS:
                time.sleep(RETRY_BACKOFF_SECONDS)

        raise DecisionUnavailable(f"JEV call failed after {MAX_ATTEMPTS} attempts: {last_error}")

    @staticmethod
    def _extract(body: dict[str, Any]) -> dict[str, Any]:
        """Pull the assistant's message out of the OpenRouter envelope.

        The envelope has changed shape before and may again, so every level is
        checked rather than indexed.
        """
        try:
            choices = body["choices"]
            message = choices[0]["message"]
            content = message["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise JevResponseError(
                f"unexpected OpenRouter response shape: {error}"
            ) from error

        if not isinstance(content, str) or not content.strip():
            raise JevResponseError("OpenRouter returned empty content")

        return {"content": content}

    # -- prompt and parsing ----------------------------------------------

    def _build_payload(self, request: DecisionRequest) -> dict[str, Any]:
        return {
            "model": self._settings.jev_model_name,
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": _SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        _summarise(request), indent=2, sort_keys=True
                    ),
                },
            ],
        }

    def _parse(
        self, raw: dict[str, Any], request: DecisionRequest
    ) -> Decision:
        """Turn the model's text into a validated `Decision`.

        Every step can fail independently, and each failure has to be visible.
        A model that returns prose instead of JSON, or a severity of 47, must
        fall back to rules rather than crash the pipeline or be trusted blindly.
        """
        content = raw.get("content", "")
        parsed = _loads_json_object(content)

        missing = EXPECTED_KEYS - set(parsed)
        if missing:
            raise JevResponseError(f"response missing keys: {sorted(missing)}")

        suspicious = _as_bool(parsed["suspicious"])
        suspicion_score = _as_float(parsed["suspicion_score"], "suspicion_score")
        severity = _as_int(parsed["severity"], "severity", low=1, high=10)
        escalate = _as_bool(parsed["escalate"])
        attack_type = _as_attack_type(parsed["attack_type"])
        reasoning = str(parsed["reasoning"])[:2000]

        decision = Decision(
            suspicious=suspicious,
            suspicion_score=suspicion_score,
            attack_type=attack_type,
            severity=severity,
            escalate=escalate,
            # Always true. This system recommends, it does not act, and an
            # analyst looks at every incident regardless of what the model says.
            needs_analyst_review=True,
            # The model's self-reported confidence is advisory. The band is
            # computed from suspicion_score below, which is at least a value the
            # model had to commit to numerically.
            confidence=suspicion_score,
            source=DecisionSource.JEV,
            reasoning=reasoning,
            raw_response={
                "model": self._settings.jev_model_name,
                "content": content,
                "model_reported_confidence": parsed["confidence"],
            },
        )

        # Band from the configured thresholds, which is the number this project
        # actually routes on.
        decision.recompute_band(
            self._settings.jev_high_confidence, self._settings.jev_medium_confidence
        )
        return decision


class JevResponseError(DecisionUnavailable):
    """The reply was not a usable decision. Callers fall back to rules.

    Subclasses `DecisionUnavailable` so the pipeline treats a malformed reply the
    same as an unreachable backend: the incident survives, the rules answer, and
    the incident records that the model layer failed.
    """


# -- prompt -----------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a security analyst judging one identity incident from Microsoft Entra \
ID sign-in and audit logs.

Respond with a single JSON object and no other text. Use exactly these keys:

  "suspicious"      boolean
  "suspicion_score" number between 0 and 1
  "attack_type"     one of: benign, password_spray, mfa_fatigue,
                    impossible_travel, oauth_abuse, account_compromise, unknown
  "severity"        integer from 1 to 10
  "escalate"        boolean
  "confidence"      number between 0 and 1
  "reasoning"       two or three sentences, no more

Judge only from the evidence given. You are assessing a signal, not confirming \
an attack: a detection firing means telemetry matched a pattern, which is not \
proof that anyone acted maliciously. If the evidence is thin, say so and score \
it low. Prefer "unknown" over guessing an attack type the evidence does not \
support."""


def _summarise(request: DecisionRequest) -> dict[str, Any]:
    """The incident as the model sees it.

    The same ordered timeline the analyst sees, plus the detection evidence.
    Raw event payloads are deliberately excluded: they are large, they contain
    fields no rule in this project uses, and a model reasoning from them
    produces conclusions the detection path cannot reproduce or defend.
    """
    incident = request.incident
    return {
        "incident": {
            "attack_type": incident.attack_type.value,
            "severity_from_detection": incident.severity,
            "user": incident.user_key,
            "source_ip": incident.source_ip,
            "application": incident.application,
            "first_seen": incident.first_seen.isoformat(),
            "last_seen": incident.last_seen.isoformat(),
            "event_count": incident.event_count,
        },
        "detections": incident.signal_summary.get("detections", []),
        "detection_evidence": incident.signal_summary.get("detail", {}),
        "timeline": [
            {
                "timestamp": entry.timestamp.isoformat(),
                "event": entry.label,
                "detail": entry.detail,
                "outcome": entry.outcome,
                "source_ip": entry.source_ip,
            }
            for entry in incident.timeline
        ],
        "known_limitations": incident.limitations,
    }


# -- defensive parsing ------------------------------------------------------


def _loads_json_object(content: str) -> dict[str, Any]:
    """Parse the model's reply, tolerating a code fence around it.

    Models wrap JSON in ```json fences often enough that ignoring that case
    would mean a pointless failure rate.
    """
    text = content.strip()
    if text.startswith("```"):
        text = text.split("```")[1] if "```" in text[3:] else text[3:]
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise JevResponseError(f"response was not valid JSON: {error}") from error

    if not isinstance(parsed, dict):
        raise JevResponseError(
            f"response was {type(parsed).__name__}, expected a JSON object"
        )
    return parsed


def _as_bool(value: Any) -> bool:
    """Accept the several shapes a model uses for a boolean.

    Rejecting "yes" outright would discard a usable answer; accepting an
    arbitrary string as truthy would accept "no" too.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    raise JevResponseError(f"could not read {value!r} as a boolean")


def _as_float(value: Any, name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise JevResponseError(f"{name} was {value!r}, not a number") from error
    if not 0.0 <= number <= 1.0:
        raise JevResponseError(f"{name} was {number}, outside 0..1")
    return number


def _as_int(value: Any, name: str, low: int, high: int) -> int:
    """Clamp rather than reject, for integers with a stated range.

    A severity of 12 is a model that disagrees with the taxonomy, not a
    transport failure. Clamping keeps the signal and the caller sees the
    disagreement; raising would throw away a decision that was otherwise sound.
    """
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError) as error:
        raise JevResponseError(f"{name} was {value!r}, not a number") from error
    return max(low, min(high, number))


def _as_attack_type(value: Any) -> AttackType:
    """Map a model reply onto the closed taxonomy, or UNKNOWN.

    An unrecognised type becomes UNKNOWN rather than an error: the rest of the
    decision may still be usable, and UNKNOWN is an honest label for a taxonomy
    the model does not share.
    """
    if isinstance(value, str):
        normalised = value.strip().lower().replace(" ", "_").replace("-", "_")
        for attack_type in AttackType:
            if attack_type.value == normalised:
                return attack_type
    logger.warning("unrecognised attack_type %r; treating as unknown", value)
    return AttackType.UNKNOWN
