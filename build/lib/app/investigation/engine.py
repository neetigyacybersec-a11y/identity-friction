"""System Two: the investigation layer.

JEV (System One) answers fast: is this suspicious, how bad, escalate or not.
System Two is the slow half — it reads the full incident and writes the thing an
analyst actually reads: what happened, the evidence for it, what to check next,
and what could not be seen.

Different model, different job. System One routes. System Two explains.

Two rules this module enforces:

1. **The model never sees raw telemetry.** It sees the same summarised timeline
   the analyst sees. Raw event payloads invite conclusions the deterministic
   path cannot reproduce.
2. **It degrades.** No API key, a timeout, a malformed reply: the incident keeps
   its decision and is marked as not investigated. It never blocks the pipeline
   and never leaves a half-written report looking authoritative.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

from app.config import Settings, get_settings
from app.models.decision import Decision
from app.models.incident import Incident
from app.models.investigation import InvestigationReport

logger = logging.getLogger(__name__)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
REQUEST_TIMEOUT_SECONDS = 60.0
MAX_ATTEMPTS = 2
RETRY_BACKOFF_SECONDS = 2.0

# The report has to arrive inside a person's attention span. Waiting longer for a
# better paragraph is a bad trade against a dashboard that feels broken.
MAX_REPORT_CHARS = 8000

EXPECTED_KEYS = {
    "summary",
    "evidence",
    "attack_hypothesis",
    "mitre_techniques",
    "investigation_steps",
    "recommended_actions",
    "limitations",
}


class InvestigationUnavailable(RuntimeError):
    """No report could be produced. The caller records the incident as
    uninvestigated and moves on."""


class InvestigationEngine:
    """Writes an investigation report for one incident."""

    def __init__(
        self,
        settings: Settings | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client

    def describe(self) -> str:
        return f"InvestigationEngine ({self._settings.llm_model_name})"

    def investigate(
        self, incident: Incident, decision: Decision | None = None
    ) -> InvestigationReport:
        if not self._settings.openrouter_configured:
            raise InvestigationUnavailable("no OpenRouter API key configured")

        raw = self._call(self._build_payload(incident, decision))
        return self._parse(raw, incident)

    # -- transport -------------------------------------------------------

    def _call(self, payload: dict[str, Any]) -> dict[str, Any]:
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
                logger.warning("investigation call failed (attempt %s): %s", attempt, error)
            else:
                if response.status_code == 200:
                    return _extract_content(response.json())
                last_error = InvestigationUnavailable(
                    f"OpenRouter returned HTTP {response.status_code}"
                )
                if response.status_code not in (429, 500, 502, 503, 504):
                    raise last_error

            if attempt < MAX_ATTEMPTS:
                time.sleep(RETRY_BACKOFF_SECONDS)

        raise InvestigationUnavailable(
            f"investigation call failed after {MAX_ATTEMPTS} attempts: {last_error}"
        )

    # -- prompt and parsing ----------------------------------------------

    def _build_payload(
        self, incident: Incident, decision: Decision | None
    ) -> dict[str, Any]:
        return {
            "model": self._settings.llm_model_name,
            # 0.0 because a security report should not vary between reads of the
            # same evidence. Creative variation is not a feature here.
            "temperature": self._settings.llm_temperature,
            "max_tokens": self._settings.llm_max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
                        _brief(incident, decision), indent=2, sort_keys=True
                    ),
                },
            ],
        }

    def _parse(self, raw: dict[str, Any], incident: Incident) -> InvestigationReport:
        content = raw.get("content", "")
        parsed = _loads_json_object(content)

        missing = EXPECTED_KEYS - set(parsed)
        if missing:
            raise InvestigationUnavailable(f"report missing keys: {sorted(missing)}")

        report = InvestigationReport(
            summary=_as_text(parsed["summary"]),
            evidence=_as_text_list(parsed["evidence"]),
            attack_hypothesis=_as_text(parsed["attack_hypothesis"]),
            mitre_techniques=_as_text_list(parsed["mitre_techniques"]),
            investigation_steps=_as_text_list(parsed["investigation_steps"]),
            recommended_actions=_as_text_list(parsed["recommended_actions"]),
            limitations=_as_text_list(parsed["limitations"]),
        )

        # The detector's own limitations are facts about the telemetry, not
        # opinions from a model. They are appended so they cannot be dropped by
        # a reply that forgot them, and kept as whole sentences.
        # Prepended as a block, so the detector's own caveats lead in their
        # original order and the model's additions follow.
        detector_limitations = [
            sentence
            for sentence in _split_sentences(incident.limitations)
            if sentence not in report.limitations
        ]
        report.limitations = [*detector_limitations, *report.limitations]

        return report


# -- prompt -----------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior identity security analyst writing a case note for another \
analyst who has not seen this evidence before.

You will receive a detected signal, the decision made about it, and an ordered \
timeline. Write the investigation report as a single JSON object with exactly \
these keys:

  "summary"               two or three sentences: what the evidence shows
  "evidence"              list of specific facts from the timeline, each citing \
                          a timestamp or an event
  "attack_hypothesis"     the most likely explanation, stated as a hypothesis
  "mitre_techniques"      list of MITRE ATT&CK technique IDs and names, only \
                          ones the evidence genuinely supports
  "investigation_steps"   what the analyst should check next, as concrete steps
  "recommended_actions"   suggested response actions, ordered by priority
  "limitations"           what this evidence cannot show

The rules that matter most:

- This is a detected signal, not a confirmed attack. Write "consistent with" \
  and "suggests". Never state that an attack occurred as fact.
- Every claim in "evidence" must be traceable to something in the timeline. \
  Do not invent events, timestamps, user agents or IP addresses.
- "limitations" is mandatory and must be specific to this case. A generic \
  disclaimer is worth nothing. Name what telemetry is missing and what would \
  change the conclusion.
- If the evidence is thin, say so. A short honest report beats a long confident \
  one that an analyst has to unpick.
- Recommend actions; do not take any. Nothing here executes anything."""


def _brief(incident: Incident, decision: Decision | None) -> dict[str, Any]:
    """Everything the model is given, and nothing more.

    The decision is included so the report can agree with or explicitly question
    the routing decision. Raw event payloads are excluded: they are large, and a
    model reasoning from fields no rule in the project checks produces findings
    nobody can reproduce.
    """
    brief: dict[str, Any] = {
        "detected_signal": {
            "title": incident.title,
            "attack_type": incident.attack_type.value,
            "severity_from_detection": incident.severity,
            "detections_fired": incident.signal_summary.get("detections", []),
            "detection_evidence": incident.signal_summary.get("detail", {}),
            "detector_limitations": incident.limitations,
        },
        "incident": {
            "subject": incident.subject or incident.user_key or incident.source_ip,
            "user": incident.user_key,
            "source_ip": incident.source_ip,
            "application": incident.application,
            "first_seen": incident.first_seen.isoformat(),
            "last_seen": incident.last_seen.isoformat(),
            "event_count": incident.event_count,
        },
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
    }

    if decision is not None:
        brief["decision"] = {
            "suspicious": decision.suspicious,
            "suspicion_score": decision.suspicion_score,
            "attack_type": decision.attack_type.value,
            "severity": decision.severity,
            "escalate": decision.escalate,
            "confidence": decision.confidence,
            "confidence_band": decision.band.value,
            "decided_by": decision.source.value,
            "reasoning": decision.reasoning,
        }

    return brief


# -- defensive parsing ------------------------------------------------------


def _extract_content(body: dict[str, Any]) -> dict[str, Any]:
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as error:
        raise InvestigationUnavailable(
            f"unexpected OpenRouter response shape: {error}"
        ) from error

    if not isinstance(content, str) or not content.strip():
        raise InvestigationUnavailable("OpenRouter returned empty content")
    return {"content": content}


def _loads_json_object(content: str) -> dict[str, Any]:
    """Parse the report, tolerating a code fence around it."""
    text = content.strip()
    if text.startswith("```"):
        text = text.split("```")[1] if "```" in text[3:] else text[3:]
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise InvestigationUnavailable(f"report was not valid JSON: {error}") from error

    if not isinstance(parsed, dict):
        raise InvestigationUnavailable(
            f"report was {type(parsed).__name__}, expected a JSON object"
        )
    return parsed


def _split_sentences(text: str) -> list[str]:
    """Split prose into sentences, keeping the full stop.

    A naive split on ". " breaks abbreviations and leaves fragments like
    "Heuristic" as if it were a limitation in its own right. This also skips the
    abbreviations that actually show up in detection prose, so "e.g. and" does
    not become a sentence boundary.
    """
    if not text:
        return []

    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z(])", text.strip())
    return [part.strip() for part in parts if part.strip()]


def _as_text(value: Any) -> str:
    """Coerce a field to text.

    A model asked for a string sometimes returns a list or an object. Joining it
    is better than discarding a report over a formatting slip.
    """
    if isinstance(value, str):
        return value.strip()[:MAX_REPORT_CHARS]
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)[:MAX_REPORT_CHARS]
    if isinstance(value, dict):
        return json.dumps(value)[:MAX_REPORT_CHARS]
    return str(value)[:MAX_REPORT_CHARS]


def _as_text_list(value: Any) -> list[str]:
    """Coerce a field to a list of strings.

    A single string where a list was asked for is the common case and is treated
    as a one-item list rather than dropped.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value)]
