"""SQLite persistence.

Hand-written SQL over the standard library's sqlite3 module. No ORM, no session,
no migration tool. See docs/adr/0003-raw-sqlite-over-sqlalchemy.md.

Two conventions worth stating once:

* Every method opens, uses and closes its own connection. At this scale SQLite
  does not care, and it keeps each method independently testable with no shared
  state to tear down.
* `sqlite3.Row` is returned everywhere, which gives dict-like access without
  inventing a row class.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from app.models.decision import (
    AttackType,
    ConfidenceBand,
    Decision,
    DecisionSource,
)
from app.models.event import DataOrigin, NormalizedEvent
from app.models.incident import DetectionResult, Incident, IncidentStatus

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


class Repository:
    """All database access lives here."""

    def __init__(self, database_path: Path | str) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialise()

    # -- connection ------------------------------------------------------

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        # Foreign keys are off by default in SQLite and must be enabled per
        # connection. Without this the ON DELETE CASCADE clauses in schema.sql
        # silently do nothing.
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialise(self) -> None:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        with self.connect() as connection:
            connection.executescript(schema)
        logger.info("database ready at %s", self.database_path)

    # -- events ----------------------------------------------------------

    def upsert_events(self, events: Iterable[NormalizedEvent]) -> int:
        """Insert events, ignoring ones already stored. Returns rows added.

        Re-running the same demo file must not double the event count, so
        `event_id` carries a UNIQUE constraint and re-inserts are ignored.
        """
        added = 0
        with self.connect() as connection:
            for event in events:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO events (
                        event_id, timestamp, raw_event_type, data_origin,
                        user_id, user_principal_name, source_ip,
                        country, city, latitude, longitude,
                        application, device, outcome, status_error_code,
                        activity, raw_json
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        event.event_id,
                        event.timestamp.isoformat(),
                        event.raw_event_type.value,
                        event.data_origin.value,
                        event.user_id,
                        event.user_principal_name,
                        event.source_ip,
                        event.country,
                        event.city,
                        event.latitude,
                        event.longitude,
                        event.application,
                        event.device,
                        event.outcome.value,
                        event.status_error_code,
                        event.activity,
                        json.dumps(event.raw),
                    ),
                )
                added += cursor.rowcount
        return added

    def count_events(self) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    def get_events(
        self,
        limit: int = 100,
        data_origin: DataOrigin | None = None,
    ) -> list[dict[str, Any]]:
        """Most recent events first, optionally filtered by origin.

        The origin filter is what the dashboard uses to show live-tenant data
        and synthetic data separately. Mixing them in one list without a badge
        is how a demo gets mistaken for a real finding.
        """
        query = "SELECT * FROM events"
        params: list[Any] = []
        if data_origin is not None:
            query += " WHERE data_origin = ?"
            params.append(data_origin.value)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._event_row_to_dict(row) for row in rows]

    def get_events_by_ids(self, event_ids: list[str]) -> list[dict[str, Any]]:
        if not event_ids:
            return []
        placeholders = ",".join("?" for _ in event_ids)
        query = (
            f"SELECT * FROM events WHERE event_id IN ({placeholders}) ORDER BY timestamp"
        )
        with self.connect() as connection:
            rows = connection.execute(query, event_ids).fetchall()
        return [self._event_row_to_dict(row) for row in rows]

    # -- incidents -------------------------------------------------------

    @staticmethod
    def _resolve_event_ids(
        connection: sqlite3.Connection, event_ids: list[str]
    ) -> dict[str, int]:
        """Map upstream event ids onto the events table's integer primary keys.

        The join table stores integer foreign keys, so the upstream string id
        has to be translated before it can be inserted. A single query with an
        IN clause beats one lookup per event.
        """
        if not event_ids:
            return {}
        unique = list(dict.fromkeys(event_ids))
        placeholders = ",".join("?" for _ in unique)
        rows = connection.execute(
            f"SELECT id, event_id FROM events WHERE event_id IN ({placeholders})",
            unique,
        ).fetchall()
        return {row["event_id"]: int(row["id"]) for row in rows}

    def upsert_incident(self, incident: Incident) -> int:
        """Insert an incident, or update the existing one with the same uid.

        Correlation can rediscover an incident it already recorded — the demo
        dataset deliberately produces overlapping signals — and an analyst
        should see one incident, not three.
        """
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT id FROM incidents WHERE incident_uid = ?", (incident.incident_id,)
            ).fetchone()

            if existing is None:
                cursor = connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_uid, attack_type, status, severity,
                        user_key, source_ip, application, data_origin, subject,
                        first_seen, last_seen, event_count,
                        title, signal_json, limitations
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        incident.incident_id,
                        incident.attack_type.value,
                        incident.status.value,
                        incident.severity,
                        incident.user_key,
                        incident.source_ip,
                        incident.application,
                        incident.data_origin.value,
                        incident.subject,
                        incident.first_seen.isoformat(),
                        incident.last_seen.isoformat(),
                        incident.event_count,
                        incident.title,
                        json.dumps(incident.signal_summary),
                        incident.limitations,
                    ),
                )
                incident_id = int(cursor.lastrowid or 0)
            else:
                incident_id = int(existing["id"])
                connection.execute(
                    """
                    UPDATE incidents SET
                        attack_type = ?, severity = ?, last_seen = ?,
                        event_count = ?, title = ?, signal_json = ?, limitations = ?
                    WHERE id = ?
                    """,
                    (
                        incident.attack_type.value,
                        incident.severity,
                        incident.last_seen.isoformat(),
                        incident.event_count,
                        incident.title,
                        json.dumps(incident.signal_summary),
                        incident.limitations,
                        incident_id,
                    ),
                )

            self._attach_events(
                connection, incident_id, incident.detections
            )

        return incident_id

    def _attach_events(
        self,
        connection: sqlite3.Connection,
        incident_id: int,
        detections: Iterable[DetectionResult],
    ) -> int:
        """Link each detection's events to the incident. Returns rows added."""
        wanted: list[str] = []
        for detection in detections:
            wanted.extend(detection.event_ids)

        resolved = self._resolve_event_ids(connection, wanted)
        added = 0
        for detection in detections:
            for event_id in detection.event_ids:
                row_id = resolved.get(event_id)
                if row_id is None:
                    # The event was never persisted, so there is nothing to
                    # link. Skip it rather than breaking the whole incident.
                    continue
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO incident_events
                        (incident_id, event_id, detection)
                    VALUES (?,?,?)
                    """,
                    (incident_id, row_id, detection.detection.value),
                )
                added += cursor.rowcount
        return added

    def link_events(
        self, incident_uid: str, event_ids: list[str], detection: str
    ) -> int:
        """Attach events to an existing incident. Used when correlation adds
        a later signal to an incident that is already open."""
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id FROM incidents WHERE incident_uid = ?", (incident_uid,)
            ).fetchone()
            if row is None:
                return 0

            incident_id = int(row["id"])
            resolved = self._resolve_event_ids(connection, event_ids)
            added = 0
            for event_id in event_ids:
                row_id = resolved.get(event_id)
                if row_id is None:
                    continue
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO incident_events
                        (incident_id, event_id, detection)
                    VALUES (?,?,?)
                    """,
                    (incident_id, row_id, detection),
                )
                added += cursor.rowcount

            connection.execute(
                """
                UPDATE incidents SET event_count = (
                    SELECT COUNT(*) FROM incident_events WHERE incident_id = ?
                ) WHERE id = ?
                """,
                (incident_id, incident_id),
            )
        return added

    def list_incidents(
        self,
        limit: int = 50,
        status: IncidentStatus | None = None,
        data_origin: DataOrigin | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM incidents WHERE 1=1"
        params: list[Any] = []
        if status is not None:
            query += " AND status = ?"
            params.append(status.value)
        if data_origin is not None:
            query += " AND data_origin = ?"
            params.append(data_origin.value)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._incident_row_to_dict(row) for row in rows]

    def get_incident(self, incident_uid: str) -> dict[str, Any] | None:
        """One incident with its timeline, decision and investigation.

        The timeline is a LEFT JOIN against incident_events and events, ordered
        by timestamp. That ordering is the whole product: an attack chain read
        out of sequence is not a timeline.
        """
        with self.connect() as connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_uid = ?", (incident_uid,)
            ).fetchone()
            if incident is None:
                return None

            timeline_rows = connection.execute(
                """
                SELECT e.*, ie.detection
                FROM incident_events ie
                JOIN events e ON e.id = ie.event_id
                WHERE ie.incident_id = ?
                ORDER BY e.timestamp
                """,
                (incident["id"],),
            ).fetchall()

            decision_row = connection.execute(
                """
                SELECT * FROM decisions WHERE incident_id = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (incident["id"],),
            ).fetchone()

        result = self._incident_row_to_dict(incident)
        result["timeline"] = [
            {
                "timestamp": row["timestamp"],
                "event_id": row["event_id"],
                "detection": row["detection"],
                "outcome": row["outcome"],
                "user_principal_name": row["user_principal_name"],
                "source_ip": row["source_ip"],
                "city": row["city"],
                "country": row["country"],
                "application": row["application"],
                "device": row["device"],
                "status_error_code": row["status_error_code"],
                "activity": row["activity"],
            }
            for row in timeline_rows
        ]
        result["decision"] = (
            self._decision_row_to_dict(decision_row) if decision_row else None
        )
        return result

    def count_incidents(self, status: IncidentStatus | None = None) -> int:
        query = "SELECT COUNT(*) AS n FROM incidents"
        params: list[Any] = []
        if status is not None:
            query += " WHERE status = ?"
            params.append(status.value)
        with self.connect() as connection:
            row = connection.execute(query, params).fetchone()
        return int(row["n"])

    def incidents_by_attack_type(self) -> dict[str, int]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT attack_type, COUNT(*) AS n FROM incidents GROUP BY attack_type"
            ).fetchall()
        return {row["attack_type"]: int(row["n"]) for row in rows}

    # -- decisions -------------------------------------------------------

    def save_decision(
        self,
        incident_uid: str,
        decision: Decision,
        investigation: dict[str, Any] | None = None,
    ) -> int | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id FROM incidents WHERE incident_uid = ?", (incident_uid,)
            ).fetchone()
            if row is None:
                logger.warning("cannot save decision: unknown incident %s", incident_uid)
                return None

            cursor = connection.execute(
                """
                INSERT INTO decisions (
                    incident_id, created_at, suspicious, suspicion_score,
                    attack_type, severity, escalate, needs_analyst_review,
                    confidence, band, source, reasoning, raw_json, investigation_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    int(row["id"]),
                    datetime.now().astimezone().isoformat(),
                    int(decision.suspicious),
                    decision.suspicion_score,
                    decision.attack_type.value,
                    decision.severity,
                    int(decision.escalate),
                    int(decision.needs_analyst_review),
                    decision.confidence,
                    decision.band.value,
                    decision.source.value,
                    decision.reasoning,
                    json.dumps(decision.raw_response) if decision.raw_response else None,
                    json.dumps(investigation) if investigation else None,
                ),
            )
            return int(cursor.lastrowid or 0)

    def save_incident_error(self, incident_uid: str, message: str) -> None:
        """Record that a model-backed layer failed, without losing the incident.

        Graceful degradation means the analyst still gets the deterministic
        result, plus a note about what is missing. See CONTEXT.md.
        """
        with self.connect() as connection:
            connection.execute(
                "UPDATE incidents SET decision_error = ? WHERE incident_uid = ?",
                (message, incident_uid),
            )

    # -- row conversion --------------------------------------------------

    @staticmethod
    def _event_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["raw"] = json.loads(data.pop("raw_json") or "{}")
        return data

    @staticmethod
    def _incident_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["signal_summary"] = json.loads(data.pop("signal_json") or "{}")
        return data

    @staticmethod
    def _decision_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for key in ("suspicious", "escalate", "needs_analyst_review"):
            data[key] = bool(data[key])
        data["raw_response"] = json.loads(data.pop("raw_json") or "null")
        data["investigation"] = json.loads(data.pop("investigation_json") or "null")
        data["attack_type"] = AttackType(data["attack_type"])
        data["band"] = ConfidenceBand(data["band"])
        data["source"] = DecisionSource(data["source"])
        return data


def make_incident_uid(parts: list[str]) -> str:
    """A stable uid from the parts that define an incident's identity.

    Correlation re-runs on every analysis, and the same attack must land in the
    same incident row each time. A hash of the grouping keys gives that for
    free, where a random uuid would create a duplicate incident on every run.
    """
    digest = hashlib.sha256("|".join(sorted(parts)).encode("utf-8"))
    return digest.hexdigest()[:16]
