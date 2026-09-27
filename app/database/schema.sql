-- Four tables, hand-written. See docs/adr/0003-raw-sqlite-over-sqlalchemy.md
-- for why there is no ORM.
--
-- SQLite has no native boolean or JSON type. Booleans are stored as 0/1 in an
-- INTEGER column, and JSON payloads are stored as TEXT. Both are read back
-- through the repository, which is the only place that converts them.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    -- The upstream identifier. Entra's own id, or a hash of the raw payload for
    -- synthetic events, so re-ingesting the same file does not duplicate rows.
    event_id            TEXT    NOT NULL UNIQUE,
    timestamp           TEXT    NOT NULL,
    raw_event_type      TEXT    NOT NULL,
    data_origin         TEXT    NOT NULL,

    user_id             TEXT,
    user_principal_name TEXT,
    source_ip           TEXT,

    country             TEXT,
    city                TEXT,
    latitude            REAL,
    longitude           REAL,

    application         TEXT,
    device              TEXT,

    outcome             TEXT    NOT NULL,
    status_error_code   INTEGER,

    activity            TEXT,

    -- The payload as received, so normalization can be re-checked later.
    raw_json            TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_user      ON events (user_principal_name);
CREATE INDEX IF NOT EXISTS idx_events_ip        ON events (source_ip);

CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_uid   TEXT    NOT NULL UNIQUE,
    attack_type    TEXT    NOT NULL,
    status         TEXT    NOT NULL,
    severity       INTEGER NOT NULL,

    user_key       TEXT,
    source_ip      TEXT,
    application    TEXT,
    data_origin    TEXT    NOT NULL,

    first_seen     TEXT    NOT NULL,
    last_seen      TEXT    NOT NULL,
    event_count    INTEGER NOT NULL DEFAULT 0,

    title          TEXT    NOT NULL DEFAULT '',
    signal_json    TEXT    NOT NULL DEFAULT '{}',
    limitations    TEXT    NOT NULL DEFAULT '',

    -- Set when a model-backed layer failed. The incident still exists and is
    -- still shown; this records what is missing from it.
    decision_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents (last_seen);

-- The join table that turns a pile of events into an incident. This is the
-- relational representation of "these events belong together" and it is all
-- the correlation this project needs. A graph database would be the wrong tool
-- for a two-hop relationship.
CREATE TABLE IF NOT EXISTS incident_events (
    incident_id    INTEGER NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    event_id       INTEGER NOT NULL REFERENCES events (id)    ON DELETE CASCADE,
    -- Which detection pulled this event into the incident.
    detection      TEXT    NOT NULL,
    PRIMARY KEY (incident_id, event_id, detection)
);

CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events (event_id);

CREATE TABLE IF NOT EXISTS decisions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id           INTEGER NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    created_at            TEXT    NOT NULL,

    suspicious            INTEGER NOT NULL,
    suspicion_score       REAL    NOT NULL,
    attack_type           TEXT    NOT NULL,
    severity              INTEGER NOT NULL,
    escalate              INTEGER NOT NULL,
    needs_analyst_review  INTEGER NOT NULL,

    confidence            REAL    NOT NULL,
    band                  TEXT    NOT NULL,
    source                TEXT    NOT NULL,
    reasoning             TEXT    NOT NULL DEFAULT '',
    raw_json              TEXT,

    -- The System Two output, stored on the incident as JSON.
    investigation_json    TEXT
);

CREATE INDEX IF NOT EXISTS idx_decisions_incident ON decisions (incident_id);
