# 0003. Raw sqlite3, not SQLAlchemy

Date: 2026-09-27

## Context

The project persists four tables — `events`, `incidents`, `incident_events`, `decisions` — and
joins them for the dashboard and the incident timeline. A one-month project that must be explainable
line by line has an obvious tension: an ORM is less code, and more code to explain.

## Decision

Use the Python standard library's `sqlite3` module directly. Hand-written SQL in
`app/database/repository.py`. Four tables. No ORM, no migration framework, no connection pool.

## Rationale

- The project needs to demonstrate tables, primary keys, foreign keys, `SELECT`, `INSERT` and
  joins. Raw SQL makes that knowledge visible instead of hidden behind a mapper, which is the
  point of a portfolio project at this level.
- `sqlite3` is in the standard library. An ORM would add a dependency whose only benefit here is
  saving a few lines of SQL that the project wants to show anyway.
- The query surface is small and fixed: insert an event, insert an incident, link events to an
  incident, fetch an incident with its timeline. Four queries in four functions.
- `sqlite3` returns `sqlite3.Row`, which gives dict-like access without inventing a row class.

## Consequences

- No lazy loading, no identity map, no session management. Each repository function opens,
  uses and closes its own connection. SQLite handles this fine at this scale and it keeps the
  functions independently testable.
- Schema changes are manual. Acceptable: the schema is four tables and the project is not
  production software.
- The trade-off flips if the schema grows past roughly ten tables or queries need to be composed
  dynamically. Reopen this ADR at that point rather than earlier.
