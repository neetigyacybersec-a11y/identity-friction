# AGENTS.md

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues, managed with the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles use their default label strings. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` at the repo root plus ADRs in `docs/adr/`. See `docs/agents/domain.md`.

## Project rules

Read `CONTEXT.md` before changing vocabulary or adding a detection. It holds the glossary and the
line between a **detected signal** and a **confirmed attack** — that line is the core claim of the
project and is not to be blurred.

Do not add a detection that claims to identify token theft. The available telemetry supports
"suspicious token or session activity" only. See `docs/adr/0002-signal-not-proof.md`.

The detection path (normalize, features, detect) must stay deterministic and free of network
calls. Only `app/decision/` and `app/investigation/` may talk to a model, and both must degrade
gracefully when the model is unavailable.
