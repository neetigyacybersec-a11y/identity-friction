# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root: the glossary and the detected-signal / confirmed-attack line.
- **`docs/adr/`**: read ADRs that touch the area you're about to work in.

This is a single-context repo. There is no `CONTEXT-MAP.md` and no per-context `src/<context>/`
layout, so don't go looking for either.

If any of these files don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them upfront. The `/domain-modeling` skill (reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates them lazily when terms or decisions actually get resolved.

## File structure

```
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-jev-behind-decision-engine-interface.md
│   ├── 0002-signal-not-proof.md
│   └── 0003-raw-sqlite-over-sqlalchemy.md
└── app/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

Two pairs the glossary treats as distinct, and the code depends on the distinction:

- **detection** (a deterministic rule that fires) vs **decision** (a model's judgement about a candidate).
- **candidate** (a detection fired; a signal exists) vs **incident** (correlated candidates a human must look at).

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0003 (raw sqlite over SQLAlchemy), but worth reopening because…_
