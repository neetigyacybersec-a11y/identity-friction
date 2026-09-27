# Entra ID Identity Defense

Detects identity attack signals in Microsoft Entra ID telemetry, groups them into
incidents with ordered timelines, and adds model-backed decisions and
investigation reports on top.

**A detected signal is not a confirmed attack.** Everything this tool produces
comes from heuristics matching log patterns. None of it is proof that anyone
acted maliciously, and nothing here takes response action. That distinction is
the project's central claim and it is enforced in the code, the API responses
and this file. See [docs/adr/0002-signal-not-proof.md](docs/adr/0002-signal-not-proof.md).

## Run it

No credentials, no tenant, no setup:

```bash
git clone <this-repo> && cd portfolioproject
python -m scripts.run_analysis --demo
```

```
demo analysis complete in 0.007s
  events       35 read, 35 new
  findings     4
  incidents    3
  decisions    3 made, 0 fell back to rules

  [ 8] Identity attack chain for daniel.reyes@contoso-labs.onmicrosoft.com: mfa_fatigue, oauth_consent
  [ 4] Impossible Travel detected for marcus.webb@contoso-labs.onmicrosoft.com
  [ 8] Account Compromise detected for source 203.0.113.77
```

With Docker:

```bash
docker compose up          # then open http://localhost:8000
```

For the dashboard and API:

```bash
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

## What it does

```
Microsoft Graph ──┐
                 ├─> normalize ─> detect ─> correlate ─> decide ─> investigate
synthetic JSON ───┘   (deterministic ──> ──> SQLite)    (model)  (model)
```

| Stage | Needs a network? | Degrades to |
| --- | --- | --- |
| normalize | no | fails loudly on a malformed event |
| detect | no | never; one broken rule does not stop the others |
| correlate | no | never |
| decide (System One) | yes | the offline rule engine, recording why |
| investigate (System Two) | yes | no report; the incident keeps its decision |

The rule that shapes the design: **a model failure never costs a deterministic
result.** With no API key the project still detects, correlates, decides,
persists and displays. There is a test for exactly this.

## The four detections

| Detection | Fires when | Needs |
| --- | --- | --- |
| Password spray | many credential failures across many accounts from one source in a sliding window | sign-in logs |
| MFA fatigue | repeated MFA denials followed by a **successful** sign-in | sign-in logs |
| Geographically anomalous authentication | implied travel speed above a threshold, with real coordinates | sign-in logs with location |
| Suspicious OAuth consent | a configured audit activity granting a broadly-powerful scope | directory audit logs |

Two decisions inside these are worth explaining, because both are about not
over-claiming:

**MFA fatigue requires a success.** A user who fails MFA and gives up is not an
incident. The rule fires on the denials *plus* a successful sign-in inside a
lookahead window, because the success is what makes it a possible compromise
rather than a mistyped password.

**A spray is named for its source, not a victim.** A spray touches many
accounts, so picking one to label the incident with would be arbitrary. The
incident's `subject` is the source IP, and the accounts appear in the evidence.

## Honest limitations

These are the constraints that actually matter. The per-detection caveats are
also stored with every incident and shown on the dashboard.

- **A signal is not a confirmed attack.** No detection here distinguishes an
  attacker from a traveller, a new office, a corporate proxy, or a user who lost
  their phone and re-entered their password correctly.
- **One IP is not one attacker.** Corporate egress, VPN and NAT concentrate an
  entire office behind one address, which produces spray signals harmlessly.
- **Thresholds are demo-scale.** They are configured in `app/config.py` and have
  not been calibrated against a real tenant's baseline.
- **JEV is reached over OpenRouter, not its native API.** Early-access API access
  was unavailable, so this uses `typesafe/jev-router` through a
  `chat/completions` call. That means **no schema guarantee** and **no calibrated
  confidence**. The adapter parses defensively, treats the model's reported
  confidence as advisory, and computes the confidence band from the returned
  score instead. See [ADR 0001](docs/adr/0001-jev-behind-decision-engine-interface.md).
- **The investigation model is told not to over-claim**, and the detector's own
  limitations are prepended to every report, so a model reply cannot drop them.
- **Only the sign-in and directory audit endpoints are read.** A detection that
  needs risk-based detection data, device compliance, or mailbox audit logs is
  out of reach here.
- **The dashboard has no authentication.** It is a single-user analyst tool, not a
  service. Do not expose it to a network.
- **The live path is unverified against a real tenant.** There were no tenant
  credentials available while building this, so Graph collection is tested
  against an injected fake client, not against Microsoft Graph.

## Live mode

Optional. Needs an Azure app registration with the **`AuditLog.Read.All`**
application permission and admin consent.

```bash
cp .env.example .env    # fill in GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET
python -m scripts.run_analysis --live
```

Authentication is app-only via `azure-identity`'s `ClientSecretCredential`. The
client secret is never logged and never reaches a stored event.

Collection handles the failure modes that are otherwise silent:

- **Pagination is followed to the end.** A 24-hour window routinely spans several
  pages, and reading only the first analyses a fraction of the activity while
  looking complete.
- **A rejected audit time filter** falls back to unfiltered collection with local
  window filtering, because the data still arrives complete.
- **One log type failing is reported, not swallowed.** Tenants without the
  directory audit licence return 403, and the sign-in detections are still worth
  running, so each half is attempted independently and the gap is recorded.
- **An empty analysis is never reported as a quiet tenant.** Missing credentials
  or missing sample data return an error, because zero incidents from no data is
  indistinguishable from zero incidents because nothing happened.

## Layout

```
app/
  config.py            every threshold, in one arguable place
  normalize.py         Graph payload -> NormalizedEvent (shared by both modes)
  features.py          windows, MFA classification, haversine
  detection/           the four deterministic rules + engine
  correlation.py       findings -> incidents, with a subject and a timeline
  decision/            DecisionEngine interface, offline rules, JEV adapter
  investigation/       System Two report writer
  database/            schema.sql + repository (raw sqlite3, no ORM)
  collect/graph.py     Microsoft Graph collector
  pipeline.py          the one order of operations
  main.py              FastAPI + dashboard
data/sample/           synthetic scenarios, in Graph's own JSON shape
docs/adr/              the decisions worth arguing about
tests/                 64 tests, no network required
```

The demo data is written in Microsoft Graph's exact JSON shape on purpose, so a
synthetic event travels through precisely the same code as a live one. The only
difference is the `data_origin` value, and the normalizer never infers it from
the payload — the caller states it, because whether telemetry is real is a fact
the code cannot know.

## Design decisions

- [ADR 0001](docs/adr/0001-jev-behind-decision-engine-interface.md) — JEV behind a `DecisionEngine` interface, reached over OpenRouter
- [ADR 0002](docs/adr/0002-signal-not-proof.md) — a detected signal is not a confirmed attack
- [ADR 0003](docs/adr/0003-raw-sqlite-over-sqlalchemy.md) — raw `sqlite3` over an ORM
- [CONTEXT.md](CONTEXT.md) — the glossary, and the line between signal and proof

The pattern running through all of them: the interesting work is the boundary.
Which boundary is defensible, what a name is allowed to claim, and what happens
when the interesting dependency is unavailable.

## Tests

```bash
python -m pytest              # 64 tests, no network, no credentials
```

They cover the failure modes, not only the happy path: no API key, a malformed
model reply, a rejected Graph filter, a 403 on one log type, pagination that
does not terminate, and a model outage that must still leave every
deterministic result intact.

## A note on installing the wheel

Use an editable install, as above. A non-editable `pip install .` puts the code
in `site-packages` but cannot carry `data/sample/` with it, so `--demo` exits 3
with a message telling you so. That is deliberate rather than a silent empty
result: an analysis of no data would report zero findings, which reads as a
clean tenant, and this tool must never say that without having looked at
something. Set `SAMPLE_DATA_DIR` to a checkout's `data/sample/` if you need demo
data from a non-editable install. The Docker image and a plain `git clone` are
both unaffected.

## Optional: a token/session anomaly rule

Not implemented, deliberately. The available telemetry supports "suspicious token
or session activity" and does not support identifying token theft. Naming a
detection for something the data cannot show is the exact error this project's
own rules warn against, so a future rule should be named for what it observes,
not for what an analyst would hope it means.
