<div align="center">

# Identity&nbsp;Friction

**Signal triage for Microsoft Entra ID telemetry.**

Deterministic detections, model-assisted review, analyst decides.

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/api-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/store-SQLite-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)

</div>

---

> ### A detected signal is not a confirmed attack.
>
> Every result this tool produces is a heuristic matching a log pattern. None of
> it is proof that anyone acted maliciously, and **nothing here takes response
> action** — no account is disabled, no session is revoked, no alert is fired.
> The output is a shortlist for a human to investigate.
>
> That distinction is the project's central claim, and it is enforced in the
> detectors, the API responses, the CLI output and the JSON payload.
> See [ADR 0002](docs/adr/0002-signal-not-proof.md).

---

## What it does

Reads Entra ID sign-in and audit telemetry, finds identity attack patterns with
deterministic rules, groups them into incidents with ordered timelines and
evidence, and adds two model-backed layers on top — a fast structured judgement
per incident (System One), and a plain-language case write-up (System Two).

Both model layers are **optional**. With no API key configured, the project still
detects, correlates, decides, persists and displays. The models add a second
opinion; they never gate the result.

```
 Microsoft Graph ──┐
                   ├──> normalize ──> detect ──> correlate ──> decide ──> investigate
 synthetic JSON ───┘      (deterministic)   (rules)   (SQLite)    (model)    (model)
                                 │                                          │
                                 └──── works offline, always ──────────────┘
```

| Stage | Network? | If it fails |
| --- | :---: | --- |
| `normalize` | no | raises on a malformed event rather than guessing |
| `detect` | no | never — one broken rule does not stop the others |
| `correlate` | no | never |
| `decide` (System One) | yes | falls back to the offline rule engine, and records that it did |
| `investigate` (System Two) | yes | no report; the incident keeps its decision |

> The rule that shapes the whole design: **a model failure never costs a
> deterministic result.** There is a test for exactly that.

---

## Quick start

Requires **Python 3.11 or newer**. Nothing else. No Microsoft tenant, no API
keys, no cloud account, no container runtime. The demo data ships with the
repo.

```bash
git clone https://github.com/neetigyacybersec-a11y/identity-friction.git
cd identity-friction

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e .
python -m scripts.run_analysis --demo
```

About 20 seconds, including the install. You should see:

```
demo analysis complete in 0.014s
  events       35 read, 35 new
  findings     4
  incidents    3
  decisions    3 made, 0 fell back to rules

3 incident(s):

  [ 8] Identity attack chain for daniel.reays@contoso-labs.onmicrosoft.com: mfa_fatigue, oauth_consent
       id       22b4257b1b1d1592
       type     account_compromise  (open)
       events   6
       window   2026-09-20T10:01:00 -> 2026-09-20T10:07:00

  [ 4] Geographically anomalous authentication detected for marcus.webb@contoso-labs.onmicrosoft.com
       id       52294a5a08f97c36
       type     impossible_travel  (open)
       events   2
       window   2026-09-20T07:15:00 -> 2026-09-20T08:45:00

  [ 8] Account compromise detected for source 203.0.113.77
       id       4db61c4af815a0ca
       type     account_compromise  (open)
       events   15
       window   2026-09-20T02:00:00 -> 2026-09-20T02:09:00
```

> Each incident is a **case file**, not a verdict. Open one in the dashboard to
> see its evidence, the decisions made about it, and the specific ways this
> detection can be wrong.

### The dashboard

```bash
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Then open **<http://localhost:8000>**.

The dashboard lists every incident with severity, attack type, subject and
corroborating rules. Each incident page carries the ordered timeline, the
evidence, the decision, the model's case write-up if one was generated, and the
detector's own limitations. There is a JSON API underneath:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | liveness, plus which layers are currently available |
| `GET /api/incidents` | filter by `status`, `min_severity`, `user_key`, `source_ip` |
| `GET /api/incidents/{uid}` | full timeline, decision and limitations |
| `POST /api/analyze/demo` | run the demo analysis on demand |
| `POST /api/analyze/live` | collect from a real tenant and analyse |
| `POST /api/incidents/{uid}/investigate` | generate a case write-up on demand |

```bash
curl -s localhost:8000/api/incidents?min_severity=8 | python3 -m json.tool
```

### Scripting

```bash
python -m scripts.run_analysis --demo --json | jq '.incident_details[] | {severity, title}'
```

`--json` emits exactly one JSON document — run summary, incidents, and the
signal/proof note — so it is safe to pipe.

---

## The four detections

| Detection | Fires when | Needs |
| --- | --- | --- |
| **Password spray** | many credential failures across many accounts from one source, inside a sliding window | sign-in logs |
| **MFA fatigue** | repeated MFA denials followed by a **successful** sign-in | sign-in logs |
| **Geographically anomalous authentication** | implied travel speed above a threshold, with real coordinates to compute it from | sign-in logs with location |
| **Suspicious OAuth consent** | a configured audit activity granting a broadly-powerful scope | directory audit logs |

Two decisions inside these are worth explaining, because both are about *not*
over-claiming:

**MFA fatigue requires a success.** A user who fails MFA and gives up is not an
incident. The rule fires on the denials *plus* a successful sign-in inside a
lookahead window, because the success is what makes it a possible compromise
rather than a mistyped password. There is a test for the version without the
success, and it must produce nothing.

**A spray is named for its source, not a victim.** A spray touches many accounts,
so choosing one to label the incident with would be arbitrary. The incident's
subject is the source IP; the accounts appear in the evidence.

**The travel rule is named for what it observes.** It is called "geographically
anomalous authentication", not "impossible travel", because two distant IP
addresses do not prove anybody moved. Corporate egress, VPN and mobile
carriers break this rule constantly and harmlessly. This project does not name a
thing for a conclusion the telemetry cannot support — that is the same rule
applied to naming, and it has already been enforced once, in the code.

---

## Honest limitations

The constraints that actually matter. The per-detection caveats are also stored
with every incident and shown on its dashboard page.

- **A signal is not a confirmed attack.** No detection here distinguishes an
  attacker from a traveller, a new office, a corporate proxy, or a user who lost
  their phone and re-entered their password correctly.
- **One IP is not one attacker.** Corporate egress, VPN and NAT concentrate an
  entire office behind a single address, producing spray signals harmlessly.
- **Thresholds are demo-scale.** They live in `app/config.py` and have not been
  calibrated against a real tenant's baseline.
- **JEV is reached over OpenRouter, not its native API.** Early-access API access
  was unavailable, so this uses `typesafe/jev-router` via a `chat/completions`
  call. That means **no schema guarantee and no calibrated confidence**. The
  adapter parses defensively, treats the model's self-reported confidence as
  advisory, and derives the confidence band from the returned score instead.
  See [ADR 0001](docs/adr/0001-jev-behind-decision-engine-interface.md).
- **The model is told not to over-claim, and told about the detector's
  limitations** — those caveats are prepended to every report, so a model reply
  cannot quietly drop them.
- **Only sign-in and directory audit endpoints are read.** Anything needing
  risk-based detection data, device compliance or mailbox audit logs is out of
  reach here.
- **The dashboard has no authentication.** It is a single-user analyst tool, not
  a service. Do not expose it to a network.
- **The live path has never touched a real tenant.** There were no credentials
  available, so Graph collection is tested against an injected fake client, not
  against Microsoft Graph. Likewise, **the model layers have never called a real
  API** — no OpenRouter key was available, so both adapters are tested against
  fakes, including their failure paths.

---

## Live mode (optional)

Needs an Azure app registration with the **`AuditLog.Read.All`** application
permission and admin consent.

```bash
cp .env.example .env      # fill in the three GRAPH_* values
python -m scripts.run_analysis --live
```

Authentication is app-only, via `azure-identity`'s `ClientSecretCredential`. The
client secret is never logged and never reaches a stored event.

Collection handles the failure modes that would otherwise be silent:

- **Pagination is followed to the end.** A 24-hour window routinely spans several
  pages, and reading only the first analyses a fraction of the activity while
  looking complete.
- **A rejected audit time filter** falls back to unfiltered collection with local
  window filtering, because the data still arrives complete.
- **One log type failing is reported, not swallowed.** Tenants without the
  directory audit licence return 403, and the sign-in detections are still worth
  running — so each half is attempted independently and the gap is recorded.
- **An empty analysis is never reported as a quiet tenant.** Missing credentials
  or missing sample data return an error, because zero incidents from no data is
  indistinguishable from zero incidents because nothing happened.

---

## Design decisions

The pattern running through all of them: the interesting work is the *boundary*.
Which boundary is defensible, what a name is allowed to claim, and what happens
when the interesting dependency is unavailable.

- **[ADR 0001](docs/adr/0001-jev-behind-decision-engine-interface.md)** — JEV
  behind a `DecisionEngine` interface, reached over OpenRouter
- **[ADR 0002](docs/adr/0002-signal-not-proof.md)** — a detected signal is not a
  confirmed attack
- **[ADR 0003](docs/adr/0003-raw-sqlite-over-sqlalchemy.md)** — raw `sqlite3`
  over an ORM
- **[CONTEXT.md](CONTEXT.md)** — the glossary, and the line between signal and
  proof

---

## Tests

```bash
pip install -e ".[dev]"
python -m pytest            # 68 tests, no network, no credentials
```

The suite covers the failure modes, not only the happy path: no API key, a
malformed model reply, a rejected Graph filter, a 403 on one log type, pagination
that never terminates, a contaminated `.env` file, and a model outage that must
still leave every deterministic result intact.

Detections are tested against specific numbers rather than "something fired" —
fourteen failures across seven accounts produce exactly one finding at severity
8, and removing the success drops it to a severity-6 spray. That second test is
the regression test for a real bug where successes were searched for inside the
already-filtered failure list.

Both model adapters and the Graph collector take an injected client precisely so
this suite can run with no network, and pytest fails the run on a deprecation
warning from `app`, so it cannot quietly rot.

---

## Layout

```
app/
  config.py            every threshold, in one arguable place
  normalize.py         Graph payload -> NormalizedEvent (shared by both modes)
  features.py          windows, MFA classification, haversine
  detection/           the four deterministic rules + engine
  correlation.py       findings -> incidents, with a subject and a timeline
  decision/            DecisionEngine interface, offline rules, JEV adapter
  investigation/       System Two case writer
  database/            schema.sql + repository (raw sqlite3, no ORM)
  collect/graph.py     Microsoft Graph collector
  pipeline.py          the one order of operations
  main.py              FastAPI + dashboard
data/sample/           synthetic scenarios, in Graph's own JSON shape
docs/adr/              the decisions worth arguing about
tests/                 68 tests, no network required
```

The demo data is written in Microsoft Graph's exact JSON shape on purpose, so a
synthetic event travels through precisely the same code as a live one. The only
difference is the `data_origin` value, and the normalizer never infers it from
the payload — the caller states it, because whether telemetry is real is a fact
the code cannot know.

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `ModuleNotFoundError: No module named 'pydantic'` | Dependencies are not installed. Activate the venv and run `pip install -e .`. |
| `no sample data files in ...` or `sample data directory not found` | Running from a non-editable install, which cannot carry `data/sample/`. Use `pip install -e .`, or set `SAMPLE_DATA_DIR` to this checkout's `data/sample`. |
| `live mode needs these environment variables: GRAPH_*` | Expected. Copy `.env.example` to `.env` and fill in the three values. |
| `no OpenRouter API key configured` in the log | Expected. The rule engine decided instead, and the run still completed. |
| Dashboard shows no incidents | Click **Analyze demo data** on the dashboard, or `POST /api/analyze/demo`. |
| Port 8000 already in use | `uvicorn app.main:app --port 8001` |

## License

Built as a portfolio project. The sample datasets are synthetic and contain no
real telemetry and no real people.

---

<div align="center">
<sub>Identity Friction — detections are heuristics. A signal is not a proof.</sub>
</div>
