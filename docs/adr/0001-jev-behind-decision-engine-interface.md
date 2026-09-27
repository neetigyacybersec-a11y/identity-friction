# 0001. JEV sits behind a DecisionEngine interface, reached over OpenRouter

Date: 2026-09-27

## Context

JEV is TypeSafe AI's System One model: it takes unstructured state in and returns typed
probabilistic decisions out, with no string generation and therefore no schema drift. It is
exactly the right tool for the four fast questions this project asks of a candidate — is this
suspicious, which attack type fits, how severe, escalate or not.

The native API is a Python SDK, `typesafe-sdk`, driven by a `TYPESAFE_API_KEY` from
`console.typesafe.ai`. JEV is in early access and the key was not available at the time of this
decision. The same model is reachable today as `typesafe/jev-router` on OpenRouter, using an
existing key and a `chat/completions` call with `response_format: json_object`.

## Decision

Call JEV through OpenRouter, and put every JEV call behind the `DecisionEngine` interface in
`app/decision/engine.py`. The interface takes normalized events and features and returns the
project's own `Decision` model. No OpenRouter type appears in the interface signature.

## Rationale

The adapter is the point, not the transport. Two reasons:

1. The backend can change without touching a caller. When early access arrives, a
   `typesafe-sdk` implementation of the same interface is one new file, and the detectors,
   pipeline, API and dashboard do not change.
2. The OpenRouter route is a text-JSON workaround, and pretending otherwise would be dishonest.
   JSON mode still returns malformed output sometimes, so the client parses defensively and the
   tests cover the malformed case. There is no schema guarantee and no calibrated confidence from
   the transport, so the adapter treats the model's self-reported confidence as *advisory* and
   computes the confidence band from returned probabilities instead.

## Consequences

- The project cannot claim it uses JEV's native typed System One API. The README and the
  interview notes say "JEV reached through OpenRouter because early-access API access was not
  available" rather than implying first-party SDK use.
- A second `DecisionEngine` implementation (`rule_decision.py`) is the offline fallback. When no
  API key is configured, or the call fails, the deterministic result stands alone. This is
  required behaviour, not a stub.
- Interview framing: the adapter existing is the stronger answer, because it shows the
  difference between using a model and depending on one.

## Alternatives considered

- **Native SDK only.** Rejected: nothing runs without early-access approval, so the project
  would be undemonstrable today.
- **Both backends.** Rejected as unnecessary abstraction for a one-month project. The interface
  already makes the second backend a one-file addition later.
- **Call OpenRouter directly from detectors.** Rejected: it would scatter model calls through the
  detection path and break the determinism constraint in `CONTEXT.md`.
