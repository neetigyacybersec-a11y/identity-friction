# 0002. A signal is not proof, and the names must say so

Date: 2026-09-27

## Context

Detection engineering has a chronic naming problem. A rule that fires gets reported as a finding,
a finding gets reported as an attack, and somewhere between the rule and the report the
qualifier falls off. Entra ID telemetry makes this worse than usual, because the same observable
pattern has several innocent explanations.

Two cases in this project:

**Geographically anomalous authentication.** Sign-in logs carry a source IP and a coarse geolocation
derived from it. A login from two places inside an hour produces an implied travel speed no human
achieves. That is a real signal. It is also produced, harmlessly and constantly, by VPNs, corporate
egress, mobile network handoffs, and IP geolocation databases that are simply wrong. "Different
countries" is not an attack.

**OAuth consent.** An audit log showing `Consent to application` with a wide set of delegated
permissions is a real signal. It is also what a legitimate admin installing a sanctioned
integration looks like. A permission grant is not malice.

The sharpest version of this problem is token theft. The available telemetry can show that a token
or session is being used in a way that deviates from its owner's pattern. It cannot show where the
token came from, whether it was stolen, or by whom. A detection that claims to identify token
theft is overstating its evidence, and an interviewer who knows identity security will find the
overstatement immediately.

## Decision

1. Separate the words. A **detected signal** is the ceiling of what this system produces. A
   **confirmed attack** is never produced, and no field, table or response holds one.
2. Name findings for what the evidence supports, not for the attack they resemble. The
   impossible-travel detector emits `impossible_travel` as an attack type but its finding text
   reads "geographically anomalous authentication", and its documented limitation names the false
   positive causes. The token detector is called "suspicious token or session activity" and its
   docstring states that it does not identify token theft.
3. Record a `limitations` field as a required part of every investigation report, and an explicit
   `limitations` note on every detection.
4. The dashboard renders the signal and the confidence band next to the finding, so the two are
   never visually fused into a single confident-looking claim.

## Consequences

- A candidate can be `suspicious: false` while a detection fired. That is a valid and useful
  outcome: the rule noticed a pattern, and the decision layer judged it benign. False positives
  are visible rather than hidden.
- `severity` is explicitly not a risk score and not comparable across incidents.
- Confidence drives routing only. It never appears as evidence, and a `low` band is a normal
  outcome, not an error.
- The README's limitations section is a required deliverable, not boilerplate.
