# Incident Reports

SOC-style reports written from lab alerts, one per file. Each takes a real alert chain from a Phase 2 simulation and writes it up the way a SOC analyst would: summary, timeline, analysis, triage queries, containment, and lessons learned.

| Report | Incident | Severity | ATT&CK |
|---|---|---|---|
| [IR-001](IR-001-rogue-account-escalation.md) | Rogue account escalated to sudo + UID-0 backdoor | High (L13) | T1136.001, T1098, T1078.003 |
| [IR-002](IR-002-sudoers-nopasswd-backdoor.md) | Sudoers backdoor granting passwordless root | Critical (L14) | T1548.003, T1565.001 |
| [IR-003](IR-003-ssh-brute-force.md) | SSH brute force against a local account | High (L10) | T1110.001 |

## Template

```markdown
# IR-NNN: <Title>

| Field | Value |
|---|---|
| Date detected | |
| Severity | Low / Medium / High / Critical |
| Affected asset | |
| ATT&CK technique | |
| Status | Open / Contained / Closed |

## Summary
Two or three sentences a manager could read.

## Timeline
| Time | Event |
|---|---|

## Analysis
Evidence, alerts, and how the conclusion was reached.

## Containment and remediation
What was done and what should be done.

## Lessons learned
Detection gaps, tuning, and process improvements.
```
