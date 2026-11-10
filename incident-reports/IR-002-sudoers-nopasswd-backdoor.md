# IR-002: Sudoers backdoor granting passwordless root

> Lab exercise written as a SOC incident report. The "attacker" and the "analyst" are the same person; all activity is from simulation 04 on an isolated lab host. Times are the Wazuh **alert** timestamps (UTC); in this run the endpoint log time matched within 2 seconds.

| Field | Value |
|---|---|
| Incident ID | IR-002 |
| Date detected | 2026-11-10 |
| Severity | **Critical** (peak rule level 14) |
| Affected asset | `soc-victim-01` (Ubuntu 24.04.5, agent 001, 192.168.64.2) |
| ATT&CK | T1548.003 Abuse Elevation Control Mechanism: Sudo, T1565.001 Stored Data Manipulation |
| Status | Closed — contained and remediated |
| Analyst | `<admin>` |

## Summary
Wazuh raised a level-14 alert (rule 100133) when a sudoers drop-in file, `/etc/sudoers.d/99-soc-lab`, was modified to grant the unprivileged account `labuser` **passwordless root** (`labuser ALL=(ALL) NOPASSWD: ALL`). The alert captured the exact granted line in its file-integrity diff. The drop-in was removed and `labuser` confirmed to have no sudo rights. No use of the backdoor was found: `labuser` ran no `sudo` command after the grant.

## Timeline (UTC)
| Time | Rule (level) | Event |
|---|---|---|
| 01:42:24 | **100132 (12)** | `/etc/sudoers.d/99-soc-lab` **added** by `/usr/bin/tee` (new file — no diff) |
| 01:43:46 | **100133 (14)** | same file **modified** by `tee -a`; diff: `1a2 > labuser ALL=(ALL) NOPASSWD: ALL` |
| 01:44:12 | 100132 (12) | `chmod 440` on the file — permission change, no content change |
| 01:44:24 | 5402 (3) | `sudo visudo -c` (syntax check, read-only) |
| 02:21:29 | 100132 (12) | Cleanup — file **deleted** (`rm`) |

## Analysis
**What happened.** A drop-in was planted in `/etc/sudoers.d/`, which `sudo` reads in addition to `/etc/sudoers`. The planted rule gives `labuser` the right to run any command as root **without a password**, turning a low-privilege account into a silent root path. The `chmod 440` afterward sets the standard sudoers permission so `sudo` accepts the file.

**How it was detected.** File-integrity monitoring watches `/etc/sudoers` and `/etc/sudoers.d/` with who-data (recording the user behind the change). Custom rule 100132 (level 12) fires on any change to these paths; custom rule 100133 (level 14) is a child that fires when the change's **content diff** contains broad/passwordless grants (`NOPASSWD`, `ALL=(ALL`). The level-14 alert included the literal offending line, so the analyst sees the granted privilege without opening the file.

**Why the first write was only level 12.** Wazuh produces a content diff only for a **modify** of a monitored file, not for a brand-new file. The attacker created the file (100132, no diff) and then appended the grant (100133, with diff). **An attacker who writes the `NOPASSWD` line into a new drop-in in a single step gets only 100132 (level 12)** — still high severity, but the analyst would have to read the file to see the granted rights rather than seeing them in the alert.

**Attribution.** All FIM alerts carry `syscheck.audit.login_user.name` = the admin, with effective user root (the edit was done through `sudo`).

## Detection context
Triage query (Threat Hunting):
```
agent.name:soc-victim-01 and rule.id:(100132 or 100133)
```
Key fields: `syscheck.path`, `syscheck.event`, `syscheck.diff`, `syscheck.audit.process.name`, `syscheck.audit.login_user.name`, `syscheck.perm_after`, `syscheck.sha256_after`.

"Was the backdoor used?":
```
rule.id:(5402 or 5403 or 100142) and data.srcuser:labuser
```
Any `labuser` sudo after 01:43:46 is use of the backdoor. None occurred.

On-host confirmation:
```bash
sudo ls -l /etc/sudoers.d/ && sudo cat /etc/sudoers.d/*
sudo -l -U labuser      # expect: not allowed to run sudo
sudo visudo -c
```

## Containment and remediation
1. Removed `/etc/sudoers.d/99-soc-lab` (the deletion itself alerted at 100132).
2. Confirmed `labuser` has no sudo rights (`sudo -l -U labuser`).
3. Validated the remaining sudoers configuration (`visudo -c`).

## Lessons learned
- **The diff is the evidence.** Capturing the exact `NOPASSWD` line in the alert makes triage immediate — a strong argument for `report_changes` on sudoers paths.
- **Detection gap — single-step new file.** Writing the grant straight into a new drop-in yields level 12, not 14. Treat any 100132 on `/etc/sudoers.d/` as worth reading the file, not just the alert.
- **Detection gap — grant form.** A narrower grant such as `labuser ALL=/bin/bash` does not match 100133's `(ALL` / `NOPASSWD` pattern; it still raises 100132 (level 12). The content rule could be widened, at the cost of more false positives.
- **Side effect worth hunting.** The same session's `sed -i.bak` left `/etc/shadow.bak`, a copy of the password hashes; it alerted only at level 5 (not in the account-file list). Hunt with `syscheck.path:/etc/shadow*`.
- **False positive.** Legitimate `visudo` edits by an administrator produce the same alerts and should be reconciled against change management.

## Linked material
- Attacker steps: [`../simulations/04-sensitive-file-tampering.md`](../simulations/04-sensitive-file-tampering.md)
- Detection logic: [`../detections/04-sensitive-file-tampering.md`](../detections/04-sensitive-file-tampering.md)
