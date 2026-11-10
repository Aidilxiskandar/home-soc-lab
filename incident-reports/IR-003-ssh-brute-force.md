# IR-003: SSH brute force against a local account

> Lab exercise written as a SOC incident report. The "attacker" and the "analyst" are the same person; all activity is from simulation 01 on an isolated lab host. Times are the Wazuh **alert** timestamps (UTC); in this run the endpoint log time matched within 1 second.

| Field | Value |
|---|---|
| Incident ID | IR-003 |
| Date detected | 2026-11-06 |
| Severity | **High** (peak rule level 10) |
| Affected asset | `soc-victim-01` (Ubuntu 24.04.5, agent 001, 192.168.64.2) |
| Source | 192.168.64.1 (lab Mac, over UTM NAT) |
| ATT&CK | T1110.001 Brute Force: Password Guessing |
| Status | Closed — attack unsuccessful |
| Analyst | `<admin>` |

## Summary
Wazuh raised a level-10 brute-force alert (custom rule 100100) after ten failed SSH password attempts against the account `labuser` from a single source in a short window. A second independent level-10 alert (built-in 5551, PAM side) corroborated it. No successful login followed; the attack did not breach the account. This report also documents a detection subtlety: the built-in SSH burst rule (5763) did **not** fire, and why that was expected rather than a failure.

## Timeline (UTC)
| Time | Rule (level) | Event |
|---|---|---|
| 03:34–03:42 | 5760 ×4 (5) | Four isolated failed logins (same source) before the main run, inside the 15-min window |
| 03:42:19 → 03:42:55 | 5760 ×10, 5503 ×10 (5) | The run: ~one wrong password every 4 s (sshd side + PAM side), all from 192.168.64.1, user `labuser` |
| 03:42:39 | **100100 (10)** | "slow SSH brute force: 10+ failed passwords from 192.168.64.1 in 15 minutes" |
| 03:42:41 | **5551 (10)** | PAM: multiple failed logins from one source in 180 s |
| — | 5763 | **did not fire** (see Analysis) |
| — | 5715 / 100101 / 100102 | No success event — no login was achieved |

## Analysis
**What happened.** A single source made a rapid run of wrong-password SSH attempts against one account. Each attempt produced two events — an sshd `Failed password` (5760) and a PAM `authentication failure` (5503), both carrying the source IP. Enough accumulated to trip two independent frequency alerts.

**How it was detected.** Custom rule 100100 (level 10) fires on 10 failures from one IP within 15 minutes — a wider, slower window than the built-in burst rule, specifically to catch low-and-slow guessing. The PAM-side built-in rule 5551 fired independently, giving a second, corroborating detection path.

**Why the built-in burst rule (5763) did not fire.** 5763 (8 failures in 120 s) and 100100 (10 in 15 min) **count the same failed-login events**, and whichever reaches its threshold first consumes the events counted so far. Four isolated failures already sat in 100100's 15-minute window, so 100100 hit 10 at the run's sixth failure and fired first; only four more failures followed — short of 5763's eight. In isolated rule-testing (no prior failures) 5763 fires on the eighth attempt. **This was the ordering of two overlapping counters, not a rule defect** — and the attack was detected regardless, which is the point of running more than one rule.

**Outcome.** No rule 5715 (successful authentication) appeared for this source, and the on-host journal showed no `Accepted password`. The brute force was unsuccessful.

## Detection context
Triage query (Threat Hunting):
```
agent.name:soc-victim-01 and rule.id:(5760 or 5503 or 5551 or 5763 or 100100 or 100101 or 100102 or 40112 or 5715 or 2502)
```
Pivot on the source: `data.srcip:192.168.64.1` over ±1 hour. Check for any 5715 (success) from that IP, and which `data.dstuser` values were tried — one user = targeted guessing, many = spraying.

On-host confirmation (SSH success events have occasionally been lost in transit, so verify at the endpoint):
```bash
sudo journalctl -u ssh --since "2026-11-06 03:30" --until "2026-11-06 03:50" --no-pager | grep -E 'Accepted|Failed'
last -i labuser | head
```

## Containment and remediation
No breach occurred, so remediation is preventive:
- The account's password-over-SSH login exists only for the lab; on a real host, prefer key-based auth and disable password login.
- Rate-limit or lock out repeat offenders (for example `fail2ban`, or Wazuh active response to block the source IP).
- Alert on any subsequent 5715 from a source that recently triggered 100100 (custom rules 100101/100102 already do this when a success event arrives).

## Lessons learned
- **"No alert" is not "nothing happened."** Because SSH success events have gone missing in transit before, confirm the outcome against the endpoint's own journal before closing a brute force as unsuccessful.
- **Overlapping frequency rules share a counter.** Two rules watching the same event can starve each other; design for at least one independent path (here, the PAM-side 5551), so a single rule's quirk cannot blind you.
- **Shared-source limitation.** All lab SSH originates from the UTM NAT address, so admin and attacker share an IP; `same_source_ip` logic cannot separate them in this environment. On a real network, source IP is a stronger pivot.
- **Not covered.** Password spraying across many users/IPs (few failures each) and key-based access (no failures to count) would not trip these rules.

## Linked material
- Attacker steps: [`../simulations/01-ssh-brute-force.md`](../simulations/01-ssh-brute-force.md)
- Detection logic: [`../detections/01-ssh-brute-force.md`](../detections/01-ssh-brute-force.md)
