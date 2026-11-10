# IR-001: Rogue local account escalated to sudo, plus a UID-0 backdoor

> Lab exercise written as a SOC incident report. The "attacker" and the "analyst" are the same person; all activity is from simulation 02 on an isolated lab host. Times are the Wazuh **alert** timestamps (UTC); in this run the endpoint log time matched within 2 seconds.

| Field | Value |
|---|---|
| Incident ID | IR-001 |
| Date detected | 2026-11-10 |
| Severity | **High** (peak rule level 13) |
| Affected asset | `soc-victim-01` (Ubuntu 24.04.5, agent 001, 192.168.64.2) |
| ATT&CK | T1136.001 Create Account, T1098 Account Manipulation, T1078.003 Valid Accounts |
| Status | Closed — contained and remediated |
| Analyst | `<admin>` |

## Summary
Wazuh raised a level-13 alert (rule 100114) when a newly created local account, `eviluser`, was added to the `sudo` group within ten minutes of being created on `soc-victim-01`. Investigation found a second, more serious artifact from the same session: a UID-0 account named `backdoor` — a second root identity. Both accounts were created by the host's own administrator account via `sudo`. The rogue accounts were removed, with both deletions confirmed by rule 5903 (`userdel`). No evidence of use of either account was found: the archive holds no session, login, `su` or `sudo` activity by `eviluser` or `backdoor`.

## Timeline (UTC)
| Time | Rule (level) | Event |
|---|---|---|
| 01:18:21 | 100130 ×4 (10) | FIM: `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` written by `/usr/sbin/useradd` |
| 01:18:22 | 5902 / 5901 (8) | New user `eviluser` (UID 1002) and its group created |
| 01:18:46 | **100114 (13)** | `usermod: add 'eviluser' to group 'sudo'` — new account granted admin within 10 min |
| 01:19:10 | **100110 (12)** | `useradd -o -u 0 backdoor` — a second **UID-0** account created |
| (each step) | 5402 (3) | The `sudo` command line showing operator, TTY and working directory |
| 01:21:57 | 5903 (3) | `userdel -r eviluser` (first cleanup) |
| 01:24:49 | 5402 (3) | `userdel backdoor` **refused** — no delete event |
| 01:30:09 | 5903 + 100130 ×4 | `userdel -f backdoor` — account, group and shadow entry removed |
| 01:33–01:34 | 100131 ×2 each (12) | `sed -i.bak` on `/etc/passwd` and `/etc/shadow` (final check; content already clean) |

## Analysis
**What happened.** The administrator account created a standard user (`eviluser`), immediately elevated it into the `sudo` group, and separately created a UID-0 account (`backdoor`). A UID-0 account is root in all but name: the kernel authorises by numeric UID, so `backdoor` has full root privilege regardless of its username.

**How it was detected.** The headline alert, rule 100114 (level 13), is a custom correlation rule: a new-account event (5902) followed within ten minutes by that user being added to a privileged group. Wazuh has **no built-in rule** for `usermod -aG sudo`, so without this custom rule the escalation would have passed at low severity. The UID-0 account was caught separately by custom rule 100110 (level 12), which keys on `UID=0` in a new-user event.

**Why some expected rules did not appear as separate alerts.** Wazuh reports one alert per event, from the deepest matching rule:
- The `usermod` line matched 100111 → 100112 → **100114**, so only 100114 fired. Rule 100112 fires on its own only when an *existing* account is added to sudo with no recent new-account event.
- The `backdoor` creation produced **100110**, not 5902, because 100110 is a child of 5902.

**Attribution.** Every step carries a rule 5402 event naming the operator, TTY and path, and the FIM alerts carry `syscheck.audit.login_user.name` — the human behind `sudo`. All activity traced to the host's own admin account.

## Detection context
Triage query (Threat Hunting):
```
agent.name:soc-victim-01 and rule.id:(5901 or 5902 or 5903 or 100110 or 100112 or 100114 or 100130 or 100131)
```
"Who ran it": `rule.id:5402 and data.command:*user*` → `data.srcuser`, `data.tty`.

On-host confirmation:
```bash
awk -F: '$3==0 {print $1}' /etc/passwd    # expect: root only
getent group sudo                          # expect: the admin only
sudo journalctl _COMM=useradd _COMM=usermod _COMM=userdel --since today --no-pager
```

## Containment and remediation
1. Removed `eviluser` (`userdel -r`).
2. Removed the UID-0 `backdoor` account — a plain `userdel` **refused** because a UID-0 account counts as the owner of running root processes (including PID 1); `userdel -f` was required.
3. Confirmed both accounts were removed via their `userdel` (rule 5903). Recommended on-host verification (to run after cleanup): `awk -F: '$3==0' /etc/passwd` should show only `root`, and `getent group sudo` should show only the admin.
4. Deleted the `.bak` files left by `sed -i.bak` — `/etc/shadow.bak` was a copy of the password hashes.

## Lessons learned
- **Custom rules closed a real gap.** `usermod -aG sudo` and UID-0 account creation have no built-in Wazuh rule; the privilege escalation would otherwise have been near-silent.
- **Detection gap — direct file edits.** An account added by editing `/etc/passwd` directly (no `useradd`) raises no 5902, only FIM 100131 ("sensitive file changed by a non-account tool"). An analyst must treat 100131 on `/etc/passwd` as a possible account change, not just a file edit.
- **Detection gap — password set via `chpasswd`/`passwd`** on the new account is covered only by 5555, not the account rules.
- **Operational note.** Removing a UID-0 backdoor is awkward and may fail on the first attempt; confirm with `awk -F: '$3==0' /etc/passwd` rather than trusting `userdel`'s exit.
- **False positive.** Legitimate admin onboarding produces the identical 100114 L13; in a real environment this should be reconciled against a change ticket.

## Linked material
- Attacker steps: [`../simulations/02-local-account-creation.md`](../simulations/02-local-account-creation.md)
- Detection logic: [`../detections/02-local-account-creation.md`](../detections/02-local-account-creation.md)
