# 01: SSH brute force

- **ATT&CK technique:** T1110.001 Brute Force: Password Guessing
- **Target:** soc-victim-01 (192.168.64.2), account `labuser`
- **Attacker:** the Mac host (192.168.64.1)
- **Date run:** 2026-11-06

## Goal
Guess an account's password over SSH by trying many passwords quickly. This is one of the most common ways internet-facing Linux hosts are compromised, so the SIEM must flag a run of failed logins from one source.

## Steps
`sshpass` and `hydra` are not installed, and `expect` hung when backgrounded in this environment. OpenSSH's `SSH_ASKPASS` helper submits a password non-interactively with no TTY, which is enough to produce real `Failed password` events on the server.

```bash
# [Mac] askpass helper that returns a wrong password each call
printf '#!/bin/sh\necho "wrongpw-$$-$(date +%s)"\n' > /tmp/askpass.sh && chmod +x /tmp/askpass.sh

# [Mac] 10 failed password attempts for labuser, ~one every 4s (server delay)
for i in $(seq 1 10); do
  SSH_ASKPASS=/tmp/askpass.sh SSH_ASKPASS_REQUIRE=force \
    ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 \
        -o ConnectTimeout=5 labuser@192.168.64.2 true </dev/null 2>&1
done
```

> First attempt (a weaker method) used plain `ssh` with no password submitted, which the server logged as `Connection closed by authenticating user` — **not** a password failure, so no brute-force rule fired. Lesson: the attack must actually submit a password, or there is nothing to detect.

## Expected evidence
`sshd: authentication failed` (5760) and the PAM equivalent (5503) per wrong password, each carrying the source IP; a burst/frequency alert once enough failures stack up from one IP.

## Result (live, 2026-11-06)
| Rule | Level | Count | Note |
|---|---|---|---|
| 5760 | 5 | 10 | each failed password, srcip 192.168.64.1, dstuser labuser |
| 5503 | 5 | 10 | PAM side of each failure |
| 5551 | 10 | 1 | PAM "multiple failed logins in a small period" |
| **100100** | **10** | 1 | custom: slow brute force, 10 failures from one IP in 15 min |

**5763 (built-in sshd burst) did not fire.** It shares a failed-login counter with the custom 100100; 4 earlier stray failures pushed 100100 to its 10-in-15-min limit first, consuming the count so 5763's 8-in-2-min window was never met. See [`../detections/01-ssh-brute-force.md`](../detections/01-ssh-brute-force.md) for the full analysis. Detection did not depend on 5763.

## Linked detection
[`../detections/01-ssh-brute-force.md`](../detections/01-ssh-brute-force.md)
