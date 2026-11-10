# 05: Sudo abuse

- **ATT&CK technique:** T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **Target:** soc-victim-01 (192.168.64.2)
- **Date run:** 2026-11-10

## Goal
Two sides of sudo misuse: a user with no sudo rights repeatedly trying to use it (reconnaissance / brute attempt), and a legitimate sudoer abusing an allowed tool to spawn a root shell ("living off the land"). The SIEM must flag both.

## Pre-check
```bash
# [VM] confirm labuser has no sudo rights, so attempts are genuinely denied
sudo -l -U labuser     # expect: "User labuser is not allowed to run sudo on soc-victim-01"
```

## Steps
```bash
# Part A [Mac -> VM as labuser] unauthorized sudo attempts (enter labuser's real password each time)
ssh labuser@192.168.64.2
sudo id        # repeat several times within 5 minutes

# Part B [VM as <admin>] abuse sudo to spawn a root shell
sudo bash -c id
```

## Expected evidence
A "not in sudoers" alert per denied attempt, escalating when repeated; a separate alert when sudo runs a shell / GTFOBins-style binary.

## Result (live, 2026-11-10)
| Rule | Level | Detail |
|---|---|---|
| **100140** | **8** | custom: labuser tried sudo but is not in sudoers (`cmd=/usr/bin/id`) |
| **100141** | **12** | custom: repeated sudo attempts by labuser (3 denials in 5 min; replaces 100140 on the 3rd, like 100114 in sim 02) |
| **100142** | **8** | custom: sudo ran a shell — `cmd=/usr/bin/bash -c id`, user `<admin>` |

> A wrong password at the prompt would instead produce 5401/5404 (auth failures); labuser used the correct password so the events were genuine "not in sudoers" denials (100140).

## Finding: endpoint clock skew
During this run the VM clock was ~21 minutes slow (systemd-timesyncd had been timing out, synced mid-run), so early events showed one time in the raw log and another in the alert. **Build timelines from the Wazuh alert timestamp, not the endpoint's log clock.** A pre-run clock check is now in [`../docs/endpoints.md`](../docs/endpoints.md).

## Linked detection
[`../detections/05-sudo-abuse.md`](../detections/05-sudo-abuse.md)
