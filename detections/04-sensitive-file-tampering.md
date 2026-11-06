# 04: Sensitive file tampering

- **ATT&CK technique:** T1565.001 Data Manipulation: Stored Data Manipulation
- **Rule type:** Built-in Wazuh rules 550, 553, 554 / Custom rules 100130, 100131 (and 100132/100133 for sudoers, shared with 05)
- **Simulation:** [`../simulations/04-sensitive-file-tampering.md`](../simulations/04-sensitive-file-tampering.md)

## Logic

An attacker edits a system file to change how the machine behaves: an extra line in `/etc/hosts` to redirect a domain, a weakened `/etc/ssh/sshd_config`, a PAM change that accepts any password, an edited `/etc/passwd`, a library in `/etc/ld.so.preload`.

FIM watches all of `/etc` with who-data ([`agent.conf`](../configs/endpoint/agent.conf)): every change gives built-in **550** (modified, L7), **554** (added, L5) or **553** (deleted, L7) within seconds, with the process and the human login user. Account, sudo and cron files also carry a content diff. The rest of `/etc` has no diff on purpose: it also holds private keys and network secrets.

The problem is volume, not coverage: **550 fires for every file in `/etc`**, including every package upgrade (seen live: `dpkg` writing `/etc/logrotate.d/*`, `/etc/apt/apt.conf.d/*` during unattended-upgrades). So the custom rules pick out the files that matter, then the changes that weren't made by the package manager or the account tools.

| Rule | Level | Matches |
|---|---|---|
| 550 / 553 / 554 | 7 / 7 / 5 | FIM: any monitored file modified / deleted / added |
| **100130** | **10** | 550/553/554 on `/etc/passwd`, `shadow`, `group`, `gshadow`, `hosts`, `ssh/sshd_config`, `ssh/sshd_config.d/*`, `pam.d/*`, `security/*`, `ld.so.preload` |
| **100131** | **12** | child of 100130, and the writing **process** is not `dpkg`, `apt`, `apt-get`, `useradd`, `usermod`, `userdel`, `groupadd`, `groupmod`, `groupdel`, `gpasswd`, `passwd`, `chpasswd`, `chage`, `chfn`, `chsh`, `systemd-sysusers` |
| 100132 | 12 | 550/553/554 on `/etc/sudoers` or `/etc/sudoers.d/*` (see [05](05-sudo-abuse.md)) |
| 100133 | 14 | child of 100132, diff contains `NOPASSWD` or `ALL=(ALL` |

Notes on 100131:
- `python3` is **not** exempt. In the live upgrade alerts the writing process was `/usr/bin/dpkg`, with `python3.12` (unattended-upgrades) only as its parent. So a Python script writing `/etc/passwd` still alerts.
- `adduser`/`deluser` aren't listed: they're Perl wrappers, and the write is done by `useradd`/`userdel`.
- If who-data isn't working (agent fell back to realtime, see endpoints.md 5.3) there's no `process_name`, and only 100130 fires.

## Rule

From [`../configs/wazuh-rules/local_rules.xml`](../configs/wazuh-rules/local_rules.xml):

```xml
<rule id="100130" level="10">
  <if_sid>550,553,554</if_sid>
  <field name="file" type="pcre2">^/etc/(passwd|shadow|group|gshadow|hosts|ssh/sshd_config(\.d/.*)?|pam\.d/.*|security/.*|ld\.so\.preload)$</field>
  <description>SOC lab: sensitive system file added, changed or deleted: $(file).</description>
  <mitre><id>T1565.001</id></mitre>
</rule>

<rule id="100131" level="12">
  <if_sid>100130</if_sid>
  <field name="process_name" negate="yes" type="pcre2">/(dpkg|apt|apt-get|useradd|usermod|userdel|groupadd|groupmod|groupdel|gpasswd|passwd|chpasswd|chage|chfn|chsh|systemd-sysusers)$</field>
  <description>SOC lab: sensitive file $(file) changed outside package or account tools, by $(process_name) (login user $(audit_name)).</description>
  <mitre><id>T1565.001</id></mitre>
</rule>
```

FIM field names in rules: `file` = `syscheck.path`, `process_name` = `syscheck.audit.process.name`, `audit_name` = `syscheck.audit.login_user.name`, `changed_content` = `syscheck.diff`.

## Testing

**Sandbox only, 2026-11-06.** wazuh-logtest can't take FIM events, so synthetic who-data FIM events were sent into the analysis queue of the offline sandbox manager (`wazuh/wazuh-manager:4.14.9`, no network, this `local_rules.xml`), and `alerts.json` was read back. The live manager was not touched.

| Synthetic FIM event | Alert |
|---|---|
| `/etc/hosts` modified by `/usr/bin/tee`, login user `<admin>` | **100131 L12** (description shows process and login user) |
| `/etc/passwd` modified by `/usr/bin/vim.basic`, login user `<admin>` | **100131 L12** |
| `/etc/passwd` modified by `/usr/sbin/useradd` | 100130 L10 |
| `/etc/shadow` modified by `/usr/bin/dpkg`, no login user | 100130 L10 |
| `/etc/sudoers.d/90-labuser` added by `/usr/bin/tee` | 100132 L12 |
| `/etc/sudoers` modified by `visudo`, diff `> labuser ALL=(ALL) NOPASSWD:ALL` | **100133 L14** |
| `/etc/logrotate.d/apt` modified by dpkg (control: not a sensitive file) | 550 L7 |
| `/etc/passwd` modified by `/usr/bin/python3.12` (script, not dpkg) | **100131 L12** |
| `/etc/hosts` modified, `mode: realtime`, no who-data | 100130 L10 (no process, so 100131 can't decide) |

Live result from the simulation run: _to be added after the run with Aidil._

## How to verify

**Dashboard** (File Integrity Monitoring → Events, or Threat Hunting):

```
agent.name:soc-victim-01 and rule.id:(100130 or 100131 or 100132 or 100133)
```

Before the custom rules are loaded, use the built-in IDs and the path instead: `agent.name:soc-victim-01 and rule.id:(550 or 553 or 554) and syscheck.path:"/etc/hosts"`.

Expected for "append a line to `/etc/hosts` with `sudo tee -a`":
- **100131** (L12): `syscheck.path: /etc/hosts`, `syscheck.event: modified`, `syscheck.mode: whodata`, `syscheck.audit.process.name: /usr/bin/tee`, `syscheck.audit.login_user.name: <admin>`, `syscheck.audit.effective_user.name: root`, `syscheck.changed_attributes` (size, mtime, hashes);
- no `syscheck.diff` for `/etc/hosts` (only account/sudo/cron paths have `report_changes`). If the simulation needs the diff, add `/etc/hosts` to the `report_changes` line in agent.conf (endpoint branch).

**Indexer:** same `curl` as in [01](01-ssh-brute-force.md#how-to-verify), with this rule list and `_source` adding `syscheck.path`, `syscheck.event`, `syscheck.audit.process.name`, `syscheck.audit.login_user.name`, `syscheck.sha256_after`.

**Endpoint cross-check:** compare with the package's copy, e.g. `sudo dpkg --verify openssh-server` or `debsums -c` (if installed), and `ls -l --time-style=full-iso /etc/hosts`.

## False positives and tuning

- **Package upgrades** touching `/etc/pam.d/*`, `/etc/ssh/sshd_config` or `/etc/security/*`: 100130 L10 with `process.name: /usr/bin/dpkg`, never 100131. Expected after `apt upgrade`; check the time against `/var/log/dpkg.log` (rules 2902/2904 fire at the same time).
- **Admin editing by hand** (`sudo vim /etc/hosts`) gives 100131 L12. That's the point: hand edits of these files should be rare and explainable. In the lab, write the reason in the simulation notes.
- **Netplan / cloud-init / systemd-resolved** can rewrite `/etc/hosts` on some installs. Not seen on soc-victim-01 so far. If it happens, exempt the exact process for `/etc/hosts` only in a child rule.
- **`/etc/shadow` on password change** is expected from `passwd` (exempt), and 5555 fires at the same time.
- The **12-hour scheduled scan** re-reports nothing that who-data already sent. Changes made while the agent was stopped show up at the next scan as `mode: scheduled`, without process or user: treat those as "who unknown", not as benign.
