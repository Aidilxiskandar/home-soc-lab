# 05: Sudo abuse

- **ATT&CK technique:** T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **Rule type:** Built-in Wazuh rules 5401, 5404, 5405, 5402, 5403, 5407, 5503 / Custom rules 100140–100142 (100143 proposed), 100132/100133 for sudoers
- **Simulation:** [`../simulations/05-sudo-abuse.md`](../simulations/05-sudo-abuse.md)

## Logic

Two halves:

1. **Trying to get root through sudo without the right to.** `labuser` isn't in sudoers. Each `sudo` attempt logs `labuser : user NOT in sudoers ; TTY=… ; COMMAND=…`. Wrong passwords log `N incorrect password attempts` plus a PAM `authentication failure` line.
2. **Using sudo to get a full root shell, or changing sudoers** (after a compromise, or to make it permanent): `sudo -i`, `sudo bash`, `sudo su -`, or shell escapes through an allowed program (`sudo vim` → `:!sh`, `sudo find … -exec /bin/sh`, `sudo less`, GTFOBins). And `/etc/sudoers` / `/etc/sudoers.d/*` edited to add `NOPASSWD` (covered by FIM, rules 100132/100133 in [04](04-sensitive-file-tampering.md)).

Built-in:

| Rule | Level | Matches | Fields |
|---|---|---|---|
| 5401 | 5 | `incorrect password attempt` | `srcuser`, `dstuser`, `command` |
| **5404** | **10** | `3 incorrect password attempts` | same |
| **5405** | 5 | `user NOT in sudoers` | same |
| 5406 | 5 | `command not allowed` (user in sudoers, but not for this command) | same |
| 5503 | 5 | PAM `authentication failure; logname=` from `sudo:auth` | `srcuser`, `dstuser` |
| 5402 | 3 | `; USER=root ; COMMAND=` (sudo to root worked) | `srcuser`, `command`, `tty`, `pwd` |
| 5403 | 4 | first time this user ran sudo (fires instead of 5402) | same |
| 5407 | 3 | sudo to a non-root user worked | same |
| 5501 | 3 | `pam_unix(sudo:session): session opened for user root` | `srcuser`, `dstuser` |

Gaps:
- **5405 is only level 5**, and nothing counts repeats. In this lab only the admin should ever use sudo, so a denied user is notable and repeated denials are an attack.
- **Root shells via sudo** are just 5402 L3, the same as `sudo apt update`.

Custom rules:

| Rule | Level | Matches |
|---|---|---|
| 100140 | 8 | child of 5405: user NOT in sudoers |
| **100141** | **12** | 3 × 100140 by the **same `srcuser`** in 5 min (`ignore=300`) |
| **100142** | **8** | child of 5402/5403/5407 where `command` starts with a shell or shell-escape binary: `bash`, `sh`, `dash`, `zsh`, `su`, `python*`, `perl`, `ruby`, `lua`, `vi`, `vim`, `nano`, `less`, `more`, `find`, `awk`, `env`, `tee`, `cp`, `dd` |
| 100143 | 12 | **proposed, commented out:** successful sudo by anyone not in a CDB list of lab admins |

100143 needs the admin account name in a CDB list (`etc/lists/soc-lab-admins` on the manager, plus a `<list>` line in `ossec.conf`). The name isn't written in this repo, so it's a manager-side step for the coordinator, if wanted.

## Rule

From [`../configs/wazuh-rules/local_rules.xml`](../configs/wazuh-rules/local_rules.xml):

```xml
<rule id="100140" level="8">
  <if_sid>5405</if_sid>
  <description>SOC lab: $(srcuser) tried sudo but is not in sudoers (command: $(command)).</description>
  <mitre><id>T1548.003</id></mitre>
  <group>authentication_failed,</group>
</rule>

<rule id="100141" level="12" frequency="3" timeframe="300" ignore="300">
  <if_matched_sid>100140</if_matched_sid>
  <same_srcuser />
  <description>SOC lab: repeated sudo attempts by $(srcuser), who is not in sudoers.</description>
  <mitre><id>T1548.003</id></mitre>
  <group>authentication_failures,</group>
</rule>

<rule id="100142" level="8">
  <if_sid>5402,5403,5407</if_sid>
  <field name="command" type="pcre2">^(\S*/)?(bash|sh|dash|zsh|su|python[0-9.]*|perl|ruby|lua|vi|vim|nano|less|more|find|awk|env|tee|cp|dd)(\s|$)</field>
  <description>SOC lab: sudo by $(srcuser) ran a shell or shell-escape binary: $(command).</description>
  <mitre><id>T1548.003</id><id>T1059.004</id></mitre>
</rule>
```

## Testing

**wazuh-logtest, 2026-11-06** (built-in on the live manager, custom rules in the offline sandbox container, see 01):

| Input (journald format) | Built-in | With custom |
|---|---|---|
| `sudo[4020]: labuser : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow` | 5405 L5 | **100140 L8** (`srcuser` labuser, `command`) |
| 2nd and 3rd such attempt within seconds | 5405 L5 | 100140, then **100141 L12** on the 3rd |
| `sudo[4021]: pam_unix(sudo:auth): authentication failure; logname=labuser … user=labuser` | 5503 L5 | 5503 L5 |
| `sudo[4021]: labuser : 3 incorrect password attempts ; … COMMAND=/usr/bin/id` | **5404 L10** | 5404 L10 |
| `sudo[4022]: labuser : TTY=pts/0 ; … USER=root ; COMMAND=/bin/bash` | 5403 L4 | **100142 L8** |
| `… USER=root ; COMMAND=/usr/bin/vim /etc/hosts` | 5402 L3 | 100142 L8 |
| `… USER=root ; COMMAND=/usr/bin/find . -exec /bin/sh ;` | 5402 L3 | 100142 L8 |
| `… USER=root ; COMMAND=/usr/bin/apt update` / `systemctl restart ssh` | 5403 / 5402 | unchanged (no false hit) |

Sudoers changes (100132 / 100133) were tested with synthetic FIM events: see [04](04-sensitive-file-tampering.md#testing).

Live result from the simulation run: _to be added after the run with Aidil._

## How to verify

**Dashboard:**

```
agent.name:soc-victim-01 and rule.id:(5401 or 5404 or 5405 or 5406 or 100140 or 100141 or 100142 or 100132 or 100133 or 5402 or 5403)
```

Expected for "labuser tries `sudo` 3 times, then the admin runs `sudo -i`":
- **100140** ×2 then **100141** (L12): `data.srcuser: labuser`, `data.dstuser: root`, `data.command`, `data.tty`, `location: journald`;
- sudo asks `labuser` for their own password first: a wrong password gives **5401**, three wrong gives **5404** (L10); the right password then gives the `NOT in sudoers` line;
- `sudo -i` by the admin: **100142** with `data.command: /bin/bash` (sudo logs the shell, not `-i`), `data.srcuser: <admin>`;
- any sudoers edit: **100132** / **100133** with `syscheck.diff` and `syscheck.audit.login_user.name`.

**Indexer:** same `curl` as in [01](01-ssh-brute-force.md#how-to-verify), with this rule list and `_source` adding `data.srcuser`, `data.dstuser`, `data.command`, `data.tty`.

**Endpoint cross-check:**

```bash
# [VM]
sudo journalctl _COMM=sudo --since "30 min ago" --no-pager
sudo -l -U labuser
```

## False positives and tuning

- **100142 will fire for the admin** on normal `sudo -i`, `sudo vim /etc/…` or `sudo cp`. That's on purpose at level 8: a root shell is worth a record, not a page. If it's too noisy, the CDB-list approach in 100143 is the better fix (lower 100142 for listed admins at a known TTY), rather than shortening the binary list.
- **`tee`, `cp`, `dd`** are on the list because they can overwrite root-owned files (GTFOBins "file write"). They're also common in admin one-liners (`echo … | sudo tee`). Drop them if 100142 gets noisy.
- **Mistyped admin password**: 5401 (L5); three in a row is 5404 (L10). Rare enough to leave as is.
- **100141 counts per `srcuser`**, not per TTY or source IP: a user hammering sudo from two sessions still adds up.
- **Not covered:** sudo caching abuse (reusing someone's cached ticket from the same TTY: no extra log line), and `pkexec` / setuid binaries (different techniques: T1548.001 and polkit). auditd `execve` from `audit.log` could cover those in Phase 3.
