# 02: Local account creation

- **ATT&CK technique:** T1136.001 Create Account: Local Account (related: T1098 Account Manipulation)
- **Rule type:** Built-in Wazuh rules 5902, 5901, 5555, 5904, 2961, 550 / Custom rules 100110–100115
- **Simulation:** [`../simulations/02-local-account-creation.md`](../simulations/02-local-account-creation.md)

## Logic

An attacker with root creates a backdoor account (`useradd` / `adduser`), sets a password, and usually gives it sudo rights (`usermod -aG sudo` or `gpasswd -a`). Two independent sources see this:

1. **Logs (journald):** `useradd`, `groupadd`, `passwd`, `chfn`, `usermod`, `gpasswd` all log to the journal.
2. **FIM (who-data):** `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` change. passwd/group have content diffs; shadow/gshadow are watched **without** diffs (`nodiff`, so no password hashes reach the SIEM).

Built-in, already seen live when `labuser` was created on 2026-11-04 (5901, 5902, 5555, 5904, 550 on `/etc/group`):

| Rule | Level | Matches | Fields |
|---|---|---|---|
| 5901 | 8 | `^new group` (groupadd / useradd's own group) | `dstuser` (group name), `gid` |
| **5902** | **8** | `^new user\|^new account added` (useradd) | `dstuser`, `uid`, `gid`, `home`, `shell` |
| 5555 | 3 | PAM `: password changed for` | `dstuser` |
| 5904 | 8 | `^changed user` (chfn, e.g. adduser's full-name prompt) | `dstuser` |
| 2960 / 2961 | 2 / 5 | gpasswd `added by` / group `sudo` | `dstuser`, `srcuser`, `group` |
| 550 | 7 | FIM: checksum changed (`/etc/passwd`, `/etc/group`, `/etc/shadow`, …) | `syscheck.path`, `syscheck.audit.login_user.name` |

Gaps found with wazuh-logtest:
- **`usermod -aG sudo X` matches no rule at all.** It logs `usermod[PID]: add 'X' to group 'sudo'`; the built-in group-add rules only decode `gpasswd`.
- A **UID 0** account (a second root) is only level 8, the same as any new user.
- `gpasswd -a X sudo` (2961) is only level 5.
- Nothing links "new user" with "given admin rights".

Custom rules:

| Rule | Level | Matches |
|---|---|---|
| 100110 | 12 | child of 5902, `UID=0,` in the message |
| 100111 | 5 | program `usermod`, `^add '…' to group '…'` |
| 100112 | 12 | child of 100111, group is `sudo`, `admin`, `wheel`, `adm`, `lxd` or `docker` |
| 100113 | 12 | child of 2960 (gpasswd), same privileged groups (field `group`) |
| **100114** | **13** | 100112 or 100113 within 10 min after a 5902 (new user) |
| **100115** | **14** | 100112 or 100113 within 10 min after a 100110 (new UID 0 user) |

`lxd` and `docker` are in the list because membership is root-equivalent on Ubuntu; `adm` reads all logs. The `add 'X' to shadow group 'sudo'` line that usermod also writes doesn't match (the regex anchors on `to group`), so one command gives one alert.

Limitation: the usermod line isn't decoded (no built-in decoder), so 100111/100112 have no `dstuser` field: the user name is in `full_log`. For the same reason **100114/100115 correlate per agent, not per user**: "any new account, then anyone added to sudo, within 10 minutes". Seen in testing: a sudo-group add for one user was raised as 100115 because a *different* UID 0 account had been created minutes earlier. For an analyst that's still the right call (both need looking at), but check the names in `full_log`. A local decoder for usermod would allow `same_dstuser`; not needed for the lab.

## Rule

From [`../configs/wazuh-rules/local_rules.xml`](../configs/wazuh-rules/local_rules.xml) (100113 and 100115 follow the same pattern):

```xml
<rule id="100110" level="12">
  <if_sid>5902</if_sid>
  <regex type="pcre2">UID=0,</regex>
  <description>SOC lab: new local account $(dstuser) created with UID 0 (root-equivalent).</description>
</rule>

<rule id="100111" level="5">
  <program_name>^usermod$</program_name>
  <regex type="pcre2">^add '([^']+)' to group '([^']+)'</regex>
  <description>SOC lab: usermod added a user to a group.</description>
</rule>

<rule id="100112" level="12">
  <if_sid>100111</if_sid>
  <regex type="pcre2">to group '(sudo|admin|wheel|adm|lxd|docker)'$</regex>
  <description>SOC lab: user added to a privileged group by usermod.</description>
</rule>

<rule id="100114" level="13" timeframe="600">
  <if_sid>100112,100113</if_sid>
  <if_matched_sid>5902</if_matched_sid>
  <description>SOC lab: new local account created and added to a privileged group within 10 minutes.</description>
</rule>
```

## Testing

**wazuh-logtest, 2026-11-06** (built-in on the live manager, custom rules in the offline sandbox container; see 01 for the method):

| Input (journald format) | Built-in only | With custom rules |
|---|---|---|
| `useradd[4101]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0` | 5902 L8 | 5902 L8 |
| `usermod[4102]: add 'backdoor' to group 'sudo'` (right after) | **no alert** | **100114 L13** |
| `usermod[4103]: add 'backdoor' to group 'users'` | no alert | 100111 L5 |
| `usermod[…]: add 'backdoor' to shadow group 'sudo'` | no alert | no alert (by design) |
| `gpasswd[4003]: user svc-backup added by root to group sudo` | 2961 L5 | 100113 L12 |
| `useradd[4001]: new user: name=svc-backup, UID=0, GID=0, …` | 5902 L8 | **100110 L12** |
| …then `usermod: add 'root2' to group 'sudo'` | no alert | **100115 L14** |

FIM on `/etc/passwd` is covered by detection 04 (rule 100130 / 100131), tested there.

### Live run, 2026-11-10

Run by the admin through sudo, about 01:18 UTC (commands confirmed from the sudo `COMMAND` lines): `useradd -m -s /bin/bash eviluser`, then `usermod -aG sudo eviluser`, then `useradd -o -u 0 backdoor`. No `-g` was given, so `backdoor` got its own new group (GID 1003, hence the second 5901); UID 0 is what matters.

| Time (UTC) | Alert | What |
|---|---|---|
| 01:18:22 | 5901 L8, 5902 L8 | `new group: name=eviluser` / `new user: name=eviluser, UID=1002` |
| 01:18:21 | **100130 L10** ×4 | FIM on `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`. `syscheck.audit.process.name: /usr/sbin/useradd`, `login_user.name: <admin>` |
| 01:18:46 | **100114 L13** | `usermod[2165]: add 'eviluser' to group 'sudo'`: new account plus sudo within 10 minutes |
| 01:18:45 | 100130 L10 ×2 | FIM on `/etc/group`, `/etc/gshadow` by `/usr/sbin/usermod` |
| 01:19:10 | 5901 L8, **100110 L12** | `new user: name=backdoor, UID=0, GID=1003`: second root account |
| 01:19:10 | 100130 L10 ×4 | FIM on the account files by `useradd` |
| each step | 5402 L3 | the admin's sudo commands |
| 01:21:55 | 100130 L10 ×4, **5903 L3** | cleanup `userdel -r eviluser`: FIM on the 4 account files by `/usr/sbin/userdel`, then `delete user 'eviluser'`. The other 10 FIM alerts (lock files, `-` backups, subuid/subgid) were built-in 550/553/554 |
| 01:30:07 | 100130 L10 ×4, **5903 L3** (01:30:09) | cleanup of `backdoor`: a plain `userdel backdoor` at 01:24:47 was refused (no delete line logged; a UID 0 account counts as the owner of root's processes). `userdel -f backdoor` then worked: `delete user 'backdoor'` plus its group. Two later `sed -i.bak '/^backdoor:/d' /etc/passwd /etc/shadow` runs found nothing left to delete, but still rewrote the files, so they fired 100131. See [04](04-sensitive-file-tampering.md) |

No 100131: every write was by `useradd`/`usermod`, which are exempt, as designed. No 100115: the UID 0 account came *after* the sudo-group add, and nobody was added to a privileged group afterwards.

**Why there's no separate 100112 alert:** Wazuh gives each event one alert, from the deepest rule in the chain that matches. 100114 is a child of 100112 (`<if_sid>100112,100113</if_sid>` plus `<if_matched_sid>5902</if_matched_sid>`), so the usermod line went 100111 → 100112 → 100114 and was reported as 100114. 100112 fires on its own only when an *existing* account is added to a privileged group with no new user in the last 10 minutes. The same line in wazuh-logtest without a preceding 5902 gives 100112 L12. The correlation rule takes the place of the single-event rule; nothing is lost, and the alert's `full_log` still holds the usermod line.

**FIM noise seen in the run:** each `useradd` also gave about 15 lower alerts: 554/553 L5/L7 for the `.lock` files (`/etc/passwd.lock`, `/etc/group.lock`, …), 550 L7 for the backup copies (`/etc/passwd-`, `/etc/shadow-`, …) and `/etc/subuid`/`/etc/subgid`, plus 517 L7 "Audit rule removed". The 517 appears because useradd replaces the file with a new one, so the who-data watch is re-created. See tuning below.

Not exercised live (covered by wazuh-logtest above): 100111 (non-privileged group), 100113 (gpasswd), 100115.

## How to verify

**Dashboard:**

```
agent.name:soc-victim-01 and rule.id:(5901 or 5902 or 5555 or 5904 or 2961 or 100110 or 100111 or 100112 or 100113 or 100114 or 100115 or 550 or 100130)
```

Expected for "create `backdoor`, set a password, add to sudo":
- **5901** + **5902**: `data.dstuser: backdoor`, `data.uid`, `data.home`, `data.shell`;
- **5555**: `data.dstuser: backdoor` (password set);
- **100114** (L13): `full_log` contains `add 'backdoor' to group 'sudo'`;
- **550 / 100130** on `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` with `syscheck.audit.login_user.name: <admin>` (the human behind sudo) and `syscheck.audit.process.name` = `/usr/sbin/useradd` / `usermod`. `syscheck.diff` on `/etc/passwd` shows the new line; none on shadow (by design).

**Indexer:** same `curl` as in [01](01-ssh-brute-force.md#how-to-verify), with this rule list and `_source` adding `data.dstuser`, `data.uid`, `syscheck.path`, `syscheck.audit.login_user.name`.

**Endpoint cross-check:**

```bash
# [VM]
getent passwd | awk -F: '$3==0 || $3>=1000'
getent group sudo
```

## False positives and tuning

- **Legitimate admin work** (adding a real user, installing docker, which creates the `docker` group and may add the admin to it) triggers the same alerts. In the lab that's rare and should be logged in the simulation notes. In production you'd suppress by change-ticket window, not by rule.
- **Package installs** create system users and groups (`systemd-*`, `_apt`, `tss`, …): they give 5901/5902 with UID < 1000 and `shell=/usr/sbin/nologin`. A child rule at level 3 for `shell=/usr/sbin/nologin` would cut this noise; not added, because an attacker could create a nologin account and change the shell later (5904 would then fire).
- **100114's 10-minute window** misses an attacker who waits. The building blocks (5902, 100112) still alert separately at 8 and 12.
- **Lock and backup files (seen live):** about 15 alerts per `useradd` for `*.lock`, `/etc/*-` backups and `subuid`/`subgid`, at level 5–7. The real files (passwd, shadow, group, gshadow) already raise 100130 at level 10, so these add nothing. Suggested endpoint-side fix in `agent.conf`: `<ignore type="sregex">^/etc/[a-z]+\.lock$</ignore>`. The `-` backups can stay: they're a second copy of the evidence, and an attacker editing `/etc/shadow-` directly would be unusual but worth seeing.
- **517 "Audit rule removed"** follows every passwd/group rewrite (the file is replaced, so the watch is re-added). It's expected and harmless. On its own, without account changes around it, it could mean someone is tampering with auditd.
- **`adduser` interactive** gives 5904 (chfn, full name) and 5555 as part of normal creation: expected, not separate findings.
