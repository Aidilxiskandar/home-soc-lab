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

Live result from the simulation run: _to be added after the run with Aidil._

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
- **`adduser` interactive** gives 5904 (chfn, full name) and 5555 as part of normal creation: expected, not separate findings.
