# Endpoints: victim VM and Wazuh agents

> **Status (Phase 1 complete, 2026-11-05):** steps 1–6 were run on soc-victim-01: enrolled, Active, group config synced, log source journald, who-data on, lab SSH set up, clean clone `soc-victim-01-clean` kept. Dashboard check 7 (FIM who-data) passed: `/etc/cron.d/soc-lab-test` gave rule 554 (added) then 553 (deleted), mode whodata, with the admin as login user. **Step 7 (mac-host) is deferred and optional.** Steps still marked **(verify)** haven't been run yet. Open items for Phase 2 are under "Still to confirm" at the end.

How to build the lab's victim machine and connect both endpoints to Wazuh.

**Where to type each command.** Every code block starts with a comment saying where it runs:
- `# [Mac]`: Terminal on the Mac.
- `# [VM]`: on soc-victim-01. Best over SSH from Mac Terminal (`ssh <admin>@<VM IP>`), because pasting into the UTM console window is unreliable. Use the UTM console only before SSH works, or when a step says so.

Commands are kept short, one per line, so they don't break when copied.

| Endpoint | What | Wazuh agent name | Wazuh group |
|---|---|---|---|
| Victim VM | Ubuntu Server 24.04 LTS (arm64) in UTM | `soc-victim-01` | `linux-victims` |
| Mac host | macOS on Apple Silicon (the lab laptop) | `mac-host` | `default` |

Prerequisite: the Wazuh stack from [`setup.md`](setup.md) is running (`docker compose ps` shows all three containers up).

## Network layout

```
 Mac (host)                                     UTM "Shared Network" (NAT), 192.168.64.0/24
 ┌────────────────────────────────────┐        ┌───────────────────────────────────┐
 │ Docker: wazuh.manager              │ 1514   │ soc-victim-01                     │
 │   1514/tcp agent events  ◄─────────┼────────┤   Wazuh agent                     │
 │   1515/tcp enrolment     ◄─────────┼────────┤   gateway = 192.168.64.1 (the Mac)│
 │                                    │ 1515   │   IP from UTM DHCP, 192.168.64.x  │
 │ mac-host agent ──► 127.0.0.1:1514  │        │   sshd :22 (lab only)             │
 └────────────────────────────────────┘        └───────────────────────────────────┘
```

- The VM reaches the Mac at the **gateway address of UTM's shared network**, normally `192.168.64.1` (macOS creates it on interface `bridge100` while a VM is running).
- Docker Desktop publishes ports 1514/1515 on all Mac interfaces, so the manager is reachable at `192.168.64.1:1514` from the VM and at `127.0.0.1:1514` from the Mac itself.
- Shared Network is NAT: the VM can reach the internet (for `apt`), but devices on the Wi-Fi cannot reach the VM. Don't add UTM port forwards.
- **The manager doesn't see real agent IPs.** Docker Desktop NATs incoming connections, so the manager sees every agent coming from `192.168.65.1` and lists the agent IP as `any`. Identify endpoints by **agent name** (`agent.name`), not IP. (Source IPs *inside* log lines, such as the attacker IP in an sshd failure, are unaffected.)

## Resource budget

| | RAM |
|---|---|
| Docker (Wazuh) | 8 GB |
| soc-victim-01 | 2 GB (raise to 3 GB only if it swaps) |
| macOS + apps | ~6 GB |

---

## 1. Install UTM and get the Ubuntu ISO

```bash
# [Mac]
brew install --cask utm
```

Download **Ubuntu Server 24.04 LTS for ARM** (`ubuntu-24.04.x-live-server-arm64.iso`) from <https://ubuntu.com/download/server/arm>. Check its SHA-256 against the `SHA256SUMS` file on the same release page:

```bash
# [Mac]
shasum -a 256 ~/Downloads/ubuntu-24.04.*-live-server-arm64.iso
```

## 2. Create the VM in UTM

1. **Create a New Virtual Machine → Virtualize → Linux.** (Never "Emulate": the CPU is ARM, so virtualisation is native and fast.)
2. Leave **Use Apple Virtualization** unticked (QEMU backend). Boot ISO image: the ISO from step 1.
3. Hardware: **2 CPU cores, 2048 MB memory**.
4. Storage: **20 GB** or more (the first build used ~30 GB; either is fine).
5. Shared directory: none.
6. Name: **`soc-victim-01`**. Before saving, tick **Open VM settings**.
7. In settings → **Network**: Network Mode = **Shared Network**. Save.

## 3. Install Ubuntu Server

Start the VM and go through the installer:

| Screen | Choice |
|---|---|
| Installation type | Ubuntu Server (not minimized) |
| Network | Accept DHCP (you should see a `192.168.64.x` address) |
| Storage | Use entire disk (default LVM is fine) |
| Profile | Server name **`soc-victim-01`**. Username: your own admin account (with sudo), e.g. your usual login name. This guide calls it `<admin>`. Use a strong, unique password. |
| Ubuntu Pro | Skip |
| SSH | Tick **Install OpenSSH server**. Leave "Import SSH identity" off. |
| Featured snaps | None |

When it finishes, shut down, then in UTM **clear the CD/DVD drive** (remove the ISO) and boot again.

Then update and set the time zone. The admin account should already be able to log in over SSH (Ubuntu allows password login by default), so from here on you can work from Mac Terminal: `ssh <admin>@<VM IP>` (the IP is shown on the VM's login screen, or run `ip -4 addr` in the console).

```bash
# [VM]
sudo apt update && sudo apt full-upgrade -y
sudo timedatectl set-timezone Asia/Kuala_Lumpur
sudo reboot
```

> **Baseline copy:** shut the VM down and use UTM's **Clone** to keep a clean copy (`soc-victim-01-clean`). If a simulation breaks the VM, delete it and clone again.

## 4. Check the VM can reach the manager

```bash
# [VM]
ip -4 addr show                      # the VM's own 192.168.64.x address
ip route | grep default              # "default via 192.168.64.1": this is the Mac
nc -vz 192.168.64.1 1515             # enrolment port: "succeeded"
nc -vz 192.168.64.1 1514             # event port: "succeeded"
```

Then confirm the same address from the Mac side (while the VM is running):

```bash
# [Mac]
ifconfig bridge100 | grep 'inet '    # expect: inet 192.168.64.1
```

If the gateway is not `192.168.64.1`, use whatever `ip route` shows in every step below. If `nc` fails: check `docker compose ps` on the Mac, and check that the macOS firewall (System Settings → Network → Firewall) allows incoming connections for Docker.

## 5. Install the Wazuh agent on soc-victim-01

> **Manager first:** run `./configs/wazuh/apply-manager-config.sh` on the Mac before this step. It sets the enrolment password and creates the `linux-victims` group. Without it, enrolment fails. See [`configs/endpoint/README.md`](../configs/endpoint/README.md) → Manager-side steps.

### 5.1 Prerequisites for the group config

```bash
# [VM]
sudo apt install -y auditd               # for FIM who-data and audit.log
sudo systemctl enable --now auditd
sudo journalctl -n 5 --no-pager          # journal works (the agent reads auth events from it)
```

### 5.2 Install agent 4.14.9 (arm64)

The agent version must not be newer than the manager (4.14.9).

Enrolment needs the **registration password**: the `WAZUH_REGISTRATION_PASSWORD` value in the git-ignored `configs/wazuh/.env` on the Mac (`setup.sh` generates it). Never paste it into a file in this repo.

**a) Copy the password to the Mac clipboard** without showing it. This runs on the **Mac**, not the VM (`pbcopy` doesn't exist on Ubuntu):

```bash
# [Mac], from the repo root
grep '^WAZUH_REGISTRATION_PASSWORD=' configs/wazuh/.env | cut -d= -f2- | pbcopy
```

**b) Download the agent** with a short file name:

```bash
# [VM]
cd /tmp
wget -O agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.9-1_arm64.deb
```

**c) Set the enrolment values, one line each.** At the password prompt, paste with Cmd+V (nothing is shown, and it stays out of shell history):

```bash
# [VM]
export WAZUH_MANAGER='192.168.64.1'
export WAZUH_AGENT_NAME='soc-victim-01'
export WAZUH_AGENT_GROUP='linux-victims'
read -rs -p 'Registration password: ' WAZUH_REGISTRATION_PASSWORD; echo
export WAZUH_REGISTRATION_PASSWORD
```

**d) Install,** passing those values through `sudo` with `-E`, then clear the password from the shell:

```bash
# [VM]
sudo -E dpkg -i ./agent.deb
unset WAZUH_REGISTRATION_PASSWORD
```

If the package was already installed once without these values, just run c) and d) again. Reinstalling over it enrols fine (seen on the first build).

**e) Start it and pin the version:**

```bash
# [VM]
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo apt-mark hold wazuh-agent           # stop apt upgrading it past the manager
```

Check it connected:

```bash
# [VM]
sudo grep -iE 'connected|error|warn' /var/ossec/logs/ossec.log | tail -20
sudo /var/ossec/bin/wazuh-control status
```

### 5.3 Check the group config arrived (verify)

After a few minutes the agent pulls `agent.conf` from the manager and restarts:

```bash
# [VM]
sudo ls -l /var/ossec/etc/shared/agent.conf        # present = group config received
sudo auditctl -l | grep wazuh_fim                  # who-data audit rules loaded
sudo grep -i whodata /var/ossec/logs/ossec.log | tail
```

If `auditctl` shows no `wazuh_fim` rules, who-data isn't active and the agent has fallen back to realtime monitoring. Alerts still arrive, but without the "who changed it" fields. Check the `ossec.log` lines for the reason.

### 5.4 One log source only (done on the first build)

The agent's **default** `ossec.conf` already reads the systemd journal (`<log_format>journald</log_format>`), and that's where Ubuntu 24.04 sends sshd, sudo and PAM messages. On the first build the group config also read `/var/log/auth.log`, so every event arrived twice, once from each source in the same second. The group config now reads only `audit.log`, and auth events come from journald.

To confirm there's no duplication after a rebuild:

```bash
# [VM]
sudo grep -n -A2 journald /var/ossec/etc/ossec.conf
```

Expect one journald `<localfile>` block, and no `auth.log` entry in `/var/ossec/etc/shared/agent.conf`. In the dashboard, one `sudo ls` gives **one** rule 5402 alert with `location: journald`.

## 6. Lab user and SSH password login (lab only)

Simulation 01 (ssh-brute-force, T1110.001) needs an account that accepts passwords over SSH.

> ⚠️ **Lab only.** Password SSH login is one of the most common ways real servers get compromised. It's acceptable here only because:
> - the VM sits behind UTM's NAT, so nothing outside this Mac can reach port 22;
> - `labuser` has no sudo rights and owns nothing of value;
> - its password is used **nowhere else** and is written only in your password manager, never in this repo.
>
> Never copy `10-lab-password-auth.conf` to a real machine. Never add a UTM port forward to port 22.

**a) Create the test user** (no sudo rights). Pick a password that *is* in a common wordlist but is used nowhere else:

```bash
# [VM]
sudo adduser labuser
```

**b) Copy the SSH drop-in to the VM.** It lives in this repo, not on the VM:

```bash
# [Mac], from the repo root
scp configs/endpoint/10-lab-password-auth.conf <admin>@<VM IP>:/tmp/
```

**c) Install it and restart SSH.** Keep this SSH session open until step d) passes. Restarting sshd doesn't drop sessions that are already open, so this window is your way back in:

```bash
# [VM]
sudo cp /tmp/10-lab-password-auth.conf /etc/ssh/sshd_config.d/
sudo sshd -t
sudo systemctl restart ssh
sudo sshd -T | grep -Ei 'passwordauth|permitroot|maxauthtries'
```

`sshd -t` prints nothing if the syntax is OK. Expected from the last line: `passwordauthentication yes`, `permitrootlogin no` and `maxauthtries 6`.

**d) Lockout check:** open a **second** Mac Terminal window and confirm both accounts can log in:

```bash
# [Mac], new window
ssh <admin>@<VM IP>
ssh labuser@<VM IP>
```

If the admin login fails, undo it from the session you kept open, then check `sudo sshd -T` again:

```bash
# [VM], the session from step c)
sudo rm /etc/ssh/sshd_config.d/10-lab-password-auth.conf
sudo systemctl restart ssh
```

(If no session is left, the UTM console window always works.)

Optional extra layer: allow SSH only from the lab subnet with the host firewall. The Mac is `192.168.64.1`, inside that range, so your session survives:

```bash
# [VM]
sudo ufw allow from 192.168.64.0/24 to any port 22 proto tcp
sudo ufw enable
```

(Simulation 05 sudo-abuse will need `labuser` to try `sudo` and fail. That is set up in `simulations/`, not here.)

## 7. Install the Wazuh agent on the Mac (mac-host): optional, deferred

> Not done in Phase 1. Phase 2 detections all target soc-victim-01. Do this step when host coverage is wanted.

Everything in this step runs on the **Mac**. The manager is reached through Docker's published port on localhost. The installer reads its settings from `/tmp/wazuh_envs`, so the steps below build that file a line at a time, then delete it.

**a) Download the agent:**

```bash
# [Mac]
cd /tmp
curl -L -o agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.9-1.arm64.pkg
```

**b) Write the settings file.** Copy the password to the clipboard first (step 5.2 a), then paste it at the prompt:

```bash
# [Mac]
read -rs 'P?Registration password: '; echo
E="WAZUH_MANAGER='127.0.0.1'"
E="$E && WAZUH_AGENT_NAME='mac-host'"
E="$E && WAZUH_REGISTRATION_PASSWORD='$P'"
(umask 077; echo "$E" > /tmp/wazuh_envs)
unset P E
```

(`read 'P?…'` is zsh, the Mac's default shell.)

**c) Install, delete the settings file, start:**

```bash
# [Mac]
sudo installer -pkg ./agent.pkg -target /
rm -f /tmp/wazuh_envs
sudo /Library/Ossec/bin/wazuh-control start
sudo /Library/Ossec/bin/wazuh-control status
```

Notes:
- `mac-host` stays in the `default` group with the default macOS config. FIM on macOS is scheduled scans only (no who-data or realtime), which is fine: the Phase 2 detections target the Ubuntu VM.
- macOS may ask to allow the agent in **System Settings → Privacy & Security** (verify). Some macOS log collection may need Full Disk Access for `/Library/Ossec/bin/wazuh-agentd` (verify).
- To stop it when not labbing: `sudo /Library/Ossec/bin/wazuh-control stop`.

## 8. Checks in the Wazuh dashboard

Open <https://localhost> and work through this list. Take a screenshot of each for `assets/`, and check each one for anything sensitive before committing.

| # | Check | Where | How to trigger | Expected |
|---|---|---|---|---|
| 1 | Both agents active | **Agents** (Endpoints summary) | – | `soc-victim-01` and `mac-host` show **Active**, version 4.14.9. IP shows `any`: expected, see Network layout |
| 2 | Victim is in the right group | Agent `soc-victim-01` → details | – | Group `linux-victims`, config **synced** |
| 3 | Auth events arriving | **Threat Hunting → Events**, filter `agent.name: soc-victim-01` and `location: journald` | From the Mac: `ssh labuser@<VM IP>` with a wrong password, once | sshd authentication-failure alert (rule group `authentication_failed`) |
| 4 | Other system logs arriving | Same, `location: journald` | On the VM: `logger "soc-lab test"` | Event visible in archives / a syslog alert if a rule matches. If nothing shows, that's normal: Wazuh only stores events that match a rule unless `logall` is on. Use check 3 instead as proof. |
| 5 | sudo logged | Events, `agent.name: soc-victim-01` | On the VM: `sudo ls` as `<admin>` | sudo alert (rule group `sudo`) |
| 6 | FIM on and baseline done | **File Integrity Monitoring** → `soc-victim-01` | Wait for first scan after enrolment | Inventory lists files under `/etc` and `/var/spool/cron` |
| 7 | FIM realtime/who-data | **File Integrity Monitoring → Events** | On the VM: `sudo touch /etc/cron.d/soc-lab-test` then `sudo rm /etc/cron.d/soc-lab-test` | "File added" then "File deleted" within seconds; `syscheck.audit.login_user.name` = `<admin>` if who-data works |
| 8 | No duplicates | Events for check 3 | – | One alert per failed login, not two (see 5.4) |
| 9 | Mac agent sending | Events, `agent.name: mac-host` | – | Any events (rootcheck, SCA or logs) |

When checks 1–8 pass (9 only if mac-host is installed), tick "Enrol agents" and "Confirm logs arrive" in the roadmap (coordinator updates the roadmap on `main`).

## Undo / reset

| Goal | How |
|---|---|
| Fresh victim | Delete `soc-victim-01` in UTM, clone `soc-victim-01-clean`, re-run steps 5–6. Remove the old agent on the manager first: `docker compose exec wazuh.manager /var/ossec/bin/manage_agents -r <ID>` |
| Remove Mac agent | `sudo /Library/Ossec/bin/wazuh-control stop`, then `sudo /bin/rm -r /Library/Ossec` and remove the launchd items as described in Wazuh's macOS uninstall docs |
| Turn SSH password login off | `sudo rm /etc/ssh/sshd_config.d/10-lab-password-auth.conf && sudo systemctl restart ssh` |

## Decisions (2026-11-04)

1. **Enrolment password: on.** Port 1515 is reachable from the Wi-Fi, so without a password any nearby device could enrol a fake agent while the lab runs. The manager uses `use_password yes`; the password lives only in the git-ignored `.env` (manager change made on the wazuh branch). Rejected: binding the ports to `192.168.64.1` only, because `bridge100` exists only while a UTM VM runs and Docker may fail to start.
2. **VM admin account:** the personal admin account created at install (written `<admin>` here, so no personal names go in the repo), separate from the unprivileged test user `labuser`. The SSH drop-in has no `AllowUsers` line, so it cannot lock the admin out.
3. **Log source: journald.** Step 5.4 found every auth event twice (15 from `/var/log/auth.log`, 19 from journald, same events at the same second). Kept journald, the agent default, so nothing is edited on the VM and it's all central config. Removed the `auth.log` and `syslog` inputs from `agent.conf`, and kept `audit.log`. Built-in rules decode journald events the same way (5402, 5501, 5502 seen, `data.command` filled in). Verified after applying: from 07:08:58 each sudo command gives exactly one 5402 alert (location journald); before that, every one was paired.

## Still to confirm when run

- **sshd fields from journald (Phase 2).** Confirm in check 3 that sshd failure alerts from journald carry `srcip` and `dstuser` (rules 5710/5760). If they don't, switch back: add `/var/log/auth.log` to `agent.conf` and remove the journald block from the VM's local `ossec.conf`. Partly answered: successful admin logins from journald already arrive as rule 5715 with `srcip` 192.168.64.1; failures not yet tested.
- **No 5715 for labuser's SSH login.** On the first build, logging in as `labuser` gave only 5502 (session closed), while admin logins gave 5715 (authentication success). Before simulation 01, log in once as `labuser` and look at the raw journald event to see whether the sshd "Accepted password" line arrives and which rule (if any) it matches. A brute force that *succeeds* needs this success alert to be detected.
- **`MaxAuthTries`.** Set to 6 in the drop-in (also sshd's default), but not re-checked with `sshd -T` after a typo in the grep. The simulation 01 run will confirm it (at most 6 failures per connection).
