# Endpoints: victim VM and Wazuh agents

> **Status: DRAFT plan, not yet run.** Steps marked **(verify)** are expected to work but need to be confirmed on the real machine. Update this guide with what actually happened.

How to build the lab's victim machine and connect both endpoints to Wazuh.

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

## Resource budget

| | RAM |
|---|---|
| Docker (Wazuh) | 8 GB |
| soc-victim-01 | 2 GB (raise to 3 GB only if it swaps) |
| macOS + apps | ~6 GB |

---

## 1. Install UTM and get the Ubuntu ISO

```bash
brew install --cask utm
```

Download **Ubuntu Server 24.04 LTS for ARM** (`ubuntu-24.04.x-live-server-arm64.iso`) from <https://ubuntu.com/download/server/arm>. Check its SHA-256 against the `SHA256SUMS` file on the same release page:

```bash
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

Then update and set the time zone:

```bash
sudo apt update && sudo apt full-upgrade -y
sudo timedatectl set-timezone Asia/Kuala_Lumpur
sudo reboot
```

> **Baseline copy:** shut the VM down and use UTM's **Clone** to keep a clean copy (`soc-victim-01-clean`). If a simulation breaks the VM, delete it and clone again.

## 4. Check the VM can reach the manager

On the VM:

```bash
ip -4 addr show                      # the VM's own 192.168.64.x address
ip route | grep default              # "default via 192.168.64.1": this is the Mac
nc -vz 192.168.64.1 1515             # enrolment port: "succeeded"
nc -vz 192.168.64.1 1514             # event port: "succeeded"
```

On the Mac (while the VM is running), confirm the same address from the other side:

```bash
ifconfig bridge100 | grep 'inet '    # expect: inet 192.168.64.1
```

If the gateway is not `192.168.64.1`, use whatever `ip route` shows in every step below. If `nc` fails: check `docker compose ps` on the Mac, and check that the macOS firewall (System Settings → Network → Firewall) allows incoming connections for Docker.

## 5. Install the Wazuh agent on soc-victim-01

> **Manager first:** run `./configs/wazuh/apply-manager-config.sh` on the Mac before this step. It sets the enrolment password and creates the `linux-victims` group. Without it, enrolment fails. See [`configs/endpoint/README.md`](../configs/endpoint/README.md) → Manager-side steps.

### 5.1 Prerequisites for the group config

```bash
sudo apt install -y auditd rsyslog       # auditd for FIM who-data; rsyslog is usually already there
sudo systemctl enable --now auditd rsyslog
ls -l /var/log/auth.log /var/log/syslog  # both must exist
```

### 5.2 Install agent 4.14.9 (arm64)

The agent version must not be newer than the manager (4.14.9).

Enrolment needs the **registration password** set on the manager : the `WAZUH_REGISTRATION_PASSWORD` value in the git-ignored `configs/wazuh/.env` on the Mac (`setup.sh` generates it). Copy it from there and never paste it into a file in this repo; `read -s` keeps it out of the screen and shell history.

```bash
cd /tmp
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.9-1_arm64.deb

read -rs -p 'Wazuh registration password: ' REGPASS; echo
sudo WAZUH_MANAGER='192.168.64.1' \
     WAZUH_AGENT_NAME='soc-victim-01' \
     WAZUH_AGENT_GROUP='linux-victims' \
     WAZUH_REGISTRATION_PASSWORD="$REGPASS" \
     dpkg -i ./wazuh-agent_4.14.9-1_arm64.deb
unset REGPASS

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo apt-mark hold wazuh-agent           # stop apt upgrading it past the manager
```

Check it connected:

```bash
sudo grep -iE 'connected|error|warn' /var/ossec/logs/ossec.log | tail -20
sudo /var/ossec/bin/wazuh-control status
```

### 5.3 Check the group config arrived (verify)

After a few minutes the agent pulls `agent.conf` from the manager and restarts:

```bash
sudo ls -l /var/ossec/etc/shared/agent.conf        # present = group config received
sudo auditctl -l | grep wazuh_fim                  # who-data audit rules loaded
sudo grep -i whodata /var/ossec/logs/ossec.log | tail
```

If `auditctl` shows no `wazuh_fim` rules, who-data isn't active and the agent has fallen back to realtime monitoring. Alerts still arrive, but without the "who changed it" fields. Check the `ossec.log` lines for the reason.

### 5.4 Duplicate log check (verify)

Recent Wazuh agents may also read the systemd journal by default. If so, every sshd/sudo line could arrive twice (once from `/var/log/auth.log`, once from journald):

```bash
sudo grep -n -B2 -A3 journald /var/ossec/etc/ossec.conf
```

If there is a journald `<localfile>` block, compare alert counts in step 8. If they double, decide with the wazuh branch which source to keep (open question below).

## 6. Lab user and SSH password login (lab only)

Simulation 01 (ssh-brute-force, T1110.001) needs an account that accepts passwords over SSH.

> ⚠️ **Lab only.** Password SSH login is one of the most common ways real servers get compromised. It's acceptable here only because:
> - the VM sits behind UTM's NAT, so nothing outside this Mac can reach port 22;
> - `labuser` has no sudo rights and owns nothing of value;
> - its password is used **nowhere else** and is written only in your password manager, never in this repo.
>
> Never copy `10-lab-password-auth.conf` to a real machine. Never add a UTM port forward to port 22.

```bash
# Unprivileged test user (no sudo group)
sudo adduser labuser          # pick a password that IS in a common wordlist but used nowhere else

# Lab SSH settings
sudo cp 10-lab-password-auth.conf /etc/ssh/sshd_config.d/   # file from configs/endpoint/
sudo sshd -t                                                 # syntax check, no output = OK
sudo systemctl restart ssh
sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|maxauthtries'
```

Expected: `passwordauthentication yes`, `permitrootlogin no` and `maxauthtries 6`.

**Lockout check:** do these SSH steps in the UTM console window, not over SSH, and keep that window open. Then, from the Mac, confirm both accounts can log in before you close it:

```bash
ssh <admin>@<VM IP>      # must work
ssh labuser@<VM IP>      # must work
```

If the admin login fails, remove the drop-in from the console (`sudo rm /etc/ssh/sshd_config.d/10-lab-password-auth.conf && sudo systemctl restart ssh`) and check `sudo sshd -T` again.

Optional extra layer: allow SSH only from the lab subnet with the host firewall:

```bash
sudo ufw allow from 192.168.64.0/24 to any port 22 proto tcp
sudo ufw enable
```

(Simulation 05 sudo-abuse will need `labuser` to try `sudo` and fail. That is set up in `simulations/`, not here.)

## 7. Install the Wazuh agent on the Mac (mac-host)

On the Mac, the manager is reached through Docker's published port on localhost.

```bash
cd /tmp
curl -LO https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.9-1.arm64.pkg

read -rs -p 'Wazuh registration password: ' REGPASS; echo
( umask 077
  echo "WAZUH_MANAGER='127.0.0.1' && WAZUH_AGENT_NAME='mac-host' && WAZUH_REGISTRATION_PASSWORD='$REGPASS'" > /tmp/wazuh_envs )
unset REGPASS
sudo installer -pkg ./wazuh-agent-4.14.9-1.arm64.pkg -target /
rm -f /tmp/wazuh_envs                      # don't leave the password lying around
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
| 1 | Both agents active | **Agents** (Endpoints summary) | – | `soc-victim-01` and `mac-host` show **Active**, version 4.14.9 |
| 2 | Victim is in the right group | Agent `soc-victim-01` → details | – | Group `linux-victims`, config **synced** |
| 3 | auth.log arriving | **Threat Hunting → Events**, filter `agent.name: soc-victim-01` and `location: /var/log/auth.log` | From the Mac: `ssh labuser@<VM IP>` with a wrong password, once | sshd authentication-failure alert (rule group `authentication_failed`) |
| 4 | syslog arriving | Same, `location: /var/log/syslog` | On the VM: `logger "soc-lab test"` | Event visible in archives / a syslog alert if a rule matches. If nothing shows, that's normal: Wazuh only stores events that match a rule unless `logall` is on. Use check 3 instead as proof. |
| 5 | sudo logged | Events, `agent.name: soc-victim-01` | On the VM: `sudo ls` as `<admin>` | sudo alert (rule group `sudo`) |
| 6 | FIM on and baseline done | **File Integrity Monitoring** → `soc-victim-01` | Wait for first scan after enrolment | Inventory lists files under `/etc` and `/var/spool/cron` |
| 7 | FIM realtime/who-data | **File Integrity Monitoring → Events** | On the VM: `sudo touch /etc/cron.d/soc-lab-test` then `sudo rm /etc/cron.d/soc-lab-test` | "File added" then "File deleted" within seconds; `syscheck.audit.login_user.name` = `<admin>` if who-data works |
| 8 | No duplicates | Events for check 3 | – | One alert per failed login, not two (see 5.4) |
| 9 | Mac agent sending | Events, `agent.name: mac-host` | – | Any events (rootcheck, SCA or logs) |

When all nine pass, tick "Enrol agents" and "Confirm logs arrive" in the roadmap (coordinator updates the roadmap on `main`).

## Undo / reset

| Goal | How |
|---|---|
| Fresh victim | Delete `soc-victim-01` in UTM, clone `soc-victim-01-clean`, re-run steps 5–6. Remove the old agent on the manager first: `docker compose exec wazuh.manager /var/ossec/bin/manage_agents -r <ID>` |
| Remove Mac agent | `sudo /Library/Ossec/bin/wazuh-control stop`, then `sudo /bin/rm -r /Library/Ossec` and remove the launchd items as described in Wazuh's macOS uninstall docs |
| Turn SSH password login off | `sudo rm /etc/ssh/sshd_config.d/10-lab-password-auth.conf && sudo systemctl restart ssh` |

## Decisions (2026-11-04)

1. **Enrolment password: on.** Port 1515 is reachable from the Wi-Fi, so without a password any nearby device could enrol a fake agent while the lab runs. The manager uses `use_password yes`; the password lives only in the git-ignored `.env` (manager change made on the wazuh branch). Rejected: binding the ports to `192.168.64.1` only, because `bridge100` exists only while a UTM VM runs and Docker may fail to start.
2. **VM admin account:** the personal admin account created at install (written `<admin>` here, so no personal names go in the repo), separate from the unprivileged test user `labuser`. The SSH drop-in has no `AllowUsers` line, so it cannot lock the admin out.
3. **Duplicate logs:** if step 5.4 / check 8 shows sshd or sudo events twice, keep one source (journald or `/var/log/auth.log`) and record which here.

## Still to confirm when run

- **Ubuntu 24.04 timestamps.** 24.04's rsyslog writes ISO-8601 timestamps (`2026-11-04T10:00:00.123456+08:00`). Wazuh 4.14 should decode them; confirm in check 3 that sshd fields (`srcip`, `dstuser`) are filled in.
