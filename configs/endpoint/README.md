# Endpoint configs

Config for the lab's victim endpoints. The full build guide is [`docs/endpoints.md`](../../docs/endpoints.md).

| File | Goes to | Purpose |
|---|---|---|
| [`agent.conf`](agent.conf) | **Manager:** `/var/ossec/etc/shared/linux-victims/agent.conf` | Group config for Linux victims: audit.log collection (auth events come from the default journald input), FIM with who-data on `/etc`, account, sudo and cron files |
| [`10-lab-password-auth.conf`](10-lab-password-auth.conf) | **Victim:** `/etc/ssh/sshd_config.d/` | Lab-only SSH password login for the T1110.001 simulation |

## Why a group config instead of editing the agent's ossec.conf

- One file in Git, pushed by the manager to every agent in the group. A second Ubuntu victim later just joins `linux-victims`.
- No hand edits on the VM that are easy to lose when the VM is rebuilt.
- The agent's own `ossec.conf` stays at Wazuh defaults, so upgrades are clean.

## Manager-side steps (for the wazuh branch)

One script on the wazuh side does it all: `configs/wazuh/apply-manager-config.sh`. With the stack up, run it from the repo:

```bash
./configs/wazuh/apply-manager-config.sh                      # uses ../endpoint/agent.conf (this file, on main)
./configs/wazuh/apply-manager-config.sh path/to/agent.conf   # or point it at another copy
```

It:
1. syncs the manager's `ossec.conf` (the image only copies the mounted file on the container's first start)
2. writes the enrolment password from `.env` (`WAZUH_REGISTRATION_PASSWORD`) to `/var/ossec/etc/authd.pass`
3. creates the `linux-victims` group if it's missing, copies in `agent.conf` and runs `verify-agent-conf`
4. restarts the manager

**Rerun it after you edit `agent.conf`, and after any `docker compose down -v`.** The group lives in the `wazuh_etc` volume, so `down -v` deletes it.

The agent joins the group at enrolment (`WAZUH_AGENT_GROUP=linux-victims`, see `docs/endpoints.md`). If it was enrolled without a group:

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_groups -a -i <AGENT_ID> -g linux-victims -q
```

Agents pull a changed `agent.conf` within a few minutes and restart themselves. Check with:

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_groups -S -i <AGENT_ID>   # "synchronized"
```
## Not needed on the manager

- **No new rules for Phase 1.** Built-in rules already cover what this config sends: sshd failures (5710, 5716, 5760, 5763), sudo (5401–5403), new user/group (5902, 5901), FIM changes (550, 553, 554). Confirm these IDs against real alerts in Phase 2. Custom rules come with Phase 2 under `detections/`.
- **No change to `<syscheck>` in the manager's own `ossec.conf`.** That block only applies to the manager container itself.
