# Endpoint configs

Config for the lab's victim endpoints. The full build guide is [`docs/endpoints.md`](../../docs/endpoints.md).

| File | Goes to | Purpose |
|---|---|---|
| [`agent.conf`](agent.conf) | **Manager:** `/var/ossec/etc/shared/linux-victims/agent.conf` | Group config for Linux victims: auth log + syslog collection, FIM with who-data on `/etc`, account, sudo and cron files |
| [`10-lab-password-auth.conf`](10-lab-password-auth.conf) | **Victim:** `/etc/ssh/sshd_config.d/` | Lab-only SSH password login for the T1110.001 simulation |

## Why a group config instead of editing the agent's ossec.conf

- One file in Git, pushed by the manager to every agent in the group. A second Ubuntu victim later just joins `linux-victims`.
- No hand edits on the VM that are easy to lose when the VM is rebuilt.
- The agent's own `ossec.conf` stays at Wazuh defaults, so upgrades are clean.

## Manager-side steps (for the wazuh branch)

Run from `configs/wazuh/` on the Mac, with the stack up. Nothing here needs a restart of the manager.

```bash
# 1. Create the group
docker compose exec wazuh.manager /var/ossec/bin/agent_groups -a -g linux-victims -q

# 2. Copy the group config in and fix ownership
docker compose cp ../endpoint/agent.conf wazuh.manager:/var/ossec/etc/shared/linux-victims/agent.conf
docker compose exec wazuh.manager chown wazuh:wazuh /var/ossec/etc/shared/linux-victims/agent.conf

# 3. Validate the XML
docker compose exec wazuh.manager /var/ossec/bin/verify-agent-conf \
  -f /var/ossec/etc/shared/linux-victims/agent.conf
```

The agent joins the group at enrolment (`WAZUH_AGENT_GROUP=linux-victims`, see `docs/endpoints.md`). If it was enrolled without a group:

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_groups -a -i <AGENT_ID> -g linux-victims -q
```

Agents pull a changed `agent.conf` within a few minutes and restart themselves. Check with:

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_groups -S -i <AGENT_ID>   # "synchronized"
```

The file sits in the `wazuh_etc` Docker volume, so it survives `docker compose stop/start` but **not** `docker compose down -v`. After a full reset, repeat steps 1–3. (The wazuh branch could make this automatic, for example with a step in `setup.sh` or a bind mount. That's its call.)

## Not needed on the manager

- **No new rules for Phase 1.** Built-in rules already cover what this config sends: sshd failures (5710, 5716, 5760, 5763), sudo (5401–5403), new user/group (5902, 5901), FIM changes (550, 553, 554). Confirm these IDs against real alerts in Phase 2. Custom rules come with Phase 2 under `detections/`.
- **No change to `<syscheck>` in the manager's own `ossec.conf`.** That block only applies to the manager container itself.
