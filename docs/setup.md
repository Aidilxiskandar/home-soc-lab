# Setup Guide: Wazuh SIEM

How to deploy the lab's Wazuh single-node stack on a Mac with Docker Desktop.

## Requirements
- Docker Desktop with **8 GB** of memory (Settings → Resources)
- About 5 GB of free disk space for images and data
- Tested on Apple Silicon (M5). Wazuh 4.14.9 ships native `arm64` images, so no emulation or VM is needed.

## 1. Run the setup script

```bash
./configs/wazuh/setup.sh
```

It does three things:
1. Creates `configs/wazuh/.env` with **random passwords** for the indexer admin, dashboard service user and Wazuh API user. The file is git-ignored and readable only by you.
2. Builds `internal_users.yml` from the template, filling in bcrypt hashes of those passwords. Upstream's demo users with publicly known passwords are removed.
3. Generates the TLS certificates for the indexer, manager and dashboard. They're git-ignored.

To choose your own passwords instead, copy `.env.example` to `.env` and edit it before running the script.

## 2. Start the stack

```bash
cd configs/wazuh
docker compose up -d
```

The first start downloads about 3 GB of images. Wait 1–3 minutes for the indexer to initialise.

## 2b. Apply manager settings

```bash
./apply-manager-config.sh
```

This turns on the **agent enrolment password** (`WAZUH_REGISTRATION_PASSWORD` in `.env`) and loads the `linux-victims` agent group from `configs/endpoint/agent.conf`. Rerun it after editing `config/wazuh_cluster/wazuh_manager.conf`, or after `docker compose down -v`. The image only copies the mounted `ossec.conf` on the container's first start, so a plain restart doesn't pick up edits.

## 3. Log in

Open <https://localhost> and accept the self-signed certificate warning.

- Username: `admin`
- Password: the `INDEXER_ADMIN_PASSWORD` value in `configs/wazuh/.env`

## Security choices (and why)

| Choice | Reason |
|---|---|
| Passwords in `.env`, never in Git | Upstream hard-codes default passwords in `docker-compose.yml`; anyone who knows the defaults could log in |
| Demo indexer users removed | `kibanaro`, `logstash`, `readall`, `snapshotrestore` ship with public passwords |
| Dashboard (443), indexer (9200) and API (55000) bound to `127.0.0.1` | Only this Mac can reach them, not other devices on the same Wi-Fi |
| Agent ports 1514/1515 open on all interfaces | Lab VMs need to reach the manager to send logs |
| Enrolment password required on 1515 | Without it, any device on the same Wi-Fi could register a fake agent. Tested: no password → `ERROR: Invalid password` |
| Syslog 514/udp removed | Not needed yet; fewer open ports |
| `restart: unless-stopped` | Stays stopped after `docker compose stop` instead of restarting with Docker Desktop |

## Everyday commands

```bash
cd configs/wazuh
docker compose stop        # stop the lab (keeps data)
docker compose start       # start it again
docker compose ps          # check status
docker compose logs -f wazuh.manager   # follow manager logs
docker compose down -v     # DELETE everything, including stored alerts
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `cp: cannot create regular file '/certificates/root-ca-manager.pem': Permission denied` during setup | Harmless on macOS: the generator makes the folder read-only too early. `setup.sh` creates the missing file afterwards. |
| Dashboard shows "Wazuh dashboard server is not ready yet" | The indexer is still starting. Wait a minute and refresh. |
| Indexer exits straight away | Check Docker has 8 GB of memory, and that `vm.max_map_count` is at least 262144 (`docker run --rm alpine sysctl vm.max_map_count`) |
