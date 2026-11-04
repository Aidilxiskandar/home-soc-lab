# ADR 0002: Run Wazuh natively in Docker, hardened from upstream defaults

- **Status:** Accepted
- **Date:** 2026-11-04

## Context
The lab host is an Apple Silicon (ARM64) Mac. Wazuh's official single-node Docker setup ships with hard-coded default passwords, demo users and services listening on every network interface.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| **Docker, native arm64 images** | Fast; low overhead; same setup Wazuh documents | Needs the hardening below |
| Linux VM running Docker or the Wazuh installer | Closer to a production server | Extra RAM for a second OS; slower |
| Docker with amd64 images under emulation | None worth having | Slow and unstable for Java (indexer) |

Checked on Docker Hub: `wazuh-manager`, `wazuh-indexer` and `wazuh-dashboard` 4.14.9 all publish `arm64` images.

## Decision
Run the official 4.14.9 single-node stack natively in Docker Desktop, with these changes:
1. Passwords are generated randomly into a git-ignored `.env`. Indexer users are built from a template with bcrypt hashes.
2. Demo users with public passwords are removed.
3. Dashboard, indexer and API ports bind to `127.0.0.1`. Only agent ports (1514/1515) are reachable from the network.
4. Syslog 514/udp is not exposed until needed.

## Consequences
- Verified after deployment: the new admin password works, the upstream default password and the demo users get HTTP 401, and the cluster is green.
- Changing a password later means editing `.env`, rerunning `setup.sh`, and reapplying the security config with `securityadmin.sh` (the indexer only reads `internal_users.yml` on first start).
- Agent ports are open to the local network, so the lab should only run on a trusted network (home Wi-Fi, not public Wi-Fi).
