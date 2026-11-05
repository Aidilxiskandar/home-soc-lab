# Architecture

## Host
- MacBook, Apple Silicon (M5), 16 GB RAM
- Docker Desktop for the SIEM stack
- A Linux VM for the victim endpoint (ARM64 Ubuntu)

## Components

| Component | Role | Runs on |
|---|---|---|
| Wazuh manager | Receives agent events, applies rules, raises alerts | Docker |
| Wazuh indexer | Stores and searches events | Docker |
| Wazuh dashboard | Web UI for alerts, search and dashboards | Docker |
| Wazuh agent (Linux) | Sends auth logs, syslog, file integrity and process data | Ubuntu VM |
| Wazuh agent (macOS) | Sends host logs from the Mac | macOS host |
| Attacker | Runs simulations (scripts, Atomic Red Team) | Ubuntu VM or a separate VM |

## Resource budget
Wazuh single-node needs roughly 4–8 GB RAM. Plan: 8 GB for Docker, about 2–3 GB for the Ubuntu VM, and the rest for macOS.

## Isolation and safety
- Lab services listen only on the local machine or the VM's host-only network
- Attacks target only lab machines
- Default passwords are changed after deployment and are never committed (see `.gitignore`)

## Open questions
- ~~Do the Wazuh Docker images run natively on ARM64?~~ Yes: 4.14.9 ships `arm64` images. See [ADR 0002](adr/0002-run-wazuh-natively-in-docker.md).
- ~~VM tool?~~ UTM (free), QEMU backend, Shared Network. See [docs/endpoints.md](endpoints.md).
