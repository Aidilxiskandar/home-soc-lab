# Home SOC Lab

A self-built Security Operations Centre (SOC) lab running on a single laptop. I use it to practise the full blue-team loop: **collect logs → simulate attacks → detect → triage → report**.

> Status: ✅ Phase 1 complete: SIEM deployed and the first endpoint is sending logs. Next: Phase 2, attack and detect. See the [roadmap](docs/roadmap.md).

## Why this project

I'm a cybersecurity graduate focusing on security operations and governance, risk and compliance (GRC). This lab is where I build and show hands-on skills: deploying a SIEM, writing detection rules, mapping attacks to MITRE ATT&CK, and writing incident reports the way a SOC analyst would.

It also asks a practical question: **what should a small business (like a cafe) actually monitor, and what would it cost?**

## Dashboard

![Wazuh dashboard showing the soc-victim-01 agent](assets/dashboard-soc-victim-01.png)

## Phase 1 highlights

- **Hardened the official Wazuh setup.** It ships with hard-coded default passwords, demo users with public passwords, and services on every network interface. Fixed all three and verified: defaults now return HTTP 401 ([ADR 0002](docs/adr/0002-run-wazuh-natively-in-docker.md)).
- **Closed a rogue-agent gap.** Agent enrolment was open to any device on the network. It now needs a password, and an attempt without one is rejected.
- **Found and fixed duplicate alerts.** Every login and sudo event arrived twice (from `/var/log/auth.log` and from journald), which would have inflated brute-force counts. Now each event is ingested from journald only, and verified as one alert per event.
- **File integrity with who-data.** Changes to `/etc`, sudoers and cron are attributed to the user who made them. `/etc/shadow` changes alert without sending password hashes to the SIEM.
- **CIS benchmark out of the box.** The first scan of the Ubuntu VM scored 46% on the CIS Ubuntu 24.04 benchmark, a baseline to harden later.

## Lab architecture

```
┌──────────────────────── MacBook (Apple Silicon, 16 GB) ────────────────────────┐
│                                                                                 │
│   Docker Desktop                                 Victim endpoints               │
│   ┌──────────────────────────────┐              ┌──────────────────────────┐    │
│   │ Wazuh single-node            │  agent logs  │ Ubuntu Linux (VM)        │    │
│   │  • Wazuh manager             │◄─────────────│  • Wazuh agent           │    │
│   │  • Wazuh indexer             │              │  • SSH, web server       │    │
│   │  • Wazuh dashboard           │◄─────────────│ macOS host               │    │
│   └──────────────────────────────┘              │  • Wazuh agent           │    │
│                ▲                                └──────────────────────────┘    │
│                │ attack traffic                                                 │
│   ┌──────────────────────────────┐                                              │
│   │ Attacker (Kali / scripts,    │                                              │
│   │ Atomic Red Team tests)       │                                              │
│   └──────────────────────────────┘                                              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

Details and design decisions: [docs/architecture.md](docs/architecture.md) and [docs/adr/](docs/adr/).

## What's in this repo

| Folder | Contents |
|---|---|
| [`docs/`](docs/) | Roadmap, architecture, setup guides, architecture decision records |
| [`configs/`](configs/) | Docker Compose and Wazuh configuration (no secrets) |
| [`simulations/`](simulations/) | Attack simulations, each mapped to a MITRE ATT&CK technique |
| [`detections/`](detections/) | Custom Wazuh detection rules with test evidence |
| [`incident-reports/`](incident-reports/) | SOC-style incident reports written from lab alerts |

## Skills demonstrated

- SIEM deployment and log onboarding (Wazuh)
- Detection engineering and rule tuning
- MITRE ATT&CK mapping
- Alert triage and incident reporting
- File integrity monitoring and vulnerability detection
- Documenting decisions and trade-offs

## Detection coverage

| # | Technique | ATT&CK ID | Simulation | Detection | Report |
|---|---|---|---|---|---|
| — | _Coming in Phase 2_ | | | | |

## Disclaimer

All attacks in this lab run only against machines I own, inside an isolated lab. Nothing here is aimed at third-party systems. This repo contains no data from any employer or client.

## License

[MIT](LICENSE)
