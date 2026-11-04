# Home SOC Lab

A self-built Security Operations Centre (SOC) lab running on a single laptop. I use it to practise the full blue-team loop: **collect logs → simulate attacks → detect → triage → report**.

> Status: 🚧 Phase 1: Wazuh SIEM deployed ([setup guide](docs/setup.md)); onboarding endpoints next. See the [roadmap](docs/roadmap.md).

## Why this project

I'm a cybersecurity graduate focusing on security operations and governance, risk and compliance (GRC). This lab is where I build and show hands-on skills: deploying a SIEM, writing detection rules, mapping attacks to MITRE ATT&CK, and writing incident reports the way a SOC analyst would.

It also asks a practical question: **what should a small business (like a cafe) actually monitor, and what would it cost?**

## Lab architecture (planned)

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
