# ADR 0001: Use Wazuh as the SIEM

- **Status:** Accepted
- **Date:** 2026-11-04

## Context
The lab needs a SIEM that is free, runs on one laptop, and is used in real SOCs, so the skills carry over to a job.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| **Wazuh** | Free and open source; SIEM + endpoint agent + file integrity + vulnerability detection in one; widely used by SMEs and MSSPs | Heavy on RAM; its own rule syntax |
| Elastic Stack (ELK) + Elastic Agent | Very popular; powerful search | Security features spread across licence tiers; more setup to reach a working SOC |
| Splunk Free | Industry standard; SPL is a valued skill | 500 MB/day limit; no alerting in the free version |
| Security Onion | Full SOC distro | Needs much more RAM than this laptop can spare; x86 focused |

## Decision
Use Wazuh single-node, deployed with Docker Compose.

## Consequences
- Covers detection, file integrity monitoring and active response with one tool
- Fits a future MSSP career path, since many MSSPs serve SMEs with Wazuh
- Splunk SPL can be learned separately later (for example on TryHackMe) if job ads ask for it
