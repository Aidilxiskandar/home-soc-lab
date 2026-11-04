# Roadmap

Paced for about 4–5 hours a week. Each phase ends with something finished and shown in this repo.

## Phase 0: Plan and set up (Nov 2026)
- [x] Create repo, roadmap and architecture plan
- [ ] Record the first design decisions as ADRs
- [ ] Give Docker Desktop enough memory for Wazuh (about 8 GB)

## Phase 1: Build the SIEM (Nov–Dec 2026)
- [ ] Deploy Wazuh single-node with Docker Compose
- [ ] Set up an Ubuntu Linux VM as the first victim endpoint
- [ ] Enrol agents on the Ubuntu VM and the macOS host
- [ ] Confirm logs arrive (auth logs, syslog, file integrity events)
- [ ] Write the setup guide: `docs/setup.md`
- **Deliverable:** working dashboard screenshot + setup guide anyone can follow

## Phase 2: Attack and detect (Jan–Feb 2027)
Five simulations, each mapped to MITRE ATT&CK, with a detection and evidence:
- [ ] SSH brute force (T1110)
- [ ] New local account created (T1136)
- [ ] Persistence via cron job (T1053.003)
- [ ] Sensitive file changed, using file integrity monitoring (T1565)
- [ ] Suspicious sudo / privilege escalation attempt (T1548)
- **Deliverable:** detection coverage table filled in on the README

## Phase 3: Triage and report (Mar–Apr 2027)
Runs alongside TryHackMe SOC Level 1 / SAL1 study.
- [ ] Write custom Wazuh rules and tune out noisy alerts
- [ ] Build a dashboard of key alerts
- [ ] Write 3 SOC-style incident reports from lab alerts
- **Deliverable:** incident reports + tuning notes

## Phase 4: Respond and apply (Gap year, 2027)
- [ ] Automated response (Wazuh active response, for example blocking a brute-forcing IP)
- [ ] Vulnerability detection on endpoints
- [ ] Write-up: "What a small business should monitor": a minimum monitoring plan and cost for an SME such as a cafe
- **Deliverable:** case-study write-up, LinkedIn post, repo made public
