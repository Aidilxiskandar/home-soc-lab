# Roadmap

Paced for about 4–5 hours a week. Each phase ends with something finished and shown in this repo.

## Phase 0: Plan and set up (Nov 2026)
- [x] Create repo, roadmap and architecture plan
- [x] Record the first design decisions as ADRs
- [x] Give Docker Desktop enough memory for Wazuh (about 8 GB)

## Phase 1: Build the SIEM (Nov–Dec 2026)
- [x] Deploy Wazuh single-node with Docker Compose (4 Nov 2026)
- [x] Set up an Ubuntu Linux VM as the first victim endpoint (`soc-victim-01`, Ubuntu 24.04.5 ARM in UTM). Guide: [`docs/endpoints.md`](endpoints.md)
- [x] Enrol the agent on the Ubuntu VM (password-protected enrolment, group `linux-victims`)
- [ ] Enrol the macOS host agent (optional, deferred)
- [x] Confirm logs arrive: auth/sudo via journald (duplicates from auth.log removed), file integrity with who-data, CIS benchmark scan (5 Nov 2026)
- [x] Write the setup guide: [`docs/setup.md`](setup.md)
- **Deliverable:** working dashboard screenshot + setup guide anyone can follow ✅

## Phase 2: Attack and detect (done 10 Nov 2026)
Five simulations, each mapped to MITRE ATT&CK, detected live with 20 custom rules (12 fired live):
- [x] SSH brute force (T1110.001) — 100100 + 5551
- [x] New local account created (T1136.001) — 100114 (sudo), 100110 (UID 0)
- [x] Persistence via cron job (T1053.003) — 100120, 100121 (suspicious content)
- [x] Sensitive file changed, FIM (T1565.001) — 100131, 100133 (NOPASSWD sudoers)
- [x] Suspicious sudo / privilege escalation (T1548.003) — 100140/100141/100142
- **Deliverable:** detection coverage table filled in on the README ✅
- [x] Write up the `simulations/` folder (attacker steps + live results, 01-05)
- Still to add: dashboard screenshots of 100133 (sudoers NOPASSWD) and 100114 (account escalation)

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
