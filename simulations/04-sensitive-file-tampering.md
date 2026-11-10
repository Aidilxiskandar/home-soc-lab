# 04: Sensitive file tampering

- **ATT&CK technique:** T1565.001 Data Manipulation: Stored Data Manipulation (sensitive system files)
- **Target:** soc-victim-01 (192.168.64.2)
- **Date run:** 2026-11-10

## Goal
Edit security-critical files directly — the account database (`/etc/passwd`, `/etc/shadow`) or the sudo policy — to plant or remove access. The SIEM must flag changes to these files, especially when made by a tool that is **not** a package manager or account utility, and loudest of all when a sudoers change grants passwordless root.

## Steps
```bash
# [VM] as <admin>, via sudo

# (a) direct edit of the account database with sed (here, removing the UID-0 backdoor from sim 02)
sudo sed -i.bak '/^backdoor:/d' /etc/passwd /etc/shadow

# (b) plant a sudoers backdoor granting labuser passwordless root
echo '# soc lab placeholder' | sudo tee /etc/sudoers.d/99-soc-lab          # create (no diff yet)
echo 'labuser ALL=(ALL) NOPASSWD: ALL' | sudo tee -a /etc/sudoers.d/99-soc-lab   # append -> diff
sudo chmod 440 /etc/sudoers.d/99-soc-lab
sudo visudo -c                                                             # confirm sudoers still valid
```

## Expected evidence
FIM alerts on the account/sudoers files; a higher-severity alert when the writing process is not a package/account tool; the top-severity alert when a sudoers change contains `NOPASSWD` / `ALL=(ALL)`.

## Result (live, 2026-11-10)
| Rule | Level | Detail |
|---|---|---|
| **100131** | **12** | /etc/passwd and /etc/shadow modified by `/usr/bin/sed` (non-package tool) — fired ×4 (2 files × 2 `sed -i` rewrites) |
| **100132** | **12** | /etc/sudoers.d/99-soc-lab added, and again on the `chmod` (permission-only change) |
| **100133** | **14** | sudoers change grants broad/passwordless rights — diff captured the exact line: `> labuser ALL=(ALL) NOPASSWD: ALL` |

Content diffs appear only on a **modify**, not a brand-new file, which is why the placeholder-then-append pattern was used to trigger 100133.

> `sed -i.bak` leaves `/etc/passwd.bak` and `/etc/shadow.bak`; `shadow.bak` is a copy of the password hashes and must be deleted during cleanup.

## Cleanup
```bash
# [VM]
sudo rm -f /etc/sudoers.d/99-soc-lab /etc/passwd.bak /etc/shadow.bak
```

## Linked detection
[`../detections/04-sensitive-file-tampering.md`](../detections/04-sensitive-file-tampering.md)
