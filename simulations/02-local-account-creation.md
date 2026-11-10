# 02: Local account creation

- **ATT&CK technique:** T1136.001 Create Account: Local Account
- **Target:** soc-victim-01 (192.168.64.2)
- **Date run:** 2026-11-10

## Goal
After gaining root, an attacker often creates a persistent account — ideally one with admin rights, or a second UID-0 account that is effectively root. The SIEM must flag new accounts and, more loudly, new accounts that gain privilege.

## Steps
```bash
# [VM] as <admin>, via sudo
sudo useradd -m -s /bin/bash eviluser      # rogue standard account
sudo usermod -aG sudo eviluser             # grant admin (sudo group)
sudo useradd -o -u 0 backdoor              # second UID-0 account (root-equivalent)
```

## Expected evidence
`New user added` (5902) and `New group added` (5901); a privilege-escalation alert when the new user joins the sudo group; a high-severity alert for a UID-0 account.

## Result (live, 2026-11-10)
| Rule | Level | Note |
|---|---|---|
| 5902 | 8 | new user eviluser |
| 5901 | 8 | new groups (×2) |
| 5402 | 3 | the three sudo invocations |
| **100110** | **12** | custom: new UID-0 account `backdoor` |
| **100114** | **13** | custom: new account created **and** added to a privileged group |

`usermod -aG sudo` did not raise a standalone 100112; because `eviluser` had just been created, Wazuh reported the group-add as the deeper correlation rule 100114 (which is a child of 100112). See [`../detections/02-local-account-creation.md`](../detections/02-local-account-creation.md).

## Cleanup
```bash
# [VM]
sudo userdel -r eviluser          # 5903 + 100130 ×4 on account files
sudo userdel -f backdoor          # plain userdel refuses: backdoor shares UID 0, so it "owns" PID 1
```
> Removing a UID-0 account needs `userdel -f`. A UID-0 account is awkward to delete precisely because it looks like the owner of running root processes — part of why it is effective persistence.

## Linked detection
[`../detections/02-local-account-creation.md`](../detections/02-local-account-creation.md)
