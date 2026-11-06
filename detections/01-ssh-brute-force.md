# 01: SSH brute force

- **ATT&CK technique:** T1110.001 Brute Force: Password Guessing
- **Rule type:** Built-in Wazuh rules 5760, 5763, 5758, 2502, 40112 / Custom rules 100100, 100101, 100102
- **Simulation:** [`../simulations/01-ssh-brute-force.md`](../simulations/01-ssh-brute-force.md)

## Logic

An attacker guesses passwords for `labuser` over SSH from one IP. On soc-victim-01 sshd logs to journald, and each wrong password gives two lines: a PAM line and an sshd `Failed password` line, both with the source IP.

**The detection is built on the failures, not on the success.** The success alert (5715) went missing twice in the Phase 2 pre-checks: the event was in the VM's journal, but never reached the manager (see [`../docs/endpoints.md`](../docs/endpoints.md), "Missing 5715"). So the primary alert is the failure-frequency rule 5763, which needs no success at all. "Brute force then success" (40112 / 100101) is a second, higher alert when 5715 does arrive. If it doesn't, the analyst checks the VM's journal before calling the brute force unsuccessful.

| Rule | Level | Matches | Role |
|---|---|---|---|
| 5760 | 5 | sshd `Failed password` / `Failed keyboard` / `authentication error` (child of 5716). Decodes `srcip`, `srcport`, `dstuser` | one per wrong password |
| 5503 | 5 | PAM `authentication failure; logname=` (pam_unix(sshd:auth)) | same failure, PAM side; `srcip` from `rhost` |
| 2502 | 10 | `more authentication failures;` / `REPEATED login failures` | sshd closes a connection after several failures |
| 5758 | 8 | `error: maximum authentication attempts exceeded` | a connection hit `MaxAuthTries` (6 in the lab) |
| **5763** | **10** | 8 × 5760 from the **same srcip** in **120 s** (`ignore=60`) | **primary brute-force alert** |
| 5710 / 5712 | 5 / 10 | `invalid user` / 8 of them from one IP in 120 s | guessing user names that don't exist |
| 5551 | 10 | 8 × 5503 from one IP in 180 s | PAM-side equivalent of 5763 |
| 40111 | 10 | 12 events in group `authentication_failed` from one IP in 160 s | generic, any service |
| 5715 | 3 | sshd `Accepted ...` | success (**intermittent**, see above) |
| 40112 | 12 | success after an `authentication_failures` alert from the same IP within 240 s | brute force that worked |
| **100100** | **10** | 10 × 5760 from one IP in **15 min** (`ignore=900`) | **custom: slow brute force under the 5763 threshold** |
| **100101** | **13** | 5715 from an IP that had 5763 in the last 15 min | **custom: login after brute force** (names `dstuser`) |
| **100102** | **13** | 5715 from an IP that had 100100 in the last 15 min | **custom: login after slow brute force** |

Why the custom rules: 5763 only sees bursts (8 in 2 minutes). `hydra -t 1 -W 20`, or a few tries a minute, stays under it forever. 100100 widens the window to 15 minutes. 40112 already covers "success after failures", but only for 240 s and from any `authentication_failures` rule. 100101/100102 tie it to the SSH brute-force rules, keep 15 minutes, and put the account in the description.

## Rule

From [`../configs/wazuh-rules/local_rules.xml`](../configs/wazuh-rules/local_rules.xml):

```xml
<rule id="100100" level="10" frequency="10" timeframe="900" ignore="900">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>SOC lab: slow SSH brute force: 10+ failed passwords from $(srcip) in 15 minutes.</description>
  <mitre><id>T1110.001</id></mitre>
  <group>authentication_failures,</group>
</rule>

<rule id="100101" level="13" timeframe="900">
  <if_sid>5715</if_sid>
  <if_matched_sid>5763</if_matched_sid>
  <same_source_ip />
  <description>SOC lab: SSH login as $(dstuser) from $(srcip) after a brute force from the same IP.</description>
  <mitre><id>T1110.001</id><id>T1078</id></mitre>
  <group>authentication_success,</group>
</rule>

<!-- 100102: same as 100101, with if_matched_sid 100100 -->
```

## Testing

**wazuh-logtest, 2026-11-06.** Built-in rules checked on the live manager (read-only). Custom rules checked in a throwaway `wazuh/wazuh-manager:4.14.9` container with no network and this `local_rules.xml` loaded, so the live manager was not changed. Log lines use the journald format seen in real alerts (`Nov 06 10:00:01 soc-victim-01 sshd[3001]: ...`).

| Input | Result |
|---|---|
| 9 × `Failed password for labuser from 192.168.64.1 port … ssh2` | 5760 ×7, **5763 on the 8th** (`srcip` 192.168.64.1, `dstuser` labuser), 5760 |
| …then `Accepted password for labuser from 192.168.64.1` | built-in only: **40112** (L12). With custom rules: **100101** (L13) |
| 21 fast failures | 5763 on the 8th and 16th, 100100 never: when 5763 fires it uses up the counted 5760s. As intended: fast is 5763's job |
| 11 failures **20 s apart**, one session (8 failures span 140 s, so 5763 can't fire), then `Accepted` | see "Slow test" below |
| `error: maximum authentication attempts exceeded for labuser from 192.168.64.1 …` | 5758 (L8) |
| `PAM 5 more authentication failures; … rhost=192.168.64.1 user=labuser` | 2502 (L10) |

Slow test (real time, about 4 minutes): 10 × 5760 and **no 5763**, then **100100 (L10) on the 10th failure** (`srcip` 192.168.64.3), one more 5760 (100100 is in its 15-minute `ignore`), and on `Accepted` **100102 (L13)**. So a slow guesser that 5763 never sees is still caught, and so is its success.

### Live run, 2026-11-06

Ten wrong passwords for `labuser` from the Mac (192.168.64.1), 03:42:17–03:42:55 UTC, about one every 4 s. Earlier single test failures had already come from the same IP at 03:34:43, 03:37:15, 03:39:15 and 03:42:09 (still inside the 15-minute window).

| Fired | Count | Notes |
|---|---|---|
| 5760 L5 | 10 | `data.srcip: 192.168.64.1`, `data.dstuser: labuser`, `location: journald` |
| 5503 L5 | 10 | PAM side, `srcip` from `rhost` |
| **100100 L10** | 1 | at 03:42:39: "slow SSH brute force: 10+ failed passwords from 192.168.64.1 in 15 minutes" |
| **5551 L10** | 1 | at 03:42:41: 8 × 5503 in 180 s |
| 5763 | **0** | see below |

**Why 5763 didn't fire, worked out from the alert timestamps:**
1. When 100100 fired at 03:42:39, the 15-minute window held 10 failures: the 3 earlier test failures, 03:42:09, and the first 6 of the run. The 2-minute window held only 7, so 5763 (8 in 120 s) wasn't met yet.
2. 5763 and 100100 both count the same 5760 events. When either one fires, it uses up the events counted so far. The sandbox test showed the same thing the other way round: 21 fast failures gave 5763 twice and 100100 never.
3. After 03:42:39 only 4 more failures arrived (03:42:43–55), fewer than 8, so 5763 never got its count.

wazuh-logtest fired 5763 because its session had no earlier failures: the 8th rapid line reached 5763's threshold first. Without the 4 stray failures before the run, 5763 would have fired on the run's 8th failure. So the gap is the order the thresholds were reached in, not a live-vs-logtest difference in the rules.

The detection still worked: two independent level-10 alerts (100100 from sshd, 5551 from PAM) within 2 s of each other, with no need for the success event (5715 wasn't part of this run).

To show 5763 itself in the write-up: wait 15 minutes after any SSH failure from the Mac, then send 8 or more failures within 2 minutes.

## How to verify

**Dashboard** (Threat Hunting → Events), time range covering the run:

```
agent.name:soc-victim-01 and rule.id:(5760 or 5763 or 5758 or 2502 or 100100 or 100101 or 100102 or 40112 or 5715)
```

Expected for a fast run (e.g. hydra with 4 tasks against `labuser`):
- many **5760** with `data.srcip: 192.168.64.1` (the Mac, the attacker side), `data.dstuser: labuser`, `location: journald`;
- **5763** (level 10) at least once, same `data.srcip`;
- **5758** / **2502** at the end of each connection (MaxAuthTries 6: at most 6 × 5760 per sshd PID, which is also the `MaxAuthTries` check from the pre-checks);
- if the right password is in the wordlist: **5715** then **100101** (or **40112** before the custom rules are loaded).

**Indexer** (from `~/soc-wazuh/configs/wazuh`; the password is read from `.env` inside the subshell and never printed):

```bash
# [Mac]
( set -a; . ./.env; set +a
  curl -sk -u "admin:$INDEXER_ADMIN_PASSWORD" \
    "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=50&sort=timestamp:asc" \
    -H 'Content-Type: application/json' -d '{
      "query": {"bool": {"filter": [
        {"term": {"agent.name": "soc-victim-01"}},
        {"terms": {"rule.id": ["5760","5763","5758","2502","100100","100101","100102","40112","5715"]}},
        {"range": {"timestamp": {"gte": "now-1h"}}}]}},
      "_source": ["timestamp","rule.id","rule.level","data.srcip","data.dstuser","full_log"]}' )
```

**If no 5715 / 100101 appears but a password was found:** don't conclude the login failed. Check the VM itself (step 3 in the pre-checks):

```bash
# [VM]
sudo journalctl -u ssh --since "10 min ago" --no-pager | grep -E 'Accepted|Failed'
```

and, if `logall_json` is on for the run, `archives.json` on the manager. Record which of the three it was (no success, success lost in transit, success not alerted) in the simulation write-up.

## False positives and tuning

- **Mistyped passwords:** one person mistyping a few times gives 5760 and maybe 2502 (level 10, it fires on a single connection with 2+ failures). It doesn't reach 5763 (8 in 2 minutes). 2502 is the noisiest of the set; if it gets annoying, a child rule at a lower level can be added for `rhost=192.168.64.1` with fewer than 4 failures. Not done now: in this lab every SSH failure is either a test or worth seeing.
- **All lab traffic has srcip 192.168.64.1.** Every SSH client (admin, attacker, scanner) is the Mac behind UTM's NAT, so `same_source_ip` can't tell the admin from the attacker. In the lab that's fine (one attacker at a time). In a real network, add `same_dstuser`-style splitting or a whitelist of jump hosts via a CDB list.
- **100100 and admin scripts:** an automation job with a stale password retrying every minute would hit 100100 after ~10 minutes. Fix the job, or exclude its account with a child rule at level 0, never by IP.
- **5763 and 100100 share one counter.** Both count 5760 from the same IP, and whichever fires first uses up the count, so one burst usually gives only one of them (seen live on 2026-11-06). That's acceptable, because either one is level 10. If both are wanted, 100100 could count the PAM rule 5503 instead (it also has `srcip`). It would then share a counter with 5551 instead, so that change only moves the overlap.
- **5763 `ignore=60`:** after it fires, one alert per minute per IP at most; a long attack produces a steady trickle, not a flood.
- **Key-based logins** (`Accepted publickey`) also give 5715. A key login straight after a password brute force from the same IP still triggers 100101, which is correct: it's worth a look.
- **Not covered:** password spraying (one password, many users) and distributed attacks (many IPs). Spraying against *non-existent* users is caught by 5712; spraying against real users from one IP is caught by 5763 (counts by IP, not by user). Many IPs: out of scope for this lab.
