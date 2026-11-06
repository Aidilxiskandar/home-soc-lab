#!/usr/bin/env bash
# Apply runtime manager settings that live inside the wazuh_etc Docker volume.
# Run after `docker compose up -d`, and again after any `docker compose down -v`.
#   1. ossec.conf from config/wazuh_cluster/wazuh_manager.conf
#   2. agent enrolment password -> /var/ossec/etc/authd.pass (from .env)
#   3. agent group linux-victims + its shared agent.conf
#   4. custom detection rules from ../wazuh-rules/local_rules.xml
#   5. optional: raw event archive (logall_json) for investigations
# Also run it after editing wazuh_manager.conf or the custom rules.
#
# Usage: ./apply-manager-config.sh [--archives] [path/to/agent.conf]
#   --archives   keep every raw event in archives.json (useful during attack
#                simulations; off by default, the repo ossec.conf has it off)
#   default agent.conf path: ../endpoint/agent.conf (configs/endpoint on main)
set -euo pipefail

cd "$(dirname "$0")"

ARCHIVES=0
if [[ "${1:-}" == "--archives" ]]; then
  ARCHIVES=1
  shift
fi
readonly ARCHIVES

readonly GROUP="linux-victims"
readonly AGENT_CONF="${1:-../endpoint/agent.conf}"
readonly RULES_FILE="../wazuh-rules/local_rules.xml"
readonly OSSEC="/var/ossec"

manager() { docker compose exec -T wazuh.manager "$@"; }

if [[ ! -f .env ]]; then
  echo "[apply] ERROR: .env not found, run ./setup.sh first" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
source .env
set +a
if [[ -z "${WAZUH_REGISTRATION_PASSWORD:-}" ]]; then
  echo "[apply] ERROR: WAZUH_REGISTRATION_PASSWORD missing in .env, rerun ./setup.sh" >&2
  exit 1
fi

if ! manager true 2>/dev/null; then
  echo "[apply] ERROR: wazuh.manager is not running (docker compose up -d)" >&2
  exit 1
fi

echo "[apply] syncing ossec.conf from config/wazuh_cluster/wazuh_manager.conf"
# The image copies the mounted ossec.conf only on the container's first start,
# so later edits to wazuh_manager.conf need this explicit copy.
manager sh -c "cp /wazuh-config-mount/etc/ossec.conf $OSSEC/etc/ossec.conf && chown root:wazuh $OSSEC/etc/ossec.conf && chmod 660 $OSSEC/etc/ossec.conf"

echo "[apply] writing enrolment password"
# Sent over stdin so the password never appears in a process list.
printf '%s\n' "$WAZUH_REGISTRATION_PASSWORD" \
  | manager sh -c "cat > $OSSEC/etc/authd.pass && chown root:wazuh $OSSEC/etc/authd.pass && chmod 640 $OSSEC/etc/authd.pass"

if [[ -f "$AGENT_CONF" ]]; then
  echo "[apply] setting up agent group $GROUP"
  if ! manager test -d "$OSSEC/etc/shared/$GROUP"; then
    manager "$OSSEC/bin/agent_groups" -a -g "$GROUP" -q
  fi
  docker compose cp "$AGENT_CONF" "wazuh.manager:$OSSEC/etc/shared/$GROUP/agent.conf"
  manager chown wazuh:wazuh "$OSSEC/etc/shared/$GROUP/agent.conf"
  manager "$OSSEC/bin/verify-agent-conf" -f "$OSSEC/etc/shared/$GROUP/agent.conf"
else
  echo "[apply] WARNING: $AGENT_CONF not found, skipping group $GROUP (merge the endpoint branch first)"
fi

if [[ -f "$RULES_FILE" ]]; then
  echo "[apply] loading custom rules from $RULES_FILE"
  manager cp "$OSSEC/etc/rules/local_rules.xml" "$OSSEC/etc/rules/local_rules.xml.bak"
  docker compose cp "$RULES_FILE" "wazuh.manager:$OSSEC/etc/rules/local_rules.xml"
  manager sh -c "chown root:wazuh $OSSEC/etc/rules/local_rules.xml && chmod 660 $OSSEC/etc/rules/local_rules.xml"
else
  echo "[apply] no custom rules at $RULES_FILE, keeping the manager's current local_rules.xml"
fi

if [[ "$ARCHIVES" == 1 ]]; then
  echo "[apply] enabling raw event archive (logall_json)"
  manager sed -i "s#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#" "$OSSEC/etc/ossec.conf"
fi

echo "[apply] checking configuration and rules"
if ! manager "$OSSEC/bin/wazuh-analysisd" -t >/dev/null 2>&1; then
  echo "[apply] ERROR: wazuh-analysisd -t failed; restoring previous rules, not restarting" >&2
  manager sh -c "test -f $OSSEC/etc/rules/local_rules.xml.bak && cp $OSSEC/etc/rules/local_rules.xml.bak $OSSEC/etc/rules/local_rules.xml" || true
  exit 1
fi

echo "[apply] restarting manager services"
manager "$OSSEC/bin/wazuh-control" restart >/dev/null
echo "[apply] done"
