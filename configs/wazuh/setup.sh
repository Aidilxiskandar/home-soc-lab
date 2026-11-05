#!/usr/bin/env bash
# One-time setup for the Wazuh single-node lab:
#   1. create .env with random passwords (if it does not exist)
#   2. build internal_users.yml with bcrypt hashes of those passwords
#   3. generate the TLS certificates
# Run from anywhere: ./configs/wazuh/setup.sh
set -euo pipefail

cd "$(dirname "$0")"

readonly INDEXER_IMAGE="wazuh/wazuh-indexer:4.14.9"
readonly TEMPLATE="config/wazuh_indexer/internal_users.template.yml"
readonly USERS_FILE="config/wazuh_indexer/internal_users.yml"
readonly CERTS_DIR="config/wazuh_indexer_ssl_certs"

random_password() {
  # 20 random alphanumerics plus a fixed suffix that guarantees upper, lower, digit, symbol.
  local core
  core="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
  printf '%sAa1.' "$core"
}

hash_password() {
  docker run --rm --entrypoint bash \
    -e PW="$1" -e OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    "$INDEXER_IMAGE" \
    -c 'bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$PW"' \
    2>/dev/null | tail -1
}

if [[ ! -f .env ]]; then
  echo "[setup] creating .env with random passwords"
  umask 077
  {
    echo "INDEXER_ADMIN_PASSWORD=$(random_password)"
    echo "KIBANASERVER_PASSWORD=$(random_password)"
    echo "WAZUH_API_PASSWORD=$(random_password)"
  } > .env
else
  echo "[setup] using existing .env"
fi

# Agent enrolment password (added later, so append it to older .env files too).
if ! grep -q '^WAZUH_REGISTRATION_PASSWORD=' .env; then
  echo "[setup] adding WAZUH_REGISTRATION_PASSWORD to .env"
  echo "WAZUH_REGISTRATION_PASSWORD=$(random_password)" >> .env
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

for var in INDEXER_ADMIN_PASSWORD KIBANASERVER_PASSWORD WAZUH_API_PASSWORD WAZUH_REGISTRATION_PASSWORD; do
  if [[ -z "${!var:-}" || "${!var}" == "change-me" ]]; then
    echo "[setup] ERROR: $var is not set in .env" >&2
    exit 1
  fi
done

echo "[setup] hashing indexer passwords"
admin_hash="$(hash_password "$INDEXER_ADMIN_PASSWORD")"
kibana_hash="$(hash_password "$KIBANASERVER_PASSWORD")"
if [[ "$admin_hash" != \$2* || "$kibana_hash" != \$2* ]]; then
  echo "[setup] ERROR: password hashing failed" >&2
  exit 1
fi

umask 077
sed -e "s|__ADMIN_HASH__|${admin_hash}|" \
    -e "s|__KIBANASERVER_HASH__|${kibana_hash}|" \
    "$TEMPLATE" > "$USERS_FILE"
echo "[setup] wrote $USERS_FILE"

if [[ -f "$CERTS_DIR/root-ca.pem" ]]; then
  echo "[setup] certificates already exist, skipping"
else
  echo "[setup] generating certificates"
  docker compose -f generate-indexer-certs.yml run --rm generator
fi

# On macOS the generator makes the certs folder read-only before it can copy
# root-ca.pem to root-ca-manager.pem, so create that copy here if it is missing.
if [[ ! -f "$CERTS_DIR/root-ca-manager.pem" ]]; then
  echo "[setup] creating root-ca-manager.pem"
  chmod u+w "$CERTS_DIR"
  cp "$CERTS_DIR/root-ca.pem" "$CERTS_DIR/root-ca-manager.pem"
  chmod 400 "$CERTS_DIR/root-ca-manager.pem"
  chmod 500 "$CERTS_DIR"
fi

echo "[setup] done. Start the stack with: docker compose up -d"
echo "[setup] then run: ./apply-manager-config.sh"
