#!/usr/bin/env bash
# Production-boundary e2e for managed cloud replicas.
#
# Real processes only: the Gleam control plane, `synch` customer daemon and
# `synch-dp` service. MinIO supplies the same S3 API production uses. The test
# publishes a file, waits for the hosted tenant to report it durable, removes
# the customer copy, destroys the data-plane working directory, and proves a
# fresh data-plane process restores the same hosted identity and held bytes.
set -euo pipefail
cd "$(dirname "$0")/../.."

require() {
  local name=$1
  [[ -n "${!name:-}" ]] || { echo "FAIL: $name is required" >&2; exit 1; }
}

require SYNCH_E2E_S3_ENDPOINT
require SYNCH_E2E_S3_BUCKET
require SYNCH_E2E_S3_ACCESS_KEY_ID
require SYNCH_E2E_S3_SECRET_ACCESS_KEY

if [[ "${SYNCH_E2E_SKIP_BUILD:-0}" != 1 ]]; then
  make -C control-plane/csqlite
  (cd control-plane && gleam export erlang-shipment)
  cargo build --release -p synch-cli -p synch-dp
fi

ROOT=$(pwd)
SYNCH_BIN="$ROOT/target/release/synch"
DP_BIN="$ROOT/target/release/synch-dp"
CP_SHIPMENT="$ROOT/control-plane/build/erlang-shipment/entrypoint.sh"
CP_BIN=(/bin/sh "$CP_SHIPMENT" run)
WORKDIR=$(mktemp -d)
mkdir -p "$WORKDIR/cp-db" "$WORKDIR/customer" "$WORKDIR/source" "$WORKDIR/dp"

port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

CP_HTTP_PORT=$(port)
CP_DNS_PORT=$(port)
CUSTOMER_PORT=$(port)
DP_METRICS_PORT=$(port)
CP_URL="http://127.0.0.1:$CP_HTTP_PORT"
DOMAIN=prod.acme.sync.test
CP_LOG="$WORKDIR/control-plane.log"
CUSTOMER_LOG="$WORKDIR/customer.log"
DP_LOG="$WORKDIR/data-plane.log"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] || continue
    if kill -0 "$pid" 2>/dev/null; then
      local pgid
      pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ') || true
      [[ -n "$pgid" ]] && kill -- "-$pgid" 2>/dev/null || kill "$pid" 2>/dev/null || true
    fi
  done
  if [[ "${SYNCH_E2E_KEEP_WORKDIR:-0}" == 1 ]]; then
    echo "e2e workdir retained at $WORKDIR"
  else
    find "$WORKDIR" -depth -delete
  fi
}
trap cleanup EXIT

wait_for() {
  local what=$1
  local attempts=$2
  shift 2
  for _ in $(seq 1 "$attempts"); do
    if "$@"; then
      return 0
    fi
    sleep 0.25
  done
  echo "FAIL: timed out waiting for $what" >&2
  tail -100 "$CP_LOG" "$CUSTOMER_LOG" "$DP_LOG" 2>/dev/null || true
  return 1
}

export CP_ROLE=primary
export CP_BASE_DOMAIN=sync.test
export CP_DB_PATH="$WORKDIR/cp-db/cp.db"
export CP_KEY_FILE="$WORKDIR/csk.key"
export CP_HTTP_LISTEN="127.0.0.1:$CP_HTTP_PORT"
export CP_DNS_LISTEN="127.0.0.1:$CP_DNS_PORT"
export CP_NS_HOSTS="ns1=127.0.0.1"
export CP_PUBLIC_URL="$CP_URL"
export CP_SESSION_SECRET=e2e-only-session-secret-not-for-production

"${CP_BIN[@]}" keygen "$CP_BASE_DOMAIN" "$CP_KEY_FILE" > "$WORKDIR/keygen.out"
grep "IN DNSKEY" "$WORKDIR/keygen.out" > "$WORKDIR/anchor.key"
"${CP_BIN[@]}" seed > "$WORKDIR/seed.out"

setsid "${CP_BIN[@]}" serve > "$CP_LOG" 2>&1 &
CP_PID=$!
PIDS+=("$CP_PID")
wait_for "the control plane" 120 curl -fsS "$CP_URL/healthz"

# Exercise the same authenticated product API an administrator uses: redeem a
# real one-time link, read the CSRF token, enrol the real customer node, then
# enable hosting.
"${CP_BIN[@]}" seed-admin seed@example.com > "$WORKDIR/admin.out"
MAGIC_URL=$(grep -o 'http[^ ]*token=[^ ]*' "$WORKDIR/admin.out")
curl -fsS -c "$WORKDIR/cookies" -o /dev/null "$MAGIC_URL"
curl -fsS -b "$WORKDIR/cookies" "$CP_URL/api/me" > "$WORKDIR/me.json"
CSRF=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf"])' \
  < "$WORKDIR/me.json")

"$SYNCH_BIN" --data-dir "$WORKDIR/customer" init --domain "$DOMAIN" \
  > "$WORKDIR/customer-init.out"
CUSTOMER_KEY=$(awk '/^device key:/ { print $3 }' "$WORKDIR/customer-init.out")
curl -fsS -b "$WORKDIR/cookies" -H "x-csrf: $CSRF" \
  -H 'content-type: application/json' \
  -d "{\"label\":\"e2e-customer\",\"nk\":\"$CUSTOMER_KEY\",\"addr\":\"127.0.0.1:$CUSTOMER_PORT\"}" \
  "$CP_URL/api/orgs/acme/networks/prod/devices" > "$WORKDIR/join.json"
curl -fsS -b "$WORKDIR/cookies" -H "x-csrf: $CSRF" \
  -H 'content-type: application/json' -X PUT -d '{"enabled":true}' \
  "$CP_URL/api/orgs/acme/networks/prod/cloud-hosting/enabled" \
  > "$WORKDIR/hosting.json"

"${CP_BIN[@]}" dataplane-key mint e2e-fleet > "$WORKDIR/dp-key.out"
DP_TOKEN=$(grep '^synchdp_' "$WORKDIR/dp-key.out")

printf 'the only customer copy\n' > "$WORKDIR/source/report.txt"
setsid "$SYNCH_BIN" --data-dir "$WORKDIR/customer" \
  --bind "127.0.0.1:$CUSTOMER_PORT" --offline \
  --doh "$CP_URL/dns-query" --dnssec-anchor "$WORKDIR/anchor.key" \
  --rekor off --no-tuf daemon run > "$CUSTOMER_LOG" 2>&1 &
CUSTOMER_PID=$!
PIDS+=("$CUSTOMER_PID")
wait_for "the customer daemon" 240 grep -q '^control socket:' "$CUSTOMER_LOG"
"$SYNCH_BIN" --data-dir "$WORKDIR/customer" source add media "$WORKDIR/source"
"$SYNCH_BIN" --data-dir "$WORKDIR/customer" source scan media

start_dp() {
  local base=$1 log=$2
  SYNCH_DP_CONTROL_URL="$CP_URL" \
  SYNCH_DP_TOKEN="$DP_TOKEN" \
  SYNCH_DP_BASE_DIR="$base" \
  SYNCH_DP_POLL_SECS=1 \
  SYNCH_DP_METRICS_ADDR="127.0.0.1:$DP_METRICS_PORT" \
  SYNCH_DP_DOH="$CP_URL/dns-query" \
  SYNCH_DP_DNSSEC_ANCHOR="$WORKDIR/anchor.key" \
  SYNCH_DP_REKOR=off \
  SYNCH_DP_CAS_BACKEND=s3 \
  SYNCH_DP_S3_BUCKET="$SYNCH_E2E_S3_BUCKET" \
  SYNCH_DP_S3_REGION="${SYNCH_E2E_S3_REGION:-us-east-1}" \
  SYNCH_DP_S3_ENDPOINT="$SYNCH_E2E_S3_ENDPOINT" \
  SYNCH_DP_S3_ACCESS_KEY_ID="$SYNCH_E2E_S3_ACCESS_KEY_ID" \
  SYNCH_DP_S3_SECRET_ACCESS_KEY="$SYNCH_E2E_S3_SECRET_ACCESS_KEY" \
  setsid "$DP_BIN" > "$log" 2>&1 &
  DP_PID=$!
  PIDS+=("$DP_PID")
}

metric_has() {
  local pattern=$1
  curl -fsS "http://127.0.0.1:$DP_METRICS_PORT/metrics" | grep -q "$pattern"
}

hosted_key() {
  curl -fsS -H "Authorization: Bearer $DP_TOKEN" \
    "$CP_URL/dp/v1/networks" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["networks"][0]["device"]["nk"])'
}

start_dp "$WORKDIR/dp" "$DP_LOG"
wait_for "the hosted tenant" 360 metric_has 'synch_dp_tenants_running 1'
FIRST_KEY=$(hosted_key)

# `held_bytes` is populated only after Cloud::finalize has received the S3
# acknowledgements for both payload and Bao outboard. This is the durability
# claim, observed through the production metrics surface.
wait_for "the hosted S3 copy" 480 metric_has \
  'synch_dp_held_bytes{org="acme",network="prod"} 23'

# Remove the publisher and its whole working copy. From here on the bucket is
# the only copy of the bytes and database stream this test can use.
"$SYNCH_BIN" --data-dir "$WORKDIR/customer" daemon stop
wait "$CUSTOMER_PID"
mv "$WORKDIR/customer" "$WORKDIR/customer-lost"
mv "$WORKDIR/source" "$WORKDIR/source-lost"

kill -TERM "$DP_PID"
wait "$DP_PID"
mv "$WORKDIR/dp" "$WORKDIR/dp-first-ephemeral-volume"
mkdir -p "$WORKDIR/dp"
: > "$DP_LOG"

# A new process on a blank volume must restore the stream, keep the exact same
# device identity, and still account for the held last copy.
start_dp "$WORKDIR/dp" "$DP_LOG"
wait_for "the restored hosted tenant" 360 metric_has 'synch_dp_tenants_running 1'
SECOND_KEY=$(hosted_key)
[[ "$SECOND_KEY" == "$FIRST_KEY" ]] || {
  echo "FAIL: restored hosted identity changed ($FIRST_KEY -> $SECOND_KEY)" >&2
  exit 1
}
wait_for "the restored last copy" 240 metric_has \
  'synch_dp_held_bytes{org="acme",network="prod"} 23'

# CI exposes this test-only bucket for listing, letting the harness also prove
# that both production prefixes exist instead of inferring that solely from
# the service's durable accounting.
if [[ -n "${SYNCH_E2E_S3_LIST_URL:-}" ]]; then
  curl -fsS "${SYNCH_E2E_S3_LIST_URL}?list-type=2&prefix=tenants/acme/prod/cas/" \
    > "$WORKDIR/cas-list.xml"
  grep -q '<Key>tenants/acme/prod/cas/' "$WORKDIR/cas-list.xml"
  curl -fsS "${SYNCH_E2E_S3_LIST_URL}?list-type=2&prefix=db/acme/prod/" \
    > "$WORKDIR/db-list.xml"
  grep -q '<Key>db/acme/prod/' "$WORKDIR/db-list.xml"
fi

kill -TERM "$DP_PID"
wait "$DP_PID"
echo "CLOUD-DATAPLANE-E2E-OK"
