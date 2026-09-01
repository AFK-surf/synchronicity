#!/usr/bin/env bash
# Production-boundary e2e for managed cloud replicas.
#
# Real processes only: the Gleam control plane, `synch` customer daemon and
# `synch-dp` service. MinIO supplies the same S3 API production uses. The test
# publishes files from two customer nodes, waits for the hosted tenant to
# report both durable, removes both customer copies, and destroys the data-plane
# working directory. A fresh data-plane process must restore the same identity
# and serve both files to a third customer node that starts only afterwards.
set -Eeuo pipefail
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
mkdir -p "$WORKDIR/cp-db" "$WORKDIR/node-1" "$WORKDIR/node-2" \
  "$WORKDIR/node-3" "$WORKDIR/source-1" "$WORKDIR/source-2" "$WORKDIR/dp"

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
NODE1_PORT=$(port)
NODE2_PORT=$(port)
NODE3_PORT=$(port)
DP_METRICS_PORT=$(port)
CP_URL="http://127.0.0.1:$CP_HTTP_PORT"
DOMAIN=prod.acme.sync.test
CP_LOG="$WORKDIR/control-plane.log"
NODE1_LOG="$WORKDIR/node-1.log"
NODE2_LOG="$WORKDIR/node-2.log"
NODE3_LOG="$WORKDIR/node-3.log"
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
trap 'status=$?; echo "FAIL: command at line $LINENO exited $status" >&2' ERR

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
  tail -100 "$CP_LOG" "$NODE1_LOG" "$NODE2_LOG" "$NODE3_LOG" "$DP_LOG" \
    2>/dev/null || true
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

init_and_join() {
  local label=$1 dir=$2 port=$3
  local init_out="$WORKDIR/$label-init.out"
  "$SYNCH_BIN" --data-dir "$dir" init --domain "$DOMAIN" > "$init_out"
  local key
  key=$(awk '/^device key:/ { print $3 }' "$init_out")
  curl -fsS -b "$WORKDIR/cookies" -H "x-csrf: $CSRF" \
    -H 'content-type: application/json' \
    -d "{\"label\":\"$label\",\"nk\":\"$key\",\"addr\":\"127.0.0.1:$port\"}" \
    "$CP_URL/api/orgs/acme/networks/prod/devices" > "$WORKDIR/$label-join.json"
}

# node-3 is enrolled now so cloud-1 learns its production membership and
# direct-address hint, but its daemon does not start until both publishers and
# the first cloud volume are gone.
init_and_join node-1 "$WORKDIR/node-1" "$NODE1_PORT"
init_and_join node-2 "$WORKDIR/node-2" "$NODE2_PORT"
init_and_join node-3 "$WORKDIR/node-3" "$NODE3_PORT"
# The fleet is named before any org switches hosting on, which is the order a
# real deployment stands up in: placement runs inside the enable, and a network
# enabled while no data plane is registered is assigned to nobody by design
# (docs/CLOUD-DATAPLANE.md §7.2).
"${CP_BIN[@]}" dataplane register e2e-dp

curl -fsS -b "$WORKDIR/cookies" -H "x-csrf: $CSRF" \
  -H 'content-type: application/json' -X PUT -d '{"enabled":true}' \
  "$CP_URL/api/orgs/acme/networks/prod/cloud-hosting/enabled" \
  > "$WORKDIR/hosting.json"
# The enable answers which data plane took the network. Asserting it here is
# what keeps a silent regression to "assigned to nobody" from looking like a
# data plane that is merely slow to converge, forty lines further down.
grep -q '"data_plane":"e2e-dp"' "$WORKDIR/hosting.json" || {
  echo "FAIL: cloud hosting was enabled but assigned to no data plane" >&2
  cat "$WORKDIR/hosting.json" >&2
  exit 1
}

"${CP_BIN[@]}" dataplane-key mint e2e-fleet --dp e2e-dp > "$WORKDIR/dp-key.out"
DP_TOKEN=$(grep '^synchdp_' "$WORKDIR/dp-key.out")

printf 'written only by node-1\n' > "$WORKDIR/source-1/from-node-1.txt"
printf 'written only by node-2\n' > "$WORKDIR/source-2/from-node-2.txt"
EXPECTED_BYTES=$(wc -c < "$WORKDIR/source-1/from-node-1.txt")
EXPECTED_BYTES=$((EXPECTED_BYTES + $(wc -c < "$WORKDIR/source-2/from-node-2.txt")))

start_customer() {
  local dir=$1 port=$2 log=$3
  setsid "$SYNCH_BIN" --data-dir "$dir" \
    --bind "127.0.0.1:$port" --offline \
    --doh "$CP_URL/dns-query" --dnssec-anchor "$WORKDIR/anchor.key" \
    --rekor off --no-tuf daemon run > "$log" 2>&1 &
  CUSTOMER_PID=$!
  PIDS+=("$CUSTOMER_PID")
}

start_customer "$WORKDIR/node-1" "$NODE1_PORT" "$NODE1_LOG"
NODE1_PID=$CUSTOMER_PID
start_customer "$WORKDIR/node-2" "$NODE2_PORT" "$NODE2_LOG"
NODE2_PID=$CUSTOMER_PID
wait_for "node-1" 240 grep -q '^control socket:' "$NODE1_LOG"
wait_for "node-2" 240 grep -q '^control socket:' "$NODE2_LOG"
"$SYNCH_BIN" --data-dir "$WORKDIR/node-1" source add media "$WORKDIR/source-1"
"$SYNCH_BIN" --data-dir "$WORKDIR/node-1" source scan media
"$SYNCH_BIN" --data-dir "$WORKDIR/node-2" source add media "$WORKDIR/source-2"
"$SYNCH_BIN" --data-dir "$WORKDIR/node-2" source scan media

# Keep node-3 genuinely empty: it is enrolled but has not opened its endpoint,
# exchanged metadata, or fetched either payload.
[[ ! -e "$WORKDIR/node-3/cas" ]]

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
# acknowledgements for every payload and Bao outboard. Requiring two roots and
# their exact combined size proves cloud-1 replicated both publishers.
wait_for "both hosted S3 copies" 600 metric_has \
  "synch_dp_held_bytes{org=\"acme\",network=\"prod\"} $EXPECTED_BYTES"
metric_has 'synch_dp_held_roots{org="acme",network="prod"} 2'

# Remove both publishers and their whole working copies. The only remaining
# payloads are now in MinIO under cloud-1's durable claims.
"$SYNCH_BIN" --data-dir "$WORKDIR/node-1" daemon stop
"$SYNCH_BIN" --data-dir "$WORKDIR/node-2" daemon stop
wait "$NODE1_PID"
wait "$NODE2_PID"
mv "$WORKDIR/node-1" "$WORKDIR/node-1-lost"
mv "$WORKDIR/node-2" "$WORKDIR/node-2-lost"
mv "$WORKDIR/source-1" "$WORKDIR/source-1-lost"
mv "$WORKDIR/source-2" "$WORKDIR/source-2-lost"

kill -TERM "$DP_PID"
wait "$DP_PID"
mv "$WORKDIR/dp" "$WORKDIR/dp-first-ephemeral-volume"
mkdir -p "$WORKDIR/dp"
: > "$DP_LOG"

# A new cloud process on a blank volume must restore its identity, claims and
# both payloads before the only surviving customer node is started.
start_dp "$WORKDIR/dp" "$DP_LOG"
wait_for "the restored hosted tenant" 360 metric_has 'synch_dp_tenants_running 1'
SECOND_KEY=$(hosted_key)
[[ "$SECOND_KEY" == "$FIRST_KEY" ]] || {
  echo "FAIL: restored hosted identity changed ($FIRST_KEY -> $SECOND_KEY)" >&2
  exit 1
}
wait_for "both restored copies" 240 metric_has \
  "synch_dp_held_bytes{org=\"acme\",network=\"prod\"} $EXPECTED_BYTES"

# node-3 starts only now. It has no source, replica, or cached payload. Its
# first successful reads must therefore learn both publisher heads and fetch
# both bodies from the restored cloud-1 node.
start_customer "$WORKDIR/node-3" "$NODE3_PORT" "$NODE3_LOG"
NODE3_PID=$CUSTOMER_PID
wait_for "node-3" 240 grep -q '^control socket:' "$NODE3_LOG"

node3_knows_both() {
  "$SYNCH_BIN" --data-dir "$WORKDIR/node-3" ls media \
    > "$WORKDIR/node-3-tree.out" 2>/dev/null || return 1
  grep -q 'from-node-1.txt' "$WORKDIR/node-3-tree.out" &&
    grep -q 'from-node-2.txt' "$WORKDIR/node-3-tree.out"
}
wait_for "node-3 to learn both publishers from cloud-1" 600 node3_knows_both

node3_reads_both() {
  "$SYNCH_BIN" --data-dir "$WORKDIR/node-3" cat media/from-node-1.txt \
    > "$WORKDIR/node-3-read-1.txt" 2>/dev/null || return 1
  "$SYNCH_BIN" --data-dir "$WORKDIR/node-3" cat media/from-node-2.txt \
    > "$WORKDIR/node-3-read-2.txt" 2>/dev/null || return 1
  cmp "$WORKDIR/source-1-lost/from-node-1.txt" "$WORKDIR/node-3-read-1.txt" &&
    cmp "$WORKDIR/source-2-lost/from-node-2.txt" "$WORKDIR/node-3-read-2.txt"
}
wait_for "node-3 to read both files from cloud-1" 120 node3_reads_both

# Teardown is not an assertion: depending on whether the control response or
# process exit wins the race, `daemon stop` can report a closed socket. TERM the
# process group directly after the byte comparisons have passed.
kill -TERM -- "-$NODE3_PID" 2>/dev/null || kill -TERM "$NODE3_PID" 2>/dev/null || true
wait "$NODE3_PID" || true

if [[ -n "${SYNCH_E2E_S3_LIST_URL:-}" ]]; then
  curl -fsS "${SYNCH_E2E_S3_LIST_URL}?list-type=2&prefix=tenants/acme/prod/cas/" \
    > "$WORKDIR/cas-list.xml"
  CAS_KEYS=$(grep -o '<Key>tenants/acme/prod/cas/' "$WORKDIR/cas-list.xml" | wc -l)
  [[ "$CAS_KEYS" -ge 4 ]] || {
    echo "FAIL: expected two MinIO payload/outboard pairs, found $CAS_KEYS keys" >&2
    exit 1
  }
  curl -fsS "${SYNCH_E2E_S3_LIST_URL}?list-type=2&prefix=db/acme/prod/" \
    > "$WORKDIR/db-list.xml"
  grep -q '<Key>db/acme/prod/' "$WORKDIR/db-list.xml"
fi

kill -TERM "$DP_PID"
wait "$DP_PID" || true
echo "CLOUD-DATAPLANE-E2E-OK"
