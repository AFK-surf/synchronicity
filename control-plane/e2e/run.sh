#!/usr/bin/env bash
# End-to-end: build the control plane, seed a demo zone, then have two
# independent validators prove the DNSSEC story:
#   1. delv (BIND) over port 53 UDP/TCP — positive, NODATA, and NXDOMAIN
#      answers must all report "fully validated".
#   2. The actual synchronicity client resolver (synch-net) over DoH.
set -euo pipefail
cd "$(dirname "$0")/.."

make -C csqlite
gleam build

# The dashboard is served out of priv/web (src/api/static.gleam), and this
# script is the only place that asks a *replica* for it. Staged here if a
# build exists — CI builds it in the job — so the comparison below has teeth.
# Without one, both nodes answer 404 and it degrades to a routing check, which
# is the honest floor: whether the file is in the shipment at all is
# `ops/image-smoke.sh`'s question, not this one.
if [[ -d web/dist ]]; then
  rm -rf priv/web && cp -r web/dist priv/web
fi

WORKDIR=$(mktemp -d)
LOG="$WORKDIR/serve.log"
cleanup() {
  # setsid gives each server its own process group; kill whole groups, or
  # the BEAM child of `gleam run` outlives the wrapper and keeps the
  # ports — every later run then talks to a stale zone.
  for pid in "${SERVER_PID:-}" "${REPLICA_PID:-}"; do
    [[ -n "$pid" ]] || continue
    local pgid
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ') || true
    [[ -n "$pgid" ]] && kill -- "-$pgid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

HTTP_PORT=8053
DNS_PORT=5359

if curl -fsS "http://127.0.0.1:${HTTP_PORT}/healthz" >/dev/null 2>&1; then
  echo "FAIL: something is already serving on the e2e ports — stale server?"
  exit 1
fi

export CP_ROLE=primary
export CP_BASE_DOMAIN=sync.test
# The database gets its own directory so the csqlite sandbox's directory
# grant never covers the sibling signing key (config refuses to start
# otherwise). The replica below has no key, so its db can sit anywhere.
mkdir -p "$WORKDIR/db"
export CP_DB_PATH="$WORKDIR/db/cp.db"
export CP_KEY_FILE="$WORKDIR/csk.key"
export CP_HTTP_LISTEN=127.0.0.1:$HTTP_PORT
export CP_DNS_LISTEN=127.0.0.1:$DNS_PORT
export CP_NS_HOSTS="ns1=127.0.0.1"
export CP_PUBLIC_URL="http://127.0.0.1:$HTTP_PORT"
export CP_SESSION_SECRET="e2e-only-session-secret-not-for-production"
# Browsing on, and the apex naming the whole fleet: the replica below is a
# node of this control plane, so a daemon must hold a tunnel to it too. The
# record's shape is cross-validated by the real client in e2e/tests.
export CP_BROWSE=on
export CP_ENDPOINTS="http://127.0.0.1:8054"

gleam run -- keygen "$CP_BASE_DOMAIN" "$CP_KEY_FILE" | tee "$WORKDIR/keygen.out"
# Zone-file syntax for the synchronicity client's --dnssec-anchor...
grep "IN DNSKEY" "$WORKDIR/keygen.out" > "$WORKDIR/anchor.key"
# ...and bind.keys syntax for delv -a.
awk '/IN DNSKEY/ {
  printf "trust-anchors {\n    \"%s\" static-key %s %s %s \"%s\";\n};\n",
         $1, $4, $5, $6, $7
}' "$WORKDIR/anchor.key" > "$WORKDIR/anchor.bindkeys"

gleam run -- seed | tee "$WORKDIR/seed.out"
get_seed() { grep "^$1=" "$WORKDIR/seed.out" | cut -d= -f2; }

setsid gleam run -- serve > "$LOG" 2>&1 &
SERVER_PID=$!

for i in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$HTTP_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "http://127.0.0.1:$HTTP_PORT/healthz"; echo

DOMAIN="prod.acme.$CP_BASE_DOMAIN"
QNAME="_synchronicity.$DOMAIN"

delv_check() {
  local qname=$1 qtype=$2 expect=$3 label=$4
  local out
  out=$(delv @127.0.0.1 -p "$DNS_PORT" -a "$WORKDIR/anchor.bindkeys" \
        +root="$CP_BASE_DOMAIN" "$qname" "$qtype" 2>&1) || true
  if ! grep -q "fully validated" <<<"$out"; then
    echo "FAIL($label): not fully validated"; echo "$out"; exit 1
  fi
  if ! grep -q "$expect" <<<"$out"; then
    echo "FAIL($label): expected '$expect'"; echo "$out"; exit 1
  fi
  echo "ok: $label"
}

# Positive answer over UDP.
delv_check "$QNAME" TXT "v=sync1" "positive TXT validates"
# Positive over TCP.
out=$(delv @127.0.0.1 -p "$DNS_PORT" +tcp -a "$WORKDIR/anchor.bindkeys" \
      +root="$CP_BASE_DOMAIN" "$QNAME" TXT 2>&1)
grep -q "fully validated" <<<"$out" || { echo "FAIL: TCP validation"; echo "$out"; exit 1; }
echo "ok: positive TXT validates over TCP"
# NODATA: existing name, absent type — negative proof must validate.
delv_check "$QNAME" A "negative response, fully validated" "NODATA proof validates"
# NXDOMAIN: nonexistent name — NSEC denial must validate.
delv_check "_synchronicity.nope.acme.$CP_BASE_DOMAIN" TXT \
  "negative response, fully validated" "NXDOMAIN proof validates"
# DNSKEY itself.
delv_check "$CP_BASE_DOMAIN" DNSKEY "257 3 13" "DNSKEY validates"

# Replica: hand a checkpointed copy of the database to a replica process
# (the external-refresh contract), and validate against it too.
python3 - "$CP_DB_PATH" <<'EOF'
import sqlite3, sys
sqlite3.connect(sys.argv[1]).execute("PRAGMA wal_checkpoint(FULL)")
EOF
cp "$CP_DB_PATH" "$WORKDIR/replica.db"
# The read half of the API is exercised here against a genuinely read-only
# copy rather than only against the primary's writable one.
# CP_SESSION_SECRET is inherited from the primary's environment, which is the
# contract: a replica verifies the cookies the primary minted.
# -u CP_ENDPOINTS: that list is the primary's, and a replica that
# sets it is describing a record it does not write — config refuses it,
# exactly as it refuses CP_KEY_FILE here.
env -u CP_KEY_FILE -u CP_ENDPOINTS \
  CP_ROLE=replica CP_DB_PATH="$WORKDIR/replica.db" \
  CP_PRIMARY_URL="http://127.0.0.1:$HTTP_PORT" \
  CP_BROWSE=on \
  CP_PUBLIC_URL=http://127.0.0.1:8054 \
  CP_HTTP_LISTEN=127.0.0.1:8054 \
  CP_DNS_LISTEN=127.0.0.1:5360 \
  setsid gleam run -- serve > "$WORKDIR/replica.log" 2>&1 &
REPLICA_PID=$!
for i in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:8054/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
out=$(delv @127.0.0.1 -p 5360 -a "$WORKDIR/anchor.bindkeys" \
      +root="$CP_BASE_DOMAIN" "$QNAME" TXT 2>&1)
grep -q "fully validated" <<<"$out" || { echo "FAIL: replica validation"; echo "$out"; cat "$WORKDIR/replica.log"; exit 1; }
echo "ok: replica serves the same fully-validated zone (no key material)"
# Refresh contract: atomically replace the replica's DB file with a newer
# copy (the primary re-published above, so serials differ) — the very next
# query must see it, with no reload signal of any kind.
cp "$CP_DB_PATH" "$WORKDIR/replica.db.new"
mv -f "$WORKDIR/replica.db.new" "$WORKDIR/replica.db"
out=$(delv @127.0.0.1 -p 5360 -a "$WORKDIR/anchor.bindkeys" \
  +root=sync.test "_synchronicity.prod.acme.sync.test" TXT 2>&1) || true
grep -q "fully validated" <<<"$out" || { echo "FAIL: replica after file swap"; echo "$out"; cat "$WORKDIR/replica.log"; exit 1; }
echo "ok: replica serves the swapped database file on the next query, fully validated"

# The read-only product surface: the reads answer, and the writes name the
# node that takes them rather than 404ing or failing at the sqlite layer.
methods=$(curl -fsS "http://127.0.0.1:8054/api/auth/methods")
grep -q '"primary":"http://127.0.0.1:'"$HTTP_PORT"'"' <<<"$methods" || {
  echo "FAIL: the replica's login screen must name the primary"; echo "$methods"; exit 1; }
grep -q '"magic_link":false' <<<"$methods" || {
  echo "FAIL: a node that mints no session must offer no method"; echo "$methods"; exit 1; }
# No -f: 409 is the answer under test, not a transport failure, and --fail
# would throw away the body that names the primary.
refused=$(curl -sS -o "$WORKDIR/refused.json" -w '%{http_code}' \
  -X POST -H 'content-type: application/json' -d '{"slug":"x","name":"X"}' \
  "http://127.0.0.1:8054/api/orgs" || true)
[[ "$refused" == "409" ]] || { echo "FAIL: a write on a replica must be 409, got $refused"; exit 1; }
grep -q 'read-only-replica' "$WORKDIR/refused.json" || {
  echo "FAIL: the refusal must name itself"; cat "$WORKDIR/refused.json"; exit 1; }
# The dashboard itself, off the same read-only copy. Compared against the
# primary rather than against a hardcoded 200: what this change added is that
# the *router* mounts the SPA fallback on a read-only node, and a regression
# there is a replica that 404s a path the primary serves. Asserting 200
# outright instead asserted that priv/web is populated, which is a packaging
# fact this job does not establish — and it duly failed in CI while passing on
# a working tree that happened to have a staged build.
spa_primary=$(curl -sS -o "$WORKDIR/spa-primary.html" -w '%{http_code}' \
  "http://127.0.0.1:$HTTP_PORT/o/acme")
spa_replica=$(curl -sS -o "$WORKDIR/spa-replica.html" -w '%{http_code}' \
  "http://127.0.0.1:8054/o/acme")
[[ "$spa_replica" == "$spa_primary" ]] || {
  echo "FAIL: /o/acme is $spa_replica on the replica and $spa_primary on the primary"; exit 1; }
cmp -s "$WORKDIR/spa-primary.html" "$WORKDIR/spa-replica.html" || {
  echo "FAIL: the replica serves a different body than the primary at /o/acme"; exit 1; }
if [[ "$spa_replica" == "200" ]]; then
  grep -q "<div id=\"root\"" "$WORKDIR/spa-replica.html" \
    || { head -5 "$WORKDIR/spa-replica.html"; echo "FAIL: that is not the dashboard"; exit 1; }
  echo "ok: replica serves the built dashboard and the read API, and names the primary for writes"
else
  echo "ok: replica routes the dashboard as the primary does (no built SPA staged), serves the read API, and names the primary for writes"
fi

# The actual synchronicity client resolver, over DoH.
export CP_DOH_URL="http://127.0.0.1:$HTTP_PORT/dns-query"
export CP_ANCHOR_FILE="$WORKDIR/anchor.key"
export CP_DOMAIN="$DOMAIN"
export CP_NAS_ACTIVE=$(get_seed nas_active)
export CP_NAS_REVOKED=$(get_seed nas_revoked)
export CP_LAPTOP_ACTIVE=$(get_seed laptop_active)
export CP_LAPTOP_RETIRING=$(get_seed laptop_retiring)
export CP_EXPECTED_ENDPOINTS="$CP_PUBLIC_URL,$CP_ENDPOINTS"
cargo test --manifest-path e2e/Cargo.toml -- --nocapture

echo "E2E-OK"
