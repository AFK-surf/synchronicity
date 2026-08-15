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
export CP_DB_PATH="$WORKDIR/cp.db"
export CP_KEY_FILE="$WORKDIR/csk.key"
export CP_HTTP_LISTEN=127.0.0.1:$HTTP_PORT
export CP_DNS_LISTEN=127.0.0.1:$DNS_PORT
export CP_NS_HOSTS="ns1=127.0.0.1"
export CP_PUBLIC_URL="http://127.0.0.1:$HTTP_PORT"
export CP_SESSION_SECRET="e2e-only-session-secret-not-for-production"

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
env -u CP_KEY_FILE -u CP_SESSION_SECRET \
  CP_ROLE=replica CP_DB_PATH="$WORKDIR/replica.db" \
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

# The actual synchronicity client resolver, over DoH.
export CP_DOH_URL="http://127.0.0.1:$HTTP_PORT/dns-query"
export CP_ANCHOR_FILE="$WORKDIR/anchor.key"
export CP_DOMAIN="$DOMAIN"
export CP_NAS_ACTIVE=$(get_seed nas_active)
export CP_NAS_REVOKED=$(get_seed nas_revoked)
export CP_LAPTOP_ACTIVE=$(get_seed laptop_active)
export CP_LAPTOP_RETIRING=$(get_seed laptop_retiring)
cargo test --manifest-path e2e/Cargo.toml -- --nocapture

echo "E2E-OK"
