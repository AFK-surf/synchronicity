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
  # setsid gives the server its own process group; kill the whole group,
  # or the BEAM child of `gleam run` outlives the wrapper and keeps the
  # ports — every later run then talks to a stale zone.
  [[ -n "${SERVER_PID:-}" ]] && kill -- -"$SERVER_PID" 2>/dev/null || true
  cat "$LOG" 2>/dev/null | tail -20 || true
}
trap cleanup EXIT

if curl -fsS "http://127.0.0.1:${CP_HTTP_PORT:-8053}/healthz" >/dev/null 2>&1; then
  echo "FAIL: something is already serving on the e2e ports — stale server?"
  exit 1
fi

export CP_ROLE=primary
export CP_BASE_DOMAIN=sync.test
export CP_DB_PATH="$WORKDIR/cp.db"
export CP_KEY_FILE="$WORKDIR/csk.key"
export CP_HTTP_PORT=8053
export CP_DNS_PORT=5359
export CP_NS_HOSTS="ns1=127.0.0.1"
export CP_PUBLIC_URL="http://127.0.0.1:$CP_HTTP_PORT"
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
  curl -fsS "http://127.0.0.1:$CP_HTTP_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "http://127.0.0.1:$CP_HTTP_PORT/healthz"; echo

DOMAIN="prod.acme.$CP_BASE_DOMAIN"
QNAME="_synchronicity.$DOMAIN"

delv_check() {
  local qname=$1 qtype=$2 expect=$3 label=$4
  local out
  out=$(delv @127.0.0.1 -p "$CP_DNS_PORT" -a "$WORKDIR/anchor.bindkeys" \
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
out=$(delv @127.0.0.1 -p "$CP_DNS_PORT" +tcp -a "$WORKDIR/anchor.bindkeys" \
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

# The actual synchronicity client resolver, over DoH.
export CP_DOH_URL="http://127.0.0.1:$CP_HTTP_PORT/dns-query"
export CP_ANCHOR_FILE="$WORKDIR/anchor.key"
export CP_DOMAIN="$DOMAIN"
export CP_NAS_ACTIVE=$(get_seed nas_active)
export CP_NAS_REVOKED=$(get_seed nas_revoked)
export CP_LAPTOP_ACTIVE=$(get_seed laptop_active)
export CP_LAPTOP_RETIRING=$(get_seed laptop_retiring)
cargo test --manifest-path e2e/Cargo.toml -- --nocapture

echo "E2E-OK"
