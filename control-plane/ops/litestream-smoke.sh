#!/usr/bin/env bash
# Primary → litestream → replica, with the real tool over the real contract.
#
#   ./ops/litestream-smoke.sh
#
# `ops/RUNBOOK.md` tells operators to keep the primary's database in WAL
# mode, run `litestream replicate` against it, and refresh each replica with
# `litestream restore` into a scratch file followed by an atomic rename. That
# is the whole of the replication contract this service depends on and none
# of which it implements — so nothing in the repo ran it. `e2e/run.sh` stands
# a replica up too, but it hands over the file with `cp` after an explicit
# `wal_checkpoint(FULL)`, which is a *weaker* thing than the documented
# contract in the way that matters: it proves nothing about a write the
# primary made while serving, because the checkpoint moved it into the main
# database file first. A plain `cp` without that checkpoint silently serves a
# stale zone, which is exactly the failure an operator would hit.
#
# So this runs the documented commands, mutates the primary through its own
# API *while litestream is replicating*, and then asks the replica for what
# was written:
#
#   * the zone it serves over DNS, so the DNSSEC half is covered;
#   * the read API, with the session cookie the primary minted, so the
#     fleet dashboard's premise — replicated session rows plus a shared
#     CP_SESSION_SECRET — is covered too;
#   * a write, which must be refused with the primary's address.
#
# Then it does it again, to cover the refresh: a second restore over a
# running replica must be served on the very next query, with no reload
# signal of any kind.
#
# Needs litestream, curl, dig (bind9-dnsutils), and the Gleam toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in litestream curl dig gleam; do
  command -v "$tool" > /dev/null || { echo "FAIL: $tool is required"; exit 1; }
done

make -C csqlite
gleam build

WORKDIR=$(mktemp -d)
PRIMARY_HTTP=8071
PRIMARY_DNS=5371
REPLICA_HTTP=8072
REPLICA_DNS=5372
BASE_DOMAIN=sync.test

cleanup() {
  # setsid gives each server its own process group; kill whole groups, or
  # the BEAM child of `gleam run` outlives the wrapper and keeps the ports.
  for pid in "${LITESTREAM_PID:-}" "${PRIMARY_PID:-}" "${REPLICA_PID:-}"; do
    [[ -n "$pid" ]] || continue
    local pgid
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ') || true
    [[ -n "$pgid" ]] && kill -- "-$pgid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

ok() { echo "ok: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

# The database gets its own directory: the csqlite sandbox grants that
# directory, so the signing key has to sit outside it.
# Three directories, because the csqlite sandbox grants each database's own
# directory: the primary's, the replica's, and litestream's replica store.
# The signing key sits outside all of them.
mkdir -p "$WORKDIR/db" "$WORKDIR/replica-db" "$WORKDIR/store"
export CP_ROLE=primary
export CP_BASE_DOMAIN="$BASE_DOMAIN"
export CP_DB_PATH="$WORKDIR/db/cp.db"
export CP_KEY_FILE="$WORKDIR/csk.key"
export CP_HTTP_LISTEN=127.0.0.1:$PRIMARY_HTTP
export CP_DNS_LISTEN=127.0.0.1:$PRIMARY_DNS
export CP_NS_HOSTS="ns1=127.0.0.1"
export CP_PUBLIC_URL="http://127.0.0.1:$PRIMARY_HTTP"
# The same secret the replica gets: a replica verifies cookies the primary
# minted, and this test is here partly to prove that it does.
export CP_SESSION_SECRET="litestream-smoke-only-secret-not-for-production"
export CP_ENDPOINTS="http://127.0.0.1:$REPLICA_HTTP"

gleam run -- keygen "$CP_BASE_DOMAIN" "$CP_KEY_FILE" > "$WORKDIR/keygen.out"
grep "IN DNSKEY" "$WORKDIR/keygen.out" > "$WORKDIR/anchor.key"
gleam run -- seed > "$WORKDIR/seed.out"

setsid gleam run -- serve > "$WORKDIR/primary.log" 2>&1 &
PRIMARY_PID=$!
for _ in $(seq 1 100); do
  curl -fsS "http://127.0.0.1:$PRIMARY_HTTP/healthz" > /dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "http://127.0.0.1:$PRIMARY_HTTP/healthz" > /dev/null \
  || { cat "$WORKDIR/primary.log"; fail "the primary never came up"; }

# --- litestream replicates the live database ---------------------------
#
# A `file:` replica, not S3: the tool under test is litestream's own
# WAL-shipping and restore, and an object store adds credentials and a
# network without adding coverage of it.
setsid litestream replicate "$CP_DB_PATH" "file://$WORKDIR/store" \
  > "$WORKDIR/litestream.log" 2>&1 < /dev/null &
LITESTREAM_PID=$!
# The snapshot, not merely the attach: `restore` has nothing to restore from
# until one exists, and litestream writes it a moment after it starts.
for _ in $(seq 1 150); do
  grep -q "snapshot written" "$WORKDIR/litestream.log" && break
  sleep 0.2
done
grep -q "snapshot written" "$WORKDIR/litestream.log" \
  || { cat "$WORKDIR/litestream.log"; fail "litestream wrote no snapshot"; }
ok "litestream is replicating the primary's WAL"

# --- a session on the primary ------------------------------------------
#
# Magic link out of the service log: the mailer is log-only here, which is
# what the login screen tells an operator to do anyway.
curl -fsS -X POST -H 'content-type: application/json' \
  -d '{"email":"admin@example.com"}' \
  "http://127.0.0.1:$PRIMARY_HTTP/auth/magic" > /dev/null
for _ in $(seq 1 50); do
  grep -q "/auth/magic/redeem?token=" "$WORKDIR/primary.log" && break
  sleep 0.2
done
LINK=$(grep -o "http://127.0.0.1:$PRIMARY_HTTP/auth/magic/redeem?token=[A-Za-z0-9_-]*" \
       "$WORKDIR/primary.log" | tail -1)
[[ -n "$LINK" ]] || { cat "$WORKDIR/primary.log"; fail "no magic link in the service log"; }
COOKIE=$(curl -sS -i "$LINK" | grep -i '^set-cookie' | sed 's/.*cp_session=\([^;]*\).*/\1/' | tr -d '\r')
[[ -n "$COOKIE" ]] || fail "redeeming the magic link set no session cookie"
CSRF=$(curl -fsS -H "Cookie: cp_session=$COOKIE" "http://127.0.0.1:$PRIMARY_HTTP/api/me" \
       | sed 's/.*"csrf":"\([^"]*\)".*/\1/')
[[ -n "$CSRF" ]] || fail "no session on the primary after redeeming"

api() {
  local method=$1 path=$2 body=${3:-}
  curl -sS -X "$method" \
    -H "Cookie: cp_session=$COOKIE" -H "x-csrf: $CSRF" \
    ${body:+-H 'content-type: application/json' -d "$body"} \
    "$path"
}

# A fresh node key in z-base-32: 32 random bytes as 52 characters, which is
# what `model.validate_nk` requires. Fresh per device rather than reused from
# the seed, because §3.2 makes one key one identity and the same key under
# two labels is refused at publish — which would fail this test for a reason
# with nothing to do with replication.
fresh_nk() {
  python3 - <<'PYTHON'
import os
# 256 bits left-padded to 260 so the final character's spare bits are zero,
# which is the canonical spelling a strict decoder expects.
bits = int.from_bytes(os.urandom(32), "big") << 4
alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
print("".join(alphabet[(bits >> (255 - 5 * i)) & 31] for i in range(52)))
PYTHON
}

# One device, created and assigned: a membership name with no members has no
# TXT record at all, so without this there would be nothing at the new name
# for the replica to serve and the DNS check would be vacuous.
add_device() {
  local label=$1 network=$2 device
  device=$(api POST "http://127.0.0.1:$PRIMARY_HTTP/api/orgs/fleet/devices" \
    "{\"label\":\"$label\",\"nk\":\"$(fresh_nk)\"}" \
    | sed 's/.*"device_id":"\([^"]*\)".*/\1/')
  [[ -n "$device" ]] || fail "could not create device $label"
  api PUT "http://127.0.0.1:$PRIMARY_HTTP/api/orgs/fleet/networks/$network/devices/$device" \
    > /dev/null || fail "could not assign device $label to $network"
}

primary_serial() {
  curl -fsS "http://127.0.0.1:$PRIMARY_HTTP/healthz" | sed 's/.*"soa_serial":\([0-9]*\).*/\1/'
}
replica_serial() {
  curl -fsS "http://127.0.0.1:$REPLICA_HTTP/healthz" | sed 's/.*"soa_serial":\([0-9]*\).*/\1/'
}

# --- restore, atomically rename, serve ---------------------------------
#
# Exactly the two commands the runbook's replica refresh loop runs, in a
# loop as the runbook's cron timer runs them. No checkpoint here and none
# anywhere: if litestream did not carry the WAL, the restored file is a zone
# from before the mutation and the loop never converges.
restore() {
  rm -f "$WORKDIR/replica-db/cp.db.new"
  litestream restore -o "$WORKDIR/replica-db/cp.db.new" "file://$WORKDIR/store" \
    >> "$WORKDIR/restore.log" 2>&1 \
    || { tail -20 "$WORKDIR/restore.log"; fail "litestream restore failed"; }
  mv -f "$WORKDIR/replica-db/cp.db.new" "$WORKDIR/replica-db/cp.db"
}

# Refresh until the running replica serves `$1`, or give up. The bound is
# generous against litestream's 1s sync interval and a CI runner's clock; it
# is not a race the test can pass by luck, because a WAL that never travels
# never converges.
refresh_until() {
  local want=$1
  for _ in $(seq 1 30); do
    restore
    [[ "$(replica_serial)" == "$want" ]] && return 0
    sleep 1
  done
  fail "the replica settled on $(replica_serial), the primary published $want — the WAL did not travel"
}

restore
ok "litestream restored a copy of the live database"

env -u CP_KEY_FILE -u CP_ENDPOINTS -u CP_NS_HOSTS \
  CP_ROLE=replica \
  CP_DB_PATH="$WORKDIR/replica-db/cp.db" \
  CP_PRIMARY_URL="http://127.0.0.1:$PRIMARY_HTTP" \
  CP_PUBLIC_URL="http://127.0.0.1:$REPLICA_HTTP" \
  CP_HTTP_LISTEN=127.0.0.1:$REPLICA_HTTP \
  CP_DNS_LISTEN=127.0.0.1:$REPLICA_DNS \
  setsid gleam run -- serve > "$WORKDIR/replica.log" 2>&1 < /dev/null &
REPLICA_PID=$!
for _ in $(seq 1 150); do
  curl -fsS "http://127.0.0.1:$REPLICA_HTTP/healthz" > /dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "http://127.0.0.1:$REPLICA_HTTP/healthz" > /dev/null \
  || { cat "$WORKDIR/replica.log"; fail "the replica never came up"; }
ok "the replica serves the restored file"

# --- a mutation on the primary, while the replica is live --------------
#
# This is the case a `cp` of the database file cannot cover and the reason
# this test exists: the write lands in the WAL of a database that is open and
# serving, and only litestream's WAL shipping carries it.
api POST "http://127.0.0.1:$PRIMARY_HTTP/api/orgs" '{"slug":"fleet","name":"Fleet"}' \
  | grep -q '"slug":"fleet"' || fail "could not create the org on the primary"
api POST "http://127.0.0.1:$PRIMARY_HTTP/api/orgs/fleet/networks" '{"name":"prod"}' \
  | grep -q '"name":"prod"' || fail "could not create the network on the primary"
add_device nas prod
PRIMARY_SERIAL=$(primary_serial)
refresh_until "$PRIMARY_SERIAL"
ok "the replica serves serial $PRIMARY_SERIAL, written while both were running"

# The zone, over real DNS: the membership name for a network that did not
# exist when the replica booted.
dig @127.0.0.1 -p "$REPLICA_DNS" +short +tcp \
  "_synchronicity.prod.fleet.$BASE_DOMAIN" TXT | grep -q "v=sync1" \
  || fail "the replica does not serve the network created after it booted"
ok "the replica answers DNS for a network created after it booted"

# The read API, with the cookie the *primary* minted. This is the fleet
# dashboard's whole premise in one request: the session row replicated, and
# the shared CP_SESSION_SECRET verifies the signature the primary wrote.
curl -fsS -H "Cookie: cp_session=$COOKIE" "http://127.0.0.1:$REPLICA_HTTP/api/me" \
  | grep -q '"email":"admin@example.com"' \
  || fail "the primary's session cookie does not resolve on the replica"
curl -fsS -H "Cookie: cp_session=$COOKIE" \
  "http://127.0.0.1:$REPLICA_HTTP/api/orgs/fleet/networks" | grep -q '"name":"prod"' \
  || fail "the replica's read API does not show the replicated network"
ok "the replica answers the read API with the session the primary minted"

# And the other half: a write is refused with the address of the node that
# takes it, rather than failing somewhere inside sqlite.
refused_body="$WORKDIR/refused.json"
refused=$(curl -sS -o "$refused_body" -w '%{http_code}' \
  -X POST -H "Cookie: cp_session=$COOKIE" -H "x-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"slug":"nope","name":"Nope"}' \
  "http://127.0.0.1:$REPLICA_HTTP/api/orgs")
[[ "$refused" == "409" ]] || { cat "$refused_body"; fail "a write on the replica answered $refused, expected 409"; }
grep -q "http://127.0.0.1:$PRIMARY_HTTP" "$refused_body" \
  || { cat "$refused_body"; fail "the refusal does not name the primary"; }
ok "a write on the replica is refused with the primary's address"

# --- the refresh contract ----------------------------------------------
#
# A second mutation, a second restore, an atomic rename over a replica that
# has already answered queries from the old file. Every pooled checkout
# reopens the database, so the swap must be served on the next query with no
# reload signal, no restart and no poll.
api POST "http://127.0.0.1:$PRIMARY_HTTP/api/orgs/fleet/networks" '{"name":"staging"}' \
  | grep -q '"name":"staging"' || fail "could not create the second network"
add_device laptop staging
NEXT_SERIAL=$(primary_serial)
[[ "$NEXT_SERIAL" != "$PRIMARY_SERIAL" ]] || fail "the second mutation did not bump the serial"
refresh_until "$NEXT_SERIAL"
dig @127.0.0.1 -p "$REPLICA_DNS" +short +tcp \
  "_synchronicity.staging.fleet.$BASE_DOMAIN" TXT | grep -q "v=sync1" \
  || fail "the replica does not serve the swapped-in zone over DNS"
ok "a live replica serves the swapped file on the next query, with no reload signal"

echo "LITESTREAM-SMOKE-OK"
