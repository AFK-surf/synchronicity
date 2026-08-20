#!/usr/bin/env bash
# Smoke-test the container image CI publishes: run the built image the way
# the README tells operators to, and prove the three pieces it ships are
# actually in it and actually work — the Erlang shipment, the `csqlite`
# port program (sandbox included), and the built SPA in priv/web.
#
#   ./ops/image-smoke.sh [image]        # default: controlplane:dev
#
# The Gleam suite and e2e already test the *code*; this tests the
# *packaging*, which nothing else does: a missing priv/web, a csqlite
# built for the wrong architecture, an entrypoint that cannot pass its
# arguments through, a runtime image without libsqlite3 or curl, a
# seccomp profile that kills the sandbox — every one of those builds
# clean and fails on first boot.
#
# Needs docker, curl and dig (bind9-dnsutils) on the host. Host ports are
# overridable (HTTP_PORT / DNS_PORT) for running it beside a dev server.
set -euo pipefail

IMAGE=${1:-controlplane:dev}
HTTP_PORT=${HTTP_PORT:-18080}
DNS_PORT=${DNS_PORT:-15353}
BASE_DOMAIN=sync.test
DOMAIN="prod.acme.$BASE_DOMAIN"
QNAME="_synchronicity.$DOMAIN"

for tool in docker curl dig; do
  command -v "$tool" > /dev/null || { echo "FAIL: $tool is required"; exit 1; }
done

# Unique per run so a leftover container from a killed run cannot make a
# later one pass against a stale image.
SUFFIX="smoke-$$"
CONTAINER="cp-$SUFFIX"
# Named volumes, not bind mounts: the image chowns both directories to
# 10001 and a fresh named volume inherits that, which is exactly why the
# README tells operators to use them — the service is not root and cannot
# chown a root-owned host directory.
KEYS_VOL="cp-keys-$SUFFIX"
DATA_VOL="cp-data-$SUFFIX"
WORKDIR=$(mktemp -d)

cleanup() {
  docker rm -f "$CONTAINER" > /dev/null 2>&1 || true
  docker volume rm -f "$KEYS_VOL" "$DATA_VOL" > /dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

ok() { echo "ok: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

# One-shot subcommand containers: same image, same volumes, same
# environment the serving container gets.
run_cmd() {
  docker run --rm \
    -e CP_ROLE=primary \
    -e CP_BASE_DOMAIN="$BASE_DOMAIN" \
    -e CP_KEY_FILE=/etc/synch-controlplane/csk.key \
    -e CP_SESSION_SECRET="image-smoke-only-session-secret-not-for-production" \
    -e CP_NS_HOSTS="ns1=192.0.2.1" \
    -v "$KEYS_VOL:/etc/synch-controlplane" \
    -v "$DATA_VOL:/var/lib/synch-controlplane" \
    "$IMAGE" "$@"
}

docker volume create "$KEYS_VOL" > /dev/null
docker volume create "$DATA_VOL" > /dev/null

# --- the entrypoint passes its arguments through -----------------------
#
# ENTRYPOINT is `sh entrypoint.sh run`, so the image's arguments are the
# service's subcommands. An unknown one must reach the CLI and be
# rejected by it (exit 2, usage on stderr) rather than being swallowed.
usage_status=0
usage=$(docker run --rm "$IMAGE" not-a-subcommand 2>&1) || usage_status=$?
[ "$usage_status" -eq 2 ] || fail "unknown subcommand exited $usage_status, expected 2: $usage"
grep -q "usage: controlplane serve" <<< "$usage" \
  || fail "no usage from the CLI; entrypoint is not passing arguments: $usage"
ok "entrypoint passes subcommands to the service"

# --- the migration chain replays inside the image ----------------------
#
# The first thing that touches priv/csqlite: it runs the whole chain
# against a scratch database, so a port program built for the wrong
# architecture, or a runtime missing libsqlite3, dies here.
run_cmd migrate-check > "$WORKDIR/migrate.log" 2>&1 \
  || { cat "$WORKDIR/migrate.log"; fail "migrate-check failed in the image"; }
ok "migrate-check replays the migration chain in the image"

# --- keygen writes to the key volume -----------------------------------
run_cmd keygen "$BASE_DOMAIN" /etc/synch-controlplane/csk.key \
  > "$WORKDIR/keygen.out" 2> "$WORKDIR/keygen.err" \
  || { cat "$WORKDIR/keygen.out" "$WORKDIR/keygen.err"; fail "keygen failed in the image"; }
grep -q " IN DS " "$WORKDIR/keygen.out" || { cat "$WORKDIR/keygen.out"; fail "keygen printed no DS record"; }
grep -q " IN DNSKEY " "$WORKDIR/keygen.out" || { cat "$WORKDIR/keygen.out"; fail "keygen printed no anchor"; }
ok "keygen writes the zone key to a fresh named volume as uid 10001"

# --- seed publishes a zone into the data volume ------------------------
run_cmd seed > "$WORKDIR/seed.out" 2>&1 \
  || { cat "$WORKDIR/seed.out"; fail "seed failed in the image"; }
grep -q "^serial=" "$WORKDIR/seed.out" || { cat "$WORKDIR/seed.out"; fail "seed published no zone"; }
ok "seed publishes a signed zone into the data volume"

# --- serve -------------------------------------------------------------
docker run -d --name "$CONTAINER" \
  -e CP_ROLE=primary \
  -e CP_BASE_DOMAIN="$BASE_DOMAIN" \
  -e CP_KEY_FILE=/etc/synch-controlplane/csk.key \
  -e CP_SESSION_SECRET="image-smoke-only-session-secret-not-for-production" \
  -e CP_NS_HOSTS="ns1=192.0.2.1" \
  -e CP_PUBLIC_URL="http://127.0.0.1:$HTTP_PORT" \
  -v "$KEYS_VOL:/etc/synch-controlplane" \
  -v "$DATA_VOL:/var/lib/synch-controlplane" \
  -p "127.0.0.1:$HTTP_PORT:8080" \
  -p "127.0.0.1:$DNS_PORT:53/udp" \
  -p "127.0.0.1:$DNS_PORT:53/tcp" \
  "$IMAGE" > /dev/null

logs_and_fail() {
  echo "--- docker logs ---" >&2
  docker logs "$CONTAINER" >&2 2>&1 || true
  fail "$1"
}

for _ in $(seq 1 100); do
  curl -fsS "http://127.0.0.1:$HTTP_PORT/healthz" > "$WORKDIR/healthz.json" 2>/dev/null && break
  docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true \
    || logs_and_fail "the container exited before serving /healthz"
  sleep 0.5
done
grep -q '"status":"ok"' "$WORKDIR/healthz.json" \
  || logs_and_fail "/healthz never reported ok: $(cat "$WORKDIR/healthz.json" 2>/dev/null)"
grep -q '"soa_serial"' "$WORKDIR/healthz.json" \
  || logs_and_fail "/healthz reports no serving zone: $(cat "$WORKDIR/healthz.json")"
ok "the container serves /healthz with a signed zone loaded"

# The service must not be running as root — the image declares uid 10001
# and the database directory is owned by it, so a runtime that ignored
# USER would work by accident here and fail on a real deployment.
uid=$(docker exec "$CONTAINER" id -u 2>&1 | tr -d '\r') \
  || logs_and_fail "could not exec into the running container: $uid"
[ "$uid" = "10001" ] || logs_and_fail "container runs as uid $uid, expected 10001"
ok "the service runs as uid 10001"

# The csqlite workers sandbox themselves before reading their first
# frame. Docker's default seccomp profile permits landlock_* and the
# runner's kernel has it, so a warning here is a real regression in the
# image (a stale port program, a dropped capability) and not noise —
# README.md calls that line a deployment defect.
if docker logs "$CONTAINER" 2>&1 | grep -q "filesystem unconfined"; then
  logs_and_fail "csqlite came up unconfined inside the container"
fi
ok "csqlite workers sandbox themselves under the default runtime profile"

# The trusted root is a tracked source file riding the shipment (priv/tuf/,
# COPYed in by the shipment stage); when the build drops it — a broadened
# .dockerignore once did — the service still boots and serves and every
# check above still passes, but `rekor-publish` and the external-mode key
# watcher can never discover a log.
#
# Asserted against the filesystem rather than the logs. The string a
# missing file produces (`trusted_root.shipped`) is only ever reached from
# `client.discover`, whose boot-time caller is the external-mode key
# watcher — and this container runs CP_ROLE=primary, which never mounts it.
# Grepping for it therefore passed whether the file shipped or not, which
# is the exact regression this check exists to catch.
# Searched by name rather than at a fixed path. `priv_dir/1` resolves
# through `code:priv_dir(controlplane)`, so the file's location inside the
# shipment is the release layout's business, and a check that hardcodes one
# and silently stops matching when that moves is the failure mode being
# fixed here — not a new guard worth introducing. There is exactly one file
# of this name in the tree, so the name is the whole question: did it ship.
if ! docker run --rm --entrypoint /bin/sh "$IMAGE" -c \
  'find /opt/synch-controlplane -name sigstore_trusted_root.json -size +0 \
     | grep -q .'; then
  fail "the trusted root did not ship in the image (priv/tuf/sigstore_trusted_root.json missing or empty)"
fi
ok "the trusted root ships in priv/tuf"

# --- the shipped SPA ---------------------------------------------------
#
# priv/web is copied in from a separate build stage; when that breaks the
# service still starts and every API test still passes, so only a request
# for the dashboard notices.
curl -fsS "http://127.0.0.1:$HTTP_PORT/" > "$WORKDIR/index.html" \
  || logs_and_fail "the dashboard root did not respond"
grep -q '<div id="root">' "$WORKDIR/index.html" \
  || logs_and_fail "the dashboard root is not the built SPA: $(head -c 200 "$WORKDIR/index.html")"
asset=$(grep -o '/assets/[A-Za-z0-9._-]*\.js' "$WORKDIR/index.html" | head -1)
[ -n "$asset" ] || logs_and_fail "the served index.html references no built asset bundle"
curl -fsS -o /dev/null "http://127.0.0.1:$HTTP_PORT$asset" \
  || logs_and_fail "the SPA bundle $asset is missing from priv/web"
ok "the built SPA is served from priv/web, bundle included"

# --- the shipped CLI guide ---------------------------------------------
#
# priv/skill/SKILL.md is a tracked source file the shipment stage COPYs in,
# the same shape as the trusted root above and open to the same packaging
# slip. Served over HTTP rather than found on disk, because the route is the
# thing being claimed: a file that shipped under a path `priv_dir/1` does not
# resolve is the same 404 to every caller.
curl -fsS "http://127.0.0.1:$HTTP_PORT/SKILL.md" > "$WORKDIR/SKILL.md" \
  || logs_and_fail "GET /SKILL.md did not respond"
grep -q '^# synch' "$WORKDIR/SKILL.md" \
  || logs_and_fail "/SKILL.md is not the CLI guide: $(head -c 200 "$WORKDIR/SKILL.md")"
ok "the synch guide ships in priv/skill and is served at /SKILL.md"

# The DoH route exists (400 for a query with no dns= parameter, not the
# 404 an unrouted path would give).
doh=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/dns-query")
[ "$doh" = "400" ] || logs_and_fail "GET /dns-query returned $doh, expected 400"
ok "the DoH endpoint is routed"

# --- authoritative DNS, UDP and TCP ------------------------------------
#
# Signature checking is the e2e suite's job (it runs delv against a real
# chain); here the question is only whether the packaged service answers
# on both transports from outside the container.
dns_check() {
  local transport=$1 dig_flag=$2 out
  out=$(dig @127.0.0.1 -p "$DNS_PORT" $dig_flag +dnssec +noall +answer "$QNAME" TXT 2>&1) || true
  grep -q "v=sync1" <<< "$out" || logs_and_fail "no membership TXT over $transport: $out"
  grep -q "RRSIG" <<< "$out" || logs_and_fail "unsigned answer over $transport: $out"
  ok "authoritative DNS answers $QNAME over $transport, signed"
}
dns_check UDP "+notcp"
dns_check TCP "+tcp"

# --- the image's own HEALTHCHECK ---------------------------------------
#
# Orchestrators act on this, so the probe itself has to work: it needs
# curl in the runtime image and the right default port.
health=starting
for _ in $(seq 1 60); do
  health=$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo unknown)
  [ "$health" = "starting" ] || break
  sleep 2
done
[ "$health" = "healthy" ] || logs_and_fail "HEALTHCHECK reported '$health', expected healthy"
ok "the image's HEALTHCHECK reports healthy"

echo "IMAGE-SMOKE-OK ($IMAGE)"
