#!/usr/bin/env bash
# Smoke-test the tools image CI publishes: run the three binaries it ships
# the way the README tells operators to, and prove the packaging is sound.
#
#   ./ops/image-smoke.sh [image]        # default: synch-tools:dev
#
# The workspace suite already tests the *code*; this tests the *image*,
# which nothing else does. A build that compiles clean can still ship a
# binary for the wrong architecture, a runtime missing ca-certificates, a
# data directory the service user cannot write, an ENV that leaves the CLI
# asking a container with no HOME for a platform data directory, or a
# `synch-s3` that cannot find the daemon's control socket. Every one of
# those is invisible until something runs.
#
# What it runs is a whole node: init, daemon, a source scanned and
# published, the tree read back through `synch cat`, and the same object
# served over HTTP by the gateway — one image, all three programs, no
# network beyond the container.
#
# Needs docker on the host. The busybox client for the gateway check
# shares the container's network namespace, so no host port is published
# and nothing here collides with a dev server.
set -euo pipefail

IMAGE=${1:-synch-tools:dev}
# The HTTP client for the gateway check. The tools image ships three
# programs and no curl, deliberately, so the one request this test makes
# comes from busybox in a throwaway container.
CLIENT_IMAGE=${CLIENT_IMAGE:-alpine:3}
CONTENT="hello from the image smoke test"

command -v docker > /dev/null || { echo "FAIL: docker is required"; exit 1; }

# Unique per run so a leftover container from a killed run cannot make a
# later one pass against a stale image.
SUFFIX="smoke-$$"
CONTAINER="synch-$SUFFIX"
# A named volume, not a bind mount: the image chowns /var/lib/synch to
# 10001 and a fresh named volume inherits that, which is what lets the
# non-root service write its own data directory on first run.
DATA_VOL="synch-data-$SUFFIX"
WORKDIR=$(mktemp -d)

cleanup() {
  docker rm -f "$CONTAINER" > /dev/null 2>&1 || true
  docker volume rm -f "$DATA_VOL" > /dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

ok() { echo "ok: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

logs_and_fail() {
  echo "--- docker logs ---" >&2
  docker logs "$CONTAINER" >&2 2>&1 || true
  fail "$1"
}

# `docker exec` into the running node. Every client command is one of
# these: the daemon owns the data directory, and the CLI, the gateway and
# every operational command are control clients of it (§9.1).
in_node() { docker exec "$CONTAINER" "$@"; }

docker volume create "$DATA_VOL" > /dev/null

# --- the three binaries are in the image, for this architecture --------
#
# `--version` is enough to catch the whole class: a missing binary, one
# built for the wrong architecture, a dynamic loader with nothing to load.
version=$(docker run --rm "$IMAGE" synch --version 2>&1) \
  || fail "synch --version failed in the image: $version"
[[ "$version" == synch\ * ]] || fail "unexpected synch --version output: $version"
ok "synch runs in the image ($version)"

s3_version=$(docker run --rm "$IMAGE" synch-s3 --version 2>&1) \
  || fail "synch-s3 --version failed in the image: $s3_version"
[[ "$s3_version" == synch-s3\ * ]] || fail "unexpected synch-s3 --version output: $s3_version"
ok "synch-s3 runs in the image ($s3_version)"

# The version the image reports has to be the version the context was
# built from. A stale layer that still runs is the failure this catches,
# and it is silent everywhere else.
if [ -r Cargo.toml ]; then
  expected=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
  [ -z "$expected" ] || [ "$version" = "synch $expected" ] \
    || fail "the image reports '$version', the workspace is at $expected"
  ok "the binaries are built from this working tree (v$expected)"
fi

# --- synch-dp starts and reads its environment -------------------------
#
# It has no CLI to ask for a version: configuration is the environment and
# nothing is read from disk (`docs/CLOUD-DATAPLANE.md`). So the check is
# that it gets far enough to reject an empty one — which means the binary
# loaded, the runtime came up, and `DpConfig::from_env` ran.
dp_status=0
dp=$(docker run --rm "$IMAGE" synch-dp 2>&1) || dp_status=$?
[ "$dp_status" -ne 0 ] || fail "synch-dp started with no configuration at all"
grep -q "SYNCH_DP_CONTROL_URL is required" <<< "$dp" \
  || fail "synch-dp did not reach its configuration check: $dp"
ok "synch-dp runs and reads its configuration from the environment"

# --- init writes to a fresh volume as uid 10001 ------------------------
docker run --rm -v "$DATA_VOL:/var/lib/synch" "$IMAGE" synch init \
  > "$WORKDIR/init.log" 2>&1 \
  || { cat "$WORKDIR/init.log"; fail "synch init failed in the image"; }
ok "synch init creates the data directory on a fresh named volume"

# --- the daemon owns the node ------------------------------------------
#
# --offline: no relays, no address discovery. The smoke test is about
# what is in the image, and a node that needed the internet to start
# would be testing the runner's egress instead.
#
# The source directory is a tmpfs rather than a second volume: a fresh
# volume at a path the image does not create comes up root-owned, and
# this process is uid 10001.
docker run -d --name "$CONTAINER" \
  -v "$DATA_VOL:/var/lib/synch" \
  --tmpfs /srv/smoke:rw,mode=1777 \
  "$IMAGE" synch --offline daemon run > /dev/null

ready=""
for _ in $(seq 1 100); do
  if in_node synch daemon status > "$WORKDIR/status.log" 2>&1; then ready=yes; break; fi
  docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true \
    || logs_and_fail "the daemon container exited before serving its control socket"
  sleep 0.5
done
[ -n "$ready" ] \
  || logs_and_fail "the daemon never answered on its control socket: $(cat "$WORKDIR/status.log")"
ok "the daemon serves its control socket in the image"

# The service must not be running as root — the image declares uid 10001
# and the data directory is owned by it, so a runtime that ignored USER
# would work by accident here and fail on a real deployment.
uid=$(in_node id -u 2>&1 | tr -d '\r') \
  || logs_and_fail "could not exec into the running container: $uid"
[ "$uid" = "10001" ] || logs_and_fail "container runs as uid $uid, expected 10001"
ok "the node runs as uid 10001"

in_node synch id > "$WORKDIR/id.log" 2>&1 \
  || { cat "$WORKDIR/id.log"; logs_and_fail "synch id failed against the running daemon"; }
ok "the node has an identity"

# --- a source is scanned, published, and read back ---------------------
#
# The first thing to touch the store and the CAS: hashing, SQLite, the
# signed root. A wrong-architecture binary is long dead by here, but a
# build that cannot open its own database is not.
in_node sh -c "printf '%s' '$CONTENT' > /srv/smoke/hello.txt" \
  || logs_and_fail "could not write the source file inside the container"
in_node synch source add smoke /srv/smoke > "$WORKDIR/source.log" 2>&1 \
  || { cat "$WORKDIR/source.log"; logs_and_fail "synch source add failed"; }
in_node synch source scan smoke > "$WORKDIR/scan.log" 2>&1 \
  || { cat "$WORKDIR/scan.log"; logs_and_fail "synch source scan failed"; }

in_node synch ls smoke > "$WORKDIR/ls.log" 2>&1 \
  || { cat "$WORKDIR/ls.log"; logs_and_fail "synch ls failed"; }
grep -q "hello.txt" "$WORKDIR/ls.log" \
  || logs_and_fail "the scanned file is not in the tree: $(cat "$WORKDIR/ls.log")"

read_back=$(in_node synch cat smoke/hello.txt 2>&1) \
  || logs_and_fail "synch cat failed: $read_back"
[ "$read_back" = "$CONTENT" ] \
  || logs_and_fail "synch cat returned '$read_back', expected '$CONTENT'"
ok "a source is scanned, published and read back through the tree"

# --- the gateway serves the same object over HTTP ----------------------
#
# `--anonymous` refuses anything but a loopback bind (§9.4), so the client
# joins the node's network namespace instead of a port being published:
# 127.0.0.1 inside that namespace is the gateway, and the host never sees
# an open port.
in_node synch-s3 bucket add smoke smoke --read-only > "$WORKDIR/bucket.log" 2>&1 \
  || { cat "$WORKDIR/bucket.log"; logs_and_fail "synch-s3 bucket add failed"; }
grep -q "smoke" <<< "$(in_node synch-s3 bucket ls 2>&1)" \
  || logs_and_fail "synch-s3 bucket ls does not list the bucket it just added"
ok "synch-s3 reaches the daemon over the control socket"

docker exec -d "$CONTAINER" synch-s3 serve --anonymous --listen 127.0.0.1:9000

served=""
for _ in $(seq 1 40); do
  served=$(docker run --rm --network "container:$CONTAINER" "$CLIENT_IMAGE" \
    wget -q -O - http://127.0.0.1:9000/smoke/hello.txt 2>/dev/null) && break
  sleep 0.5
done
[ "$served" = "$CONTENT" ] \
  || logs_and_fail "the gateway served '$served', expected '$CONTENT'"
ok "synch-s3 serves the published object over HTTP"

# --- and it shuts down on request --------------------------------------
#
# `daemon stop` is what an orchestrator's rolling restart ends up calling;
# a container whose main process ignores it is one that gets SIGKILLed at
# the end of every grace period.
in_node synch daemon stop > "$WORKDIR/stop.log" 2>&1 \
  || { cat "$WORKDIR/stop.log"; logs_and_fail "synch daemon stop failed"; }
exit_code=$(timeout 60 docker wait "$CONTAINER" 2>&1 || echo "timed out")
[ "$exit_code" = "0" ] || logs_and_fail "the daemon exited $exit_code after daemon stop"
ok "the daemon shuts down cleanly and the container exits 0"

echo
echo "the image is sound: $IMAGE"
