#!/bin/sh
#
# Starts a daemon for local development, in the data directory the app defaults
# to. Point SYNCH_BIN at a build of the daemon, or leave it and it looks for the
# sibling synchronicity checkout.
#
# `daemon run`, deliberately, where the app now tells people to use `daemon
# start`. The two are not interchangeable: `start` spawns a detached child and
# returns, which is right for someone who wants a daemon running and their
# terminal back. This script `exec`s, so the daemon *is* this process and
# ctrl-C stops it — which is what a development helper should do. `start` here
# would exit immediately and leave an orphan behind.

set -eu

data_dir=${SYNCH_DATA_DIR:-"$HOME/Library/Application Support/synchronicity"}
socket_path="$data_dir/control.sock"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
daemon_path=${SYNCH_BIN:-}
if [ -z "$daemon_path" ]; then
  for candidate in \
    "$script_dir/../synchronicity/target/debug/synch" \
    "$script_dir/../synchronicity/target/release/synch" \
    "$(command -v synch || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      daemon_path=$candidate
      break
    fi
  done
fi

if [ -z "$daemon_path" ]; then
  echo "No synch binary found. Set SYNCH_BIN, or build the daemon next door." >&2
  exit 1
fi

while [ -S "$socket_path" ] && lsof -t -- "$socket_path" >/dev/null 2>&1; do
  sleep 1
done

exec "$daemon_path" \
  --data-dir "$data_dir" \
  --offline \
  --bind 127.0.0.1:0 \
  --no-tuf \
  daemon run
