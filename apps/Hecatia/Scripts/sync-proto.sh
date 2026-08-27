#!/bin/sh
#
# The daemon owns control.proto; Hecatia keeps a target-local copy for SwiftPM's
# protoc plugins. Both live in this monorepo, so the copy must never drift.
#
#   Scripts/sync-proto.sh check   [path-to-synchronicity]   (default: ../..)
#   Scripts/sync-proto.sh update  [path-to-synchronicity]

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
mine="$project_dir/Sources/Hecatia/control.proto"

action=${1:-check}
daemon_repo=${2:-$project_dir/../..}
theirs="$daemon_repo/crates/synch-cli/proto/control.proto"

if [ ! -f "$theirs" ]; then
  echo "no control.proto at $theirs" >&2
  echo "the canonical monorepo proto is required" >&2
  exit 2
fi

case "$action" in
  check)
    if diff -q "$theirs" "$mine" >/dev/null; then
      echo "control.proto is in sync with $daemon_repo"
    else
      echo "control.proto has DRIFTED from $daemon_repo:" >&2
      diff -u "$mine" "$theirs" || true
      exit 1
    fi
    ;;
  update)
    cp "$theirs" "$mine"
    echo "copied $theirs -> $mine"
    ;;
  *)
    echo "usage: $0 [check|update] [path-to-synchronicity]" >&2
    exit 2
    ;;
esac
