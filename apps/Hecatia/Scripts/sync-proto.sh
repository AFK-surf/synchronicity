#!/bin/sh
#
# The daemon owns control.proto; this repo keeps a copy so it can build on its
# own. Since the two now live in separate repositories, the copy can drift
# silently — this is how you check, and how you update.
#
#   Scripts/sync-proto.sh check   [path-to-synchronicity]   (default: ../synchronicity)
#   Scripts/sync-proto.sh update  [path-to-synchronicity]

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
mine="$project_dir/Sources/Hecatia/control.proto"

action=${1:-check}
daemon_repo=${2:-$project_dir/../synchronicity}
theirs="$daemon_repo/crates/synch-cli/proto/control.proto"

if [ ! -f "$theirs" ]; then
  # A missing checkout is not drift. `make test` runs `check` before the two
  # audits, so failing here would take them down as collateral on any clone
  # without the sibling repo — and they need no sibling and would still have
  # been worth running. `check` therefore skips loudly and lets the rest of
  # the recipe through; `update`, which cannot do anything useful without the
  # file, still fails.
  echo "no control.proto at $theirs" >&2
  echo "pass the path to the synchronicity checkout as the second argument" >&2
  if [ "${1:-check}" = check ]; then
    echo "SKIPPED: cannot tell whether control.proto has drifted." >&2
    exit 0
  fi
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
