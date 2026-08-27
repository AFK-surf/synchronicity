#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH= cd -- "$project_dir/../.." && pwd)
sync="$script_dir/sync-proto.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hecatia-proto-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# The default is anchored to the script, not the caller's working directory.
(cd "${TMPDIR:-/tmp}" && "$sync" check) \
  || fail "the default monorepo proto check failed"

# This repository owns the canonical proto. Losing it must make the gate red,
# not turn the gate off.
if "$sync" check "$tmp/missing-repository" >/dev/null 2>&1; then
  fail "a missing canonical proto was accepted"
fi

# Exercise the real comparison rather than only the happy path.
fixture="$tmp/drifted-repository"
mkdir -p "$fixture/crates/synch-cli/proto"
cp "$repo_root/crates/synch-cli/proto/control.proto" \
  "$fixture/crates/synch-cli/proto/control.proto"
printf '\n// deliberate test drift\n' \
  >> "$fixture/crates/synch-cli/proto/control.proto"
if "$sync" check "$fixture" >/dev/null 2>&1; then
  fail "a drifted proto was accepted"
fi

echo "proto synchronization checks passed"
