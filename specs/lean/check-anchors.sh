#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
rust_anchors=$(mktemp)
lean_anchors=$(mktemp)
trap 'rm -f "$rust_anchors" "$lean_anchors"' EXIT HUP INT TERM

rg -o --no-filename 'LEAN-MODEL: [a-z0-9-]+' \
  "$root/crates/synch-store/src" "$root/crates/synch-engine/src" \
  | sed 's/LEAN-MODEL: //' | LC_ALL=C sort > "$rust_anchors"

rg -o --no-filename 'RUST-IMPL: [a-z0-9-]+' \
  "$root/specs/lean/Synchronicity" \
  | sed 's/RUST-IMPL: //' | LC_ALL=C sort > "$lean_anchors"

if [ "$(wc -l < "$rust_anchors")" -ne "$(sort -u "$rust_anchors" | wc -l)" ]; then
  echo "duplicate LEAN-MODEL anchor in Rust" >&2
  exit 1
fi
if [ "$(wc -l < "$lean_anchors")" -ne "$(sort -u "$lean_anchors" | wc -l)" ]; then
  echo "duplicate RUST-IMPL anchor in Lean" >&2
  exit 1
fi

if ! diff -u "$rust_anchors" "$lean_anchors"; then
  echo "Rust/Lean proof anchors differ" >&2
  exit 1
fi
