#!/bin/sh
# The Rust/Lean review anchors are bidirectional in name and target.
#
# Lean side: every declaration modelling a Rust linearization point carries
# `@[rust_impl "anchor"]`, and `lake exe anchors` prints `anchor Decl` for each.
# Rust side: the modelled site carries `// LEAN-MODEL: anchor (Decl)`.
# The two lists must be identical, an anchor must sit on exactly one Lean
# declaration, and a Rust anchor must name its declaration.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
rust_anchors=$(mktemp)
lean_anchors=$(mktemp)
trap 'rm -f "$rust_anchors" "$lean_anchors"' EXIT HUP INT TERM

rust_src="$root/crates/synch-store/src $root/crates/synch-engine/src \
  $root/crates/synch-mpt/src $root/crates/synch-net/src $root/crates/synch-verified/src"

# A Rust anchor that names no declaration is a stale spelling.
# shellcheck disable=SC2086
if grep -rnE 'LEAN-MODEL: [a-z0-9-]+[[:space:]]*$' $rust_src; then
  echo "LEAN-MODEL anchor without its Lean declaration; write 'LEAN-MODEL: anchor (Decl)'" >&2
  exit 1
fi

# shellcheck disable=SC2086
grep -rhoE 'LEAN-MODEL: [a-z0-9-]+ \([A-Za-z0-9_.]+\)' $rust_src \
  | sed 's/LEAN-MODEL: //; s/ (\(.*\))$/ \1/' | LC_ALL=C sort > "$rust_anchors"

lean_dump=$(cd "$root/specs/lean" && lake exe anchors) || {
  echo "lake exe anchors failed" >&2
  exit 1
}
printf '%s\n' "$lean_dump" | LC_ALL=C sort > "$lean_anchors"

if [ "$(wc -l < "$rust_anchors")" -ne "$(sort -u "$rust_anchors" | wc -l)" ]; then
  echo "duplicate LEAN-MODEL anchor in Rust" >&2
  exit 1
fi
if [ "$(cut -d' ' -f1 "$lean_anchors" | wc -l)" -ne "$(cut -d' ' -f1 "$lean_anchors" | sort -u | wc -l)" ]; then
  echo "an anchor sits on more than one Lean declaration" >&2
  exit 1
fi

if ! diff -u "$rust_anchors" "$lean_anchors"; then
  echo "Rust/Lean proof anchors differ" >&2
  exit 1
fi
