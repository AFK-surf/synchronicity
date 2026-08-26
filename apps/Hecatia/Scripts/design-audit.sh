#!/bin/sh
# Does the view layer still obey the design constraints in docs/DESIGN.md?
#
# Only the mechanical half is checkable, and only the mechanical half is
# checked. The rules below are the ones a grep can decide; the judgement ones —
# is this emphasis earned, does this sentence say what happens — belong to
# review and to the rendered snapshots, not here.

set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

views=$(find Sources/Hecatia/Views Sources/Hecatia/App -name '*.swift')
theme=Sources/Hecatia/Views/Shared/Theme.swift
others=$(echo "$views" | grep -v "^$theme$")

failures=0

fail() {
  printf '%s\n' "$1" >&2
  failures=$((failures + 1))
}

# Reports every offending line of a pattern, or nothing.
forbid() {
  pattern=$1
  rule=$2
  scope=$3
  hits=$(grep -nE "$pattern" $scope 2>/dev/null || true)
  if [ -n "$hits" ]; then
    fail "$rule"
    printf '%s\n' "$hits" | sed 's/^/    /' >&2
  fi
}

# --- Depth -----------------------------------------------------------------
# "Don't add shadows to cards, buttons, or text" and "no decorative gradients":
# elevation is a surface change here, never a shadow.
forbid '\.shadow\(' \
  'shadow: elevation is a surface change, not a shadow (docs/DESIGN.md)' "$views"
forbid '[Gg]radient' \
  'gradient: the reference system defines none, and neither does this app' "$views"

# --- Type ------------------------------------------------------------------
# The system font, at the system text styles, so the app follows the user's
# Larger Text setting. A pinned point size does not.
forbid '\.system\(size:' \
  'pinned font size: use a system text style (.body/.callout/.caption)' "$views"
forbid 'design: \.rounded|design: \.serif|custom\(' \
  'font design: this platform ships SF, and the default design is it' "$views"
forbid '\.weight\(\.medium\)|\.medium\)\.' \
  'weight 500: the ladder is 300/400/600/700 — use .semibold' "$views"

# --- Shape -----------------------------------------------------------------
# One radius grammar, defined once. A literal here is a step between the steps.
forbid 'cornerRadius: [0-9]' \
  'raw corner radius: use Theme.Radius (5 / 8 / 11 / 18)' "$others"

# --- Spacing ---------------------------------------------------------------
# The 8pt ladder, defined once. `spacing: 0` is not a measurement — it is
# "these touch" — so it is allowed to be a literal.
forbid 'spacing: [1-9][0-9]*' \
  'raw spacing: use Theme.Space' "$others"
forbid '\.padding\((\.[a-zA-Z]+, )?[0-9]+\)' \
  'raw padding: use Theme.Space' "$others"

# --- Colour ----------------------------------------------------------------
# Semantic colours only, so both appearances resolve. A literal hex or a bare
# Color.white is the light-mode-only bug the reference warns about by omission.
forbid 'Color\(red:|Color\(white:|Color\.white|Color\.black|NSColor\.white|NSColor\.black|#[0-9a-fA-F]{6}' \
  'literal colour: use a semantic colour so dark mode resolves' "$views"

# --- Names -----------------------------------------------------------------
# `labelsHidden()` hides a label from the screen *and* from VoiceOver, so the
# control needs a spoken name in the same modifier chain. Checked by proximity
# rather than by parsing: a label that has drifted onto a different view a
# screenful away is exactly the mistake this catches.
for hit in $(grep -rn 'labelsHidden()' $views | cut -d: -f1,2); do
  file=${hit%%:*}
  line=${hit##*:}
  from=$((line > 3 ? line - 3 : 1))
  if ! sed -n "$from,$((line + 6))p" "$file" | grep -q 'accessibilityLabel'; then
    fail "labelsHidden with no accessibilityLabel beside it: $file:$line"
  fi
done

if [ "$failures" -ne 0 ]; then
  printf '\n%s design rule(s) violated. See docs/DESIGN.md.\n' "$failures" >&2
  exit 1
fi

files=$(printf '%s\n' "$views" | wc -l | tr -d ' ')
echo "design: $files view files obey the constraints in docs/DESIGN.md."
