#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
generated_dir="$project_dir/XcodeGenerated"

. "$script_dir/env.sh"

swift build --package-path "$project_dir" --configuration debug >/dev/null

# SwiftPM derives this directory from the package directory name, so it is
# found rather than spelled out — it moved once already when the project was
# renamed, and a wrong path here fails as a missing file rather than as a
# stale one.
mkdir -p "$generated_dir"
for generated in control.pb.swift control.grpc.swift; do
  found=$(find "$project_dir/.build/plugins/outputs" -name "$generated" -print -quit 2>/dev/null)
  if [ -z "$found" ]; then
    echo "no $generated under .build/plugins/outputs — did 'swift build' run?" >&2
    exit 1
  fi
  cp "$found" "$generated_dir/$generated"
done
