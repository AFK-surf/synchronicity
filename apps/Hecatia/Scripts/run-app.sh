#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
configuration=${1:-debug}

app_dir=$("$script_dir/build-app.sh" "$configuration")
open "$app_dir"
