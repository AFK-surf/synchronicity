#!/bin/sh
# Does every daemon operation the app declares actually have a call site?
#
# `CoverageTests` proves the registry accounts for every operation, but a
# registry row is a claim, not a wire. An operation can be listed, given a
# gate and a title, and still be reachable from nothing — which is what
# `rpc.listParts` looked like until its caller was found. This checks the other
# half: every command builder and every non-private client method is used by
# something outside the file that declares it.
#
# And it checks the count against `control.proto` rather than against a number
# someone wrote down. That is the check that was missing: the registry said 55
# and the test that guarded it counted the registry, so `space set`, `space
# sync` and `fill` shipped in the daemon and stayed green here for three
# releases. `make check-proto` keeps that proto identical to the daemon's, so
# counting it is counting the daemon.

set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

# ---- the registry accounts for every operation the proto declares ----------

proto=Sources/Hecatia/control.proto

# The `oneof kind` block of `message Command`, one `Type name = N;` per line.
#
# Anchored on `message Command`, not on `oneof kind`, because `oneof kind` is
# no longer unique: v3 added `ConnectRequest` and `ConnectResponse`, each with
# a `oneof kind` of its own, and an awk range restarts on every match. Measured
# against the v3 proto the old expression returns 60 rather than 54 — it counts
# the six frame variants of the socket bridge as six more subcommands, and
# would have demanded fifteen registry rows for the nine operations the daemon
# actually grew.
oneof_count=$(awk '/^message Command \{/,/^\}/' "$proto" \
  | grep -cE '^    [A-Za-z][A-Za-z0-9]* [a-z_]+ = [0-9]+;')
# Every `rpc` in `service Control`, minus `Run` itself — `Run` is the carrier
# for the oneof above, not one more typed operation.
rpc_count=$(awk '/^service Control \{/,/^\}/' "$proto" | grep -cE '^  rpc ')
typed_count=$((rpc_count - 1))
daemon_total=$((typed_count + oneof_count))

registry_typed=$(awk '/^  static let typed: \[Operation\] = \[/,/^  \]/' \
  Sources/Hecatia/Store/Operations.swift | grep -c '^    \.init(')
registry_run=$(awk '/^  static let run: \[Operation\] = \[/,/^  \]/' \
  Sources/Hecatia/Store/Operations.swift | grep -c '^    \.init(')
registry_total=$((registry_typed + registry_run))

if [ "$registry_typed" -ne "$typed_count" ] || [ "$registry_run" -ne "$oneof_count" ]; then
  echo "coverage: the registry does not match $proto." >&2
  echo "  proto:    $typed_count typed rpcs + $oneof_count Run subcommands = $daemon_total" >&2
  echo "  registry: $registry_typed typed + $registry_run run = $registry_total" >&2
  echo "Run 'make check-proto' first; if that passes, the daemon grew an" >&2
  echo "operation and Operations.swift needs a row for it." >&2
  exit 1
fi

sources=$(find Sources Tests -name '*.swift' \
  ! -name 'Cmd.swift' ! -name 'ControlClient.swift' \
  ! -name 'control.pb.swift' ! -name 'control.grpc.swift')

missing=0
checked_builders=0
checked_methods=0

report() {
  echo "unreachable: $1 is declared in $2 and called from nowhere else" >&2
  missing=$((missing + 1))
}

# Every `Cmd.<name>` builder — the subcommands `Run` carries.
for name in $(grep -oE '^  static (var|func) [a-zA-Z]+' Sources/Hecatia/Daemon/Cmd.swift \
              | awk '{print $3}' | sort -u); do
  # `make` and `reference` build a command; they are not one.
  case "$name" in make|reference) continue ;; esac
  checked_builders=$((checked_builders + 1))
  grep -q "Cmd\.$name\b" $sources || report "Cmd.$name" "Cmd.swift"
done

# Every non-private method of the client — the typed rpcs.
for name in $(grep -oE '^  func [a-zA-Z]+' Sources/Hecatia/Daemon/ControlClient.swift \
              | awk '{print $2}' | sort -u); do
  checked_methods=$((checked_methods + 1))
  grep -q "\.$name(" $sources || report "ControlClient.$name" "ControlClient.swift"
done

# Every `Topic` has an operation that can fill it.
#
# `Operation.provides` records which slice a read supplies, and until this it
# was written for two dozen operations and read by nothing. A topic no
# operation provides is a slice of the app that can only ever be empty, which
# is the kind of thing that survives a refactor unnoticed.
checked_topics=0
for topic in $(grep -oE '^  case [a-z][a-zA-Z0-9]*' Sources/Hecatia/Store/Topic.swift \
               | awk '{print $2}' | sort -u); do
  checked_topics=$((checked_topics + 1))
  grep -q "provides: \[.*\.$topic\b" Sources/Hecatia/Store/Operations.swift || {
    echo "unfilled: no operation provides Topic.$topic" >&2
    missing=$((missing + 1))
  }
done

if [ "$missing" -ne 0 ]; then
  echo "$missing declared operation(s) have no call site." >&2
  exit 1
fi

echo "$checked_builders command builders, $checked_methods client methods and $checked_topics topics: all reachable."
