# synchronicity control plane

A managed, multi-tenant control plane for [synchronicity](../README.md):
the authoritative, DNSSEC-signed source of truth for cluster membership
zones, plus a web dashboard for managing them.

Synchronicity clusters discover their members through DNSSEC-validated
TXT records at `_synchronicity.<domain>` (`v=sync1 id=<label>
nk=<z-base-32 key>`), resolved over DoH and validated fail-closed by
every node. This service serves those zones — signed with ECDSA P-256
(DNSSEC algorithm 13), over authoritative DNS on port 53 (UDP + TCP)
and RFC 8484 DoH — and gives organizations a dashboard to manage them.

## Model

- **Organizations** have **users** (owner / admin / member roles, via
  invites) and **devices**.
- Each org has **networks**; a network is one synchronicity cluster and
  owns one membership name: `_synchronicity.<network>.<org>.<base>`.
- A **device** is one `id=` label plus its keys. Key rotation follows
  synchronicity's operator-driven window: two keys publish under one
  label until the old one is retired. The §3.2 ambiguity rule (one key,
  one identity) is unrepresentable in the schema and re-checked before
  every publish.
- Sign-in: Google, GitHub, per-org custom OIDC (never auto-linked —
  org-controlled issuers can't capture existing accounts), and email
  magic links.

## Stack

- **Backend**: Gleam on OTP 27 (pinned via `.tool-versions`, asdf).
  SQLite behind `csqlite/` — a small C port program speaking a framed
  stdio protocol, one OS process per connection, so the BEAM never loads
  SQLite (no NIFs; links against the system libsqlite3). Zones are
  pre-signed at mutation time and served from an in-memory snapshot.
- **Frontend**: Vite + React + TypeScript + Tailwind (`web/`).
- **Replication**: primary + read-only DNS replicas fed by external,
  operator-owned tooling (e.g. litestream). See `ops/RUNBOOK.md`.

## Developing

```sh
asdf install            # erlang + gleam per .tool-versions
                        # also install rebar3 (builds Erlang deps like ranch):
                        #   curl -fsSL -o ~/bin/rebar3 https://s3.amazonaws.com/rebar3/rebar3 && chmod +x ~/bin/rebar3
                        # CI gets it from setup-beam's rebar3-version input
make -C csqlite         # needs libsqlite3-dev
gleam test              # backend suite
just dev                # backend :8080 + vite dev server
just e2e                # delv + the real synchronicity resolver validate
                        # a served zone end to end (needs bind9-dnsutils,
                        # rust, and the repo's crates/)
```

The e2e is the load-bearing test: `delv` must report `fully validated`
for positive, NODATA and NXDOMAIN answers over UDP and TCP, and the
actual client resolver (`crates/synch-net`) must validate and parse the
member set over DoH — rotation windows, revocations and all.
