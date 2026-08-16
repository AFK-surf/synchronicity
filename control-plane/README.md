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
- The zone key can be put on a public transparency log
  (`controlplane rekor-publish`), with the proof served inside the zone at
  `_synchronicity-rekor.<apex>` so clients verify it offline — a
  substituted DS then has to be a *public* substitution or fail
  validation. v1 uses synchronicity's own log-entry convention (the client
  pins and verifies real Sigstore *checkpoints* and *keys*, but matching
  Rekor v2's on-log entry serialization for end-to-end interop against the
  public Sigstore log is future work, and the submission client is a stub);
  a self-hosted, convention-compatible log works today. See
  [docs/REKOR-ZONE-KEY.md](../docs/REKOR-ZONE-KEY.md) §2, §8.
- The zone also **relays Sigstore's TUF metadata** verbatim at
  `_synchronicity-tuf.<apex>` (`controlplane tuf-refresh`, and the hourly
  job when the stored timestamp nears expiry), so clients' log-key pins
  follow Sigstore's rotations without an upgrade. This service is a relay,
  not the verifier: it checks structure, versions and expiries, and the
  cryptographic gate is the client's, against a TUF root built into it.
  Relaying nothing costs nothing — clients keep the pins they have.
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
  SQLite (no NIFs; links against the system libsqlite3). Each worker
  sandboxes itself before reading its first frame: Landlock + a seccomp
  allowlist + rlimits on Linux, pledge + unveil on OpenBSD, confining
  it to stdio and the database's own directory. Zones are pre-signed at
  mutation time and served straight from SQLite through a pool of
  reset-on-checkout workers (one read transaction per answer).
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

## Configuration

The service reads only `CP_*` environment variables. Missing required
values refuse to start — there are no defaults for anything that
changes what the service *is*. Unset optional providers (SMTP, Google,
GitHub) disable that path.

IPv6 listen addresses are written in brackets: `[::1]:53`.
`CP_HTTP_PORT` and `CP_DNS_PORT` are gone; the port lives in the
listen address.

| Variable | Role | Meaning |
|---|---|---|
| `CP_ROLE` | both | Required. `primary` or `replica`. |
| `CP_BASE_DOMAIN` | both | Required. Zone apex, no trailing dot (`sync.example.dev`). |
| `CP_DB_PATH` | both | Required. SQLite file, absolute path, in its own directory (the sandbox grants that directory — keep the key out of it). |
| `CP_KEY_FILE` | primary | Required on the primary (zone CSK). Must live outside the database's directory. **Must be unset on replicas.** |
| `CP_HTTP_LISTEN` | both | HTTP / DoH bind as `address:port`. Default `0.0.0.0:8080`. |
| `CP_DNS_LISTEN` | both | Authoritative DNS (UDP + TCP) bind as `address:port`. Default `0.0.0.0:53`. |
| `CP_NS_HOSTS` | primary | Semicolon-separated `host=ipv4[,ipv6]` NS glue, e.g. `ns1=192.0.2.1;ns2=192.0.2.53,2001:db8::53`. Hostnames without dots are relative to the apex. |
| `CP_PUBLIC_URL` | primary | External base URL for links and OAuth callbacks. Default `http://127.0.0.1:<http-port>`. |
| `CP_SESSION_SECRET` | primary | Required on the primary, ≥32 characters. Signs session cookies. |
| `CP_SMTP_HOST` | primary | SMTP hostname. Absent means log-only magic-link mail. |
| `CP_SMTP_PORT` | primary | SMTP port. Default `587`. Used only when `CP_SMTP_HOST` is set. |
| `CP_SMTP_USER` | primary | SMTP username. Default empty. |
| `CP_SMTP_PASS` | primary | SMTP password. Default empty. |
| `CP_SMTP_FROM` | primary | Required when `CP_SMTP_HOST` is set. Envelope From. |
| `CP_GOOGLE_CLIENT_ID` | primary | Google OAuth client id. Both id and secret must be set to enable Google sign-in. |
| `CP_GOOGLE_CLIENT_SECRET` | primary | Google OAuth client secret. |
| `CP_GITHUB_CLIENT_ID` | primary | GitHub OAuth client id. Both id and secret must be set to enable GitHub sign-in. |
| `CP_GITHUB_CLIENT_SECRET` | primary | GitHub OAuth client secret. |
| `CP_REKOR_URL` | primary | Zone-key transparency log write endpoint. Default `https://rekor.sigstore.dev`. |
| `CP_REKOR_KEY` | primary | File pinning the log's verification key; defaults to the embedded rekor.sigstore.dev snapshot. Set it for a self-hosted log. |
| `CP_REKOR_REQUIRE` | primary | `true` refuses to publish a zone whose active key has no verified log record. Default off — the rollout publishes before it enforces. |
| `CP_TUF_URL` | primary | Sigstore TUF repository this zone relays, so clients' log pins follow it. Default `https://tuf-repo-cdn.sigstore.dev`. Fetched by `controlplane tuf-refresh` and by the hourly job within three days of the stored timestamp's expiry. |

Day-2 operations (replicas, key ceremony, backups) live in
`ops/RUNBOOK.md`.
