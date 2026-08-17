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
- The zone key can be put on the public Sigstore Rekor v2 transparency log
  (`controlplane rekor-publish`), with the proof served inside the zone at
  `_synchronicity-rekor.<apex>` so clients verify it offline — a
  substituted DS then has to be a *public* substitution or fail
  validation. The entry's verifier is a **self-signed certificate naming
  the apex in a `dNSName` SAN**: Rekor validates certificates not at all
  and copies the DER verbatim into the Merkle leaf, so the zone name lands
  where anyone reading the log can index it. Inside it rides one custom
  extension — the DNSSEC chain from the apex's DS up to the root — which is
  what lets a monitor confirm offline that the key really is authorized for
  the zone the entry names. `rekor-publish`
  collects the chain over DoH, mints the certificate, POSTs a
  `hashedrekord` v0.0.2 `CreateEntryRequest` to `CP_REKOR_URL`, then
  verifies the returned entry locally (canonicalized body, inclusion,
  checkpoint, possession, the certificate's key and name bindings) before
  storing it. **Run it after the DS is live in the parent** — there is no
  chain to collect before then. A self-hosted, Rekor-v2-compatible log
  works via `CP_REKOR_KEY`.
  See [docs/REKOR-ZONE-KEY.md](../docs/REKOR-ZONE-KEY.md) §2, §3, §5.
- It **follows Sigstore's TUF metadata** (`controlplane tuf-refresh`, and the
  hourly job when the stored timestamp nears expiry) to learn which
  transparency log shard is in service, so a Sigstore rotation costs a
  refresh rather than a release. It **verifies that metadata itself** before
  storing it — the same workflow the client runs, against the same anchor
  (`priv/tuf/sigstore_tuf_root.json`) — because that decision is one no
  client is in a position to re-check. Nothing in the zone depends on it:
  clients read Sigstore's repository themselves for their own pins
  (docs/REKOR-ZONE-KEY.md §10).
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

## Container image

`ghcr.io/afk-surf/synchronicity/control-plane`, built from
[`Dockerfile`](Dockerfile) by
[`.github/workflows/control-plane-image.yml`](../.github/workflows/control-plane-image.yml)
for `linux/amd64` and `linux/arm64`. `latest` follows `main`; tagged
releases get `X.Y.Z` and `X.Y`; every build is also tagged
`sha-<commit>` and carries signed build provenance
(`gh attestation verify oci://…` / `cosign verify-attestation`).

The image contains what the systemd deployment does — the Erlang
shipment, `priv/csqlite`, and the built SPA in `priv/web` — and runs the
primary and the replica alike: `CP_ROLE` picks, and every other setting
is the same `CP_*` environment described below. It runs as uid/gid
10001, and the entrypoint takes the service's subcommands, so `keygen`,
`ds`, `rekor-publish`, `tuf-refresh`, `seed-admin` and `migrate-check`
work the same way `serve` does.

```sh
# The zone key, generated once and kept outside the database's directory
# (the csqlite sandbox grants that directory — see Configuration).
docker run --rm -v cp-keys:/etc/synch-controlplane \
  ghcr.io/afk-surf/synchronicity/control-plane \
  keygen sync.example /etc/synch-controlplane/csk.key

docker run -d --name cp \
  -e CP_ROLE=primary \
  -e CP_BASE_DOMAIN=sync.example \
  -e CP_KEY_FILE=/etc/synch-controlplane/csk.key \
  -e CP_SESSION_SECRET="$(openssl rand -hex 32)" \
  -e CP_NS_HOSTS='ns1=192.0.2.1;ns2=192.0.2.53' \
  -e CP_PUBLIC_URL=https://sync.example \
  -v cp-keys:/etc/synch-controlplane \
  -v cp-data:/var/lib/synch-controlplane \
  -p 8080:8080 -p 53:53/udp -p 53:53/tcp \
  ghcr.io/afk-surf/synchronicity/control-plane
```

- **Volumes.** `/var/lib/synch-controlplane` holds the database at
  `/var/lib/synch-controlplane/db/cp.db` — the image's only default,
  `CP_DB_PATH`, and a path rather than a policy. The zone key belongs on
  a *separate* mount (`/etc/synch-controlplane` above): a csqlite worker
  sandboxes itself to the database's own directory, so anything else
  living there is inside the sandbox. Replicas mount the database
  read-write (SQLite needs it) and must leave `CP_KEY_FILE` unset —
  they hold no key material. Replication stays external and
  operator-owned; the atomic-rename contract in `ops/RUNBOOK.md` is
  unchanged by containers, and litestream sees the same file.
- **Ports.** 8080/tcp (dashboard, API, DoH) and 53 on UDP and TCP.
  Binding 53 as a non-root user works under Docker, which sets
  `net.ipv4.ip_unprivileged_port_start=0` in the container's network
  namespace. On a runtime that does not (Kubernetes), either set that
  sysctl or move `CP_DNS_LISTEN` to a high port and map 53 to it.
- **The sandbox needs the host's cooperation.** Each csqlite worker
  still applies its seccomp allowlist and rlimits, but Landlock needs a
  kernel that has it enabled and a container seccomp profile that
  permits the `landlock_*` syscalls (Docker's default profile does).
  Where it is missing the worker warns on stderr —
  `csqlite: landlock unsupported here; filesystem unconfined` — and
  keeps serving; treat that line as a deployment defect, not noise.
- **Health.** `HEALTHCHECK` polls `/healthz`, which reports the served
  SOA serial and signature expiry — on a replica that is how a stalled
  restore loop shows up. It probes port 8080; if `CP_HTTP_LISTEN` moves,
  set `CP_HEALTHCHECK_PORT` to match.

Nothing is published until that exact image has booted:
[`ops/image-smoke.sh`](ops/image-smoke.sh) runs the built image the way
this section tells you to run it — `keygen` and `seed` into fresh named
volumes, then `serve` — and checks what only running it can check. The
shipped SPA is served with its bundle, `/healthz` reports a loaded zone,
the authoritative DNS answers over UDP and TCP with signatures, the
csqlite workers come up sandboxed under the default runtime profile, the
service is uid 10001, and the image's own `HEALTHCHECK` goes healthy.
The publish job depends on it, so a green image is one that ran.

To build it locally, from the repository root:

```sh
docker build -t controlplane control-plane
```

Or from `control-plane/`, build and smoke-test it in one step (needs
`docker`, `curl` and `dig`):

```sh
just image-smoke
```

## Configuration

The service reads only `CP_*` environment variables. Missing required
values refuse to start — there are no defaults for anything that
changes what the service *is*. Unset optional providers (SMTP, Google,
GitHub) disable that path.

IPv6 listen addresses are written in brackets: `[::1]:53`.
`CP_HTTP_PORT` and `CP_DNS_PORT` are gone; the port lives in the
listen address.

Two DNS modes. `CP_DNS_MODE=serve` (the default) makes this service the
authoritative nameserver: it signs the zone with its own CSK and answers
on `CP_DNS_LISTEN`. `CP_DNS_MODE=external` instead publishes the
membership records into a zone a managed provider hosts and signs
(Cloudflare or Bunny), running no DNS listeners and holding no zone key
— the provider's fleet is the redundancy, so the mode is primary-only
and `CP_KEY_FILE`, `CP_DNS_LISTEN` and `CP_NS_HOSTS` must be unset.
Provider configuration present while the mode is `serve` refuses to
start: a credential that quietly does nothing is a lie. See
[docs/EXTERNAL-DNS-PROVIDER.md](../docs/EXTERNAL-DNS-PROVIDER.md).

| Variable | Role | Meaning |
|---|---|---|
| `CP_ROLE` | both | Required. `primary` or `replica`. |
| `CP_BASE_DOMAIN` | both | Required. Zone apex, no trailing dot (`sync.example`). |
| `CP_DB_PATH` | both | Required. SQLite file, absolute path, in its own directory (the sandbox grants that directory — keep the key out of it). |
| `CP_KEY_FILE` | primary | Required on the primary in serve mode (zone CSK). Must live outside the database's directory. **Must be unset on replicas** and with `CP_DNS_MODE=external` — there is no zone CSK to hold. |
| `CP_HTTP_LISTEN` | both | HTTP / DoH bind as `address:port`. Default `0.0.0.0:8080`. |
| `CP_DNS_LISTEN` | both | Authoritative DNS (UDP + TCP) bind as `address:port`. Default `0.0.0.0:53`. Must be unset with `CP_DNS_MODE=external` — the provider answers. |
| `CP_NS_HOSTS` | primary | Semicolon-separated `host=ipv4[,ipv6]` NS glue, e.g. `ns1=192.0.2.1;ns2=192.0.2.53,2001:db8::53`. Hostnames without dots are relative to the apex. Must be unset with `CP_DNS_MODE=external`. |
| `CP_DNS_MODE` | both | `serve` (default) or `external`; `external` is primary-only. See "Two DNS modes" above. |
| `CP_DNS_PROVIDER` | primary | Required with `CP_DNS_MODE=external`: `cloudflare`, `bunny` or `log-only` (no credentials — prints the change set instead of applying it). |
| `CP_SIGNING_ZONE` | primary | External mode only. The zone the provider actually hosts, when it is not the apex — e.g. a control plane at `sync.example.com` living inside the `example.com` zone, with no delegation of its own. Must contain the apex; default is the apex. |
| `CP_CLOUDFLARE_API_TOKEN` | primary | Required when the provider is `cloudflare`. Zone-scoped API token. |
| `CP_CLOUDFLARE_ZONE_ID` | primary | Cloudflare zone id. Default empty: discovered by zone name at boot. |
| `CP_CLOUDFLARE_API_URL` | primary | Cloudflare API base URL override; default empty means the real endpoint. A test/e2e hook, like `CP_REKOR_URL`. |
| `CP_BUNNY_API_KEY` | primary | Required when the provider is `bunny`. |
| `CP_BUNNY_ZONE_ID` | primary | Bunny DNS zone id. Default empty: discovered by zone name at boot. |
| `CP_BUNNY_API_URL` | primary | Bunny API base URL override; default empty means the real endpoint. |
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
| `CP_REKOR_URL` | primary | Zone-key transparency log write endpoint (Rekor v2, `POST /api/v2/log/entries`). Unset — the normal case — the shard in service is read from the stored `trusted_root.json`, so a Sigstore rotation costs a `tuf-refresh` and not a release. |
| `CP_REKOR_KEY` | primary | File pinning the log's verification key. Unset, the key comes from the same trusted-root entry as the endpoint. Set it for a self-hosted log, together with `CP_REKOR_URL`. |
| `CP_REKOR_REQUIRE` | primary | `true` refuses to publish a zone whose active key has no verified log record. Default off — the rollout publishes before it enforces. |
| `CP_DNSSEC_CHAIN_RESOLVER` | primary | DoH endpoint the DNSSEC chain in a log entry is collected from. Default `https://cloudflare-dns.com/dns-query`. Not a trust decision — every reader verifies the signatures itself — so point it at your own validating resolver if you would rather not tell a third party when you rotate keys. |
| `CP_TUF_URL` | primary | Sigstore TUF repository this service follows to find the transparency-log shard in service. Default `https://tuf-repo-cdn.sigstore.dev`. Fetched by `controlplane tuf-refresh` and by the hourly job within three days of the stored timestamp's expiry. |
| `CP_TUF_ROOT` | primary | The `root.json` TUF verification anchors on. Defaults to `priv/tuf/sigstore_tuf_root.json`, byte-identical to the root the client embeds. Set it — together with `CP_TUF_URL` — for a deployment running its own TUF repository; a repository whose root this service does not hold is one none of whose files it can check. |

Day-2 operations (replicas, key ceremony, backups) live in
`ops/RUNBOOK.md`.
