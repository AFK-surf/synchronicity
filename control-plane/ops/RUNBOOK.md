# Control-plane operations runbook

The control plane is the authoritative, DNSSEC-signed source of truth for
synchronicity membership zones: `_synchronicity.<network>.<org>.<base>`
TXT records, served over port 53 (UDP+TCP) and RFC 8484 DoH.

## Topology

- **One primary**: dashboard + API + auth, DNS/DoH, owns the zone key
  (`csk.key`) and the writable SQLite database. Republishes and re-signs
  the whole zone inside every mutating transaction; a background job
  re-signs when signatures come within 7 days of expiry (14-day validity).
- **N replicas** (typically your `ns1`, `ns2` hosts): DNS/DoH only, read
  a copy of the database, hold **no key material** — the private key never
  enters the database, so replication never carries it.
- **Replication is external and operator-owned.** The service never runs,
  configures, or supervises litestream (or whatever tool you choose). The
  contract is only:
  - the primary keeps the DB in WAL mode (it does, always);
  - something replaces each replica's DB file via *write-new + atomic
    rename*;
  - nothing else: every query checks a pooled worker out, and checkout
    reopens the database file — a swapped file is served on the very
    next query. There is no reload signal and no poll.

  Staleness bound: your refresh interval R, full stop. With R=60s
  that is well inside the 300s record TTL and the client's 10-minute
  trust grace. If refresh stops, the replica keeps serving its last good
  database file (signatures stay valid for days) and `/healthz` shows
  the stale serial. A DB from a newer build is refused at every
  checkout, never probed.

### Example litestream setup (operator-owned, not shipped config)

Primary, `litestream replicate`:

```yaml
dbs:
  - path: /var/lib/synch-controlplane/db/cp.db
    replicas:
      - type: s3
        bucket: cp-litestream
        path: cp
        sync-interval: 1s
```

Replica restore loop (cron/systemd timer, ~60s):

```sh
litestream restore -o /var/lib/synch-controlplane/db/cp.db.new "$REPLICA_URL" \
  && mv -f /var/lib/synch-controlplane/db/cp.db.new /var/lib/synch-controlplane/db/cp.db
```

**The database contains OAuth client secrets and per-org OIDC client
secrets.** Protect the replication bucket accordingly.

## Configuration (environment; missing required values refuse to start)

| Variable | Role | Meaning |
|---|---|---|
| `CP_ROLE` | both | `primary` or `replica` |
| `CP_BASE_DOMAIN` | both | zone apex, e.g. `sync.example.dev` |
| `CP_DB_PATH` | both | SQLite file; **absolute, in its own directory** (see below) |
| `CP_KEY_FILE` | primary | zone key file; **not in the database's directory**; unset on replicas |
| `CP_HTTP_LISTEN` | both | `address:port`, default `0.0.0.0:8080` |
| `CP_DNS_LISTEN` | both | `address:port`, default `0.0.0.0:53` |
| `CP_NS_HOSTS` | primary | `ns1=192.0.2.1;ns2=192.0.2.53,2001:db8::53` |
| `CP_PUBLIC_URL` | primary | external URL for links/OAuth callbacks |
| `CP_SESSION_SECRET` | primary | ≥32 chars; signs session cookies |
| `CP_SMTP_HOST/PORT/USER/PASS/FROM` | primary | magic-link mail (absent = log-only) |
| `CP_GOOGLE_CLIENT_ID/SECRET` | primary | Google sign-in (absent = disabled) |
| `CP_GITHUB_CLIENT_ID/SECRET` | primary | GitHub sign-in (absent = disabled) |
| `CP_REKOR_URL` | primary | zone-key transparency log, default `https://log2025-1.rekor.sigstore.dev` |
| `CP_REKOR_KEY` | primary | file pinning the log's verification key; defaults to the embedded log2025-1.rekor.sigstore.dev snapshot |
| `CP_REKOR_REQUIRE` | primary | `true` refuses to publish a zone whose key has no verified log record |
| `CP_DNSSEC_CHAIN_RESOLVER` | primary | DoH endpoint the log entry's DNSSEC chain is collected from, default `https://cloudflare-dns.com/dns-query` |
| `CP_DNSSEC_CHAIN_ROOT_DNSKEY` | primary | `false` omits the root DNSKEY link from that chain; default `true` |
| `CP_TUF_URL` | primary | Sigstore TUF repository relayed in the zone, default `https://tuf-repo-cdn.sigstore.dev` |

> **Why the database gets its own directory.** Each SQLite connection
> runs in a `csqlite` worker sandboxed (Landlock on Linux, `unveil`/
> `pledge` on OpenBSD) to exactly the *directory* holding `CP_DB_PATH` —
> the kernel primitives grant a directory, not a single file. So the
> zone signing key (`CP_KEY_FILE`) must live **outside** that directory,
> or a compromised worker's grant would cover it. Put the database in a
> dedicated subdirectory — `/var/lib/synch-controlplane/db/cp.db` with
> the key at `/var/lib/synch-controlplane/csk.key` — and the service
> refuses to start if the two share a directory or the path is relative.

## First-time setup

1. **Key ceremony** (on the primary host):

   ```sh
   controlplane keygen sync.example.dev /var/lib/synch-controlplane/csk.key
   ```

   Prints the key tag, the **DS record** for the parent zone, and the
   trust-anchor line clients can pin with `--dnssec-anchor`. Back up the
   key file offline; `keygen` refuses to overwrite an existing file.
   (`controlplane ds <apex> <keyfile>` reprints all of it.)

2. **Put the DS at the parent registrar and wait for it to be live.**
   `dig +dnssec <apex> DS` against a public resolver until it answers.
   This step now comes *before* logging, which reverses the earlier
   order — see step 3 for why.

3. **Log the zone key** (before any client resolves the zone —
   clients require the record by default):

   ```sh
   controlplane rekor-publish sync.example.dev \
     /var/lib/synch-controlplane/csk.key \
     [/path/to/previous-csk.key]
   ```

   Puts the key on a public transparency log, verifies the returned
   proof locally with the same rules clients apply, stores it, and
   republishes so the proof is served at `_synchronicity-rekor.<apex>`
   (docs/REKOR-ZONE-KEY.md). It is separate from `keygen` because
   `keygen` must stay runnable on an offline host and this step needs
   egress; it is idempotent, so re-running only refreshes the stored
   checkpoint against a grown tree. Nothing is stored that did not
   verify.

   **It needs the DS to be live first.** The entry carries the DNSSEC
   chain from the apex's DS up to the root, which is what lets a monitor
   decide offline whether this key was ever delegated — and there is
   nothing to collect until the parent publishes the DS. If it is not
   there yet the command says so:

   ```
   no DS RRset at sync.example.dev. — is the DS live in the parent yet?
   ```

   **Name the previous key file when you have one.** That adds the
   succession countersignature — the one thing an attacker holding a
   substituted DS cannot produce — and it is the difference between a
   monitor logging a routine rotation and a monitor paging somebody. The
   command tells you which you got:

   ```
   zone key 34918 rollover: log index 67673584 (entry added),
   DNSSEC chain carried, countersigned by key tag 12345 (monitors see tier A)
   ```

   A first key, or a recovery where the old private key is gone, has no
   predecessor and legitimately reads `NOT countersigned: monitors will
   alert (tier B)`. That is expected, and it is why somebody should be
   told before you do it.

4. **Relay Sigstore's TUF metadata** (once there is egress):

   ```sh
   controlplane tuf-refresh
   ```

   Walks `CP_TUF_URL` the way TUF consistent snapshots are meant to be
   walked — timestamp names the snapshot, the snapshot names the targets,
   the targets name `trusted_root.json` by digest — stores every file
   verbatim and republishes so the bundle is served at
   `_synchronicity-tuf.<apex>` (docs/REKOR-ZONE-KEY.md §10). Clients
   verify that chain offline against a TUF root built into them and adopt
   the log keys it names, so Sigstore's log rotations stop being a client
   upgrade. This service checks structure, versions and expiries only —
   it is a relay, not the verifier — and refuses a fetch that would walk
   clients backwards. The hourly job refetches on its own once the stored
   timestamp is within three days of expiring; run this by hand after any
   long outage, or on an egress host before couriering the database in an
   air-gapped deployment. Skipping it entirely is fine: clients keep the
   log keys their build shipped with.

4. Start the primary (systemd unit in `ops/systemd/`). First boot
   migrates the DB, writes zone metadata and publishes the (empty) zone.

5. **First user**: `controlplane seed-admin you@example.com` prints a
   one-time sign-in link.

6. Start replicas + your replication tooling on the `ns` hosts.

7. **Delegate at the parent zone**:
   - `NS` records pointing at `ns1.<base>`, `ns2.<base>`;
   - glue `A`/`AAAA` for those names (they match `CP_NS_HOSTS`);
   - the `DS` record from step 1.

8. **Verify from outside** (must print `; fully validated`):

   ```sh
   delv _synchronicity.<net>.<org>.<base> TXT +rtrace
   ```

   Then on a device: `synch domain add <net>.<org>.<base>`.

Air-gapped / direct mode needs no delegation: point the client at the
control plane itself with
`synch --doh https://<host>/dns-query --dnssec-anchor anchor.key ...`
(anchor from `https://<host>/api/zone/anchor`).

## Day-2 operations

- **Device key rotation is operator-driven end to end** (matching
  synchronicity's design): open the rotation window in the dashboard
  (both keys publish under one label), run `synch key rotate`/`activate`
  on the device, confirm propagation with `synch key ls`, then retire
  the old key. The dashboard shows a persistent banner while a window is
  open, and refuses a second concurrent rotation.
- **Revocation is not a kill switch**: a revoked key leaves DNS on the
  next publish (immediately), but peers may keep trusting it for up to
  TTL + grace ≈ 15 minutes, plus your replica refresh interval.
- **Signature freshness**: `/healthz` reports `sig_expires_at`. The
  primary re-signs automatically at 7 days before expiry. If the primary
  is down long enough for that to matter you have days, not minutes.
- **Zone key loss**: generate a new key (`keygen` to a new path), update
  `CP_KEY_FILE`, replace the DS at the parent, wait out the parent TTL.
  Until the DS switch completes, validators still expect the old key —
  this is a planned outage of new-validation, existing caches keep
  working. **Zone key rollover** (proactive) is the same dance with both
  DS records present during the window; v1 keeps this manual and rare.
  With transparency enabled the order is: `keygen`, publish both DNSKEYs,
  **add the DS at the parent and wait**, then `rekor-publish <apex>
  <newkey> <oldkey>`, then switch signing, then `rekor-retire <apex>
  <oldkey>`. Logging comes after the DS because the entry carries the
  DNSSEC chain that the DS makes buildable; the two-key window is what
  covers the gap, since the old key keeps signing until the new one is
  logged.
- **Zone key transparency** (docs/REKOR-ZONE-KEY.md): `rekor-publish`
  puts the zone key on a public log and the zone serves the proof at
  `_synchronicity-rekor.<apex>`. Rollout is phased — publish first
  (`CP_REKOR_REQUIRE` unset), turn the gate on once every key in play has
  a verified record. With the gate on, *every* publish path refuses while
  the active key has none, including the hourly re-sign; that is
  deliberate, and `rekor-publish` is how you get out of it.
- **Watch the log** (docs/REKOR-ZONE-KEY.md §5.5). A required log with no
  watcher is a formality. `synch-monitor` reads the whole log's tiles,
  finds every entry naming your apex, and classifies it:

  ```sh
  echo '{"known":{"keys":{"sync.example.dev":[]}}}' > /var/lib/synch-monitor/state.json
  synch-monitor --state /var/lib/synch-monitor/state.json
  ```

  Exit codes: `0` nothing new, `10` routine countersigned rotations only,
  `20` unauthorized claims naming your apex (recorded, no alarm — no
  client would have accepted one), `30` **a chain-valid key nobody
  countersigned: look now**, `2` the run could not finish. Run it from
  somewhere that is not the control plane's network; the independence is
  the point. Seed the state file with the keys you already know, and note
  that it only ever learns new predecessors from tier A findings —
  deliberately, so an attacker's first key cannot bootstrap their second.
- **Log-pin refresh** (docs/REKOR-ZONE-KEY.md §10): `tuf-refresh` relays
  Sigstore's TUF metadata at `_synchronicity-tuf.<apex>` so clients'
  transparency-log pins follow Sigstore's rotations. `/healthz` reports
  `tuf_root_version` and `tuf_timestamp_expires_at`; an expiry that stops
  moving means the hourly refetch is failing — check egress to
  `CP_TUF_URL`. It is never urgent: an expired or absent bundle leaves
  every client on the pins it already has, which is where they were
  before this existed.
- **Backups**: the litestream bucket *is* the database backup. The key
  file is backed up offline from the ceremony. Those two artifacts
  restore the whole service.

## Failure posture (deliberate)

- Ambiguous or malformed zone states are unrepresentable (DB constraints)
  and re-checked at build time — the service refuses to publish rather
  than emit a zone that would trip the client's §3.2 rules.
- A prolonged control-plane outage degrades clusters toward their cached
  bindings and then toward static-only trust — synchronicity fails
  closed, and so does this service: better no answer than an unsigned one.
