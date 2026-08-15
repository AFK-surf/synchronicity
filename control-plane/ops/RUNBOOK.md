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
  - path: /var/lib/synch-controlplane/cp.db
    replicas:
      - type: s3
        bucket: cp-litestream
        path: cp
        sync-interval: 1s
```

Replica restore loop (cron/systemd timer, ~60s):

```sh
litestream restore -o /var/lib/synch-controlplane/cp.db.new "$REPLICA_URL" \
  && mv -f /var/lib/synch-controlplane/cp.db.new /var/lib/synch-controlplane/cp.db
```

**The database contains OAuth client secrets and per-org OIDC client
secrets.** Protect the replication bucket accordingly.

## Configuration (environment; missing required values refuse to start)

| Variable | Role | Meaning |
|---|---|---|
| `CP_ROLE` | both | `primary` or `replica` |
| `CP_BASE_DOMAIN` | both | zone apex, e.g. `sync.example.dev` |
| `CP_DB_PATH` | both | SQLite file |
| `CP_KEY_FILE` | primary | zone key file; **must be unset on replicas** |
| `CP_HTTP_LISTEN` | both | `address:port`, default `0.0.0.0:8080` |
| `CP_DNS_LISTEN` | both | `address:port`, default `0.0.0.0:53` |
| `CP_NS_HOSTS` | primary | `ns1=192.0.2.1;ns2=192.0.2.53,2001:db8::53` |
| `CP_PUBLIC_URL` | primary | external URL for links/OAuth callbacks |
| `CP_SESSION_SECRET` | primary | ≥32 chars; signs session cookies |
| `CP_SMTP_HOST/PORT/USER/PASS/FROM` | primary | magic-link mail (absent = log-only) |
| `CP_GOOGLE_CLIENT_ID/SECRET` | primary | Google sign-in (absent = disabled) |
| `CP_GITHUB_CLIENT_ID/SECRET` | primary | GitHub sign-in (absent = disabled) |

## First-time setup

1. **Key ceremony** (on the primary host):

   ```sh
   controlplane keygen sync.example.dev /var/lib/synch-controlplane/csk.key
   ```

   Prints the key tag, the **DS record** for the parent zone, and the
   trust-anchor line clients can pin with `--dnssec-anchor`. Back up the
   key file offline; `keygen` refuses to overwrite an existing file.
   (`controlplane ds <apex> <keyfile>` reprints all of it.)

2. Start the primary (systemd unit in `ops/systemd/`). First boot
   migrates the DB, writes zone metadata and publishes the (empty) zone.

3. **First user**: `controlplane seed-admin you@example.com` prints a
   one-time sign-in link.

4. Start replicas + your replication tooling on the `ns` hosts.

5. **Delegate at the parent zone**:
   - `NS` records pointing at `ns1.<base>`, `ns2.<base>`;
   - glue `A`/`AAAA` for those names (they match `CP_NS_HOSTS`);
   - the `DS` record from step 1.

6. **Verify from outside** (must print `; fully validated`):

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
