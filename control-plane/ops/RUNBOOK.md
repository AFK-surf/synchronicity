# Control-plane operations runbook

The control plane is the authoritative, DNSSEC-signed source of truth for
synchronicity membership zones: `_synchronicity.<network>.<org>.<base>`
TXT records, served over port 53 (UDP+TCP) and RFC 8484 DoH.

## Topology

- **One primary**: dashboard + API + auth, DNS/DoH, owns the zone key
  (`csk.key`) and the writable SQLite database. Republishes and re-signs
  the whole zone inside every mutating transaction; a background job
  re-signs when signatures come within 7 days of expiry (14-day validity).
- **N replicas** (typically your `ns1`, `ns2` hosts): DNS/DoH, read
  a copy of the database, hold **no key material** — the private key never
  enters the database, so replication never carries it. With
  `CP_DASHBOARD=on` they also serve the dashboard, every GET of the API and
  the file browser off that same copy; see below.
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
  that is well inside the 300s record TTL and the client's 15-minute
  trust grace (`DEFAULT_TRUST_GRACE`, `crates/synch-net/src/dns.rs`). If refresh stops, the replica keeps serving its last good
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

### A replica that also serves the dashboard

`CP_DASHBOARD=on` mounts, off the same read-only copy the nameserver reads:
the SPA, every GET of the product API, and — with `CP_BROWSE=on` — the file
browser, including the `/agent/v1/attach` tunnel daemons open. Writes are not
mounted: a mutation answers **409 `read-only-replica`** naming
`CP_PRIMARY_URL`, and the dashboard renders that as a link rather than an
error.

Why you would: the reads are the load. A network's file listing, a version
history, a download of a 40 GB object — all of it is a GET, and putting it on
`ns1` and `ns2` takes it off the node that owns the zone key. The writes stay
in one place because there is only one writable database, which is also why
this is not a load-balancer trick: the split is in the router, not in front
of it.

Four things have to line up:

1. **`CP_SESSION_SECRET` is identical on every node.** A replica verifies
   cookies the primary minted; one byte of difference and every session
   fails its signature check.
2. **`CP_COOKIE_DOMAIN` covers every node's name**, if the nodes have names
   of their own. A cookie set host-only at `sync.example` is never sent to
   `ns1.sync.example`, so the session simply is not there. Set it to a
   parent — `sync.example` — and every host under that name receives the
   cookie, which is the trade you are making.
3. **`CP_PRIMARY_URL`** names the primary. It is what a refused write and the
   login screen point at, and nothing in the database says it.
4. **Sign-in happens on the primary.** Minting a session is a write. The
   replica's login screen says so and links there; once signed in, the
   session works fleet-wide (given 1 and 2).

**Attach and the file browser.** Each node's daemons attach to *that node* —
the registry of open tunnels is one process's memory, so a node no daemon
attached to can answer no browse question however current its copy is. Give
each node its own `CP_PUBLIC_URL`, and list the whole fleet on the primary:

```sh
# primary
CP_BROWSE=on
CP_PUBLIC_URL=https://sync.example
CP_ENDPOINTS=https://ns1.sync.example,https://ns2.sync.example

# ns1
CP_ROLE=replica
CP_DASHBOARD=on
CP_BROWSE=on
CP_PUBLIC_URL=https://ns1.sync.example
CP_PRIMARY_URL=https://sync.example
CP_COOKIE_DOMAIN=sync.example
CP_SESSION_SECRET=…the primary's, byte for byte…
```

The apex then publishes one `v=synccp1 url=` record per endpoint at
`_synchronicity-cp.<base>`, and every daemon opens a standing tunnel to each
(`synch cloud status` lists one line per endpoint). At most 8 endpoints:
every one costs every daemon in every network a WebSocket, and both ends
refuse a longer list — the control plane at boot, the daemon at discovery.

A daemon built before this change reads the first record it can parse and
attaches to one node of the fleet, which still works; it is one tunnel
instead of several.

**One thing a replica cannot do: write the download audit row.** Browse
downloads are audited on the node that served them, and a replica's database
is read-only, so a download served by `ns1` leaves no `browse.download` row
in the table the org reads. It is not lost: the node prints the row it could
not write to its service log —

```
browse.download not audited (this node cannot write): actor=u-… org=o-… {"network":…}
```

— so collect it there (journald, your log shipper) if you want a complete
trail. If it has to be complete *in the table*, keep `CP_BROWSE` on the
primary alone and let the replicas serve the dashboard's other reads.

## Configuration (environment; missing required values refuse to start)

| Variable | Role | Meaning |
|---|---|---|
| `CP_ROLE` | both | `primary` or `replica` |
| `CP_BASE_DOMAIN` | both | zone apex, e.g. `sync.example` |
| `CP_DB_PATH` | both | SQLite file; **absolute, in its own directory** (see below) |
| `CP_KEY_FILE` | primary | zone key file; **not in the database's directory**; unset on replicas |
| `CP_HTTP_LISTEN` | both | `address:port`, default `0.0.0.0:8080` |
| `CP_DNS_LISTEN` | both | `address:port`, default `0.0.0.0:53` |
| `CP_NS_HOSTS` | primary | `ns1=192.0.2.1;ns2=192.0.2.53,2001:db8::53` |
| `CP_PUBLIC_URL` | both | this node's own external URL — links and OAuth callbacks on the primary, the attach endpoint daemons dial and sign their proof over on any node with `CP_BROWSE=on` |
| `CP_SESSION_SECRET` | primary; replica with `CP_DASHBOARD=on` | ≥32 chars; signs session cookies. **The same value on every node**: a replica verifies cookies the primary minted, and one byte of difference is a dashboard nobody can sign in to |
| `CP_DASHBOARD` | replica | `on` mounts the dashboard and the read half of the API off the replicated copy. Off by default — a replica serves DNS alone, which is what every replica did before the switch existed. Refused on the primary, which always serves it |
| `CP_PRIMARY_URL` | replica with `CP_DASHBOARD=on` | the primary's public URL. Required, and the one fact a read-only node cannot derive: it is what a refused write and the login screen name, and without it the dashboard is a dead end |
| `CP_COOKIE_DOMAIN` | nodes with a dashboard | the `Domain` session cookies are set with. Unset is host-only, which is right for one node and wrong for a fleet: a cookie set at `sync.example` is never sent to `ns1.sync.example`. Set it to a parent of every node's name — the trade is that every host under that name receives the cookie |
| `CP_ENDPOINTS` | primary | this deployment's *other* control-plane endpoints, comma- or semicolon-separated (`https://ns1.sync.example,https://ns2.sync.example`). Each becomes its own `v=synccp1 url=` record at `_synchronicity-cp.<base>`, beside this node's `CP_PUBLIC_URL` — the apex saying where this base's control plane answers, not a browse-specific list. Cloud attach is what dials them today, one standing tunnel per endpoint per daemon. At most 8 endpoints in total |
| `CP_SMTP_HOST/PORT/USER/PASS/FROM` | primary | magic-link and invitation mail (absent = log-only); `FROM` is the header, display name and all |
| `CP_GOOGLE_CLIENT_ID/SECRET` | primary | Google sign-in (absent = disabled) |
| `CP_GITHUB_CLIENT_ID/SECRET` | primary | GitHub sign-in (absent = disabled) |
| `CP_REKOR_URL` | primary | zone-key transparency log; unset, the shard in service is read from the stored `trusted_root.json` |
| `CP_REKOR_KEY` | primary | file pinning the log's verification key — exactly one, PEM or base64 SPKI; unset, it comes from the same trusted-root entry as the endpoint |
| `CP_REKOR_REQUIRE` | primary | `true` refuses to publish a zone whose key has no verified log record |
| `CP_DNSSEC_CHAIN_RESOLVER` | primary | DoH endpoint the log entry's DNSSEC chain is collected from, default `https://cloudflare-dns.com/dns-query`. In external mode it must be a **validating** resolver: the key watcher refuses answers without the AD bit. |

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
   controlplane keygen sync.example /var/lib/synch-controlplane/csk.key
   ```

   Prints the key tag, the **DS record** for the parent zone, and the
   trust-anchor line clients can pin with `--dnssec-anchor`. The file is
   created `0600` before the private scalar is written into it. Back up the
   key file offline; `keygen` refuses to overwrite an existing file.
   (`controlplane ds <apex> <keyfile>` reprints all of it.)

2. **Put the DS at the parent registrar and wait for it to be live.**
   `dig +dnssec <apex> DS` against a public resolver until it answers.
   This step now comes *before* logging, which reverses the earlier
   order — see step 3 for why.

3. **Log the zone key** (before any client resolves the zone —
   clients require the record by default):

   ```sh
   controlplane rekor-publish /var/lib/synch-controlplane/csk.key
   ```

   The apex is `CP_BASE_DOMAIN` and is not an argument: this command puts
   an entry naming an apex into a public log, and the only apex this
   deployment may name is its own.

   Puts the key on a public transparency log, verifies the returned
   proof locally with the same rules clients apply, stores it, and
   republishes so the proof is served at `_synchronicity-rekor.<apex>`
   (docs/REKOR-ZONE-KEY.md). It is separate from `keygen` because
   `keygen` must stay runnable on an offline host and this step needs
   egress; it is idempotent, so re-running only refreshes the stored
   checkpoint against a grown tree. Nothing is stored that did not
   verify.

   **Which log it submits to is discovered, not compiled in.** The shard
   in service and its verification key both come out of the
   `trusted_root.json` this service **ships** in `priv/tuf` (see "Log
   directory" below), so this step needs no egress beyond the log itself. A
   deployment naming its own log sets `CP_REKOR_URL` and `CP_REKOR_KEY`
   together.

   **It needs the DS to be live first.** The entry carries the DNSSEC
   chain from the apex's DS up to the root, which is what lets a monitor
   decide offline whether this key was ever delegated — and there is
   nothing to collect until the parent publishes the DS. If it is not
   there yet the command says so:

   ```
   no DS RRset at sync.example. — is the DS live in the parent yet?
   ```

   **Expect every monitor watching this apex to report the key.** That is
   what publishing to a transparency log now means, and there is nothing to
   suppress it with: a monitor cannot tell your rotation from a
   substitution, because an attacker holding your registrar can build the
   same chain you just did. It reports the authorization and leaves the
   judgement to you. The command says so:

   ```
   zone key 34918 rollover: log index 67673584 (entry added),
   DNSSEC chain carried (monitors will report this key)
   ```

   So tell whoever watches the monitor **before** you run it, and write the
   key tag down. Your own record of what you published is the only thing
   that distinguishes a report you caused from one you did not.

**The log directory needs no command and no egress.** Which shard this
service submits to, and which key checks the proof that comes back, come out
of `priv/tuf/sigstore_trusted_root.json` — shipped with the image, byte-identical
to the directory the client embeds (docs/REKOR-ZONE-KEY.md §10.3). Nothing
about it touches the zone, and clients pin their own log keys from their own
walk of Sigstore's repository, so a directory this service got wrong yields a
proof clients refuse rather than a proof they wrongly accept.

When Sigstore opens the next shard, this service keeps naming the old one
until it is redeployed, and says so: `rekor-publish` fails naming the missing
shard and the external-mode watcher logs it each tick. `CP_REKOR_URL` and
`CP_REKOR_KEY` name a log outright in the meantime. Air-gapped deployments
need nothing special here — there is nothing to fetch.

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

   Then on a device: `synch domain set <net>.<org>.<base>`.

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
  next publish — immediately in serve mode, and on the next reconciler
  pass in external mode (a poke after the transaction commits, so
  seconds; the sweep at 300s is the fallback). Peers may keep trusting
  it for up to TTL + grace ≈ 20 minutes, plus your replica refresh
  interval.
- **Signature freshness**: `/healthz` reports `sig_expires_at`. The
  primary re-signs automatically at 7 days before expiry. If the primary
  is down long enough for that to matter you have days, not minutes.
- **Zone key loss**: generate a new key (`keygen` to a new path), update
  `CP_KEY_FILE`, replace the DS at the parent, wait out the parent TTL.
  Until the DS switch completes, validators still expect the old key —
  this is a planned outage of new-validation, existing caches keep
  working. **Zone key rollover** (proactive) is the same dance with both
  DS records present during the window; v1 keeps this manual and rare.

  **The rollover, step by step.** `zone_meta` carries a staging slot for
  the key coming in, so the zone can serve a two-key DNSKEY RRset while
  the outgoing key keeps signing — the ordinary DNSSEC rollover, and the
  thing that makes the sequence below possible at all:

  ```
  controlplane keygen        <apex> /path/new.key      # 1. mint
  controlplane zone-key stage <apex> /path/old.key /path/new.key
                                                       # 2. publish both
  #   3. add the new DS at the parent; wait for it to go live and for the
  #      old DS's TTL to pass
  controlplane rekor-publish /path/old.key              # 4. log both keys
  #   5. swap CP_KEY_FILE to new.key, restart
  controlplane zone-key promote <apex> /path/new.key   # 6. new key signs
  #   7. remove the old DS at the parent
  controlplane rekor-retire  /path/old.key              # 8. retire
  ```

  Step 2 is deliberately **not** gated: the signing key is unchanged and
  already on the record, so there is no new claim for the gate to hold
  back. Step 6 **is** gated, and that is the point — it refuses unless
  the incoming key is already on the public record, which is what step 4
  arranged. Getting the order wrong therefore fails at step 6 with a
  message naming step 4, rather than producing a zone clients reject.

  Staging is what makes the ordering possible. `rekor-publish` claims the
  key set **observed live on the wire**, so a key has to be serving before
  it can be logged, while with `CP_REKOR_REQUIRE=true` the gate will not
  let a key sign anything until it is logged. Staging separates *published*
  from *active* — the incoming key rides in the DNSKEY RRset, where the
  parent and the log can both see it, without signing anything.

  If you boot with the staged key file before promoting, the error says so
  and names `zone-key promote`, rather than claiming the key file is
  wrong.

  Every monitor watching the apex will report the new key — tell them
  first, and record the key tag.
- **Zone key transparency** (docs/REKOR-ZONE-KEY.md): `rekor-publish`
  puts the zone key on a public log and the zone serves the proof at
  `_synchronicity-rekor.<apex>`. Rollout is phased — publish first
  (`CP_REKOR_REQUIRE` unset), turn the gate on once every key in play has
  a verified record. With the gate on, publishing a **change** to the zone
  refuses while the active key has no record, and `rekor-publish` is how
  you get out of it. The hourly **re-sign** is deliberately not gated: it
  emits records clients already accept, so refusing it withholds nothing
  from anybody — it just lets the signatures expire after `sig_validity`
  (14 days by default) and takes the whole zone bogus on DNSSEC rather
  than on transparency. A transparency gap should not become a DNS
  outage.
- **Watch the log** (docs/REKOR-ZONE-KEY.md §5.5). A required log with no
  watcher is a formality. `synch-monitor` reads the whole log's tiles and
  reports **every newly authorized key** for the apexes you watch:

  ```sh
  echo '{"known":{"keys":{"sync.example":[]}}}' > /var/lib/synch-monitor/state.json
  # --from-index is not optional in practice: without it the first run
  # walks the log from entry 0, and the production shard has ~10^8 entries
  # in it. Take the current tree size from the checkpoint and subtract
  # however far back you want to look.
  # --allow-gap is required alongside it, and says so: --from-index skips a
  # stretch of the log no run will ever classify, which is a real loss of
  # coverage and is stated rather than defaulted.
  size=$(curl -sS https://log2025-1.rekor.sigstore.dev/api/v2/checkpoint | sed -n 2p)
  synch-monitor run --state /var/lib/synch-monitor/state.json \
                    --from-index "$((size - 200000))" --allow-gap
  ```

  `run` is the subcommand and is not optional — without it the binary exits 2
  on a usage error, having walked nothing.

  Then install the unit and timer beside it — `ops/systemd/
  synch-monitor.{service,timer}` — which run it hourly from the recorded
  index. **Run it somewhere that is not the control plane's network**;
  the independence is the point.

  Exit codes: `0` nothing new, `10` unauthorized claims naming your apex
  (recorded, no alarm — no client would have accepted one), `20` **a key
  was authorized for your apex that this monitor had not seen: check it
  against what you published**, `30` the run could not finish. They are
  ordered by severity so a rule testing `>= 10` reads correctly — which
  is why failure is `30` and not the `2` it used to be, since at `2` it
  sorted below "nothing new" and that rule silently ignored every failed
  run. A monitor that cannot finish is not a monitor with nothing to say.

  New authorizations go to **stdout**, one line each with the apex, key
  tag, the DS your registrar should be showing, the SPKI digest and the
  log index. Everything else goes to stderr. A cron job that mails stdout
  mails exactly the events that need a human.

  **The monitor cannot tell your rotation from a substitution**, and does
  not try: an attacker who has taken your registrar holds the DS, so
  their entry carries a valid chain exactly like yours. It tells you a
  key was authorized; *you* decide whether you authorized it. So keep a
  record of every key you publish — that record is the discriminator, and
  nothing in the log can replace it. Run the monitor from somewhere that
  is not the control plane's network; the independence is the point. Seed
  the state file with the keys you have already accounted for, so the
  first run reports only what you did not know. The keys it records are
  bookkeeping about what it has already told you, **not** a trust list:
  an attacker's key is recorded once reported, the same as yours.
- **Log directory** (docs/REKOR-ZONE-KEY.md §10.3): which transparency-log
  shard this service submits to ships with the image and moves on a deploy.
  Nothing to monitor and nothing to keep fresh; the signal that it has gone
  stale is `rekor-publish` refusing, naming the shard it cannot find. It does
  not affect clients at all — they follow Sigstore's repository themselves.
- **Backups**: the litestream bucket *is* the database backup. The key
  file is backed up offline from the ceremony. Those two artifacts
  restore the whole service.

## External DNS provider mode

`CP_DNS_MODE=external` publishes the zone through a managed provider
(Cloudflare or Bunny) instead of serving DNS here. The provider holds the
DNSSEC signing key; this deployment holds only the record set. See
`docs/EXTERNAL-DNS-PROVIDER.md` for the design.

What differs operationally:

- **Configuration**: `CP_DNS_MODE=external`, `CP_DNS_PROVIDER`
  (`cloudflare` | `bunny` | `log-only`), the provider credential
  (`CP_CLOUDFLARE_API_TOKEN` or `CP_BUNNY_API_KEY`), optionally
  `CP_CLOUDFLARE_ZONE_ID` (set it: otherwise the zone is discovered with a
  live API call at boot), and `CP_SIGNING_ZONE` when the apex is served
  out of a zone above it. `CP_KEY_FILE` is **refused** — there is no
  local zone key.
- **No `keygen`, no DS to publish, no `resign`.** The provider signs. The
  `zone-key promote` and `rekor-publish` commands that take a key file do
  not apply here; the zone-key watcher observes the provider's keys and
  logs them itself, every 300s.
- **Ownership marker**: the reconciler will only delete records below the
  apex when `_synchronicity-owner.<apex>` carries this deployment's
  marker. A `provider-sync: conflict:` line means it found something else
  there and touched nothing. On a *first* sync that is correct and the
  remedy is to remove the foreign record; after a successful sync the
  marker is re-asserted automatically as drift.
- **What to alert on**: `/healthz` reports `provider_in_sync`,
  `provider_last_error`, `provider_last_ok_at`, `keys_observed`,
  `keys_logged` and `oldest_unlogged_age`. `provider_in_sync: false` for
  more than a couple of sweeps is the reconciler wedged or the provider
  API refusing writes; `keys_observed: 0` is the watcher never having
  worked, which reads the same as "everything is logged" if you look only
  at `oldest_unlogged_age`.
- **`CP_DNS_PROVIDER=log-only`** prints the change set and applies
  nothing, and reports `provider_in_sync: true` while publishing nothing
  at all. It is a dry run; the `"provider": "log-only"` field beside it is
  how you tell.

## Failure posture (deliberate)

- Ambiguous or malformed zone states are unrepresentable (DB constraints)
  and re-checked at build time — the service refuses to publish rather
  than emit a zone that would trip the client's §3.2 rules.
- A prolonged control-plane outage degrades clusters toward their cached
  bindings and then toward static-only trust — synchronicity fails
  closed, and so does this service: better no answer than an unsigned one.
