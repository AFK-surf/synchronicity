//// Forward-only ordered migrations, mirroring the host repo's
//// crates/synch-store/src/schema.rs ethos: `migrations()[v]` takes a
//// database at version v to v+1, each in one transaction that also stamps
//// `PRAGMA user_version`. No `IF NOT EXISTS`, no probing — a database
//// stamped newer than this build knows is refused, not guessed at.

import gleam/int
import gleam/list
import gleam/result
import store/sqlite.{type Connection}

pub type MigrateError {
  /// The database was written by a newer build. Refuse; never probe.
  DbNewerThanBuild(db_version: Int, build_version: Int)
  Failed(target_version: Int, error: sqlite.Error)
}

/// The schema version this build writes.
pub fn build_version() -> Int {
  list.length(migrations())
}

pub fn current_version(conn: Connection) -> Result(Int, sqlite.Error) {
  case sqlite.query(conn, "PRAGMA user_version", []) {
    Ok([[sqlite.Int(v)]]) -> Ok(v)
    Ok(_) -> Error(sqlite.Protocol)
    Error(e) -> Error(e)
  }
}

/// Brings the database to this build's version. Returns the version
/// migrated to (unchanged if already current).
pub fn migrate(conn: Connection) -> Result(Int, MigrateError) {
  let target = build_version()
  use from <- result.try(
    current_version(conn) |> result.map_error(Failed(0, _)),
  )
  case from > target {
    True -> Error(DbNewerThanBuild(from, target))
    False ->
      migrations()
      |> list.drop(from)
      |> list.index_fold(Ok(from), fn(acc, sql, offset) {
        use _ <- result.try(acc)
        let to = from + offset + 1
        apply(conn, sql, to)
      })
  }
}

fn apply(conn: Connection, sql: String, to: Int) -> Result(Int, MigrateError) {
  sqlite.transaction(conn, Failed(to, _), fn() {
    use _ <- result.try(
      sqlite.script(conn, sql) |> result.map_error(Failed(to, _)),
    )
    use _ <- result.try(
      sqlite.script(conn, "PRAGMA user_version = " <> int.to_string(to))
      |> result.map_error(Failed(to, _)),
    )
    Ok(to)
  })
}

fn migrations() -> List(String) {
  [v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12]
}

/// V12: the cloud data plane (docs/CLOUD-DATAPLANE.md §3).
///
/// Four additions, and each one exists because the hosted-replica service is
/// a *caller* of this control plane rather than a part of it.
///
/// **`networks.cloud_hosted`** copies V9's shape and its rationale verbatim:
/// off for every network that already exists and for every one created after,
/// because hosting is the org's call alone. Like `browse_enabled` it is
/// deliberately **not** a zone fact — the zone carries the *consequence* (the
/// hosted device's TXT record), while the flag itself is enforced at the
/// data-plane API, where a change takes effect within one poll interval
/// instead of a TTL later, and where it never reaches public DNS.
///
/// **`cloud_collect_queue`** is the retention clock over an offboarded
/// tenant's object storage: one row per network whose hosting was switched
/// off, holding the moment it went. It is keyed by *slug and name* rather
/// than by `network_id`, and carries **no foreign key**, for the same reason
/// the audit trail carries none — it has to outlive the thing it describes.
/// The bytes in the bucket are named `tenants/<org>/<network>/`, and they do
/// not stop existing because the row that pointed at them was deleted; a
/// clock kept on the network would be destroyed by the ordinary delete
/// button, and the fleet would then hold that customer's data for ever with
/// nothing left to say it should not. Enabling hosting removes the row (a
/// re-provision inside the hold is cheap and deliberate), collecting removes
/// it, and a second disable does not replace it — `ON CONFLICT DO NOTHING`,
/// so a reconciler that re-sends `{enabled: false}` cannot push the deletion
/// another 30 days out.
///
/// **`dataplane_keys`** is a fourth credential kind, and pointedly *not* a row
/// in `api_keys`. An `api_keys` row names one org (`org_id NOT NULL`) and the
/// role CHECK stops at `admin`; the data plane's whole job is to enumerate
/// every org's hosted networks, so bending that table would break the one-org
/// invariant `api/common.check_org` and every handler downstream lean on.
/// Everything about *being* a credential is copied from V10 — the SHA-256 of
/// the token and never the token, the display `prefix` that lets a list name a
/// leaked token without holding enough to be one, the optional expiry — and
/// everything about *scope* is absent, because the scope is "the `/dp/v1`
/// surface" and that is a fact about routing, not about a row. There is no
/// `created_by`: these are minted from the operator CLI
/// (`controlplane dataplane-key mint`), where there is no signed-in person to
/// name, and no HTTP route mints or lists them — the credential that can see
/// every org is never reachable *through* the API it authorizes.
///
/// **`network_hosting_status`** is one row per network, last write wins: the
/// metering heartbeat a hosted tenant sends every few minutes. The browse
/// tunnel's replication answer is deliberately unstored (a held-object count
/// is stale the moment a fetch lands), but billing needs a number that
/// survives the tenant being *down* — a stale heartbeat is itself the alert —
/// so this one is kept. `slot` is the hosting slot the row is about, which is
/// the suffix of the `cloud-<n>` device label and never the shard: slots are
/// durable identities, shards are interchangeable pods, and `shard` is
/// operational metadata that changes under a tenant without anything else
/// moving.
///
/// **The system user.** `devices.created_by` is `NOT NULL REFERENCES
/// users(id)` and a data-plane key is not a person, so the hosted device rows
/// need a user to point at. Seeding one here means no human's id is
/// impersonated and the audit trail names the service.
///
/// Its `email` is `system-dataplane`, which is **not an email address**: it
/// carries no `@`. That is the whole of why the row can never log in, and it
/// is enforced by every sign-in path rather than by a flag somebody could
/// forget to check. `auth/magic.request` refuses an address without an `@`
/// before it mints anything, so no magic link can ever be addressed here.
/// Google and GitHub assert only addresses they have verified, and a verified
/// address contains an `@`, so `auth/identity`'s trusted auto-link can never
/// match this row. A custom OIDC issuer *could* mint any email claim it likes,
/// including this one — and is refused anyway, because OIDC never auto-links:
/// it finds the existing row, sees `email_trusted = False`, and answers
/// `NeedsExplicitLink`, which needs a live session on this account that
/// nothing can ever create. A sentinel column would have been one more thing
/// for a future sign-in path to consult; an unaddressable address is refused
/// by the paths that already exist.
///
/// `created_at` is 0 rather than a clock reading: the row is schema, not
/// history, and a migration that produces byte-identical databases on every
/// replay is worth more than a timestamp nobody will read.
const v12 = "
ALTER TABLE networks ADD COLUMN cloud_hosted INTEGER NOT NULL DEFAULT 0;
CREATE INDEX networks_cloud_hosted ON networks (cloud_hosted)
  WHERE cloud_hosted = 1;

CREATE TABLE cloud_collect_queue (
  org_slug     TEXT NOT NULL,
  network_name TEXT NOT NULL,
  disabled_at  INTEGER NOT NULL,
  PRIMARY KEY (org_slug, network_name)
);
CREATE INDEX cloud_collect_queue_due ON cloud_collect_queue (disabled_at);

CREATE TABLE dataplane_keys (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  prefix       TEXT NOT NULL,
  token_hash   BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER,
  last_used_at INTEGER
);

CREATE TABLE network_hosting_status (
  network_id   TEXT PRIMARY KEY REFERENCES networks(id) ON DELETE CASCADE,
  slot         INTEGER NOT NULL,
  held_roots   INTEGER NOT NULL,
  held_bytes   INTEGER NOT NULL,
  wanted       INTEGER NOT NULL,
  last_sync_ns INTEGER NOT NULL,
  shard        TEXT NOT NULL,
  updated_at   INTEGER NOT NULL
);

INSERT INTO users (id, email, name, created_at)
  VALUES ('system-dataplane', 'system-dataplane', 'cloud data plane', 0);
"

/// V11: the browser every OAuth flow was started from.
///
/// The account-linking flow (`?link=1`) binds the linked identity to the
/// start-time session's user. Storing the initiating browser's binding token
/// hash here — the session cookie's token when there was a session, a fresh
/// per-flow cookie's otherwise — lets the callback refuse a browser that is
/// not the one that started the flow: a state/authorize URL handed to a
/// victim must not complete in the victim's browser, with or without a
/// session on either side. The hash is SHA-256 of the token, never the token
/// itself.
const v11 = "
ALTER TABLE oauth_states ADD COLUMN binding_token_hash BLOB;
"

/// V10: API keys — the credential for a caller that is a program.
///
/// Two kinds, one table, because everything about *being* a credential is the
/// same for both: the hash, the display prefix, the optional expiry, the
/// trail, the one revoke button.
///
/// An **org key** is a credential the org holds. It names one org and carries
/// its own `role`, so authorisation never reads `org_members` for it: a key
/// cannot reach another org, cannot be promoted by anything that happens to
/// its creator's membership, and — because the role grammar stops at `admin`
/// — can never be an owner. That last one is the whole of the escalation
/// story: every act that hands an org away (ownership transfer, deletion, the
/// sign-in configuration) is owner-gated, and so is closed to every key by
/// construction rather than by a list.
///
/// A **join key** is scoped to one network and the only act it can take is
/// putting a device into it. It carries no rank — `role = 'join'` is a
/// *kind*, and `api/common.check_org` refuses the whole family before any
/// rank is read. The two columns that say so travel together by CHECK, the
/// shape `auth_identities` uses for `provider`/`oidc_provider_id`: a `join`
/// row without a network, or a network on a row that is not `join`, is
/// unrepresentable rather than merely unexpected.
///
/// The difference between the kinds is where each is handed out. An org key
/// goes in a CI secret store, read by a job somebody wrote. A join key goes
/// in a provisioning image, a cloud-init file, a QR code taped to a rack —
/// places where a credential that could also *delete* a network has no
/// business being.
///
/// `created_by` is the person who minted it, kept because rows a key writes
/// still need a user to name in the `created_by` columns that reference
/// `users`. It is not who the key *is*: the audit trail records `key:<id>`,
/// which stays truthful after the minter has left.
///
/// The row keeps the SHA-256 of the token and never the token — the shape
/// sessions, invites and magic links already store. `prefix` is the leading
/// characters in clear, which is what lets a list say which key a leaked
/// token belongs to without holding enough to be one.
const v10 = "
CREATE TABLE api_keys (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES orgs(id),
  network_id   TEXT REFERENCES networks(id),
  name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  prefix       TEXT NOT NULL,
  token_hash   BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  role         TEXT NOT NULL CHECK (role IN ('admin','member','join')),
  created_by   TEXT NOT NULL REFERENCES users(id),
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER,
  last_used_at INTEGER,
  CHECK ((role = 'join') = (network_id IS NOT NULL))
);
CREATE INDEX api_keys_by_org ON api_keys (org_id);
CREATE INDEX api_keys_by_network ON api_keys (network_id);
"

/// V9: a network says whether its files may be browsed.
///
/// Off for every network that already exists and for every one created
/// after, because browsing is the org's call alone: daemons attach by
/// default, so this column is the whole of the gate. It is deliberately not
/// a zone fact — the apex record is deployment-wide, and per-network
/// enablement is enforced at the attach endpoint and on every browse call,
/// where a change takes effect at once instead of a TTL later, and where it
/// never reaches public DNS.
const v9 = "
ALTER TABLE networks ADD COLUMN browse_enabled INTEGER NOT NULL DEFAULT 0;
"

/// V8: `tuf_material` goes.
///
/// This service no longer walks Sigstore's TUF repository. The directory it
/// needs — which shard to submit to, and the key that checks the proof coming
/// back — ships in `priv/tuf/sigstore_trusted_root.json` and moves on a
/// deploy, so there is nothing to store between fetches.
///
/// Dropping the table rather than leaving it: a table nothing reads is a
/// question every future reader has to answer, and the answer would be
/// "material from a mechanism that was removed".
const v8 = "
DROP TABLE IF EXISTS tuf_material;
"

/// V5: `tuf_material` stops keeping the root chain.
///
/// The chain was kept to be copied into the zone. Clients read Sigstore's
/// TUF repository themselves now (docs/REKOR-ZONE-KEY.md §10), and every
/// walk this service makes starts from the anchor in `priv/tuf`, so nothing
/// reads those two columns. A rebuild rather than `DROP COLUMN`: the table
/// is one row, and this way the schema a fresh database gets is the schema a
/// migrated one gets, on every SQLite the deployment might be running.
const v5 = "
CREATE TABLE tuf_material_v5 (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  source            TEXT    NOT NULL,
  root_version      INTEGER NOT NULL,
  timestamp_json    BLOB    NOT NULL,
  timestamp_version INTEGER NOT NULL,
  timestamp_expires INTEGER NOT NULL,
  snapshot_json     BLOB    NOT NULL,
  snapshot_version  INTEGER NOT NULL,
  targets_json      BLOB    NOT NULL,
  targets_version   INTEGER NOT NULL,
  trusted_root      BLOB    NOT NULL,
  fetched_at        INTEGER NOT NULL
);
INSERT INTO tuf_material_v5
  SELECT id, source, root_version, timestamp_json, timestamp_version,
         timestamp_expires, snapshot_json, snapshot_version, targets_json,
         targets_version, trusted_root, fetched_at
  FROM tuf_material;
DROP TABLE tuf_material;
ALTER TABLE tuf_material_v5 RENAME TO tuf_material;
"

/// V4: external DNS provider mode (docs/EXTERNAL-DNS-PROVIDER.md).
///
/// `provider_sync_state` is one row — one deployment has one apex, one
/// provider. Desired state is derived from the product tables, never
/// stored: the row records only what the reconciler last did and how it
/// went, so `/healthz` can answer "in sync?" from `applied_hash` with no
/// provider round-trip. `last_error` and `last_error_at` travel together by
/// CHECK — an error without a time, or a time without an error, is a shape
/// the reporting code would misread.
///
/// `observed_zone_keys` is the key watcher's memory: the provider's signing
/// keys as last seen on the validated wire, and when each was covered by a
/// logged claim. Keyed by the SHA-256 of the DNSKEY rdata, the digest every
/// other part of this design names keys by; the rdata itself is stored so a
/// re-log can claim the exact observed bytes.
const v4 = "
CREATE TABLE provider_sync_state (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  provider           TEXT    NOT NULL CHECK (provider IN ('cloudflare','bunny','log-only')),
  provider_zone_id   TEXT    NOT NULL,
  applied_hash       BLOB             CHECK (applied_hash IS NULL OR length(applied_hash) = 32),
  last_synced_serial INTEGER,
  last_ok_at         INTEGER,
  last_attempt_at    INTEGER NOT NULL,
  last_error         TEXT,
  last_error_at      INTEGER,
  CHECK ((last_error IS NULL) = (last_error_at IS NULL))
);
CREATE TABLE observed_zone_keys (
  key_sha256   BLOB    NOT NULL CHECK (length(key_sha256) = 32),
  key_tag      INTEGER NOT NULL,
  dnskey_rdata BLOB    NOT NULL,
  first_seen   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  logged_at    INTEGER,
  PRIMARY KEY (key_sha256)
);
"

/// V3: zone-key transparency and the stored TUF material
/// (docs/REKOR-ZONE-KEY.md §5.2, §10.3).
///
/// `rekor_records` holds one row per zone-key lifecycle event: the entry
/// exactly as the log serialized it, beside the checkpoint and audit path
/// that prove it is in the tree. What is stored is what the log returned,
/// not a decomposition of it — so the certificate naming the zone stays
/// inside `canonicalized_body`, where Rekor put it.
///
/// Identity is `(keyset_sha256, action)`: an entry claims a key *set* — the
/// apex DNSKEY RRset its chain proves — and the identity is the SHA-256 over
/// that set's canonical rdata digests. The keys themselves are one row each
/// in `rekor_record_keys`, keyed by the SHA-256 of the DNSKEY rdata (the
/// digest a monitor's memory uses too), with the RFC 4034 key tag beside it
/// for operators. A tag is only a 16-bit checksum two keys can share, so it
/// is display data, never identity; the publish gate's question — is this
/// key claimed by a verified record — is a join on the rdata digest.
///
/// `chainless` records whether an entry carries a DNSSEC chain, and the CHECK
/// confines that to `retire`: a zone being retired may have no DS left in its
/// parent to build a chain from, while anything a client treats as
/// authorization must carry one. Recording it saves re-parsing DER to tell an
/// operator what monitors will make of a key.
///
/// `tuf_material` is a single row, because there is one Sigstore repository
/// and one current view of it — the files verbatim, their versions, and the
/// timestamp expiry the hourly job watches. The versions are what let a
/// refetch refuse a regression; the `trusted_root` is what names the log
/// shard this service submits to. (V5 drops `root_json`/`root_count`.)
const v3 = "
CREATE TABLE rekor_records (
  keyset_sha256      BLOB    NOT NULL CHECK (length(keyset_sha256) = 32),
  apex               TEXT    NOT NULL,
  action             TEXT    NOT NULL CHECK (action IN ('create','rollover','retire')),
  statement          BLOB    NOT NULL,
  canonicalized_body BLOB    NOT NULL,
  log_id             BLOB    NOT NULL CHECK (length(log_id) = 32),
  log_index          INTEGER NOT NULL,
  checkpoint         BLOB    NOT NULL,
  inclusion_path     BLOB    NOT NULL,
  chainless          INTEGER NOT NULL DEFAULT 0
                     CHECK (chainless = 0 OR action = 'retire'),
  integrated_at      INTEGER NOT NULL,
  verified_at        INTEGER NOT NULL,
  PRIMARY KEY (keyset_sha256, action)
);
CREATE INDEX rekor_records_by_apex ON rekor_records (apex);
CREATE TABLE rekor_record_keys (
  keyset_sha256 BLOB    NOT NULL CHECK (length(keyset_sha256) = 32),
  action        TEXT    NOT NULL,
  key_sha256    BLOB    NOT NULL CHECK (length(key_sha256) = 32),
  key_tag       INTEGER NOT NULL,
  PRIMARY KEY (keyset_sha256, action, key_sha256),
  FOREIGN KEY (keyset_sha256, action)
    REFERENCES rekor_records (keyset_sha256, action) ON DELETE CASCADE
);
CREATE INDEX rekor_record_keys_by_key ON rekor_record_keys (key_sha256);
CREATE TABLE tuf_material (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  source            TEXT    NOT NULL,
  root_json         BLOB    NOT NULL,
  root_count        INTEGER NOT NULL CHECK (root_count BETWEEN 1 AND 255),
  root_version      INTEGER NOT NULL,
  timestamp_json    BLOB    NOT NULL,
  timestamp_version INTEGER NOT NULL,
  timestamp_expires INTEGER NOT NULL,
  snapshot_json     BLOB    NOT NULL,
  snapshot_version  INTEGER NOT NULL,
  targets_json      BLOB    NOT NULL,
  targets_version   INTEGER NOT NULL,
  trusted_root      BLOB    NOT NULL,
  fetched_at        INTEGER NOT NULL
);
"

/// V2: DNS answers query SQLite directly (no in-memory snapshot), so
/// canonical DNS order must be computable in SQL — `sort_key` is the
/// reversed-label byte encoding whose BLOB order equals RFC 4034 §6.1
/// order. The nsec_chain table is redundant once NSEC rows are reachable
/// by sort_key (every owner carries its NSEC RRset in presigned_rrsets).
/// Publish rewrites every presigned row, so the empty default only exists
/// until the boot republish.
const v2 = "
ALTER TABLE presigned_rrsets ADD COLUMN sort_key BLOB NOT NULL DEFAULT x'';
CREATE INDEX presigned_by_sort_key ON presigned_rrsets (sort_key, rtype);
DROP TABLE nsec_chain;
"

/// V1: the whole product schema.
///
/// Invariants the schema itself carries:
///   - device_keys_live_nk: a non-revoked device key belongs to exactly one
///     device, globally — the §3.2 "same nk under two ids" ambiguity is
///     unrepresentable, and a zone can never be published ambiguous.
///   - network_devices_unique_label: two devices with the same label can
///     never be assigned to one network (defense in depth; the assign
///     transaction checks first and zone building re-validates).
/// Label grammars: org slugs and network names become DNS labels (no
/// leading/trailing hyphen); device labels only need the id= grammar
/// [a-z0-9-]{1,63}. CHECKs here are defensive floors — the application
/// validates strictly before insert.
const v1 = "
CREATE TABLE users (
  id         TEXT PRIMARY KEY,
  email      TEXT NOT NULL UNIQUE,
  name       TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE orgs (
  id         TEXT PRIMARY KEY,
  slug       TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  CHECK (
    length(slug) BETWEEN 1 AND 63
    AND slug NOT GLOB '*[^a-z0-9-]*'
    AND slug NOT GLOB '-*'
    AND slug NOT GLOB '*-'
  )
);

CREATE TABLE org_members (
  org_id   TEXT NOT NULL REFERENCES orgs(id),
  user_id  TEXT NOT NULL REFERENCES users(id),
  role     TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
  added_at INTEGER NOT NULL,
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE oidc_providers (
  id                     TEXT PRIMARY KEY,
  org_id                 TEXT NOT NULL UNIQUE REFERENCES orgs(id),
  issuer                 TEXT NOT NULL,
  client_id              TEXT NOT NULL,
  client_secret          TEXT NOT NULL,
  authorization_endpoint TEXT NOT NULL,
  token_endpoint         TEXT NOT NULL,
  userinfo_endpoint      TEXT,
  discovered_at          INTEGER NOT NULL
);

CREATE TABLE auth_identities (
  id               TEXT PRIMARY KEY,
  user_id          TEXT NOT NULL REFERENCES users(id),
  provider         TEXT NOT NULL CHECK (provider IN ('google','github','oidc','magic')),
  oidc_provider_id TEXT REFERENCES oidc_providers(id),
  subject          TEXT NOT NULL,
  created_at       INTEGER NOT NULL,
  CHECK ((provider = 'oidc') = (oidc_provider_id IS NOT NULL))
);
CREATE UNIQUE INDEX auth_identities_subject
  ON auth_identities (provider, coalesce(oidc_provider_id, ''), subject);

CREATE TABLE invites (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES orgs(id),
  email       TEXT NOT NULL,
  role        TEXT NOT NULL CHECK (role IN ('admin','member')),
  token_hash  BLOB NOT NULL UNIQUE,
  created_by  TEXT NOT NULL REFERENCES users(id),
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  accepted_at INTEGER
);

CREATE TABLE sessions (
  token_hash   BLOB PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id),
  csrf_token   TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE TABLE magic_link_tokens (
  token_hash  BLOB PRIMARY KEY,
  email       TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE TABLE oauth_states (
  state            TEXT PRIMARY KEY,
  provider         TEXT NOT NULL,
  oidc_provider_id TEXT REFERENCES oidc_providers(id),
  pkce_verifier    TEXT NOT NULL,
  nonce            TEXT,
  redirect_to      TEXT,
  link_user_id     TEXT REFERENCES users(id),
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL
);

CREATE TABLE networks (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL REFERENCES orgs(id),
  name       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (org_id, name),
  CHECK (
    length(name) BETWEEN 1 AND 63
    AND name NOT GLOB '*[^a-z0-9-]*'
    AND name NOT GLOB '-*'
    AND name NOT GLOB '*-'
  )
);

CREATE TABLE devices (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL REFERENCES orgs(id),
  label      TEXT NOT NULL,
  relay      TEXT,
  addr       TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  CHECK (length(label) BETWEEN 1 AND 63 AND label NOT GLOB '*[^a-z0-9-]*')
);

CREATE TABLE device_keys (
  id         TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL REFERENCES devices(id),
  nk_z32     TEXT NOT NULL,
  nk_bytes   BLOB NOT NULL CHECK (length(nk_bytes) = 32),
  state      TEXT NOT NULL CHECK (state IN ('active','retiring','revoked')),
  added_at   INTEGER NOT NULL,
  retired_at INTEGER
);
CREATE UNIQUE INDEX device_keys_live_nk
  ON device_keys (nk_bytes) WHERE state != 'revoked';
CREATE INDEX device_keys_by_device ON device_keys (device_id);

CREATE TABLE network_devices (
  network_id TEXT NOT NULL REFERENCES networks(id),
  device_id  TEXT NOT NULL REFERENCES devices(id),
  added_at   INTEGER NOT NULL,
  PRIMARY KEY (network_id, device_id)
);
CREATE TRIGGER network_devices_unique_label
  BEFORE INSERT ON network_devices
  WHEN EXISTS (
    SELECT 1
    FROM network_devices nd
    JOIN devices d ON d.id = nd.device_id
    WHERE nd.network_id = NEW.network_id
      AND d.label = (SELECT label FROM devices WHERE id = NEW.device_id)
  )
  BEGIN
    SELECT RAISE(ABORT, 'label already used in this network');
  END;

CREATE TABLE zone_meta (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  base_domain        TEXT NOT NULL,
  soa_serial         INTEGER NOT NULL,
  -- 64 bytes: a P-256 zone key (serve mode). 0 bytes: external mode,
  -- where the provider holds the zone keys and this row carries none.
  dnskey_public      BLOB NOT NULL CHECK (length(dnskey_public) IN (64, 0)),
  key_tag            INTEGER NOT NULL,
  sig_inception_skew INTEGER NOT NULL,
  sig_validity       INTEGER NOT NULL,
  sig_refresh_before INTEGER NOT NULL
);

CREATE TABLE zone_ns (
  hostname TEXT PRIMARY KEY,
  ipv4     TEXT,
  ipv6     TEXT
);

CREATE TABLE presigned_rrsets (
  name           TEXT NOT NULL,
  rtype          INTEGER NOT NULL,
  ttl            INTEGER NOT NULL,
  rrset_wire     BLOB NOT NULL,
  rrsig_wire     BLOB NOT NULL,
  sig_expires_at INTEGER NOT NULL,
  soa_serial     INTEGER NOT NULL,
  signed_at      INTEGER NOT NULL,
  PRIMARY KEY (name, rtype)
);

CREATE TABLE nsec_chain (
  owner TEXT PRIMARY KEY,
  next  TEXT NOT NULL,
  ord   INTEGER NOT NULL UNIQUE
);

CREATE TABLE audit_log (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  at     INTEGER NOT NULL,
  actor  TEXT,
  org_id TEXT,
  action TEXT NOT NULL,
  detail TEXT NOT NULL
);
"

/// V6: a staging slot for the key a rollover is bringing in.
///
/// Without it a zone key cannot be replaced at all: `ensure_meta` refuses
/// to boot when the key file disagrees with `dnskey_public`, and the
/// DNSKEY RRset is built from that one column, so the RRset can never hold
/// two keys. That makes DNSSEC's ordinary rollover — publish the incoming
/// key beside the outgoing one, wait for the parent DS and for caches to
/// pick it up, then switch signers — unrepresentable, and with
/// `CP_REKOR_REQUIRE=true` it deadlocks outright: the publish gate demands
/// the active key already be logged, `rekor-publish` claims the key set it
/// reads from live DNS, and a key cannot be in live DNS before it is
/// served.
///
/// The incoming key is public-only and never signs. It rides in the DNSKEY
/// RRset so the parent can be given its DS and so `rekor-publish` can claim
/// it, and `zone-key promote` moves it into `dnskey_public` once both are
/// true. Empty means no rollover in flight, which is every zone until
/// somebody starts one.
const v6 = "
ALTER TABLE zone_meta
  ADD COLUMN dnskey_incoming BLOB NOT NULL DEFAULT x''
  CHECK (length(dnskey_incoming) IN (64, 0));
ALTER TABLE zone_meta
  ADD COLUMN key_tag_incoming INTEGER NOT NULL DEFAULT 0;
"

/// V7: a provider apply can partly succeed.
///
/// `last_failures` is the rendered list for an operator and `last_partial_at`
/// records when the partial apply happened. Desired state remains a pure
/// function of the product tables; the next sweep recomputes the diff.
const v7 = "
ALTER TABLE provider_sync_state ADD COLUMN last_failures TEXT;
ALTER TABLE provider_sync_state ADD COLUMN last_partial_at INTEGER;
"
