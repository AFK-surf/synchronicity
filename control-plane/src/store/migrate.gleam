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
  [v1, v2, v3, v4, v5, v6, v7]
}

/// V7: identify a key by its key, not by a checksum of it.
///
/// V6's primary key was `(key_tag, action)`. An RFC 4034 key tag is a 16-bit
/// checksum over the DNSKEY rdata, so two distinct keys collide with odds
/// around 1/65536 per rollover — and a collision meant one key's row silently
/// *replaced* another's, taking its proof out of the served zone with no
/// error anywhere. Rare and silent is the bad combination: it would surface
/// as a cluster that stopped resolving for reasons nobody could reconstruct.
///
/// The identity is now `(spki_sha256, action)` — the SHA-256 of the key's DER
/// SubjectPublicKeyInfo, which is what identifies a key everywhere else in
/// this design (the succession extension names a predecessor by SPKI for the
/// same reason, and a monitor's known-keys file is keyed by this digest).
/// `key_tag` stays as an indexed column because that is what a client selects
/// on — it reads the tag from the RRSIG it just validated — but selection is
/// no longer identity: a lookup may now return two rows for one tag, and the
/// client tries each until one verifies.
///
/// Existing rows carry no SPKI column to backfill from, and the certificate
/// inside `canonicalized_body` would have to be parsed in SQL to get one, so
/// the table is rebuilt. `rekor-publish` repopulates it, which is a step the
/// ceremony already has.
const v7 = "
DROP TABLE rekor_records;
CREATE TABLE rekor_records (
  spki_sha256        BLOB    NOT NULL CHECK (length(spki_sha256) = 32),
  key_tag            INTEGER NOT NULL,
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
  PRIMARY KEY (spki_sha256, action)
);
CREATE INDEX rekor_records_by_apex ON rekor_records (apex);
CREATE INDEX rekor_records_by_key_tag ON rekor_records (key_tag);
"

/// V6: proof v3 — the certificate verifier (docs/REKOR-ZONE-KEY.md §2, §3).
///
/// Every row written under v5 holds a `canonicalizedBody` whose verifier is a
/// raw public key. Such an entry names no zone anywhere in its Merkle leaf,
/// which is the apex-anonymous shape v3 abolished: no client will accept one
/// and no monitor could ever have seen it. Carrying those rows forward would
/// mean serving proofs every upgraded client refuses, so the table is rebuilt
/// empty and the operator re-runs `rekor-publish`.
///
/// The columns are unchanged — the certificate lives inside
/// `canonicalized_body`, where the log put it, and this service stores what
/// the log serialized rather than a decomposition of it. The one addition is
/// `chainless`, recording whether an entry carries a DNSSEC chain: only a
/// `retire` may, and being able to say so without re-parsing DER is what lets
/// `/healthz` and the dashboard tell an operator what monitors will see.
///
/// One ordering consequence rides along, and it is the reason a rebuild is
/// tolerable: an entry now has to carry a DNSSEC chain, which cannot be built
/// until the **DS is live in the parent**, so re-running `rekor-publish` is a
/// step that happens after the DS is in place anyway (§5.2).
const v6 = "
DROP TABLE rekor_records;
CREATE TABLE rekor_records (
  key_tag            INTEGER NOT NULL,
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
  PRIMARY KEY (key_tag, action)
);
CREATE INDEX rekor_records_by_apex ON rekor_records (apex);
"

/// V5: the Rekor v2 rework (docs/REKOR-ZONE-KEY.md §2, §3). The record now
/// carries the log's own `canonicalizedBody` (the Merkle leaf preimage,
/// a real `hashedrekord` v0.0.2 entry over the DSSE PAE) beside the
/// Statement, replacing the v1 leaf convention that hashed a
/// synchronicity-canonical DSSE envelope. Any row written under v3/v4 is a
/// proof under the old leaf convention that no v2 client will accept, so the
/// table is rebuilt empty rather than carried forward with mislabelled
/// columns: `dsse_signature` bytes are not a `canonicalizedBody`. An operator
/// re-runs `rekor-publish` to repopulate it, which the ceremony already
/// budgets for.
const v5 = "
DROP TABLE rekor_records;
CREATE TABLE rekor_records (
  key_tag            INTEGER NOT NULL,
  apex               TEXT    NOT NULL,
  action             TEXT    NOT NULL CHECK (action IN ('create','rollover','retire')),
  statement          BLOB    NOT NULL,
  canonicalized_body BLOB    NOT NULL,
  log_id             BLOB    NOT NULL CHECK (length(log_id) = 32),
  log_index          INTEGER NOT NULL,
  checkpoint         BLOB    NOT NULL,
  inclusion_path     BLOB    NOT NULL,
  integrated_at      INTEGER NOT NULL,
  verified_at        INTEGER NOT NULL,
  PRIMARY KEY (key_tag, action)
);
CREATE INDEX rekor_records_by_apex ON rekor_records (apex);
"

/// V4: the relayed TUF material (docs/REKOR-ZONE-KEY.md §10.3). One row,
/// because there is one Sigstore repository and one current view of it —
/// the files verbatim, their versions, and the timestamp expiry the hourly
/// job watches. This service is a relay, not the verifier: the columns
/// exist so it can refuse regressions and know when to refetch, and the
/// cryptographic gate is the client's.
///
/// `root_json` holds the root chain as one blob of u32-length-prefixed
/// files, ascending — the same framing the bundle record uses, so serving
/// is a copy rather than a re-encode.
const v4 = "
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

/// V3: zone-key transparency (docs/REKOR-ZONE-KEY.md §5.2). One row per
/// zone-key lifecycle event, holding the entry exactly as it was logged
/// plus the checkpoint and audit path that prove it is in the tree. The
/// primary key is (key_tag, action) because a key is created once, rolled
/// over once and retired once; re-publishing refreshes the row rather than
/// minting a second entry for the same claim.
const v3 = "
CREATE TABLE rekor_records (
  key_tag         INTEGER NOT NULL,
  apex            TEXT    NOT NULL,
  action          TEXT    NOT NULL CHECK (action IN ('create','rollover','retire')),
  dsse_payload    BLOB    NOT NULL,
  dsse_signature  BLOB    NOT NULL,
  log_id          BLOB    NOT NULL CHECK (length(log_id) = 32),
  log_index       INTEGER NOT NULL,
  checkpoint      BLOB    NOT NULL,
  inclusion_path  BLOB    NOT NULL,
  integrated_at   INTEGER NOT NULL,
  verified_at     INTEGER NOT NULL,
  PRIMARY KEY (key_tag, action)
);
CREATE INDEX rekor_records_by_apex ON rekor_records (apex);
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
  dnskey_public      BLOB NOT NULL CHECK (length(dnskey_public) = 64),
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
