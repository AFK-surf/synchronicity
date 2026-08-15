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
  let step = {
    use _ <- result.try(sqlite.exec(conn, "BEGIN IMMEDIATE", []))
    use _ <- result.try(sqlite.script(conn, sql))
    use _ <- result.try(sqlite.script(
      conn,
      "PRAGMA user_version = " <> int.to_string(to),
    ))
    use _ <- result.try(sqlite.exec(conn, "COMMIT", []))
    Ok(to)
  }
  case step {
    Ok(v) -> Ok(v)
    Error(e) -> {
      let _ = sqlite.exec(conn, "ROLLBACK", [])
      Error(Failed(to, e))
    }
  }
}

fn migrations() -> List(String) {
  [v1, v2]
}

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
