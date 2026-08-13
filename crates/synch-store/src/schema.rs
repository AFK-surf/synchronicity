//! The SQLite schema (§10), applied verbatim on open.

/// The schema version stored in `config`.
///
/// Every statement below is `IF NOT EXISTS`, so applying this schema to an
/// older database *is* the migration for anything additive;
/// [`crate::db::Store::open`] stamps the new version afterwards. A change that
/// is *not* additive — v3 dropped the dead `want` table — needs a statement of
/// its own in [`MIGRATIONS`].
pub const SCHEMA_VERSION: u32 = 3;

/// The statements an older database needs beyond re-applying [`SCHEMA`], each
/// paired with the version that introduced it.
///
/// Applying the schema covers every additive change, so this list only carries
/// what the schema cannot say: dropped tables, dropped columns, rewrites. A
/// database at version `v` runs every entry whose version is greater than `v`,
/// in order, and is then stamped [`SCHEMA_VERSION`].
pub const MIGRATIONS: &[(u32, &str)] = &[
    // v3: the `want` table described a persistent download queue. §6.4 is
    // explicitly queue-less — fetching is on-demand and request-scoped — so the
    // table never had a producer or a consumer.
    (3, "DROP TABLE IF EXISTS want"),
];

/// The §10 schema. Every statement is `IF NOT EXISTS`, so opening an existing
/// database is a no-op.
pub const SCHEMA: &str = r#"
-- node & config
CREATE TABLE IF NOT EXISTS config        (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                                         -- includes 'self_origin_id'
CREATE TABLE IF NOT EXISTS device_keys (  -- own keys; >1 row only during rotation
  node_id     BLOB PRIMARY KEY,
  secret_key  BLOB NOT NULL,
  state       TEXT NOT NULL,             -- 'active' | 'retiring'
  created_at  INTEGER NOT NULL
);

-- membership: OriginId -> device-key bindings.
-- origin_id is the canonical rendering: '<id>@<domain>' or 'key:<z-base-32>'.
CREATE TABLE IF NOT EXISTS bindings (
  origin_id    TEXT NOT NULL,
  node_id      BLOB NOT NULL,            -- bound device key (32 bytes)
  source       TEXT NOT NULL,            -- 'static' | 'dns'
  domain       TEXT,                     -- for dns source
  note         TEXT,
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,                  -- NULL for static
  PRIMARY KEY (origin_id, node_id, source)
);
CREATE INDEX IF NOT EXISTS bindings_by_key ON bindings (node_id);

-- mptsync
CREATE TABLE IF NOT EXISTS heads (
  origin_id   TEXT NOT NULL,
  slot        TEXT NOT NULL,             -- 'complete' | 'pending'
  seq         INTEGER NOT NULL,
  root        BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  signed_by   BLOB NOT NULL,
  sig         BLOB NOT NULL,
  received_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY (origin_id, slot)
);
CREATE TABLE IF NOT EXISTS head_history (
  origin_id TEXT, seq INTEGER, root BLOB, created_at INTEGER,
  signed_by BLOB, sig BLOB,
  PRIMARY KEY (origin_id, seq, root)
);
-- key-loss recovery (§3.4): the highest head a peer has advertised for an
-- origin in its `Hello` summary. These are observations of existing traffic,
-- never heads: the heads behind them are signed by a key that is no longer
-- bound, so they cannot be accepted (§4.4) and only their existence is kept.
CREATE TABLE IF NOT EXISTS observed_heads (
  origin_id   TEXT PRIMARY KEY,
  seq         INTEGER NOT NULL,
  root        BLOB NOT NULL,
  complete    INTEGER NOT NULL,      -- whether the advertiser can serve that trie
  observed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS trie_nodes    (hash BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS trie_values   (hash BLOB PRIMARY KEY, data BLOB NOT NULL);

-- materialized views of trie leaves (rebuilt incrementally from diffs)
CREATE TABLE IF NOT EXISTS entries (
  origin_id   TEXT NOT NULL,
  space       TEXT NOT NULL,
  path        TEXT NOT NULL,
  kind        INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  mtime_ns    INTEGER NOT NULL,
  content     BLOB,
  seq         INTEGER NOT NULL,
  prev        BLOB,
  PRIMARY KEY (origin_id, space, path)
);
CREATE INDEX IF NOT EXISTS entries_by_path    ON entries (space, path);
CREATE INDEX IF NOT EXISTS entries_by_content ON entries (content);

CREATE TABLE IF NOT EXISTS blob_providers (
  object_root BLOB NOT NULL,
  origin_id   TEXT NOT NULL,
  size        INTEGER NOT NULL,
  complete    INTEGER NOT NULL,
  spans       BLOB,
  PRIMARY KEY (object_root, origin_id)
);

-- local content store index
CREATE TABLE IF NOT EXISTS blobs (
  root        BLOB PRIMARY KEY,
  size        INTEGER NOT NULL,
  complete    INTEGER NOT NULL,
  bitmap      BLOB,
  inline      BLOB,
  pinned      INTEGER NOT NULL DEFAULT 0,
  last_access INTEGER NOT NULL
);

-- indexing / engine state
CREATE TABLE IF NOT EXISTS spaces        (id TEXT PRIMARY KEY, local_path TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS local_files   (space TEXT, relpath TEXT, size INTEGER, mtime_ns INTEGER,
                                          file_id BLOB, content BLOB, scanned_at INTEGER,
                                          PRIMARY KEY (space, relpath));
CREATE TABLE IF NOT EXISTS mirrors       (origin_id TEXT, space TEXT, local_path TEXT NOT NULL,
                                          PRIMARY KEY (origin_id, space));
CREATE TABLE IF NOT EXISTS peers_seen    (node_id BLOB PRIMARY KEY, last_addr BLOB, last_seen INTEGER,
                                          last_sync INTEGER, latency_ewma_us INTEGER);
"#;
