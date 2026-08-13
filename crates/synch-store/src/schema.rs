//! The schema as an ordered chain of migrations (§10).
//!
//! There is one path to a database of the current shape: replaying
//! [`MIGRATIONS`] from wherever a database currently is. `MIGRATIONS[v]` takes
//! a database from version `v` to `v + 1`, so index 0 takes an *empty* file to
//! version 1 — the original schema — and a fresh database is simply one that
//! replays the whole chain. There is deliberately no separate "current schema"
//! bootstrap: a second path to the same tables is a second thing to keep
//! correct, and it would drift.
//!
//! The rules the chain keeps (§10):
//!
//! - Each step runs in **one transaction**, with the `schema_version` stamp
//!   updated inside it, so a crash mid-upgrade leaves a database that is
//!   exactly at some version and never between two.
//! - A database stamped newer than this build knows is **refused**, not probed.
//! - No `IF NOT EXISTS` anywhere: whether an object exists is determined by the
//!   version number, never discovered by trying.
//! - Anything SQL cannot express is a [`Migration::Rust`] step in the same
//!   numbered chain, under the same transaction rule.

use rusqlite::Transaction;

use crate::error::Result;

/// The version a database this build writes carries: the length of the chain.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// One step of the migration chain.
pub enum Migration {
    /// A batch of SQL statements.
    Sql(&'static str),
    /// A step SQL cannot express — a backfill, a rewrite of stored text.
    Rust {
        /// What the step does, for logs and failure messages.
        name: &'static str,
        /// The step itself, run inside the migration's transaction.
        run: fn(&Transaction<'_>) -> Result<()>,
    },
}

impl std::fmt::Debug for Migration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Migration::Sql(_) => f.write_str("Migration::Sql"),
            Migration::Rust { name, .. } => write!(f, "Migration::Rust({name})"),
        }
    }
}

/// The whole history of this schema, in order.
///
/// `MIGRATIONS[v]` upgrades a database at version `v` to version `v + 1`.
pub const MIGRATIONS: &[Migration] = &[
    Migration::Sql(V1_ORIGINAL),
    Migration::Sql(V2_OBSERVED_HEADS),
    Migration::Sql(V3_DROP_WANT),
    Migration::Sql(V4_MIRROR_POLICIES),
    Migration::Rust {
        name: "s3 bucket policies",
        run: v5_bucket_policies,
    },
    Migration::Sql(V6_ENTRY_SYMLINK_TARGET),
    Migration::Sql(V7_OBSERVED_CLAIMED_BY),
];

/// v1 — the original schema, exactly as it first shipped.
const V1_ORIGINAL: &str = r#"
-- node & config
CREATE TABLE config        (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                                         -- includes 'self_origin_id'
CREATE TABLE device_keys (                -- own keys; >1 row only during rotation
  node_id     BLOB PRIMARY KEY,
  secret_key  BLOB NOT NULL,
  state       TEXT NOT NULL,             -- 'active' | 'retiring'
  created_at  INTEGER NOT NULL
);

-- membership: OriginId -> device-key bindings.
-- origin_id is the canonical rendering: '<id>@<domain>' or 'key:<z-base-32>'.
CREATE TABLE bindings (
  origin_id    TEXT NOT NULL,
  node_id      BLOB NOT NULL,            -- bound device key (32 bytes)
  source       TEXT NOT NULL,            -- 'static' | 'dns'
  domain       TEXT,                     -- for dns source
  note         TEXT,
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,                  -- NULL for static
  PRIMARY KEY (origin_id, node_id, source)
);
CREATE INDEX bindings_by_key ON bindings (node_id);

-- mptsync
CREATE TABLE heads (
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
CREATE TABLE head_history (
  origin_id TEXT, seq INTEGER, root BLOB, created_at INTEGER,
  signed_by BLOB, sig BLOB,
  PRIMARY KEY (origin_id, seq, root)
);
CREATE TABLE trie_nodes    (hash BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE trie_values   (hash BLOB PRIMARY KEY, data BLOB NOT NULL);

-- materialized views of trie leaves (rebuilt incrementally from diffs)
CREATE TABLE entries (
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
CREATE INDEX entries_by_path    ON entries (space, path);
CREATE INDEX entries_by_content ON entries (content);

CREATE TABLE blob_providers (
  object_root BLOB NOT NULL,
  origin_id   TEXT NOT NULL,
  size        INTEGER NOT NULL,
  complete    INTEGER NOT NULL,
  spans       BLOB,
  PRIMARY KEY (object_root, origin_id)
);

-- local content store index
CREATE TABLE blobs (
  root        BLOB PRIMARY KEY,
  size        INTEGER NOT NULL,
  complete    INTEGER NOT NULL,
  bitmap      BLOB,
  inline      BLOB,
  pinned      INTEGER NOT NULL DEFAULT 0,
  last_access INTEGER NOT NULL
);

-- indexing / engine state
CREATE TABLE spaces        (id TEXT PRIMARY KEY, local_path TEXT NOT NULL);
CREATE TABLE local_files   (space TEXT, relpath TEXT, size INTEGER, mtime_ns INTEGER,
                            file_id BLOB, content BLOB, scanned_at INTEGER,
                            PRIMARY KEY (space, relpath));
CREATE TABLE mirrors       (origin_id TEXT, space TEXT, local_path TEXT NOT NULL,
                            PRIMARY KEY (origin_id, space));
CREATE TABLE want          (root BLOB, ranges BLOB, priority INTEGER, reason TEXT,
                            created_at INTEGER, PRIMARY KEY (root, ranges));
CREATE TABLE peers_seen    (node_id BLOB PRIMARY KEY, last_addr BLOB, last_seen INTEGER,
                            last_sync INTEGER, latency_ewma_us INTEGER);
"#;

/// v2 — key-loss recovery (§3.4) needs somewhere to keep what peers advertise
/// for *our own* origin: observations of existing traffic, never heads.
const V2_OBSERVED_HEADS: &str = r#"
CREATE TABLE observed_heads (
  origin_id   TEXT PRIMARY KEY,
  seq         INTEGER NOT NULL,
  root        BLOB NOT NULL,
  complete    INTEGER NOT NULL,      -- whether the advertiser can serve that trie
  observed_at INTEGER NOT NULL
);
"#;

/// v3 — the `want` table described a persistent download queue. §6.4 is
/// explicitly queue-less — fetching is on-demand and request-scoped — so the
/// table never had a producer or a consumer.
const V3_DROP_WANT: &str = "DROP TABLE want;";

/// v4 — a mirror materializes the *unified tree* under a version policy
/// (§7.2, §8), so it is keyed by the directory it writes into and no longer
/// names an origin. Existing rows keep behaving exactly as they did, as an
/// `origin=` pin on the origin they used to name.
const V4_MIRROR_POLICIES: &str = r#"
ALTER TABLE mirrors RENAME TO mirrors_v3;
CREATE TABLE mirrors (
  local_path TEXT PRIMARY KEY,           -- one mirror per directory
  space      TEXT NOT NULL,
  policy     TEXT NOT NULL               -- 'newest' | 'origin=<id>' | 'strict' (§7.2)
);
INSERT OR REPLACE INTO mirrors (local_path, space, policy)
  SELECT local_path, space, 'origin=' || origin_id FROM mirrors_v3;
DROP TABLE mirrors_v3;
"#;

/// v5 — the same reshape for `synch-s3`'s bucket map, which lives in a `config`
/// row rather than a table of its own (§9.4).
///
/// Each line was `<bucket>\t<origin>\t<space>`; a bucket now names a space of
/// the unified tree plus a version policy, and an existing bucket keeps serving
/// exactly what it served as an `origin=` pin.
fn v5_bucket_policies(tx: &Transaction<'_>) -> Result<()> {
    use rusqlite::OptionalExtension;
    let existing: Option<String> = tx
        .query_row(
            "SELECT value FROM config WHERE key = 's3_buckets'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(existing) = existing else {
        return Ok(());
    };
    let rewritten = existing
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let (name, origin, space) = (parts.next()?, parts.next()?, parts.next()?);
            Some(format!("{name}\t{space}\torigin={origin}"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    tx.execute(
        "UPDATE config SET value = ?1 WHERE key = 's3_buckets'",
        rusqlite::params![rewritten],
    )?;
    Ok(())
}

/// v6 — a symlink's target is part of its version identity (§8): two symlinks
/// are the same version iff their targets match, and a symlink is never the
/// same version as a file. `entries` is the view versions are computed from, so
/// the target has to live there.
///
/// Rebuilt rather than `ALTER TABLE ... ADD COLUMN`, so the stored DDL reads in
/// declaration order instead of trailing the primary key. `entries` is a
/// derived cache of the trie, but copying it forward is cheaper and quieter
/// than making every node re-materialize on upgrade.
const V6_ENTRY_SYMLINK_TARGET: &str = r#"
DROP INDEX entries_by_path;
DROP INDEX entries_by_content;
ALTER TABLE entries RENAME TO entries_v5;
CREATE TABLE entries (
  origin_id   TEXT NOT NULL,
  space       TEXT NOT NULL,
  path        TEXT NOT NULL,
  kind        INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  mtime_ns    INTEGER NOT NULL,
  content     BLOB,
  seq         INTEGER NOT NULL,
  prev        BLOB,
  symlink_target TEXT,
  PRIMARY KEY (origin_id, space, path)
);
INSERT INTO entries (origin_id, space, path, kind, size, mtime_ns, content, seq, prev,
                     symlink_target)
  SELECT origin_id, space, path, kind, size, mtime_ns, content, seq, prev, NULL
  FROM entries_v5;
DROP TABLE entries_v5;
CREATE INDEX entries_by_path    ON entries (space, path);
CREATE INDEX entries_by_content ON entries (content);
"#;

/// v7 — recovery detection rests on peers' *unauthenticated* summaries, so
/// §3.4 has `synch doctor` report which peer claimed the highest seq: within
/// the trust stance of §12 any member could assert a huge one and hold a fresh
/// node in recovery, and the attribution is what lets an operator judge the
/// claim.
///
/// Rebuilt rather than `ALTER ... ADD COLUMN` for the same reason as v6: the
/// stored DDL should read in declaration order.
const V7_OBSERVED_CLAIMED_BY: &str = r#"
ALTER TABLE observed_heads RENAME TO observed_heads_v6;
CREATE TABLE observed_heads (
  origin_id   TEXT PRIMARY KEY,
  seq         INTEGER NOT NULL,
  root        BLOB NOT NULL,
  complete    INTEGER NOT NULL,
  claimed_by  BLOB,
  observed_at INTEGER NOT NULL
);
INSERT INTO observed_heads (origin_id, seq, root, complete, claimed_by, observed_at)
  SELECT origin_id, seq, root, complete, NULL, observed_at FROM observed_heads_v6;
DROP TABLE observed_heads_v6;
"#;

/// The §10 schema as the design document states it — the shape replaying the
/// whole chain must produce.
///
/// Documentation only: nothing executes this in a running node, and
/// `the_chain_produces_the_documented_schema` asserts that a database built
/// from it is indistinguishable from one built by the chain. Keeping it
/// `cfg(test)` is what makes "there is exactly one path to a database" a
/// property of the code rather than a promise.
#[cfg(test)]
pub const FINAL_SCHEMA: &str = r#"
CREATE TABLE config        (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE device_keys (
  node_id     BLOB PRIMARY KEY,
  secret_key  BLOB NOT NULL,
  state       TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE TABLE bindings (
  origin_id    TEXT NOT NULL,
  node_id      BLOB NOT NULL,
  source       TEXT NOT NULL,
  domain       TEXT,
  note         TEXT,
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,
  PRIMARY KEY (origin_id, node_id, source)
);
CREATE INDEX bindings_by_key ON bindings (node_id);
CREATE TABLE heads (
  origin_id   TEXT NOT NULL,
  slot        TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  root        BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  signed_by   BLOB NOT NULL,
  sig         BLOB NOT NULL,
  received_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY (origin_id, slot)
);
CREATE TABLE head_history (
  origin_id TEXT, seq INTEGER, root BLOB, created_at INTEGER,
  signed_by BLOB, sig BLOB,
  PRIMARY KEY (origin_id, seq, root)
);
CREATE TABLE trie_nodes    (hash BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE trie_values   (hash BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE entries (
  origin_id   TEXT NOT NULL,
  space       TEXT NOT NULL,
  path        TEXT NOT NULL,
  kind        INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  mtime_ns    INTEGER NOT NULL,
  content     BLOB,
  seq         INTEGER NOT NULL,
  prev        BLOB,
  symlink_target TEXT,
  PRIMARY KEY (origin_id, space, path)
);
CREATE INDEX entries_by_path    ON entries (space, path);
CREATE INDEX entries_by_content ON entries (content);
CREATE TABLE blob_providers (
  object_root BLOB NOT NULL,
  origin_id   TEXT NOT NULL,
  size        INTEGER NOT NULL,
  complete    INTEGER NOT NULL,
  spans       BLOB,
  PRIMARY KEY (object_root, origin_id)
);
CREATE TABLE blobs (
  root        BLOB PRIMARY KEY,
  size        INTEGER NOT NULL,
  complete    INTEGER NOT NULL,
  bitmap      BLOB,
  inline      BLOB,
  pinned      INTEGER NOT NULL DEFAULT 0,
  last_access INTEGER NOT NULL
);
CREATE TABLE spaces        (id TEXT PRIMARY KEY, local_path TEXT NOT NULL);
CREATE TABLE local_files   (space TEXT, relpath TEXT, size INTEGER, mtime_ns INTEGER,
                            file_id BLOB, content BLOB, scanned_at INTEGER,
                            PRIMARY KEY (space, relpath));
CREATE TABLE mirrors (
  local_path TEXT PRIMARY KEY,
  space      TEXT NOT NULL,
  policy     TEXT NOT NULL
);
CREATE TABLE peers_seen    (node_id BLOB PRIMARY KEY, last_addr BLOB, last_seen INTEGER,
                            last_sync INTEGER, latency_ewma_us INTEGER);
CREATE TABLE observed_heads (
  origin_id   TEXT PRIMARY KEY,
  seq         INTEGER NOT NULL,
  root        BLOB NOT NULL,
  complete    INTEGER NOT NULL,
  claimed_by  BLOB,
  observed_at INTEGER NOT NULL
);
"#;
