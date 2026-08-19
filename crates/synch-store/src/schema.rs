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
    Migration::Sql(V8_S3_CONFIG_NAMESPACE),
    Migration::Sql(V9_ENTRY_UNIX_MODE),
    Migration::Rust {
        name: "verified groups as ranges",
        run: v10_groups_as_ranges,
    },
    Migration::Sql(V11_HEADS_POINT_AT_HISTORY),
    Migration::Rust {
        name: "history records local receipt",
        run: v12_history_recorded_at,
    },
    Migration::Sql(V13_PROVIDERS_BY_ORIGIN),
    Migration::Sql(V14_DNS_BINDINGS_ARE_PER_DOMAIN),
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
-- Plain INSERT, not INSERT OR REPLACE. The key moves from
-- (origin_id, space) to local_path, so two v3 mirrors that pointed at one
-- directory would collide here — and the survivor's sweep would then delete
-- the other origin's materialized files. Failing loudly is the right outcome
-- for an ambiguous upgrade.
--
-- Worth knowing before reading that as an operator trap it is not: there has
-- never been a released build whose chain stopped at v3. v1 through v8 landed
-- in one commit, so a fresh database replays v1 — which creates an empty
-- `mirrors` — and reaches this SELECT with no rows to collide. A database that
-- could fail here would have to be hand-built at v3, and `Store::open` is the
-- only way in, so recovering it means hand-editing either way.
INSERT INTO mirrors (local_path, space, policy)
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

/// v8 — the gateway's configuration moves into the `s3.*` config namespace
/// (§9.4).
///
/// `synch-s3` no longer opens the database: its buckets and access keys are
/// stored by the daemon and reached over the control socket, and the daemon
/// serves exactly one namespace to that client. A prefix is what makes the
/// fence checkable — `s3.buckets` and `s3.keys` are inside it, `self_origin_id`
/// is not — so the two rows are renamed to sit under it.
const V8_S3_CONFIG_NAMESPACE: &str = r#"
UPDATE config SET key = 's3.buckets' WHERE key = 's3_buckets';
UPDATE config SET key = 's3.keys'    WHERE key = 's3_access_keys';
"#;

/// v9 — a file's advisory unix mode (§4.2) is metadata a mirror has to
/// reproduce (§7.2), and `entries` is what every materializing surface reads.
/// The scanner has always published the mode in its `f:` records; this view
/// dropped it on the way in, so no reader could ever see it and every mirrored
/// file came out with whatever mode the copy happened to create.
///
/// The column is nullable because the mode genuinely is optional: a Windows
/// origin publishes none. Existing rows are carried forward as NULL rather than
/// backfilled — the authoritative value is in each origin's trie, not here, and
/// re-deriving it means re-materializing every leaf of every trie inside a
/// migration transaction. Rows refresh as their origins republish, and
/// `synch doctor --rebuild` repopulates all of them at once.
///
/// Rebuilt rather than `ALTER ... ADD COLUMN` for the same reason as v6 and v7:
/// the stored DDL should read in declaration order.
const V9_ENTRY_UNIX_MODE: &str = r#"
DROP INDEX entries_by_path;
DROP INDEX entries_by_content;
ALTER TABLE entries RENAME TO entries_v8;
CREATE TABLE entries (
  origin_id   TEXT NOT NULL,
  space       TEXT NOT NULL,
  path        TEXT NOT NULL,
  kind        INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  mtime_ns    INTEGER NOT NULL,
  unix_mode   INTEGER,
  content     BLOB,
  seq         INTEGER NOT NULL,
  prev        BLOB,
  symlink_target TEXT,
  PRIMARY KEY (origin_id, space, path)
);
INSERT INTO entries (origin_id, space, path, kind, size, mtime_ns, unix_mode, content, seq,
                     prev, symlink_target)
  SELECT origin_id, space, path, kind, size, mtime_ns, NULL, content, seq, prev, symlink_target
  FROM entries_v8;
DROP TABLE entries_v8;
CREATE INDEX entries_by_path    ON entries (space, path);
CREATE INDEX entries_by_content ON entries (content);
"#;

/// v10 — `blobs.bitmap` holds the verified groups as ranges rather than as a
/// bit per group.
///
/// The column keeps its name and type; only the encoding changes. A bitmap cost
/// `O(group_count)` to read and to write, and a partial object's row is read and
/// rewritten on every committed window and read again on every slice served, so
/// the cost fell on exactly the hot paths — quadratic in the object for a fetch,
/// and a cheap-request/expensive-work amplification for a provider. Runs of
/// verified groups are contiguous in practice, so the range form is a few
/// integers where the bitmap was hundreds of kilobytes.
///
/// Only partial rows carry the column at all: a complete object's groups are
/// implied by its size.
fn v10_groups_as_ranges(tx: &Transaction<'_>) -> Result<()> {
    let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = {
        let mut stmt = tx.prepare(
            "SELECT root, size, bitmap FROM blobs WHERE complete = 0 AND bitmap IS NOT NULL",
        )?;
        let mapped = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (root, size, bits) in rows {
        let groups = synch_core::group_count(size as u64);
        let ranges = crate::cas::bitmap_to_ranges(&bits, groups);
        tx.execute(
            "UPDATE blobs SET bitmap = ?2 WHERE root = ?1",
            rusqlite::params![root, crate::cas::ranges_to_blob(&ranges)],
        )?;
    }
    Ok(())
}

/// v11 — `heads` points into `head_history` rather than copying it.
///
/// The two tables carried the same five columns for the same rows, and every
/// head that reached the complete slot was written to `head_history` twice
/// under two separate rules: on arrival (`offer_head`, `publish`, `activate`)
/// and again on displacement (`try_promote`, `publish`, `activate`). The second
/// rule was provably redundant — every head reaching the complete slot passed
/// through one of the first three — and was saved only by `INSERT OR IGNORE`.
///
/// The duplication then had to be patched around: retention needed an explicit
/// exemption so it would not delete the history rows shadowing the current
/// heads, and the GC mark set was a `UNION` across both tables. With `heads`
/// holding only `(seq, root)` and the signature living in one place, the mark
/// set is one table and the exemption is a single referential rule instead of a
/// special case per table.
///
/// A *rule*, not a declared constraint: no `FOREIGN KEY` is stated here, so
/// `PRAGMA foreign_keys=ON` enforces nothing over it. What holds the pointer up
/// is that `put_head_in` writes the `head_history` row before the slot names
/// it, and that both `DELETE FROM head_history` sites carry a
/// `NOT EXISTS (SELECT 1 FROM heads …)` guard. Those are the only writers, so
/// the invariant is sound — but it is sound by review rather than by
/// construction, and the failure mode if a history row ever did go missing is
/// silent: `HEAD_JOIN` is an inner join, so the head reads back as absent.
///
/// It does **not** follow that the origin restarts at seq 1, which is what this
/// comment used to claim. `next_own_seq_in` takes `MAX(seq)` over a `UNION` of
/// `heads` and `head_history` and floors the result with the publish floor —
/// none of which goes through `HEAD_JOIN` — so the seq survives a lost
/// signature. What is actually lost is the ability to *serve* or re-sign that
/// head. Stating the hazard larger than it is has its own cost: it argues for a
/// table-rebuild migration that a declared `FOREIGN KEY` would not even let
/// these two `DELETE`s skip rows with, since RESTRICT would make them error
/// where they mean to pass over.
///
/// The backfill is `INSERT OR IGNORE` first so that a head whose history row
/// was somehow missing does not lose its signature to the rebuild.
const V11_HEADS_POINT_AT_HISTORY: &str = r#"
INSERT OR IGNORE INTO head_history (origin_id, seq, root, created_at, signed_by, sig)
  SELECT origin_id, seq, root, created_at, signed_by, sig FROM heads;
ALTER TABLE heads RENAME TO heads_v10;
CREATE TABLE heads (
  origin_id   TEXT NOT NULL,
  slot        TEXT NOT NULL,             -- 'complete' | 'pending'
  seq         INTEGER NOT NULL,
  root        BLOB NOT NULL,
  received_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY (origin_id, slot)
);
INSERT INTO heads (origin_id, slot, seq, root, received_at, verified_at)
  SELECT origin_id, slot, seq, root, received_at, verified_at FROM heads_v10;
DROP TABLE heads_v10;
"#;

/// v12 — `head_history` records when a row was received locally.
///
/// Retention keys on `recorded_at`. `created_at` is the signer's own choice and
/// is never clamped, so a row claiming to have been created at the end of time
/// would outlive every retention window — and with it every trie node reachable
/// from its root, which GC marks from this table.
///
/// Existing rows are stamped with the migration's own time: what this node knows
/// about them is that it holds them now.
fn v12_history_recorded_at(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        "ALTER TABLE head_history RENAME TO head_history_v11;
         CREATE TABLE head_history (
           origin_id TEXT, seq INTEGER, root BLOB, created_at INTEGER,
           signed_by BLOB, sig BLOB, recorded_at INTEGER NOT NULL,
           PRIMARY KEY (origin_id, seq, root)
         );",
    )?;
    tx.execute(
        "INSERT INTO head_history
           (origin_id, seq, root, created_at, signed_by, sig, recorded_at)
         SELECT origin_id, seq, root, created_at, signed_by, sig, ?1
           FROM head_history_v11",
        rusqlite::params![synch_core::now_ns()],
    )?;
    tx.execute_batch("DROP TABLE head_history_v11;")?;
    Ok(())
}

/// v13 — `blob_providers` is indexed by origin as well as by object.
///
/// `PRIMARY KEY (object_root, origin_id)` serves "who advertises this object?"
/// and nothing serves "what does this origin advertise?", which is a full table
/// scan over *objects × advertising origins*. Two readers ask it:
/// `provider_roots_for_origin`, once per maintenance pass, and
/// `delete_origin_providers`, once per origin inside `doctor --rebuild`'s write
/// transaction — so the rebuild was one scan per origin, holding the write
/// connection throughout. `entries` has had both a covering primary key and a
/// secondary index from the start; this table got neither.
const V13_PROVIDERS_BY_ORIGIN: &str =
    "CREATE INDEX blob_providers_by_origin ON blob_providers (origin_id);";

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
  domain       TEXT NOT NULL DEFAULT '',
  note         TEXT,
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,
  PRIMARY KEY (origin_id, node_id, source, domain)
);
CREATE INDEX bindings_by_key ON bindings (node_id);
CREATE TABLE heads (
  origin_id   TEXT NOT NULL,
  slot        TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  root        BLOB NOT NULL,
  received_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY (origin_id, slot)
);
CREATE TABLE head_history (
  origin_id TEXT, seq INTEGER, root BLOB, created_at INTEGER,
  signed_by BLOB, sig BLOB, recorded_at INTEGER NOT NULL,
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
  unix_mode   INTEGER,
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
CREATE INDEX blob_providers_by_origin ON blob_providers (origin_id);
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

/// v14 — a DNS binding's identity includes the domain that published it.
///
/// The key was `(origin_id, node_id, source)`, and `origin_id` carries the
/// membership domain only for a *named* record: an `id=`-less one binds
/// `OriginId::Key(nk)`, which renders `key:<z32>` and names no domain at all.
/// So two configured membership domains publishing `v=sync1 nk=K` wrote the
/// same row, and `refresh_dns_bindings`' `DO UPDATE SET domain =
/// excluded.domain` made whichever refreshed last the owner of it.
///
/// Three things rested on that column being right. `hint_source_is_sole`
/// (`synch-engine`'s membership) asks whether every live binding for a key is
/// a DNS binding from *this* domain before it lets an answer supply dialing
/// data — the check the previous audit added precisely so a second domain
/// could not repoint a key the first one vouches for. With one row it is
/// trivially satisfied by whichever domain wrote last, so the defence was
/// absent exactly where it was aimed. `remove_domain` filters on the same
/// column and would miss a binding the other domain had relabelled, or delete
/// one this domain still vouches for. And a short TTL from one domain
/// overwrote a long expiry from the other.
///
/// Static bindings are untouched: they have no domain and one row per
/// `(origin, key)` is what they mean.
const V14_DNS_BINDINGS_ARE_PER_DOMAIN: &str = r#"
ALTER TABLE bindings RENAME TO bindings_v12;
CREATE TABLE bindings (
  origin_id    TEXT NOT NULL,
  node_id      BLOB NOT NULL,
  source       TEXT NOT NULL,            -- 'static' | 'dns'
  -- '' rather than NULL for a static binding, so the domain can be part of
  -- the key: SQLite admits no expression in a PRIMARY KEY, and one row per
  -- (origin, key) is exactly what a static binding means. The reader maps it
  -- back to `None`.
  domain       TEXT NOT NULL DEFAULT '',
  note         TEXT,
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,                  -- NULL for static
  PRIMARY KEY (origin_id, node_id, source, domain)
);
INSERT INTO bindings (origin_id, node_id, source, domain, note, added_at, expires_at)
  SELECT origin_id, node_id, source, coalesce(domain, ''), note, added_at, expires_at
  FROM bindings_v12;
DROP TABLE bindings_v12;
CREATE INDEX bindings_by_key ON bindings (node_id);
"#;
