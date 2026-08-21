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

use rusqlite::{OptionalExtension, Transaction};

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
    Migration::Sql(V15_IDENTITY_HISTORY),
    Migration::Rust {
        name: "the membership domain is the one that names this node",
        run: v16_one_membership_domain,
    },
    Migration::Sql(V17_DELEGATED_BINDINGS),
    Migration::Sql(V18_REDACTED_NODES),
    Migration::Sql(V19_S3_MULTIPART_UPLOADS),
    Migration::Sql(V20_SERVERLESS_FOUNDATION),
    Migration::Sql(V21_REPLICATION),
];

/// v20 — state shared by filesystem and serverless CAS backends.
///
/// `complete` describes the verified bytes available in the backend's local
/// working set. `durable` is deliberately separate: an S3 backend may have a
/// complete scratch copy which policy has not promoted, or a durable object
/// whose local cache is empty. Local-filesystem rows are backfilled because a
/// complete local object already passed the fsync-before-row invariant.
///
/// A nullable space path is the representation of a detached space. It has no
/// scanner or watcher root, but remains a space this origin can publish into.
const V20_SERVERLESS_FOUNDATION: &str = r#"
ALTER TABLE blobs ADD COLUMN durable INTEGER NOT NULL DEFAULT 0;
UPDATE blobs SET durable = complete;

ALTER TABLE spaces RENAME TO spaces_v19;
CREATE TABLE spaces (id TEXT PRIMARY KEY, local_path TEXT);
INSERT INTO spaces (id, local_path) SELECT id, local_path FROM spaces_v19;
DROP TABLE spaces_v19;
"#;

/// v21 — replication: pins gain a holder, spaces gain a policy (`docs/REPLICATION.md`).
///
/// `blobs.pinned` was a boolean with no provenance, which cannot answer the one
/// question that matters when something stops holding an object: *may these
/// bytes go now?* Once an operator's `pin add` and one or more replicated
/// spaces can hold the same root — and they can, because content is
/// deduplicated by hash across every space — a single flag has to be either set
/// or clear for all of them, and clearing it for one holder drops it for every
/// other. So the flag becomes a set of claims, and pinnedness becomes derived:
/// `EXISTS` a row, rather than a column that must be kept in agreement with one.
///
/// A row is live while it exists. `release_after` is when a claim is *due* to
/// go, and `expire_pins` is what actually removes it, so every predicate that
/// asks "is this pinned" stays free of the clock — including the one inside
/// `delete_blob_if_collectable`, which is re-read in the transaction that does
/// the delete and must not start depending on when it runs.
///
/// The backfill dates each recovered pin at its blob's `last_access` rather
/// than at migration time: it is the only timestamp the old row carries, and a
/// fabricated "now" would make every pre-existing pin look newer than the
/// content it holds.
///
/// The two indexes are the ones the queries actually use. `pins` is filtered by
/// `holder` on every status read and every release sweep, and its primary key
/// leads with `root`, so without `pins_by_holder` each of those scans the whole
/// table. `replica_want` is walked oldest-first per holder, which is what
/// `replica_want_by_holder` answers — an index on `last_attempt` alone would
/// look plausible and serve no statement, since the backoff is computed from
/// `attempts` and cannot seek on it.
///
/// `spaces` gains the replication policy in the same step, because v20 already
/// made a row mean "this node's participation in this space" — a nullable
/// `local_path` for detached spaces — and holding every version of a space is
/// the second kind of participation that row can describe. One per space, so a
/// column rather than a table.
const V21_REPLICATION: &str = r#"
CREATE TABLE pins (
  root          BLOB NOT NULL,
  holder        TEXT NOT NULL,             -- 'operator' | 'replica:<space>'
  created_at    INTEGER NOT NULL,
  release_after INTEGER,                   -- NULL = held; set = due to go then
  PRIMARY KEY (root, holder)
);
CREATE INDEX pins_pending_release ON pins (release_after) WHERE release_after IS NOT NULL;
CREATE INDEX pins_by_holder ON pins (holder);
INSERT INTO pins (root, holder, created_at, release_after)
  SELECT root, 'operator', last_access, NULL FROM blobs WHERE pinned != 0;
ALTER TABLE blobs DROP COLUMN pinned;

ALTER TABLE spaces ADD COLUMN replicate TEXT;      -- NULL | 'tree' | 'archive'
ALTER TABLE spaces ADD COLUMN grace     INTEGER;   -- seconds a released root is still held
ALTER TABLE spaces ADD COLUMN budget    INTEGER;   -- optional byte ceiling

CREATE TABLE replica_want (
  root         BLOB NOT NULL,
  holder       TEXT NOT NULL,              -- 'replica:<space>', as in pins.holder
  size         INTEGER NOT NULL,
  prev         BLOB,                       -- delta donor: the root this version replaced
  first_wanted INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_attempt INTEGER,
  last_error   TEXT,
  PRIMARY KEY (root, holder)
);
CREATE INDEX replica_want_by_holder ON replica_want (holder, first_wanted);
"#;

/// v19 — the multipart uploads an S3 client has open (§9.4).
///
/// A multipart upload is a conversation that outlives every request in it: the
/// client creates one, streams parts over minutes or days, and completes it —
/// possibly through a different gateway process, since the gateway holds no
/// state and any number of them may point at one daemon. The daemon is
/// therefore the only place the conversation can live.
///
/// `state` is a three-step latch rather than a boolean, because "being
/// completed" and "completed" are different answers to a retried request: a
/// client that never saw the response to its `CompleteMultipartUpload` retries
/// it, and a row that remembers the result replays it instead of reporting an
/// upload that no longer exists. It is `open` -> `completing` -> `completed`;
/// a validation failure returns it to `open`, because the client is entitled
/// to fix its part list and try again.
///
/// `principal` is the access key that opened the upload. An upload id is a
/// bearer token, and without an owner recorded beside it a listing that names
/// the id hands every client the ability to overwrite and complete every other
/// client's upload — publishing forged content under this node's signature.
///
/// `latched_ns` is when a completion took the latch. A completion whose caller
/// simply goes away — a client socket timing out mid-assembly is routine —
/// leaves the latch set with no error path to clear it, so the latch has to be
/// stealable on age rather than only by a daemon restart.
///
/// A part row is only ever written once its payload is durable on disk, so a
/// row implies bytes for as long as the upload is open. The reverse does not hold — a crash between the two
/// leaves a file no row names — which is the safe asymmetry: an unreferenced
/// file is collectable, an unbacked row is not.
const V19_S3_MULTIPART_UPLOADS: &str = r#"
CREATE TABLE s3_uploads (
  id          TEXT PRIMARY KEY,          -- the S3 UploadId: 32 random hex (§9.4)
  space       TEXT NOT NULL,
  path        TEXT NOT NULL,             -- already normalized at creation
  principal   TEXT,                      -- the access key that opened it; NULL when anonymous
  created_ns  INTEGER NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('open','completing','completed')),
  etag        BLOB,                      -- the object root, once completed
  size        INTEGER,                   -- the object size, once completed
  latched_ns  INTEGER,                   -- when a completion took the latch
  completed_ns INTEGER
);
CREATE INDEX s3_uploads_by_age ON s3_uploads (created_ns);
CREATE INDEX s3_uploads_by_target ON s3_uploads (space, path);

CREATE TABLE s3_upload_parts (
  upload      TEXT NOT NULL REFERENCES s3_uploads(id) ON DELETE CASCADE,
  number      INTEGER NOT NULL,          -- 1..=10000
  file        TEXT NOT NULL,             -- the payload's name within the upload directory
  size        INTEGER NOT NULL,
  root        BLOB NOT NULL,             -- the part's own blake3 root, which is its ETag
  created_ns  INTEGER NOT NULL,
  PRIMARY KEY (upload, number)
);
"#;

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
/// The origin does not restart at seq 1: `next_own_seq_in` takes `MAX(seq)` over a `UNION` of
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
CREATE TABLE identity_history (
  at          INTEGER NOT NULL,
  previous    TEXT,
  adopted     TEXT NOT NULL,
  node_id     BLOB NOT NULL,
  domain      TEXT NOT NULL
);
CREATE TABLE bindings (
  origin_id    TEXT NOT NULL,
  node_id      BLOB NOT NULL,
  source       TEXT NOT NULL,            -- 'static' | 'dns' | 'delegated'
  domain       TEXT NOT NULL DEFAULT '',
  issuer       TEXT NOT NULL DEFAULT '', -- delegated: the vouching origin
  spaces       TEXT,                     -- delegated: newline-separated space ids
  note         TEXT,
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,
  PRIMARY KEY (origin_id, node_id, source, domain, issuer)
);
CREATE INDEX bindings_by_key    ON bindings (node_id);
CREATE INDEX bindings_by_issuer ON bindings (issuer);
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
CREATE TABLE redacted_nodes (hash BLOB PRIMARY KEY);
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
  last_access INTEGER NOT NULL,
  durable     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE pins (                       -- who holds an object, and until when
  root          BLOB NOT NULL,
  holder        TEXT NOT NULL,            -- 'operator' | 'replica:<space>'
  created_at    INTEGER NOT NULL,
  release_after INTEGER,
  PRIMARY KEY (root, holder)
);
CREATE INDEX pins_pending_release ON pins (release_after) WHERE release_after IS NOT NULL;
CREATE INDEX pins_by_holder ON pins (holder);
CREATE TABLE replica_want (               -- content a replicated space wants (§3.3)
  root         BLOB NOT NULL,
  holder       TEXT NOT NULL,
  size         INTEGER NOT NULL,
  prev         BLOB,
  first_wanted INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_attempt INTEGER,
  last_error   TEXT,
  PRIMARY KEY (root, holder)
);
CREATE INDEX replica_want_by_holder ON replica_want (holder, first_wanted);
CREATE TABLE spaces        (id TEXT PRIMARY KEY, local_path TEXT,
                            replicate TEXT, grace INTEGER, budget INTEGER);
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

CREATE TABLE s3_uploads (
  id          TEXT PRIMARY KEY,
  space       TEXT NOT NULL,
  path        TEXT NOT NULL,
  principal   TEXT,
  created_ns  INTEGER NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('open','completing','completed')),
  etag        BLOB,
  size        INTEGER,
  latched_ns  INTEGER,
  completed_ns INTEGER
);
CREATE INDEX s3_uploads_by_age ON s3_uploads (created_ns);
CREATE INDEX s3_uploads_by_target ON s3_uploads (space, path);

CREATE TABLE s3_upload_parts (
  upload      TEXT NOT NULL REFERENCES s3_uploads(id) ON DELETE CASCADE,
  number      INTEGER NOT NULL,
  file        TEXT NOT NULL,
  size        INTEGER NOT NULL,
  root        BLOB NOT NULL,
  created_ns  INTEGER NOT NULL,
  PRIMARY KEY (upload, number)
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
/// data, so a second domain cannot repoint a key the first one vouches for.
/// With one row it is
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

/// v15 — every identity this node has adopted from its zone (§3.1).
///
/// A node takes its own `id=` from the membership zone, so a relabel there is
/// adopted unattended and drops the published views under the old name. The
/// trail of what was adopted, when, and from where is the only record that it
/// happened; `synch id` reads it. `previous` is NULL for a first name.
const V15_IDENTITY_HISTORY: &str = r#"
CREATE TABLE identity_history (
  at        INTEGER NOT NULL,
  previous  TEXT,                          -- NULL for a node's first name
  adopted   TEXT NOT NULL,
  node_id   BLOB NOT NULL,
  domain    TEXT NOT NULL
);
"#;

/// v16 — one membership domain, and it is the one that names this node (§3.1).
///
/// `membership_domains` held a newline-joined list of zones to resolve for
/// trusting *other* members, independent of what this node called itself. A
/// node now takes its own name from its zone, so the domain is the `@domain`
/// half of that name and there is exactly one.
///
/// Which one is not a choice this step has to make: a node that publishes as
/// `nas@cluster.example` names `cluster.example`, whatever else was configured
/// alongside it. A key-identified node names none, so every configured domain
/// was some other zone and none survives. The dns bindings of the zones being
/// left go with them — they were vouched for by an authority this node no
/// longer resolves, and nothing would otherwise remove them before their own
/// expiry.
fn v16_one_membership_domain(tx: &Transaction<'_>) -> Result<()> {
    one_membership_domain(tx)
}

/// The body of [`v16_one_membership_domain`], over any connection, so the test
/// can replay it on a database the chain has already migrated.
fn one_membership_domain(tx: &rusqlite::Connection) -> Result<()> {
    let self_origin: Option<String> = tx
        .query_row(
            "SELECT value FROM config WHERE key = 'self_origin_id'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    // The canonical rendering of a named origin is '<id>@<domain>'; a
    // key-identified one is 'key:<z-base-32>' and names no domain.
    let own_domain = self_origin
        .as_deref()
        .and_then(|origin| origin.rsplit_once('@'))
        .map(|(_, domain)| domain.to_string());

    tx.execute("DELETE FROM config WHERE key = 'membership_domains'", [])?;
    match own_domain {
        Some(domain) => {
            tx.execute(
                "INSERT INTO config (key, value) VALUES ('membership.domain', ?1)",
                rusqlite::params![domain],
            )?;
            tx.execute(
                "DELETE FROM bindings WHERE source = 'dns' AND domain <> ?1",
                rusqlite::params![domain],
            )?;
        }
        None => {
            tx.execute("DELETE FROM bindings WHERE source = 'dns'", [])?;
        }
    }
    Ok(())
}

/// v17 — delegated trust (§3.5).
///
/// A binding gains the origin that vouched for it and the spaces that vouching
/// covers, and `issuer` joins the primary key alongside the `domain` v14 put
/// there: two rooted origins may each delegate the same device key with
/// different space lists, and those are two independent statements. Keyed
/// without it, the second would silently overwrite the first, and removing one
/// issuer's delegation would take the other's with it — the same argument v14
/// makes for two membership domains publishing one key, applied to the axis
/// this migration adds. Both discriminators are `''` for the sources they do
/// not describe, for the reason v14 gives: SQLite admits no expression in a
/// primary key.
///
/// Delegated rows are a *materialized view* of `d:` trie leaves, exactly as
/// `entries` is of `f:` leaves — never independent state. Nothing backfills
/// them here because there is nothing to backfill: no database that has
/// reached this version has ever held one, and the rows appear as the
/// delegating origins' tries land.
const V17_DELEGATED_BINDINGS: &str = r#"
ALTER TABLE bindings RENAME TO bindings_v16;
CREATE TABLE bindings (
  origin_id    TEXT NOT NULL,
  node_id      BLOB NOT NULL,            -- bound device key (32 bytes)
  source       TEXT NOT NULL,            -- 'static' | 'dns' | 'delegated'
  domain       TEXT NOT NULL DEFAULT '', -- for dns source, '' otherwise
  issuer       TEXT NOT NULL DEFAULT '', -- for delegated source: the vouching origin
  spaces       TEXT,                     -- for delegated source: newline-separated space ids
  note         TEXT,
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,                  -- NULL for static
  PRIMARY KEY (origin_id, node_id, source, domain, issuer)
);
INSERT INTO bindings (origin_id, node_id, source, domain, issuer, spaces, note, added_at, expires_at)
  SELECT origin_id, node_id, source, domain, '', NULL, note, added_at, expires_at
  FROM bindings_v16;
DROP TABLE bindings_v16;
CREATE INDEX bindings_by_key    ON bindings (node_id);
CREATE INDEX bindings_by_issuer ON bindings (issuer);
"#;

/// v18 — the scope boundary a peer reported, remembered (§5.5).
///
/// A node reading under a scope has to tell "the peer does not have this" from
/// "the peer will not show me this", and has to keep telling them apart across
/// restarts: a completeness walk that re-read a refused position as merely
/// missing would never settle, and a fetch would retry until its head was
/// abandoned. The row is a fact about this node's own view, derived from what
/// peers answered.
const V18_REDACTED_NODES: &str = r#"
CREATE TABLE redacted_nodes (hash BLOB PRIMARY KEY);
"#;

#[cfg(test)]
mod identity_migration_tests {
    use crate::Store;

    /// The migration has already run on a fresh database, so the state it
    /// consumed is written back and replayed by hand.
    fn replay_v16(domains: &str, self_origin: &str) -> Store {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.set_config("membership_domains", domains).unwrap();
        store.set_config("self_origin_id", self_origin).unwrap();
        store.set_membership_domain(None).unwrap();
        store
            .transaction(|txn| super::one_membership_domain(txn.conn()))
            .unwrap();
        store
    }

    /// v16 keeps the domain the node's own name points at, whatever else was
    /// configured beside it, and drops the bindings of the zones being left.
    #[test]
    fn the_surviving_domain_is_the_one_that_names_this_node() {
        let store = replay_v16("other.example\ncluster.example", "nas@cluster.example");
        assert_eq!(
            store.membership_domain().unwrap().as_deref(),
            Some("cluster.example")
        );
        assert_eq!(store.config("membership_domains").unwrap(), None);
    }

    /// A key-identified node names no domain, so every configured one was some
    /// other zone and none survives.
    #[test]
    fn a_key_identified_node_keeps_no_domain() {
        let store = replay_v16(
            "cluster.example",
            "key:c1oa1qttuk8kzr8ntdcrnf9jhgh4bhtxa9x7wqxrn9nkr45yqnro",
        );
        assert_eq!(store.membership_domain().unwrap(), None);
    }
}
