//! The materialized views of trie leaves — `entries` and `blob_providers` —
//! plus the engine's own state tables (§10).
//!
//! The trie is authoritative; everything here is a derived cache that can
//! always be rebuilt from `trie_nodes`.

use rusqlite::{params, OptionalExtension};
use synch_core::{
    parse_blob_key, parse_file_key, AdState, BlobAd, EntryKind, FileEntry, Hash, OriginId,
    MAX_PROVIDER_ADS,
};
use synch_mpt::{ChangeKind, ResolvedChange, Trie};

use crate::{
    db::{hash_column, origin_column, Store, Txn},
    error::{Result, StoreError},
    unified::VersionPolicy,
};

/// One row of the `entries` view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRow {
    /// The origin asserting this entry.
    pub origin: OriginId,
    /// The space the entry lives in.
    pub space: String,
    /// The normalized path within the space.
    pub path: String,
    /// What the entry describes.
    pub kind: EntryKind,
    /// Content length in bytes.
    pub size: u64,
    /// The origin's observed mtime, in unix nanoseconds.
    pub mtime_ns: i64,
    /// The origin's advisory unix mode (§4.2), when it published one.
    ///
    /// `None` where the origin's platform has no mode to report, and on rows
    /// materialized before the column existed — a mirror reproduces what it is
    /// given and leaves the rest alone.
    pub unix_mode: Option<u32>,
    /// The object root, for files.
    pub content: Option<Hash>,
    /// The origin trie seq at which this version was published.
    pub seq: u64,
    /// The previous content root (§8 lineage).
    pub prev: Option<Hash>,
    /// The link target, for [`EntryKind::Symlink`].
    ///
    /// Part of the entry's version identity: a content-less kind is identified
    /// by `(kind, target)`, so two symlinks agree only when their targets match
    /// (§8).
    pub symlink_target: Option<String>,
}

/// The smallest string that sorts above every path carrying `prefix`.
///
/// Paths are compared as bytes, and `prefix` is a prefix of a string exactly
/// when the string sorts in `[prefix, successor)` — so this is what turns a
/// prefix listing into one range scan of the index. The successor is the
/// prefix with its last character raised by one, carrying into the character
/// before it where there is nothing above (`U+10FFFF`), and skipping the
/// surrogate block, which no `char` occupies. A prefix made only of `U+10FFFF`
/// has no successor and no upper bound: nothing sorts above it either.
pub(crate) fn prefix_upper_bound(prefix: &str) -> Option<String> {
    let mut head = prefix.to_string();
    while let Some(last) = head.pop() {
        let raised = match last as u32 + 1 {
            // The surrogate range is not a scalar value; the next character
            // above `U+D7FF` is `U+E000`.
            code @ 0xd800..=0xdfff => 0xe000.max(code),
            code => code,
        };
        if let Some(next) = char::from_u32(raised) {
            head.push(next);
            return Some(head);
        }
    }
    None
}

fn kind_to_int(kind: EntryKind) -> i64 {
    match kind {
        EntryKind::File => 0,
        EntryKind::Dir => 1,
        EntryKind::Symlink => 2,
        EntryKind::Tombstone => 3,
    }
}

fn kind_from_int(value: i64) -> Result<EntryKind> {
    Ok(match value {
        0 => EntryKind::File,
        1 => EntryKind::Dir,
        2 => EntryKind::Symlink,
        3 => EntryKind::Tombstone,
        other => return Err(StoreError::column("entries.kind", other.to_string())),
    })
}

/// A configured local space (§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceRow {
    /// The space id, used in `f:<space>/...` keys.
    pub id: String,
    /// The local directory being indexed.
    pub local_path: String,
}

/// A row of the scanner's change-detection state (§7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFile {
    /// The space.
    pub space: String,
    /// The normalized relative path.
    pub relpath: String,
    /// The observed size.
    pub size: u64,
    /// The observed mtime, in unix nanoseconds.
    pub mtime_ns: i64,
    /// A platform file identity (inode / file index), when available.
    pub file_id: Option<Vec<u8>>,
    /// The content root the last scan produced.
    pub content: Option<Hash>,
    /// When the file was last scanned.
    pub scanned_at: i64,
}

/// A configured read-only mirror of the unified tree (§7.2).
///
/// Keyed by the directory it writes into: a mirror materializes one space of
/// the unified tree under a version policy, rather than one origin's view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRow {
    /// The local directory the mirror materializes into.
    pub local_path: String,
    /// The space being mirrored.
    pub space: String,
    /// Which version of each path the mirror writes (§8).
    pub policy: VersionPolicy,
}

/// A peer we have seen, for ranking and `synch peers` (§6.4, §9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSeen {
    /// The peer's device key.
    pub node_id: synch_core::NodeId,
    /// The last address it was reached at, encoded.
    pub last_addr: Option<Vec<u8>>,
    /// When it was last seen.
    pub last_seen: i64,
    /// When a sync exchange last completed with it.
    pub last_sync: i64,
    /// An exponentially weighted moving average of round-trip latency.
    pub latency_ewma_us: i64,
}

impl Store {
    // ---- entries ----------------------------------------------------------

    /// Inserts or replaces one entry row.
    pub fn put_entry(
        &self,
        origin: &OriginId,
        space: &str,
        path: &str,
        entry: &FileEntry,
    ) -> Result<()> {
        let conn = self.conn();
        put_entry_in(&conn, origin, space, path, entry)
    }

    /// Deletes one entry row.
    pub fn delete_entry(&self, origin: &OriginId, space: &str, path: &str) -> Result<()> {
        self.conn().execute(
            "DELETE FROM entries WHERE origin_id = ?1 AND space = ?2 AND path = ?3",
            params![origin.canonical(), space, path],
        )?;
        Ok(())
    }

    /// Deletes every entry row for an origin, e.g. when trust is withdrawn.
    pub fn delete_origin_entries(&self, origin: &OriginId) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM entries WHERE origin_id = ?1",
            params![origin.canonical()],
        )?)
    }

    /// Reads one entry.
    pub fn entry(&self, origin: &OriginId, space: &str, path: &str) -> Result<Option<EntryRow>> {
        let rows = self.query_entries(
            "WHERE origin_id = ?1 AND space = ?2 AND path = ?3",
            params![origin.canonical(), space, path],
        )?;
        Ok(rows.into_iter().next())
    }

    /// Every origin's entry for one path — the §8 divergence view.
    pub fn entries_for_path(&self, space: &str, path: &str) -> Result<Vec<EntryRow>> {
        self.query_entries("WHERE space = ?1 AND path = ?2", params![space, path])
    }

    /// Lists entries under a path prefix, optionally restricted to one origin.
    pub fn list_entries(
        &self,
        origin: Option<&OriginId>,
        space: &str,
        prefix: &str,
        start_after: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<EntryRow>> {
        let mut filter = String::from("WHERE space = ?1 AND path >= ?2");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> =
            vec![Box::new(space.to_string()), Box::new(prefix.to_string())];
        // The prefix's byte successor bounds the scan from above, so the index
        // is walked over the prefix's range alone.
        if let Some(upper) = prefix_upper_bound(prefix) {
            args.push(Box::new(upper));
            filter.push_str(&format!(" AND path < ?{}", args.len()));
        }
        if let Some(origin) = origin {
            args.push(Box::new(origin.canonical()));
            filter.push_str(&format!(" AND origin_id = ?{}", args.len()));
        }
        if let Some(after) = start_after {
            args.push(Box::new(after.to_string()));
            filter.push_str(&format!(" AND path > ?{}", args.len()));
        }
        filter.push_str(" ORDER BY path, origin_id");
        if let Some(limit) = limit {
            filter.push_str(&format!(" LIMIT {limit}"));
        }
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        self.query_entries(&filter, refs.as_slice())
    }

    /// One origin's tombstones whose deletion time is older than `before`
    /// (§4.2).
    ///
    /// The deletion time is the tombstone's own `mtime_ns`, which is set to
    /// "now" when the scanner notices the path is gone. Always scoped to one
    /// origin: dropping a tombstone rewrites a trie, and a node only ever
    /// rewrites its own.
    pub fn expired_tombstones(&self, origin: &OriginId, before: i64) -> Result<Vec<EntryRow>> {
        self.query_entries(
            "WHERE origin_id = ?1 AND kind = ?2 AND mtime_ns < ?3 ORDER BY space, path",
            params![
                origin.canonical(),
                kind_to_int(EntryKind::Tombstone),
                before
            ],
        )
    }

    /// How many entries one origin has published for a space.
    ///
    /// The manifest carries this number and rebuilds it on every publish
    /// (§4.2), so it is asked for once per batch over the whole space: counting
    /// in SQL rather than materializing every row to call `.len()` on it keeps
    /// a 100 000-file index from rebuilding itself in memory each time.
    pub fn count_entries(&self, origin: &OriginId, space: &str) -> Result<u64> {
        let count: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM entries WHERE origin_id = ?1 AND space = ?2",
            params![origin.canonical(), space],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    /// Every origin that has materialized entries.
    ///
    /// Used by `synch doctor` to name origins whose data this node still holds
    /// after their binding went away — removal cuts off future participation
    /// and never cascades a deletion through everyone's tries (§12).
    pub fn entry_origins(&self) -> Result<Vec<OriginId>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT DISTINCT origin_id FROM entries ORDER BY origin_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(origin_column(row?, "entries.origin_id")?);
        }
        Ok(out)
    }

    /// Every space id that any origin has published entries for.
    pub fn known_spaces(&self) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT DISTINCT space FROM entries ORDER BY space")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn query_entries(
        &self,
        filter: &str,
        args: impl rusqlite::Params,
    ) -> Result<Vec<EntryRow>> {
        let conn = self.conn();
        let sql = format!(
            "SELECT origin_id, space, path, kind, size, mtime_ns, unix_mode, content, seq, prev,
                    symlink_target
             FROM entries {filter}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(args, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
                row.get::<_, Option<String>>(10)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                origin,
                space,
                path,
                kind,
                size,
                mtime_ns,
                unix_mode,
                content,
                seq,
                prev,
                symlink_target,
            ) = row?;
            out.push(EntryRow {
                origin: origin_column(origin, "entries.origin_id")?,
                space,
                path,
                kind: kind_from_int(kind)?,
                size: size as u64,
                mtime_ns,
                unix_mode: unix_mode.map(|m| m as u32),
                content: content
                    .map(|b| hash_column(b, "entries.content"))
                    .transpose()?,
                seq: seq as u64,
                prev: prev.map(|b| hash_column(b, "entries.prev")).transpose()?,
                symlink_target,
            });
        }
        Ok(out)
    }

    // ---- blob providers ---------------------------------------------------

    /// Inserts or replaces one provider row.
    pub fn put_provider(&self, root: &Hash, origin: &OriginId, ad: &BlobAd) -> Result<()> {
        let conn = self.conn();
        put_provider_in(&conn, root, origin, ad)
    }

    /// Deletes one provider row.
    pub fn delete_provider(&self, root: &Hash, origin: &OriginId) -> Result<()> {
        self.conn().execute(
            "DELETE FROM blob_providers WHERE object_root = ?1 AND origin_id = ?2",
            params![root.as_bytes().to_vec(), origin.canonical()],
        )?;
        Ok(())
    }

    /// Every object root one origin currently advertises a `b:` record for.
    ///
    /// Read from the materialized view rather than the trie because that is
    /// what every other reader uses, and for our own origin the two agree by
    /// construction.
    pub fn provider_roots_for_origin(&self, origin: &OriginId) -> Result<Vec<Hash>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT object_root FROM blob_providers WHERE origin_id = ?1 ORDER BY object_root",
        )?;
        let rows = stmt.query_map(params![origin.canonical()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(hash_column(row?, "blob_providers.object_root")?);
        }
        Ok(out)
    }

    /// Deletes every provider row for an origin.
    pub fn delete_origin_providers(&self, origin: &OriginId) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM blob_providers WHERE origin_id = ?1",
            params![origin.canonical()],
        )?)
    }

    /// "Who can serve this object?" — answered locally, with no round trip
    /// (§6.3).
    ///
    /// At most [`MAX_PROVIDER_ADS`] rows, bounded in SQL rather than by the
    /// caller. `FindProviders` answers out of this and truncated afterwards,
    /// which bounds what goes on the wire and nothing else: the rows were all
    /// read, and each one's spans decoded, before the truncation could apply
    /// (§12). Membership is a hundred origins, so the limit cannot bite an
    /// honest cluster, and the ordering it cuts against is deterministic.
    ///
    /// The connection guard is released before any of it is decoded. It is the
    /// single global write mutex, and holding it across a per-row postcard
    /// decode let one small request — a `FindProviders` for a root some origin
    /// published a pathological `b:` record for — stall every other writer in
    /// the process for as long as the decode took.
    pub fn providers(&self, root: &Hash) -> Result<Vec<(OriginId, BlobAd)>> {
        let encoded = {
            let conn = self.conn();
            let mut stmt = conn.prepare(
                "SELECT origin_id, size, complete, spans FROM blob_providers
                 WHERE object_root = ?1 ORDER BY complete DESC, origin_id
                 LIMIT ?2",
            )?;
            let rows = stmt.query_map(
                params![root.as_bytes().to_vec(), MAX_PROVIDER_ADS as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut out = Vec::new();
        for (origin, size, complete, spans) in encoded {
            // `complete` is the legacy duplicate of "the spans cover the whole
            // object" and is still written for older readers; the spans are
            // authoritative. A row written as complete before v11 carries no
            // spans, so it is reconstituted from the size.
            // Decoded as an [`AdState`], whose own `Deserialize` stops at
            // `MAX_AD_SPANS` — the column is that struct's one field, so the
            // bytes are the same either way and the cap comes for free.
            // Reading it as a bare `Vec` is what would let a row hold millions
            // of spans.
            let state: AdState = match spans {
                Some(bytes) => {
                    postcard::from_bytes(&bytes).map_err(|e| StoreError::Decode(e.to_string()))?
                }
                None if complete != 0 && size > 0 => AdState {
                    spans: vec![(0, size as u64)],
                },
                None => AdState { spans: Vec::new() },
            };
            out.push((
                origin_column(origin, "blob_providers.origin_id")?,
                BlobAd {
                    v: synch_core::RECORD_VERSION,
                    size: size as u64,
                    state,
                },
            ));
        }
        Ok(out)
    }

    /// The providers whose advertised spans intersect a byte range (§6.3).
    pub fn providers_for_range(
        &self,
        root: &Hash,
        start: u64,
        end: u64,
    ) -> Result<Vec<(OriginId, BlobAd)>> {
        Ok(self
            .providers(root)?
            .into_iter()
            .filter(|(_, ad)| ad.intersects(start, end))
            .collect())
    }

    // ---- materialization from a trie diff ---------------------------------

    /// Rewrites `entries` and `blob_providers` for one origin from the diff
    /// between two roots (§5.2).
    ///
    /// Only touched subtrees are visited, so the cost is proportional to the
    /// change rather than to the size of the trie. Runs in one transaction so
    /// the derived views never show a half-applied head.
    pub fn materialize_diff(
        &self,
        origin: &OriginId,
        old_root: Hash,
        new_root: Hash,
    ) -> Result<usize> {
        let changes: Vec<ResolvedChange> = Trie::new(self).diff_resolved(old_root, new_root)?;
        let count = changes.len();
        self.with_tx(|tx| {
            for change in &changes {
                apply_change(tx, origin, change)?;
            }
            Ok(())
        })?;
        Ok(count)
    }

    /// Rebuilds `entries` and `blob_providers` for one origin from scratch
    /// (`synch doctor --rebuild`).
    pub fn rematerialize(&self, origin: &OriginId, root: Hash) -> Result<usize> {
        // One transaction, because the intermediate state is destructive. The
        // Letting the two deletes autocommit and computing the diff outside
        // any transaction leaves `entries` observably empty for the whole
        // rebuild — and a mirror pass reading `unified_listing` in that window
        // builds an empty `known` set and its sweep unlinks the user's files.
        self.transaction(|txn| {
            txn.delete_origin_entries(origin)?;
            txn.delete_origin_providers(origin)?;
            txn.materialize_diff(origin, Hash::EMPTY, root)
        })
    }

    // ---- spaces -----------------------------------------------------------

    /// Registers a local space.
    pub fn put_space(&self, id: &str, local_path: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO spaces (id, local_path) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET local_path = excluded.local_path",
            params![id, local_path],
        )?;
        Ok(())
    }

    /// Removes a local space.
    pub fn remove_space(&self, id: &str) -> Result<bool> {
        let n = self
            .conn()
            .execute("DELETE FROM spaces WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    /// Every configured local space.
    pub fn spaces(&self) -> Result<Vec<SpaceRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id, local_path FROM spaces ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok(SpaceRow {
                id: row.get(0)?,
                local_path: row.get(1)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// One configured local space.
    pub fn space(&self, id: &str) -> Result<Option<SpaceRow>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT id, local_path FROM spaces WHERE id = ?1",
                params![id],
                |row| {
                    Ok(SpaceRow {
                        id: row.get(0)?,
                        local_path: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    // ---- scanner state ----------------------------------------------------

    /// Records a scanned file's identity for change detection (§7.1).
    pub fn put_local_file(&self, file: &LocalFile) -> Result<()> {
        self.conn().execute(
            "INSERT INTO local_files (space, relpath, size, mtime_ns, file_id, content, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(space, relpath) DO UPDATE SET
               size = excluded.size, mtime_ns = excluded.mtime_ns, file_id = excluded.file_id,
               content = excluded.content, scanned_at = excluded.scanned_at",
            params![
                file.space,
                file.relpath,
                file.size as i64,
                file.mtime_ns,
                file.file_id,
                file.content.map(|h| h.as_bytes().to_vec()),
                file.scanned_at,
            ],
        )?;
        Ok(())
    }

    /// Reads a scanned file's recorded identity.
    pub fn local_file(&self, space: &str, relpath: &str) -> Result<Option<LocalFile>> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT space, relpath, size, mtime_ns, file_id, content, scanned_at
                 FROM local_files WHERE space = ?1 AND relpath = ?2",
                params![space, relpath],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((space, relpath, size, mtime_ns, file_id, content, scanned_at)) = row else {
            return Ok(None);
        };
        Ok(Some(LocalFile {
            space,
            relpath,
            size: size as u64,
            mtime_ns,
            file_id,
            content: content
                .map(|b| hash_column(b, "local_files.content"))
                .transpose()?,
            scanned_at,
        }))
    }

    /// The paths whose current entries name this content root, as
    /// `space/path` strings.
    ///
    /// What `pin ls` prints next to a bare hash: which files, if any, the
    /// pinned object currently is. A pin can outlive every entry naming it —
    /// that is its purpose — so an empty answer is meaningful, not an error.
    pub fn paths_naming(&self, root: &Hash) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT space, path FROM entries WHERE content = ?1 ORDER BY space, path",
        )?;
        let rows = stmt.query_map(params![root.as_bytes().to_vec()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (space, path) = row?;
            out.push(format!("{space}/{path}"));
        }
        Ok(out)
    }

    /// Every row the scanner has recorded for a space.
    ///
    /// The full rows, not just the paths: startup reconciliation compares the
    /// recorded content hash against what the node's own trie actually
    /// publishes (§7.1).
    pub fn local_file_rows(&self, space: &str) -> Result<Vec<LocalFile>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT space, relpath, size, mtime_ns, file_id, content, scanned_at
             FROM local_files WHERE space = ?1 ORDER BY relpath",
        )?;
        let rows = stmt.query_map(params![space], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (space, relpath, size, mtime_ns, file_id, content, scanned_at) = row?;
            out.push(LocalFile {
                space,
                relpath,
                size: size as u64,
                mtime_ns,
                file_id,
                content: content
                    .map(|b| hash_column(b, "local_files.content"))
                    .transpose()?,
                scanned_at,
            });
        }
        Ok(out)
    }

    /// Every path the scanner has recorded for a space.
    pub fn local_files(&self, space: &str) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT relpath FROM local_files WHERE space = ?1 ORDER BY relpath")?;
        let rows = stmt.query_map(params![space], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Forgets a scanned file.
    pub fn remove_local_file(&self, space: &str, relpath: &str) -> Result<()> {
        self.conn().execute(
            "DELETE FROM local_files WHERE space = ?1 AND relpath = ?2",
            params![space, relpath],
        )?;
        Ok(())
    }

    // ---- mirrors ----------------------------------------------------------

    /// Registers (or re-points) the mirror at a local directory.
    pub fn put_mirror(&self, local_path: &str, space: &str, policy: &VersionPolicy) -> Result<()> {
        self.conn().execute(
            "INSERT INTO mirrors (local_path, space, policy) VALUES (?1, ?2, ?3)
             ON CONFLICT(local_path) DO UPDATE SET
               space = excluded.space, policy = excluded.policy",
            params![local_path, space, policy.render()],
        )?;
        Ok(())
    }

    /// Removes the mirror at a local directory.
    pub fn remove_mirror(&self, local_path: &str) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM mirrors WHERE local_path = ?1",
            params![local_path],
        )?;
        Ok(n > 0)
    }

    /// The mirror configured for a local directory, if any.
    pub fn mirror(&self, local_path: &str) -> Result<Option<MirrorRow>> {
        Ok(self
            .mirrors()?
            .into_iter()
            .find(|m| m.local_path == local_path))
    }

    /// Every configured mirror.
    pub fn mirrors(&self) -> Result<Vec<MirrorRow>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT local_path, space, policy FROM mirrors ORDER BY local_path")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (local_path, space, policy) = row?;
            out.push(MirrorRow {
                local_path,
                space,
                policy: policy.parse()?,
            });
        }
        Ok(out)
    }

    // ---- peers ------------------------------------------------------------

    /// Records that a peer was seen.
    pub fn record_peer_seen(
        &self,
        node_id: &synch_core::NodeId,
        addr: Option<&[u8]>,
        now: i64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO peers_seen (node_id, last_addr, last_seen, last_sync, latency_ewma_us)
             VALUES (?1, ?2, ?3, 0, 0)
             ON CONFLICT(node_id) DO UPDATE SET
               last_addr = COALESCE(excluded.last_addr, peers_seen.last_addr),
               last_seen = excluded.last_seen",
            params![node_id.as_bytes().to_vec(), addr, now],
        )?;
        Ok(())
    }

    /// Records a completed sync exchange and folds a latency sample into the
    /// peer's EWMA, which is what the fetcher ranks providers by (§6.4).
    pub fn record_peer_sync(
        &self,
        node_id: &synch_core::NodeId,
        now: i64,
        latency_us: i64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO peers_seen (node_id, last_addr, last_seen, last_sync, latency_ewma_us)
             VALUES (?1, NULL, ?2, ?2, ?3)
             ON CONFLICT(node_id) DO UPDATE SET
               last_seen = excluded.last_seen,
               last_sync = excluded.last_sync,
               latency_ewma_us = CASE
                 WHEN peers_seen.latency_ewma_us = 0 THEN excluded.latency_ewma_us
                 ELSE (peers_seen.latency_ewma_us * 3 + excluded.latency_ewma_us) / 4
               END",
            params![node_id.as_bytes().to_vec(), now, latency_us],
        )?;
        Ok(())
    }

    /// Records that a peer could not be reached, penalizing its latency EWMA.
    ///
    /// Ranking (§6.4) has to be able to move in both directions. With latency
    /// recorded only on success, a peer that was once fast and has since gone
    /// dark keeps its low EWMA and is therefore chosen first on every fetch
    /// from then on, with nothing in the system able to demote it — the fetch
    /// wastes a slot on it every time.
    ///
    /// `last_sync` is deliberately not touched: nothing synced. Only the EWMA
    /// moves, and it moves the same way a slow success would, so a peer that
    /// recovers earns its rank back over the following exchanges rather than
    /// being blacklisted.
    pub fn record_peer_failure(
        &self,
        node_id: &synch_core::NodeId,
        now: i64,
        penalty_us: i64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO peers_seen (node_id, last_addr, last_seen, last_sync, latency_ewma_us)
             VALUES (?1, NULL, ?2, 0, ?3)
             ON CONFLICT(node_id) DO UPDATE SET
               latency_ewma_us = CASE
                 WHEN peers_seen.latency_ewma_us = 0 THEN excluded.latency_ewma_us
                 ELSE (peers_seen.latency_ewma_us * 3 + excluded.latency_ewma_us) / 4
               END",
            params![node_id.as_bytes().to_vec(), now, penalty_us],
        )?;
        Ok(())
    }

    /// Every peer we have seen, most recently seen first.
    pub fn peers_seen(&self) -> Result<Vec<PeerSeen>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT node_id, last_addr, last_seen, last_sync, latency_ewma_us
             FROM peers_seen ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (node_id, last_addr, last_seen, last_sync, latency_ewma_us) = row?;
            out.push(PeerSeen {
                node_id: crate::db::key_column(node_id, "peers_seen.node_id")?,
                last_addr,
                last_seen,
                last_sync,
                latency_ewma_us,
            });
        }
        Ok(out)
    }
}

impl Txn<'_> {
    /// Rewrites `entries` and `blob_providers` for one origin from the diff
    /// between two roots, inside the transaction (§5.2, §10).
    ///
    /// This is the half of a head flip that the derived views see, and it
    /// commits with the flip: a crash can never leave `entries` — what the
    /// unified tree, mirrors, and `synch-s3` serve from — missing a promoted
    /// head's delta.
    pub fn materialize_diff(
        &self,
        origin: &OriginId,
        old_root: Hash,
        new_root: Hash,
    ) -> Result<usize> {
        let changes: Vec<ResolvedChange> = Trie::new(self).diff_resolved(old_root, new_root)?;
        for change in &changes {
            apply_change(self.conn(), origin, change)?;
        }
        Ok(changes.len())
    }

    /// Deletes every entry row for an origin, inside the transaction.
    pub fn delete_origin_entries(&self, origin: &OriginId) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM entries WHERE origin_id = ?1",
            params![origin.canonical()],
        )?)
    }

    /// Deletes every provider row for an origin, inside the transaction.
    pub fn delete_origin_providers(&self, origin: &OriginId) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM blob_providers WHERE origin_id = ?1",
            params![origin.canonical()],
        )?)
    }
}

fn apply_change(
    tx: &rusqlite::Connection,
    origin: &OriginId,
    change: &ResolvedChange,
) -> Result<()> {
    let key = &change.key;
    if key.first() == Some(&synch_core::record::PREFIX_FILE) {
        let Ok((space, path)) = parse_file_key(key) else {
            // A key we cannot parse is a peer's problem, not ours: skip it
            // rather than refusing to materialize the rest of their trie.
            tracing::debug!(origin = %origin, "skipping unparseable f: key");
            return Ok(());
        };
        match change.kind() {
            ChangeKind::Deleted => {
                tx.execute(
                    "DELETE FROM entries WHERE origin_id = ?1 AND space = ?2 AND path = ?3",
                    params![origin.canonical(), space, path],
                )?;
            }
            _ => {
                let bytes = change.new.as_ref().expect("non-delete change has a value");
                let entry: FileEntry = postcard::from_bytes(bytes)
                    .map_err(|e| StoreError::Decode(format!("f: record: {e}")))?;
                put_entry_in(tx, origin, &space, &path, &entry)?;
            }
        }
    } else if key.first() == Some(&synch_core::record::PREFIX_BLOB) {
        let Ok(root) = parse_blob_key(key) else {
            tracing::debug!(origin = %origin, "skipping unparseable b: key");
            return Ok(());
        };
        match change.kind() {
            ChangeKind::Deleted => {
                tx.execute(
                    "DELETE FROM blob_providers WHERE object_root = ?1 AND origin_id = ?2",
                    params![root.as_bytes().to_vec(), origin.canonical()],
                )?;
            }
            _ => {
                let bytes = change.new.as_ref().expect("non-delete change has a value");
                let ad: BlobAd = postcard::from_bytes(bytes)
                    .map_err(|e| StoreError::Decode(format!("b: record: {e}")))?;
                put_provider_in(tx, &root, origin, &ad)?;
            }
        }
    }
    // `m:` records are read straight from the trie; they have no derived view.
    Ok(())
}

/// Materializes one trie leaf into `entries`.
///
/// The row is the leaf, verbatim. Every column here is what the origin
/// published and what every other node holding this trie also materializes:
/// two nodes with the same trie must produce the same `entries`, and
/// `doctor --rebuild` must produce what the original materialization did, or
/// version selection stops being a function of the data (§8). A peer's
/// `mtime_ns` is judged where it is *used* — [`VersionSet::select`] orders
/// under the reader's own clock — not where it is stored.
fn put_entry_in(
    conn: &rusqlite::Connection,
    origin: &OriginId,
    space: &str,
    path: &str,
    entry: &FileEntry,
) -> Result<()> {
    conn.execute(
        "INSERT INTO entries (origin_id, space, path, kind, size, mtime_ns, unix_mode, content,
                              seq, prev, symlink_target)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(origin_id, space, path) DO UPDATE SET
           kind = excluded.kind, size = excluded.size, mtime_ns = excluded.mtime_ns,
           unix_mode = excluded.unix_mode, content = excluded.content, seq = excluded.seq,
           prev = excluded.prev, symlink_target = excluded.symlink_target",
        params![
            origin.canonical(),
            space,
            path,
            kind_to_int(entry.kind),
            entry.size as i64,
            entry.mtime_ns,
            entry.unix_mode.map(|m| m as i64),
            entry.content.map(|h| h.as_bytes().to_vec()),
            entry.seq as i64,
            entry.prev.map(|h| h.as_bytes().to_vec()),
            entry.symlink_target.as_deref(),
        ],
    )?;
    Ok(())
}

fn put_provider_in(
    conn: &rusqlite::Connection,
    root: &Hash,
    origin: &OriginId,
    ad: &BlobAd,
) -> Result<()> {
    // The spans are the record; `complete` is derived from them on the way in
    // rather than tracked beside them, so the two cannot disagree.
    let complete = i64::from(ad.is_complete());
    let spans =
        Some(postcard::to_stdvec(&ad.state.spans).map_err(|e| StoreError::Decode(e.to_string()))?);
    conn.execute(
        "INSERT INTO blob_providers (object_root, origin_id, size, complete, spans)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(object_root, origin_id) DO UPDATE SET
           size = excluded.size, complete = excluded.complete, spans = excluded.spans",
        params![
            root.as_bytes().to_vec(),
            origin.canonical(),
            ad.size as i64,
            complete,
            spans
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use synch_core::{blob_key, file_key, AD_SPAN_GRANULARITY};

    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).unwrap();
        (dir, s)
    }

    fn origin(name: &str) -> OriginId {
        OriginId::named(name, "x.example").unwrap()
    }

    #[test]
    fn entries_round_trip() {
        let (_d, store) = store();
        let o = origin("nas");
        let e = FileEntry::file(10, 5, Hash::new(b"c"), 3);
        store.put_entry(&o, "media", "a/b.txt", &e).unwrap();

        let row = store.entry(&o, "media", "a/b.txt").unwrap().unwrap();
        assert_eq!(row.size, 10);
        assert_eq!(row.content, Some(Hash::new(b"c")));
        assert_eq!(row.kind, EntryKind::File);
        assert_eq!(row.seq, 3);

        store.delete_entry(&o, "media", "a/b.txt").unwrap();
        assert!(store.entry(&o, "media", "a/b.txt").unwrap().is_none());
    }

    /// The advisory mode is metadata a mirror materializes (§7.2), so it has to
    /// survive the trip through this view rather than being dropped at it.
    #[test]
    fn entries_carry_the_advisory_unix_mode() {
        let (_d, store) = store();
        let o = origin("nas");
        let mut e = FileEntry::file(10, 5, Hash::new(b"c"), 3);
        e.unix_mode = Some(0o100_640);
        store.put_entry(&o, "media", "a.txt", &e).unwrap();
        assert_eq!(
            store
                .entry(&o, "media", "a.txt")
                .unwrap()
                .unwrap()
                .unix_mode,
            Some(0o100_640)
        );

        // An origin with no mode to report publishes none, and that is not the
        // same as reporting zero.
        store
            .put_entry(
                &o,
                "media",
                "b.txt",
                &FileEntry::file(1, 0, Hash::new(b"d"), 1),
            )
            .unwrap();
        assert_eq!(
            store
                .entry(&o, "media", "b.txt")
                .unwrap()
                .unwrap()
                .unix_mode,
            None
        );

        // And it survives the path every peer's entry actually takes: decoded
        // from a trie leaf into the view.
        let trie = Trie::new(&store);
        let root = trie
            .insert(
                Hash::EMPTY,
                &file_key("media", "c.txt").unwrap(),
                &postcard::to_stdvec(&e).unwrap(),
            )
            .unwrap();
        let peer = origin("laptop");
        store.materialize_diff(&peer, Hash::EMPTY, root).unwrap();
        assert_eq!(
            store
                .entry(&peer, "media", "c.txt")
                .unwrap()
                .unwrap()
                .unix_mode,
            Some(0o100_640)
        );
    }

    #[test]
    fn counting_entries_is_scoped_to_one_origin_and_space() {
        let (_d, store) = store();
        let nas = origin("nas");
        let laptop = origin("laptop");
        let e = FileEntry::file(1, 0, Hash::new(b"c"), 1);
        store.put_entry(&nas, "media", "a", &e).unwrap();
        store.put_entry(&nas, "media", "b", &e).unwrap();
        store.put_entry(&nas, "docs", "c", &e).unwrap();
        store.put_entry(&laptop, "media", "d", &e).unwrap();

        assert_eq!(store.count_entries(&nas, "media").unwrap(), 2);
        assert_eq!(store.count_entries(&nas, "docs").unwrap(), 1);
        assert_eq!(store.count_entries(&laptop, "media").unwrap(), 1);
        assert_eq!(store.count_entries(&nas, "nothing").unwrap(), 0);
        // And it agrees with the listing it stands in for.
        assert_eq!(
            store.count_entries(&nas, "media").unwrap() as usize,
            store
                .list_entries(Some(&nas), "media", "", None, None)
                .unwrap()
                .len()
        );
    }

    #[test]
    fn divergence_across_origins_is_visible() {
        let (_d, store) = store();
        let nas = origin("nas");
        let laptop = origin("laptop");
        store
            .put_entry(
                &nas,
                "media",
                "f",
                &FileEntry::file(1, 0, Hash::new(b"v2"), 2),
            )
            .unwrap();
        store
            .put_entry(
                &laptop,
                "media",
                "f",
                &FileEntry::file(1, 0, Hash::new(b"v1"), 1),
            )
            .unwrap();

        let rows = store.entries_for_path("media", "f").unwrap();
        assert_eq!(rows.len(), 2);
        let roots: Vec<_> = rows.iter().map(|r| r.content).collect();
        assert!(roots.contains(&Some(Hash::new(b"v1"))));
        assert!(roots.contains(&Some(Hash::new(b"v2"))));
    }

    #[test]
    fn listing_by_prefix_and_origin() {
        let (_d, store) = store();
        let nas = origin("nas");
        let laptop = origin("laptop");
        for path in ["a/1", "a/2", "a/sub/3", "b/1"] {
            store
                .put_entry(&nas, "s", path, &FileEntry::file(1, 0, Hash::new(b"x"), 1))
                .unwrap();
        }
        store
            .put_entry(
                &laptop,
                "s",
                "a/1",
                &FileEntry::file(1, 0, Hash::new(b"y"), 1),
            )
            .unwrap();

        let all = store.list_entries(None, "s", "a/", None, None).unwrap();
        assert_eq!(all.len(), 4);
        let mine = store
            .list_entries(Some(&nas), "s", "a/", None, None)
            .unwrap();
        assert_eq!(mine.len(), 3);
        let page = store
            .list_entries(Some(&nas), "s", "a/", None, Some(2))
            .unwrap();
        assert_eq!(page.len(), 2);
        let rest = store
            .list_entries(Some(&nas), "s", "a/", Some("a/2"), None)
            .unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].path, "a/sub/3");
        assert_eq!(store.known_spaces().unwrap(), vec!["s".to_string()]);
    }

    #[test]
    fn providers_round_trip_and_filter_by_range() {
        let (_d, store) = store();
        let g = AD_SPAN_GRANULARITY;
        let root = Hash::new(b"obj");
        store
            .put_provider(&root, &origin("nas"), &BlobAd::complete(10 * g))
            .unwrap();
        store
            .put_provider(&root, &origin("laptop"), &BlobAd::partial(10 * g, [(0, g)]))
            .unwrap();

        let all = store.providers(&root).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all[0].1.is_complete());

        let head = store.providers_for_range(&root, 0, 100).unwrap();
        assert_eq!(head.len(), 2);
        let tail = store.providers_for_range(&root, 5 * g, 6 * g).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].0, origin("nas"));

        store.delete_provider(&root, &origin("nas")).unwrap();
        assert_eq!(store.providers(&root).unwrap().len(), 1);
    }

    /// The provider read is bounded by the query, not by the caller.
    ///
    /// `FindProviders` truncates its answer to `MAX_PROVIDER_ADS`, but that
    /// happens after every row has been read and every row's spans decoded —
    /// under the single global connection mutex. The bound belongs in the SQL,
    /// where it costs the reader nothing to enforce (§12).
    #[test]
    fn a_provider_read_stops_at_the_advertised_bound() {
        let (_d, store) = store();
        let root = Hash::new(b"a popular object");
        for i in 0..MAX_PROVIDER_ADS + 64 {
            store
                .put_provider(
                    &root,
                    &origin(&format!("holder{i:04}")),
                    &BlobAd::complete(10),
                )
                .unwrap();
        }
        assert_eq!(store.providers(&root).unwrap().len(), MAX_PROVIDER_ADS);
        assert_eq!(
            store.providers_for_range(&root, 0, 10).unwrap().len(),
            MAX_PROVIDER_ADS
        );
    }

    /// A `b:` record naming a million spans lands as a bounded row.
    ///
    /// The record is a trie value, so it is bounded only by `MAX_FRAME_LEN` —
    /// and materialization is where an origin's published bytes become this
    /// node's memory. The cap is applied by the ad's own decode, so the row it
    /// writes is already bounded and every later read of it is too.
    #[test]
    fn a_pathological_ad_materializes_to_a_bounded_row() {
        let (_d, store) = store();
        let o = origin("nas");
        let trie = Trie::new(&store);
        let g = AD_SPAN_GRANULARITY;
        let root = Hash::new(b"an object");
        let spans: Vec<(u64, u64)> = (0..(synch_core::MAX_AD_SPANS as u64 + 500))
            .map(|i| (i * 2 * g, i * 2 * g + g))
            .collect();
        let ad = BlobAd {
            v: synch_core::RECORD_VERSION,
            size: u64::MAX,
            state: AdState { spans },
        };
        let after = trie
            .insert(
                Hash::EMPTY,
                &synch_core::blob_key(&root),
                &postcard::to_stdvec(&ad).unwrap(),
            )
            .unwrap();
        store.materialize_diff(&o, Hash::EMPTY, after).unwrap();

        let providers = store.providers(&root).unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].1.state.spans.len(), synch_core::MAX_AD_SPANS);
    }

    #[test]
    fn materializes_from_a_trie_diff() {
        let (_d, store) = store();
        let o = origin("nas");
        let trie = Trie::new(&store);

        let entry = FileEntry::file(42, 7, Hash::new(b"content"), 1);
        let ad = BlobAd::complete(42);
        let mut root = Hash::EMPTY;
        root = trie
            .insert(
                root,
                &file_key("media", "clip.mp4").unwrap(),
                &postcard::to_stdvec(&entry).unwrap(),
            )
            .unwrap();
        root = trie
            .insert(
                root,
                &blob_key(&Hash::new(b"content")),
                &postcard::to_stdvec(&ad).unwrap(),
            )
            .unwrap();

        assert_eq!(store.materialize_diff(&o, Hash::EMPTY, root).unwrap(), 2);
        let row = store.entry(&o, "media", "clip.mp4").unwrap().unwrap();
        assert_eq!(row.size, 42);
        assert_eq!(store.providers(&Hash::new(b"content")).unwrap().len(), 1);

        // Deleting the file from the trie must delete the derived row.
        let root2 = trie
            .remove(root, &file_key("media", "clip.mp4").unwrap())
            .unwrap();
        assert_eq!(store.materialize_diff(&o, root, root2).unwrap(), 1);
        assert!(store.entry(&o, "media", "clip.mp4").unwrap().is_none());
        // The blob ad is untouched by the file deletion.
        assert_eq!(store.providers(&Hash::new(b"content")).unwrap().len(), 1);
    }

    #[test]
    fn rematerialize_rebuilds_from_the_trie() {
        let (_d, store) = store();
        let o = origin("nas");
        let trie = Trie::new(&store);
        let mut root = Hash::EMPTY;
        for i in 0..5u8 {
            let entry = FileEntry::file(i as u64, 0, Hash::new(&[i]), 1);
            root = trie
                .insert(
                    root,
                    &file_key("s", &format!("f{i}")).unwrap(),
                    &postcard::to_stdvec(&entry).unwrap(),
                )
                .unwrap();
        }
        store.materialize_diff(&o, Hash::EMPTY, root).unwrap();
        assert_eq!(
            store
                .list_entries(Some(&o), "s", "", None, None)
                .unwrap()
                .len(),
            5
        );

        // Corrupt the derived cache, then rebuild it from the authoritative trie.
        store.delete_origin_entries(&o).unwrap();
        assert!(store
            .list_entries(Some(&o), "s", "", None, None)
            .unwrap()
            .is_empty());
        store.rematerialize(&o, root).unwrap();
        assert_eq!(
            store
                .list_entries(Some(&o), "s", "", None, None)
                .unwrap()
                .len(),
            5
        );
    }

    #[test]
    fn spaces_and_mirrors() {
        let (_d, store) = store();
        store.put_space("media", "/srv/media").unwrap();
        store.put_space("media", "/srv/media2").unwrap();
        assert_eq!(store.spaces().unwrap().len(), 1);
        assert_eq!(
            store.space("media").unwrap().unwrap().local_path,
            "/srv/media2"
        );
        assert!(store.remove_space("media").unwrap());
        assert!(!store.remove_space("media").unwrap());

        // A mirror is keyed by the directory it writes into, and carries the
        // version policy it materializes under (§7.2).
        store
            .put_mirror("/mnt/nas-media", "media", &VersionPolicy::Newest)
            .unwrap();
        assert_eq!(store.mirrors().unwrap().len(), 1);
        let policy = VersionPolicy::Origin(origin("nas"));
        store
            .put_mirror("/mnt/nas-media", "media", &policy)
            .unwrap();
        let mirrors = store.mirrors().unwrap();
        assert_eq!(mirrors.len(), 1, "re-pointing a directory is an update");
        assert_eq!(mirrors[0].policy, policy);
        assert_eq!(
            store.mirror("/mnt/nas-media").unwrap().unwrap().space,
            "media"
        );
        assert!(store.mirror("/elsewhere").unwrap().is_none());
        assert!(store.remove_mirror("/mnt/nas-media").unwrap());
        assert!(!store.remove_mirror("/mnt/nas-media").unwrap());
    }

    #[test]
    fn local_files_track_scanner_state() {
        let (_d, store) = store();
        let f = LocalFile {
            space: "s".into(),
            relpath: "a.txt".into(),
            size: 5,
            mtime_ns: 100,
            file_id: Some(vec![1, 2, 3]),
            content: Some(Hash::new(b"a")),
            scanned_at: 1,
        };
        store.put_local_file(&f).unwrap();
        assert_eq!(store.local_file("s", "a.txt").unwrap().unwrap(), f);
        assert_eq!(store.local_files("s").unwrap(), vec!["a.txt".to_string()]);
        assert_eq!(store.local_file_rows("s").unwrap(), vec![f.clone()]);
        assert!(store.local_file_rows("other").unwrap().is_empty());
        store.remove_local_file("s", "a.txt").unwrap();
        assert!(store.local_file("s", "a.txt").unwrap().is_none());
    }

    #[test]
    fn expired_tombstones_are_scoped_to_one_origin_and_age() {
        let (_d, store) = store();
        let nas = origin("nas");
        let laptop = origin("laptop");
        // mtime_ns is the deletion time (§4.2).
        store
            .put_entry(&nas, "s", "old", &FileEntry::tombstone(100, 2, None))
            .unwrap();
        store
            .put_entry(&nas, "s", "fresh", &FileEntry::tombstone(900, 3, None))
            .unwrap();
        store
            .put_entry(
                &nas,
                "s",
                "live",
                &FileEntry::file(1, 100, Hash::new(b"c"), 3),
            )
            .unwrap();
        store
            .put_entry(&laptop, "s", "theirs", &FileEntry::tombstone(1, 1, None))
            .unwrap();

        let expired = store.expired_tombstones(&nas, 500).unwrap();
        assert_eq!(expired.len(), 1, "only the aged tombstone, and only ours");
        assert_eq!(expired[0].path, "old");
        assert!(store.expired_tombstones(&nas, 0).unwrap().is_empty());
    }

    #[test]
    fn peer_latency_ewma() {
        let (_d, store) = store();
        let key = iroh_base::SecretKey::generate().public();
        store.record_peer_seen(&key, Some(&[1, 2]), 10).unwrap();
        store.record_peer_sync(&key, 20, 1000).unwrap();
        store.record_peer_sync(&key, 30, 2000).unwrap();
        let peers = store.peers_seen().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].last_sync, 30);
        assert!(peers[0].latency_ewma_us > 1000 && peers[0].latency_ewma_us < 2000);
        assert_eq!(peers[0].last_addr, Some(vec![1, 2]));
    }

    /// A listing must not stop short of a path that sorts high.
    ///
    /// A prefix scan is bounded by the prefix's byte successor, so every path
    /// carrying the prefix is inside it — including one whose next character is
    /// the highest there is. What the mirror's unlink sweep reads is this
    /// listing, so a path missing from it is a file the sweep would remove.
    #[test]
    fn a_prefix_listing_reaches_every_path_under_it() {
        assert_eq!(prefix_upper_bound("a").as_deref(), Some("b"));
        assert_eq!(prefix_upper_bound("az").as_deref(), Some("a{"));
        assert_eq!(prefix_upper_bound("é").as_deref(), Some("ê"));
        // The character above `U+D7FF` is `U+E000`: the surrogate block is not
        // a scalar value.
        assert_eq!(prefix_upper_bound("\u{d7ff}").as_deref(), Some("\u{e000}"));
        // `U+10FFFF` has nothing above it, so the carry goes left, and a prefix
        // made only of it has no upper bound at all.
        assert_eq!(prefix_upper_bound("a\u{10ffff}").as_deref(), Some("b"));
        assert_eq!(prefix_upper_bound("\u{10ffff}"), None);
        assert_eq!(prefix_upper_bound(""), None);

        let (_d, store) = store();
        let origin = OriginId::named("nas", "x.example").unwrap();
        for path in [
            "docs/a.txt",
            "docs/\u{10ffff}.txt",
            "docs/\u{10ffff}\u{10ffff}",
            "elsewhere.txt",
        ] {
            store
                .put_entry(
                    &origin,
                    "s",
                    path,
                    &FileEntry::file(1, 0, Hash::new(path.as_bytes()), 1),
                )
                .unwrap();
        }
        let listed: Vec<String> = store
            .list_entries(None, "s", "docs/", None, None)
            .unwrap()
            .into_iter()
            .map(|row| row.path)
            .collect();
        assert_eq!(
            listed,
            vec![
                "docs/a.txt".to_string(),
                "docs/\u{10ffff}.txt".to_string(),
                "docs/\u{10ffff}\u{10ffff}".to_string(),
            ]
        );
        assert_eq!(
            store.unified_paths("s", "docs/", None, None).unwrap(),
            listed
        );
        // And a prefix with no successor still lists what carries it.
        assert_eq!(
            store
                .list_entries(None, "s", "\u{10ffff}", None, None)
                .unwrap()
                .len(),
            0
        );
    }
}
