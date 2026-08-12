//! The materialized views of trie leaves — `entries` and `blob_providers` —
//! plus the engine's own state tables (§10).
//!
//! The trie is authoritative; everything here is a derived cache that can
//! always be rebuilt from `trie_nodes`.

use rusqlite::{params, OptionalExtension};
use synch_core::{
    parse_blob_key, parse_file_key, AdState, BlobAd, EntryKind, FileEntry, Hash, OriginId,
};
use synch_mpt::{ChangeKind, ResolvedChange, Trie};

use crate::{
    db::{hash_column, origin_column, Store},
    error::{Result, StoreError},
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
    /// The object root, for files.
    pub content: Option<Hash>,
    /// The origin trie seq at which this version was published.
    pub seq: u64,
    /// The previous content root (§8 lineage).
    pub prev: Option<Hash>,
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

/// A configured read-only mirror (§7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRow {
    /// The origin whose space is mirrored.
    pub origin: OriginId,
    /// The space being mirrored.
    pub space: String,
    /// The local directory the mirror materializes into.
    pub local_path: String,
}

/// A queued content want (§6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    /// The object root wanted.
    pub root: Hash,
    /// The encoded wanted ranges.
    pub ranges: Vec<u8>,
    /// Priority: explicit `synch get` > policy mirror > prefetch.
    pub priority: i64,
    /// Why it is wanted, for display.
    pub reason: String,
    /// When it was queued.
    pub created_at: i64,
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
        let mut filter = String::from("WHERE space = ?1 AND path >= ?2 AND path < ?3");
        // `prefix || 0x7f` bounds the LIKE-free prefix scan from above.
        let upper = format!("{prefix}\u{10ffff}");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(space.to_string()),
            Box::new(prefix.to_string()),
            Box::new(upper),
        ];
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

    /// Every space id that any origin has published entries for.
    pub fn known_spaces(&self) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT DISTINCT space FROM entries ORDER BY space")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn query_entries(&self, filter: &str, args: impl rusqlite::Params) -> Result<Vec<EntryRow>> {
        let conn = self.conn();
        let sql = format!(
            "SELECT origin_id, space, path, kind, size, mtime_ns, content, seq, prev
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
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<Vec<u8>>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (origin, space, path, kind, size, mtime_ns, content, seq, prev) = row?;
            out.push(EntryRow {
                origin: origin_column(origin, "entries.origin_id")?,
                space,
                path,
                kind: kind_from_int(kind)?,
                size: size as u64,
                mtime_ns,
                content: content
                    .map(|b| hash_column(b, "entries.content"))
                    .transpose()?,
                seq: seq as u64,
                prev: prev.map(|b| hash_column(b, "entries.prev")).transpose()?,
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

    /// Deletes every provider row for an origin.
    pub fn delete_origin_providers(&self, origin: &OriginId) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM blob_providers WHERE origin_id = ?1",
            params![origin.canonical()],
        )?)
    }

    /// "Who can serve this object?" — answered locally, with no round trip
    /// (§6.3).
    pub fn providers(&self, root: &Hash) -> Result<Vec<(OriginId, BlobAd)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT origin_id, size, complete, spans FROM blob_providers
             WHERE object_root = ?1 ORDER BY complete DESC, origin_id",
        )?;
        let rows = stmt.query_map(params![root.as_bytes().to_vec()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (origin, size, complete, spans) = row?;
            let state = if complete != 0 {
                AdState::Complete
            } else {
                let spans: Vec<(u64, u64)> = match spans {
                    Some(bytes) => postcard::from_bytes(&bytes)
                        .map_err(|e| StoreError::Decode(e.to_string()))?,
                    None => Vec::new(),
                };
                AdState::Partial { spans }
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
        self.transaction(|tx| {
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
        self.delete_origin_entries(origin)?;
        self.delete_origin_providers(origin)?;
        self.materialize_diff(origin, Hash::EMPTY, root)
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

    /// Registers a read-only mirror.
    pub fn put_mirror(&self, origin: &OriginId, space: &str, local_path: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO mirrors (origin_id, space, local_path) VALUES (?1, ?2, ?3)
             ON CONFLICT(origin_id, space) DO UPDATE SET local_path = excluded.local_path",
            params![origin.canonical(), space, local_path],
        )?;
        Ok(())
    }

    /// Removes a mirror.
    pub fn remove_mirror(&self, origin: &OriginId, space: &str) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM mirrors WHERE origin_id = ?1 AND space = ?2",
            params![origin.canonical(), space],
        )?;
        Ok(n > 0)
    }

    /// Every configured mirror.
    pub fn mirrors(&self) -> Result<Vec<MirrorRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT origin_id, space, local_path FROM mirrors ORDER BY origin_id, space",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (origin, space, local_path) = row?;
            out.push(MirrorRow {
                origin: origin_column(origin, "mirrors.origin_id")?,
                space,
                local_path,
            });
        }
        Ok(out)
    }

    // ---- want queue -------------------------------------------------------

    /// Queues a content want.
    pub fn put_want(&self, want: &Want) -> Result<()> {
        self.conn().execute(
            "INSERT INTO want (root, ranges, priority, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(root, ranges) DO UPDATE SET
               priority = MAX(want.priority, excluded.priority)",
            params![
                want.root.as_bytes().to_vec(),
                want.ranges,
                want.priority,
                want.reason,
                want.created_at
            ],
        )?;
        Ok(())
    }

    /// The queued wants, highest priority first.
    pub fn wants(&self) -> Result<Vec<Want>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT root, ranges, priority, reason, created_at FROM want
             ORDER BY priority DESC, created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (root, ranges, priority, reason, created_at) = row?;
            out.push(Want {
                root: hash_column(root, "want.root")?,
                ranges,
                priority,
                reason,
                created_at,
            });
        }
        Ok(out)
    }

    /// Removes a want.
    pub fn remove_want(&self, root: &Hash, ranges: &[u8]) -> Result<()> {
        self.conn().execute(
            "DELETE FROM want WHERE root = ?1 AND ranges = ?2",
            params![root.as_bytes().to_vec(), ranges],
        )?;
        Ok(())
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

fn apply_change(
    tx: &rusqlite::Transaction<'_>,
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

fn put_entry_in(
    conn: &rusqlite::Connection,
    origin: &OriginId,
    space: &str,
    path: &str,
    entry: &FileEntry,
) -> Result<()> {
    conn.execute(
        "INSERT INTO entries (origin_id, space, path, kind, size, mtime_ns, content, seq, prev)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(origin_id, space, path) DO UPDATE SET
           kind = excluded.kind, size = excluded.size, mtime_ns = excluded.mtime_ns,
           content = excluded.content, seq = excluded.seq, prev = excluded.prev",
        params![
            origin.canonical(),
            space,
            path,
            kind_to_int(entry.kind),
            entry.size as i64,
            entry.mtime_ns,
            entry.content.map(|h| h.as_bytes().to_vec()),
            entry.seq as i64,
            entry.prev.map(|h| h.as_bytes().to_vec()),
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
    let (complete, spans) = match &ad.state {
        AdState::Complete => (1i64, None),
        AdState::Partial { spans } => (
            0i64,
            Some(postcard::to_stdvec(spans).map_err(|e| StoreError::Decode(e.to_string()))?),
        ),
    };
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

        let o = origin("nas");
        store.put_mirror(&o, "media", "/mnt/nas-media").unwrap();
        assert_eq!(store.mirrors().unwrap().len(), 1);
        assert!(store.remove_mirror(&o, "media").unwrap());
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
        store.remove_local_file("s", "a.txt").unwrap();
        assert!(store.local_file("s", "a.txt").unwrap().is_none());
    }

    #[test]
    fn wants_are_prioritized() {
        let (_d, store) = store();
        let low = Want {
            root: Hash::new(b"a"),
            ranges: vec![0],
            priority: 1,
            reason: "prefetch".into(),
            created_at: 0,
        };
        let high = Want {
            root: Hash::new(b"b"),
            ranges: vec![0],
            priority: 10,
            reason: "get".into(),
            created_at: 1,
        };
        store.put_want(&low).unwrap();
        store.put_want(&high).unwrap();
        let wants = store.wants().unwrap();
        assert_eq!(wants[0].root, Hash::new(b"b"));

        // Re-queueing at a higher priority raises it, never lowers it.
        let mut bump = low.clone();
        bump.priority = 100;
        store.put_want(&bump).unwrap();
        assert_eq!(store.wants().unwrap()[0].priority, 100);

        store.remove_want(&low.root, &low.ranges).unwrap();
        assert_eq!(store.wants().unwrap().len(), 1);
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
}
