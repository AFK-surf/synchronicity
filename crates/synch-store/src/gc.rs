//! Mark-and-sweep garbage collection for trie nodes, values, and content (§5.4).

use std::collections::HashSet;

use rusqlite::params;
use synch_core::Hash;
use synch_mpt::Trie;

use crate::{db::hash_column, db::Store, error::Result};

/// What one GC pass swept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcStats {
    /// Trie nodes swept.
    pub nodes: usize,
    /// Out-of-line trie values swept.
    pub values: usize,
    /// Content objects swept.
    pub blobs: usize,
    /// CAS files swept that no row accounted for.
    pub orphans: usize,
    /// Roots marked from.
    pub roots_marked: usize,
}

/// How much the content-addressed trie storage holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrieStats {
    /// Stored trie nodes.
    pub nodes: usize,
    /// Stored out-of-line trie values.
    pub values: usize,
}

impl Store {
    /// Runs one mark-and-sweep pass over `trie_nodes` and `trie_values`.
    ///
    /// The whole pass — the retained roots, the mark walk, the candidate
    /// snapshot and the deletes — runs inside **one** immediate transaction.
    /// That is not tidiness; splitting it is a data-loss bug. Taking the
    /// connection mutex per step — with the mark walk releasing it between node
    /// reads — lets a writer commit in the gap. A publish is one transaction
    /// that writes new trie nodes *and* the head row: landing between the mark
    /// and the snapshot, its nodes are absent from the mark set and present in
    /// the candidate list, so the sweep deletes them while the head row
    /// survives pointing at them. The trie is
    /// authoritative and `entries` cannot regenerate it, so the node's own
    /// published root becomes permanently unservable — and `publish` then calls
    /// `note_complete` on it, so the store goes on advertising that it can
    /// serve it. The same window eats a peer's in-flight bootstrap, since
    /// `fetch_pending` commits one batch per transaction and `reachable`
    /// silently skips missing children.
    pub fn gc_trie(&self) -> Result<GcStats> {
        let mut stats = GcStats::default();
        let (swept_nodes, swept_values, roots) =
            self.transaction(|txn| -> Result<(usize, usize, Vec<Hash>)> {
                let conn = txn.conn();
                let roots = retained_roots_in(conn)?;
                stats.roots_marked = roots.len();
                // One accumulating mark set across every retained root, not one
                // walk per root. Successive roots of an origin share all but
                // the path that changed, so walking each into its own set would
                // cost a store read per node *per root* — and `head_history`
                // holds a row per publish for `root_retention`, so that
                // multiplier is in the thousands for a node that publishes
                // steadily. All of it inside the immediate transaction below,
                // which holds the one write connection.
                let trie = Trie::new(txn);
                let mut marked = synch_mpt::Reachable::default();
                for root in &roots {
                    trie.reach_into(*root, &mut marked)?;
                }
                let (nodes, values) = (marked.nodes, marked.values);
                // Deleted set-wise rather than row by row: pulling every hash
                // into a `Vec` and issuing one `DELETE ... WHERE hash = ?` per
                // unreferenced row is, on a large store, millions of statements
                // under the write lock.
                let n = sweep_unmarked(conn, "trie_nodes", &nodes)?;
                let v = sweep_unmarked(conn, "trie_values", &values)?;
                Ok((n, v, roots))
            })?;
        stats.nodes = swept_nodes;
        stats.values = swept_values;
        // The memo may only vouch for roots the sweep just marked from. A root
        // that fell out of the retained set has had its nodes taken, and a memo
        // entry for it would be a standing lie about what this node can serve —
        // but dropping the *whole* memo would throw away the answer §5.1
        // exists to avoid recomputing on every `Hello`.
        self.retain_complete_roots(&roots.into_iter().collect());
        Ok(stats)
    }

    /// Sweeps content objects that no retained entry references, that are not
    /// pinned, and that nothing has touched since `before`.
    ///
    /// Content GC is pin- and retention-driven, so history depth is a storage
    /// policy rather than a protocol constant (§8). The retention window is
    /// what keeps an object that was just fetched — for a `synch get` of a
    /// historical root, say, which no current entry references — from being
    /// swept out from under the fetch that produced it.
    ///
    /// `last_access` is written on ingest and on every download milestone, not
    /// on reads: a streaming read would otherwise cost one row update per
    /// chunk — each taking the single write connection and appending a WAL
    /// frame, so gateway range reads and mirror materialization would serialize
    /// against publishes and GC — and an object nothing references is by
    /// construction not being read through the tree. `read_range` therefore
    /// does not touch the row: doing so would cost exactly that and quietly
    /// invert the retention semantics — with it a hot object is never
    /// collected, without it it is. Every write path stamps the column, which
    /// is all this needs.
    pub fn gc_content(&self, before: i64) -> Result<GcStats> {
        let referenced = self.referenced_content()?;
        let pinned: HashSet<Hash> = self.pinned_blobs()?.into_iter().collect();
        let mut stats = GcStats::default();
        // The three reads above are a snapshot and the delete is a fourth
        // statement, so a pin or a resumed fetch landing in between would
        // otherwise be decided against by a snapshot older than it is. They
        // stay as a cheap pre-filter — they keep the pass from opening a
        // transaction per row — and `delete_blob_if_collectable` re-reads the
        // predicate inside the transaction that does the delete, which is what
        // actually decides.
        for candidate in self.blob_candidates()? {
            if referenced.contains(&candidate.root) || pinned.contains(&candidate.root) {
                continue;
            }
            if candidate.last_access >= before {
                continue;
            }
            if self.delete_blob_if_collectable(&candidate.root, before)? {
                stats.blobs += 1;
            }
        }
        Ok(stats)
    }

    /// Removes CAS files that no `blobs` row accounts for.
    ///
    /// The row sweeps walk rows, so a payload or an outboard left without one —
    /// a fetch that failed verification, a crash between
    /// [`Store::delete_blob`]'s row delete and its unlinks — is disk nothing
    /// else would ever reclaim.
    ///
    /// A file counts as orphaned only once its own mtime is older than the same
    /// retention horizon `gc_content` uses, **and** no write is in flight for
    /// its object.
    ///
    /// The mtime alone was the argument, and it covered the wrong case. It
    /// reasoned that payload and outboard are created before the row that
    /// describes them, so a file with no row inside the window is a write in
    /// progress — true of a *first* write. `write_slice` opens with
    /// `truncate(false)` and reuses whatever file is there, so for a resumed
    /// write the mtime was sampled before the writer touched it and proves
    /// nothing about the present. The shape that mattered is exactly the one
    /// this sweep exists for: a stale orphan payload, left by a fetch that
    /// failed verification days ago, that a fetch is now resuming into. Stat it,
    /// read `blobs`, drop the guard, and the writer's commit lands before the
    /// unlink — a row claiming verified groups whose bytes are gone.
    ///
    /// So the decision and the unlink are one step under one guard, and the
    /// writer's own mark is part of the decision (`Store::lease_write`).
    /// Anything in a shard directory that is not named for an object is left
    /// alone.
    ///
    /// Half-written ingests go with them, by way of [`Store::gc_staging`].
    ///
    /// Nothing in the CAS root but a directory is descended into. That is not
    /// defensiveness: `read_dir` on a regular file fails with `NotADirectory`,
    /// not `NotFound`, so a single stray file in the root — a leaked staging
    /// file, say — would make this return an error on every pass from then on.
    /// `maintenance_pass` would report failure forever and no orphan would be
    /// swept again, including the file causing it.
    ///
    /// Returns how many files went.
    pub fn gc_orphans(&self, before: i64) -> Result<usize> {
        let mut swept = self.gc_staging(before)?;
        let shards = match std::fs::read_dir(self.cas_dir()) {
            Ok(shards) => shards,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(swept),
            Err(e) => return Err(e.into()),
        };
        for shard in shards {
            let shard = shard?.path();
            if !shard.is_dir() || shard == self.staging_dir() {
                continue;
            }
            let files = match std::fs::read_dir(&shard) {
                Ok(files) => files,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            for file in files {
                let path = file?.path();
                let Some(root) = cas_root_of(&path) else {
                    continue;
                };
                // One guard across the whole decision and the unlink, so
                // nothing can make the file live in between. The `stat` is
                // inside it too: it is the reading the verdict rests on.
                let conn = self.conn();
                let Ok(meta) = std::fs::metadata(&path) else {
                    continue;
                };
                if !meta.is_file() || mtime_nanos(&meta).is_none_or(|at| at >= before) {
                    continue;
                }
                if blob_row_exists(&conn, &root)? || self.is_being_written(&root) {
                    continue;
                }
                if std::fs::remove_file(&path).is_ok() {
                    swept += 1;
                }
                drop(conn);
            }
        }
        Ok(swept)
    }

    /// Removes staging files no ingest is still writing.
    ///
    /// [`Store::ingest_file`] streams into a staging file and renames it onto
    /// its content address, so one left behind is a whole object of disk that
    /// nothing else will ever reclaim — it is not named for an object, so
    /// `cas_root_of` says nothing about it and the orphan sweep above passes
    /// over it. It is not a crash-only leak either: the `create_dir_all` and
    /// the `rename` that follow the stream can both fail (ENOSPC, which is
    /// precisely when reclaiming matters), and a panic inside the hashing
    /// unwinds straight past the cleanup in the error arm. Every leak is larger
    /// than [`INLINE_BLOB_MAX`](synch_core::INLINE_BLOB_MAX) by construction,
    /// since smaller files never take this path.
    ///
    /// Age is the same horizon the rest of GC uses, read off the file's own
    /// mtime: an ingest in progress is writing to it, so it is younger than the
    /// window and stays. Files written by an older build, which staged into the
    /// CAS root under an `incoming-` name, are taken from there as well —
    /// nothing else would.
    ///
    /// Returns how many files went.
    pub fn gc_staging(&self, before: i64) -> Result<usize> {
        // The staging directory holds staging files and nothing else, so every
        // stale file in it goes; the CAS root holds shard directories, so only
        // the names an older build staged there do.
        let mut swept = sweep_stale_files(&self.staging_dir(), before, &|_| true)?;
        swept += sweep_stale_files(&self.cas_dir(), before, &is_legacy_staging)?;
        Ok(swept)
    }

    /// Runs every sweep, with `before` as the content retention horizon.
    pub fn gc(&self, before: i64) -> Result<GcStats> {
        let trie = self.gc_trie()?;
        let content = self.gc_content(before)?;
        Ok(GcStats {
            nodes: trie.nodes,
            values: trie.values,
            blobs: content.blobs,
            // After the content sweep, so a row it took this pass leaves no
            // files behind for a whole retention window.
            orphans: self.gc_orphans(before)?,
            roots_marked: trie.roots_marked,
        })
    }

    /// Every content root referenced by any origin's materialized entries.
    pub fn referenced_content(&self) -> Result<HashSet<Hash>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT DISTINCT content FROM entries WHERE content IS NOT NULL")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = HashSet::new();
        for row in rows {
            out.insert(hash_column(row?, "entries.content")?);
        }
        Ok(out)
    }

    /// Counts of the content-addressed tables, for `synch doctor` GC stats.
    pub fn trie_stats(&self) -> Result<TrieStats> {
        let conn = self.conn();
        Ok(TrieStats {
            nodes: conn.query_row("SELECT COUNT(*) FROM trie_nodes", [], |r| {
                r.get::<_, i64>(0)
            })? as usize,
            values: conn.query_row("SELECT COUNT(*) FROM trie_values", [], |r| {
                r.get::<_, i64>(0)
            })? as usize,
        })
    }
}

/// The GC mark set, read inside the sweeping transaction.
///
/// The object a CAS file is named for: `<hex>` for a payload, `<hex>.obao` for
/// an outboard.
///
/// `None` for anything else in the directory, which is then left alone.
fn cas_root_of(path: &std::path::Path) -> Option<Hash> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".obao").unwrap_or(name);
    let bytes = hex::decode(stem).ok()?;
    Hash::from_slice(&bytes).ok()
}

/// True for the staging names an older build wrote into the CAS root itself,
/// before staging got a directory of its own.
fn is_legacy_staging(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("incoming-") && name.ends_with(".tmp"))
}

/// Removes the regular files directly in `dir` that `wanted` names and that
/// nothing has touched since `before`. A directory that is not there holds no
/// stale files.
fn sweep_stale_files(
    dir: &std::path::Path,
    before: i64,
    wanted: &dyn Fn(&std::path::Path) -> bool,
) -> Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let mut swept = 0;
    for entry in entries {
        let path = entry?.path();
        if !wanted(&path) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || mtime_nanos(&meta).is_none_or(|at| at >= before) {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            swept += 1;
        }
    }
    Ok(swept)
}

/// A file's modification time in unix nanoseconds, if it has one this side of
/// the epoch.
fn mtime_nanos(meta: &std::fs::Metadata) -> Option<i64> {
    meta.modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_nanos()).ok())
}

/// Every origin's complete and pending heads plus retained history roots
/// (§5.4). Pending heads must be in the mark set or GC would eat an in-progress
/// bootstrap.
///
/// One table, not a union across two: `put_head` writes the signature to
/// `head_history` before the slot points at it, and both delete paths refuse to
/// remove a row a slot still names, so every current head's root is here by
/// construction. The union returned the same set — but stating the mark set
/// twice, in two places, is how the two come to disagree.
///
/// And one *function*, for the same reason. [`Store::retained_roots`] used to
/// carry a second copy of this query; the sweep ran this one and the sweep's
/// test asserted on that one, so a change to either would have been invisible
/// to the other until an audit found them.
pub(crate) fn retained_roots_in(conn: &rusqlite::Connection) -> Result<Vec<Hash>> {
    let mut stmt = conn.prepare("SELECT DISTINCT root FROM head_history")?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(hash_column(row?, "heads.root")?);
    }
    Ok(out)
}

/// Whether a `blobs` row accounts for an object, on a connection already held.
fn blob_row_exists(conn: &rusqlite::Connection, root: &Hash) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM blobs WHERE root = ?1)",
        params![root.as_bytes().to_vec()],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

/// Deletes every row of `table` whose hash is not in `marked`, in one
/// statement, and reports how many went.
///
/// The marked set goes into a temporary table rather than an `IN (?, ?, …)`
/// list: the set is the size of the live trie, which is far past SQLite's
/// parameter limit.
fn sweep_unmarked(
    conn: &rusqlite::Connection,
    table: &str,
    marked: &HashSet<Hash>,
) -> Result<usize> {
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS gc_marked (hash BLOB PRIMARY KEY);
         DELETE FROM gc_marked;",
    )?;
    {
        let mut insert = conn.prepare("INSERT OR IGNORE INTO gc_marked (hash) VALUES (?1)")?;
        for hash in marked {
            insert.execute(params![hash.as_bytes().to_vec()])?;
        }
    }
    let swept = conn.execute(
        &format!("DELETE FROM {table} WHERE hash NOT IN (SELECT hash FROM gc_marked)"),
        [],
    )?;
    conn.execute_batch("DELETE FROM gc_marked;")?;
    Ok(swept)
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use synch_core::{file_key, FileEntry, Hash, SignedHead};
    use synch_mpt::NodeStore;

    use super::*;
    use crate::heads::Slot;
    use crate::testutil::{origin, sign_head, store};

    fn publish(store: &Store, files: &[(&str, u64)]) -> Hash {
        let trie = Trie::new(store);
        let mut root = Hash::EMPTY;
        for (path, size) in files {
            let entry = FileEntry::file(*size, 0, Hash::new(path.as_bytes()), 1);
            root = trie
                .insert(
                    root,
                    &file_key("s", path).unwrap(),
                    &postcard::to_stdvec(&entry).unwrap(),
                )
                .unwrap();
        }
        root
    }

    #[test]
    fn unreferenced_nodes_are_swept() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let old = publish(&store, &[("a", 1), ("b", 2)]);
        let new = publish(&store, &[("a", 1), ("b", 2), ("c", 3)]);
        assert!(
            store.retained_roots().unwrap().is_empty(),
            "nothing is retained until a head points at it"
        );

        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&key, origin(), 2, new, 0),
                0,
                0,
            )
            .unwrap();

        let stats = store.gc_trie().unwrap();
        assert!(stats.nodes > 0, "the old root's private nodes must go");
        assert_eq!(stats.roots_marked, 1);

        // Everything under the retained root survives; the displaced root is gone.
        let trie = Trie::new(&store);
        assert!(trie.is_complete(new).unwrap());
        assert!(!store.has_node(&old).unwrap());
    }

    #[test]
    fn pending_heads_are_in_the_mark_set() {
        // §5.4: pending heads must be marked or GC would eat an in-progress
        // bootstrap.
        let (_d, store) = store();
        let key = SecretKey::generate();
        let complete = publish(&store, &[("a", 1)]);
        let pending = publish(&store, &[("a", 1), ("b", 2)]);
        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&key, origin(), 1, complete, 0),
                0,
                0,
            )
            .unwrap();
        store
            .put_head(
                Slot::Pending,
                &SignedHead::sign(&key, origin(), 2, pending, 0),
                0,
                0,
            )
            .unwrap();

        store.gc_trie().unwrap();
        let trie = Trie::new(&store);
        assert!(trie.is_complete(complete).unwrap());
        assert!(trie.is_complete(pending).unwrap());
    }

    #[test]
    fn history_roots_are_retained() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let old = publish(&store, &[("a", 1)]);
        let new = publish(&store, &[("a", 1), ("b", 2)]);
        store
            .record_history(&SignedHead::sign(&key, origin(), 1, old, 0), 0)
            .unwrap();
        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&key, origin(), 2, new, 0),
                0,
                0,
            )
            .unwrap();

        store.gc_trie().unwrap();
        let trie = Trie::new(&store);
        // Retained old roots serve laggard peers cheap diffs and power `synch log`.
        assert!(trie.is_complete(old).unwrap());
        assert!(trie.is_complete(new).unwrap());

        // Once history is pruned, the old root's private nodes go.
        store.prune_history_before(&origin(), 1).unwrap();
        let stats = store.gc_trie().unwrap();
        assert!(stats.nodes > 0);
        assert!(!store.has_node(&old).unwrap());
    }

    #[test]
    fn out_of_line_values_are_swept_with_their_nodes() {
        let (_d, store) = store();
        let trie = Trie::new(&store);
        let root = trie.insert(Hash::EMPTY, b"k", &vec![7u8; 500]).unwrap();
        assert!(trie.is_complete(root).unwrap());
        let stats = store.gc_trie().unwrap();
        assert_eq!(stats.values, 1);
        assert!(stats.nodes >= 1);
    }

    #[test]
    fn content_gc_respects_references_and_pins() {
        let (_d, store) = store();
        let referenced = store.ingest_bytes(&vec![1u8; 100_000], 0).unwrap();
        let pinned = store.ingest_bytes(&vec![2u8; 100_000], 0).unwrap();
        let orphan = store.ingest_bytes(&vec![3u8; 100_000], 0).unwrap();

        store
            .put_entry(
                &origin(),
                "s",
                "a",
                &FileEntry::file(100_000, 0, referenced, 1),
            )
            .unwrap();
        store.set_pinned(&pinned, true).unwrap();

        // Ingested at 0, so a horizon of 1 puts all three past retention.
        let stats = store.gc_content(1).unwrap();
        assert_eq!(stats.blobs, 1);
        assert!(store.blob(&referenced).unwrap().is_some());
        assert!(store.blob(&pinned).unwrap().is_some());
        assert!(store.blob(&orphan).unwrap().is_none());
        assert!(!store.blob_path(&orphan).exists());

        // `gc` runs content before orphans, so a row it took leaves no files
        // behind for a whole retention window.
        let stats = store.gc(1).unwrap();
        assert_eq!(stats.blobs, 0);
        assert_eq!(stats.orphans, 0);
    }

    #[test]
    fn content_inside_the_retention_window_survives() {
        // An object nothing references yet — just fetched for a historical
        // root, say — is not swept out from under the fetch that produced it.
        let (_d, store) = store();
        let fresh = store.ingest_bytes(&vec![4u8; 100_000], 1_000).unwrap();
        assert_eq!(store.gc_content(500).unwrap().blobs, 0);
        assert!(store.blob(&fresh).unwrap().is_some());
        assert_eq!(store.gc_content(2_000).unwrap().blobs, 1);
        assert!(store.blob(&fresh).unwrap().is_none());
    }

    /// CAS files no row accounts for are reclaimed once old enough to be
    /// leftovers rather than a write in progress, and files not named for an
    /// object are never touched.
    #[test]
    fn stray_cas_files_are_swept_once_they_are_old_enough() {
        let (_d, store) = store();
        let live = store.ingest_bytes(&vec![7u8; 100_000], 0).unwrap();
        let stale = Hash::new(b"a fetch that never verified");
        let fresh = Hash::new(b"a fetch still running");
        for root in [&stale, &fresh] {
            let path = store.blob_path(root);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"leftovers").unwrap();
            std::fs::write(store.outboard_path(root), b"leftovers").unwrap();
        }
        // Something in the directory that is not named for an object at all.
        let stranger = store.cas_dir().join("ab").join("README");
        std::fs::create_dir_all(stranger.parent().unwrap()).unwrap();
        std::fs::write(&stranger, b"not ours").unwrap();

        // A horizon in the past leaves everything: every file was written now.
        assert_eq!(store.gc_orphans(0).unwrap(), 0);
        assert!(store.blob_path(&stale).exists());

        // A horizon in the future takes the two payloads and their outboards,
        // and nothing that a row or a name speaks for.
        let horizon = synch_core::now_ns() + 60 * 1_000_000_000;
        assert_eq!(store.gc_orphans(horizon).unwrap(), 4);
        for root in [&stale, &fresh] {
            assert!(!store.blob_path(root).exists());
            assert!(!store.outboard_path(root).exists());
        }
        assert!(store.blob_path(&live).exists(), "a file with a row stays");
        assert!(stranger.exists(), "and so does a file that is not ours");

        // The full pass reports what it took.
        assert_eq!(store.gc(0).unwrap().orphans, 0);
    }

    /// A leaked staging file is reclaimed, and never kills the sweep: a regular
    /// file in the CAS root used to make every orphan pass fail NotADirectory.
    #[test]
    fn a_staging_file_in_the_cas_root_is_reclaimed_rather_than_breaking_the_sweep() {
        let (_d, store) = store();
        let live = store.ingest_bytes(&vec![7u8; 100_000], 0).unwrap();
        // Exactly what an older build left behind, in the place it left it.
        let legacy = store.cas_dir().join("incoming-1234-0.tmp");
        std::fs::write(&legacy, vec![1u8; 100_000]).unwrap();
        // And what this one leaves: a staging file in the staging directory.
        std::fs::create_dir_all(store.staging_dir()).unwrap();
        let staged = store.staging_dir().join("1234-1.tmp");
        std::fs::write(&staged, vec![2u8; 100_000]).unwrap();

        // Inside the window both are ingests that may still be running, and the
        // sweep completes rather than failing on the file in the root.
        assert_eq!(store.gc_orphans(0).unwrap(), 0);
        assert!(legacy.exists() && staged.exists());

        // Past it, both are reclaimed — and the object with a row is untouched.
        let horizon = synch_core::now_ns() + 60 * 1_000_000_000;
        assert_eq!(store.gc_orphans(horizon).unwrap(), 2);
        assert!(!legacy.exists() && !staged.exists());
        assert!(store.blob_path(&live).exists());
        // The staging directory itself is not mistaken for a shard.
        assert!(store.staging_dir().is_dir());
    }

    #[test]
    fn history_pruning_keeps_the_current_heads_and_fork_evidence() {
        // §5.4 prunes old roots by retention; §3.4 and §4.4 make same-seq
        // forks evidence that has to outlive it.
        let (_d, store) = store();
        let key = SecretKey::generate();
        let old = SignedHead::sign(&key, origin(), 1, Hash([1u8; 32]), 100);
        let fork_a = SignedHead::sign(&key, origin(), 2, Hash([2u8; 32]), 200);
        let fork_b = SignedHead::sign(&key, origin(), 2, Hash([3u8; 32]), 200);
        let current = SignedHead::sign(&key, origin(), 3, Hash([4u8; 32]), 300);
        for head in [&old, &fork_a, &fork_b, &current] {
            // Received here when it was signed, which is what retention reads.
            store.record_history(head, head.created_at).unwrap();
        }
        store
            .put_head(Slot::Complete, &current, current.created_at, 0)
            .unwrap();

        // A horizon past every row: the plain old root goes, the current head
        // stays because it is current, and both fork rows stay because the
        // head that moved past them is not itself out of retention yet.
        assert_eq!(store.prune_history_before(&origin(), 250).unwrap(), 1);
        let kept: Vec<u64> = store
            .head_history(&origin())
            .unwrap()
            .into_iter()
            .map(|h| h.seq)
            .collect();
        assert_eq!(kept, vec![3, 2, 2]);
        assert_eq!(store.equivocations().unwrap().len(), 1);

        // Once the head that published past the fork is itself older than
        // retention, the evidence ages out with everything else.
        assert_eq!(store.prune_history_before(&origin(), 400).unwrap(), 2);
        assert_eq!(store.head_history(&origin()).unwrap().len(), 1);
        assert!(store.equivocations().unwrap().is_empty());

        // An origin that never published past the forked seq keeps the
        // evidence whatever the horizon.
        let a = sign_head(&key, 2, 2);
        let b = sign_head(&key, 2, 3);
        store.record_history(&a, a.created_at).unwrap();
        store.record_history(&b, b.created_at).unwrap();
        store.put_head(Slot::Complete, &a, a.created_at, 0).unwrap();
        assert_eq!(store.prune_history_before(&origin(), i64::MAX).unwrap(), 0);
        let seqs: Vec<u64> = store
            .head_history(&origin())
            .unwrap()
            .into_iter()
            .map(|h| h.seq)
            .collect();
        assert_eq!(seqs, vec![3, 2, 2]);
    }

    /// A head dated at the end of time is pruned like any other: retention
    /// keys on when this node recorded the row, not on the signer's claim.
    #[test]
    fn a_head_dated_at_the_end_of_time_still_ages_out() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let liar = SignedHead::sign(&key, origin(), 1, Hash([1u8; 32]), i64::MAX);
        let current = SignedHead::sign(&key, origin(), 2, Hash([2u8; 32]), i64::MAX);
        store.record_history(&liar, 100).unwrap();
        store.put_head(Slot::Complete, &current, 200, 0).unwrap();

        // Inside the horizon it stays, like any recently received row.
        assert_eq!(store.prune_history_before(&origin(), 50).unwrap(), 0);
        // Past it, the signed date buys nothing.
        assert_eq!(store.prune_history_before(&origin(), 150).unwrap(), 1);
        let kept: Vec<u64> = store
            .head_history(&origin())
            .unwrap()
            .into_iter()
            .map(|h| h.seq)
            .collect();
        assert_eq!(kept, vec![2], "only the current head is left");
    }

    /// An origin that merely publishes regularly does not pin its old forks:
    /// "moved past" is read off retained history, not the complete slot.
    #[test]
    fn a_live_origin_does_not_pin_its_old_forks() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let day = 24 * 3600 * 1_000_000_000i64;
        let long_ago = 1_000 * day;
        let now = long_ago + 100 * day;

        // A fork a hundred days ago, and ordinary history just past it.
        for root in [1u8, 2u8] {
            store
                .record_history(&sign_head(&key, 5, root), long_ago)
                .unwrap();
        }
        for seq in 6..10u64 {
            store
                .record_history(&sign_head(&key, seq, seq as u8 + 50), long_ago)
                .unwrap();
        }
        // And a head taken today, which holds the complete slot.
        let current = sign_head(&key, 20, 99);
        store.put_head(Slot::Complete, &current, now, now).unwrap();

        // A seven-day window: everything but today's head is out of it, and the
        // heads at 6..9 are the origin on record past the fork.
        assert_eq!(
            store
                .prune_history_before(&origin(), now - 7 * day)
                .unwrap(),
            6
        );
        let kept: Vec<u64> = store
            .head_history(&origin())
            .unwrap()
            .into_iter()
            .map(|h| h.seq)
            .collect();
        assert_eq!(kept, vec![20], "only the current head is left");
        assert!(store.equivocations().unwrap().is_empty());
    }

    /// Future-seq fork flooding is prunable: a retained head at a higher seq
    /// is the proof the origin moved on, and only the single highest forked
    /// seq is left without one.
    #[test]
    fn forks_above_the_complete_head_are_bounded_by_the_origin_own_flood() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let real = SignedHead::sign(&key, origin(), 100, Hash([7u8; 32]), 0);
        store.put_head(Slot::Complete, &real, 1_000, 1_000).unwrap();

        // Two roots at each of two hundred far-future seqs, none of them ever
        // completing, so the complete slot stays at 100.
        for seq in 1_000_000..1_000_200u64 {
            for root in 0..2u8 {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&seq.to_le_bytes());
                bytes[8] = root;
                let head = SignedHead::sign(&key, origin(), seq, Hash(bytes), 0);
                store.record_history(&head, 1_000).unwrap();
            }
        }
        // The highest of them holds the pending slot, as `offer_head` would
        // have left it.
        let mut top = [0u8; 32];
        top[..8].copy_from_slice(&1_000_199u64.to_le_bytes());
        top[8] = 1;
        let pending = SignedHead::sign(&key, origin(), 1_000_199, Hash(top), 0);
        store
            .put_head(Slot::Pending, &pending, 1_000, 1_000)
            .unwrap();
        assert_eq!(store.head_history(&origin()).unwrap().len(), 401);

        // A horizon past every row takes every forked seq the origin itself
        // published past: 199 of the 200.
        assert_eq!(store.prune_history_before(&origin(), 10_000).unwrap(), 398);
        // What is left is the two slots and the one forked seq nothing stands
        // above — still two roots, so the equivocation is still provable.
        let left = store.head_history(&origin()).unwrap();
        assert_eq!(left.len(), 3);
        assert_eq!(store.equivocations().unwrap().len(), 1);
        assert_eq!(store.equivocations().unwrap()[0].heads.len(), 2);
        assert_eq!(store.complete_head(&origin()).unwrap(), Some(real));
        assert_eq!(store.pending_head(&origin()).unwrap(), Some(pending));
        // And a second pass finds nothing more, rather than oscillating.
        assert_eq!(store.prune_history_before(&origin(), 10_000).unwrap(), 0);
    }

    /// A fork is never pruned down to a single root: the pair is the evidence,
    /// so a forked seq goes whole or not at all.
    #[test]
    fn fork_evidence_is_pruned_whole_or_not_at_all() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let old = SignedHead::sign(&key, origin(), 2, Hash([2u8; 32]), 0);
        let recent = SignedHead::sign(&key, origin(), 2, Hash([3u8; 32]), 0);
        let past = SignedHead::sign(&key, origin(), 3, Hash([4u8; 32]), 0);
        store.record_history(&old, 100).unwrap();
        store.record_history(&recent, 900).unwrap();
        store.record_history(&past, 100).unwrap();

        // The origin is on record past the fork and one of the two roots is out
        // of the window — but taking it alone would leave a row that proves
        // nothing, so both stay. The head at seq 3 stays with them: it is the
        // proof the origin moved past the fork, and a pass that took it would
        // leave a fork nothing could ever retire.
        assert_eq!(store.prune_history_before(&origin(), 500).unwrap(), 0);
        assert_eq!(store.equivocations().unwrap().len(), 1);
        // Once both roots are past the window, the fork goes whole. Its
        // witness at seq 3 is also the top of the history, which no pass ever
        // takes: pruning it would lower the seq ceiling the origin is on
        // record at.
        assert_eq!(store.prune_history_before(&origin(), 1_000).unwrap(), 2);
        assert!(store.equivocations().unwrap().is_empty());
        assert_eq!(
            store
                .head_history(&origin())
                .unwrap()
                .iter()
                .map(|h| h.seq)
                .collect::<Vec<_>>(),
            vec![3]
        );
    }
}
