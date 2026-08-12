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
    /// Roots marked from.
    pub roots_marked: usize,
}

impl Store {
    /// Marks every trie node and value reachable from the retained roots.
    ///
    /// The mark set is every origin's **complete and pending** heads plus
    /// retained history roots (§5.4). Pending heads must be in the mark set or
    /// GC would eat an in-progress bootstrap.
    pub fn gc_mark(&self) -> Result<(HashSet<Hash>, HashSet<Hash>)> {
        let trie = Trie::new(self);
        let mut nodes = HashSet::new();
        let mut values = HashSet::new();
        for root in self.retained_roots()? {
            let reachable = trie.reachable(root)?;
            nodes.extend(reachable.nodes);
            values.extend(reachable.values);
        }
        Ok((nodes, values))
    }

    /// Runs one mark-and-sweep pass over `trie_nodes` and `trie_values`.
    pub fn gc_trie(&self) -> Result<GcStats> {
        let roots = self.retained_roots()?;
        let (nodes, values) = self.gc_mark()?;
        let mut stats = GcStats {
            roots_marked: roots.len(),
            ..GcStats::default()
        };
        let all_nodes = self.all_hashes("trie_nodes")?;
        let all_values = self.all_hashes("trie_values")?;
        self.transaction(|tx| {
            for hash in &all_nodes {
                if !nodes.contains(hash) {
                    tx.execute(
                        "DELETE FROM trie_nodes WHERE hash = ?1",
                        params![hash.as_bytes().to_vec()],
                    )?;
                    stats.nodes += 1;
                }
            }
            for hash in &all_values {
                if !values.contains(hash) {
                    tx.execute(
                        "DELETE FROM trie_values WHERE hash = ?1",
                        params![hash.as_bytes().to_vec()],
                    )?;
                    stats.values += 1;
                }
            }
            Ok(())
        })?;
        Ok(stats)
    }

    /// Sweeps content objects that no retained entry references and that are
    /// not pinned.
    ///
    /// Content GC is pin- and retention-driven, so history depth is a storage
    /// policy rather than a protocol constant (§8).
    pub fn gc_content(&self) -> Result<GcStats> {
        let referenced = self.referenced_content()?;
        let pinned: HashSet<Hash> = self.pinned_blobs()?.into_iter().collect();
        let mut stats = GcStats::default();
        for blob in self.blobs()? {
            if referenced.contains(&blob.root) || pinned.contains(&blob.root) {
                continue;
            }
            self.delete_blob(&blob.root)?;
            stats.blobs += 1;
        }
        Ok(stats)
    }

    /// Runs both sweeps.
    pub fn gc(&self) -> Result<GcStats> {
        let trie = self.gc_trie()?;
        let content = self.gc_content()?;
        Ok(GcStats {
            nodes: trie.nodes,
            values: trie.values,
            blobs: content.blobs,
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

    fn all_hashes(&self, table: &str) -> Result<Vec<Hash>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT hash FROM {table}"))?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(hash_column(row?, "hash")?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use synch_core::{file_key, FileEntry, OriginId, SignedHead};
    use synch_mpt::NodeStore;

    use super::*;
    use crate::heads::Slot;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).unwrap();
        (dir, s)
    }

    fn origin() -> OriginId {
        OriginId::named("nas", "x.example").unwrap()
    }

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
        let before = store.gc_mark().unwrap().0.len();
        assert_eq!(before, 0, "nothing is retained until a head points at it");

        let head = SignedHead::sign(&key, origin(), 2, new, 0);
        store.put_head(Slot::Complete, &head, 0, 0).unwrap();

        let stats = store.gc_trie().unwrap();
        assert!(stats.nodes > 0, "the old root's private nodes must go");
        assert_eq!(stats.roots_marked, 1);

        // Everything under the retained root survives.
        let trie = Trie::new(&store);
        assert!(trie.is_complete(new).unwrap());
        // The displaced root is gone.
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
            .record_history(&SignedHead::sign(&key, origin(), 1, old, 0))
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
        store.prune_history(&origin(), 2).unwrap();
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

        let stats = store.gc_content().unwrap();
        assert_eq!(stats.blobs, 1);
        assert!(store.blob(&referenced).unwrap().is_some());
        assert!(store.blob(&pinned).unwrap().is_some());
        assert!(store.blob(&orphan).unwrap().is_none());
        assert!(!store.blob_path(&orphan).exists());
    }

    #[test]
    fn full_gc_reports_both_sweeps() {
        let (_d, store) = store();
        let trie = Trie::new(&store);
        trie.insert(Hash::EMPTY, b"k", &vec![7u8; 500]).unwrap();
        store.ingest_bytes(&vec![3u8; 100_000], 0).unwrap();
        let stats = store.gc().unwrap();
        assert!(stats.nodes > 0);
        assert_eq!(stats.values, 1);
        assert_eq!(stats.blobs, 1);
    }
}
