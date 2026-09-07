//! Structural diff between two roots (§5.2).
//!
//! The diff walks both tries in lockstep and prunes any subtree whose two sides
//! are structurally identical — which, because nodes are content-addressed, is
//! exactly the "only touched subtrees are visited" property that makes
//! re-materializing `entries` after a head flip cost `O(change)`.

use synch_core::Hash;

use crate::{error::MptError, node::ValueRef, scope::Scope, store::NodeStore, trie::Trie};

/// What happened to one key between two roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// The key exists only under the new root.
    Added,
    /// The key exists under both roots with different values.
    Changed,
    /// The key exists only under the old root.
    Deleted,
}

/// One key's difference between two roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The key.
    pub key: Vec<u8>,
    /// The value under the old root, if any.
    pub old: Option<ValueRef>,
    /// The value under the new root, if any.
    pub new: Option<ValueRef>,
}

impl<S: NodeStore + ?Sized> Trie<'_, S> {
    /// Diffs two roots, returning one [`Change`] per differing key in
    /// lexicographic key order.
    ///
    /// The whole diff is the Lean operation `Trie.Diff.diff`: both tries
    /// walked in lockstep with the shared descent's defences, every subtree
    /// whose two sides are the same node pruned, and a value compared as a
    /// value rather than as a representation (inline bytes and the address
    /// of the same bytes out of line are one value, decided by the digest
    /// without touching the store). Rust supplies raw node reads, the
    /// refusals a peer recorded and BLAKE3.
    pub fn diff(&self, old_root: Hash, new_root: Hash) -> Result<Vec<Change>, MptError> {
        synch_verified::trie::diff(
            &mut crate::lean_storage::Bytes(self.store()),
            &mut crate::lean_storage::Redactions(self.store()),
            &mut crate::lean_storage::Blake3,
            old_root.as_bytes(),
            new_root.as_bytes(),
        )
        .map_err(crate::lean_storage::walk_error)?
        .into_iter()
        .map(|change| {
            Ok(Change {
                key: change.key,
                old: change.old.map(crate::lean_storage::value_ref).transpose()?,
                new: change.new.map(crate::lean_storage::value_ref).transpose()?,
            })
        })
        .collect()
    }

    /// Streams the diff, resolving one value at a time, and reports how many
    /// changes were handed over.
    ///
    /// This is what a head promotion applies. The walk ceiling bounds
    /// positions, not the bytes hanging off them — six canonical nodes
    /// describe 65 536 positions — so collecting fully resolved changes meant
    /// resolving one large payload once per position, into memory, inside the
    /// transaction the flip runs in. An allocation failure there aborts rather
    /// than returning `Err`, so §12's per-origin containment never runs, and
    /// the pending head is durable: the next start reproduces it.
    ///
    /// Only the **new** side is resolved. The old side decides nothing but
    /// whether the change is a deletion, which its presence already says;
    /// resolving it doubled the reads and peak for a value nothing reads.
    ///
    /// Confined to the part of the keyspace `scope` admits. A node reading
    /// under a scope holds only that part of it, so an unscoped walk would
    /// descend into a subtree it was never sent and fail on an absence that
    /// is the design working (§5.5). Promotion's materialization is scoped
    /// exactly as the fetch that filled the trie was.
    ///
    /// The Lean operation `Trie.Diff.materialize` drives the walk and hands
    /// each change to `apply` through the `Apply` host service, in walk order;
    /// the scope is its Authorization-domain input.
    pub fn for_each_resolved_change_scoped<E, F>(
        &self,
        old_root: Hash,
        new_root: Hash,
        scope: &Scope,
        mut apply: F,
    ) -> Result<usize, E>
    where
        E: From<MptError>,
        F: FnMut(ChangeView<'_>) -> Result<(), E>,
    {
        let mut applier = crate::lean_storage::Applier {
            apply: &mut apply,
            stopped: None,
        };
        let walked = synch_verified::trie::materialize(
            &mut crate::lean_storage::Bytes(self.store()),
            &mut crate::lean_storage::Redactions(self.store()),
            &mut crate::lean_storage::Blake3,
            &mut applier,
            old_root.as_bytes(),
            new_root.as_bytes(),
            synch_verified::trie::ServeScope {
                prefixes: scope.prefixes().map(<[Vec<u8>]>::to_vec),
                exact: scope.exact().to_vec(),
            },
        )
        .map_err(crate::lean_storage::walk_error);
        // The caller's own error, not the sentinel that carried it out.
        if let Some(e) = applier.stopped {
            return Err(e);
        }
        Ok(usize::try_from(walked?).unwrap_or(usize::MAX))
    }
}

/// One change as a promotion applies it: the key, its kind, and the new
/// value's bytes.
///
/// Borrowed, and missing the old side on purpose — see
/// [`Trie::for_each_resolved_change_scoped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeView<'a> {
    /// The key.
    pub key: &'a [u8],
    /// Whether the key was added, changed, or deleted.
    pub kind: ChangeKind,
    /// The value under the new root, absent for a deletion.
    pub new: Option<&'a [u8]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemStore;

    /// The streaming diff hands each change over as it is found, so a caller
    /// that stops sees the rest of the walk not happen — what keeps the head
    /// flip's memory proportional to the largest single value, not their sum.
    #[test]
    fn resolved_changes_are_streamed_and_stop_where_the_caller_stops() {
        let s = MemStore::new();
        let t = Trie::new(&s);
        let mut root = Hash::EMPTY;
        for i in 0..64u8 {
            root = t.insert(root, &[i], b"v").unwrap();
        }

        // Nothing changed is nothing reported, however the walk is invoked.
        assert!(t.diff(Hash::EMPTY, Hash::EMPTY).unwrap().is_empty());

        let mut seen = 0usize;
        let stopped: Result<usize, MptError> =
            t.for_each_resolved_change_scoped(Hash::EMPTY, root, &Scope::full(), |_change| {
                seen += 1;
                Err(MptError::OddDepthValue)
            });
        assert!(matches!(stopped, Err(MptError::OddDepthValue)));
        assert_eq!(seen, 1, "the walk stopped at the first refusal");

        // And a caller that takes everything sees every change exactly once,
        // with only the new side resolved; the same set, sorted, is what
        // `diff` returns (the classification is asserted by the
        // `diff_completeness` property test).
        let mut keys = Vec::new();
        let count: usize = t
            .for_each_resolved_change_scoped(Hash::EMPTY, root, &Scope::full(), |change| {
                assert_eq!(change.kind, ChangeKind::Added);
                assert_eq!(change.new, Some(b"v".as_slice()));
                keys.push(change.key.to_vec());
                Ok::<(), MptError>(())
            })
            .unwrap();
        assert_eq!(count, 64);
        let changes = t.diff(Hash::EMPTY, root).unwrap();
        assert_eq!(changes.len(), 64);
        assert!(changes.windows(2).all(|w| w[0].key <= w[1].key));
    }
}
