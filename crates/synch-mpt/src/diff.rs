//! Structural diff between two roots (§5.2).
//!
//! The diff walks both tries in lockstep and prunes any subtree whose two sides
//! are structurally identical — which, because nodes are content-addressed, is
//! exactly the "only touched subtrees are visited" property that makes
//! re-materializing `entries` after a head flip cost `O(change)`.

use synch_core::Hash;

use crate::{
    error::MptError,
    nibbles::Nibbles,
    node::ValueRef,
    scope::Scope,
    store::NodeStore,
    trie::{root_opt, Cursor, Step, Trie},
};

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

impl Change {
    /// Classifies the change.
    pub fn kind(&self) -> ChangeKind {
        match (&self.old, &self.new) {
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), None) => ChangeKind::Deleted,
            _ => ChangeKind::Changed,
        }
    }
}

impl<S: NodeStore + ?Sized> Trie<'_, S> {
    /// Diffs two roots, returning one [`Change`] per differing key in
    /// lexicographic key order.
    pub fn diff(&self, old_root: Hash, new_root: Hash) -> Result<Vec<Change>, MptError> {
        self.diff_scoped(old_root, new_root, &Scope::full())
    }

    /// The same diff, confined to the part of the keyspace `scope` admits.
    ///
    /// A node reading under a scope holds only that part of it, so an unscoped
    /// diff would descend into a subtree it was never sent and fail on an
    /// absence that is the design working (§5.5). Promotion's materialization
    /// is scoped exactly as the fetch that filled the trie was.
    pub(crate) fn diff_scoped(
        &self,
        old_root: Hash,
        new_root: Hash,
        scope: &Scope,
    ) -> Result<Vec<Change>, MptError> {
        let mut out = Vec::new();
        self.diff_each_scoped(old_root, new_root, scope, |change| {
            out.push(change);
            Ok(())
        })?;
        out.sort_by(|x, y| x.key.cmp(&y.key));
        Ok(out)
    }

    /// Diffs two roots within `scope`, handing each [`Change`] to `emit` as it
    /// is found.
    ///
    /// Unordered, unlike [`Trie::diff`]: sorting needs the whole set in memory,
    /// which is the thing a streaming walk exists not to need.
    pub(crate) fn diff_each_scoped(
        &self,
        old_root: Hash,
        new_root: Hash,
        scope: &Scope,
        mut emit: impl FnMut(Change) -> Result<(), MptError>,
    ) -> Result<(), MptError> {
        if old_root == new_root {
            return Ok(());
        }
        let a = self.cursor_at(root_opt(old_root))?;
        let b = self.cursor_at(root_opt(new_root))?;
        self.diff_walk(a, b, scope, &mut emit)
    }

    /// Walks both tries in lockstep ([`Trie::descend`]), which is what holds
    /// the hostile-shape defences: this runs inside the head-promotion
    /// transaction (§5.2), holding the write lock, so an unbounded or
    /// overflowing walk here is a cluster-wide outage rather than a slow
    /// query.
    fn diff_walk(
        &self,
        a: Cursor,
        b: Cursor,
        scope: &Scope,
        emit: &mut dyn FnMut(Change) -> Result<(), MptError>,
    ) -> Result<(), MptError> {
        let mut path: Vec<u8> = Vec::new();
        if !self.enter(&a, &b, &path, emit)? {
            return Ok(());
        }
        self.descend((a, b), &mut path, &mut |pair, nibble, path| {
            // The same boundary the fetch stopped at: an out-of-scope position
            // holds nothing this node was sent, so descending it would fail on
            // an absence that is the design working. Tested before the cursors
            // are taken, since taking them reads the absent node (§5.5).
            if !scope.admits_path(path) {
                return Ok(Step::Skip);
            }
            let ca = self.cursor_child(&pair.0, nibble)?;
            let cb = self.cursor_child(&pair.1, nibble)?;
            // Charged only where something is actually there, as `collect`
            // charges only a non-empty child: a branch has sixteen slots and
            // an ordinary trie leaves most empty, so billing all sixteen
            // measured *frames entered* — sixteen times per real position —
            // against the ceiling the scan walk is measured by, and refused
            // the first-adoption diff of ~57 k files at §14's shape, well
            // inside the 100 k initial index §7.1 names.
            if ca.is_empty() && cb.is_empty() {
                return Ok(Step::Skip);
            }
            match self.enter(&ca, &cb, path, emit)? {
                true => Ok(Step::Descend((ca, cb))),
                false => Ok(Step::Visited),
            }
        })
    }

    /// Records the difference between the values at one position, and reports
    /// whether the subtree below it is worth descending into.
    fn enter(
        &self,
        a: &Cursor,
        b: &Cursor,
        path: &[u8],
        emit: &mut dyn FnMut(Change) -> Result<(), MptError>,
    ) -> Result<bool, MptError> {
        match (a.node_ref(), b.node_ref()) {
            (None, None) => return Ok(false),
            // Structural sharing: identical nodes have identical subtrees.
            (Some(x), Some(y)) if x == y => return Ok(false),
            _ => {}
        }
        let va = a.value_ref();
        let vb = b.value_ref();
        if !same_value(va, vb) {
            let key = Nibbles::from_nibbles(path)
                .to_bytes()
                .ok_or(MptError::OddDepthValue)?;
            emit(Change {
                key,
                old: va.cloned(),
                new: vb.cloned(),
            })?;
        }
        Ok(true)
    }

    /// Diffs two roots and resolves every value to bytes.
    ///
    /// Materializes the whole set, which is what makes it the wrong shape for
    /// applying a promotion: see [`Trie::for_each_resolved_change`].
    pub fn diff_resolved(
        &self,
        old_root: Hash,
        new_root: Hash,
    ) -> Result<Vec<ResolvedChange>, MptError> {
        self.diff_resolved_scoped(old_root, new_root, &Scope::full())
    }

    /// The same, confined to `scope`.
    pub(crate) fn diff_resolved_scoped(
        &self,
        old_root: Hash,
        new_root: Hash,
        scope: &Scope,
    ) -> Result<Vec<ResolvedChange>, MptError> {
        self.diff_scoped(old_root, new_root, scope)?
            .into_iter()
            .map(|c| {
                Ok(ResolvedChange {
                    old: c.old.as_ref().map(|v| self.resolve(v)).transpose()?,
                    new: c.new.as_ref().map(|v| self.resolve(v)).transpose()?,
                    key: c.key,
                })
            })
            .collect()
    }

    /// Streams the diff, resolving one value at a time, and reports how many
    /// changes were handed over.
    ///
    /// This is what a head promotion applies, and the difference from
    /// [`Trie::diff_resolved`] is a bound rather than a style: the walk ceiling
    /// bounds positions, not the bytes hanging off them — six canonical nodes
    /// describe 65 536 positions — so collecting `Vec<ResolvedChange>` meant
    /// resolving one large payload once per position, into memory, inside the
    /// transaction the flip runs in. An allocation failure there aborts rather
    /// than returning `Err`, so §12's per-origin containment never runs, and
    /// the pending head is durable: the next start reproduces it.
    ///
    /// Only the **new** side is resolved. The old side decides nothing but
    /// whether the change is a deletion, which its presence already says;
    /// resolving it doubled the reads and peak for a value nothing reads.
    pub fn for_each_resolved_change<E, F>(
        &self,
        old_root: Hash,
        new_root: Hash,
        apply: F,
    ) -> Result<usize, E>
    where
        E: From<MptError>,
        F: FnMut(ChangeView<'_>) -> Result<(), E>,
    {
        self.for_each_resolved_change_scoped(old_root, new_root, &Scope::full(), apply)
    }

    /// The same stream, confined to the part of the keyspace `scope` admits.
    ///
    /// A node reading under a scope holds only that part of it, so an unscoped
    /// walk would descend into a subtree it was never sent and fail on an
    /// absence that is the design working (§5.5). Promotion's materialization
    /// is scoped exactly as the fetch that filled the trie was.
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
        let mut count = 0usize;
        let mut stopped: Option<E> = None;
        let walked = self.diff_each_scoped(old_root, new_root, scope, |change| {
            let new = change.new.as_ref().map(|v| self.resolve(v)).transpose()?;
            let view = ChangeView {
                key: &change.key,
                kind: change.kind(),
                new: new.as_deref(),
            };
            match apply(view) {
                Ok(()) => {
                    count += 1;
                    Ok(())
                }
                Err(e) => {
                    stopped = Some(e);
                    Err(MptError::WalkStopped)
                }
            }
        });
        // The caller's own error, not the sentinel that carried it out.
        if let Some(e) = stopped {
            return Err(e);
        }
        walked?;
        Ok(count)
    }
}

/// True if two value references denote the same bytes.
///
/// `ValueRef` has two representations for one value — inline, or a hash of an
/// out-of-line payload — and which one a node carries is a storage decision,
/// not part of the value. Comparing references directly would report a change
/// where there is none: `Inline(x)` and `Hash(blake3(x))` resolve identically.
/// Nothing would be corrupted, but rows would re-materialize unchanged, the
/// "every reported key really differs" contract would break, and a peer could
/// force a full re-materialization by republishing with representations
/// flipped.
///
/// Compared without touching the store: the out-of-line hash *is* the BLAKE3
/// of the value, so the inline side can be hashed and compared directly.
fn same_value(a: Option<&ValueRef>, b: Option<&ValueRef>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => match (x, y) {
            (ValueRef::Inline(p), ValueRef::Inline(q)) => p == q,
            (ValueRef::Hash(p), ValueRef::Hash(q)) => p == q,
            (ValueRef::Inline(p), ValueRef::Hash(q)) | (ValueRef::Hash(q), ValueRef::Inline(p)) => {
                &Hash::new(p) == q
            }
        },
        _ => false,
    }
}

/// One change as a promotion applies it: the key, its kind, and the new
/// value's bytes.
///
/// Borrowed, and missing the old side on purpose — see
/// [`Trie::for_each_resolved_change`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeView<'a> {
    /// The key.
    pub key: &'a [u8],
    /// Whether the key was added, changed, or deleted.
    pub kind: ChangeKind,
    /// The value under the new root, absent for a deletion.
    pub new: Option<&'a [u8]>,
}

/// A [`Change`] with both sides resolved to bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedChange {
    /// The key.
    pub key: Vec<u8>,
    /// The value under the old root, if any.
    pub old: Option<Vec<u8>>,
    /// The value under the new root, if any.
    pub new: Option<Vec<u8>>,
}

impl ResolvedChange {
    /// Classifies the change.
    pub fn kind(&self) -> ChangeKind {
        match (&self.old, &self.new) {
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), None) => ChangeKind::Deleted,
            _ => ChangeKind::Changed,
        }
    }
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
            t.for_each_resolved_change(Hash::EMPTY, root, |_change| {
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
            .for_each_resolved_change(Hash::EMPTY, root, |change| {
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
