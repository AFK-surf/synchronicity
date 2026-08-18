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
    store::NodeStore,
    trie::{root_opt, Cursor, FanoutGuard, Frame, Trie, MAX_DEPTH_NIBBLES},
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
        let mut out = Vec::new();
        self.diff_each(old_root, new_root, |change| {
            out.push(change);
            Ok(())
        })?;
        out.sort_by(|x, y| x.key.cmp(&y.key));
        Ok(out)
    }

    /// Diffs two roots, handing each [`Change`] to `emit` as it is found.
    ///
    /// Unordered, unlike [`Trie::diff`]: sorting needs the whole set in memory,
    /// which is the thing a streaming walk exists not to need.
    pub fn diff_each(
        &self,
        old_root: Hash,
        new_root: Hash,
        mut emit: impl FnMut(Change) -> Result<(), MptError>,
    ) -> Result<(), MptError> {
        if old_root == new_root {
            return Ok(());
        }
        let a = self.cursor_at(root_opt(old_root))?;
        let b = self.cursor_at(root_opt(new_root))?;
        self.diff_walk(a, b, &mut emit)
    }

    /// Walks both tries in lockstep with an explicit heap stack.
    ///
    /// The new root is a peer's, reached over the network, and the *shape* it
    /// describes is not canonicalized by anything the fetch checks — a hostile
    /// peer can chain extension nodes to any depth. Recursion here would meet
    /// that with a stack overflow, which aborts the process rather than
    /// returning an error, and this walk runs inside head promotion (§5.2), so
    /// the frames live on the heap and the descent stops at
    /// [`MAX_DEPTH_NIBBLES`] — past which no key short enough to be valid can
    /// begin (§12).
    fn diff_walk(
        &self,
        a: Cursor,
        b: Cursor,
        emit: &mut dyn FnMut(Change) -> Result<(), MptError>,
    ) -> Result<(), MptError> {
        let mut path: Vec<u8> = Vec::new();
        let mut stack: Vec<(Frame, Cursor)> = Vec::new();
        // Keeps the diff proportional to the two tries. This runs inside the
        // head-promotion transaction, holding the write lock, so an unbounded
        // walk here is a cluster-wide outage rather than a slow query.
        let mut guard = FanoutGuard::default();

        if !self.enter(&a, &b, &path, emit)? {
            return Ok(());
        }
        stack.push((Frame { cursor: a, next: 0 }, b));

        while let Some(top) = stack.len().checked_sub(1) {
            let nibble = stack[top].0.next;
            if nibble >= 16 || path.len() >= MAX_DEPTH_NIBBLES {
                stack.pop();
                path.pop();
                continue;
            }
            stack[top].0.next += 1;
            let ca = self.cursor_child(&stack[top].0.cursor, nibble)?;
            let cb = self.cursor_child(&stack[top].1, nibble)?;
            // Charged only where something is actually there, exactly as
            // `collect` charges only a non-empty child. A branch node has
            // sixteen slots and an ordinary trie leaves most of them empty, so
            // billing all sixteen made the guard measure *frames entered*
            // rather than positions visited — sixteen times the cost per real
            // position, against the same ceiling the scan walk is measured by.
            // At §14's one-`f:`-and-one-`b:`-per-file shape that refused the
            // first-adoption diff of ~57 k files, well inside the 100 k initial
            // index §7.1 names.
            if ca.is_empty() && cb.is_empty() {
                continue;
            }
            path.push(nibble);
            guard.visit()?;
            if self.enter(&ca, &cb, &path, emit)? {
                stack.push((
                    Frame {
                        cursor: ca,
                        next: 0,
                    },
                    cb,
                ));
            } else {
                path.pop();
            }
        }
        Ok(())
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
        self.diff(old_root, new_root)?
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
    /// [`Trie::diff_resolved`] is a bound rather than a style. `FanoutGuard`
    /// caps a structural walk at `WALK_POSITION_CEILING` *positions*, which is
    /// a bound on the walk's work and says nothing about the bytes hanging off
    /// it: a trie can put one large value at very many positions and still come
    /// in well under the ceiling — six canonical nodes describe 65 536
    /// positions — so collecting `Vec<ResolvedChange>` first meant resolving
    /// that payload once per position, into memory, inside the transaction the
    /// flip runs in. An allocation failure there is an abort rather than an
    /// `Err`, so the per-origin containment §12 promises never runs, and the
    /// pending head is durable: the next start reproduces it.
    ///
    /// Only the **new** side is resolved. The old side decides nothing but
    /// whether the change is a deletion, which its presence already says, and
    /// resolving it doubled the reads and the peak for a value nothing reads.
    pub fn for_each_resolved_change<E, F>(
        &self,
        old_root: Hash,
        new_root: Hash,
        mut apply: F,
    ) -> Result<usize, E>
    where
        E: From<MptError>,
        F: FnMut(ChangeView<'_>) -> Result<(), E>,
    {
        let mut count = 0usize;
        let mut stopped: Option<E> = None;
        let walked = self.diff_each(old_root, new_root, |change| {
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
/// not part of the value. Comparing the references directly would report a
/// change where there is none: `Inline(x)` and `Hash(blake3(x))` resolve
/// identically. That produces no false negatives, so nothing would be
/// corrupted by it, but it would re-materialize rows that have not changed,
/// break the "every reported key really differs" contract the property tests
/// assert, and let a peer force a full re-materialization of an unchanged trie
/// by republishing it with the representations flipped.
///
/// Compared without touching the store: the out-of-line hash *is* the BLAKE3 of
/// the value, so the inline side can be hashed and the two compared directly.
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

/// One change as a promotion applies it: the key, what kind of change it is,
/// and the new value's bytes.
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
    /// that stops sees the rest of the walk not happen.
    ///
    /// This is the property that bounds the peak: `diff_resolved` materializes
    /// every changed value before the caller sees any of them, and a trie can
    /// put one large value at very many positions while staying well inside the
    /// walk's position ceiling. Applying one at a time is what keeps the head
    /// flip's memory proportional to the largest single value rather than to
    /// their sum.
    #[test]
    fn resolved_changes_are_streamed_and_stop_where_the_caller_stops() {
        let s = MemStore::new();
        let t = Trie::new(&s);
        let mut root = Hash::EMPTY;
        for i in 0..64u8 {
            root = t.insert(root, &[i], b"v").unwrap();
        }

        let mut seen = 0usize;
        let stopped: Result<usize, MptError> =
            t.for_each_resolved_change(Hash::EMPTY, root, |_change| {
                seen += 1;
                Err(MptError::OddDepthValue)
            });
        assert!(matches!(stopped, Err(MptError::OddDepthValue)));
        assert_eq!(seen, 1, "the walk stopped at the first refusal");

        // And a caller that takes everything sees every change exactly once,
        // with only the new side resolved.
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
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 64);
    }

    #[test]
    fn diff_of_equal_roots_is_empty() {
        let s = MemStore::new();
        let t = Trie::new(&s);
        let root = t.insert(Hash::EMPTY, b"a", b"1").unwrap();
        assert!(t.diff(root, root).unwrap().is_empty());
        assert!(t.diff(Hash::EMPTY, Hash::EMPTY).unwrap().is_empty());
    }

    #[test]
    fn diff_reports_add_change_delete() {
        let s = MemStore::new();
        let t = Trie::new(&s);
        let mut a = Hash::EMPTY;
        a = t.insert(a, b"keep", b"same").unwrap();
        a = t.insert(a, b"edit", b"before").unwrap();
        a = t.insert(a, b"gone", b"bye").unwrap();

        let mut b = a;
        b = t.insert(b, b"edit", b"after").unwrap();
        b = t.remove(b, b"gone").unwrap();
        b = t.insert(b, b"new", b"hello").unwrap();

        let changes = t.diff_resolved(a, b).unwrap();
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].key, b"edit".to_vec());
        assert_eq!(changes[0].kind(), ChangeKind::Changed);
        assert_eq!(changes[0].old.as_deref(), Some(b"before".as_slice()));
        assert_eq!(changes[0].new.as_deref(), Some(b"after".as_slice()));
        assert_eq!(changes[1].key, b"gone".to_vec());
        assert_eq!(changes[1].kind(), ChangeKind::Deleted);
        assert_eq!(changes[2].key, b"new".to_vec());
        assert_eq!(changes[2].kind(), ChangeKind::Added);
    }

    #[test]
    fn diff_from_empty_lists_everything() {
        let s = MemStore::new();
        let t = Trie::new(&s);
        let mut root = Hash::EMPTY;
        for k in ["a", "b", "c"] {
            root = t.insert(root, k.as_bytes(), b"v").unwrap();
        }
        let changes = t.diff(Hash::EMPTY, root).unwrap();
        assert_eq!(changes.len(), 3);
        assert!(changes.iter().all(|c| c.kind() == ChangeKind::Added));

        let reverse = t.diff(root, Hash::EMPTY).unwrap();
        assert_eq!(reverse.len(), 3);
        assert!(reverse.iter().all(|c| c.kind() == ChangeKind::Deleted));
    }

    #[test]
    fn diff_handles_out_of_line_values() {
        let s = MemStore::new();
        let t = Trie::new(&s);
        let big_a = vec![1u8; 300];
        let big_b = vec![2u8; 300];
        let a = t.insert(Hash::EMPTY, b"k", &big_a).unwrap();
        let b = t.insert(a, b"k", &big_b).unwrap();
        let changes = t.diff_resolved(a, b).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old.as_deref(), Some(big_a.as_slice()));
        assert_eq!(changes[0].new.as_deref(), Some(big_b.as_slice()));
    }

    #[test]
    fn diff_prunes_unchanged_subtrees() {
        // A deep, wide trie with a single changed leaf must not require loading
        // the whole thing: we approximate that here by asserting the diff is
        // exactly one change over a large trie.
        let s = MemStore::new();
        let t = Trie::new(&s);
        let mut root = Hash::EMPTY;
        for i in 0..500u16 {
            root = t
                .insert(root, format!("f:space/dir{i:04}/file").as_bytes(), b"v")
                .unwrap();
        }
        let root2 = t.insert(root, b"f:space/dir0250/file", b"w").unwrap();
        let changes = t.diff(root, root2).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key, b"f:space/dir0250/file".to_vec());
    }

    #[test]
    fn diff_across_shape_changes() {
        // Inserting a key that forces an extension node to split changes the
        // shape at the top; the diff must still report exactly one addition.
        let s = MemStore::new();
        let t = Trie::new(&s);
        let mut a = Hash::EMPTY;
        a = t.insert(a, b"prefix/aaa", b"1").unwrap();
        a = t.insert(a, b"prefix/aab", b"2").unwrap();
        let b = t.insert(a, b"zzz", b"3").unwrap();
        let changes = t.diff(a, b).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key, b"zzz".to_vec());
    }
}
