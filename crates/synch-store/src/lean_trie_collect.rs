//! Collecting the trie through the Lean domain program: which roots are
//! retained, what they reach, which completeness certificates survive, and
//! what is swept, all inside the one immediate transaction the pass insists
//! on. Rust binds the storage session, the digest behind the memo keys and
//! the memo itself, and names the diagnostics.

use std::collections::HashSet;

use synch_core::{origin::OriginParseError, Hash};
use synch_verified::{
    host,
    trie::{self, CollectError, TrieCollectDomainError as Domain},
};

use crate::{
    db::MemoMutation, gc::GcStats, lean_diagnostics, lean_storage::Session, Result, Store,
    StoreError,
};

fn error(error: CollectError<StoreError>) -> StoreError {
    use trie::OperationError;
    match error {
        CollectError::Operation(OperationError::Host(error)) => error,
        CollectError::Operation(OperationError::MalformedMetadata(_))
        | CollectError::Domain(Domain::Malformed) => {
            StoreError::Decode("invalid head history metadata".into())
        }
        CollectError::Operation(OperationError::Protocol) => {
            StoreError::invalid("invalid native trie-collection protocol")
        }
        CollectError::Domain(Domain::Decode(message)) => StoreError::Decode(message),
        CollectError::Domain(Domain::ColumnType {
            index,
            column,
            actual,
        }) => lean_diagnostics::column_type(index, column, actual),
        CollectError::Domain(Domain::Column { column, reason }) => match column.as_str() {
            "head_history.root" => StoreError::column("head_history.root", reason),
            "head_history.origin_id" => StoreError::column("head_history.origin_id", reason),
            _ => StoreError::invalid("unknown native trie-collection error column"),
        },
        CollectError::Domain(Domain::Origin(error)) => {
            use synch_verified::history::OriginError;
            let error = match error {
                OriginError::Label(text) => OriginParseError::Label(text),
                OriginError::Domain(text) => OriginParseError::Domain(text),
                OriginError::Shape(text) => OriginParseError::Shape(text),
                OriginError::KeyDecode => {
                    OriginParseError::Key("failed to decode base32 string".into())
                }
                OriginError::KeyData => {
                    OriginParseError::Key("data is not a valid public key".into())
                }
            };
            StoreError::column("head_history.origin_id", error.to_string())
        }
        // Nothing was swept: the transaction rolled back with the walk.
        CollectError::Domain(Domain::Exhausted) => {
            StoreError::invalid("the trie mark walk outran its budget; nothing was swept")
        }
    }
}

/// BLAKE3 over exactly the bytes Lean supplies for a memo key.
struct Blake3;

impl host::Digest for Blake3 {
    type Error = StoreError;
    fn blake3(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(Hash::new(bytes).as_bytes().to_vec())
    }
}

/// The completeness memo as a service. Forgetting begins the same mutation
/// the store's own transactions begin, and the guard it holds ends it when
/// the pass is over: after the storage session has committed or rolled back,
/// so a reader that started before the sweep cannot certify its snapshot.
struct Memo<'a> {
    store: &'a Store,
    mutation: Option<MemoMutation>,
}

impl host::Memo for Memo<'_> {
    type Error = StoreError;
    fn forget_except(&mut self, keep: &[&[u8]]) -> Result<()> {
        let keep = keep
            .iter()
            .map(|key| Hash::from_slice(key))
            .collect::<std::result::Result<HashSet<Hash>, _>>()
            .map_err(|_| StoreError::invalid("a memo key is not 32 bytes"))?;
        if self.mutation.is_none() {
            self.mutation = Some(self.store.begin_memo_mutation(&keep));
        }
        Ok(())
    }

    fn is_known(&mut self, key: &[u8]) -> Result<bool> {
        let key =
            Hash::from_slice(key).map_err(|_| StoreError::invalid("a memo key is not 32 bytes"))?;
        synch_mpt::NodeStore::is_known_complete(self.store, &key)
    }

    fn generation(&mut self) -> Result<u64> {
        synch_mpt::NodeStore::completeness_generation(self.store)
    }

    fn certify(&mut self, key: &[u8], generation: u64) -> Result<bool> {
        let key =
            Hash::from_slice(key).map_err(|_| StoreError::invalid("a memo key is not 32 bytes"))?;
        synch_mpt::NodeStore::note_complete_at(self.store, &key, generation)
    }
}

/// One mark-and-sweep pass over `trie_nodes`, `trie_node_origins` and
/// `trie_values`: the Lean command `trieCollect`.
pub(crate) fn gc_trie(store: &Store) -> Result<GcStats> {
    let scope = store.local_trie_scope()?;
    // Declared before the session so it is dropped after it: the memo
    // mutation ends only once the transaction has ended.
    let mut memo = Memo {
        store,
        mutation: None,
    };
    let mut digest = Blake3;
    let mut storage = Session::new(store);
    let collected = trie::collect(
        &mut storage,
        trie::CollectResources {
            digest: &mut digest,
            memo: &mut memo,
        },
        scope.prefixes(),
        scope.exact(),
    )
    .map_err(error)?;
    let count = |value: u64| usize::try_from(value).unwrap_or(usize::MAX);
    Ok(GcStats {
        nodes: count(collected.nodes),
        values: count(collected.values),
        roots_marked: count(collected.roots),
        ..GcStats::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{origin, store};
    use crate::Slot;
    use iroh_base::SecretKey;
    use synch_core::SignedHead;
    use synch_mpt::{NodeStore, Trie};

    fn publish(store: &Store, keys: &[&[u8]]) -> Hash {
        let trie = Trie::new(store);
        let mut root = Hash::EMPTY;
        for key in keys {
            root = trie.insert(root, key, &vec![7u8; 300]).unwrap();
        }
        root
    }

    /// Provenance rows name nodes; a row for a swept node would vouch, for
    /// the next trie to carry that hash, for a node this store no longer
    /// holds as anyone's. So they are swept with the same mark, and a
    /// retained root's provenance survives.
    #[test]
    fn provenance_is_swept_with_its_node_and_kept_with_a_retained_one() {
        let (_dir, store) = store();
        let key = SecretKey::generate();
        let old = publish(&store, &[b"f:s/a"]);
        let new = publish(&store, &[b"f:s/a", b"f:s/b"]);
        store.note_owned(&origin(), &old).unwrap();
        store.note_owned(&origin(), &new).unwrap();
        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&key, origin(), 2, new, 0),
                0,
                0,
            )
            .unwrap();
        let stats = store.gc_trie().unwrap();
        assert!(stats.nodes > 0);
        assert_eq!(stats.roots_marked, 1);
        assert!(!store.has_node(&old).unwrap());
        assert!(!store.owns_node(&origin(), &old).unwrap());
        assert!(store.owns_node(&origin(), &new).unwrap());
        assert!(Trie::new(&store).is_complete(new).unwrap());
        // The out-of-line values of the retained trie survive with it.
        assert!(Trie::new(&store)
            .get(new, b"f:s/b")
            .unwrap()
            .is_some_and(|value| value == vec![7u8; 300]));
    }

    /// The certificate of a root marked from survives, under the local
    /// scope and as its origin's own; an unretained root's does not, and a
    /// walk that started before the sweep cannot certify afterwards.
    #[test]
    fn the_sweep_keeps_exactly_the_marked_certificates() {
        let (_dir, store) = store();
        let key = SecretKey::generate();
        let retained = publish(&store, &[b"f:s/a"]);
        let displaced = publish(&store, &[b"f:s/z"]);
        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&key, origin(), 1, retained, 0),
                0,
                0,
            )
            .unwrap();
        let scope = store.local_trie_scope().unwrap();
        let owned = scope.memo_key_for(Some(&origin()), retained).unwrap();
        let before = store.completeness_generation().unwrap();
        store.note_complete(&retained).unwrap();
        store.note_complete(&owned).unwrap();
        store.note_complete(&displaced).unwrap();
        store.gc_trie().unwrap();
        assert!(store.is_known_complete(&retained).unwrap());
        assert!(store.is_known_complete(&owned).unwrap());
        assert!(!store.is_known_complete(&displaced).unwrap());
        assert!(
            !store.note_complete_at(&displaced, before).unwrap(),
            "a walk from before the sweep certifies nothing"
        );
        assert!(store.completeness_generation().unwrap() > before);
    }
}
