//! Serving trie nodes and values to a peer through the Lean domain program.
//! Lean owns which positions a scoped peer may see, what stands at each,
//! what a node reveals, whether this store vouches for it under the root's
//! origins, and one answer's budget; this module gathers the Authorization
//! inputs (the peer's scope and origins, and which of the root's origins are
//! confined), binds the storage session and names the diagnostics.

use synch_core::{now_ns, Hash, NodeId};
use synch_verified::trie::{self, ServeError, ServeScope, TrieServeDomainError};

use crate::{lean_diagnostics, Result, Store, StoreError};

fn error(error: ServeError<StoreError>) -> StoreError {
    use trie::OperationError;
    match error {
        ServeError::Operation(OperationError::Host(error)) => error,
        ServeError::Operation(OperationError::MalformedMetadata(_))
        | ServeError::Domain(TrieServeDomainError::Malformed) => {
            StoreError::Decode("invalid head history metadata".into())
        }
        ServeError::Operation(OperationError::Protocol) => {
            StoreError::invalid("invalid native trie-serving protocol")
        }
        // A root this node holds no head for, or only the asking peer's own,
        // vouches for no position: a delegate signs and publishes its own
        // trie, so a root of the caller's choosing is exactly what a peer's
        // own head is, and with one it could read every withheld subtree.
        ServeError::Domain(TrieServeDomainError::UnvouchedRoot) => {
            StoreError::invalid("requested positions against a root this node holds no head for")
        }
        ServeError::Domain(TrieServeDomainError::Decode(message)) => StoreError::Decode(message),
        ServeError::Domain(TrieServeDomainError::ColumnType {
            index,
            column,
            actual,
        }) => lean_diagnostics::column_type(index, column, actual),
        ServeError::Domain(TrieServeDomainError::Column { column, reason }) => {
            match column.as_str() {
                "head_history.origin_id" => StoreError::column("head_history.origin_id", reason),
                _ => StoreError::invalid("unknown native trie-serving error column"),
            }
        }
    }
}

fn hash_of(bytes: &[u8]) -> Result<Hash> {
    Hash::from_slice(bytes).map_err(|_| StoreError::invalid("a served hash is not 32 bytes"))
}

fn payloads(pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Vec<(Hash, Vec<u8>)>> {
    pairs
        .into_iter()
        .map(|(hash, data)| Ok((hash_of(&hash)?, data)))
        .collect()
}

fn hashes(list: &[Vec<u8>]) -> Result<Vec<Hash>> {
    list.iter().map(|hash| hash_of(hash)).collect()
}

fn wanted(wants: &[(Vec<u8>, Hash)]) -> Vec<(Vec<u8>, [u8; 32])> {
    wants
        .iter()
        .map(|(path, claimed)| (path.clone(), *claimed.as_bytes()))
        .collect()
}

impl Store {
    /// The Authorization-domain inputs of one served request: the scope the
    /// asking peer reads under and the origins its key speaks for, and which
    /// of the root's head origins confine provenance (a node under a confined
    /// origin's root travels only with this store's provenance for it).
    fn serving_inputs(
        &self,
        peer: &NodeId,
        root: &Hash,
    ) -> Result<(ServeScope, Vec<String>, Vec<String>)> {
        let now = now_ns();
        let (scope, origins) = self.scope_for_key_with_origins(peer, now)?;
        let scope = ServeScope {
            prefixes: scope.prefixes().map(<[Vec<u8>]>::to_vec),
            exact: scope.exact().to_vec(),
        };
        let peer_origins = origins.iter().map(|origin| origin.canonical()).collect();
        let mut confined = Vec::new();
        for origin in self.head_root_origins(root)? {
            if self.provenance_owner(&origin, now)?.is_some() {
                confined.push(origin.canonical());
            }
        }
        Ok((scope, peer_origins, confined))
    }

    /// The nodes a peer asked for by position under a root: served payloads,
    /// the hashes this node did not have, and the positions the peer may not
    /// see past (§5.5). The Lean command `Trie.Serve.serveNodes`.
    #[allow(clippy::type_complexity)]
    pub fn serve_trie_nodes(
        &self,
        peer: &NodeId,
        root: &Hash,
        wants: &[(Vec<u8>, Hash)],
    ) -> Result<(Vec<(Hash, Vec<u8>)>, Vec<Hash>, Vec<Hash>)> {
        let (scope, peer_origins, confined) = self.serving_inputs(peer, root)?;
        let mut storage = crate::lean_storage::Session::new(self);
        let answer = trie::serve_nodes(
            &mut storage,
            root.as_bytes(),
            &wanted(wants),
            scope,
            peer_origins,
            confined,
        )
        .map_err(error)?;
        Ok((
            payloads(answer.nodes)?,
            hashes(&answer.missing)?,
            hashes(&answer.redacted)?,
        ))
    }

    /// The out-of-line values a peer asked for, each authorized by the
    /// position of the node that holds it when the peer's view is scoped.
    /// The Lean command `Trie.Serve.serveValues`.
    #[allow(clippy::type_complexity)]
    pub fn serve_trie_values(
        &self,
        peer: &NodeId,
        root: &Hash,
        wants: &[(Vec<u8>, Hash)],
    ) -> Result<(Vec<(Hash, Vec<u8>)>, Vec<Hash>)> {
        let (scope, peer_origins, confined) = self.serving_inputs(peer, root)?;
        let mut storage = crate::lean_storage::Session::new(self);
        let answer = trie::serve_values(
            &mut storage,
            root.as_bytes(),
            &wanted(wants),
            scope,
            peer_origins,
            confined,
        )
        .map_err(error)?;
        Ok((payloads(answer.values)?, hashes(&answer.missing)?))
    }

    /// What stands at each nibble position under a root, in the caller's
    /// order: the descent reads this store and nothing else, so a position
    /// cannot be claimed into existence. The Lean command `Trie.Serve.resolvePaths`.
    pub fn resolve_trie_paths(&self, root: &Hash, paths: &[Vec<u8>]) -> Result<Vec<Option<Hash>>> {
        let mut storage = crate::lean_storage::Session::new(self);
        trie::resolve_paths(&mut storage, root.as_bytes(), paths)
            .map_err(error)?
            .into_iter()
            .map(|found| found.as_deref().map(hash_of).transpose())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::missing_oracle::MissingWalk;
    use crate::testutil::store;
    use crate::{Binding, BindingSource, Slot};
    use synch_core::{OriginId, SignedHead};
    use synch_mpt::{MemStore, Nibbles, NodeStore, Scope, Trie, TrieNode};

    fn publish(store: &Store, keys: &[&[u8]]) -> Hash {
        let trie = Trie::new(store);
        let mut root = Hash::EMPTY;
        for key in keys {
            root = trie.insert(root, key, key).unwrap();
        }
        root
    }

    /// The positions a walk emits under `root`, paired with the hashes it
    /// claims for them, copying every node it meets into `into`.
    fn positions(store: &Store, root: Hash, scope: Scope, into: &MemStore) -> Vec<(Vec<u8>, Hash)> {
        let mut walk = MissingWalk::scoped(None, root, scope);
        let mut wants: Vec<(Vec<u8>, Hash)> = Vec::new();
        loop {
            let batch = walk.next_batch(&Trie::new(into), 64).unwrap();
            if batch.is_empty() {
                break;
            }
            for (path, hash) in &batch.nodes {
                let bytes = store.get_node(hash).unwrap().unwrap();
                into.put_node(hash, &bytes).unwrap();
                wants.push((path.clone(), *hash));
            }
            for (_, hash) in &batch.values {
                let bytes = store.get_value(hash).unwrap().unwrap();
                into.put_value(hash, &bytes).unwrap();
            }
            walk.resume();
        }
        wants
    }

    /// A key rooted in configuration, speaking for `origin`.
    fn rooted(store: &Store, origin: &OriginId) -> NodeId {
        let key = iroh_base::SecretKey::generate().public();
        store
            .put_binding(&Binding {
                origin: origin.clone(),
                node_id: key,
                source: BindingSource::Static,
                domain: None,
                issuer: None,
                spaces: Vec::new(),
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        key
    }

    /// A key `issuer` delegated `spaces` to.
    fn delegated(store: &Store, issuer: &OriginId, spaces: &[&str]) -> NodeId {
        let key = iroh_base::SecretKey::generate().public();
        store
            .put_binding(&Binding {
                origin: OriginId::Key(key),
                node_id: key,
                source: BindingSource::Delegated,
                domain: None,
                issuer: Some(issuer.clone()),
                spaces: spaces.iter().map(|s| s.to_string()).collect(),
                note: None,
                added_at: 0,
                expires_at: Some(i64::MAX),
            })
            .unwrap();
        key
    }

    #[test]
    fn a_claimed_position_resolves_to_what_is_really_there() {
        let (_dir, store) = store();
        let root = publish(
            &store,
            &[b"f:photos/a.jpg", b"f:photos/b.jpg", b"f:finance/q3.pdf"],
        );
        // The positions a real walk emits, paired with the hashes it claims
        // for them, resolve on the server's own copy to exactly those hashes.
        let wants = positions(&store, root, Scope::full(), &MemStore::new());
        assert!(wants.len() > 1, "the trie is too small to be a test");
        let paths: Vec<Vec<u8>> = wants.iter().map(|(path, _)| path.clone()).collect();
        let resolved = store.resolve_trie_paths(&root, &paths).unwrap();
        for (index, (_, claimed)) in wants.iter().enumerate() {
            assert_eq!(
                resolved[index],
                Some(*claimed),
                "a real position did not resolve"
            );
        }
        // A position that names nothing resolves to nothing, and the merged
        // descent agrees with resolving each path alone.
        let nowhere = Nibbles::from_bytes(b"zzzz").as_slice().to_vec();
        assert_eq!(
            store.resolve_trie_paths(&root, &[nowhere]).unwrap()[0],
            None
        );
        for (index, path) in paths.iter().enumerate() {
            let alone = store
                .resolve_trie_paths(&root, std::slice::from_ref(path))
                .unwrap();
            assert_eq!(resolved[index], alone[0], "batching changed an answer");
        }
        assert_eq!(
            store.resolve_trie_paths(&Hash::EMPTY, &paths).unwrap(),
            vec![None; paths.len()]
        );
    }

    #[test]
    fn a_rooted_peer_is_answered_by_hash() {
        let (_dir, store) = store();
        let root = publish(&store, &[b"f:photos/a.jpg", b"f:photos/b.jpg"]);
        let peer = rooted(&store, &OriginId::named("laptop", "x.example").unwrap());
        let bogus = Hash::new(b"nowhere");
        // The positions are not consulted, and a hash named twice is served
        // once, whatever it was claimed to sit under.
        let (nodes, missing, redacted) = store
            .serve_trie_nodes(
                &peer,
                &root,
                &[(vec![], root), (vec![9, 9], root), (vec![9], bogus)],
            )
            .unwrap();
        assert_eq!(nodes.len(), 1, "a hash named twice is served once");
        assert_eq!(nodes[0].0, root);
        assert!(TrieNode::decode(&nodes[0].1).is_ok());
        assert_eq!(missing, vec![bogus]);
        assert!(redacted.is_empty());
        // And a value by its hash, with no descent paid for.
        let value = b"v".repeat(synch_core::INLINE_VALUE_MAX + 1);
        let root = Trie::new(&store)
            .insert(root, b"f:photos/c.jpg", &value)
            .unwrap();
        let value_hash = Hash::new(&value);
        let (values, missing) = store
            .serve_trie_values(&peer, &root, &[(vec![9], value_hash), (vec![], bogus)])
            .unwrap();
        assert_eq!(values, vec![(value_hash, value)]);
        assert_eq!(missing, vec![bogus]);
    }

    /// A delegate sees its spaces and the spine above them, and nothing that
    /// spells another space's name (§5.5).
    #[test]
    fn a_scoped_peer_sees_its_grant_and_not_its_sibling() {
        let (_dir, store) = store();
        let issuer = OriginId::named("nas", "x.example").unwrap();
        let issuer_key = iroh_base::SecretKey::generate();
        store
            .put_binding(&Binding {
                origin: issuer.clone(),
                node_id: issuer_key.public(),
                source: BindingSource::Static,
                domain: None,
                issuer: None,
                spaces: Vec::new(),
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        let delegate = delegated(&store, &issuer, &["photos"]);
        let root = publish(
            &store,
            &[
                b"f:photos/a.jpg",
                b"f:photos/b.jpg",
                b"f:finance/q3.pdf",
                b"m:space/photos",
                b"m:space/finance",
            ],
        );
        let unscoped = positions(&store, root, Scope::full(), &MemStore::new());

        // Before the issuer's head is recorded, the root vouches for nothing.
        let refused = store.serve_trie_nodes(&delegate, &root, &unscoped[..1]);
        assert!(
            matches!(refused, Err(StoreError::Invalid(_))),
            "a root this node holds no head for: {refused:?}"
        );
        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&issuer_key, issuer.clone(), 1, root, 0),
                0,
                0,
            )
            .unwrap();

        // Every position the scoped walk asks for is answered or redacted
        // and the delegate's copy ends up holding its space and not the
        // other one.
        let scope = Scope::of(&synch_core::scope_prefixes(&["photos".to_string()]));
        let copy = MemStore::new();
        let mut walk = MissingWalk::scoped(None, root, scope.clone());
        let mut served_any = true;
        while served_any {
            served_any = false;
            let batch = walk.next_batch(&Trie::new(&copy), 64).unwrap();
            if batch.is_empty() {
                break;
            }
            let (nodes, missing, redacted) = store
                .serve_trie_nodes(&delegate, &root, &batch.nodes)
                .unwrap();
            assert!(
                missing.is_empty() && redacted.is_empty(),
                "an honest walk asks within its grant"
            );
            for (hash, bytes) in nodes {
                copy.put_node(&hash, &bytes).unwrap();
                served_any = true;
            }
            walk.resume();
        }
        assert!(walk.is_exhausted(), "the scoped walk was served whole");
        let view = Trie::new(&copy);
        assert_eq!(
            view.get(root, b"f:photos/a.jpg").unwrap().as_deref(),
            Some(b"f:photos/a.jpg".as_slice())
        );
        assert_eq!(
            view.get(root, b"m:space/photos").unwrap().as_deref(),
            Some(b"m:space/photos".as_slice())
        );
        for (_, hash) in &unscoped {
            if let Some(bytes) = copy.get_node(hash).unwrap() {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                assert!(
                    !text.contains("finance"),
                    "a served node spells the sibling"
                );
            }
        }
        assert!(
            view.get(root, b"f:finance/q3.pdf").is_err() || {
                view.get(root, b"f:finance/q3.pdf").unwrap().is_none()
            }
        );

        // A position the grant does not admit is refused whatever hash is
        // claimed there, and an admitted position that holds nothing cannot
        // be talked into holding the withheld hash.
        let withheld: Vec<&(Vec<u8>, Hash)> = unscoped
            .iter()
            .filter(|(path, _)| !scope.admits_path(path))
            .collect();
        assert!(!withheld.is_empty());
        for (path, hash) in &withheld {
            let (nodes, missing, _) = store
                .serve_trie_nodes(&delegate, &root, &[(path.clone(), *hash)])
                .unwrap();
            assert!(nodes.is_empty(), "an out-of-scope position was served");
            assert_eq!(missing, vec![*hash]);
            let inside = Nibbles::from_bytes(b"f:photos/nothing-here")
                .as_slice()
                .to_vec();
            let (nodes, missing, _) = store
                .serve_trie_nodes(&delegate, &root, &[(inside, *hash)])
                .unwrap();
            assert!(
                nodes.is_empty(),
                "a claimed hash was served at an empty position"
            );
            assert_eq!(missing, vec![*hash]);
        }

        // A node at an admitted position is still judged by what it reveals:
        // a trie holding only the sibling space collapses to a leaf at the
        // root, and that leaf spells the sibling's name.
        let lone = publish(&store, &[b"f:finance/q3.pdf"]);
        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&issuer_key, issuer.clone(), 2, lone, 0),
                0,
                0,
            )
            .unwrap();
        let (nodes, missing, redacted) = store
            .serve_trie_nodes(&delegate, &lone, &[(vec![], lone)])
            .unwrap();
        assert!(nodes.is_empty() && missing.is_empty());
        assert_eq!(redacted, vec![lone]);

        // A value is served by the coverage of the node that holds it.
        let long = b"w".repeat(synch_core::INLINE_VALUE_MAX * 4);
        let root = Trie::new(&store)
            .insert(root, b"m:space/finance", &long)
            .unwrap();
        let root = Trie::new(&store)
            .insert(root, b"m:space/photos", &long)
            .unwrap();
        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&issuer_key, issuer.clone(), 3, root, 0),
                0,
                0,
            )
            .unwrap();
        let value = Hash::new(&long);
        let holders = positions(&store, root, Scope::full(), &MemStore::new());
        let photos = Nibbles::from_bytes(b"m:space/photos").as_slice().to_vec();
        let finance = Nibbles::from_bytes(b"m:space/finance").as_slice().to_vec();
        let holder_of = |key: &[u8]| -> Vec<u8> {
            holders
                .iter()
                .map(|(path, _)| path.clone())
                .filter(|path| key.starts_with(path))
                .max_by_key(|path| path.len())
                .unwrap()
        };
        let (values, missing) = store
            .serve_trie_values(&delegate, &root, &[(holder_of(&photos), value)])
            .unwrap();
        assert_eq!(
            values.len(),
            1,
            "the granted space's record goes out: {missing:?}"
        );
        let (values, missing) = store
            .serve_trie_values(&delegate, &root, &[(holder_of(&finance), value)])
            .unwrap();
        assert!(values.is_empty(), "the sibling's record does not");
        assert_eq!(missing, vec![value]);
    }
}
