//! Merkle proofs for single keys (§4.3).
//!
//! A proof is the node path from the root down to where the key resolves — or
//! to where it provably dead-ends. Verification is self-contained: it needs the
//! root hash and the proof, nothing else, which is what lets a holder of one
//! signed head answer for one key without shipping a whole trie — the
//! capability partial replication (§13) is built on.
//!
//! **Not on any wire.** This module is behind the off-by-default `proofs`
//! feature and has no caller in the workspace; no `MptMessage` carries a
//! `Proof`, so nothing here decodes peer-supplied input today. Two things
//! follow, and both have been mistaken for defects. `verify` bounds its input
//! only by what the caller already materialized, which is correct while the
//! caller is local and is the first thing to revisit if this is ever put on a
//! wire. And `synch_core::MAX_PROOF_NODES` is *not* the bound it is missing:
//! that constant sizes **bao hash-tree slice proofs** in the blob path
//! (`synch-net`'s `GetProof`), a different structure for a different purpose.
//! Partial replication is what would make this live; §13 is where that is.

use serde::{Deserialize, Serialize};
use synch_core::Hash;

use crate::{
    error::MptError,
    nibbles::Nibbles,
    node::{TrieNode, ValueRef},
    store::{MemStore, NodeStore},
    trie::{root_opt, Trie},
};

/// A Merkle proof for a single key against a root.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// The encoded nodes on the path from the root, root first.
    pub nodes: Vec<Vec<u8>>,
    /// The out-of-line value payload, when the proved value is not inline.
    pub value: Option<Vec<u8>>,
}

impl Proof {
    /// Verifies this proof against `root` for `key`.
    ///
    /// Returns the proved value, or `None` for a proof of absence. Any node
    /// that does not hash correctly, or a path that is not fully covered by the
    /// proof, is an error — a prover cannot claim absence by omission.
    pub fn verify(&self, root: Hash, key: &[u8]) -> Result<Option<Vec<u8>>, MptError> {
        let store = MemStore::new();
        for encoded in &self.nodes {
            let hash = TrieNode::hash_of_encoded(encoded)?;
            store
                .put_node(&hash, encoded)
                .expect("in-memory store is infallible");
        }
        if let Some(value) = &self.value {
            let hash = Hash::new(value);
            store
                .put_value(&hash, value)
                .expect("in-memory store is infallible");
        }
        Trie::new(&store).get(root, key)
    }
}

impl<S: NodeStore + ?Sized> Trie<'_, S> {
    /// Builds a Merkle proof for `key` against `root`.
    pub fn prove(&self, root: Hash, key: &[u8]) -> Result<Proof, MptError> {
        let nibbles = Nibbles::from_bytes(key);
        let mut rest = nibbles.as_slice();
        let mut current = root_opt(root);
        let mut proof = Proof::default();
        loop {
            let Some(hash) = current else {
                return Ok(proof);
            };
            let encoded = self
                .store()
                .get_node(&hash)
                .map_err(MptError::store)?
                .ok_or(MptError::MissingNode(hash))?;
            proof.nodes.push(encoded.clone());
            match TrieNode::decode(&encoded)? {
                TrieNode::Leaf { key_rest, value } => {
                    if key_rest.as_slice() == rest {
                        if let ValueRef::Hash(h) = value {
                            proof.value = Some(self.resolve(&ValueRef::Hash(h))?);
                        }
                    }
                    return Ok(proof);
                }
                TrieNode::Ext { prefix, child } => {
                    let p = prefix.as_slice();
                    if !rest.starts_with(p) {
                        return Ok(proof);
                    }
                    rest = &rest[p.len()..];
                    current = Some(child);
                }
                TrieNode::Branch { children, value } => {
                    if rest.is_empty() {
                        if let Some(ValueRef::Hash(h)) = value {
                            proof.value = Some(self.resolve(&ValueRef::Hash(h))?);
                        }
                        return Ok(proof);
                    }
                    current = children[rest[0] as usize];
                    rest = &rest[1..];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemStore;

    fn populated() -> (MemStore, Hash) {
        let store = MemStore::new();
        let trie = Trie::new(&store);
        let mut root = Hash::EMPTY;
        for i in 0..64u16 {
            root = trie
                .insert(root, format!("f:space/file{i:03}").as_bytes(), b"entry")
                .unwrap();
        }
        root = trie.insert(root, b"f:space/big", &vec![7u8; 400]).unwrap();
        (store, root)
    }

    #[test]
    fn proves_presence() {
        let (store, root) = populated();
        let trie = Trie::new(&store);
        let proof = trie.prove(root, b"f:space/file007").unwrap();
        assert_eq!(
            proof.verify(root, b"f:space/file007").unwrap(),
            Some(b"entry".to_vec())
        );
        // A proof is much smaller than the trie it came from.
        assert!(proof.nodes.len() < store.node_count());
    }

    #[test]
    fn proves_out_of_line_values() {
        let (store, root) = populated();
        let trie = Trie::new(&store);
        let proof = trie.prove(root, b"f:space/big").unwrap();
        assert!(proof.value.is_some());
        assert_eq!(
            proof.verify(root, b"f:space/big").unwrap(),
            Some(vec![7u8; 400])
        );
    }

    #[test]
    fn proves_absence() {
        let (store, root) = populated();
        let trie = Trie::new(&store);
        for key in [
            b"f:space/file999".as_slice(),
            b"zzz".as_slice(),
            b"f:".as_slice(),
        ] {
            let proof = trie.prove(root, key).unwrap();
            assert_eq!(proof.verify(root, key).unwrap(), None);
        }
    }

    #[test]
    fn empty_trie_proof() {
        let store = MemStore::new();
        let trie = Trie::new(&store);
        let proof = trie.prove(Hash::EMPTY, b"anything").unwrap();
        assert!(proof.nodes.is_empty());
        assert_eq!(proof.verify(Hash::EMPTY, b"anything").unwrap(), None);
    }

    #[test]
    fn tampered_node_fails_verification() {
        let (store, root) = populated();
        let trie = Trie::new(&store);
        let mut proof = trie.prove(root, b"f:space/file007").unwrap();
        let last = proof.nodes.last_mut().unwrap();
        let idx = last.len() - 1;
        last[idx] ^= 0xff;
        // Either the node no longer decodes, or it hashes to something the walk
        // cannot reach from the root. Both are errors, never a silent success.
        assert!(proof.verify(root, b"f:space/file007").is_err());
    }

    #[test]
    fn truncated_proof_cannot_claim_absence() {
        let (store, root) = populated();
        let trie = Trie::new(&store);
        let mut proof = trie.prove(root, b"f:space/file007").unwrap();
        proof.nodes.pop();
        assert!(matches!(
            proof.verify(root, b"f:space/file007"),
            Err(MptError::MissingNode(_))
        ));
    }

    #[test]
    fn proof_does_not_verify_against_another_root() {
        let (store, root) = populated();
        let trie = Trie::new(&store);
        let other = trie.insert(root, b"f:space/file007", b"changed").unwrap();
        let proof = trie.prove(root, b"f:space/file007").unwrap();
        assert!(proof.verify(other, b"f:space/file007").is_err());
    }

    #[test]
    fn substituted_value_fails() {
        let (store, root) = populated();
        let trie = Trie::new(&store);
        let mut proof = trie.prove(root, b"f:space/big").unwrap();
        proof.value = Some(vec![8u8; 400]);
        assert!(matches!(
            proof.verify(root, b"f:space/big"),
            Err(MptError::MissingValue(_))
        ));
    }

    #[test]
    fn proof_round_trips_on_the_wire() {
        let (store, root) = populated();
        let trie = Trie::new(&store);
        let proof = trie.prove(root, b"f:space/file007").unwrap();
        let bytes = postcard::to_stdvec(&proof).unwrap();
        let back: Proof = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, proof);
    }
}
