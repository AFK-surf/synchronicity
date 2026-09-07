//! Merkle proofs for single keys (§4.3).
//!
//! A proof is the node path from the root down to where the key resolves — or
//! to where it provably dead-ends. Verification is self-contained: root hash
//! and proof alone, which is what lets a holder of one signed head answer for
//! one key without shipping a whole trie — the capability partial replication
//! (§13) is built on.
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
//!
//! Both halves are Lean operations (`Trie/Proof.lean`): proving is the
//! lookup with its node trace, verifying is the lookup over the proof's own
//! nodes as a raw snapshot, and `specs/lean` (`TrieMerkleProofs`) proves the
//! round trip and that a verified value is a path through the proof's nodes.

use serde::{Deserialize, Serialize};
use synch_core::Hash;

use crate::{error::MptError, store::NodeStore, trie::Trie};

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
    ///
    /// The whole verification is the Lean operation `Trie.Proof.verify`: each
    /// node admitted at the canonical ingress boundary and addressed by the
    /// digest of its kind's tag and bytes, the payload by its plain digest,
    /// and the lookup `Trie::get` runs, run again over those nodes as a raw
    /// snapshot. Rust supplies BLAKE3; nothing is read from any store.
    pub fn verify(&self, root: Hash, key: &[u8]) -> Result<Option<Vec<u8>>, MptError> {
        use synch_verified::trie::VerifyProofError;
        let nodes: Vec<&[u8]> = self.nodes.iter().map(Vec::as_slice).collect();
        synch_verified::trie::verify_proof(
            &mut crate::lean_storage::Blake3,
            root.as_bytes(),
            key,
            &nodes,
            self.value.as_deref(),
        )
        .map_err(|error| match error {
            VerifyProofError::Operation(error) => crate::lean_storage::operation_error(error),
            VerifyProofError::Refused(refusal) => crate::lean_storage::refusal_error(refusal),
            VerifyProofError::Lookup(error) => crate::lean_storage::lookup_error(error),
        })
    }
}

impl<S: NodeStore + ?Sized> Trie<'_, S> {
    /// Builds a Merkle proof for `key` against `root`.
    ///
    /// The Lean operation `Trie.Proof.prove` is `Trie::get`'s descent with
    /// its node trace: the same key bound, the same depth bound, every node
    /// read on the way down, and the payload when the value found is out of
    /// line. Rust supplies raw node reads.
    pub fn prove(&self, root: Hash, key: &[u8]) -> Result<Proof, MptError> {
        let proof = synch_verified::trie::prove(
            &mut crate::lean_storage::Bytes(self.store()),
            root.as_bytes(),
            key,
        )
        .map_err(crate::lean_storage::lookup_error)?;
        Ok(Proof {
            nodes: proof.nodes,
            value: proof.value,
        })
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
    fn proves_presence_absence_and_out_of_line() {
        let (store, root) = populated();
        let trie = Trie::new(&store);

        let proof = trie.prove(root, b"f:space/file007").unwrap();
        assert_eq!(
            proof.verify(root, b"f:space/file007").unwrap(),
            Some(b"entry".to_vec())
        );
        assert!(proof.nodes.len() < store.node_count());

        let proof = trie.prove(root, b"f:space/big").unwrap();
        assert!(
            proof.value.is_some(),
            "an out-of-line value travels with it"
        );
        assert_eq!(
            proof.verify(root, b"f:space/big").unwrap(),
            Some(vec![7u8; 400])
        );

        for key in [
            b"f:space/file999".as_slice(),
            b"zzz".as_slice(),
            b"f:".as_slice(),
        ] {
            let proof = trie.prove(root, key).unwrap();
            assert_eq!(proof.verify(root, key).unwrap(), None);
        }

        let proof = trie.prove(Hash::EMPTY, b"anything").unwrap();
        assert!(proof.nodes.is_empty());
        assert_eq!(proof.verify(Hash::EMPTY, b"anything").unwrap(), None);
    }

    #[test]
    fn a_tampered_proof_never_verifies() {
        let (store, root) = populated();
        let trie = Trie::new(&store);

        // A flipped byte: the node no longer decodes, or no longer hashes to
        // something the walk can reach from the root. Both are errors.
        let mut proof = trie.prove(root, b"f:space/file007").unwrap();
        let last = proof.nodes.last_mut().unwrap();
        let idx = last.len() - 1;
        last[idx] ^= 0xff;
        assert!(proof.verify(root, b"f:space/file007").is_err());

        // Truncation is the omission attack: absence cannot be claimed by
        // dropping the nodes that prove presence.
        let mut proof = trie.prove(root, b"f:space/file007").unwrap();
        proof.nodes.pop();
        assert!(matches!(
            proof.verify(root, b"f:space/file007"),
            Err(MptError::MissingNode(_))
        ));

        // A proof is bound to the root it was made against.
        let other = trie.insert(root, b"f:space/file007", b"changed").unwrap();
        let proof = trie.prove(root, b"f:space/file007").unwrap();
        assert!(proof.verify(other, b"f:space/file007").is_err());

        // A substituted value payload fails rather than verifying.
        let mut proof = trie.prove(root, b"f:space/big").unwrap();
        proof.value = Some(vec![8u8; 400]);
        assert!(matches!(
            proof.verify(root, b"f:space/big"),
            Err(MptError::MissingValue(_))
        ));
    }
}
