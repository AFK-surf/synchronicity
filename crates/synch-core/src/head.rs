//! Signed heads: the mutable pointer per origin (§4.4).

use std::cmp::Ordering;

use iroh_base::{SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::{
    hash::Hash,
    origin::{NodeId, OriginId},
};

/// The signing domain-separation tag (§4.4).
pub const HEAD_SIGNING_DOMAIN: &[u8] = b"sync-head/1";

/// The mutable pointer per origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHead {
    /// The origin this head belongs to.
    pub origin: OriginId,
    /// Strictly monotonic per origin, across key rotations.
    pub seq: u64,
    /// MPT root hash ([`Hash::EMPTY`] for the empty trie).
    pub root: Hash,
    /// Unix nanoseconds; informational only, never used for ordering.
    pub created_at: i64,
    /// The device key that produced `sig`.
    pub signed_by: NodeId,
    /// Ed25519 signature over the §4.4 signing input.
    pub sig: Signature,
}

/// Builds the exact byte string that a head signature covers (§4.4):
///
/// ```text
/// "sync-head/1" || origin || seq || root || created_at || signed_by
/// ```
///
/// Each variable-length field is length-prefixed so that no two distinct field
/// assignments can produce the same signing input.
pub fn head_signing_input(
    origin: &OriginId,
    seq: u64,
    root: &Hash,
    created_at: i64,
    signed_by: &NodeId,
) -> Vec<u8> {
    let canonical = origin.canonical();
    let origin_bytes = canonical.as_bytes();
    let mut buf =
        Vec::with_capacity(HEAD_SIGNING_DOMAIN.len() + 4 + origin_bytes.len() + 8 + 32 + 8 + 32);
    buf.extend_from_slice(HEAD_SIGNING_DOMAIN);
    buf.extend_from_slice(&(origin_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(origin_bytes);
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(root.as_bytes());
    buf.extend_from_slice(&created_at.to_le_bytes());
    buf.extend_from_slice(signed_by.as_bytes());
    buf
}

/// Error verifying a [`SignedHead`].
#[derive(Debug, thiserror::Error)]
pub enum HeadError {
    /// The ed25519 signature did not verify under `signed_by`.
    #[error("head signature does not verify")]
    BadSignature,
}

impl SignedHead {
    /// Signs a new head with `key`.
    pub fn sign(
        key: &SecretKey,
        origin: OriginId,
        seq: u64,
        root: Hash,
        created_at: i64,
    ) -> SignedHead {
        let signed_by = key.public();
        let input = head_signing_input(&origin, seq, &root, created_at, &signed_by);
        let sig = key.sign(&input);
        SignedHead {
            origin,
            seq,
            root,
            created_at,
            signed_by,
            sig,
        }
    }

    /// Verifies the signature under `signed_by`.
    ///
    /// This is only half of validity: the caller must *also* check that
    /// `signed_by` is bound to `origin` (§3.1, enforced in `synch-store`'s
    /// bindings table). Both checks together make a head valid (§4.4).
    pub fn verify_signature(&self) -> Result<(), HeadError> {
        let input = head_signing_input(
            &self.origin,
            self.seq,
            &self.root,
            self.created_at,
            &self.signed_by,
        );
        self.signed_by
            .verify(&input, &self.sig)
            .map_err(|_| HeadError::BadSignature)
    }

    /// The `(seq, root)` ordering key used for head acceptance (§4.4/§5.2).
    pub fn order_key(&self) -> (u64, [u8; 32]) {
        (self.seq, self.root.0)
    }

    /// Lexicographic `(seq, root)` comparison against another head.
    ///
    /// `created_at` is never used for ordering — clocks lie.
    pub fn cmp_order(&self, other: &SignedHead) -> Ordering {
        self.order_key().cmp(&other.order_key())
    }

    /// True if this head should displace `current` under the §5.2 acceptance
    /// rule: strictly greater `(seq, root)` lexicographically.
    pub fn supersedes(&self, current: Option<&(u64, Hash)>) -> bool {
        match current {
            None => true,
            Some((seq, root)) => self.order_key() > (*seq, root.0),
        }
    }

    /// True if this head equivocates against `other`: same origin and seq, but a
    /// different root (§4.4).
    pub fn equivocates_with(&self, other: &SignedHead) -> bool {
        self.origin == other.origin && self.seq == other.seq && self.root != other.root
    }
}

/// A head summary as carried in `Hello` (§5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadSummary {
    /// The origin being summarized.
    pub origin: OriginId,
    /// The seq of the summarized head.
    pub seq: u64,
    /// The root of the summarized head.
    pub root: Hash,
    /// True if the sender holds the full trie under `root` and can serve it.
    ///
    /// A signed head alone proves nothing about that (§5.1).
    pub complete: bool,
}

impl HeadSummary {
    /// The `(seq, root)` ordering key.
    pub fn order_key(&self) -> (u64, [u8; 32]) {
        (self.seq, self.root.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> OriginId {
        OriginId::named("nas", "cluster.example.com").unwrap()
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = SecretKey::generate();
        let head = SignedHead::sign(&key, origin(), 7, Hash::new(b"root"), 1234);
        head.verify_signature().unwrap();
    }

    #[test]
    fn tampering_breaks_verification() {
        let key = SecretKey::generate();
        let head = SignedHead::sign(&key, origin(), 7, Hash::new(b"root"), 1234);

        let mut h = head.clone();
        h.seq = 8;
        assert!(h.verify_signature().is_err());

        let mut h = head.clone();
        h.root = Hash::new(b"other");
        assert!(h.verify_signature().is_err());

        let mut h = head.clone();
        h.created_at = 9999;
        assert!(h.verify_signature().is_err());

        let mut h = head.clone();
        h.origin = OriginId::named("laptop", "cluster.example.com").unwrap();
        assert!(h.verify_signature().is_err());

        let mut h = head.clone();
        h.signed_by = SecretKey::generate().public();
        assert!(h.verify_signature().is_err());
    }

    #[test]
    fn key_origin_head_verifies() {
        let key = SecretKey::generate();
        let o = OriginId::Key(key.public());
        let head = SignedHead::sign(&key, o, 1, Hash::EMPTY, 0);
        head.verify_signature().unwrap();
    }

    #[test]
    fn signing_input_is_domain_separated() {
        let o = origin();
        let k = SecretKey::generate().public();
        let input = head_signing_input(&o, 1, &Hash::EMPTY, 0, &k);
        assert!(input.starts_with(HEAD_SIGNING_DOMAIN));
    }

    #[test]
    fn signing_input_is_unambiguous_across_field_boundaries() {
        // Two origins whose canonical renderings differ only in where the split
        // between fields would fall must not collide.
        let k = SecretKey::generate().public();
        let a = OriginId::named("ab", "x.example").unwrap();
        let b = OriginId::named("a", "bx.example").unwrap();
        assert_ne!(
            head_signing_input(&a, 1, &Hash::EMPTY, 0, &k),
            head_signing_input(&b, 1, &Hash::EMPTY, 0, &k)
        );
    }

    #[test]
    fn seq_root_ordering() {
        let key = SecretKey::generate();
        let low = SignedHead::sign(&key, origin(), 1, Hash([1u8; 32]), 0);
        let same_seq_high_root = SignedHead::sign(&key, origin(), 1, Hash([2u8; 32]), 0);
        let high_seq = SignedHead::sign(&key, origin(), 2, Hash([0u8; 32]), 0);

        assert_eq!(low.cmp_order(&same_seq_high_root), Ordering::Less);
        assert_eq!(same_seq_high_root.cmp_order(&high_seq), Ordering::Less);

        // Equal-seq, greater-root heads are accepted, not ignored (§5.2).
        assert!(same_seq_high_root.supersedes(Some(&(1, Hash([1u8; 32])))));
        assert!(!low.supersedes(Some(&(1, Hash([2u8; 32])))));
        assert!(!low.supersedes(Some(&(1, Hash([1u8; 32])))));
        assert!(low.supersedes(None));
    }

    #[test]
    fn equivocation_detection() {
        let key = SecretKey::generate();
        let a = SignedHead::sign(&key, origin(), 3, Hash([1u8; 32]), 0);
        let b = SignedHead::sign(&key, origin(), 3, Hash([2u8; 32]), 0);
        let c = SignedHead::sign(&key, origin(), 4, Hash([2u8; 32]), 0);
        assert!(a.equivocates_with(&b));
        assert!(!a.equivocates_with(&c));
        assert!(!a.equivocates_with(&a.clone()));
    }

    #[test]
    fn head_survives_postcard_round_trip() {
        let key = SecretKey::generate();
        let head = SignedHead::sign(&key, origin(), 7, Hash::new(b"root"), 1234);
        let bytes = postcard::to_stdvec(&head).unwrap();
        let back: SignedHead = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, head);
        back.verify_signature().unwrap();
    }
}
