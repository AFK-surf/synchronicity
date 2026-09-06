//! Complete trie operations. No decoded node shapes cross this interface.
use crate::{
    host::{ByteStorage, Digest},
    operation::{self, terminal, Command},
};

pub use crate::generated::{LookupDomainError, NodeRefusal, NodeVerdict};
pub use crate::operation::OperationError;

/// Admit node bytes at the canonical ingress boundary: decoded, re-encoded
/// identically, within the shared key bound and shaped as the trie
/// invariants require. Lean decides; the host only hashes the tagged bytes.
/// The outer error is the host's or the transport's, the inner the refusal.
pub fn admit<D: Digest>(
    digest: &mut D,
    bytes: &[u8],
) -> Result<Result<[u8; 32], NodeRefusal>, OperationError<D::Error>> {
    let command = Command::TrieAdmit(bytes.len() as u64);
    let result = operation::run_digest(digest, &[bytes], &command)?;
    let outcome: Result<Vec<u8>, NodeRefusal> =
        terminal(&result).map_err(|()| OperationError::Protocol)?;
    match outcome {
        Ok(hash) => Ok(Ok(hash.try_into().map_err(|_| OperationError::Protocol)?)),
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// Whether served node bytes are the node `expected` names and, when they are
/// not, whose fault that is: the origin's for bytes the hash covers but this
/// build refuses, the peer's for bytes that hash to nothing wanted.
pub fn verify<D: Digest>(
    digest: &mut D,
    expected: &[u8; 32],
    bytes: &[u8],
) -> Result<NodeVerdict, OperationError<D::Error>> {
    let command = Command::TrieVerify {
        expected: expected.to_vec(),
        size: bytes.len() as u64,
    };
    let result = operation::run_digest(digest, &[bytes], &command)?;
    terminal(&result).map_err(|()| OperationError::Protocol)
}

/// A completed lookup failure, not an intermediate host observation.
#[derive(Debug)]
pub enum LookupError<E> {
    Host(E),
    MissingNode([u8; 32]),
    MissingValue([u8; 32]),
    KeyTooLong(usize),
    Decode(String),
    DepthExceeded,
    Protocol,
}

fn domain<E>(error: LookupDomainError) -> LookupError<E> {
    let address = |address: Vec<u8>| address.try_into().map_err(|_| LookupError::Protocol);
    match error {
        LookupDomainError::KeyTooLong(size) => {
            LookupError::KeyTooLong(usize::try_from(size).unwrap_or(usize::MAX))
        }
        LookupDomainError::MissingNode(hash) => match address(hash) {
            Ok(hash) => LookupError::MissingNode(hash),
            Err(error) => error,
        },
        LookupDomainError::MissingValue(hash) => match address(hash) {
            Ok(hash) => LookupError::MissingValue(hash),
            Err(error) => error,
        },
        LookupDomainError::Decode(message) => LookupError::Decode(message),
        LookupDomainError::DepthExceeded => LookupError::DepthExceeded,
    }
}

fn finish<E>(result: Vec<u8>) -> Result<Option<Vec<u8>>, LookupError<E>> {
    let outcome: Result<Option<Vec<u8>>, LookupDomainError> =
        terminal(&result).map_err(|()| LookupError::Protocol)?;
    outcome.map_err(domain)
}

/// Lookup over raw byte storage. Lean owns key bounds, decoding and traversal.
/// The key remains borrowed until the operation requests its bytes.
pub fn get<S: ByteStorage>(
    storage: &mut S,
    root: &[u8; 32],
    key: &[u8],
) -> Result<Option<Vec<u8>>, LookupError<S::Error>> {
    let command = Command::TrieGet {
        root: root.to_vec(),
        key_size: key.len() as u64,
    };
    let result =
        operation::run_readonly(storage, &[key], &command).map_err(|error| match error {
            OperationError::Host(error) => LookupError::Host(error),
            OperationError::MalformedMetadata(_) | OperationError::Protocol => {
                LookupError::Protocol
            }
        })?;
    finish(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Store {
        calls: Vec<(String, Vec<u8>)>,
        node: Option<Vec<u8>>,
        value: Option<Vec<u8>>,
        fail: bool,
    }

    impl ByteStorage for Store {
        type Error = &'static str;

        fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            self.calls.push((space.into(), key.into()));
            if self.fail {
                return Err("original storage failure");
            }
            match space {
                "trie_nodes" => Ok(self.node.clone()),
                "trie_values" => Ok(self.value.clone()),
                _ => panic!("unexpected storage namespace"),
            }
        }
    }

    #[test]
    fn oversized_input_is_rejected_without_borrowing_or_reading_storage() {
        let mut store = Store::default();
        // No input capability exists: Lean must reject the size before requesting it.
        let command = Command::TrieGet {
            root: vec![1; 32],
            key_size: u64::MAX,
        };
        let result = operation::run_readonly(&mut store, &[], &command).unwrap();
        assert!(matches!(
            finish::<()>(result),
            Err(LookupError::KeyTooLong(usize::MAX))
        ));
        assert!(matches!(
            get(&mut store, &[0; 32], &vec![0; 4097]),
            Err(LookupError::KeyTooLong(4097))
        ));
        assert!(store.calls.is_empty());
    }

    #[test]
    fn missing_input_capability_fails_before_storage() {
        let mut store = Store::default();
        let command = Command::TrieGet {
            root: vec![1; 32],
            key_size: 1,
        };
        let result = operation::run_readonly(&mut store, &[], &command);
        assert!(matches!(result, Err(OperationError::Protocol)));
        assert!(store.calls.is_empty());
    }

    #[test]
    fn empty_root_and_maximum_key_need_no_storage() {
        let mut store = Store::default();
        assert_eq!(get(&mut store, &[0; 32], &vec![0; 4096]).unwrap(), None);
        assert!(store.calls.is_empty());
    }

    #[test]
    fn permissive_local_leaf_decoding_preserves_empty_values() {
        // Non-minimal leaf tag, empty suffix, inline empty value, trailing byte.
        let mut store = Store {
            node: Some(vec![128, 0, 0, 0, 0, 99]),
            ..Store::default()
        };
        assert_eq!(get(&mut store, &[1; 32], &[]).unwrap(), Some(vec![]));
        assert_eq!(store.calls, vec![("trie_nodes".into(), vec![1; 32])]);
    }

    #[test]
    fn hashed_values_preserve_missing_empty_and_host_errors() {
        let mut node = vec![0, 0, 1];
        node.extend([2; 32]);
        let mut store = Store {
            node: Some(node),
            ..Store::default()
        };
        assert!(
            matches!(get(&mut store, &[1; 32], &[]), Err(LookupError::MissingValue(hash)) if hash == [2; 32])
        );
        assert_eq!(store.calls[1], ("trie_values".into(), vec![2; 32]));
        store.value = Some(vec![]);
        assert_eq!(get(&mut store, &[1; 32], &[]).unwrap(), Some(vec![]));
        store.fail = true;
        assert!(matches!(
            get(&mut store, &[1; 32], &[]),
            Err(LookupError::Host("original storage failure"))
        ));
    }

    #[test]
    fn missing_and_malformed_nodes_are_distinct() {
        let mut store = Store::default();
        assert!(
            matches!(get(&mut store, &[1; 32], &[]), Err(LookupError::MissingNode(hash)) if hash == [1; 32])
        );
        store.node = Some(vec![]);
        assert!(matches!(
            get(&mut store, &[1; 32], &[]),
            Err(LookupError::Decode(_))
        ));
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    /// A digest host that records what it was asked to hash and can fail once.
    #[derive(Default)]
    struct Hasher {
        requests: Vec<Vec<u8>>,
        fail: bool,
    }

    impl Digest for Hasher {
        type Error = &'static str;
        fn blake3(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
            self.requests.push(bytes.to_vec());
            if self.fail {
                return Err("original digest failure");
            }
            Ok(blake3::hash(bytes).as_bytes().to_vec())
        }
    }

    fn tagged(tag: &str, bytes: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(tag.as_bytes());
        hasher.update(bytes);
        *hasher.finalize().as_bytes()
    }

    // Leaf with a two-nibble key [10, 11] and inline value "xy", canonically.
    const LEAF: [u8; 8] = [0, 2, 10, 11, 0, 2, 120, 121];

    #[test]
    fn a_canonical_node_is_admitted_under_its_own_tag_only() {
        let mut hasher = Hasher::default();
        let hash = admit(&mut hasher, &LEAF).unwrap().unwrap();
        assert_eq!(hash, tagged("synch-mpt/1/leaf", &LEAF));
        // One digest request, of the tagged bytes, nothing else.
        assert_eq!(hasher.requests.len(), 1);
        assert_eq!(hasher.requests[0][..16], *b"synch-mpt/1/leaf");
        assert_eq!(
            verify(&mut hasher, &hash, &LEAF).unwrap(),
            NodeVerdict::Accepted
        );
        assert_eq!(
            verify(&mut hasher, &tagged("synch-mpt/1/ext", &LEAF), &LEAF).unwrap(),
            NodeVerdict::PeerFault
        );
    }

    #[test]
    fn a_non_canonical_image_is_refused_and_its_fault_follows_the_hash() {
        // Non-minimal leaf tag and a trailing byte decode locally but never verify.
        let padded = [128, 0, 2, 10, 11, 0, 2, 120, 121, 99];
        let mut hasher = Hasher::default();
        let refusal = admit(&mut hasher, &padded).unwrap().unwrap_err();
        assert!(matches!(refusal, NodeRefusal::Decode(_)));
        // Refusal is decided before any digest is requested.
        assert!(hasher.requests.is_empty());
        // Hashing to the requested address under a kind's tag is the origin's fault.
        let expected = tagged("synch-mpt/1/branch", &padded);
        assert!(matches!(
            verify(&mut hasher, &expected, &padded).unwrap(),
            NodeVerdict::OriginFault(NodeRefusal::Decode(_))
        ));
        // Hashing to nothing wanted is the peer's, after every tag was tried.
        hasher.requests.clear();
        assert_eq!(
            verify(&mut hasher, &[7; 32], &padded).unwrap(),
            NodeVerdict::PeerFault
        );
        assert_eq!(hasher.requests.len(), 3);
    }

    #[test]
    fn structural_invariants_are_refused_by_name() {
        // A one-occupant branch: fifteen absent children, one present, no value.
        let mut lonely = vec![2u8];
        lonely.extend(std::iter::repeat_n(0, 6));
        lonely.push(1);
        lonely.extend([9; 32]);
        lonely.extend(std::iter::repeat_n(0, 9));
        lonely.push(0);
        let mut hasher = Hasher::default();
        assert!(matches!(
            admit(&mut hasher, &lonely).unwrap().unwrap_err(),
            NodeRefusal::NonCanonical(message) if message == "a branch has fewer than two occupants"
        ));
        // An empty extension prefix.
        let mut empty = vec![1u8, 0];
        empty.extend([9; 32]);
        assert!(matches!(
            admit(&mut hasher, &empty).unwrap().unwrap_err(),
            NodeRefusal::NonCanonical(message) if message == "an extension prefix is empty"
        ));
        // A nibble run past twice the key bound.
        let mut long = vec![0u8, 129, 64];
        long.extend(std::iter::repeat_n(0, 8193));
        long.extend([0, 0]);
        assert!(matches!(
            admit(&mut hasher, &long).unwrap().unwrap_err(),
            NodeRefusal::KeyTooLong(4096)
        ));
        assert!(hasher.requests.is_empty());
    }

    #[test]
    fn digest_failures_are_the_hosts_own() {
        let mut hasher = Hasher {
            fail: true,
            ..Hasher::default()
        };
        assert!(matches!(
            admit(&mut hasher, &LEAF),
            Err(OperationError::Host("original digest failure"))
        ));
        assert!(matches!(
            verify(&mut hasher, &[0; 32], &LEAF),
            Err(OperationError::Host("original digest failure"))
        ));
    }
}
