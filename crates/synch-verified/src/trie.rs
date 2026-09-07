//! Complete trie operations. No decoded node shapes cross this interface.
use crate::{
    host::{ByteStorage, ByteWrites, Digest},
    operation::{self, terminal, Command},
};

pub use crate::generated::{
    Collected, LookupDomainError, MutationDomainError, NodeAnswer, NodeRefusal, NodeVerdict,
    TrieChange, TrieCollectDomainError, TrieServeDomainError, TrieValue, TrieWalkDomainError,
    ValueAnswer,
};
pub use crate::operation::OperationError;
use crate::{host::Storage, operation::Decode};

/// Completed serving failure, preserving original host errors.
#[derive(Debug)]
pub enum ServeError<E> {
    Operation(OperationError<E>),
    Domain(TrieServeDomainError),
}

/// Which part of a trie a peer may see: allowed nibble prefixes, or every
/// prefix when `None`, and exact keys. An Authorization-domain input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeScope {
    pub prefixes: Option<Vec<Vec<u8>>>,
    pub exact: Vec<Vec<u8>>,
}

fn served<T: Decode, S: Storage>(
    storage: &mut S,
    command: &Command,
) -> Result<T, ServeError<S::Error>> {
    let result = operation::run(storage, operation::Capabilities::default(), &[], command)
        .map_err(ServeError::Operation)?;
    let outcome: Result<T, TrieServeDomainError> =
        terminal(&result).map_err(|()| ServeError::Operation(OperationError::Protocol))?;
    outcome.map_err(ServeError::Domain)
}

fn wanted(wants: &[(Vec<u8>, [u8; 32])]) -> Vec<(Vec<u8>, Vec<u8>)> {
    wants
        .iter()
        .map(|(path, claimed)| (path.clone(), claimed.to_vec()))
        .collect()
}

/// Serve the nodes a peer asked for by `(nibble path, claimed hash)` under a
/// root. Lean decides which positions the scope admits, what stands there,
/// whether a node's contents run out of scope, whether this store vouches
/// for it under the root's origins, and how much one answer carries; the
/// scope, the peer's own origins and the confined origins are the caller's
/// Authorization-domain inputs.
pub fn serve_nodes<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
    wants: &[(Vec<u8>, [u8; 32])],
    scope: ServeScope,
    peer_origins: Vec<String>,
    confined: Vec<String>,
) -> Result<NodeAnswer, ServeError<S::Error>> {
    let command = Command::TrieServeNodes {
        root: root.to_vec(),
        wants: wanted(wants),
        prefixes: scope.prefixes,
        exact: scope.exact,
        peer_origins,
        confined,
    };
    served(storage, &command)
}

/// Serve the out-of-line values a peer asked for, each authorized by the
/// position of the node that holds it when the peer's view is scoped.
pub fn serve_values<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
    wants: &[(Vec<u8>, [u8; 32])],
    scope: ServeScope,
    peer_origins: Vec<String>,
    confined: Vec<String>,
) -> Result<ValueAnswer, ServeError<S::Error>> {
    let command = Command::TrieServeValues {
        root: root.to_vec(),
        wants: wanted(wants),
        prefixes: scope.prefixes,
        exact: scope.exact,
        peer_origins,
        confined,
    };
    served(storage, &command)
}

/// What stands at each nibble position under a root, in the caller's order.
pub fn resolve_paths<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
    paths: &[Vec<u8>],
) -> Result<Vec<Option<Vec<u8>>>, ServeError<S::Error>> {
    let command = Command::TrieResolve {
        root: root.to_vec(),
        paths: paths.to_vec(),
    };
    served(storage, &command)
}

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

/// A completed write, or the domain reason it did not happen; the outer error
/// is the host's or the transport's.
pub type Mutation<E> = Result<Result<[u8; 32], MutationDomainError>, OperationError<E>>;

fn mutated<E>(result: Result<Vec<u8>, OperationError<E>>) -> Mutation<E> {
    let outcome: Result<Vec<u8>, MutationDomainError> =
        terminal(&result?).map_err(|()| OperationError::Protocol)?;
    match outcome {
        Ok(root) => Ok(Ok(root.try_into().map_err(|_| OperationError::Protocol)?)),
        Err(error) => Ok(Err(error)),
    }
}

/// Insert or replace a key, answering the new root. Lean owns the bounds,
/// the descent, canonical form and the order of writes; the host supplies
/// raw node reads, content-addressed writes and BLAKE3.
pub fn insert<S: ByteStorage>(
    storage: &mut S,
    writes: &mut dyn ByteWrites<Error = S::Error>,
    digest: &mut dyn Digest<Error = S::Error>,
    root: &[u8; 32],
    key: &[u8],
    value: &[u8],
) -> Mutation<S::Error> {
    let command = Command::TrieInsert {
        root: root.to_vec(),
        key_size: key.len() as u64,
        value_size: value.len() as u64,
    };
    mutated(operation::run_bytes(
        storage,
        writes,
        digest,
        &[key, value],
        &command,
    ))
}

/// Remove a key, answering the new root; an absent key leaves it unchanged.
pub fn remove<S: ByteStorage>(
    storage: &mut S,
    writes: &mut dyn ByteWrites<Error = S::Error>,
    digest: &mut dyn Digest<Error = S::Error>,
    root: &[u8; 32],
    key: &[u8],
) -> Mutation<S::Error> {
    let command = Command::TrieRemove {
        root: root.to_vec(),
        key_size: key.len() as u64,
    };
    mutated(operation::run_bytes(
        storage,
        writes,
        digest,
        &[key],
        &command,
    ))
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

#[cfg(test)]
mod write_tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A content-addressed byte store, in memory, with the digest primitive.
    #[derive(Default)]
    struct Nodes {
        nodes: BTreeMap<Vec<u8>, Vec<u8>>,
        values: BTreeMap<Vec<u8>, Vec<u8>>,
        writes: Vec<(String, Vec<u8>)>,
        fail_writes: bool,
    }

    impl ByteStorage for Nodes {
        type Error = &'static str;
        fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(match space {
                "trie_nodes" => self.nodes.get(key).cloned(),
                "trie_values" => self.values.get(key).cloned(),
                _ => panic!("unexpected namespace"),
            })
        }
    }

    impl ByteWrites for Nodes {
        type Error = &'static str;
        fn put_bytes(&mut self, space: &str, key: &[u8], bytes: &[u8]) -> Result<(), Self::Error> {
            if self.fail_writes {
                return Err("original write failure");
            }
            self.writes.push((space.into(), key.to_vec()));
            match space {
                "trie_nodes" => self.nodes.insert(key.to_vec(), bytes.to_vec()),
                "trie_values" => self.values.insert(key.to_vec(), bytes.to_vec()),
                _ => panic!("unexpected namespace"),
            };
            Ok(())
        }
    }

    struct Hasher;
    impl Digest for Hasher {
        type Error = &'static str;
        fn blake3(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(blake3::hash(bytes).as_bytes().to_vec())
        }
    }

    fn tagged(tag: &str, bytes: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(tag.as_bytes());
        hasher.update(bytes);
        *hasher.finalize().as_bytes()
    }

    #[test]
    fn a_first_insert_stores_one_canonical_leaf_under_its_tagged_digest() {
        let mut store = Nodes::default();
        let mut writes = Nodes::default();
        let root = insert(
            &mut store,
            &mut writes,
            &mut Hasher,
            &[0; 32],
            &[0xab],
            b"xy",
        )
        .unwrap()
        .unwrap();
        // Leaf with nibbles [10, 11] and the inline value: the same canonical
        // image the ingress boundary admits, hashed under the leaf tag.
        let leaf = [0u8, 2, 10, 11, 0, 2, 120, 121];
        assert_eq!(root, tagged("synch-mpt/1/leaf", &leaf));
        assert_eq!(
            writes.writes,
            vec![("trie_nodes".to_string(), root.to_vec())]
        );
        assert_eq!(writes.nodes[&root.to_vec()], leaf);
        assert_eq!(admit(&mut Hasher, &leaf).unwrap().unwrap(), root);
        // Reading back through the lookup command sees the value.
        assert_eq!(
            get(&mut writes, &root, &[0xab]).unwrap(),
            Some(b"xy".to_vec())
        );
    }

    #[test]
    fn large_values_are_stored_out_of_line_before_the_node_that_names_them() {
        let big = vec![7u8; 129];
        let mut reads = Nodes::default();
        let mut sink = Nodes::default();
        let root = insert(&mut reads, &mut sink, &mut Hasher, &[0; 32], b"k", &big)
            .unwrap()
            .unwrap();
        assert_eq!(sink.writes[0].0, "trie_values");
        assert_eq!(sink.writes[0].1, blake3::hash(&big).as_bytes().to_vec());
        assert_eq!(sink.writes[1], ("trie_nodes".to_string(), root.to_vec()));
    }

    #[test]
    fn bounds_are_refused_before_any_effect() {
        let mut store = Nodes::default();
        let mut writes = Nodes::default();
        assert!(matches!(
            insert(
                &mut store,
                &mut writes,
                &mut Hasher,
                &[0; 32],
                &[0; 4097],
                b"v"
            ),
            Ok(Err(MutationDomainError::KeyTooLong(4097)))
        ));
        assert!(matches!(
            insert(
                &mut store,
                &mut writes,
                &mut Hasher,
                &[0; 32],
                b"k",
                &vec![0; 32769]
            ),
            Ok(Err(MutationDomainError::ValueTooLong(32769)))
        ));
        assert!(matches!(
            remove(&mut store, &mut writes, &mut Hasher, &[0; 32], &[0; 4097]),
            Ok(Err(MutationDomainError::KeyTooLong(4097)))
        ));
        assert!(writes.writes.is_empty());
        // Removing from the empty trie answers the empty root without effects.
        assert_eq!(
            remove(&mut store, &mut writes, &mut Hasher, &[0; 32], b"k").unwrap(),
            Ok([0; 32])
        );
        assert!(writes.writes.is_empty());
    }

    #[test]
    fn a_missing_node_and_a_failed_write_are_reported_as_such() {
        let mut store = Nodes::default();
        let mut writes = Nodes::default();
        assert!(matches!(
            insert(&mut store, &mut writes, &mut Hasher, &[9; 32], b"k", b"v"),
            Ok(Err(MutationDomainError::MissingNode(hash))) if hash == vec![9; 32]
        ));
        writes.fail_writes = true;
        assert!(matches!(
            insert(&mut store, &mut writes, &mut Hasher, &[0; 32], b"k", b"v"),
            Err(OperationError::Host("original write failure"))
        ));
    }
}

/// Completed collection failure, preserving original host errors.
#[derive(Debug)]
pub enum CollectError<E> {
    Operation(OperationError<E>),
    Domain(TrieCollectDomainError),
}

/// The services a trie sweep directs besides its relational storage: the
/// digest behind the memo keys, and the completeness memo itself.
pub struct CollectResources<'a, E> {
    pub digest: &'a mut dyn Digest<Error = E>,
    pub memo: &'a mut dyn crate::host::Memo<Error = E>,
}
impl<E> std::fmt::Debug for CollectResources<'_, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectResources").finish_non_exhaustive()
    }
}

/// One mark-and-sweep pass over the trie, in one transaction: every head
/// row's root is marked from, the completeness certificates of exactly those
/// roots are kept (under the local scope `prefixes`/`exact`, and as each
/// origin's own), and every node, provenance row and out-of-line value the
/// mark missed is swept set-wise. Answers what was swept and how many roots
/// were marked from.
pub fn collect<S: Storage>(
    storage: &mut S,
    resources: CollectResources<'_, S::Error>,
    prefixes: Option<&[Vec<u8>]>,
    exact: &[Vec<u8>],
) -> Result<Collected, CollectError<S::Error>> {
    let command = Command::TrieCollect {
        prefixes: prefixes.map(<[Vec<u8>]>::to_vec),
        exact: exact.to_vec(),
    };
    let capabilities = operation::Capabilities {
        digest: Some(resources.digest),
        memo: Some(resources.memo),
        ..operation::Capabilities::default()
    };
    let result =
        operation::run(storage, capabilities, &[], &command).map_err(CollectError::Operation)?;
    let outcome: Result<Collected, TrieCollectDomainError> =
        terminal(&result).map_err(|()| CollectError::Operation(OperationError::Protocol))?;
    outcome.map_err(CollectError::Domain)
}

/// The key a completeness answer for `root` under a scope, and as `owner`'s
/// own when given, is memoized under: the root itself for the whole keyspace,
/// digests over the root, the scope's sets and the owner otherwise. Lean
/// owns the layout; the host only hashes.
pub fn memo_key<D: Digest>(
    digest: &mut D,
    root: &[u8; 32],
    prefixes: Option<&[Vec<u8>]>,
    exact: &[Vec<u8>],
    owner: Option<&str>,
) -> Result<[u8; 32], OperationError<D::Error>> {
    let command = Command::TrieMemoKey {
        root: root.to_vec(),
        prefixes: prefixes.map(<[Vec<u8>]>::to_vec),
        exact: exact.to_vec(),
        owner: owner.map(str::to_owned),
    };
    let result = operation::run_digest(digest, &[], &command)?;
    let key: Vec<u8> = terminal(&result).map_err(|()| OperationError::Protocol)?;
    key.try_into().map_err(|_| OperationError::Protocol)
}

/// Completed walk failure, preserving original host errors.
#[derive(Debug)]
pub enum WalkError<E> {
    Operation(OperationError<E>),
    Domain(TrieWalkDomainError),
}

/// The services a walk directs besides raw node reads: the refusals a peer
/// recorded, the digest a value comparison uses, and, for a materialization,
/// the taker of each change.
pub struct WalkResources<'a, E> {
    pub redaction: &'a mut dyn crate::host::Redaction<Error = E>,
    pub digest: Option<&'a mut dyn Digest<Error = E>>,
    pub apply: Option<&'a mut dyn crate::host::Apply<Error = E>>,
}
impl<E> std::fmt::Debug for WalkResources<'_, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalkResources").finish_non_exhaustive()
    }
}

fn walked<T: Decode, S: ByteStorage>(
    storage: &mut S,
    resources: WalkResources<'_, S::Error>,
    command: &Command,
) -> Result<T, WalkError<S::Error>> {
    let capabilities = operation::Capabilities {
        redaction: Some(resources.redaction),
        digest: resources.digest,
        apply: resources.apply,
        ..operation::Capabilities::default()
    };
    let result =
        operation::run_walk(storage, capabilities, &[], command).map_err(WalkError::Operation)?;
    let outcome: Result<T, TrieWalkDomainError> =
        terminal(&result).map_err(|()| WalkError::Operation(OperationError::Protocol))?;
    outcome.map_err(WalkError::Domain)
}

/// One listed entry: the key and its value's bytes.
pub type ScanEntry = (Vec<u8>, Vec<u8>);

/// Every pair under a root whose key starts with `prefix`, in key order,
/// optionally resuming strictly after `start_after` and capped at `limit`.
/// Lean owns the cursor, the hostile-shape defences and the order; a
/// refused position reads as empty.
pub fn scan<S: ByteStorage>(
    storage: &mut S,
    redaction: &mut dyn crate::host::Redaction<Error = S::Error>,
    root: &[u8; 32],
    prefix: &[u8],
    start_after: Option<&[u8]>,
    limit: Option<u64>,
) -> Result<Vec<ScanEntry>, WalkError<S::Error>> {
    let command = Command::TrieScan {
        root: root.to_vec(),
        key_prefix: prefix.to_vec(),
        start_after: start_after.map(<[u8]>::to_vec),
        limit,
    };
    let resources = WalkResources {
        redaction,
        digest: None,
        apply: None,
    };
    walked(storage, resources, &command)
}

/// Every differing key between two roots, in key order, each with its old
/// and new value references. A value is compared as a value: inline bytes
/// and the address of the same bytes out of line are one value.
pub fn diff<S: ByteStorage>(
    storage: &mut S,
    redaction: &mut dyn crate::host::Redaction<Error = S::Error>,
    digest: &mut dyn Digest<Error = S::Error>,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> Result<Vec<TrieChange>, WalkError<S::Error>> {
    let command = Command::TrieDiff {
        old_root: old_root.to_vec(),
        new_root: new_root.to_vec(),
    };
    let resources = WalkResources {
        redaction,
        digest: Some(digest),
        apply: None,
    };
    walked(storage, resources, &command)
}

/// The diff a head promotion applies: every change the scope admits handed
/// to `apply` as it is found, with only its new value resolved; answers
/// how many were handed over. The scope is an Authorization-domain input.
pub fn materialize<S: ByteStorage>(
    storage: &mut S,
    redaction: &mut dyn crate::host::Redaction<Error = S::Error>,
    digest: &mut dyn Digest<Error = S::Error>,
    apply: &mut dyn crate::host::Apply<Error = S::Error>,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    scope: ServeScope,
) -> Result<u64, WalkError<S::Error>> {
    let command = Command::TrieMaterialize {
        old_root: old_root.to_vec(),
        new_root: new_root.to_vec(),
        prefixes: scope.prefixes,
        exact: scope.exact,
    };
    let resources = WalkResources {
        redaction,
        digest: Some(digest),
        apply: Some(apply),
    };
    walked(storage, resources, &command)
}
