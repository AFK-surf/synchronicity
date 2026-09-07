//! Literal byte-storage adapter for Lean operations; no trie interpretation.
use crate::{MptError, NodeStore};
use synch_core::Hash;

pub(crate) struct Bytes<'a, S: ?Sized>(pub(crate) &'a S);

impl<S: NodeStore + ?Sized> synch_verified::host::ByteStorage for Bytes<'_, S> {
    type Error = MptError;
    fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>, MptError> {
        let hash = Hash::from_slice(key).map_err(MptError::store)?;
        match space {
            "trie_nodes" => self.0.get_node(&hash).map_err(MptError::store),
            "trie_values" => self.0.get_value(&hash).map_err(MptError::store),
            _ => Err(protocol_error()),
        }
    }
}

/// Literal presence projections over the two raw relations a requesting
/// walk consults. The operation supplies the predicates; no scope or trie
/// shape is interpreted here, and value payloads are never materialized.
impl<S: NodeStore + ?Sized> synch_verified::host::Snapshots for Bytes<'_, S> {
    type Error = MptError;

    fn snapshot(
        &mut self,
        selection: &synch_verified::host::Selection,
        columns: &[String],
    ) -> Result<synch_verified::host::Scan<MptError>, MptError> {
        use synch_verified::host::{Cell, Scan};
        if !selection.like_any.is_empty() || !selection.not_equals.is_empty() || columns != ["hash"]
        {
            return Err(protocol_error());
        }
        let (key, present) = match (selection.relation.as_str(), selection.equals.as_slice()) {
            ("trie_values", [(column, Cell::Blob(key))]) if column == "hash" => {
                let hash = Hash::from_slice(key).map_err(MptError::store)?;
                (key, self.0.has_value(&hash).map_err(MptError::store)?)
            }
            (
                "trie_node_origins",
                [(origin_column, Cell::Text(origin)), (hash_column, Cell::Blob(key))],
            ) if origin_column == "origin_id" && hash_column == "hash" => {
                let origin = origin.parse().map_err(MptError::store)?;
                let hash = Hash::from_slice(key).map_err(MptError::store)?;
                (
                    key,
                    self.0.owns_node(&origin, &hash).map_err(MptError::store)?,
                )
            }
            _ => return Err(protocol_error()),
        };
        Ok(Scan {
            rows: if present {
                vec![vec![Cell::Blob(key.clone())]]
            } else {
                Vec::new()
            },
            failure: None,
        })
    }
}

impl<S: NodeStore + ?Sized> synch_verified::host::Memo for Bytes<'_, S> {
    type Error = MptError;

    fn forget_except(&mut self, _keep: &[&[u8]]) -> Result<(), MptError> {
        // The read-only runner refuses this effect before reaching the service.
        Err(protocol_error())
    }

    fn is_known(&mut self, key: &[u8]) -> Result<bool, MptError> {
        let hash = Hash::from_slice(key).map_err(MptError::store)?;
        self.0.is_known_complete(&hash).map_err(MptError::store)
    }

    fn generation(&mut self) -> Result<u64, MptError> {
        self.0.completeness_generation().map_err(MptError::store)
    }

    fn certify(&mut self, key: &[u8], generation: u64) -> Result<bool, MptError> {
        let hash = Hash::from_slice(key).map_err(MptError::store)?;
        self.0
            .note_complete_at(&hash, generation)
            .map_err(MptError::store)
    }
}

pub(crate) fn complete<S: NodeStore + ?Sized>(
    store: &S,
    owner: Option<&synch_core::OriginId>,
    root: Hash,
    scope: &crate::Scope,
) -> Result<bool, MptError> {
    use synch_verified::trie::{self, CompleteError, TrieMissingDomainError as Domain};
    trie::is_complete(
        &mut Bytes(store),
        trie::CompleteResources {
            snapshots: &mut Bytes(store),
            digest: &mut Blake3,
            memo: &mut Bytes(store),
            redaction: &mut Redactions(store),
        },
        root.as_bytes(),
        trie::ServeScope {
            prefixes: scope.prefixes().map(<[Vec<u8>]>::to_vec),
            exact: scope.exact().to_vec(),
        },
        owner.map(synch_core::OriginId::canonical),
    )
    .map_err(|error| match error {
        CompleteError::Operation(error) => operation_error(error),
        CompleteError::Domain(Domain::Decode(message)) => MptError::Decode(message),
        CompleteError::Domain(Domain::NodeDepth(depth)) => MptError::NonCanonical(format!(
            "a trie node sits at nibble depth {depth}, past the {} any valid key reaches",
            crate::trie::MAX_DEPTH_NIBBLES,
        )),
        CompleteError::Domain(Domain::ValueDepth(depth)) => MptError::NonCanonical(format!(
            "a trie value sits at nibble depth {depth}, past the {} any valid key reaches",
            crate::trie::MAX_DEPTH_NIBBLES,
        )),
        CompleteError::Domain(Domain::ExpectedBranch(hash)) => match Hash::from_slice(&hash) {
            Ok(hash) => MptError::NonCanonical(format!(
                "node {hash} sits under an extension but is not a branch"
            )),
            Err(_) => protocol_error(),
        },
        CompleteError::Domain(Domain::Exhausted) => {
            MptError::NonCanonical("the completeness walk outran its work budget".into())
        }
    })
}

pub(crate) fn protocol_error() -> MptError {
    MptError::store(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid native trie-operation protocol",
    ))
}

pub(crate) fn lookup_error(error: synch_verified::trie::LookupError<MptError>) -> MptError {
    use synch_verified::trie::LookupError;
    match error {
        LookupError::Host(error) => error,
        LookupError::MissingNode(hash) => MptError::MissingNode(Hash(hash)),
        LookupError::MissingValue(hash) => MptError::MissingValue(Hash(hash)),
        LookupError::KeyTooLong(size) => MptError::KeyTooLong(size),
        LookupError::Decode(message) => MptError::Decode(message),
        LookupError::DepthExceeded => {
            MptError::NonCanonical("lookup descended further than any valid key is long".into())
        }
        LookupError::Protocol => protocol_error(),
    }
}

/// The digest primitive for the canonical ingress boundary: exactly the bytes
/// Lean supplies, tag included, through BLAKE3. No node shape is interpreted.
pub(crate) struct Blake3;

impl synch_verified::host::Digest for Blake3 {
    type Error = MptError;
    fn blake3(&mut self, bytes: &[u8]) -> Result<Vec<u8>, MptError> {
        Ok(blake3::hash(bytes).as_bytes().to_vec())
    }
}

pub(crate) fn operation_error(error: synch_verified::trie::OperationError<MptError>) -> MptError {
    use synch_verified::trie::OperationError;
    match error {
        OperationError::Host(error) => error,
        OperationError::MalformedMetadata(_) | OperationError::Protocol => protocol_error(),
    }
}

/// A refusal is one of the store's existing diagnostics, by name.
pub(crate) fn refusal_error(refusal: synch_verified::trie::NodeRefusal) -> MptError {
    use synch_verified::trie::NodeRefusal;
    match refusal {
        NodeRefusal::Decode(message) => MptError::Decode(message),
        NodeRefusal::NonCanonical(message) => MptError::NonCanonical(message),
        NodeRefusal::KeyTooLong(bytes) => {
            MptError::KeyTooLong(usize::try_from(bytes).unwrap_or(usize::MAX))
        }
    }
}

impl<S: NodeStore + ?Sized> synch_verified::host::ByteWrites for Bytes<'_, S> {
    type Error = MptError;
    fn put_bytes(&mut self, space: &str, key: &[u8], bytes: &[u8]) -> Result<(), MptError> {
        let hash = Hash::from_slice(key).map_err(MptError::store)?;
        match space {
            "trie_nodes" => self.0.put_node(&hash, bytes).map_err(MptError::store),
            "trie_values" => self.0.put_value(&hash, bytes).map_err(MptError::store),
            _ => Err(protocol_error()),
        }
    }
}

/// A refused or failed write is one of the store's existing diagnostics.
pub(crate) fn mutation_error(error: synch_verified::trie::MutationDomainError) -> MptError {
    use synch_verified::trie::MutationDomainError;
    match error {
        MutationDomainError::KeyTooLong(bytes) => {
            MptError::KeyTooLong(usize::try_from(bytes).unwrap_or(usize::MAX))
        }
        MutationDomainError::ValueTooLong(bytes) => {
            MptError::ValueTooLong(usize::try_from(bytes).unwrap_or(usize::MAX))
        }
        MutationDomainError::MissingNode(hash) => match Hash::from_slice(&hash) {
            Ok(hash) => MptError::MissingNode(hash),
            Err(_) => protocol_error(),
        },
        MutationDomainError::Decode(message) => MptError::Decode(message),
        MutationDomainError::DepthExceeded => {
            MptError::NonCanonical("a write descended further than any valid key is long".into())
        }
    }
}

/// The refusals a peer recorded, answered by the node store.
pub(crate) struct Redactions<'a, S: ?Sized>(pub(crate) &'a S);

impl<S: NodeStore + ?Sized> synch_verified::host::Redaction for Redactions<'_, S> {
    type Error = MptError;
    fn is_redacted(&mut self, hash: &[u8], path: Option<&[u8]>) -> Result<bool, MptError> {
        let hash = Hash::from_slice(hash).map_err(MptError::store)?;
        self.0.is_redacted(&hash, path).map_err(MptError::store)
    }
}

/// The materializer of a head promotion as a walk service: each change is
/// handed to the caller's closure, and the first refusal is kept aside so
/// the caller's own error comes back rather than the sentinel that carried
/// it out of the walk.
pub(crate) struct Applier<'a, E> {
    pub(crate) apply: &'a mut dyn FnMut(crate::ChangeView<'_>) -> Result<(), E>,
    pub(crate) stopped: Option<E>,
}

impl<E> std::fmt::Debug for Applier<'_, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Applier").finish_non_exhaustive()
    }
}

impl<E> synch_verified::host::Apply for Applier<'_, E> {
    type Error = MptError;
    fn apply_change(&mut self, key: &[u8], kind: u64, new: Option<&[u8]>) -> Result<(), MptError> {
        let kind = match kind {
            0 => crate::ChangeKind::Added,
            1 => crate::ChangeKind::Changed,
            2 => crate::ChangeKind::Deleted,
            _ => return Err(protocol_error()),
        };
        match (self.apply)(crate::ChangeView { key, kind, new }) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.stopped = Some(error);
                Err(MptError::WalkStopped)
            }
        }
    }
}

/// A walk's refusal is one of the store's existing diagnostics, by name.
pub(crate) fn walk_error(error: synch_verified::trie::WalkError<MptError>) -> MptError {
    use synch_verified::trie::{TrieWalkDomainError, WalkError};
    match error {
        WalkError::Operation(error) => operation_error(error),
        WalkError::Domain(TrieWalkDomainError::MissingNode(hash)) => {
            match Hash::from_slice(&hash) {
                Ok(hash) => MptError::MissingNode(hash),
                Err(_) => protocol_error(),
            }
        }
        WalkError::Domain(TrieWalkDomainError::MissingValue(hash)) => match Hash::from_slice(&hash)
        {
            Ok(hash) => MptError::MissingValue(hash),
            Err(_) => protocol_error(),
        },
        WalkError::Domain(TrieWalkDomainError::Decode(message)) => MptError::Decode(message),
        WalkError::Domain(TrieWalkDomainError::OddDepthValue) => MptError::OddDepthValue,
        WalkError::Domain(TrieWalkDomainError::Ceiling) => MptError::NonCanonical(format!(
            "structural walk exceeded {} positions. If this is a cold \
             materialization of an origin that has been publishing for a long time, this \
             node cannot adopt it at all — its trie has grown past what any *first* \
             adoption here can walk, while incremental followers are unaffected",
            crate::trie::WALK_POSITION_CEILING
        )),
    }
}

/// A value reference as Lean reports it, in the store's own type.
pub(crate) fn value_ref(
    value: synch_verified::trie::TrieValue,
) -> Result<crate::ValueRef, MptError> {
    use synch_verified::trie::TrieValue;
    Ok(match value {
        TrieValue::Inline(bytes) => crate::ValueRef::Inline(bytes),
        TrieValue::Hash(address) => {
            crate::ValueRef::Hash(Hash::from_slice(&address).map_err(|_| protocol_error())?)
        }
    })
}
