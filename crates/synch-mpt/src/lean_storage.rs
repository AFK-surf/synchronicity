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
