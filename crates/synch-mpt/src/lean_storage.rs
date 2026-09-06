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
