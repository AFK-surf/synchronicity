//! Complete trie operations. No decoded node shapes cross this interface.
use crate::{
    host::ByteStorage,
    operation::{self, terminal, Command, OperationError},
};

pub use crate::generated::LookupDomainError;

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
