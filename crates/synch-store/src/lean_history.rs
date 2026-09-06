//! Host adapters for the complete Lean retention command; no retention policy.
use crate::{lean_storage::SqliteStorage, Result, Store, StoreError};
use synch_core::{origin::OriginParseError, NodeId, OriginId};
use synch_verified::{
    cas::OperationError,
    history::{CellType, DomainError, Error, OriginError},
};

struct Crypto;
impl synch_verified::host::Crypto for Crypto {
    type Error = StoreError;
    fn validate_ed25519(&mut self, bytes: &[u8]) -> Result<bool> {
        Ok(<&[u8; 32]>::try_from(bytes).is_ok_and(|key| NodeId::from_bytes(key).is_ok()))
    }
}

fn error(error: Error<StoreError>) -> StoreError {
    match error {
        Error::Operation(OperationError::Host(error)) => error,
        Error::Operation(_) | Error::Domain(DomainError::Malformed) => {
            StoreError::invalid("invalid Lean history operation result")
        }
        Error::Domain(DomainError::ColumnType {
            index,
            column,
            actual,
        }) => rusqlite::Error::InvalidColumnType(
            index as usize,
            column,
            match actual {
                CellType::Null => rusqlite::types::Type::Null,
                CellType::Integer => rusqlite::types::Type::Integer,
                CellType::Real => rusqlite::types::Type::Real,
                CellType::Text => rusqlite::types::Type::Text,
                CellType::Blob => rusqlite::types::Type::Blob,
            },
        )
        .into(),
        Error::Domain(DomainError::InvalidText(bytes)) => match std::str::from_utf8(&bytes) {
            Err(error) => rusqlite::Error::Utf8Error(error).into(),
            Ok(_) => StoreError::invalid("invalid Lean UTF-8 diagnostic"),
        },
        Error::Domain(DomainError::Column { column, reason }) => {
            let column = match column.as_str() {
                "heads.root" => "heads.root",
                "heads.sig" => "heads.sig",
                "heads.signed_by" => "heads.signed_by",
                "head_history.root" => "head_history.root",
                _ => return StoreError::invalid("unknown Lean history column diagnostic"),
            };
            StoreError::column(column, reason)
        }
        Error::Domain(DomainError::Origin(error)) => {
            let error = match error {
                OriginError::Label(text) => OriginParseError::Label(text),
                OriginError::Domain(text) => OriginParseError::Domain(text),
                OriginError::Shape(text) => OriginParseError::Shape(text),
                OriginError::KeyDecode => {
                    OriginParseError::Key("failed to decode base32 string".into())
                }
                OriginError::KeyData => {
                    OriginParseError::Key("data is not a valid public key".into())
                }
            };
            StoreError::column("heads.origin_id", error.to_string())
        }
    }
}

pub(crate) fn prune(store: &Store, origin: &OriginId, before: i64) -> Result<usize> {
    store.with_connection_scope(|conn| {
        let mut storage = SqliteStorage::new(conn);
        let count =
            synch_verified::history::prune(&mut storage, &mut Crypto, &origin.canonical(), before)
                .map_err(error)?;
        usize::try_from(count).map_err(|_| StoreError::invalid("history deletion count overflow"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Slot;
    use rusqlite::{params, types::Value};
    use synch_verified::host::Crypto as _;

    #[test]
    fn key_origin_retention_runs_through_real_crypto_and_sqlite() {
        for seed in 1..=8 {
            let (_dir, store) = crate::testutil::store();
            let key = iroh_base::SecretKey::from_bytes(&[seed; 32]);
            let origin = OriginId::Key(key.public());
            for seq in 1..=3 {
                let head = synch_core::SignedHead::sign(
                    &key,
                    origin.clone(),
                    seq,
                    synch_core::Hash::new(&[seq as u8]),
                    0,
                );
                if seq == 3 {
                    store.put_head(Slot::Complete, &head, 0, 0).unwrap();
                } else {
                    store.record_history(&head, 0).unwrap();
                }
            }
            assert_eq!(store.prune_history_before(&origin, 10).unwrap(), 2);
            assert_eq!(store.head_history(&origin).unwrap().len(), 1);
            assert!(store.conn().is_autocommit());
        }
    }

    #[test]
    fn stored_head_diagnostics_match_the_existing_reader() {
        let invalid_key = (0u8..=255)
            .map(|byte| vec![byte; 32])
            .find(|bytes| !Crypto.validate_ed25519(bytes).unwrap())
            .unwrap();
        for case in 0..6 {
            let (_dir, store) = crate::testutil::store();
            let origin = OriginId::Named {
                id: if case == 2 { "bad_name" } else { "node" }.into(),
                domain: "example".into(),
            };
            let root: Vec<u8> = if case == 1 || case == 2 {
                vec![]
            } else {
                vec![1; 32]
            };
            let sig: Vec<u8> = if case == 1 { vec![] } else { vec![0; 64] };
            let key = match case {
                3 => Value::Blob(vec![]),
                4 => Value::Blob(invalid_key.clone()),
                5 => Value::Null,
                _ => Value::Blob(
                    iroh_base::SecretKey::generate()
                        .public()
                        .as_bytes()
                        .to_vec(),
                ),
            };
            let created = if case == 0 {
                Value::Text("bad".into())
            } else {
                Value::Integer(0)
            };
            {
                let conn = store.conn();
                conn.execute_batch("CREATE TEMP TABLE heads (origin_id, slot, seq, root, received_at, verified_at);
                    CREATE TEMP TABLE head_history (origin_id, seq, root, created_at, signed_by, sig, recorded_at);").unwrap();
                conn.execute(
                    "INSERT INTO heads VALUES (?1, 'complete', 1, ?2, 0, 0)",
                    params![origin.canonical(), root],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO head_history VALUES (?1, 1, ?2, ?3, ?4, ?5, 0)",
                    params![origin.canonical(), root, created, key, sig],
                )
                .unwrap();
            }
            let expected = store.head(&origin, Slot::Complete).unwrap_err();
            let actual = store.prune_history_before(&origin, 10).unwrap_err();
            assert_eq!(actual.to_string(), expected.to_string(), "case {case}");
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
            assert!(store.conn().is_autocommit());
        }
    }
}
