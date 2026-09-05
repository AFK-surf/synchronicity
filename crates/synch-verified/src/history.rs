//! Complete Lean retention command. Store cutover remains pending scan/error
//! compatibility; this facade only constructs commands and decodes final results.
use crate::{
    host::{Crypto, Storage},
    operation::{OperationError, Reader, Slice},
};

/// Storage class observed at a Lean-selected invalid column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellType {
    Null,
    Integer,
    Real,
    Text,
    Blob,
}

/// Origin parse failure selected by Lean, with original text for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginError {
    Label(String),
    Domain(String),
    KeyDecode,
    KeyData,
    Shape(String),
}

/// Completed domain validation error, not a host service request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    Malformed,
    ColumnType {
        index: u64,
        column: String,
        actual: CellType,
    },
    InvalidText(Vec<u8>),
    Column {
        column: String,
        reason: String,
    },
    Origin(OriginError),
}

/// Retention failure, preserving the original host error when applicable.
#[derive(Debug)]
pub enum Error<E> {
    Operation(OperationError<E>),
    Domain(DomainError),
}

fn decode(bytes: &[u8]) -> Result<Result<u64, DomainError>, ()> {
    let mut r = Reader(bytes);
    let result = match r.byte()? {
        0 => Ok(r.word()?),
        1 => Err(DomainError::Malformed),
        2 => Err(DomainError::ColumnType {
            index: r.word()?,
            column: r.string()?,
            actual: match r.byte()? {
                0 => CellType::Null,
                1 => CellType::Integer,
                2 => CellType::Real,
                3 => CellType::Text,
                4 => CellType::Blob,
                _ => return Err(()),
            },
        }),
        3 => Err(DomainError::InvalidText(r.bytes()?)),
        4 => Err(DomainError::Column {
            column: r.string()?,
            reason: r.string()?,
        }),
        5 => Err(DomainError::Origin(match r.byte()? {
            0 => OriginError::Label(r.string()?),
            1 => OriginError::Domain(r.string()?),
            2 => OriginError::KeyDecode,
            3 => OriginError::KeyData,
            4 => OriginError::Shape(r.string()?),
            _ => return Err(()),
        })),
        _ => return Err(()),
    };
    r.end()?;
    Ok(result)
}

/// Run retention with raw storage and primitive crypto. Lean owns transactions,
/// validation, retention decisions, mutations and rollback/error selection.
pub fn prune<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    origin: &str,
    before: i64,
) -> Result<u64, Error<S::Error>> {
    unsafe extern "C" {
        fn synch_adapter_operation_history_prune(
            origin: Slice,
            before: u64,
        ) -> *mut std::ffi::c_void;
    }
    // SAFETY: the runner initializes Lean; the constructor copies the input and
    // returns one fresh owned native continuation, confined to this call.
    let result = unsafe {
        crate::operation::run_with_crypto(storage, crypto, || {
            synch_adapter_operation_history_prune(origin.as_bytes().into(), before as u64)
        })
    }
    .map_err(Error::Operation)?;
    decode(&result)
        .map_err(|()| Error::Operation(OperationError::Protocol))?
        .map_err(Error::Domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Cell, Exclusion, Fields, Join, Order, Row};
    use std::{cell::RefCell, rc::Rc};

    type Trace = Rc<RefCell<Vec<&'static str>>>;
    struct Rows {
        trace: Trace,
        head: Row,
        rollback_error: bool,
    }
    struct Primitive {
        trace: Trace,
        result: Result<bool, &'static str>,
        keys: Vec<Vec<u8>>,
    }
    impl Crypto for Primitive {
        type Error = &'static str;
        fn validate_ed25519(&mut self, bytes: &[u8]) -> Result<bool, Self::Error> {
            self.trace.borrow_mut().push("crypto");
            self.keys.push(bytes.to_vec());
            self.result
        }
    }
    impl Storage for Rows {
        type Error = &'static str;
        fn begin(&mut self) -> Result<u64, Self::Error> {
            self.trace.borrow_mut().push("begin");
            Ok(7)
        }
        fn commit(&mut self, tx: u64) -> Result<(), Self::Error> {
            assert_eq!(tx, 7);
            self.trace.borrow_mut().push("commit");
            Ok(())
        }
        fn rollback(&mut self, tx: u64) -> Result<(), Self::Error> {
            assert_eq!(tx, 7);
            self.trace.borrow_mut().push("rollback");
            if self.rollback_error {
                Err("rollback failed")
            } else {
                Ok(())
            }
        }
        fn read_rows(
            &mut self,
            tx: u64,
            relation: &str,
            _: &[String],
            equals: &Fields,
            _: &[Order],
            _: &[Join],
        ) -> Result<Vec<Row>, Self::Error> {
            assert_eq!(tx, 7);
            match relation {
                "heads" => {
                    self.trace.borrow_mut().push("heads");
                    Ok(
                        if equals.contains(&("slot".into(), Cell::Text("complete".into()))) {
                            vec![self.head.clone()]
                        } else {
                            vec![]
                        },
                    )
                }
                "head_history" => {
                    self.trace.borrow_mut().push("receipts");
                    Ok(vec![])
                }
                _ => panic!("unexpected relation"),
            }
        }
        fn exists_rows(&mut self, _: u64, _: &str, _: &Fields) -> Result<bool, Self::Error> {
            panic!("unexpected exists")
        }
        fn upsert(
            &mut self,
            _: u64,
            _: &str,
            _: &Fields,
            _: &[String],
            _: &[String],
        ) -> Result<(), Self::Error> {
            panic!("unexpected upsert")
        }
        fn delete_rows(
            &mut self,
            _: u64,
            _: &str,
            _: &Fields,
            _: &[Exclusion],
        ) -> Result<u64, Self::Error> {
            panic!("unexpected delete")
        }
        fn read_bytes(&mut self, _: &str, _: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            panic!("unexpected bytes")
        }
    }
    fn setup(origin: &str, result: Result<bool, &'static str>) -> (Rows, Primitive, Trace) {
        let trace = Trace::default();
        let head = vec![
            Cell::Text(origin.into()),
            Cell::Integer(1),
            Cell::Blob(vec![1; 32]),
            Cell::Integer(0),
            Cell::Blob(vec![2; 32]),
            Cell::Blob(vec![0; 64]),
            Cell::Integer(0),
            Cell::Integer(0),
        ];
        (
            Rows {
                trace: trace.clone(),
                head,
                rollback_error: false,
            },
            Primitive {
                trace: trace.clone(),
                result,
                keys: vec![],
            },
            trace,
        )
    }
    #[test]
    fn named_head_validates_signing_key_before_reading_more() {
        let (mut rows, mut crypto, trace) = setup("node@example", Ok(true));
        assert_eq!(
            prune(&mut rows, &mut crypto, "node@example", 10).unwrap(),
            0
        );
        assert_eq!(
            *trace.borrow(),
            ["begin", "heads", "crypto", "heads", "receipts", "commit"]
        );
        assert_eq!(crypto.keys, [vec![2; 32]]);
    }
    #[test]
    fn key_origin_and_signing_key_are_separate_primitive_checks() {
        let origin = format!("key:{}", "y".repeat(52));
        let (mut rows, mut crypto, trace) = setup(&origin, Ok(true));
        assert_eq!(prune(&mut rows, &mut crypto, &origin, 10).unwrap(), 0);
        assert_eq!(crypto.keys, [vec![0; 32], vec![2; 32]]);
        assert_eq!(
            *trace.borrow(),
            ["begin", "heads", "crypto", "crypto", "heads", "receipts", "commit"]
        );
    }
    #[test]
    fn invalid_key_and_host_error_are_distinct_and_rollback() {
        for result in [Ok(false), Err("crypto failed")] {
            let (mut rows, mut crypto, trace) = setup("node@example", result);
            rows.rollback_error = true;
            match (
                result,
                prune(&mut rows, &mut crypto, "node@example", 10).unwrap_err(),
            ) {
                (Ok(false), Error::Domain(DomainError::Column { column, reason })) => {
                    assert_eq!(column, "heads.signed_by");
                    assert_eq!(reason, "data is not a valid public key");
                }
                (Err(_), Error::Operation(OperationError::Host("crypto failed"))) => (),
                other => panic!("wrong primary error: {other:?}"),
            }
            assert_eq!(*trace.borrow(), ["begin", "heads", "crypto", "rollback"]);
        }
    }
    #[test]
    fn syntax_failure_is_terminal_domain_data_not_a_host_callback() {
        let (mut rows, mut crypto, trace) = setup("bad_name@example", Ok(true));
        assert!(
            matches!(prune(&mut rows, &mut crypto, "bad_name@example", 10),
            Err(Error::Domain(DomainError::Origin(OriginError::Label(original)))) if original == "bad_name")
        );
        assert!(crypto.keys.is_empty());
        assert_eq!(*trace.borrow(), ["begin", "heads", "rollback"]);
    }
    #[test]
    fn terminal_decoder_rejects_unknown_tags_and_trailing_data() {
        for bytes in [&[9][..], &[2, 0][..], &[5, 9][..], &[1, 0][..]] {
            assert!(decode(bytes).is_err());
        }
    }
}
