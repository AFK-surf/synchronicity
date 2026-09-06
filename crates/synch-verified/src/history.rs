//! Complete Lean retention command used by Store. This facade only starts the
//! command and hands its terminal back; it contains no retention algorithm.
use crate::{
    host::{Crypto, Storage},
    operation::{run, terminal, Capabilities, Command, OperationError},
};

pub use crate::generated::{CellType, HistoryDomainError as DomainError, OriginError};

/// Retention failure, preserving the original host error when applicable.
#[derive(Debug)]
pub enum Error<E> {
    Operation(OperationError<E>),
    Domain(DomainError),
}

/// Run retention with raw storage and primitive crypto. Lean owns transactions,
/// validation, retention decisions, mutations and rollback/error selection.
pub fn prune<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    origin: &str,
    before: i64,
) -> Result<u64, Error<S::Error>> {
    let command = Command::PruneHistory {
        origin: origin.to_owned(),
        before,
    };
    let capabilities = Capabilities {
        crypto: Some(crypto),
        ..Capabilities::default()
    };
    let result = run(storage, capabilities, &[], &command).map_err(Error::Operation)?;
    let outcome: Result<u64, DomainError> =
        terminal(&result).map_err(|()| Error::Operation(OperationError::Protocol))?;
    outcome.map_err(Error::Domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Cell, Fields, Join, Order, Row};
    use std::{cell::RefCell, rc::Rc};

    type Trace = Rc<RefCell<Vec<&'static str>>>;
    struct Rows {
        trace: Trace,
        head: Row,
        rollback_error: bool,
        receipts: Vec<Row>,
        scan_failure: Option<&'static str>,
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
        fn scan_rows(
            &mut self,
            tx: u64,
            relation: &str,
            columns: &[String],
            equals: &crate::host::Fields,
            order: &[crate::host::Order],
            joins: &[crate::host::Join],
        ) -> Result<crate::host::Scan<Self::Error>, Self::Error> {
            self.read_rows(tx, relation, columns, equals, order, joins)
                .map(|rows| crate::host::Scan {
                    rows,
                    failure: if relation == "head_history" {
                        self.scan_failure
                    } else {
                        None
                    },
                })
        }

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
                    Ok(self.receipts.clone())
                }
                _ => panic!("unexpected relation"),
            }
        }
        fn delete_rows(
            &mut self,
            _: u64,
            _: &str,
            _: &Fields,
            _: &[crate::host::Exclusion],
            _: &Fields,
        ) -> Result<u64, Self::Error> {
            panic!("unexpected delete")
        }
        host_unexpected!(
            exists_rows,
            upsert,
            read_bytes,
            snapshot,
            update,
            copy_rows,
            delete,
            write,
            snapshot_excluding
        );
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
                receipts: vec![],
                scan_failure: None,
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
        for bytes in [&[9][..], &[1, 0, 0][..], &[1, 4, 9][..], &[0, 0][..]] {
            assert!(terminal::<Result<u64, DomainError>>(bytes).is_err());
        }
        assert_eq!(
            terminal::<Result<u64, DomainError>>(&[1, 4, 2]),
            Ok(Err(DomainError::Origin(OriginError::KeyDecode)))
        );
    }

    #[test]
    fn earlier_row_error_wins_over_trailing_scan_failure() {
        for width in [0, 32] {
            let (mut rows, mut crypto, trace) = setup("node@example", Ok(true));
            rows.receipts = vec![vec![
                Cell::Integer(1),
                Cell::Blob(vec![0; width]),
                Cell::Integer(0),
            ]];
            rows.scan_failure = Some("scan failed");
            let result = prune(&mut rows, &mut crypto, "node@example", 10).unwrap_err();
            match (width, result) {
                (0, Error::Domain(DomainError::Column { column, reason })) => {
                    assert_eq!(column, "head_history.root");
                    assert_eq!(reason, "0 bytes, not 32");
                }
                (32, Error::Operation(OperationError::Host("scan failed"))) => (),
                other => panic!("wrong error order: {other:?}"),
            }
            assert_eq!(
                *trace.borrow(),
                ["begin", "heads", "crypto", "heads", "receipts", "rollback"]
            );
        }
    }
}
