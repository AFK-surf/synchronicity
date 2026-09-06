#[test]
fn pin_acquisition_requires_durability_and_orders_possession_effects() {
    use synch_verified::host::{Cell, Fields, Row, Storage};

    struct Script {
        durable: Option<i64>,
        wanted: bool,
        trace: Vec<&'static str>,
    }

    fn key() -> Fields {
        vec![
            ("root".into(), Cell::Blob(vec![0; 32])),
            ("holder".into(), Cell::Text("replica:space".into())),
        ]
    }

    impl Storage for Script {
        fn scan_rows(
            &mut self,
            tx: u64,
            relation: &str,
            columns: &[String],
            equals: &synch_verified::host::Fields,
            order: &[synch_verified::host::Order],
            joins: &[synch_verified::host::Join],
        ) -> Result<synch_verified::host::Scan<Self::Error>, Self::Error> {
            self.read_rows(tx, relation, columns, equals, order, joins)
                .map(|rows| synch_verified::host::Scan {
                    rows,
                    failure: None,
                })
        }

        type Error = &'static str;

        fn begin(&mut self) -> Result<u64, Self::Error> {
            self.trace.push("begin");
            Ok(7)
        }
        fn commit(&mut self, tx: u64) -> Result<(), Self::Error> {
            assert_eq!(tx, 7);
            self.trace.push("commit");
            Ok(())
        }
        fn read_rows(
            &mut self,
            tx: u64,
            relation: &str,
            columns: &[String],
            equals: &Fields,
            _order: &[synch_verified::host::Order],
            _joins: &[synch_verified::host::Join],
        ) -> Result<Vec<Row>, Self::Error> {
            assert_eq!(tx, 7);
            match relation {
                "blobs" => {
                    assert_eq!(columns, ["durable"]);
                    assert_eq!(equals, &key()[..1]);
                    self.trace.push("read durable");
                    Ok(self
                        .durable
                        .map(|value| vec![Cell::Integer(value)])
                        .into_iter()
                        .collect())
                }
                "content_want" => {
                    assert_eq!(columns, ["root"]);
                    assert_eq!(equals, &key());
                    self.trace.push("read want");
                    Ok(if self.wanted {
                        vec![vec![Cell::Blob(vec![0; 32])]]
                    } else {
                        vec![]
                    })
                }
                _ => panic!("unexpected raw relation"),
            }
        }
        fn upsert(
            &mut self,
            tx: u64,
            relation: &str,
            values: &Fields,
            conflicts: &[String],
            updates: &[String],
        ) -> Result<(), Self::Error> {
            assert_eq!(tx, 7);
            assert_eq!(relation, "pins");
            assert_eq!(conflicts, ["root", "holder"]);
            assert_eq!(updates, ["release_after"]);
            let mut expected = key();
            expected.extend([
                ("created_at".into(), Cell::Integer(-17)),
                ("release_after".into(), Cell::Null),
            ]);
            assert_eq!(values, &expected);
            self.trace.push("upsert pin");
            Ok(())
        }
        fn delete_rows(
            &mut self,
            tx: u64,
            relation: &str,
            equals: &Fields,
            _unless: &[synch_verified::host::Exclusion],
            at_most: &Fields,
        ) -> Result<u64, Self::Error> {
            assert!(at_most.is_empty());
            assert_eq!(tx, 7);
            assert_eq!(relation, "content_want");
            assert_eq!(equals, &key());
            self.trace.push("delete want");
            Ok(1)
        }

        // The relational host is one trait; these operations never request the
        // read-repair, copy or expression-upsert statements.

        synch_verified::host_unexpected!(
            exists_rows,
            rollback,
            read_bytes,
            snapshot,
            update,
            copy_rows,
            delete,
            write
        );
    }

    for durable in [None, Some(0), Some(1), Some(-7), Some(i64::MIN)] {
        for wanted in [false, true] {
            for possession in [false, true] {
                let mut script = Script {
                    durable,
                    wanted,
                    trace: vec![],
                };
                let accepted = synch_verified::cas::acquire(
                    &mut script,
                    &[0; 32],
                    "replica:space",
                    -17,
                    possession,
                )
                .unwrap();
                let durable = durable.is_some_and(|value| value != 0);
                let expected = durable && (!possession || wanted);
                assert_eq!(accepted, expected);
                let mut trace = vec!["begin", "read durable"];
                // A plain pin has no use for the want; possession consults
                // it only once the row is known durable.
                if durable && possession {
                    trace.push("read want");
                }
                if expected {
                    if possession {
                        trace.push("delete want");
                    }
                    trace.push("upsert pin");
                }
                trace.push("commit");
                assert_eq!(script.trace, trace);
            }
        }
    }
}

#[test]
fn deletion_protocol_checks_every_protection_and_orders_effects() {
    use std::{cell::RefCell, rc::Rc};
    use synch_verified::{
        cas::{delete, Outcome::*},
        host::{Cell, Fields, Resources, Row, Storage},
    };
    fn step(
        trace: &RefCell<Vec<&'static str>>,
        fail_at: Option<usize>,
        label: &'static str,
    ) -> Result<(), &'static str> {
        let mut trace = trace.borrow_mut();
        let index = trace.len();
        trace.push(label);
        if fail_at == Some(index) {
            Err("primary failure")
        } else {
            Ok(())
        }
    }
    struct Sql {
        fail_at: Option<usize>,
        trace: Rc<RefCell<Vec<&'static str>>>,
        accessed: Option<i64>,
        pinned: bool,
        referenced: bool,
    }
    struct Files {
        fail_at: Option<usize>,
        trace: Rc<RefCell<Vec<&'static str>>>,
        writing: bool,
    }
    impl Storage for Sql {
        fn scan_rows(
            &mut self,
            tx: u64,
            relation: &str,
            columns: &[String],
            equals: &synch_verified::host::Fields,
            order: &[synch_verified::host::Order],
            joins: &[synch_verified::host::Join],
        ) -> Result<synch_verified::host::Scan<Self::Error>, Self::Error> {
            self.read_rows(tx, relation, columns, equals, order, joins)
                .map(|rows| synch_verified::host::Scan {
                    rows,
                    failure: None,
                })
        }

        type Error = &'static str;
        fn begin(&mut self) -> Result<u64, Self::Error> {
            step(&self.trace, self.fail_at, "begin")?;
            Ok(7)
        }
        fn commit(&mut self, tx: u64) -> Result<(), Self::Error> {
            assert_eq!(tx, 7);
            step(&self.trace, self.fail_at, "commit")?;
            Ok(())
        }
        fn rollback(&mut self, _: u64) -> Result<(), Self::Error> {
            self.trace.borrow_mut().push("rollback");
            Err("rollback failure")
        }
        fn exists_rows(
            &mut self,
            tx: u64,
            table: &str,
            equals: &Fields,
        ) -> Result<bool, Self::Error> {
            assert_eq!(tx, 7);
            let (column, exists) = match table {
                "pins" => {
                    step(&self.trace, self.fail_at, "pins")?;
                    ("root", self.pinned)
                }
                "entries" => {
                    step(&self.trace, self.fail_at, "entries")?;
                    ("content", self.referenced)
                }
                _ => panic!("unexpected table"),
            };
            assert_eq!(equals, &vec![(column.into(), Cell::Blob(vec![9; 32]))]);
            Ok(exists)
        }
        fn read_rows(
            &mut self,
            tx: u64,
            table: &str,
            columns: &[String],
            equals: &Fields,
            _order: &[synch_verified::host::Order],
            _joins: &[synch_verified::host::Join],
        ) -> Result<Vec<Row>, Self::Error> {
            assert_eq!(tx, 7);
            assert_eq!(table, "blobs");
            assert_eq!(columns, &["last_access"]);
            assert_eq!(equals, &vec![("root".into(), Cell::Blob(vec![9; 32]))]);
            step(&self.trace, self.fail_at, "access")?;
            Ok(self
                .accessed
                .map(|n| vec![vec![Cell::Integer(n)]])
                .unwrap_or_default())
        }
        fn delete_rows(
            &mut self,
            tx: u64,
            table: &str,
            equals: &Fields,
            _unless: &[synch_verified::host::Exclusion],
            at_most: &synch_verified::host::Fields,
        ) -> Result<u64, Self::Error> {
            assert!(at_most.is_empty());
            assert_eq!(tx, 7);
            assert_eq!(table, "blobs");
            assert_eq!(equals, &vec![("root".into(), Cell::Blob(vec![9; 32]))]);
            step(&self.trace, self.fail_at, "delete")?;
            Ok(u64::from(self.accessed.is_some()))
        }

        // The relational host is one trait; these operations never request the
        // read-repair, copy or expression-upsert statements.

        synch_verified::host_unexpected!(
            upsert, read_bytes, snapshot, update, copy_rows, delete, write
        );
    }
    impl Resources for Files {
        type Error = &'static str;
        fn read_counter(&mut self, space: &str, key: &[u8]) -> Result<u64, Self::Error> {
            assert_eq!(space, "cas_writers");
            assert_eq!(key, &[9; 32]);
            step(&self.trace, self.fail_at, "writers")?;
            Ok(if self.writing { 3 } else { 0 })
        }
        fn remove_file(&mut self, space: &str, key: &[u8]) -> Result<(), Self::Error> {
            assert_eq!(key, &[9; 32]);
            self.trace.borrow_mut().push(match space {
                "cas_payload" => "payload",
                "cas_outboard" => "outboard",
                _ => panic!("unexpected namespace"),
            });
            // Both removals must be attempted even when they fail.
            Err("injected unlink failure")
        }
    }
    for row in [false, true] {
        for writing in [false, true] {
            for pinned in [false, true] {
                for referenced in [false, true] {
                    for last in [i64::MIN, -1, 0, 1, i64::MAX] {
                        for before in [None, Some(i64::MIN), Some(-1), Some(0), Some(i64::MAX)] {
                            let trace = Rc::new(RefCell::new(Vec::new()));
                            let mut sql = Sql {
                                fail_at: None,
                                trace: trace.clone(),
                                accessed: row.then_some(last),
                                pinned,
                                referenced,
                            };
                            let mut files = Files {
                                fail_at: None,
                                trace: trace.clone(),
                                writing,
                            };
                            let outcome = delete(&mut sql, &mut files, &[9; 32], before).unwrap();
                            let expected = if writing {
                                Writing
                            } else if pinned || referenced {
                                ProtectedClaim
                            } else if before.is_some_and(|cutoff| !row || last >= cutoff) {
                                Skipped
                            } else {
                                Applied
                            };
                            assert_eq!(outcome, expected);
                            let mut expected_trace =
                                vec!["begin", "pins", "entries", "access", "writers"];
                            if expected == Applied {
                                expected_trace.push("delete");
                            }
                            expected_trace.push("commit");
                            if expected == Applied {
                                expected_trace.extend(["payload", "outboard"]);
                            }
                            assert_eq!(*trace.borrow(), expected_trace);
                        }
                    }
                }
            }
        }
    }

    for fail_at in 0..7 {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut sql = Sql {
            trace: trace.clone(),
            accessed: Some(-1),
            pinned: false,
            referenced: false,
            fail_at: Some(fail_at),
        };
        let mut files = Files {
            trace: trace.clone(),
            writing: false,
            fail_at: Some(fail_at),
        };
        let result = delete(&mut sql, &mut files, &[9; 32], None);
        assert!(matches!(
            result,
            Err(synch_verified::cas::LifecycleError::Operation(
                synch_verified::cas::OperationError::Host("primary failure")
            ))
        ));
        let success = [
            "begin", "pins", "entries", "access", "writers", "delete", "commit",
        ];
        let mut expected = success[..=fail_at].to_vec();
        if fail_at > 0 {
            expected.push("rollback");
        }
        assert_eq!(*trace.borrow(), expected);
    }
}
