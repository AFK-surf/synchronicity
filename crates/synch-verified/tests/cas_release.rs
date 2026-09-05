use synch_verified::cas::{unpin, OperationError, PinHolder};
use synch_verified::host::{Cell, Exclusion, Fields, Join, Order, Row, Scan, Storage};

const ROOT: [u8; 32] = [0xa7; 32];
const TX: u64 = 73;

struct Script {
    holder: &'static str,
    space: Option<&'static str>,
    affected: u64,
    failure: Option<&'static str>,
    rollback_fails: bool,
    trace: Vec<&'static str>,
}

impl Script {
    fn new(holder: &'static str, space: Option<&'static str>, affected: u64) -> Self {
        Self {
            holder,
            space,
            affected,
            failure: None,
            rollback_fails: false,
            trace: Vec::new(),
        }
    }

    fn step(&mut self, name: &'static str) -> Result<(), &'static str> {
        self.trace.push(name);
        if self.failure == Some(name) {
            Err(name)
        } else {
            Ok(())
        }
    }
}

impl Storage for Script {
    type Error = &'static str;

    fn begin(&mut self) -> Result<u64, Self::Error> {
        self.step("begin")?;
        Ok(TX)
    }

    fn commit(&mut self, tx: u64) -> Result<(), Self::Error> {
        assert_eq!(tx, TX);
        self.step("commit")
    }

    fn rollback(&mut self, tx: u64) -> Result<(), Self::Error> {
        assert_eq!(tx, TX);
        self.trace.push("rollback");
        if self.rollback_fails {
            Err("rollback")
        } else {
            Ok(())
        }
    }

    fn delete_rows(
        &mut self,
        tx: u64,
        relation: &str,
        equals: &Fields,
        unless: &[Exclusion],
    ) -> Result<u64, Self::Error> {
        assert_eq!(tx, TX);
        assert_eq!(relation, "pins");
        assert_eq!(
            equals,
            &vec![
                ("root".into(), Cell::Blob(ROOT.to_vec())),
                ("holder".into(), Cell::Text(self.holder.into())),
            ]
        );
        let expected: Vec<_> = self
            .space
            .map(|space| Exclusion {
                relation: "entries".into(),
                equals: vec![
                    ("space".into(), Cell::Text(space.into())),
                    ("content".into(), Cell::Blob(ROOT.to_vec())),
                ],
            })
            .into_iter()
            .collect();
        assert_eq!(unless, expected);
        self.step("delete")?;
        Ok(self.affected)
    }

    fn scan_rows(
        &mut self,
        _: u64,
        _: &str,
        _: &[String],
        _: &Fields,
        _: &[Order],
        _: &[Join],
    ) -> Result<Scan<Self::Error>, Self::Error> {
        panic!("release must not scan rows")
    }

    fn read_rows(
        &mut self,
        _: u64,
        _: &str,
        _: &[String],
        _: &Fields,
        _: &[Order],
        _: &[Join],
    ) -> Result<Vec<Row>, Self::Error> {
        panic!("release must not read rows")
    }

    fn exists_rows(&mut self, _: u64, _: &str, _: &Fields) -> Result<bool, Self::Error> {
        panic!("release protection must be atomic with deletion")
    }

    fn upsert(
        &mut self,
        _: u64,
        _: &str,
        _: &Fields,
        _: &[String],
        _: &[String],
    ) -> Result<(), Self::Error> {
        panic!("release must not upsert")
    }

    fn read_bytes(&mut self, _: &str, _: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        panic!("release must not read bytes")
    }
}

#[test]
fn release_renders_typed_holders_and_uses_atomic_live_reference_guards() {
    let cases = [
        (PinHolder::Operator, "operator", None),
        (PinHolder::Source("space"), "source:space", Some("space")),
        (PinHolder::Replica("space"), "replica:space", Some("space")),
        (PinHolder::Other("custom"), "custom", None),
        (PinHolder::Other("source:x"), "source:x", None),
        (PinHolder::Other("replica:x"), "replica:x", None),
        (PinHolder::Source(""), "source:", Some("")),
        (PinHolder::Replica(""), "replica:", Some("")),
        (PinHolder::Source("雪:a"), "source:雪:a", Some("雪:a")),
        (PinHolder::Replica("雪:a"), "replica:雪:a", Some("雪:a")),
        (PinHolder::Other("雪:a"), "雪:a", None),
        (PinHolder::Other(""), "", None),
    ];
    for (holder, rendered, space) in cases {
        for affected in [0, 1, 2, u64::MAX] {
            let mut script = Script::new(rendered, space, affected);
            assert_eq!(unpin(&mut script, &ROOT, holder).unwrap(), affected != 0);
            assert_eq!(script.trace, ["begin", "delete", "commit"]);
        }
    }
}

#[test]
fn release_failure_preserves_primary_error_and_transaction_trace() {
    for (failure, expected) in [
        ("begin", vec!["begin"]),
        ("delete", vec!["begin", "delete", "rollback"]),
        ("commit", vec!["begin", "delete", "commit", "rollback"]),
    ] {
        for rollback_fails in [false, true] {
            let mut script = Script::new("source:space", Some("space"), 1);
            script.failure = Some(failure);
            script.rollback_fails = rollback_fails;
            match unpin(&mut script, &ROOT, PinHolder::Source("space")) {
                Err(OperationError::Host(error)) => assert_eq!(error, failure),
                result => panic!("expected original host failure, got {result:?}"),
            }
            assert_eq!(script.trace, expected);
        }
    }
}
