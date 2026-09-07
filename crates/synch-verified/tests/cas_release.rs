use synch_verified::cas::{unpin, OperationError, PinHolder};
use synch_verified::host::{Cell, Exclusion, Fields, Storage};
use synch_verified::host_unexpected;

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
        at_most: &Fields,
    ) -> Result<u64, Self::Error> {
        assert!(at_most.is_empty());
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
                keys: vec![],
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

    // The relational host is one trait; these operations never request the
    // read-repair, copy or expression-upsert statements.
    host_unexpected!(
        delete_except,
        scan_rows,
        read_rows,
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

#[test]
fn release_renders_typed_holders_and_uses_atomic_live_reference_guards() {
    let cases = [
        (PinHolder::Operator, "operator", None),
        (
            PinHolder::Source("space".into()),
            "source:space",
            Some("space"),
        ),
        (
            PinHolder::Replica("space".into()),
            "replica:space",
            Some("space"),
        ),
        (PinHolder::Other("custom".into()), "custom", None),
        (PinHolder::Other("source:x".into()), "source:x", None),
        (PinHolder::Other("replica:x".into()), "replica:x", None),
        (PinHolder::Source("".into()), "source:", Some("")),
        (PinHolder::Replica("".into()), "replica:", Some("")),
        (
            PinHolder::Source("雪:a".into()),
            "source:雪:a",
            Some("雪:a"),
        ),
        (
            PinHolder::Replica("雪:a".into()),
            "replica:雪:a",
            Some("雪:a"),
        ),
        (PinHolder::Other("雪:a".into()), "雪:a", None),
        (PinHolder::Other("".into()), "", None),
    ];
    for (holder, rendered, space) in cases {
        for affected in [0, 1, 2, u64::MAX] {
            let mut script = Script::new(rendered, space, affected);
            assert_eq!(
                unpin(&mut script, &ROOT, holder.clone()).unwrap(),
                affected != 0
            );
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
            match unpin(&mut script, &ROOT, PinHolder::Source("space".into())) {
                Err(OperationError::Host(error)) => assert_eq!(error, failure),
                result => panic!("expected original host failure, got {result:?}"),
            }
            assert_eq!(script.trace, expected);
        }
    }
}
