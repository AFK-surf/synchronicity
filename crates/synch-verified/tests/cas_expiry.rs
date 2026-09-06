use synch_verified::cas::{expire, OperationError, PinHolder};
use synch_verified::host::{Cell, Exclusion, Fields, Storage};
use synch_verified::host_unexpected;

const TX: u64 = 81;

struct Script {
    holder: Option<&'static str>,
    now: i64,
    affected: u64,
    failure: Option<&'static str>,
    rollback_fails: bool,
    trace: Vec<&'static str>,
}

impl Script {
    fn new(holder: Option<&'static str>, now: i64, affected: u64) -> Self {
        Self {
            holder,
            now,
            affected,
            failure: None,
            rollback_fails: false,
            trace: vec![],
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
        assert_eq!(tx, TX);
        assert_eq!(relation, "pins");
        let expected: Fields = self
            .holder
            .map(|holder| ("holder".into(), Cell::Text(holder.into())))
            .into_iter()
            .collect();
        assert_eq!(equals, &expected);
        assert_eq!(
            unless,
            &[Exclusion {
                relation: "entries".into(),
                equals: vec![],
                keys: vec![("root".into(), "content".into())],
            }]
        );
        assert_eq!(
            at_most,
            &vec![("release_after".into(), Cell::Integer(self.now))]
        );
        self.step("delete")?;
        Ok(self.affected)
    }

    // The relational host is one trait; these operations never request the
    // read-repair, copy or expression-upsert statements.
    host_unexpected!(
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
fn expiry_is_one_atomic_mutation_for_optional_typed_holder_and_signed_time() {
    let cases = [
        (None, None),
        (Some(PinHolder::Operator), Some("operator")),
        (
            Some(PinHolder::Source("space".into())),
            Some("source:space"),
        ),
        (
            Some(PinHolder::Replica("space".into())),
            Some("replica:space"),
        ),
        (Some(PinHolder::Other("source:x".into())), Some("source:x")),
        (Some(PinHolder::Other("".into())), Some("")),
        (Some(PinHolder::Source("雪:a".into())), Some("source:雪:a")),
    ];
    for (holder, rendered) in cases {
        for now in [i64::MIN, -1, 0, i64::MAX] {
            for affected in [0, 1, 2, u64::MAX] {
                let mut script = Script::new(rendered, now, affected);
                assert_eq!(expire(&mut script, holder.clone(), now).unwrap(), affected);
                assert_eq!(script.trace, ["begin", "delete", "commit"]);
            }
        }
    }
}

#[test]
fn expiry_failure_preserves_primary_error_and_transaction_trace() {
    for (failure, expected) in [
        ("begin", vec!["begin"]),
        ("delete", vec!["begin", "delete", "rollback"]),
        ("commit", vec!["begin", "delete", "commit", "rollback"]),
    ] {
        for rollback_fails in [false, true] {
            let mut script = Script::new(None, 12, 3);
            script.failure = Some(failure);
            script.rollback_fails = rollback_fails;
            match expire(&mut script, None, 12) {
                Err(OperationError::Host(error)) => assert_eq!(error, failure),
                result => panic!("expected original host failure, got {result:?}"),
            }
            assert_eq!(script.trace, expected);
        }
    }
}
