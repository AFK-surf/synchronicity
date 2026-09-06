//! The native constructor drives literal host services for the entire read.
use std::{cell::RefCell, rc::Rc};
use synch_verified::host_unexpected;
use synch_verified::{
    cas::{self, OperationError, ReadDomainError, ReadError, ReadRequest},
    host::{
        Cell, Clock, Fields, FileFailure, FileFailureKind, FileIO, Join, Order, Row, Scan,
        Selection, SourceValue, Storage,
    },
};

const ROOT: [u8; 32] = [7; 32];
const TX: u64 = 41;
const HANDLE: u64 = 53;

#[derive(Default)]
struct Trace {
    calls: Vec<&'static str>,
    fail: Option<&'static str>,
    rollback_fails: bool,
}
impl Trace {
    fn step(&mut self, name: &'static str) -> Result<(), &'static str> {
        self.calls.push(name);
        if self.fail == Some(name) {
            Err(name)
        } else {
            Ok(())
        }
    }
}
type Shared = Rc<RefCell<Trace>>;

struct Database {
    trace: Shared,
    metadata: Vec<Row>,
    trailing: Option<&'static str>,
}
fn root_fields() -> Fields {
    vec![("root".into(), Cell::Blob(ROOT.to_vec()))]
}
fn metadata(size: i64, complete: bool, inline: Cell) -> Row {
    vec![
        Cell::Blob(ROOT.to_vec()),
        Cell::Integer(size),
        Cell::Integer(i64::from(complete)),
        Cell::Null,
        inline,
        Cell::Integer(99),
        Cell::Integer(1),
    ]
}
fn assert_root(selection: &Selection) {
    assert_eq!(selection.relation, "blobs");
    assert_eq!(selection.equals, root_fields());
    assert!(selection.like_any.is_empty());
}
fn assert_roles(selection: &Selection) {
    assert_eq!(selection.relation, "pins");
    assert_eq!(selection.equals, root_fields());
    assert_eq!(
        selection.like_any,
        [
            ("holder".into(), "source:%".into()),
            ("holder".into(), "replica:%".into())
        ]
    );
}
impl Storage for Database {
    type Error = &'static str;
    fn begin(&mut self) -> Result<u64, Self::Error> {
        self.trace.borrow_mut().step("begin")?;
        Ok(TX)
    }
    fn commit(&mut self, tx: u64) -> Result<(), Self::Error> {
        assert_eq!(tx, TX);
        self.trace.borrow_mut().step("commit")
    }
    fn rollback(&mut self, tx: u64) -> Result<(), Self::Error> {
        assert_eq!(tx, TX);
        let mut trace = self.trace.borrow_mut();
        trace.step("rollback")?;
        if trace.rollback_fails {
            Err("secondary rollback")
        } else {
            Ok(())
        }
    }
    fn read_rows(
        &mut self,
        tx: u64,
        relation: &str,
        columns: &[String],
        equals: &Fields,
        order: &[Order],
        joins: &[Join],
    ) -> Result<Vec<Row>, Self::Error> {
        assert_eq!(tx, TX);
        assert_eq!(relation, "blobs");
        assert_eq!(columns, ["size"]);
        assert_eq!(equals, &root_fields());
        assert!(order.is_empty() && joins.is_empty());
        self.trace.borrow_mut().step("size")?;
        Ok(vec![vec![Cell::Integer(4)]])
    }

    fn snapshot(
        &mut self,
        selection: &Selection,
        columns: &[String],
    ) -> Result<Scan<Self::Error>, Self::Error> {
        assert_root(selection);
        assert_eq!(
            columns,
            [
                "root",
                "size",
                "complete",
                "bitmap",
                "inline",
                "last_access",
                "durable"
            ]
        );
        self.trace.borrow_mut().step("snapshot")?;
        Ok(Scan {
            rows: self.metadata.clone(),
            failure: self.trailing,
        })
    }
    fn update(
        &mut self,
        tx: u64,
        selection: &Selection,
        values: &Fields,
    ) -> Result<u64, Self::Error> {
        assert_eq!(tx, TX);
        assert_root(selection);
        assert_eq!(
            values,
            &vec![
                ("complete".into(), Cell::Integer(0)),
                ("durable".into(), Cell::Integer(0)),
                ("bitmap".into(), Cell::Null),
                ("inline".into(), Cell::Null)
            ]
        );
        self.trace.borrow_mut().step("update")?;
        Ok(1)
    }
    fn copy_rows(
        &mut self,
        tx: u64,
        target: &str,
        source: &Selection,
        values: &[(String, SourceValue)],
        conflicts: &[String],
    ) -> Result<u64, Self::Error> {
        assert_eq!(tx, TX);
        assert_eq!(target, "content_want");
        assert_roles(source);
        assert_eq!(
            values,
            [
                ("root".into(), SourceValue::Column("root".into())),
                ("holder".into(), SourceValue::Column("holder".into())),
                ("size".into(), SourceValue::Literal(Cell::Integer(4))),
                ("prev".into(), SourceValue::Literal(Cell::Null)),
                (
                    "first_wanted".into(),
                    SourceValue::Literal(Cell::Integer(123))
                ),
            ]
        );
        assert_eq!(conflicts, ["root", "holder"]);
        self.trace.borrow_mut().step("copy")?;
        Ok(2)
    }
    fn delete(&mut self, tx: u64, selection: &Selection) -> Result<u64, Self::Error> {
        assert_eq!(tx, TX);
        assert_roles(selection);
        self.trace.borrow_mut().step("delete")?;
        Ok(2)
    }
    host_unexpected!(
        delete_except,
        scan_rows,
        exists_rows,
        upsert,
        delete_rows,
        read_bytes,
        write,
        snapshot_excluding
    );
}
struct Files {
    trace: Shared,
    bytes: Vec<u8>,
    open_failure: Option<FileFailureKind>,
    failure: Option<FileFailureKind>,
    reads: Vec<(u64, u64)>,
}
impl FileIO for Files {
    type Error = &'static str;
    fn open(&mut self, space: &str, key: &[u8]) -> Result<u64, FileFailure<Self::Error>> {
        assert_eq!(space, "cas_payload");
        assert_eq!(key, ROOT);
        self.trace
            .borrow_mut()
            .step("open")
            .map_err(|error| FileFailure {
                error,
                kind: FileFailureKind::Other,
            })?;
        if let Some(kind) = self.open_failure {
            return Err(FileFailure {
                error: "physical open",
                kind,
            });
        }
        Ok(HANDLE)
    }
    fn read_into(
        &mut self,
        handle: u64,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), FileFailure<Self::Error>> {
        assert_eq!(handle, HANDLE);
        self.reads.push((offset, buffer.len() as u64));
        self.trace
            .borrow_mut()
            .step("transfer")
            .map_err(|error| FileFailure {
                error,
                kind: FileFailureKind::Other,
            })?;
        if let Some(kind) = self.failure {
            // A failed transfer may have touched the sink's tail; the
            // interpreter takes it back and the caller sees no bytes.
            buffer.fill(255);
            return Err(FileFailure {
                error: "physical read",
                kind,
            });
        }
        let offset = usize::try_from(offset).unwrap();
        buffer.copy_from_slice(&self.bytes[offset..offset + buffer.len()]);
        Ok(())
    }
    fn close(&mut self, handle: u64) -> Result<(), Self::Error> {
        assert_eq!(handle, HANDLE);
        self.trace.borrow_mut().step("close")
    }
    host_unexpected!(read_at);
}
struct Time(Shared);
impl Clock for Time {
    type Error = &'static str;
    fn now_ns(&mut self) -> Result<i64, Self::Error> {
        self.0.borrow_mut().step("clock")?;
        Ok(123)
    }
}
fn fixture(size: i64, complete: bool, inline: Cell) -> (Shared, Database, Files, Time) {
    let trace = Rc::new(RefCell::new(Trace::default()));
    let db = Database {
        trace: trace.clone(),
        metadata: vec![metadata(size, complete, inline)],
        trailing: None,
    };
    let files = Files {
        trace: trace.clone(),
        bytes: vec![],
        open_failure: None,
        failure: None,
        reads: vec![],
    };
    let time = Time(trace.clone());
    (trace, db, files, time)
}
fn assert_host(result: Result<Vec<u8>, ReadError<&'static str>>, expected: &str) {
    match result {
        Err(ReadError::Operation(OperationError::Host(error))) => assert_eq!(error, expected),
        result => panic!("expected host error {expected}, got {result:?}"),
    }
}

#[test]
fn native_complete_read_uses_one_handle_and_one_transfer() {
    let (trace, mut db, mut files, mut clock) = fixture(65543, true, Cell::Null);
    files.bytes = (0..65543).map(|n| (n % 251) as u8).collect();
    let result = cas::read(&mut db, &mut files, &mut clock, &ROOT, ReadRequest::All).unwrap();
    assert_eq!(result, files.bytes);
    assert_eq!(files.reads, [(0, 65543)]);
    assert_eq!(
        trace.borrow().calls,
        ["snapshot", "open", "transfer", "close"]
    );
}

#[test]
fn native_partial_output_is_discarded_on_later_read_close_or_repair_failure() {
    for (physical_failure, host_failure) in [
        (Some(FileFailureKind::Other), None),
        (Some(FileFailureKind::ShortRead), None),
        (Some(FileFailureKind::ShortRead), Some("update")),
        (Some(FileFailureKind::ShortRead), Some("commit")),
        (None, Some("close")),
    ] {
        let (trace, mut db, mut files, mut clock) = fixture(65540, true, Cell::Null);
        files.bytes = vec![1; 65540];
        files.failure = physical_failure;
        trace.borrow_mut().fail = host_failure;
        assert_host(
            cas::read(&mut db, &mut files, &mut clock, &ROOT, ReadRequest::All),
            host_failure.unwrap_or("physical read"),
        );
        assert_eq!(files.reads, [(0, 65540)]);
        let calls = &trace.borrow().calls;
        assert_eq!(&calls[..4], ["snapshot", "open", "transfer", "close"]);
        if let Some(begin) = calls.iter().position(|step| *step == "begin") {
            assert_eq!(begin, 4, "healing must start after closing the file");
        }
    }
}

#[test]
fn native_ranged_read_offsets_and_clamps_in_lean() {
    let (trace, mut db, mut files, mut clock) = fixture(65550, true, Cell::Null);
    files.bytes = (0..65550).map(|n| (n % 251) as u8).collect();
    let result = cas::read(
        &mut db,
        &mut files,
        &mut clock,
        &ROOT,
        ReadRequest::Range {
            offset: 3,
            length: u64::MAX,
        },
    )
    .unwrap();
    assert_eq!(result, files.bytes[3..]);
    assert_eq!(files.reads, [(3, 65547)]);
    assert_eq!(
        trace.borrow().calls,
        ["snapshot", "open", "transfer", "close"]
    );
}

#[test]
fn native_missing_open_heals_without_closing_an_unopened_handle() {
    for kind in [
        FileFailureKind::Missing,
        FileFailureKind::ShortRead,
        FileFailureKind::Other,
    ] {
        let (trace, mut db, mut files, mut clock) = fixture(4, true, Cell::Null);
        files.open_failure = Some(kind);
        assert_host(
            cas::read(&mut db, &mut files, &mut clock, &ROOT, ReadRequest::All),
            "physical open",
        );
        let expected = if kind == FileFailureKind::Other {
            vec!["snapshot", "open"]
        } else {
            vec![
                "snapshot", "open", "begin", "size", "update", "clock", "copy", "delete", "commit",
            ]
        };
        assert_eq!(trace.borrow().calls, expected);
        assert!(files.reads.is_empty());
    }
}

#[test]
fn native_empty_unavailable_missing_and_inline_reads_need_no_file_services() {
    for (size, complete, request, expected) in [
        (0, false, ReadRequest::All, Ok(vec![])),
        (
            4,
            false,
            ReadRequest::Range {
                offset: 4,
                length: 100,
            },
            Ok(vec![]),
        ),
        (
            4,
            false,
            ReadRequest::All,
            Err(ReadDomainError::Unavailable),
        ),
    ] {
        let (trace, mut db, mut files, mut clock) = fixture(size, complete, Cell::Null);
        let result = cas::read(&mut db, &mut files, &mut clock, &ROOT, request);
        match (result, expected) {
            (Ok(bytes), Ok(expected)) => assert_eq!(bytes, expected),
            (Err(ReadError::Domain(error)), Err(expected)) => assert_eq!(error, expected),
            (actual, expected) => panic!("{actual:?} != {expected:?}"),
        }
        assert_eq!(trace.borrow().calls, ["snapshot"]);
    }
    let (trace, mut db, mut files, mut clock) = fixture(4, true, Cell::Blob(vec![1, 2, 3, 4]));
    db.trailing = Some("ignored after first row");
    assert_eq!(
        cas::read(
            &mut db,
            &mut files,
            &mut clock,
            &ROOT,
            ReadRequest::Range {
                offset: 1,
                length: 2
            }
        )
        .unwrap(),
        [2, 3]
    );
    assert_eq!(trace.borrow().calls, ["snapshot"]);
    db.metadata.clear();
    db.trailing = None;
    assert!(matches!(
        cas::read(&mut db, &mut files, &mut clock, &ROOT, ReadRequest::All),
        Err(ReadError::Domain(ReadDomainError::MissingBlob))
    ));
    db.trailing = Some("empty scan failure");
    assert_host(
        cas::read(&mut db, &mut files, &mut clock, &ROOT, ReadRequest::All),
        "empty scan failure",
    );
}

#[test]
fn native_complete_read_preserves_each_host_failure_and_closes_before_return() {
    for (fail, expected_calls) in [
        ("snapshot", vec!["snapshot"]),
        ("open", vec!["snapshot", "open"]),
        ("transfer", vec!["snapshot", "open", "transfer", "close"]),
        ("close", vec!["snapshot", "open", "transfer", "close"]),
    ] {
        let (trace, mut db, mut files, mut clock) = fixture(4, true, Cell::Null);
        trace.borrow_mut().fail = Some(fail);
        files.bytes = vec![1, 2, 3, 4];
        assert_host(
            cas::read(&mut db, &mut files, &mut clock, &ROOT, ReadRequest::All),
            fail,
        );
        assert_eq!(trace.borrow().calls, expected_calls);
    }
}

#[test]
fn native_healing_is_atomic_and_primary_failures_survive_rollback_failures() {
    let path = [
        "snapshot", "open", "transfer", "close", "begin", "size", "update", "clock", "copy",
        "delete", "commit",
    ];
    for kind in [FileFailureKind::Missing, FileFailureKind::ShortRead] {
        for fail in [
            None,
            Some("close"),
            Some("begin"),
            Some("size"),
            Some("update"),
            Some("clock"),
            Some("copy"),
            Some("delete"),
            Some("commit"),
        ] {
            for rollback_fails in [false, true] {
                let (trace, mut db, mut files, mut clock) = fixture(4, true, Cell::Null);
                trace.borrow_mut().fail = fail;
                trace.borrow_mut().rollback_fails = rollback_fails;
                files.failure = Some(kind);
                assert_host(
                    cas::read(&mut db, &mut files, &mut clock, &ROOT, ReadRequest::All),
                    fail.unwrap_or("physical read"),
                );
                let mut expected = match fail {
                    None => path.to_vec(),
                    Some(name) => {
                        path[..=path.iter().position(|step| *step == name).unwrap()].to_vec()
                    }
                };
                if matches!(
                    fail,
                    Some("size" | "update" | "clock" | "copy" | "delete" | "commit")
                ) {
                    expected.push("rollback");
                }
                assert_eq!(
                    trace.borrow().calls,
                    expected,
                    "failure {fail:?}, rollback {rollback_fails}"
                );
            }
        }
    }
}
