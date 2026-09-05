//! Private synchronous transport for raw storage/resource and crypto effects.
use crate::host::{ByteStorage, Cell, Exclusion, Fields, Join, Order, Resources, Row, Storage};
use std::{ffi::c_void, marker::PhantomData, ptr::NonNull, rc::Rc};

#[derive(Debug)]
pub enum OperationError<E> {
    Host(E),
    MalformedMetadata(u64),
    Protocol,
}

impl<E: std::fmt::Display> std::fmt::Display for OperationError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host(error) => error.fmt(f),
            Self::MalformedMetadata(_) => f.write_str("malformed Lean operation metadata"),
            Self::Protocol => f.write_str("invalid Lean host-effect protocol"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for OperationError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Host(error) => Some(error),
            _ => None,
        }
    }
}

#[repr(C)]
pub(crate) struct Slice {
    ptr: *const u8,
    len: usize,
}
impl From<&[u8]> for Slice {
    fn from(value: &[u8]) -> Self {
        Self {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }
}

unsafe extern "C" {
    fn synch_adapter_operation_packet(state: *mut c_void) -> *mut c_void;
    fn synch_adapter_operation_resume(state: *mut c_void, reply: Slice) -> *mut c_void;
    fn synch_adapter_bytes_len(bytes: *mut c_void) -> usize;
    fn synch_adapter_bytes_data(bytes: *mut c_void) -> *const u8;
    fn synch_adapter_scope_drop(value: *mut c_void);
}

// Never exported or made Send/Sync. The interpreter and all host resources
// remain on the caller's stack and thread, including panic unwinding.
struct Handle(NonNull<c_void>, PhantomData<Rc<()>>);
impl Handle {
    fn new(ptr: *mut c_void) -> Self {
        Self(
            NonNull::new(ptr).expect("Lean returned a null object"),
            PhantomData,
        )
    }
    fn packet(&self) -> Vec<u8> {
        // SAFETY: live thread-confined handle; adapter returns a fresh owned byte array.
        let bytes = Self::new(unsafe { synch_adapter_operation_packet(self.0.as_ptr()) });
        // SAFETY: byte array ownership keeps its immutable storage live through the copy.
        unsafe {
            let count = synch_adapter_bytes_len(bytes.0.as_ptr());
            if count == 0 {
                return Vec::new();
            }
            std::slice::from_raw_parts(synch_adapter_bytes_data(bytes.0.as_ptr()), count).to_vec()
        }
    }
    fn resume(&mut self, reply: &[u8]) {
        // SAFETY: adapter borrows state and copies reply; returned continuation is owned.
        let next =
            Self::new(unsafe { synch_adapter_operation_resume(self.0.as_ptr(), reply.into()) });
        *self = next;
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: exactly one reference owned, runtime alive on this synchronous stack.
        unsafe { synch_adapter_scope_drop(self.0.as_ptr()) }
    }
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ()> {
        if count > self.0.len() {
            return Err(());
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }
    pub(crate) fn byte(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn word(&mut self) -> Result<u64, ()> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| ())?,
        ))
    }
    fn count(&mut self) -> Result<usize, ()> {
        usize::try_from(self.word()?).map_err(|_| ())
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, ()> {
        let count = self.count()?;
        Ok(self.take(count)?.to_vec())
    }
    pub(crate) fn string(&mut self) -> Result<String, ()> {
        String::from_utf8(self.bytes()?).map_err(|_| ())
    }
    fn list<T>(&mut self, read: impl Fn(&mut Self) -> Result<T, ()>) -> Result<Vec<T>, ()> {
        let count = self.count()?;
        if count > self.0.len() {
            return Err(());
        }
        (0..count).map(|_| read(self)).collect()
    }
    fn cell(&mut self) -> Result<Cell, ()> {
        Ok(match self.byte()? {
            0 => Cell::Null,
            1 => Cell::Integer(self.word()? as i64),
            2 => Cell::Text(self.string()?),
            3 => Cell::Blob(self.bytes()?),
            4 => Cell::Real(self.word()?),
            5 => Cell::RawText(self.bytes()?),
            _ => return Err(()),
        })
    }
    fn fields(&mut self) -> Result<Fields, ()> {
        self.list(|r| Ok((r.string()?, r.cell()?)))
    }
    pub(crate) fn end(&self) -> Result<(), ()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn word(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    word(out, value.len() as u64);
    out.extend_from_slice(value);
}
fn cell(out: &mut Vec<u8>, value: &Cell) {
    match value {
        Cell::Null => out.push(0),
        Cell::Integer(value) => {
            out.push(1);
            word(out, *value as u64);
        }
        Cell::Text(value) => {
            out.push(2);
            bytes(out, value.as_bytes());
        }
        Cell::Blob(value) => {
            out.push(3);
            bytes(out, value);
        }
        Cell::Real(bits) => {
            out.push(4);
            word(out, *bits);
        }
        Cell::RawText(value) => {
            out.push(5);
            bytes(out, value);
        }
    }
}
fn rows(out: &mut Vec<u8>, values: Vec<Row>) {
    word(out, values.len() as u64);
    for row in values {
        word(out, row.len() as u64);
        for value in row {
            cell(out, &value);
        }
    }
}

enum Frame {
    Done(Vec<u8>),
    Failure(u64, u64),
    Begin,
    Commit(u64),
    Rollback(u64),
    ReadRows(u64, String, Vec<String>, Fields, Vec<Order>, Vec<Join>),
    Upsert(u64, String, Fields, Vec<String>, Vec<String>),
    DeleteRows(u64, String, Fields, Vec<Exclusion>, Fields),
    ReadBytes(String, Vec<u8>),
    ReadInput(u64, u64, u64),
    ReadCounter(String, Vec<u8>),
    RemoveFile(String, Vec<u8>),
    ExistsRows(u64, String, Fields),
    ValidateEd25519(Vec<u8>),
    ScanRows(u64, String, Vec<String>, Fields, Vec<Order>, Vec<Join>),
}

fn decode(packet: &[u8]) -> Result<Frame, ()> {
    let mut r = Reader(packet);
    if r.byte()? != 1 {
        return Err(());
    }
    let frame = match r.byte()? {
        0 => Frame::Done(r.bytes()?),
        1 => Frame::Failure(r.word()?, r.word()?),
        16 => Frame::Begin,
        17 => Frame::Commit(r.word()?),
        18 => Frame::Rollback(r.word()?),
        kind @ (19 | 28) => {
            let frame = Frame::ReadRows(
                r.word()?,
                r.string()?,
                r.list(Reader::string)?,
                r.fields()?,
                r.list(|r| {
                    let column = r.string()?;
                    let descending = match r.byte()? {
                        0 => false,
                        1 => true,
                        _ => return Err(()),
                    };
                    Ok(Order { column, descending })
                })?,
                r.list(|r| {
                    Ok(Join {
                        relation: r.string()?,
                        keys: r.list(|r| Ok((r.string()?, r.string()?)))?,
                    })
                })?,
            );
            match frame {
                Frame::ReadRows(tx, table, columns, equals, order, joins) if kind == 28 => {
                    Frame::ScanRows(tx, table, columns, equals, order, joins)
                }
                frame => frame,
            }
        }
        20 => Frame::Upsert(
            r.word()?,
            r.string()?,
            r.fields()?,
            r.list(Reader::string)?,
            r.list(Reader::string)?,
        ),
        21 => Frame::DeleteRows(
            r.word()?,
            r.string()?,
            r.fields()?,
            r.list(|r| {
                Ok(Exclusion {
                    relation: r.string()?,
                    equals: r.fields()?,
                    keys: r.list(|r| Ok((r.string()?, r.string()?)))?,
                })
            })?,
            r.fields()?,
        ),
        22 => Frame::ReadBytes(r.string()?, r.bytes()?),
        23 => Frame::ReadInput(r.word()?, r.word()?, r.word()?),
        24 => Frame::ReadCounter(r.string()?, r.bytes()?),
        25 => Frame::RemoveFile(r.string()?, r.bytes()?),
        26 => Frame::ExistsRows(r.word()?, r.string()?, r.fields()?),
        27 => Frame::ValidateEd25519(r.bytes()?),
        _ => return Err(()),
    };
    r.end()?;
    Ok(frame)
}

fn reply<E, A>(
    tag: u8,
    value: Result<A, E>,
    errors: &mut Vec<Option<E>>,
    encode: impl FnOnce(&mut Vec<u8>, A),
) -> Vec<u8> {
    match value {
        Ok(value) => {
            let mut out = vec![1, tag];
            encode(&mut out, value);
            out
        }
        Err(error) => {
            errors.push(Some(error));
            let mut out = vec![1, 0];
            word(&mut out, 1);
            word(&mut out, errors.len() as u64);
            out
        }
    }
}

fn execute<S: Storage>(
    mut state: Handle,
    storage: &mut S,
    inputs: &[&[u8]],
    mut resources: Option<&mut dyn Resources<Error = S::Error>>,
    mut crypto: Option<&mut dyn crate::host::Crypto<Error = S::Error>>,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    let mut errors = Vec::new();
    loop {
        let frame = decode(&state.packet()).map_err(|()| OperationError::Protocol)?;
        let response = match frame {
            Frame::ScanRows(tx, table, columns, equals, order, joins) => {
                match storage.scan_rows(tx, &table, &columns, &equals, &order, &joins) {
                    Err(error) => reply(28, Err::<(), _>(error), &mut errors, |_, ()| {}),
                    Ok(scan) => {
                        let mut out = vec![1, 28];
                        rows(&mut out, scan.rows);
                        if let Some(error) = scan.failure {
                            errors.push(Some(error));
                            out.push(1);
                            word(&mut out, 1);
                            word(&mut out, errors.len() as u64);
                        } else {
                            out.push(0);
                        }
                        out
                    }
                }
            }
            Frame::ValidateEd25519(bytes) => match crypto.as_deref_mut() {
                Some(crypto) => reply(
                    27,
                    crypto.validate_ed25519(&bytes),
                    &mut errors,
                    |out, valid| out.push(u8::from(valid)),
                ),
                None => return Err(OperationError::Protocol),
            },
            Frame::ReadCounter(space, key) => match resources.as_deref_mut() {
                Some(resources) => {
                    reply(24, resources.read_counter(&space, &key), &mut errors, word)
                }
                None => return Err(OperationError::Protocol),
            },
            Frame::RemoveFile(space, key) => match resources.as_deref_mut() {
                Some(resources) => reply(
                    25,
                    resources.remove_file(&space, &key),
                    &mut errors,
                    |_, ()| {},
                ),
                None => return Err(OperationError::Protocol),
            },
            Frame::ExistsRows(tx, table, equals) => reply(
                26,
                storage.exists_rows(tx, &table, &equals),
                &mut errors,
                |out, exists| out.push(u8::from(exists)),
            ),
            Frame::ReadInput(handle, offset, count) => {
                let selected = usize::try_from(handle)
                    .ok()
                    .and_then(|handle| inputs.get(handle))
                    .and_then(|input| {
                        let start = usize::try_from(offset).ok()?;
                        let count = usize::try_from(count).ok()?;
                        input.get(start..start.checked_add(count)?)
                    });
                match selected {
                    Some(input) => {
                        let mut out = vec![1, 23];
                        bytes(&mut out, input);
                        out
                    }
                    None => {
                        let mut out = vec![1, 0];
                        word(&mut out, 3);
                        word(&mut out, 0);
                        out
                    }
                }
            }
            Frame::Done(result) => return Ok(result),
            Frame::Failure(code, token) => {
                return Err(match (code, token) {
                    (1, token) if token > 0 => errors
                        .get_mut((token - 1) as usize)
                        .and_then(Option::take)
                        .map(OperationError::Host)
                        .unwrap_or(OperationError::Protocol),
                    (2, detail) => OperationError::MalformedMetadata(detail),
                    _ => OperationError::Protocol,
                })
            }
            Frame::Begin => reply(16, storage.begin(), &mut errors, word),
            Frame::Commit(tx) => reply(17, storage.commit(tx), &mut errors, |_, ()| {}),
            Frame::Rollback(tx) => reply(18, storage.rollback(tx), &mut errors, |_, ()| {}),
            Frame::ReadRows(tx, table, columns, equals, order, joins) => reply(
                19,
                storage.read_rows(tx, &table, &columns, &equals, &order, &joins),
                &mut errors,
                rows,
            ),
            Frame::Upsert(tx, table, values, conflict, updates) => reply(
                20,
                storage.upsert(tx, &table, &values, &conflict, &updates),
                &mut errors,
                |_, ()| {},
            ),
            Frame::DeleteRows(tx, table, equals, unless, at_most) => reply(
                21,
                storage.delete_rows(tx, &table, &equals, &unless, &at_most),
                &mut errors,
                word,
            ),
            Frame::ReadBytes(space, key) => reply(
                22,
                storage.read_bytes(&space, &key),
                &mut errors,
                |out, value| match value {
                    None => out.push(0),
                    Some(value) => {
                        out.push(1);
                        bytes(out, &value);
                    }
                },
            ),
        };
        state.resume(&response);
    }
}

/// Run a domain constructor without exposing continuations to its caller.
///
/// # Safety
/// `start` must return one fresh owned Lean Wire.NativeState. It is called only after
/// this thread's runtime is initialized; borrowed input buffers live until return.
pub(crate) unsafe fn run<S: Storage>(
    storage: &mut S,
    inputs: &[&[u8]],
    start: impl FnOnce() -> *mut c_void,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    crate::native::enter();
    execute(Handle::new(start()), storage, inputs, None, None)
}

/// Run with separate raw resource capabilities.
///
/// # Safety
/// `start` obeys the fresh owned constructor contract of `run`.
pub(crate) unsafe fn run_with_resources<S: Storage>(
    storage: &mut S,
    resources: &mut dyn Resources<Error = S::Error>,
    start: impl FnOnce() -> *mut c_void,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    crate::native::enter();
    execute(Handle::new(start()), storage, &[], Some(resources), None)
}

/// Run with separate primitive crypto capabilities.
///
/// # Safety
/// `start` returns a fresh owned native program after runtime initialization.
pub(crate) unsafe fn run_with_crypto<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn crate::host::Crypto<Error = S::Error>,
    start: impl FnOnce() -> *mut c_void,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    crate::native::enter();
    execute(Handle::new(start()), storage, &[], None, Some(crypto))
}

struct ReadOnly<'a, S>(&'a mut S);
impl<S: ByteStorage> Storage for ReadOnly<'_, S> {
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
                failure: None,
            })
    }

    type Error = OperationError<S::Error>;
    fn exists_rows(&mut self, _: u64, _: &str, _: &Fields) -> Result<bool, Self::Error> {
        Err(OperationError::Protocol)
    }
    fn begin(&mut self) -> Result<u64, Self::Error> {
        Err(OperationError::Protocol)
    }
    fn commit(&mut self, _: u64) -> Result<(), Self::Error> {
        Err(OperationError::Protocol)
    }
    fn rollback(&mut self, _: u64) -> Result<(), Self::Error> {
        Err(OperationError::Protocol)
    }
    fn read_rows(
        &mut self,
        _: u64,
        _: &str,
        _: &[String],
        _: &Fields,
        _order: &[crate::host::Order],
        _joins: &[crate::host::Join],
    ) -> Result<Vec<Row>, Self::Error> {
        Err(OperationError::Protocol)
    }
    fn upsert(
        &mut self,
        _: u64,
        _: &str,
        _: &Fields,
        _: &[String],
        _: &[String],
    ) -> Result<(), Self::Error> {
        Err(OperationError::Protocol)
    }
    fn delete_rows(
        &mut self,
        _: u64,
        _: &str,
        _: &Fields,
        _unless: &[crate::host::Exclusion],
        _at_most: &Fields,
    ) -> Result<u64, Self::Error> {
        Err(OperationError::Protocol)
    }
    fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.read_bytes(space, key).map_err(OperationError::Host)
    }
}

/// Same ownership contract as `run`, narrowed to byte-reading capabilities.
pub(crate) unsafe fn run_readonly<S: ByteStorage>(
    storage: &mut S,
    inputs: &[&[u8]],
    start: impl FnOnce() -> *mut c_void,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    // SAFETY: forwarded constructor contract; adapter cannot grant write capabilities.
    unsafe { run(&mut ReadOnly(storage), inputs, start) }.map_err(|error| match error {
        OperationError::Host(error) => error,
        OperationError::MalformedMetadata(detail) => OperationError::MalformedMetadata(detail),
        OperationError::Protocol => OperationError::Protocol,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::acquire;

    #[test]
    fn cell_packets_preserve_real_bits_and_unvalidated_text() {
        for value in [
            Cell::Real(1.5f64.to_bits()),
            Cell::Real(u64::MAX),
            Cell::RawText(vec![255, 0, 254]),
        ] {
            let mut encoded = Vec::new();
            cell(&mut encoded, &value);
            let mut reader = Reader(&encoded);
            assert_eq!(reader.cell().unwrap(), value);
            reader.end().unwrap();
        }
    }

    #[test]
    fn ordered_and_guarded_packets_are_exact_and_fail_closed() {
        let mut read = vec![1, 19];
        word(&mut read, 7);
        bytes(&mut read, b"head_history");
        word(&mut read, 1);
        bytes(&mut read, b"seq");
        word(&mut read, 0); // equality fields
        word(&mut read, 1); // order terms
        bytes(&mut read, b"seq");
        read.push(1);
        let direction_offset = read.len() - 1;
        word(&mut read, 0); // joins
        match decode(&read).unwrap() {
            Frame::ReadRows(7, relation, columns, equals, order, joins) => {
                assert!(joins.is_empty());
                assert_eq!(relation, "head_history");
                assert_eq!(columns, ["seq"]);
                assert!(equals.is_empty());
                assert_eq!(
                    order,
                    [Order {
                        column: "seq".into(),
                        descending: true
                    }]
                );
            }
            _ => panic!("wrong request kind"),
        }
        let mut joined = read[..read.len() - 8].to_vec();
        word(&mut joined, 1);
        bytes(&mut joined, b"pins");
        word(&mut joined, 1);
        bytes(&mut joined, b"root");
        bytes(&mut joined, b"root");
        match decode(&joined).unwrap() {
            Frame::ReadRows(_, _, _, _, _, joins) => assert_eq!(
                joins,
                [Join {
                    relation: "pins".into(),
                    keys: vec![("root".into(), "root".into())],
                }]
            ),
            _ => panic!("wrong request kind"),
        }
        for length in 0..joined.len() {
            assert!(decode(&joined[..length]).is_err());
        }
        read[direction_offset] = 2;
        assert!(decode(&read).is_err());
        let mut delete = vec![1, 21];
        word(&mut delete, 7);
        bytes(&mut delete, b"head_history");
        word(&mut delete, 0);
        word(&mut delete, 1);
        bytes(&mut delete, b"heads");
        word(&mut delete, 1);
        bytes(&mut delete, b"seq");
        cell(&mut delete, &Cell::Integer(-1));
        word(&mut delete, 1);
        bytes(&mut delete, b"root");
        bytes(&mut delete, b"root");
        word(&mut delete, 1);
        bytes(&mut delete, b"seq");
        cell(&mut delete, &Cell::Integer(i64::MIN));
        match decode(&delete).unwrap() {
            Frame::DeleteRows(7, _, _, blockers, at_most) => {
                assert_eq!(at_most, vec![("seq".into(), Cell::Integer(i64::MIN))]);
                assert_eq!(
                    blockers,
                    [Exclusion {
                        relation: "heads".into(),
                        equals: vec![("seq".into(), Cell::Integer(-1))],
                        keys: vec![("root".into(), "root".into())],
                    }]
                );
            }
            _ => panic!("wrong request kind"),
        }
        for length in 0..delete.len() {
            assert!(decode(&delete[..length]).is_err());
        }
        delete.push(0);
        assert!(decode(&delete).is_err());
    }
    unsafe extern "C" {
        fn synch_adapter_operation_acquire(
            root: Slice,
            holder: Slice,
            now: u64,
            possession: u8,
        ) -> *mut c_void;
    }

    #[derive(Default)]
    struct Script {
        calls: Vec<&'static str>,
        fail_at: Option<usize>,
        rollback_fails: bool,
    }
    impl Script {
        fn step(&mut self, label: &'static str) -> Result<(), &'static str> {
            let index = self.calls.len();
            self.calls.push(label);
            if self.fail_at == Some(index) {
                Err("primary")
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Script {
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
                    failure: None,
                })
        }

        type Error = &'static str;
        fn exists_rows(&mut self, _: u64, _: &str, _: &Fields) -> Result<bool, Self::Error> {
            panic!("unexpected existence query")
        }
        fn begin(&mut self) -> Result<u64, Self::Error> {
            self.step("begin")?;
            Ok(42)
        }
        fn commit(&mut self, tx: u64) -> Result<(), Self::Error> {
            assert_eq!(tx, 42);
            self.step("commit")
        }
        fn rollback(&mut self, tx: u64) -> Result<(), Self::Error> {
            assert_eq!(tx, 42);
            self.step("rollback")?;
            if self.rollback_fails {
                Err("rollback")
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
            _order: &[crate::host::Order],
            _joins: &[crate::host::Join],
        ) -> Result<Vec<Row>, Self::Error> {
            assert_eq!(tx, 42);
            assert_eq!(equals[0], ("root".into(), Cell::Blob(vec![9; 32])));
            match relation {
                "blobs" => {
                    self.step("durable")?;
                    assert_eq!(columns, &["durable"]);
                    Ok(vec![vec![Cell::Integer(-7)]])
                }
                "content_want" => {
                    self.step("want")?;
                    assert_eq!(columns, &["root"]);
                    Ok(vec![vec![Cell::Blob(vec![9; 32])]])
                }
                _ => panic!("unexpected relation"),
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
            assert_eq!(tx, 42);
            assert_eq!(relation, "pins");
            assert_eq!(conflicts, &["root", "holder"]);
            assert_eq!(updates, &["release_after"]);
            assert_eq!(values[2], ("created_at".into(), Cell::Integer(-11)));
            assert_eq!(values[3], ("release_after".into(), Cell::Null));
            self.step("upsert")
        }
        fn delete_rows(
            &mut self,
            tx: u64,
            relation: &str,
            equals: &Fields,
            _unless: &[crate::host::Exclusion],
            at_most: &Fields,
        ) -> Result<u64, Self::Error> {
            assert!(at_most.is_empty());
            assert_eq!(tx, 42);
            assert_eq!(relation, "content_want");
            assert_eq!(equals[1], ("holder".into(), Cell::Text("holder".into())));
            self.step("delete")?;
            Ok(1)
        }
        fn read_bytes(&mut self, _: &str, _: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            panic!("unexpected byte read")
        }
    }

    #[test]
    fn acquisition_native_program_owns_complete_storage_trace() {
        let mut script = Script::default();
        assert!(acquire(&mut script, &[9; 32], "holder", -11, true).unwrap());
        assert_eq!(
            script.calls,
            ["begin", "durable", "want", "delete", "upsert", "commit"]
        );
    }

    #[test]
    fn each_native_effect_failure_stops_and_preserves_primary_error() {
        let normal = ["begin", "durable", "want", "delete", "upsert", "commit"];
        for index in 0..normal.len() {
            for rollback_fails in [false, true] {
                let mut script = Script {
                    fail_at: Some(index),
                    rollback_fails,
                    ..Script::default()
                };
                assert!(matches!(
                    acquire(&mut script, &[9; 32], "holder", -11, true),
                    Err(OperationError::Host("primary"))
                ));
                let mut expected = normal[..=index].to_vec();
                if index > 0 {
                    expected.push("rollback");
                }
                assert_eq!(script.calls, expected);
            }
        }
    }

    fn state() -> Handle {
        crate::native::enter();
        // SAFETY: initialized thread, adapter copies slices and returns owned state.
        Handle::new(unsafe {
            synch_adapter_operation_acquire(
                [9; 32].as_slice().into(),
                b"holder".as_slice().into(),
                0,
                1,
            )
        })
    }

    #[test]
    fn malformed_reply_runs_lean_rollback_and_polling_does_not_advance() {
        let mut state = state();
        assert_eq!(state.packet(), [1, 16]);
        assert_eq!(state.packet(), [1, 16]);
        let mut begun = vec![1, 16];
        word(&mut begun, 42);
        state.resume(&begun);
        assert!(matches!(
            decode(&state.packet()),
            Ok(Frame::ReadRows(42, ..))
        ));
        state.resume(&[1, 17]); // Wrong success variant for the outstanding read.
        assert!(matches!(decode(&state.packet()), Ok(Frame::Rollback(42))));
        state.resume(&[1, 18]);
        assert!(matches!(decode(&state.packet()), Ok(Frame::Failure(3, 0))));
        state.resume(&begun); // A terminal operation cannot be restarted.
        assert!(matches!(decode(&state.packet()), Ok(Frame::Failure(3, 0))));
    }

    #[test]
    fn packet_decoder_rejects_truncation_trailing_data_and_hostile_lengths() {
        for packet in [
            &[][..],
            &[2, 16],
            &[1, 16, 0],
            &[1, 99],
            &[1, 0, 255, 255, 255, 255, 255, 255, 255, 255],
        ] {
            assert!(decode(packet).is_err());
        }
    }
}
