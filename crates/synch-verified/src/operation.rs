//! Private synchronous transport. Only raw storage effects are interpreted here.
use crate::host::{Cell, Fields, Row, Storage};
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
struct Slice {
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
    fn synch_adapter_operation_acquire(
        root: Slice,
        holder: Slice,
        now: u64,
        possession: u8,
    ) -> *mut c_void;
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

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ()> {
        if count > self.0.len() {
            return Err(());
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<u64, ()> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| ())?,
        ))
    }
    fn count(&mut self) -> Result<usize, ()> {
        usize::try_from(self.word()?).map_err(|_| ())
    }
    fn bytes(&mut self) -> Result<Vec<u8>, ()> {
        let count = self.count()?;
        Ok(self.take(count)?.to_vec())
    }
    fn string(&mut self) -> Result<String, ()> {
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
            _ => return Err(()),
        })
    }
    fn fields(&mut self) -> Result<Fields, ()> {
        self.list(|r| Ok((r.string()?, r.cell()?)))
    }
    fn end(&self) -> Result<(), ()> {
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
    ReadRows(u64, String, Vec<String>, Fields),
    Upsert(u64, String, Fields, Vec<String>, Vec<String>),
    DeleteRows(u64, String, Fields),
    ReadBytes(String, Vec<u8>),
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
        19 => Frame::ReadRows(r.word()?, r.string()?, r.list(Reader::string)?, r.fields()?),
        20 => Frame::Upsert(
            r.word()?,
            r.string()?,
            r.fields()?,
            r.list(Reader::string)?,
            r.list(Reader::string)?,
        ),
        21 => Frame::DeleteRows(r.word()?, r.string()?, r.fields()?),
        22 => Frame::ReadBytes(r.string()?, r.bytes()?),
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
) -> Result<Vec<u8>, OperationError<S::Error>> {
    let mut errors = Vec::new();
    loop {
        let frame = decode(&state.packet()).map_err(|()| OperationError::Protocol)?;
        let response = match frame {
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
            Frame::ReadRows(tx, table, columns, equals) => reply(
                19,
                storage.read_rows(tx, &table, &columns, &equals),
                &mut errors,
                rows,
            ),
            Frame::Upsert(tx, table, values, conflict, updates) => reply(
                20,
                storage.upsert(tx, &table, &values, &conflict, &updates),
                &mut errors,
                |_, ()| {},
            ),
            Frame::DeleteRows(tx, table, equals) => reply(
                21,
                storage.delete_rows(tx, &table, &equals),
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

pub(crate) fn acquire<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
    holder: &str,
    now: i64,
    possession: bool,
) -> Result<bool, OperationError<S::Error>> {
    crate::native::enter();
    // SAFETY: initialized runtime; adapter copies live input slices and returns ownership.
    let state = Handle::new(unsafe {
        synch_adapter_operation_acquire(
            root.as_slice().into(),
            holder.as_bytes().into(),
            now as u64,
            u8::from(possession),
        )
    });
    match execute(state, storage)?.as_slice() {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(OperationError::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        type Error = &'static str;
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
        ) -> Result<u64, Self::Error> {
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
