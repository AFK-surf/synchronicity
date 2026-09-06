//! Complete CAS operations; no host policy snapshots or mutation plans.

/// Completed deletion result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Skipped,
    Writing,
    Protected,
    Applied,
}

pub use crate::operation::OperationError;

/// Input resource bound to the invocation's `input` namespace. Lean observes
/// file length itself; immutable byte inputs carry their actual byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestInput {
    Bytes { size: u64 },
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestTier {
    Local,
    Cache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryPolicy {
    RequireSync,
    AllowUnsupported,
}

pub use crate::host::WriteServices as IngestResources;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingested {
    pub root: [u8; 32],
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestDomainError {
    Malformed,
    ColumnType {
        index: u64,
        column: String,
        actual: CellType,
    },
    SizeMismatch {
        root: [u8; 32],
        recorded: u64,
        offered: u64,
    },
    DirectorySyncUnsupported,
}

#[derive(Debug)]
pub enum IngestError<E> {
    Operation(OperationError<E>),
    Domain(IngestDomainError),
}

/// The column-type terminal every CAS operation frames the same way: the
/// projection index, the column name and the observed storage class.
fn decode_column_type(
    reader: &mut crate::operation::Reader<'_>,
) -> Result<(u64, String, CellType), ()> {
    let index = reader.word()?;
    let column = reader.string()?;
    let actual = match reader.byte()? {
        0 => CellType::Null,
        1 => CellType::Integer,
        2 => CellType::Real,
        3 => CellType::Text,
        4 => CellType::Blob,
        _ => return Err(()),
    };
    Ok((index, column, actual))
}

fn decode_ingest(bytes: &[u8]) -> Result<Result<Ingested, IngestDomainError>, ()> {
    let mut reader = crate::operation::Reader(bytes);
    let result = match reader.byte()? {
        0 => Ok(Ingested {
            root: reader.byte_slice()?.try_into().map_err(|_| ())?,
            size: reader.word()?,
        }),
        1 => Err(IngestDomainError::Malformed),
        2 => {
            let (index, column, actual) = decode_column_type(&mut reader)?;
            Err(IngestDomainError::ColumnType {
                index,
                column,
                actual,
            })
        }
        3 => Err(IngestDomainError::SizeMismatch {
            root: reader.byte_slice()?.try_into().map_err(|_| ())?,
            recorded: reader.word()?,
            offered: reader.word()?,
        }),
        4 => Err(IngestDomainError::DirectorySyncUnsupported),
        _ => return Err(()),
    };
    reader.end()?;
    Ok(result)
}

/// Ingest one invocation-bound input through Lean's complete command, including
/// capture, hashing, staging, leases, durability and atomic metadata publication.
pub fn ingest<S: crate::host::Upsert>(
    storage: &mut S,
    resources: IngestResources<'_, S::Error>,
    input: IngestInput,
    now: i64,
    tier: IngestTier,
    directory: DirectoryPolicy,
) -> Result<Ingested, IngestError<S::Error>> {
    unsafe extern "C" {
        fn synch_adapter_operation_ingest(
            kind: u8,
            size: u64,
            now: i64,
            cache: u8,
            allow_unsupported: u8,
        ) -> *mut std::ffi::c_void;
    }
    let (kind, size) = match input {
        IngestInput::Bytes { size } => (0, size),
        IngestInput::File => (1, 0),
    };
    // SAFETY: the runner initializes Lean and owns the fresh thread-confined
    // continuation; the constructor receives only copied scalar command values.
    let result = unsafe {
        crate::operation::run_ingest(storage, resources, || {
            synch_adapter_operation_ingest(
                kind,
                size,
                now,
                u8::from(tier == IngestTier::Cache),
                u8::from(directory == DirectoryPolicy::AllowUnsupported),
            )
        })
    }
    .map_err(IngestError::Operation)?;
    decode_ingest(&result)
        .map_err(|()| IngestError::Operation(OperationError::Protocol))?
        .map_err(IngestError::Domain)
}

/// Whole-object or bounded local read. Lean owns admission and repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadRequest {
    All,
    Range { offset: u64, length: u64 },
}

/// Raw storage class named by a completed Lean validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellType {
    Null,
    Integer,
    Real,
    Text,
    Blob,
}

/// Domain failure selected by the complete Lean local-read operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadDomainError {
    MissingBlob,
    Range {
        start: u64,
        stop: u64,
        size: u64,
    },
    Unavailable,
    ShortInline,
    Malformed,
    ColumnType {
        index: u64,
        column: String,
        actual: CellType,
    },
    Column {
        column: String,
        reason: String,
    },
}

/// Completed read failure, preserving original host errors.
#[derive(Debug)]
pub enum ReadError<E> {
    Operation(OperationError<E>),
    Domain(ReadDomainError),
}

fn decode_read(bytes: &[u8]) -> Result<Result<u64, ReadDomainError>, ()> {
    let mut reader = crate::operation::Reader(bytes);
    let result = match reader.byte()? {
        0 => Ok(reader.word()?),
        1 => Err(ReadDomainError::MissingBlob),
        2 => Err(ReadDomainError::Range {
            start: reader.word()?,
            stop: reader.word()?,
            size: reader.word()?,
        }),
        3 => Err(ReadDomainError::Unavailable),
        4 => Err(ReadDomainError::ShortInline),
        5 => Err(ReadDomainError::Malformed),
        6 => {
            let (index, column, actual) = decode_column_type(&mut reader)?;
            Err(ReadDomainError::ColumnType {
                index,
                column,
                actual,
            })
        }
        7 => Err(ReadDomainError::Column {
            column: reader.string()?,
            reason: reader.string()?,
        }),
        // Tag 8 is Lean's explicit protocol failure, never a domain error.
        _ => return Err(()),
    };
    reader.end()?;
    Ok(result)
}

// Private and provisional: no caller can observe partial output. This is only
// a growable byte sink, not a second implementation of read/range policy.
struct ReadOutput<E> {
    bytes: Vec<u8>,
    error: std::marker::PhantomData<fn() -> E>,
}
impl<E> crate::host::Output for ReadOutput<E> {
    type Error = OperationError<E>;
    fn append(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| OperationError::Protocol)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

fn finish_read<E>(result: &[u8], output: ReadOutput<E>) -> Result<Vec<u8>, ReadError<E>> {
    let count = decode_read(result)
        .map_err(|()| ReadError::Operation(OperationError::Protocol))?
        .map_err(ReadError::Domain)?;
    if usize::try_from(count).ok() != Some(output.bytes.len()) {
        return Err(ReadError::Operation(OperationError::Protocol));
    }
    Ok(output.bytes)
}

/// Execute one complete local read with raw storage, file and clock services.
/// The constructor copies its command inputs; no CAS metadata or mutation plan
/// is interpreted by this facade.
pub fn read<S: crate::host::Access>(
    storage: &mut S,
    files: &mut dyn crate::host::FileIO<Error = S::Error>,
    clock: &mut dyn crate::host::Clock<Error = S::Error>,
    root: &[u8; 32],
    request: ReadRequest,
) -> Result<Vec<u8>, ReadError<S::Error>> {
    use crate::operation::Slice;
    unsafe extern "C" {
        fn synch_adapter_operation_read(
            root: Slice,
            all: u8,
            offset: u64,
            length: u64,
        ) -> *mut std::ffi::c_void;
    }
    let (all, offset, length) = match request {
        ReadRequest::All => (1, 0, 0),
        ReadRequest::Range { offset, length } => (0, offset, length),
    };
    let mut output = ReadOutput {
        bytes: Vec::new(),
        error: std::marker::PhantomData,
    };
    // SAFETY: the shared runner initializes Lean before constructing one fresh
    // owned continuation. The constructor copies the borrowed root bytes.
    let result = unsafe {
        crate::operation::run_read(storage, files, clock, &mut output, || {
            synch_adapter_operation_read(root.as_slice().into(), all, offset, length)
        })
    }
    .map_err(ReadError::Operation)?;
    finish_read(&result, output)
}

/// Holder identity supplied with a domain command. Opaque spellings remain
/// opaque even when they resemble a known role; Lean owns storage rendering
/// and the live-reference guard.
#[derive(Debug, Clone, Copy)]
pub enum PinHolder<'a> {
    Operator,
    Source(&'a str),
    Replica(&'a str),
    Other(&'a str),
}

/// Expire due claims, optionally for one holder, through Lean's complete
/// transaction. Storage performs only the requested atomic mutation.
pub fn expire<S: crate::host::Storage>(
    storage: &mut S,
    holder: Option<PinHolder<'_>>,
    now: i64,
) -> Result<u64, OperationError<S::Error>> {
    use crate::operation::Slice;
    unsafe extern "C" {
        fn synch_adapter_operation_expire(
            payload: Slice,
            kind: u8,
            now: u64,
        ) -> *mut std::ffi::c_void;
    }
    let (kind, payload) = match holder {
        Some(PinHolder::Operator) => (0, ""),
        Some(PinHolder::Source(space)) => (1, space),
        Some(PinHolder::Replica(space)) => (2, space),
        Some(PinHolder::Other(text)) => (3, text),
        None => (4, ""),
    };
    // SAFETY: constructor copies borrowed arguments into a fresh owned program;
    // the shared runner initializes Lean before invoking it.
    let result = unsafe {
        crate::operation::run(storage, &[], || {
            synch_adapter_operation_expire(payload.as_bytes().into(), kind, now as u64)
        })
    }?;
    let bytes = result.try_into().map_err(|_| OperationError::Protocol)?;
    Ok(u64::from_le_bytes(bytes))
}

/// Release one explicit claim through the complete Lean operation.
pub fn unpin<S: crate::host::Storage>(
    storage: &mut S,
    root: &[u8; 32],
    holder: PinHolder<'_>,
) -> Result<bool, OperationError<S::Error>> {
    use crate::operation::Slice;
    unsafe extern "C" {
        fn synch_adapter_operation_unpin(
            root: Slice,
            payload: Slice,
            kind: u8,
        ) -> *mut std::ffi::c_void;
    }
    let (kind, payload) = match holder {
        PinHolder::Operator => (0, ""),
        PinHolder::Source(space) => (1, space),
        PinHolder::Replica(space) => (2, space),
        PinHolder::Other(text) => (3, text),
    };
    // SAFETY: the constructor copies borrowed arguments into a fresh owned
    // program; the shared runner initializes Lean before invoking it.
    let result = unsafe {
        crate::operation::run(storage, &[], || {
            synch_adapter_operation_unpin(root.as_slice().into(), payload.as_bytes().into(), kind)
        })
    }?;
    match result.as_slice() {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(OperationError::Protocol),
    }
}

/// Domain failure selected by a complete Lean acquisition or deletion.
///
/// The column-type terminal carries the same fields as ingestion's and the
/// read path's, so the host translates all three with one conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleDomainError {
    Malformed,
    ColumnType {
        index: u64,
        column: String,
        actual: CellType,
    },
}

/// Completed acquisition or deletion failure, preserving original host errors.
#[derive(Debug)]
pub enum LifecycleError<E> {
    Operation(OperationError<E>),
    Domain(LifecycleDomainError),
}

/// Frame shared by acquisition and deletion: tag 0 carries the operation's
/// own value, tags 1 and 2 the malformed-metadata and column-type errors.
fn decode_lifecycle<A>(
    bytes: &[u8],
    value: impl FnOnce(&mut crate::operation::Reader<'_>) -> Result<A, ()>,
) -> Result<Result<A, LifecycleDomainError>, ()> {
    let mut reader = crate::operation::Reader(bytes);
    let result = match reader.byte()? {
        0 => Ok(value(&mut reader)?),
        1 => Err(LifecycleDomainError::Malformed),
        2 => {
            let (index, column, actual) = decode_column_type(&mut reader)?;
            Err(LifecycleDomainError::ColumnType {
                index,
                column,
                actual,
            })
        }
        _ => return Err(()),
    };
    reader.end()?;
    Ok(result)
}

fn finish_lifecycle<A, E>(
    result: Result<Vec<u8>, OperationError<E>>,
    value: impl FnOnce(&mut crate::operation::Reader<'_>) -> Result<A, ()>,
) -> Result<A, LifecycleError<E>> {
    let bytes = result.map_err(LifecycleError::Operation)?;
    decode_lifecycle(&bytes, value)
        .map_err(|()| LifecycleError::Operation(OperationError::Protocol))?
        .map_err(LifecycleError::Domain)
}

/// Delete one object through its complete Lean storage/resource program.
pub fn delete<S: crate::host::Storage>(
    storage: &mut S,
    resources: &mut dyn crate::host::Resources<Error = S::Error>,
    root: &[u8; 32],
    before: Option<i64>,
) -> Result<Outcome, LifecycleError<S::Error>> {
    use crate::operation::Slice;
    unsafe extern "C" {
        fn synch_adapter_operation_delete(
            root: Slice,
            has_before: u8,
            before: u64,
        ) -> *mut std::ffi::c_void;
    }
    // SAFETY: constructor returns a fresh owned program; runner initializes Lean first.
    let result = unsafe {
        crate::operation::run_with_resources(storage, resources, || {
            synch_adapter_operation_delete(
                root.as_slice().into(),
                u8::from(before.is_some()),
                before.unwrap_or(0) as u64,
            )
        })
    };
    finish_lifecycle(result, |reader| match reader.byte()? {
        0 => Ok(Outcome::Skipped),
        1 => Ok(Outcome::Writing),
        2 => Ok(Outcome::Protected),
        3 => Ok(Outcome::Applied),
        _ => Err(()),
    })
}

/// Execute complete pin/possession acquisition over raw storage capabilities.
/// Lean owns reads, interpretation, mutations, transaction completion and errors.
pub fn acquire<S: crate::host::Storage>(
    storage: &mut S,
    root: &[u8; 32],
    holder: &str,
    now: i64,
    possession: bool,
) -> Result<bool, LifecycleError<S::Error>> {
    use crate::operation::Slice;
    unsafe extern "C" {
        fn synch_adapter_operation_acquire(
            root: Slice,
            holder: Slice,
            now: u64,
            possession: u8,
        ) -> *mut std::ffi::c_void;
    }
    // SAFETY: constructor copies its arguments and returns a fresh owned program;
    // the shared runner initializes the runtime before invoking it.
    let result = unsafe {
        crate::operation::run(storage, &[], || {
            synch_adapter_operation_acquire(
                root.as_slice().into(),
                holder.as_bytes().into(),
                now as u64,
                u8::from(possession),
            )
        })
    };
    finish_lifecycle(result, |reader| match reader.byte()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(()),
    })
}

#[cfg(test)]
mod lifecycle_terminal_tests {
    use super::*;

    fn acquired(reader: &mut crate::operation::Reader<'_>) -> Result<bool, ()> {
        match reader.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(()),
        }
    }

    #[test]
    fn lifecycle_values_are_exactly_framed() {
        assert_eq!(decode_lifecycle(&[0, 0], acquired), Ok(Ok(false)));
        assert_eq!(decode_lifecycle(&[0, 1], acquired), Ok(Ok(true)));
        assert_eq!(
            decode_lifecycle(&[1], acquired),
            Ok(Err(LifecycleDomainError::Malformed))
        );
        for malformed in [&[][..], &[0], &[0, 2], &[0, 1, 0], &[1, 0], &[2], &[3]] {
            assert_eq!(decode_lifecycle(malformed, acquired), Err(()));
        }
    }

    #[test]
    fn lifecycle_column_type_carries_index_name_and_class() {
        for (octet, actual) in [
            (0, CellType::Null),
            (1, CellType::Integer),
            (2, CellType::Real),
            (3, CellType::Text),
            (4, CellType::Blob),
        ] {
            let mut packet = vec![2];
            packet.extend_from_slice(&0_u64.to_le_bytes());
            packet.extend_from_slice(&7_u64.to_le_bytes());
            packet.extend_from_slice(b"durable");
            packet.push(octet);
            assert_eq!(
                decode_lifecycle(&packet, acquired),
                Ok(Err(LifecycleDomainError::ColumnType {
                    index: 0,
                    column: "durable".into(),
                    actual,
                }))
            );
            packet.push(0);
            assert_eq!(decode_lifecycle(&packet, acquired), Err(()));
        }
        let mut unknown = vec![2];
        unknown.extend_from_slice(&0_u64.to_le_bytes());
        unknown.extend_from_slice(&0_u64.to_le_bytes());
        unknown.push(5);
        assert_eq!(decode_lifecycle(&unknown, acquired), Err(()));
    }
}

#[cfg(test)]
mod ingest_terminal_tests {
    use super::*;

    fn root_packet(tag: u8, root: &[u8]) -> Vec<u8> {
        let mut packet = vec![tag];
        packet.extend_from_slice(&(root.len() as u64).to_le_bytes());
        packet.extend_from_slice(root);
        packet
    }

    #[test]
    fn ingestion_success_requires_exact_root_and_unsigned_size() {
        let mut packet = root_packet(0, &[7; 32]);
        packet.extend_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            decode_ingest(&packet),
            Ok(Ok(Ingested {
                root: [7; 32],
                size: u64::MAX
            }))
        );
        for end in 0..packet.len() {
            assert!(decode_ingest(&packet[..end]).is_err());
        }
        packet.push(0);
        assert!(decode_ingest(&packet).is_err());
        for width in [0, 31, 33] {
            let mut packet = root_packet(0, &vec![0; width]);
            packet.extend_from_slice(&1_u64.to_le_bytes());
            assert!(decode_ingest(&packet).is_err());
        }
    }

    #[test]
    fn ingestion_size_mismatch_and_directory_failure_are_domain_results() {
        let mut packet = root_packet(3, &[9; 32]);
        packet.extend_from_slice(&u64::MAX.to_le_bytes());
        packet.extend_from_slice(&0_u64.to_le_bytes());
        assert_eq!(
            decode_ingest(&packet),
            Ok(Err(IngestDomainError::SizeMismatch {
                root: [9; 32],
                recorded: u64::MAX,
                offered: 0,
            }))
        );
        assert_eq!(
            decode_ingest(&[4]),
            Ok(Err(IngestDomainError::DirectorySyncUnsupported))
        );
        for malformed in [&[4, 0][..], &[5], &[2], &[1, 0]] {
            assert!(decode_ingest(malformed).is_err());
        }
    }
}

#[cfg(test)]
mod read_terminal_tests {
    use super::{decode_read, finish_read, OperationError, ReadDomainError, ReadError, ReadOutput};
    use crate::host::Output;

    #[test]
    fn read_terminal_errors_are_strictly_framed() {
        assert_eq!(decode_read(&[1]), Ok(Err(ReadDomainError::MissingBlob)));
        assert_eq!(decode_read(&[3]), Ok(Err(ReadDomainError::Unavailable)));
        assert_eq!(decode_read(&[4]), Ok(Err(ReadDomainError::ShortInline)));
        assert_eq!(decode_read(&[5]), Ok(Err(ReadDomainError::Malformed)));
        for invalid in [&[][..], &[1, 0], &[8], &[9], &[0], &[2], &[6], &[7]] {
            assert_eq!(decode_read(invalid), Err(()));
        }
    }

    #[test]
    fn read_terminal_range_preserves_unsigned_endpoints() {
        let mut packet = vec![2];
        for value in [u64::MAX - 1, u64::MAX, 7] {
            packet.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(
            decode_read(&packet),
            Ok(Err(ReadDomainError::Range {
                start: u64::MAX - 1,
                stop: u64::MAX,
                size: 7,
            }))
        );
        packet.push(0);
        assert_eq!(decode_read(&packet), Err(()));
    }

    #[test]
    fn read_terminal_count_is_exactly_framed() {
        let mut packet = vec![0];
        packet.extend_from_slice(&2_u64.to_le_bytes());
        assert_eq!(decode_read(&packet), Ok(Ok(2)));
        packet.push(0);
        assert_eq!(decode_read(&packet), Err(()));
        packet.pop();
        packet.pop();
        assert_eq!(decode_read(&packet), Err(()));
    }

    #[test]
    fn read_terminal_count_releases_the_private_output_without_copying() {
        for size in [0_usize, 2, 65543] {
            let mut packet = vec![0];
            packet.extend_from_slice(&(size as u64).to_le_bytes());
            let mut output = ReadOutput::<()> {
                bytes: vec![],
                error: std::marker::PhantomData,
            };
            output
                .append(&(0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>())
                .unwrap();
            let pointer = output.bytes.as_ptr();
            let capacity = output.bytes.capacity();
            let payload = finish_read(&packet, output).unwrap();
            assert_eq!(payload.as_ptr(), pointer);
            assert_eq!(payload.capacity(), capacity);
            assert_eq!(payload.len(), size);
            assert!(payload
                .iter()
                .enumerate()
                .all(|(n, byte)| *byte == (n % 251) as u8));
        }
    }

    #[test]
    fn failed_or_inconsistent_terminal_never_releases_private_prefix() {
        let make_output = || ReadOutput::<()> {
            bytes: vec![1, 2, 3],
            error: std::marker::PhantomData,
        };
        for count in [0_u64, 2, 4, u64::MAX] {
            let mut packet = vec![0];
            packet.extend_from_slice(&count.to_le_bytes());
            assert!(matches!(
                finish_read(&packet, make_output()),
                Err(ReadError::Operation(OperationError::Protocol))
            ));
        }
        assert!(matches!(
            finish_read(&[3], make_output()),
            Err(ReadError::Domain(ReadDomainError::Unavailable))
        ));
        assert!(matches!(
            finish_read(&[8], make_output()),
            Err(ReadError::Operation(OperationError::Protocol))
        ));
    }
}
