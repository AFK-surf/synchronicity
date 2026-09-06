//! Complete CAS operations; no host policy snapshots or mutation plans.
//!
//! Every command's arguments and outcome are Lean `Commands` types mirrored
//! by `hostgen`. This module binds the raw services a command may direct,
//! starts it, and hands its terminal back as a typed result.

pub use crate::generated::{
    CellType, Committed, DurableDomainError, IngestDomainError, IngestInput, Ingested,
    LifecycleDomainError, Outcome, PinHolder, ReadDomainError,
};
pub use crate::host::IngestResources;
pub use crate::operation::OperationError;
use crate::{
    host::{Clock, FileIO, Resources, Storage},
    operation::{run, terminal, Capabilities, Command, Decode},
};

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

#[derive(Debug)]
pub enum IngestError<E> {
    Operation(OperationError<E>),
    Domain(IngestDomainError),
}

/// Completed read failure, preserving original host errors.
#[derive(Debug)]
pub enum ReadError<E> {
    Operation(OperationError<E>),
    Domain(ReadDomainError),
}

/// Completed acquisition or deletion failure, preserving original host errors.
#[derive(Debug)]
pub enum LifecycleError<E> {
    Operation(OperationError<E>),
    Domain(LifecycleDomainError),
}

/// Completed durability-transition failure, preserving original host errors.
#[derive(Debug)]
pub enum DurableError<E> {
    Operation(OperationError<E>),
    Domain(DurableDomainError),
}

/// Decode a run's terminal, or carry its host or protocol failure through.
fn finish<T: Decode, E>(
    result: Result<Vec<u8>, OperationError<E>>,
) -> Result<T, OperationError<E>> {
    terminal(&result?).map_err(|()| OperationError::Protocol)
}

/// Record verified groups of an object through Lean's metadata commit: the
/// offered size is settled against the row's claim inside the transaction,
/// the groups are merged into what the row holds, and one row is written.
/// Every writer of an object commits this way, whatever produced the bytes.
pub fn commit_groups<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
    size: u64,
    spans: &[(u64, u64)],
    inline: Option<&[u8]>,
    now: i64,
    tier: IngestTier,
) -> Result<Committed, IngestError<S::Error>> {
    let command = Command::CommitGroups {
        root: root.to_vec(),
        spans: spans.to_vec(),
        size,
        inline: inline.map(<[u8]>::to_vec),
        now,
        cache: tier == IngestTier::Cache,
    };
    let outcome: Result<Committed, IngestDomainError> =
        finish(run(storage, Capabilities::default(), &[], &command))
            .map_err(IngestError::Operation)?;
    outcome.map_err(IngestError::Domain)
}

/// The cheap refusal: a size the row's claim cannot yield to is rejected
/// before any bytes are decoded against it. The commit decides again.
pub fn admit_size<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
    size: u64,
) -> Result<(), IngestError<S::Error>> {
    let command = Command::AdmitSize {
        root: root.to_vec(),
        size,
    };
    let outcome: Result<(), IngestDomainError> =
        finish(run(storage, Capabilities::default(), &[], &command))
            .map_err(IngestError::Operation)?;
    outcome.map_err(IngestError::Domain)
}

/// Ingest one invocation-bound input through Lean's complete command, including
/// capture, staging, leases, durability and atomic metadata publication. The
/// bytes themselves are hashed and laid out by the host's construction service.
pub fn ingest<S: Storage>(
    storage: &mut S,
    resources: IngestResources<'_, S::Error>,
    input: IngestInput,
    now: i64,
    tier: IngestTier,
    directory: DirectoryPolicy,
) -> Result<Ingested, IngestError<S::Error>> {
    let command = Command::Ingest {
        input,
        now,
        cache: tier == IngestTier::Cache,
        allow_unsupported: directory == DirectoryPolicy::AllowUnsupported,
    };
    let capabilities = Capabilities {
        files: Some(resources.files),
        construct: Some(resources.construct),
        temporary: Some(resources.temporary),
        leases: Some(resources.leases),
        source: Some(resources.source),
        ..Capabilities::default()
    };
    let outcome: Result<Ingested, IngestDomainError> =
        finish(run(storage, capabilities, &[], &command)).map_err(IngestError::Operation)?;
    outcome.map_err(IngestError::Domain)
}

/// Whole-object or bounded local read. Lean owns admission and repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadRequest {
    All,
    Range { offset: u64, length: u64 },
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
            .try_reserve_exact(bytes.len())
            .map_err(|_| OperationError::Protocol)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn grow(&mut self, count: u64) -> Result<&mut [u8], Self::Error> {
        let count = usize::try_from(count).map_err(|_| OperationError::Protocol)?;
        let start = self.bytes.len();
        let end = start.checked_add(count).ok_or(OperationError::Protocol)?;
        self.bytes
            .try_reserve_exact(count)
            .map_err(|_| OperationError::Protocol)?;
        self.bytes.resize(end, 0);
        Ok(&mut self.bytes[start..])
    }
    fn shrink(&mut self, count: u64) {
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        self.bytes.truncate(self.bytes.len().saturating_sub(count));
    }
}

/// The private output is released only on a successful terminal whose count
/// is exactly what the sink holds; anything else discards it.
fn finish_read<E>(
    result: Result<Vec<u8>, OperationError<E>>,
    output: ReadOutput<E>,
) -> Result<Vec<u8>, ReadError<E>> {
    let outcome: Result<u64, ReadDomainError> = finish(result).map_err(ReadError::Operation)?;
    let count = outcome.map_err(ReadError::Domain)?;
    if usize::try_from(count).ok() != Some(output.bytes.len()) {
        return Err(ReadError::Operation(OperationError::Protocol));
    }
    Ok(output.bytes)
}

/// Execute one complete local read with raw storage, file and clock services.
pub fn read<S: Storage>(
    storage: &mut S,
    files: &mut dyn FileIO<Error = S::Error>,
    clock: &mut dyn Clock<Error = S::Error>,
    root: &[u8; 32],
    request: ReadRequest,
) -> Result<Vec<u8>, ReadError<S::Error>> {
    let command = Command::Read {
        root: root.to_vec(),
        range: match request {
            ReadRequest::All => None,
            ReadRequest::Range { offset, length } => Some((offset, length)),
        },
    };
    let mut output = ReadOutput {
        bytes: Vec::new(),
        error: std::marker::PhantomData,
    };
    let capabilities = Capabilities {
        files: Some(files),
        clock: Some(clock),
        output: Some(&mut output),
        ..Capabilities::default()
    };
    let result = run(storage, capabilities, &[], &command);
    finish_read(result, output)
}

/// Expire due claims, optionally for one holder, through Lean's complete
/// transaction. Storage performs only the requested atomic mutation.
pub fn expire<S: Storage>(
    storage: &mut S,
    holder: Option<PinHolder>,
    now: i64,
) -> Result<u64, OperationError<S::Error>> {
    let command = Command::Expire { holder, now };
    finish(run(storage, Capabilities::default(), &[], &command))
}

/// Release one explicit claim through the complete Lean operation.
pub fn unpin<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
    holder: PinHolder,
) -> Result<bool, OperationError<S::Error>> {
    let command = Command::Unpin {
        root: root.to_vec(),
        holder,
    };
    finish(run(storage, Capabilities::default(), &[], &command))
}

/// Delete one object through its complete Lean storage/resource program.
pub fn delete<S: Storage>(
    storage: &mut S,
    resources: &mut dyn Resources<Error = S::Error>,
    root: &[u8; 32],
    before: Option<i64>,
) -> Result<Outcome, LifecycleError<S::Error>> {
    let command = Command::Delete {
        root: root.to_vec(),
        before,
    };
    let capabilities = Capabilities {
        resources: Some(resources),
        ..Capabilities::default()
    };
    let outcome: Result<Outcome, LifecycleDomainError> =
        finish(run(storage, capabilities, &[], &command)).map_err(LifecycleError::Operation)?;
    outcome.map_err(LifecycleError::Domain)
}

/// Execute complete pin/possession acquisition over raw storage capabilities.
/// Lean owns reads, interpretation, mutations, transaction completion and errors.
pub fn acquire<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
    holder: &str,
    now: i64,
    possession: bool,
) -> Result<bool, LifecycleError<S::Error>> {
    let command = Command::Acquire {
        root: root.to_vec(),
        holder: holder.to_owned(),
        now,
        possession,
    };
    let outcome: Result<bool, LifecycleDomainError> =
        finish(run(storage, Capabilities::default(), &[], &command))
            .map_err(LifecycleError::Operation)?;
    outcome.map_err(LifecycleError::Domain)
}

/// Decode a durability transition's terminal into its typed outcome.
fn finish_durable<T: Decode, E>(
    result: Result<Vec<u8>, OperationError<E>>,
) -> Result<T, DurableError<E>> {
    let outcome: Result<T, DurableDomainError> = finish(result).map_err(DurableError::Operation)?;
    outcome.map_err(DurableError::Domain)
}

/// Record that the backend holds the complete object, after its own
/// acknowledgement. Never creates a row; answers whether one was marked.
pub fn mark_durable<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
) -> Result<bool, DurableError<S::Error>> {
    let command = Command::CasMarkDurable(root.to_vec());
    finish_durable(run(storage, Capabilities::default(), &[], &command))
}

/// Reconstruct a cold durable row once the backend confirmed the final pair:
/// a row agreeing on size is marked, a missing row is created without local
/// bytes, and a row disagreeing on size is refused untouched.
pub fn adopt_durable<S: Storage>(
    storage: &mut S,
    root: &[u8; 32],
    size: u64,
    now: i64,
) -> Result<(), DurableError<S::Error>> {
    let command = Command::CasAdoptDurable {
        root: root.to_vec(),
        size,
        now,
    };
    finish_durable(run(storage, Capabilities::default(), &[], &command))
}

/// The backend answered that the object is not there: withdraw the durable
/// claim, drop a row without local bytes, and turn every machine role's pin
/// into a repair intent. Answers whether a claim was withdrawn.
pub fn heal_missing<S: Storage>(
    storage: &mut S,
    clock: &mut dyn Clock<Error = S::Error>,
    root: &[u8; 32],
) -> Result<bool, DurableError<S::Error>> {
    let command = Command::CasHealMissing(root.to_vec());
    let capabilities = Capabilities {
        clock: Some(clock),
        ..Capabilities::default()
    };
    finish_durable(run(storage, capabilities, &[], &command))
}

/// Reconcile cache claims with an ephemeral scratch generation marker.
/// Answers whether the marker changed and the cache rows were reset.
pub fn reconcile_scratch<S: Storage>(
    storage: &mut S,
    marker: &str,
) -> Result<bool, DurableError<S::Error>> {
    let command = Command::CasReconcileScratch(marker.to_owned());
    finish_durable(run(storage, Capabilities::default(), &[], &command))
}

/// Drop reconstructible local bytes while keeping a remote durable claim;
/// refused while a writer holds the object. Answers whether it cleared.
pub fn clear_cache<S: Storage>(
    storage: &mut S,
    resources: &mut dyn Resources<Error = S::Error>,
    root: &[u8; 32],
) -> Result<bool, DurableError<S::Error>> {
    let command = Command::CasClearCache(root.to_vec());
    let capabilities = Capabilities {
        resources: Some(resources),
        ..Capabilities::default()
    };
    finish_durable(run(storage, capabilities, &[], &command))
}

#[cfg(test)]
mod terminal_tests {
    use super::*;
    use crate::host::Output;

    #[test]
    fn lifecycle_terminals_are_exactly_framed() {
        type Lifecycle = Result<bool, LifecycleDomainError>;
        assert_eq!(terminal::<Lifecycle>(&[0, 0]), Ok(Ok(false)));
        assert_eq!(terminal::<Lifecycle>(&[0, 1]), Ok(Ok(true)));
        assert_eq!(
            terminal::<Lifecycle>(&[1, 0]),
            Ok(Err(LifecycleDomainError::Malformed))
        );
        for malformed in [&[][..], &[0], &[0, 2], &[0, 1, 0], &[1], &[1, 2], &[2]] {
            assert_eq!(terminal::<Lifecycle>(malformed), Err(()));
        }
    }

    #[test]
    fn column_type_carries_index_name_and_class() {
        for (octet, actual) in [
            (0, CellType::Null),
            (1, CellType::Integer),
            (2, CellType::Real),
            (3, CellType::Text),
            (4, CellType::Blob),
        ] {
            let mut packet = vec![1, 1];
            packet.extend_from_slice(&0_u64.to_le_bytes());
            packet.extend_from_slice(&7_u64.to_le_bytes());
            packet.extend_from_slice(b"durable");
            packet.push(octet);
            assert_eq!(
                terminal::<Result<bool, LifecycleDomainError>>(&packet),
                Ok(Err(LifecycleDomainError::ColumnType {
                    index: 0,
                    column: "durable".into(),
                    actual,
                }))
            );
            packet.push(0);
            assert_eq!(
                terminal::<Result<bool, LifecycleDomainError>>(&packet),
                Err(())
            );
        }
        let mut unknown = vec![1, 1];
        unknown.extend_from_slice(&0_u64.to_le_bytes());
        unknown.extend_from_slice(&0_u64.to_le_bytes());
        unknown.push(5);
        assert_eq!(
            terminal::<Result<bool, LifecycleDomainError>>(&unknown),
            Err(())
        );
    }

    #[test]
    fn ingestion_terminals_carry_root_size_and_mismatch() {
        let mut packet = vec![0];
        packet.extend_from_slice(&32_u64.to_le_bytes());
        packet.extend_from_slice(&[7; 32]);
        packet.extend_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            terminal::<Result<Ingested, IngestDomainError>>(&packet),
            Ok(Ok(Ingested {
                root: vec![7; 32],
                size: u64::MAX
            }))
        );
        let mut mismatch = vec![1, 2];
        mismatch.extend_from_slice(&32_u64.to_le_bytes());
        mismatch.extend_from_slice(&[9; 32]);
        mismatch.extend_from_slice(&5_u64.to_le_bytes());
        mismatch.extend_from_slice(&6_u64.to_le_bytes());
        assert_eq!(
            terminal::<Result<Ingested, IngestDomainError>>(&mismatch),
            Ok(Err(IngestDomainError::SizeMismatch {
                root: vec![9; 32],
                recorded: 5,
                offered: 6,
            }))
        );
        assert_eq!(
            terminal::<Result<Ingested, IngestDomainError>>(&[1, 3]),
            Ok(Err(IngestDomainError::DirectorySyncUnsupported))
        );
    }

    #[test]
    fn read_terminal_range_preserves_unsigned_endpoints() {
        let mut packet = vec![1, 1];
        for value in [u64::MAX - 1, u64::MAX, 7] {
            packet.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(
            terminal::<Result<u64, ReadDomainError>>(&packet),
            Ok(Err(ReadDomainError::Range {
                start: u64::MAX - 1,
                stop: u64::MAX,
                size: 7,
            }))
        );
        packet.push(0);
        assert_eq!(terminal::<Result<u64, ReadDomainError>>(&packet), Err(()));
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
            let payload = finish_read(Ok(packet), output).unwrap();
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
                finish_read(Ok(packet), make_output()),
                Err(ReadError::Operation(OperationError::Protocol))
            ));
        }
        assert!(matches!(
            finish_read(Ok(vec![1, 2]), make_output()),
            Err(ReadError::Domain(ReadDomainError::Unavailable))
        ));
        assert!(matches!(
            finish_read(Ok(vec![9]), make_output()),
            Err(ReadError::Operation(OperationError::Protocol))
        ));
        assert!(matches!(
            finish_read(Err(OperationError::Host(())), make_output()),
            Err(ReadError::Operation(OperationError::Host(())))
        ));
    }
}
