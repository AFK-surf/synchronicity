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

/// Delete one object through its complete Lean storage/resource program.
pub fn delete<S: crate::host::Storage>(
    storage: &mut S,
    resources: &mut dyn crate::host::Resources<Error = S::Error>,
    root: &[u8; 32],
    before: Option<i64>,
) -> Result<Outcome, OperationError<S::Error>> {
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
    }?;
    match result.as_slice() {
        [0] => Ok(Outcome::Skipped),
        [1] => Ok(Outcome::Writing),
        [2] => Ok(Outcome::Protected),
        [3] => Ok(Outcome::Applied),
        _ => Err(OperationError::Protocol),
    }
}

/// Execute complete pin/possession acquisition over raw storage capabilities.
/// Lean owns reads, interpretation, mutations, transaction completion and errors.
pub fn acquire<S: crate::host::Storage>(
    storage: &mut S,
    root: &[u8; 32],
    holder: &str,
    now: i64,
    possession: bool,
) -> Result<bool, OperationError<S::Error>> {
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
    }?;
    match result.as_slice() {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(OperationError::Protocol),
    }
}
