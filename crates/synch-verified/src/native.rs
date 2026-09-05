use std::{
    ffi::c_void,
    ptr::NonNull,
    sync::{Arc, Once},
};

#[repr(C)]
#[derive(Clone, Copy)]
struct Slice {
    ptr: *const u8,
    len: usize,
}
impl From<&[u8]> for Slice {
    fn from(bytes: &[u8]) -> Self {
        Self {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }
}

unsafe extern "C" {
    fn synch_lean_pin_acquisition_start(row: u8, durable: u8, wanted: u8, possession: u8) -> u8;
    fn synch_lean_pin_acquisition_ack(step: u8) -> u8;
    fn synch_lean_deletion_start(
        collect: u8,
        row: u8,
        writing: u8,
        pinned: u8,
        referenced: u8,
        last_access: u64,
        before: u64,
    ) -> u8;
    fn synch_lean_deletion_ack(step: u8) -> u8;
    fn synch_adapter_cas_plan(
        row: u8,
        durable: u8,
        complete: u8,
        recorded: u64,
        claimed: u64,
        old: *const u64,
        old_count: usize,
        incoming: *const u64,
        incoming_count: usize,
    ) -> *mut c_void;
    fn synch_adapter_cas_plan_status(plan: *mut c_void) -> u8;
    fn synch_adapter_cas_plan_spans(plan: *mut c_void) -> *mut c_void;
    fn synch_adapter_words_len(words: *mut c_void) -> usize;
    fn synch_adapter_words_get(words: *mut c_void, index: usize) -> u64;
    fn synch_adapter_walk_absent(walk: *mut c_void, redacted: u8) -> *mut c_void;
    fn synch_adapter_walk_present(
        walk: *mut c_void,
        reference: *mut c_void,
        node: *mut c_void,
        child_shape: u8,
        payload: Slice,
        present: u8,
    ) -> *mut c_void;
    fn synch_adapter_walk_node(
        tag: u8,
        children: *const Slice,
        count: usize,
        prefix: Slice,
        child: Slice,
    ) -> *mut c_void;
    fn synch_adapter_walk_new(
        scope: *mut c_void,
        reference: Slice,
        root: Slice,
        max_depth: u64,
    ) -> *mut c_void;
    fn synch_adapter_walk_query(walk: *mut c_void, operation: u8, hash: Slice) -> u64;
    fn synch_adapter_walk_update(
        walk: *mut c_void,
        operation: u8,
        reference: Slice,
        hash: Slice,
        step: Slice,
    ) -> *mut c_void;
    fn synch_adapter_walk_field(walk: *mut c_void, field: u8) -> *mut c_void;
    fn synch_adapter_bytes_len(value: *mut c_void) -> usize;
    fn synch_adapter_bytes_data(value: *mut c_void) -> *const u8;
    fn synch_adapter_cache_new(capacity: u64) -> *mut c_void;
    fn synch_adapter_cache_epoch(cache: *mut c_void) -> u64;
    fn synch_adapter_cache_can_certify(cache: *mut c_void, epoch: u64) -> u8;
    fn synch_adapter_cache_known(cache: *mut c_void, key: Slice) -> u8;
    fn synch_adapter_cache_update(
        cache: *mut c_void,
        operation: u8,
        epoch: u64,
        key: Slice,
        keep: *const Slice,
        count: usize,
    ) -> *mut c_void;
    fn synch_adapter_initialize() -> u8;
    fn synch_adapter_thread_initialize();
    fn synch_adapter_thread_finalize();
    fn synch_adapter_scope_new(
        full: u8,
        prefixes: *const Slice,
        np: usize,
        exact: *const Slice,
        ne: usize,
    ) -> *mut c_void;
    fn synch_adapter_scope_drop(scope: *mut c_void);
    fn synch_adapter_scope_query(
        scope: *mut c_void,
        operation: u8,
        path: Slice,
        tag: u8,
        inline_value: u8,
        suffix: Slice,
    ) -> u8;
    fn synch_lean_group_count(size: u64) -> u64;
    fn synch_lean_settle_size(
        row: u8,
        durable: u8,
        complete: u8,
        final_held: u8,
        recorded: u64,
        claimed: u64,
    ) -> u8;
}

static INITIALIZE: Once = Once::new();
struct Thread;
impl Drop for Thread {
    fn drop(&mut self) {
        // SAFETY: paired with initialization on this same thread, after calls return.
        unsafe { synch_adapter_thread_finalize() }
    }
}
thread_local! { static THREAD: Thread = {
    // SAFETY: runtime initialization is serialized before touching this TLS slot.
    unsafe { synch_adapter_thread_initialize() };
    Thread
}; }

fn enter() {
    INITIALIZE.call_once(|| {
        // SAFETY: exactly once per process, before any exported decision call.
        assert_eq!(
            unsafe { synch_adapter_initialize() },
            1,
            "Lean initialization failed"
        );
    });
    THREAD.with(|_| {});
}

#[derive(Debug)]
struct Handle(NonNull<c_void>);
// SAFETY: the C adapter marks the entire immutable Lean object graph MT before
// returning it. Calls only borrow the Rust handle and consume a new Lean ref.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        // A scope can be stored in a Rust TLS slot created before THREAD, and
        // consequently dropped after THREAD has finalized. Reinitialize only
        // for that destructor instead of panicking on access to destroyed TLS.
        let release = || {
            // SAFETY: Arc drops the sole owned handle exactly once; it came from Lean.
            unsafe { synch_adapter_scope_drop(self.0.as_ptr()) }
        };
        if THREAD.try_with(|_| release()).is_err() {
            // SAFETY: no Lean call is in progress after our TLS destructor ran.
            unsafe { synch_adapter_thread_initialize() };
            release();
            unsafe { synch_adapter_thread_finalize() };
        }
    }
}

/// An immutable, thread-shareable scope owned by Lean, not a Rust reimplementation.
#[derive(Debug, Clone)]
pub struct Scope(Arc<Handle>);

/// A storage read selected by the Lean frontier scheduler.
#[derive(Debug)]
pub struct WalkPosition {
    pub reference: Option<[u8; 32]>,
    pub hash: [u8; 32],
    pub path: Vec<u8>,
}

/// Resumable frontier, deduplication, retries and shape obligations owned by Lean.
#[derive(Debug)]
pub struct MissingWalk(Arc<Handle>);

/// Canonicality diagnostic emitted by Lean; the walk remains failed afterward.
#[derive(Debug, PartialEq, Eq)]
pub enum WalkError {
    UnexpectedObservation,
    NodeDepth(u64),
    ValueDepth(u64),
    NotBranch([u8; 32]),
}

/// Storage observation for an extension child, without a canonicality decision.
#[derive(Debug, Clone, Copy)]
pub enum ChildShape {
    Absent,
    Branch,
    Other,
}

/// Decoded node structure. Hashes and paths are copied without interpreting edges.
#[derive(Debug)]
pub enum WalkNode<'a> {
    Branch(&'a [Option<[u8; 32]>; 16]),
    Extension {
        prefix: &'a [u8],
        child: &'a [u8; 32],
    },
    Leaf(&'a [u8]),
}

impl WalkNode<'_> {
    fn native(&self) -> Handle {
        enter();
        let (tag, children, prefix, child) = match self {
            Self::Branch(children) => (
                0,
                children
                    .iter()
                    .map(|h| h.as_ref().map_or(&[][..], |h| h.as_slice()).into())
                    .collect::<Vec<Slice>>(),
                &[][..],
                &[][..],
            ),
            Self::Extension { prefix, child } => (1, Vec::new(), *prefix, child.as_slice()),
            Self::Leaf(suffix) => (2, Vec::new(), *suffix, &[][..]),
        };
        // SAFETY: all fields remain live during this copying call; the result
        // is an owned MT Lean object and is released by Handle.
        let ptr = unsafe {
            synch_adapter_walk_node(
                tag,
                children.as_ptr(),
                children.len(),
                prefix.into(),
                child.into(),
            )
        };
        Handle(NonNull::new(ptr).expect("Lean node allocation failed"))
    }
}

impl MissingWalk {
    /// Report absence/refusal. Lean decides whether to request and defer the node.
    pub fn observe_absent(&mut self, redacted: bool) -> Result<bool, WalkError> {
        enter();
        // SAFETY: the adapter consumes a fresh reference to the live MT state.
        let ptr = unsafe { synch_adapter_walk_absent(self.0 .0.as_ptr(), redacted.into()) };
        self.0 = Arc::new(Handle(
            NonNull::new(ptr).expect("Lean walk allocation failed"),
        ));
        self.check_error()?;
        Ok(self.query(6, &[]) == 1)
    }

    /// Apply decoded storage facts. The optional result is a payload to request.
    pub fn observe_present(
        &mut self,
        reference: WalkNode<'_>,
        node: WalkNode<'_>,
        child: ChildShape,
        payload: Option<&[u8; 32]>,
        present: bool,
    ) -> Result<Option<[u8; 32]>, WalkError> {
        let reference = reference.native();
        let node = node.native();
        let child = match child {
            ChildShape::Absent => 0,
            ChildShape::Branch => 1,
            ChildShape::Other => 2,
        };
        // SAFETY: borrowed handles and payload bytes remain live during this
        // copying call; the replacement owns an independent MT reference.
        let ptr = unsafe {
            synch_adapter_walk_present(
                self.0 .0.as_ptr(),
                reference.0.as_ptr(),
                node.0.as_ptr(),
                child,
                payload.map_or(&[][..], |h| h.as_slice()).into(),
                present.into(),
            )
        };
        self.0 = Arc::new(Handle(
            NonNull::new(ptr).expect("Lean walk allocation failed"),
        ));
        self.check_error()?;
        match self.query(6, &[]) {
            0 => Ok(None),
            2 => Ok(Some(
                self.field(4).try_into().expect("Lean payload hash width"),
            )),
            _ => panic!("invalid Lean present observation result"),
        }
    }

    fn check_error(&self) -> Result<(), WalkError> {
        if self.query(1, &[]) != 2 {
            return Ok(());
        }
        Err(match self.query(5, &[]) {
            0 => WalkError::NodeDepth(self.query(2, &[])),
            1 => WalkError::ValueDepth(self.query(2, &[])),
            2 => WalkError::NotBranch(self.field(3).try_into().expect("Lean fault hash width")),
            3 => WalkError::UnexpectedObservation,
            _ => panic!("invalid Lean walk error tag"),
        })
    }
    /// Empty hashes are represented by `None`, never by a malformed short hash.
    pub fn new(
        scope: &Scope,
        reference: Option<&[u8; 32]>,
        root: Option<&[u8; 32]>,
        max_depth: u64,
    ) -> Self {
        enter();
        // SAFETY: the scope stays alive and all input byte arrays are copied.
        let ptr = unsafe {
            synch_adapter_walk_new(
                scope.0 .0.as_ptr(),
                reference.map_or(&[][..], |h| h.as_slice()).into(),
                root.map_or(&[][..], |h| h.as_slice()).into(),
                max_depth,
            )
        };
        Self(Arc::new(Handle(
            NonNull::new(ptr).expect("Lean walk allocation failed"),
        )))
    }

    fn query(&self, operation: u8, hash: &[u8]) -> u64 {
        enter();
        // SAFETY: the adapter consumes a fresh reference and copies input bytes.
        unsafe { synch_adapter_walk_query(self.0 .0.as_ptr(), operation, hash.into()) }
    }

    fn update(&mut self, operation: u8, reference: &[u8], hash: &[u8], step: &[u8]) {
        enter();
        // SAFETY: the immutable old state and buffers remain live throughout;
        // the adapter returns an independently owned MT replacement state.
        let ptr = unsafe {
            synch_adapter_walk_update(
                self.0 .0.as_ptr(),
                operation,
                reference.into(),
                hash.into(),
                step.into(),
            )
        };
        self.0 = Arc::new(Handle(
            NonNull::new(ptr).expect("Lean walk allocation failed"),
        ));
    }

    fn field(&self, field: u8) -> Vec<u8> {
        enter();
        // SAFETY: the exported getter constructs a ByteArray. The owned handle
        // keeps its backing allocation live until the bytes have been copied.
        unsafe {
            let ptr = synch_adapter_walk_field(self.0 .0.as_ptr(), field);
            let value = Handle(NonNull::new(ptr).expect("Lean field allocation failed"));
            let len = synch_adapter_bytes_len(value.0.as_ptr());
            if len == 0 {
                return Vec::new();
            }
            std::slice::from_raw_parts(synch_adapter_bytes_data(value.0.as_ptr()), len).to_vec()
        }
    }

    /// Select the next read; canonicality errors remain sticky across retries.
    pub fn poll(&mut self) -> Result<Option<WalkPosition>, WalkError> {
        self.update(0, &[], &[], &[]);
        self.check_error()?;
        match self.query(1, &[]) {
            0 => Ok(None),
            1 => {
                let reference = self.field(0);
                Ok(Some(WalkPosition {
                    reference: if reference.is_empty() {
                        None
                    } else {
                        Some(reference.try_into().expect("Lean reference hash width"))
                    },
                    hash: self.field(1).try_into().expect("Lean node hash width"),
                    path: self.field(2),
                }))
            }
            _ => panic!("invalid Lean walk status"),
        }
    }

    /// Whether all frontier and deferred work has drained without a fault.
    pub fn is_exhausted(&self) -> bool {
        self.query(0, &[]) != 0
    }
    /// Retry deferred positions without restarting completed work.
    pub fn resume(&mut self) {
        self.update(2, &[], &[], &[]);
    }
    /// Reset payload request deduplication at a batch boundary.
    pub fn start_batch(&mut self) {
        self.update(3, &[], &[], &[]);
    }
}

/// Completeness certificate state owned and updated exclusively by Lean.
/// Callers synchronize storage effects and these transitions with their mutex.
#[derive(Debug)]
pub struct CertificateCache(Arc<Handle>);

impl CertificateCache {
    /// Start with no certificates, no mutations, and epoch zero.
    pub fn new(capacity: u64) -> Self {
        enter();
        // SAFETY: exact scalar ABI; the adapter returns one owned MT reference.
        let ptr = unsafe { synch_adapter_cache_new(capacity) };
        Self(Arc::new(Handle(
            NonNull::new(ptr).expect("Lean cache allocation failed"),
        )))
    }

    /// Snapshot epoch, computed by the same state used by certification.
    pub fn epoch(&self) -> u64 {
        enter();
        // SAFETY: this handle remains live; the adapter consumes a fresh ref.
        unsafe { synch_adapter_cache_epoch(self.0 .0.as_ptr()) }
    }

    /// Whether a certificate is usable in the current state.
    pub fn contains(&self, key: &[u8]) -> bool {
        enter();
        // SAFETY: the call copies the key and borrows the live MT cache.
        unsafe { synch_adapter_cache_known(self.0 .0.as_ptr(), key.into()) != 0 }
    }

    fn update(&mut self, operation: u8, epoch: u64, key: &[u8], keep: &[&[u8]]) {
        enter();
        let keep: Vec<Slice> = keep.iter().map(|key| (*key).into()).collect();
        // SAFETY: all inputs remain live during this copying call; the result
        // owns an independent MT reference. Dropping the old state is safe.
        let ptr = unsafe {
            synch_adapter_cache_update(
                self.0 .0.as_ptr(),
                operation,
                epoch,
                key.into(),
                keep.as_ptr(),
                keep.len(),
            )
        };
        self.0 = Arc::new(Handle(
            NonNull::new(ptr).expect("Lean cache allocation failed"),
        ));
    }

    /// Invalidate before a storage mutation, retaining only eligible keys.
    pub fn begin(&mut self, keep: &[&[u8]]) {
        self.update(0, 0, &[], keep);
    }

    /// Invalidate again after storage commit or rollback.
    pub fn finish(&mut self) {
        self.update(1, 0, &[], &[]);
    }

    /// Certify a completed walk's snapshot. The decision and update both use
    /// Lean's guard; the exclusive Rust borrow prevents a mutation between them.
    pub fn certify(&mut self, epoch: u64, key: &[u8]) -> bool {
        let accepted = self.can_certify(epoch);
        self.update(2, epoch, key, &[]);
        accepted
    }

    /// Test a snapshot ticket without storing a certificate (for non-caching stores).
    pub fn can_certify(&self, epoch: u64) -> bool {
        enter();
        // SAFETY: the adapter borrows the live MT state with a fresh reference.
        unsafe { synch_adapter_cache_can_certify(self.0 .0.as_ptr(), epoch) != 0 }
    }
}

/// The node fields relevant to authorization. Hash bytes never authorize a key.
#[derive(Debug, Clone, Copy)]
pub enum Shape<'a> {
    Branch { inline_value: bool },
    Extension(&'a [u8]),
    Leaf(&'a [u8]),
}
impl Shape<'_> {
    fn parts(self) -> (u8, u8, Slice) {
        match self {
            Self::Branch { inline_value } => (0, inline_value.into(), (&[][..]).into()),
            Self::Extension(suffix) => (1, 0, suffix.into()),
            Self::Leaf(suffix) => (2, 0, suffix.into()),
        }
    }
}

impl Scope {
    /// Copies validated nibble paths into Lean; `None` grants the full keyspace.
    pub fn new(prefixes: Option<&[Vec<u8>]>, exact: &[Vec<u8>]) -> Self {
        enter();
        let p: Vec<Slice> = prefixes
            .unwrap_or_default()
            .iter()
            .map(|p| p.as_slice().into())
            .collect();
        let e: Vec<Slice> = exact.iter().map(|p| p.as_slice().into()).collect();
        // SAFETY: all slice buffers remain live for this synchronous copying call.
        let ptr = unsafe {
            synch_adapter_scope_new(
                prefixes.is_none().into(),
                p.as_ptr(),
                p.len(),
                e.as_ptr(),
                e.len(),
            )
        };
        Self(Arc::new(Handle(
            NonNull::new(ptr).expect("Lean scope allocation failed"),
        )))
    }

    fn query(&self, op: u8, path: &[u8], shape: Shape<'_>) -> bool {
        enter();
        let (tag, inline_value, suffix) = shape.parts();
        // SAFETY: Arc keeps the MT scope alive; buffers are copied and consumed
        // during this synchronous call. No pointers into Rust escape it.
        unsafe {
            synch_adapter_scope_query(
                self.0 .0.as_ptr(),
                op,
                path.into(),
                tag,
                inline_value,
                suffix,
            ) != 0
        }
    }

    /// Whether the position lies on a permitted path.
    pub fn admits_path(&self, path: &[u8]) -> bool {
        self.query(
            0,
            path,
            Shape::Branch {
                inline_value: false,
            },
        )
    }
    /// Whether the complete subtree is granted.
    pub fn contains_subtree(&self, path: &[u8]) -> bool {
        self.query(
            1,
            path,
            Shape::Branch {
                inline_value: false,
            },
        )
    }
    /// Whether the complete key is granted.
    pub fn admits_key(&self, path: &[u8]) -> bool {
        self.query(
            2,
            path,
            Shape::Branch {
                inline_value: false,
            },
        )
    }
    /// Whether this node's revealed structure and inline data are permitted.
    pub fn admits_node(&self, path: &[u8], shape: Shape<'_>) -> bool {
        self.query(3, path, shape)
    }
    /// Whether this node's own payload is permitted.
    pub fn admits_value(&self, path: &[u8], shape: Shape<'_>) -> bool {
        self.query(4, path, shape)
    }
}

/// A successful settlement always records the offered size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    Keep,
    Reset,
    Refuse,
}

/// SQL effects and terminal outcomes of a Lean pin-acquisition plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAcquisitionStep {
    Refused,
    DeleteWant,
    UpsertPin,
    Finished,
}

/// The native acquisition protocol. Execute it within one write transaction.
#[derive(Debug)]
pub struct PinAcquisition {
    step: u8,
}

impl PinAcquisition {
    /// Start from current row, durable-claim and holder-specific want facts.
    pub fn new(row: bool, durable: bool, wanted: bool, possession: bool) -> Self {
        enter();
        // SAFETY: exact scalar ABI with normalized Bool arguments.
        let step = unsafe {
            synch_lean_pin_acquisition_start(
                row.into(),
                durable.into(),
                wanted.into(),
                possession.into(),
            )
        };
        Self { step }
    }

    /// Observe the requested effect; polling does not advance the plan.
    pub fn step(&self) -> PinAcquisitionStep {
        match self.step {
            0 => PinAcquisitionStep::Refused,
            1 => PinAcquisitionStep::DeleteWant,
            2 => PinAcquisitionStep::UpsertPin,
            3 => PinAcquisitionStep::Finished,
            _ => panic!("invalid Lean pin acquisition step"),
        }
    }

    /// Acknowledge a successful effect, never a SQL error.
    pub fn acknowledge(&mut self) {
        enter();
        // SAFETY: exact scalar ABI; transitions are implemented only in Lean.
        self.step = unsafe { synch_lean_pin_acquisition_ack(self.step) };
    }
}

/// An effect or terminal outcome selected by the Lean deletion protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionStep {
    Skip,
    Writing,
    Protected,
    DeleteRow,
    Commit,
    UnlinkPayload,
    UnlinkOutboard,
    Finished,
}

/// Lean-owned deletion policy and effect ordering, represented by a scalar tag.
#[derive(Debug)]
pub struct Deletion {
    step: u8,
}

impl Deletion {
    /// Snapshot facts must remain protected against writers and new references
    /// until the protocol finishes. `None` selects explicit, age-independent deletion.
    pub fn new(
        row: bool,
        writing: bool,
        pinned: bool,
        referenced: bool,
        last_access: i64,
        before: Option<i64>,
    ) -> Self {
        enter();
        // SAFETY: generated C represents Int64 as uint64_t; casting preserves
        // the signed timestamp bit pattern, interpreted as signed inside Lean.
        let step = unsafe {
            synch_lean_deletion_start(
                before.is_some().into(),
                row.into(),
                writing.into(),
                pinned.into(),
                referenced.into(),
                last_access as u64,
                before.unwrap_or(0) as u64,
            )
        };
        Self { step }
    }

    /// Read the next effect without advancing the protocol.
    pub fn step(&self) -> DeletionStep {
        match self.step {
            0 => DeletionStep::Skip,
            1 => DeletionStep::Writing,
            2 => DeletionStep::Protected,
            3 => DeletionStep::DeleteRow,
            4 => DeletionStep::Commit,
            5 => DeletionStep::UnlinkPayload,
            6 => DeletionStep::UnlinkOutboard,
            7 => DeletionStep::Finished,
            _ => panic!("invalid Lean deletion step"),
        }
    }

    /// Acknowledge successful SQL execution or a best-effort unlink attempt.
    /// Never acknowledge a failed row deletion or failed transaction commit.
    pub fn acknowledge(&mut self) {
        enter();
        // SAFETY: scalar ABI; all transition decisions remain in Lean.
        self.step = unsafe { synch_lean_deletion_ack(self.step) };
    }
}

/// Accepted CAS commit plan. Ranges are normalized and clamped by Lean.
#[derive(Debug, PartialEq, Eq)]
pub struct CasCommit {
    pub complete: bool,
    pub ranges: Vec<(u64, u64)>,
}

/// Plan a CAS row update from transaction-local facts and verified incoming runs.
/// `None` means the offered size conflicts with durable or attested data.
pub fn plan_cas_commit(
    row: bool,
    durable: bool,
    complete: bool,
    recorded: u64,
    claimed: u64,
    old: &[(u64, u64)],
    incoming: &[(u64, u64)],
) -> Option<CasCommit> {
    enter();
    let old: Vec<u64> = old.iter().flat_map(|&(a, b)| [a, b]).collect();
    let incoming: Vec<u64> = incoming.iter().flat_map(|&(a, b)| [a, b]).collect();
    // SAFETY: scalar ABI and copied endpoints; both returned objects own MT refs.
    unsafe {
        let plan = Handle(
            NonNull::new(synch_adapter_cas_plan(
                row.into(),
                durable.into(),
                complete.into(),
                recorded,
                claimed,
                old.as_ptr(),
                old.len(),
                incoming.as_ptr(),
                incoming.len(),
            ))
            .expect("Lean CAS plan allocation failed"),
        );
        let complete = match synch_adapter_cas_plan_status(plan.0.as_ptr()) {
            0 => return None,
            1 => false,
            2 => true,
            _ => panic!("invalid Lean CAS plan status"),
        };
        // LEAN-MODEL: cas-native-plan-encoding (VerifiedCoreProofs.cas_plan_encoding_roundtrip)
        // The exported UInt64 pairs decode to the exact planned intervals.
        let spans = Handle(
            NonNull::new(synch_adapter_cas_plan_spans(plan.0.as_ptr()))
                .expect("Lean CAS spans allocation failed"),
        );
        let len = synch_adapter_words_len(spans.0.as_ptr());
        assert_eq!(len % 2, 0, "Lean CAS endpoint pairs");
        let ranges = (0..len)
            .step_by(2)
            .map(|i| {
                (
                    synch_adapter_words_get(spans.0.as_ptr(), i),
                    synch_adapter_words_get(spans.0.as_ptr(), i + 1),
                )
            })
            .collect();
        Some(CasCommit { complete, ranges })
    }
}

/// Overflow-free group count computed by the linked Lean implementation.
pub fn group_count(size: u64) -> u64 {
    enter();
    // SAFETY: exact scalar ABI, no pointers or unchecked preconditions.
    unsafe { synch_lean_group_count(size) }
}

/// Settle a claim using row facts read inside the caller's transaction.
pub fn settle_size(
    row: bool,
    durable: bool,
    complete: bool,
    final_held: bool,
    recorded: u64,
    claimed: u64,
) -> Settlement {
    enter();
    // SAFETY: exact scalar ABI; Bool arguments are normalized to zero or one.
    match unsafe {
        synch_lean_settle_size(
            row.into(),
            durable.into(),
            complete.into(),
            final_held.into(),
            recorded,
            claimed,
        )
    } {
        0 => Settlement::Refuse,
        1 => Settlement::Keep,
        2 => Settlement::Reset,
        _ => panic!("invalid Lean settlement result"),
    }
}
