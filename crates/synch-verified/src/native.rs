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
// SAFETY: the C adapter marks the entire immutable Lean scope graph MT before
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
