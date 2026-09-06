//! The Lean runtime and its objects, as far as this crate touches them:
//! process and thread initialization, owned references to the continuation
//! and packet objects the exported Lean entry points exchange, and the byte
//! arrays that carry commands and replies into Lean. Every policy decision is
//! a Lean export; nothing here interprets a continuation.
//!
//! The object layout is copied from the pinned toolchain's `lean.h`, whose
//! helpers are `static inline` and cannot be linked. `build.rs` refuses any
//! other Lean version; when the pin moves, recheck each item against the
//! `lean.h` definition its comment names.
use std::{
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
    sync::{
        atomic::{AtomicI32, Ordering},
        Once,
    },
};

/// `lean_object`: the reference count, then the bitfields `m_cs_sz:16`,
/// `m_other:8` and `m_tag:8`. GCC and Clang pack bitfields from the low bits
/// on every supported target and Lean runs on little-endian machines only,
/// so the three occupy these bytes in this order.
#[repr(C)]
struct Object {
    rc: i32,
    cs_sz: u16,
    other: u8,
    tag: u8,
}

/// `lean_sarray_object`: the elements follow the capacity in place.
#[repr(C)]
struct ScalarArray {
    header: Object,
    size: usize,
    capacity: usize,
}

const _: () = assert!(size_of::<Object>() == 8 && size_of::<ScalarArray>() == 24);

/// `LeanScalarArray`, the tag of a `ByteArray`.
const SCALAR_ARRAY: u8 = 248;

unsafe extern "C" {
    fn lean_initialize_runtime_module();
    fn lean_initialize_thread();
    fn lean_finalize_thread();
    fn lean_io_mark_end_initialization();
    fn lean_io_result_show_error(result: *mut Object);
    fn lean_alloc_object(size: usize) -> *mut Object;
    fn lean_dec_ref_cold(object: *mut Object);
    #[link_name = "initialize_VerifiedCore"]
    fn initialize_verified_core(builtin: u8) -> *mut Object;
    fn synch_lean_start(command: *mut Object) -> *mut Object;
    fn synch_lean_operation_packet(state: *mut Object) -> *mut Object;
    fn synch_lean_operation_resume(state: *mut Object, reply: *mut Object) -> *mut Object;
}

/// `lean_is_scalar`: a tagged pointer carries a small value, not an object.
fn is_scalar(object: *mut Object) -> bool {
    object as usize & 1 == 1
}

/// `lean_inc`. A positive count belongs to one thread; a negative one is
/// shared and counts down atomically; zero marks a persistent object.
///
/// # Safety
/// `object` is a live Lean object or scalar.
unsafe fn inc(object: *mut Object) {
    if is_scalar(object) {
        return;
    }
    // SAFETY: the object is live, and the shared case is only ever counted atomically.
    unsafe {
        let rc = (*object).rc;
        if rc > 0 {
            (*object).rc = rc + 1;
        } else if rc != 0 {
            AtomicI32::from_ptr(&raw mut (*object).rc).fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// `lean_dec`. The runtime releases the last reference, and any shared one.
///
/// # Safety
/// `object` is a live Lean object or scalar, and this reference is owned.
unsafe fn dec(object: *mut Object) {
    if is_scalar(object) {
        return;
    }
    // SAFETY: the object is live and this reference is owned.
    unsafe {
        let rc = (*object).rc;
        if rc > 1 {
            (*object).rc = rc - 1;
        } else if rc != 0 {
            lean_dec_ref_cold(object);
        }
    }
}

/// `lean_sarray_cptr`: the elements follow the fixed part of the object.
///
/// # Safety
/// `object` is a live scalar array.
unsafe fn elements(object: *mut Object) -> *mut u8 {
    // SAFETY: the caller guarantees a scalar array, whose data starts here.
    unsafe { object.cast::<u8>().add(size_of::<ScalarArray>()) }
}

/// `lean_alloc_sarray` with element size one, filled from `bytes`: a fresh
/// owned `ByteArray` whose size and capacity are the length. The allocator
/// has already recorded `m_cs_sz`, so only the count, element size and tag
/// are written, as `lean_set_st_header` does.
fn byte_array(bytes: &[u8]) -> *mut Object {
    let size = size_of::<ScalarArray>()
        .checked_add(bytes.len())
        .expect("Lean byte array size overflows");
    // SAFETY: the runtime aborts rather than return null; the allocation holds
    // the fixed part and `bytes.len()` trailing bytes, all written before any
    // Lean code can observe the object.
    unsafe {
        let array = lean_alloc_object(size).cast::<ScalarArray>();
        (*array).header.rc = 1;
        (*array).header.other = 1;
        (*array).header.tag = SCALAR_ARRAY;
        (*array).size = bytes.len();
        (*array).capacity = bytes.len();
        let object = array.cast::<Object>();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), elements(object), bytes.len());
        object
    }
}

static INITIALIZE: Once = Once::new();

/// Initialize the runtime and the compiled Lean modules once per process.
fn initialize() -> bool {
    // SAFETY: called once, before any other call into the runtime.
    unsafe {
        lean_initialize_runtime_module();
        let result = initialize_verified_core(1);
        // `lean_io_result_is_ok`: the `ok` constructor carries tag zero.
        let ok = (*result).tag == 0;
        if !ok {
            lean_io_result_show_error(result);
        }
        dec(result);
        if ok {
            lean_io_mark_end_initialization();
        }
        ok
    }
}

struct Thread;
impl Drop for Thread {
    fn drop(&mut self) {
        // SAFETY: paired with initialization on this same thread, after calls return.
        unsafe { lean_finalize_thread() }
    }
}
thread_local! { static THREAD: Thread = {
    // SAFETY: runtime initialization is serialized before touching this TLS slot.
    unsafe { lean_initialize_thread() };
    Thread
}; }

/// Make the runtime ready for this thread: once per process for the runtime
/// and the modules, once per thread for the thread's own state.
fn enter() {
    INITIALIZE.call_once(|| assert!(initialize(), "Lean initialization failed"));
    THREAD.with(|_| {});
}

/// An owned reference to one Lean object, confined to the thread that holds
/// it: never `Send` or `Sync`, so the interpreter, every host resource and
/// any panic unwinding stay on the caller's stack and thread. `None` only
/// while the reference is being transferred into Lean, so unwinding cannot
/// release it twice.
pub(crate) struct Handle(Option<NonNull<Object>>, PhantomData<Rc<()>>);

impl Handle {
    fn own(object: *mut Object) -> Self {
        Self(
            Some(NonNull::new(object).expect("Lean returned a null object")),
            PhantomData,
        )
    }

    fn as_ptr(&self) -> *mut Object {
        self.0
            .expect("Lean handle was already transferred")
            .as_ptr()
    }

    /// The pending request or the terminal result of this continuation.
    pub(crate) fn packet(&self) -> Packet {
        // SAFETY: the state is live and thread-confined. The export consumes
        // one reference, so one is added first, and returns a fresh owned
        // byte array.
        Packet(Self::own(unsafe {
            inc(self.as_ptr());
            synch_lean_operation_packet(self.as_ptr())
        }))
    }

    /// Feed a reply to the pending request, replacing this continuation.
    pub(crate) fn resume(&mut self, reply: &[u8]) {
        let state = self.0.take().expect("Lean handle was already transferred");
        // SAFETY: our sole owned reference is transferred, never a borrowed
        // one, together with a fresh reply array; the export consumes both on
        // the request and the terminal branch. Keeping no reference to the
        // previous continuation lets Lean update buffers in place. If the
        // returned pointer is null and `own` panics, self is already disarmed.
        *self =
            Self::own(unsafe { synch_lean_operation_resume(state.as_ptr(), byte_array(reply)) });
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(object) = self.0.take() {
            // SAFETY: exactly one reference owned, runtime alive on this stack.
            unsafe { dec(object.as_ptr()) }
        }
    }
}

/// An owned, immutable Lean `ByteArray`. A borrowed view cannot outlive it,
/// and ownership keeps the handle's thread confinement.
pub(crate) struct Packet(Handle);

impl Packet {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        // SAFETY: the owned array keeps its bytes allocated while this owner
        // lives; the slice borrows self and no mutable view is exposed.
        unsafe {
            let count = (*self.0.as_ptr().cast::<ScalarArray>()).size;
            if count == 0 {
                return &[];
            }
            std::slice::from_raw_parts(elements(self.0.as_ptr()), count)
        }
    }
}

/// Start a command from its encoded packet, which Lean decodes; the caller
/// owns the fresh continuation until the run ends. The runtime is made ready
/// for this thread first.
pub(crate) fn start(command: &[u8]) -> Handle {
    enter();
    // SAFETY: the runtime is initialized on this thread, and the export takes
    // ownership of a fresh array.
    Handle::own(unsafe { synch_lean_start(byte_array(command)) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_arrays_round_trip_through_the_lean_layout() {
        enter();
        for bytes in [&b""[..], b"x", &[7u8; 4096]] {
            let packet = Packet(Handle::own(byte_array(bytes)));
            assert_eq!(packet.as_bytes(), bytes);
        }
    }
}
