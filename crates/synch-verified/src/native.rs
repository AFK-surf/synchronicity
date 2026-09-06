use std::sync::Once;

unsafe extern "C" {
    fn synch_adapter_initialize() -> u8;
    fn synch_adapter_thread_initialize();
    fn synch_adapter_thread_finalize();
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

pub(crate) fn enter() {
    INITIALIZE.call_once(|| {
        // SAFETY: exactly once per process, before any native operation call.
        assert_eq!(
            unsafe { synch_adapter_initialize() },
            1,
            "Lean initialization failed"
        );
    });
    THREAD.with(|_| {});
}
