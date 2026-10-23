//! Holds program loads in flight, so a test can keep a compile running for
//! exactly as long as it measures (feature `compile-hold`).
//!
//! Whether a compile stalls the worker cannot be asked of the clock: a load
//! that takes 170ms on one machine takes 15ms on the next, and a probe timed
//! against it fails on the fast one for its speed alone. A load held here lasts
//! until the test releases it, on any machine, so the question becomes whether
//! the worker answers while a compile is in flight — which a stalled worker
//! never does and a free one always does.
//!
//! Test machinery: process-global, and only built with the feature.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

struct State {
    held: bool,
    entered: usize,
}

static STATE: Mutex<State> = Mutex::new(State {
    held: false,
    entered: 0,
});
static CHANGED: Condvar = Condvar::new();

fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Loads that start from now on wait at their start until [`release`].
pub fn hold() {
    state().held = true;
}

/// Lets every held load go on; later ones run straight through.
pub fn release() {
    state().held = false;
    CHANGED.notify_all();
}

/// Blocks the calling thread until `count` loads have started since the
/// process began. A blocking wait: call it off the async runtime.
pub fn wait_entered(count: usize) {
    let mut state = state();
    while state.entered < count {
        state = CHANGED.wait(state).unwrap_or_else(PoisonError::into_inner);
    }
}

/// Where a load starts: counted, then held while [`hold`] is in force.
pub(crate) fn checkpoint() {
    let mut state = state();
    state.entered += 1;
    CHANGED.notify_all();
    while state.held {
        state = CHANGED.wait(state).unwrap_or_else(PoisonError::into_inner);
    }
}
