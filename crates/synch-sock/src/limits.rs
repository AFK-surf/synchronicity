//! The documented bounds (`docs/SOCKETS.md` §10).
//!
//! DESIGN.md §12 declines per-peer rate limits on the sync ALPNs on the grounds
//! that every peer is an authorized member and abuse is a membership problem.
//! Sockets keep that stance: nothing here is a quota. What these are is the
//! same kind of sanity bound §12 already permits — a cap on the cost of any
//! *single* invocation, so that one stream cannot take a worker with it.
//!
//! The one that is not a cap at all is [`Limits::idle_deadline`]. There is
//! deliberately no total wall-clock bound: a socket that proxies is supposed to
//! be long-lived, and CPU is bounded by the timeslicer rather than by a clock.

use std::time::Duration;

/// Per-invocation and per-socket bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// The most endpoint handles one invocation may hold, `SY_SELF` included.
    ///
    /// Also the `sy_poll` array cap, and deliberately the same number: a
    /// program that can hold sixteen endpoints must be able to wait on all
    /// sixteen, or the last one it opened is one it can never learn about.
    pub max_handles: usize,
    /// The most outbound TCP connections one invocation may open.
    pub max_egress: usize,
    /// Bytes buffered per endpoint, each direction.
    ///
    /// A full rx ring stops the host reading, which backpressures the far side
    /// through QUIC's or TCP's own flow control. Nothing here has to implement
    /// backpressure; it only has to stop reading, and this is the number at
    /// which it does.
    pub ring_bytes: usize,
    /// Host-side bytes one invocation may hold across the object table.
    pub max_footprint: u64,
    /// The most concurrent invocations of one socket.
    pub max_streams: usize,
    /// How long an invocation may go with no readiness and no progress.
    pub idle_deadline: Duration,
    /// The largest ELF object that may be armed.
    pub max_program_bytes: u64,
    /// Keys one socket's map may hold.
    pub map_max_keys: usize,
    /// Bytes one socket's map may hold, keys and values summed.
    pub map_max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_handles: 16,
            max_egress: 8,
            ring_bytes: 256 * 1024,
            max_footprint: 1024 * 1024,
            max_streams: 64,
            idle_deadline: Duration::from_secs(300),
            max_program_bytes: 4 * 1024 * 1024,
            map_max_keys: 4096,
            map_max_bytes: 1024 * 1024,
        }
    }
}

/// The timeslice the runtime yields and throttles a guest at.
///
/// zeroserve's numbers, and the right ones for a worker shared between streams:
/// yield often enough that a busy program does not delay the reactor past a
/// millisecond, throttle at the point where "busy" has become "spinning", and
/// sleep long enough that the throttle is felt.
pub(crate) const YIELD_AFTER: Duration = Duration::from_millis(1);
/// See [`YIELD_AFTER`].
pub(crate) const THROTTLE_AFTER: Duration = Duration::from_millis(20);
/// See [`YIELD_AFTER`].
pub(crate) const THROTTLE_FOR: Duration = Duration::from_millis(100);

/// How often the preemption watcher interrupts a running guest.
///
/// Preemption is asynchronous and has no cooperative fallback, which is what
/// makes a program with no `sy_poll` in it still interruptible.
pub(crate) const PREEMPTION_INTERVAL: Duration = Duration::from_micros(500);

/// The most bytes one `sy_log` line may carry before it is flushed.
pub(crate) const MAX_LOG_LINE: usize = 512;

/// The most distinct metric names one socket may create.
pub(crate) const MAX_METRIC_NAMES: usize = 32;

/// The most labels one invocation may carry.
pub(crate) const MAX_LABELS: usize = 8;

/// The most bytes a single helper will copy in one call.
///
/// Not a security bound — the pointer cage already confines every access to the
/// guest's own stack, so a larger request simply fails validation. It is here
/// so that an absurd length argument is refused as an argument rather than
/// walked.
pub(crate) const MAX_COPY: u64 = 64 * 1024;

/// Consecutive faults, out of the last [`FAULT_WINDOW`] invocations, that
/// auto-disarm a socket.
///
/// A program that cannot run is not left accepting connections. The window is
/// short because the signal is unambiguous: a fault is a contained crash, not a
/// refusal, and a program faulting half the time is broken rather than picky.
pub(crate) const FAULT_QUARANTINE: usize = 8;
/// See [`FAULT_QUARANTINE`].
pub(crate) const FAULT_WINDOW: usize = 16;
