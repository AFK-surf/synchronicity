//! The documented bounds (`docs/SOCKETS.md` §10).
//!
//! DESIGN.md §12 declines per-peer rate limits on the sync ALPNs on the grounds
//! that every peer is an authorized member and abuse is a membership problem.
//! Sockets keep that stance: nothing here is a quota. What these are is the
//! same kind of sanity bound §12 already permits — a cap on the cost of any
//! *single* invocation, so that one stream cannot take a worker with it.
//!
//! [`Limits::idle_deadline`] is a cap on the same footing as the rest, on
//! time rather than on bytes: an invocation that stops making progress —
//! no bytes moved — is ended with `Deadline` when the deadline expires, so a
//! caller cannot hold a stream and a slot forever by sending nothing.
//! Progress is bytes moved, deliberately and only: readiness is not
//! progress, because a terminal or bogus handle is ready forever and
//! counting that would let a guest re-poll a dead handle with the deadline
//! never arriving. There is still no *total* wall-clock bound: progress
//! pushes the deadline out, so a proxy with steady traffic never notices it.
//! CPU is bounded by the timeslicer rather than by a clock.

use std::time::Duration;

/// Per-invocation and per-socket bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// The most endpoint handles one invocation may hold, `SY_SELF` included.
    ///
    /// Also the `sy_poll` array cap, and deliberately the same number: a
    /// program that can hold 32 endpoints must be able to wait on all 32, or
    /// the last one it opened is one it can never learn about.
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
            max_handles: 32,
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

/// How long a finished invocation may spend getting queued bytes onto the wire.
///
/// A program returning is not the same as its last write landing: what it wrote
/// is in a ring the host owns, and the host told the guest it had taken it. So
/// every endpoint that still owes bytes — the caller's stream and everything
/// the program connected to — half-closes and drains before the teardown drops
/// them, and this is the whole budget for all of it, spent by all of them at
/// once. It is a bound rather than a promise: an upstream that has stopped
/// reading would otherwise hold an invocation's concurrency slot open with
/// nothing to show for it.
pub(crate) const TEARDOWN_DRAIN: Duration = Duration::from_secs(5);

/// The most bytes one `sy_log` line may carry before it is flushed.
pub(crate) const MAX_LOG_LINE: usize = 512;

/// The most distinct metric names one socket may create.
pub(crate) const MAX_METRIC_NAMES: usize = 32;

/// The most labels one invocation may carry.
pub(crate) const MAX_LABELS: usize = 8;

/// The most milliseconds a guest may name for a rate-limit window or a map
/// TTL.
///
/// Clamped, not refused: a window beyond it is a program asking the
/// memory-only map to remember something no memory-resident store should
/// promise, and the clamp keeps the value inside every duration computation
/// the runtime performs. That matters twice: `Duration::as_nanos()` for a
/// window of `2^58` ms is a multiple of `2^64`, which truncates to zero in
/// the limiter's `as u64` and would divide by zero; and `Instant + Duration`
/// overflows on the nanosecond-repr platforms (macOS, OpenBSD) for values
/// near `u64::MAX` ms. `u32::MAX` ms is ~49.7 days — long enough that the
/// clamp is indistinguishable from the program's intent.
pub(crate) const MAX_GUEST_DURATION_MS: u64 = u32::MAX as u64;

/// Host bytes one cursor entry costs beyond its name's bytes.
///
/// `sy_list_open` retains a `Vec<String>`: 24 bytes of `String` header per
/// entry in the vector, plus one heap allocation per name whose size is the
/// name rounded up by the allocator. Measured against a counting allocator,
/// 65 536 fifteen-byte names retained ~2.8 MiB for ~0.98 MiB of payload —
/// ~28 bytes of overhead per entry. Charged as 32, with headroom so the
/// bound holds across allocators; the footprint meter counts each entry at
/// `len + 32`, which is what keeps the documented 1 MiB per-invocation
/// footprint a number that means something.
pub const CURSOR_ENTRY_OVERHEAD: u64 = 32;

/// The most bytes a single helper will copy in one call.
///
/// Not a security bound — the pointer cage already confines every access to the
/// guest's own stack, so a larger request simply fails validation. It is here
/// so that an absurd length argument is refused as an argument rather than
/// walked.
///
/// Two ways of meeting it, and the difference is what a short answer means.
/// The stream helpers — `sy_read`, `sy_write`, `sy_pread`, `sy_log` — clamp
/// to it: a short count is the documented outcome of a stream call, the
/// guest's next call continues where it left off, and a large request on a
/// small stream is normal. The byte-copy helpers — `sy_memcpy`, `sy_memset`,
/// `sy_getrandom`, the decoders — refuse an over-cap length with `SY_EINVAL`
/// instead, because a short copy is not a short stream read; it is a silently
/// different answer.
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
