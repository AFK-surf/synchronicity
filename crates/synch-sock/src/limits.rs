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
    /// The most handles one invocation may hold, `SY_SELF` included.
    ///
    /// Also the `sy_poll` array cap, and deliberately the same number: a
    /// program that can hold 256 handles must be able to wait on all 256, or
    /// the last one it opened is one it can never learn about.
    ///
    /// The table is deliberately larger than any one resource's own bound.
    /// What stops a guest turning spare slots into host memory or OS
    /// children is not this number but the bounds beside it:
    /// `MAX_OPEN_ENDPOINTS` for everything ring-bearing, `max_egress`,
    /// the SSH channel cap, `MAX_LANES_PER_CHANNEL`, `MAX_LIVE_PROCESSES`,
    /// `MAX_OPEN_PTYS`, `MAX_OPEN_FILE_TRANSFERS`, and the footprint meter
    /// for objects, cursors, and JSON values (`docs/SSH-SOCKETS.md` §9).
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
            max_handles: 256,
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

/// Consecutive faults, out of the last [`FAULT_WINDOW`] invocations, that
/// auto-disarm a socket.
///
/// A program that cannot run is not left accepting connections. The window is
/// short because the signal is unambiguous: a fault is a contained crash, not a
/// refusal, and a program faulting half the time is broken rather than picky.
pub(crate) const FAULT_QUARANTINE: usize = 8;
/// See [`FAULT_QUARANTINE`].
pub(crate) const FAULT_WINDOW: usize = 16;

/// Caps for `synch socket connect --listen` (crates/synch-cli/src/connect.rs).
///
/// The listener is a pre-auth front door: a connection is admitted before any
/// authentication happens, so a flood of accept()s would hold admission slots —
/// and the daemon's socket-pool streams behind them — for connections that may
/// never authenticate. The semaphore caps concurrent pre-auth connections, and
/// the sliding window caps the acceptance rate globally and per peer IP. A
/// breach drops the connection immediately, fail-closed: refusing a legitimate
/// burst is preferable to letting a flood starve every legitimate user.
pub const MAX_ACCEPT_CONCURRENT: usize = 16;
/// See [`MAX_ACCEPT_CONCURRENT`] — global accepts per second.
pub const MAX_ACCEPTS_PER_SECOND: usize = 64;
/// See [`MAX_ACCEPT_CONCURRENT`] — accepts per peer IP per second.
pub const MAX_ACCEPTS_PER_IP_PER_SECOND: usize = 8;

/// The most open endpoints one invocation may hold, `SY_SELF` included.
///
/// The 256-slot handle table's guard against ring amplification, and the
/// pre-256 table size on purpose: every endpoint carries up to two
/// `ring_bytes` rings, and the per-role caps alone do not bound them,
/// because a counted budget can be released while its endpoint lives on —
/// a closed process handle leaves its stdio endpoints open, a channel
/// closed from the wire leaves the guest's fd in the table, an ended
/// egress task gives its permit back while the guest keeps the handle.
/// Counting open endpoints at insertion bounds the sum of all such
/// residue at exactly what the 32-handle table used to allow.
pub(crate) const MAX_OPEN_ENDPOINTS: usize = 32;

/// The most concurrently live child processes one invocation may hold.
///
/// A process handle stands in front of a real OS child, which no handle-table
/// arithmetic should be able to multiply: before the table grew to 256 slots
/// the table itself was the only bound on spawns, and `docs/SSH-SOCKETS.md`
/// §9 requires that growing the table be paired with a bound like this one.
/// Counted as `Slot::Process` entries — pipe and PTY spawns alike — so a
/// guest that is done with a child gives the slot back with `sy_close`.
pub(crate) const MAX_LIVE_PROCESSES: usize = 16;

/// The most PTY masters one invocation may hold open.
///
/// The counterpart of [`MAX_LIVE_PROCESSES`] for `sy_pty_open`: a PTY master
/// carries a full-sized ring before any child is attached to it, so the
/// masters are bounded on their own rather than only through the children.
pub(crate) const MAX_OPEN_PTYS: usize = 16;

/// The most file-transfer service endpoints one invocation may hold open.
///
/// Each `sy_sftp_open` allocates an endpoint ring and a bridge pipe
/// host-side; like the process caps, this keeps the 256-slot handle table
/// from being a multiplier on host memory (`docs/SSH-SOCKETS.md` §9).
pub(crate) const MAX_OPEN_FILE_TRANSFERS: usize = 16;

/// The most tree writers one invocation may hold open
/// (`docs/TREE-WRITES.md` §8).
///
/// A writer carries a [`WRITER_BUFFER_BYTES`] staging buffer and, engine-side,
/// a staging file on the callee's disk. Bounded like the ring-bearing
/// endpoints are — by its own count, not the footprint meter — so the 256-slot
/// handle table cannot multiply either.
pub(crate) const MAX_OPEN_WRITERS: usize = 4;

/// Host bytes one tree writer buffers between the guest and the staging file.
///
/// A full buffer is backpressure — `sy_put_write` returns `SY_EAGAIN` and the
/// writer polls `SY_POLL_OUT` when room appears — exactly as a full tx ring
/// is.
pub(crate) const WRITER_BUFFER_BYTES: usize = 256 * 1024;

/// The most commits — deletes included — one invocation may dispatch.
///
/// A sanity bound on heads-per-stream rather than a quota: every commit is a
/// published head, and a program with many files to publish per invocation is
/// meant to batch them into fewer, larger objects.
pub(crate) const MAX_PUT_COMMITS: u32 = 64;

/// The most extended-data lanes one SSH channel may hold open.
///
/// `data_type` is a guest-chosen `u32` and lanes are keyed per
/// `(channel, data_type)`, so without a cap a guest could mint one ring per
/// integer up to the handle table's size. A real session uses one
/// extended-data type (stderr); eight is generous.
pub(crate) const MAX_LANES_PER_CHANNEL: usize = 8;

/// The capacity of an ssh lane's outbound channel, in queued messages.
///
/// The lane a guest registers for a channel's data is bounded at 8 queued
/// messages, matching the inbound `channel(8)`: a client that withholds its
/// recipient window (never sends CHANNEL_WINDOW_ADJUST) backpressures the
/// guest (`sy_write` -> EAGAIN once the endpoint ring and this channel are
/// full) instead of growing host memory for the lifetime of the connection.
pub const CHANNEL_LANE_CAPACITY: usize = 8;

/// The most pipelined CHANNEL_REQUEST tasks parked per channel.
///
/// Each request copies the client payload and parks behind the per-channel
/// order mutex while the guest decides (up to 60s). Requests beyond the cap
/// get an immediate `reply(false)`, fail-closed: the run loop is never
/// blocked long by a client that floods requests faster than the guest
/// answers them.
pub const MAX_OUTSTANDING_REQUESTS_PER_CHANNEL: usize = 16;

/// The most declined extended-data lanes remembered per channel.
///
/// When a guest answers an extended-data event with `sy_ssh_event_done` rather
/// than opening a lane, the connection remembers the refusal so the same
/// `data_type` does not raise an event again. `data_type` is a wire-controlled
/// `u32` and the event carries no payload, so neither the per-event nor the
/// total event-bytes bound applies: without a cap here, a client streaming
/// `data_type = 0, 1, 2, …` with empty payloads bought one permanent set entry
/// per ~40-byte packet, and each packet reset the inactivity timer, so the
/// connection never idled out. Unbounded daemon heap growth from one
/// connection, which §6.2 promises cannot happen.
///
/// A real session uses one extended-data type (stderr). Past the cap the bytes
/// are still discarded; the only cost is that such a type may raise an event
/// again later, which the ordinary event-queue bounds already govern.
pub const MAX_DISCARDED_LANES_PER_CHANNEL: usize = 16;

/// The sliding window, in seconds, over which auth rejections are throttled.
///
/// Host-side and cross-connection: when the window is full, further auth
/// attempts are rejected without consulting the guest — fail-closed against
/// online brute force that would otherwise pace itself with one fresh
/// connection per batch.
pub const AUTH_REJECTION_WINDOW_SECS: u64 = 60;
/// See [`AUTH_REJECTION_WINDOW_SECS`] — rejections per window, all IPs.
pub const MAX_AUTH_REJECTIONS_PER_WINDOW: usize = 64;
/// See [`AUTH_REJECTION_WINDOW_SECS`] — rejections per window per peer IP.
pub const MAX_AUTH_REJECTIONS_PER_IP: usize = 16;

/// The longest auth username accepted, in bytes.
///
/// A wire-controlled username is copied into an event payload; beyond this
/// the attempt is rejected as an ordinary auth failure, never a disconnect —
/// an oversized username must not be able to kill the connection.
pub const MAX_AUTH_USERNAME_BYTES: usize = 1024;

/// The bound, in milliseconds, on handler awaits that send into a bounded
/// lane or channel.
///
/// A guest that registers a lane but stops reading its lane fd would
/// otherwise block the ssh run loop inside `lane.send(...).await` forever,
/// starving the inactivity timer and the keepalive. On timeout the bytes are
/// dropped under the bounded-discard contract (`docs/SSH-SOCKETS.md` §14.3);
/// the vendored russh mirrors this value for its own `chan.send` bound
/// (`vendor/russh/PATCHES.md`).
pub const LANE_SEND_TIMEOUT_MS: u64 = 1000;
