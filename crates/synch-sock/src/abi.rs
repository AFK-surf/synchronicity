//! The guest-visible ABI: error codes, poll flags, struct layouts and bounds.
//!
//! Everything here is duplicated in `sdk/synch.h`, and `sdk`'s
//! `the_header_and_the_abi_agree` test is what keeps the two from drifting:
//! the header is the guest's only view of these numbers, and a guest compiled
//! against a stale one gets wrong answers rather than errors. (Named rather
//! than linked: a `#[cfg(test)]` item is not in the documented crate, so a
//! link to one is a link rustdoc cannot resolve.)

/// Negative returns. Every helper that can fail returns one of these.
///
/// Distinguished rather than collapsed into `-1`, because a program's only
/// recovery is to tell them apart: `SY_EAGAIN` means poll and come back,
/// `SY_EPERM` means stop asking, and a program that read both as failure would
/// either spin or give up.
pub mod errno {
    /// The operation would block; poll for readiness and retry.
    pub(crate) const EAGAIN: i64 = -1;
    /// No such handle in this invocation.
    pub const EBADF: i64 = -2;
    /// A malformed argument: a bad length, an unparseable name, a bad enum.
    pub const EINVAL: i64 = -3;
    /// Refused by policy: egress not declared or not armed, a path out of scope.
    pub(crate) const EPERM: i64 = -4;
    /// The connection was reset by the peer.
    pub(crate) const ECONNRESET: i64 = -5;
    /// A connect or a read timed out.
    pub(crate) const ETIMEDOUT: i64 = -6;
    /// A documented bound in `docs/SOCKETS.md` §10 was hit.
    pub(crate) const ELIMIT: i64 = -7;
    /// No such path, key, or object.
    pub const ENOENT: i64 = -8;
    /// Written to after the peer's read side went away.
    pub(crate) const EPIPE: i64 = -9;
    /// The operation is invalid in the handle's selected protocol state.
    pub(crate) const ESTATE: i64 = -10;
}

/// Readiness bits, for `sy_poll`'s `events` and `revents`.
pub mod poll {
    /// Readable, or an EOF is pending.
    pub const IN: u32 = 0x1;
    /// The tx window has room; a connecting endpoint has finished connecting.
    pub const OUT: u32 = 0x2;
    /// The endpoint is shut in both directions. Reported without asking.
    pub const HUP: u32 = 0x4;
    /// The endpoint failed; `sy_errno` says why.
    pub(crate) const ERR: u32 = 0x8;
    /// The peer closed or shut down its write side.
    pub(crate) const RDHUP: u32 = 0x10;
    /// Every bit a program may ask for. Anything else in `events` is refused,
    /// so a guest built against a newer header fails loudly here rather than
    /// silently waiting for a condition this build never reports.
    pub const ALL: u32 = IN | OUT | HUP | ERR | RDHUP;
}

/// The inbound stream's handle. Always zero, always present, never allocated.
pub const SY_SELF: i64 = 0;

/// `struct sy_pollfd { sy_s64 handle; sy_u32 events; sy_u32 revents; }`.
///
/// The one guest-visible struct left in the ABI, and deliberately: `sy_poll`
/// is the hot path, its array is one validated region however many handles it
/// watches, and its three flat fields carry no enum worth a name. Everything
/// structured — stat results, SSH events, PTY specs, process status, backing
/// declarations — crosses the cage as a JSON handle instead (`sy_json_*`).
pub(crate) const POLLFD_SIZE: u64 = 16;

/// Flags for `sy_base64_encode` and `sy_base64_decode_in_place`.
///
/// Two orthogonal booleans rather than a four-value enum: the URL-safe
/// alphabet and the padding are independent choices, combinable with `|`.
pub mod base64_flag {
    /// Use the URL-safe alphabet.
    pub const URL: u64 = 0x1;
    /// Omit (or refuse) `=` padding.
    pub const NO_PAD: u64 = 0x2;
    /// Both together, spelled out so the flag check can match exhaustively.
    pub(crate) const URL_NO_PAD: u64 = URL | NO_PAD;
}

/// What `sy_json_type` returns.
///
/// zeroserve's tags, verbatim: the JSON API is modeled on its, and a type tag
/// is a discriminant a C program switches on, not a protocol value worth
/// spelling out.
pub mod json_type {
    /// `null`.
    pub const NULL: i64 = 0;
    /// `true` or `false`.
    pub const BOOL: i64 = 1;
    /// A number.
    pub const NUMBER: i64 = 2;
    /// A string.
    pub const STRING: i64 = 3;
    /// An array.
    pub const ARRAY: i64 = 4;
    /// An object.
    pub const OBJECT: i64 = 5;
}

/// The entrypoint section run once per incoming stream.
pub(crate) const SECTION_STREAM: &str = "synchronicity.stream";

/// The entrypoint section run once at arm time, to collect declarations.
pub(crate) const SECTION_INIT: &str = "synchronicity.init";
