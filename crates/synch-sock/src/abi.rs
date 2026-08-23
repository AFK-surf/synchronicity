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
    pub const EAGAIN: i64 = -1;
    /// No such handle in this invocation.
    pub const EBADF: i64 = -2;
    /// A malformed argument: a bad length, an unparseable name, a bad enum.
    pub const EINVAL: i64 = -3;
    /// Refused by policy: egress not declared or not armed, a path out of scope.
    pub const EPERM: i64 = -4;
    /// The connection was reset by the peer.
    pub const ECONNRESET: i64 = -5;
    /// A connect or a read timed out.
    pub const ETIMEDOUT: i64 = -6;
    /// A documented bound in `docs/SOCKETS.md` §10 was hit.
    pub const ELIMIT: i64 = -7;
    /// No such path, key, or object.
    pub const ENOENT: i64 = -8;
    /// Written to after the peer's read side went away.
    pub const EPIPE: i64 = -9;
}

/// Readiness bits, for `sy_poll`'s `events` and `revents`.
pub mod poll {
    /// Readable, or an EOF is pending.
    pub const IN: u32 = 0x1;
    /// The tx window has room; a connecting endpoint has finished connecting.
    pub const OUT: u32 = 0x2;
    /// The peer half-closed its write side.
    pub const HUP: u32 = 0x4;
    /// The endpoint failed; `sy_errno` says why.
    pub const ERR: u32 = 0x8;
    /// Every bit a program may ask for. Anything else in `events` is refused,
    /// so a guest built against a newer header fails loudly here rather than
    /// silently waiting for a condition this build never reports.
    pub const ALL: u32 = IN | OUT | HUP | ERR;
}

/// The inbound stream's handle. Always zero, always present, never allocated.
pub const SY_SELF: i64 = 0;

/// `struct sy_pollfd { sy_s64 handle; sy_u32 events; sy_u32 revents; }`.
pub const POLLFD_SIZE: u64 = 16;

/// `struct sy_stat { sy_u64 size; sy_s64 mtime_ns; sy_u32 mode; sy_u32 kind; sy_u8 root[32]; }`.
pub const STAT_SIZE: u64 = 56;

/// What `sy_peer_kind` returns.
pub mod peer_kind {
    /// A rooted member: every space, by construction.
    pub const MEMBER: u64 = 1;
    /// A delegate: only the spaces its delegation names (§3.5).
    pub const DELEGATE: u64 = 2;
}

/// Base64 alphabets and padding, as `sy_base64_encode` takes them.
pub mod base64_kind {
    /// Standard alphabet, padded.
    pub const STANDARD: u64 = 0;
    /// Standard alphabet, unpadded.
    pub const STANDARD_NO_PAD: u64 = 1;
    /// URL-safe alphabet, padded.
    pub const URL: u64 = 2;
    /// URL-safe alphabet, unpadded.
    pub const URL_NO_PAD: u64 = 3;
}

/// The entrypoint section run once per incoming stream.
pub const SECTION_STREAM: &str = "synchronicity.stream";

/// The entrypoint section run once at arm time, to collect declarations.
pub const SECTION_INIT: &str = "synchronicity.init";
