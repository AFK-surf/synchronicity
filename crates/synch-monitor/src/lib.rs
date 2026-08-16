//! Watching the transparency log a zone key was required to appear in.
//!
//! A required log with no watcher is a formality. This crate is the watcher:
//! it reads the log's static tiles from end to end, pulls the certificate out
//! of every `hashedrekord` leaf, indexes it by the `dNSName` SAN inside, and
//! for the apexes an operator cares about decides — offline, from the leaf
//! alone — which of two things it is looking at
//! (docs/REKOR-ZONE-KEY.md §5.5).
//!
//! ```text
//!  tier A   the chain verifies and covers this key   an authorization: REPORT
//!  tier B   no valid chain, or a chain for another   noise
//! ```
//!
//! # What this crate reports, and what it deliberately does not decide
//!
//! **A fully verified DNSSEC chain is enough.** An entry whose chain walks to
//! the anchor in force and covers the certificate's own key is an entry that
//! *authorizes* that key for that apex — and the monitor's job is to surface
//! every such authorization for a watched zone, the first time it sees it.
//!
//! It does not try to say whether the authorization was *legitimate*, and
//! that limit is deliberate rather than unfinished. An attacker who has taken
//! the registrar holds the DS, so their entry produces a chain that verifies
//! exactly like the operator's own: a substitution and a rotation are
//! indistinguishable in the log, and no amount of reading the leaf separates
//! them. So this crate does not pretend to. Every authorization event for a
//! watched zone is reported, and **the operator's own record of what they
//! published is the discriminator** — they know which keys they minted, and
//! nothing in a public log can tell them that.
//!
//! This is how Certificate Transparency monitoring works: a CT monitor tells
//! you a certificate exists for your name and leaves "did you ask for it?" to
//! you. Be clear about what that costs — automation cannot raise the alarm on
//! its own, so the operator has to hold a record to compare against, and a
//! zone whose owner never reads the reports is no better watched than one
//! nobody monitors.
//!
//! # Reporting once, not forever
//!
//! [`KnownKeys`] is the memory that makes this usable: a key already recorded
//! for an apex has been reported, and is not reported again. It is not a
//! trust store and must never be read as one — an attacker's key is recorded
//! the moment it is reported, exactly like the operator's, because the
//! monitor draws no distinction. Nothing about being *recorded* makes a later
//! entry look more routine.
//!
//! # Why tier B is silent, and why that is only safe because clients agree
//!
//! Tier B is where an entry goes when its chain proves nothing: absent,
//! broken, or about some other key. Anybody may write anything into a public
//! log, so unauthorized claims naming an apex are a nuisance, not an
//! escalation — *provided no client would ever have accepted one*. That
//! proviso is load-bearing. If a client accepted an entry a monitor files as
//! tier B, an attacker would hold a key that works against victims and rings
//! no bell, which is strictly worse than not logging at all. The client
//! therefore enforces the chain on the monitor's behalf, using
//! [`synch_net::chain`] — the same validator this crate calls, deliberately
//! the same code — and the invariant to preserve on both sides is:
//!
//! > **anything a client accepts is classified tier A.**
//!
//! Never tighten this crate's chain rule without tightening the client's.

#![deny(missing_docs)]

pub mod classify;
pub mod state;
pub mod tiles;

pub use classify::{classify, Finding, KnownKeys, Tier};
pub use state::MonitorState;

/// Why a monitor run could not finish.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MonitorError {
    /// The log could not be reached, or answered something unexpected.
    #[error("log transport: {0}")]
    Transport(String),
    /// A tile is missing or does not decode.
    #[error("tile: {0}")]
    Tile(String),
    /// The checkpoint does not verify, or does not extend what was persisted.
    #[error("checkpoint: {0}")]
    Checkpoint(String),
    /// The persisted state could not be read or written.
    #[error("state: {0}")]
    State(String),
}
