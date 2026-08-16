//! Watching the transparency log a zone key was required to appear in.
//!
//! A required log with no watcher is a formality. This crate is the watcher:
//! it reads the log's static tiles from end to end, pulls the certificate out
//! of every `hashedrekord` leaf, indexes it by the `dNSName` SAN inside, and
//! for the apexes an operator cares about decides — offline, from the leaf
//! alone — which of three things it is looking at
//! (docs/REKOR-ZONE-KEY.md §5.5).
//!
//! ```text
//!  tier A   valid chain + valid succession countersignature   routine
//!  tier B   valid chain, no valid countersignature            ALERT
//!  tier C   no valid chain                                    noise
//! ```
//!
//! # Why tier B is the alarm, and tier A is unreachable to an attacker
//!
//! An attacker who has taken over the registrar can produce tier A's first
//! half: they hold the DS, so they can assemble a real DNSSEC chain naming
//! their key. What they cannot produce is the second half. The
//! countersignature is made by the **previous zone key's private half** —
//! the one thing a DS substitution does not give them. If they had that key,
//! transparency was never going to help; the operator's problem is theft, not
//! substitution, and the runbook for theft is different.
//!
//! So tier B is not "something odd" — it is the compromise signature, and it
//! is loud on purpose. Two legitimate events land there too, and both must be
//! documented rather than tuned away: a zone's **genesis** key has no
//! predecessor to countersign it, and **disaster recovery** happens precisely
//! because the predecessor's private key is gone. Tier B means *a human
//! looks*, not *an attack happened*.
//!
//! # Why tier C is silent, and why that is only safe because clients agree
//!
//! Tier C is where an entry goes when its chain proves nothing: absent,
//! broken, or about some other key. Anybody may write anything into a public
//! log, so unauthorized claims naming an apex are a nuisance, not an
//! escalation — *provided no client would ever have accepted one*. That
//! proviso is load-bearing. If a client accepted an entry a monitor files as
//! tier C, an attacker would hold a key that works against victims and rings
//! no bell, which is strictly worse than not logging at all. The client
//! therefore enforces the chain on the monitor's behalf, using
//! [`synch_net::chain`] — the same validator this crate calls, deliberately
//! the same code — and the invariant to preserve on both sides is:
//!
//! > **anything a client accepts is classified at least tier B.**
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
