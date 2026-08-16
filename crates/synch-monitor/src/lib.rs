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
//! # What a watch list covers
//!
//! An operator writes down zones, but the thing they are protecting is a
//! *name*: `_synchronicity.<network>.<org>.<apex>`, the record a client
//! resolves. Which zone signs that name is not a fixed property of it — a cut
//! can be created or removed at any label boundary along it, and whoever holds
//! the zone above the boundary decides. The client follows whatever cut exists
//! and demands a log entry for the key at *that* signer (§4.2), so an entry
//! naming an unexpected zone is accepted by clients and has to be seen here.
//!
//! So a watch on `cp.example.com` covers every zone comparable with it in the
//! DNS tree — the whole ladder above it and everything below it, not merely
//! that spelling:
//!
//! ```text
//!   .                    excluded, and only this one — see below
//!   com                  a TLD can withdraw example.com's delegation
//!   example.com          can withdraw cp's, and serve cp's names itself
//!   cp.example.com       the zone the operator wrote down
//!   org.cp.example.com   a new cut, taking the names under it out of cp's key
//!   …and anything deeper
//! ```
//!
//! Every one of those keys can authorize itself over
//! `_synchronicity.network.org.cp.example.com`, every one produces an entry a
//! client accepts, and matching the watch list by equality reported only the
//! middle line. The ancestors are not a slippery slope to be trimmed: `com`
//! really can take the name, and an entry naming `com` is one no client would
//! ever refuse. It costs nothing to watch, because a TLD publishing a
//! synchronicity zone-key entry is an event that should be read either way.
//!
//! **The root is the exception, and it is not an oversight.** A root takeover
//! is real — the root can withdraw `com` — but the entry it would need cannot
//! exist: a certificate whose SAN is the DNS root is refused by
//! [`synch_net::x509::Certificate::single_dns_name`], on both sides. So a
//! client served a root-signed membership answer **fails closed** rather than
//! accepting a key nobody watched, and there is no silent case left for a
//! monitor to catch. Excluding it also keeps a stray `""` in a hand-edited
//! state file — which parses as the root, and is comparable with every name in
//! existence — from turning one watch into a report on the entire log.
//! `tests/tiers.rs` pins the refusal so it cannot quietly become an
//! acceptance. See [`KnownKeys::watches`].
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

pub use classify::{classify, Finding, KnownKeys, Tier, Watched};
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
