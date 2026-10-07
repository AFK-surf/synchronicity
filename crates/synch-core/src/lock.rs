//! Wire schema for best-effort cluster locks (`docs/LOCKS.md`).
//!
//! A lock is a named lease that at most one node holds while the nodes that
//! want it can talk to each other promptly. It is granted by a claim exchange
//! among every peer that may write the lock's space — no coordinator, no
//! quorum — and these are the messages of that exchange, carried as
//! length-framed postcard on `sync/lock/1` like the other ALPNs.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{origin::OriginId, record::validate_space};

/// ALPN for the lock claim exchange (`docs/LOCKS.md` §9.2).
pub const ALPN_LOCK: &[u8] = b"sync/lock/1";

/// The longest lock name, in bytes (§14).
pub const MAX_LOCK_NAME_BYTES: usize = 512;
/// The longest owner label a claim may carry, in bytes (§14).
pub const MAX_LOCK_OWNER_BYTES: usize = 128;
/// The largest opaque payload a claim may carry (§14) — an S3 lock key's body.
pub const MAX_LOCK_PAYLOAD_BYTES: usize = 16 * 1024;
/// The shortest lease a claim may ask for (§14).
pub const MIN_LOCK_TTL_MS: u32 = 5_000;
/// The longest lease a claim may ask for (§14).
pub const MAX_LOCK_TTL_MS: u32 = 3_600_000;
/// How many claims one answer may report.
///
/// One lock has one holder and, at any moment, a handful of contenders; the
/// bound is the per-message work cap, not a statement about contention.
pub const MAX_LOCK_REPORTS: usize = 64;
/// How many ended claim ids one answer may carry.
pub const MAX_LOCK_ENDED: usize = 256;
/// How many handoff watermarks one answer may carry (§8).
pub const MAX_LOCK_WATERMARKS: usize = 8;
/// How many expired claims one claim may say it took over from (§6).
pub const MAX_LOCK_SUPERSEDES: usize = 16;

/// A lock's name: the space that authorizes it and a name inside it.
///
/// The name is any UTF-8 string up to [`MAX_LOCK_NAME_BYTES`]; it need not be
/// a path, and may equal one — that is how an S3 lock key and the CLI name
/// the same lock (§11.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockName {
    /// The space whose writers may contend for the lock.
    pub space: String,
    /// The lock's name within the space.
    pub name: String,
}

/// Why a lock name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LockNameError {
    /// The text had no `/` between space and name.
    #[error("a lock is named <space>/<name>")]
    Shape,
    /// The space is not a legal space id.
    #[error("{0}")]
    Space(String),
    /// The name is empty, too long, or carries a control character.
    #[error("a lock name is 1 to {MAX_LOCK_NAME_BYTES} bytes with no control characters")]
    Name,
}

impl LockName {
    /// A checked lock name.
    pub fn new(space: impl Into<String>, name: impl Into<String>) -> Result<Self, LockNameError> {
        let lock = LockName {
            space: space.into(),
            name: name.into(),
        };
        lock.check()?;
        Ok(lock)
    }

    /// Parses `<space>/<name>`.
    pub fn parse(text: &str) -> Result<Self, LockNameError> {
        let (space, name) = text.split_once('/').ok_or(LockNameError::Shape)?;
        LockName::new(space, name)
    }

    /// Re-checks a name that arrived over the wire.
    pub fn check(&self) -> Result<(), LockNameError> {
        validate_space(&self.space).map_err(|e| LockNameError::Space(e.to_string()))?;
        if self.name.is_empty()
            || self.name.len() > MAX_LOCK_NAME_BYTES
            || self.name.chars().any(char::is_control)
        {
            return Err(LockNameError::Name);
        }
        Ok(())
    }
}

impl fmt::Display for LockName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.space, self.name)
    }
}

/// A claim's place in the total order (§3.3): Lamport time, then origin.
///
/// The derived order compares `lamport` first, which is the point: a ticket
/// is taken above every ticket its node has heard of, so a claimant that saw
/// another claim always orders after it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ticket {
    /// One above the highest ticket the claimant had heard of.
    pub lamport: u64,
    /// The claimant's origin, which breaks ties.
    pub origin: OriginId,
}

/// A claim's identity: its ticket and a random nonce.
///
/// Ordered by ticket; the nonce only keeps two claims apart if one node ever
/// reused a ticket (a database restored from a backup).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ClaimId {
    /// The claim's ticket.
    pub ticket: Ticket,
    /// Random, chosen by the claimant.
    pub nonce: u64,
}

impl ClaimId {
    /// The fencing token clients see (§7): `<lamport>-<nonce hex>-<origin>`.
    ///
    /// The origin goes last because it is the one part that may itself carry
    /// a `-`; it orders by ticket like the claim it names.
    pub fn token(&self) -> String {
        format!(
            "{}-{:016x}-{}",
            self.ticket.lamport, self.nonce, self.ticket.origin
        )
    }

    /// Reads a token back, or `None` if it is not one.
    pub fn parse_token(text: &str) -> Option<ClaimId> {
        let mut parts = text.trim().splitn(3, '-');
        let lamport = parts.next()?.parse().ok()?;
        let nonce = u64::from_str_radix(parts.next()?, 16).ok()?;
        let origin = parts.next()?.parse().ok()?;
        Some(ClaimId {
            ticket: Ticket { lamport, origin },
            nonce,
        })
    }
}

/// One claim on a lock (§3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// The claim's identity and order.
    pub id: ClaimId,
    /// The lease observers keep without a renewal, in milliseconds.
    pub ttl_ms: u32,
    /// Display only: who on the claimant's node asked for it.
    pub owner: String,
    /// Opaque to the protocol: an S3 lock key's body.
    pub payload: Vec<u8>,
    /// Expired claims this one took over from (§6).
    pub supersedes: Vec<ClaimId>,
}

impl Claim {
    /// Checks the bounds a claim arriving from a peer must keep.
    pub fn check(&self) -> Result<(), String> {
        if !(MIN_LOCK_TTL_MS..=MAX_LOCK_TTL_MS).contains(&self.ttl_ms) {
            return Err(format!("lease of {} ms is out of range", self.ttl_ms));
        }
        if self.owner.len() > MAX_LOCK_OWNER_BYTES {
            return Err("owner label too long".into());
        }
        if self.payload.len() > MAX_LOCK_PAYLOAD_BYTES {
            return Err("payload too large".into());
        }
        if self.supersedes.len() > MAX_LOCK_SUPERSEDES {
            return Err("too many superseded claims".into());
        }
        Ok(())
    }
}

/// What the reporting node knows of a claim (§3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ClaimState {
    /// Its lease ran out at the reporter without a renewal.
    Expired,
    /// Live, and not known to be held.
    Live,
    /// Held: the holder reporting itself, or a renewal received for it.
    Held,
}

/// A claim as one node reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The claim.
    pub claim: Claim,
    /// What the reporter knows of it.
    pub state: ClaimState,
    /// How long the reporter will keep it without a renewal.
    pub remaining_ms: u32,
}

/// Why a claim ended (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndReason {
    /// The holder released the lock.
    Released,
    /// A claimant lost the decision.
    Withdrawn,
    /// A holder lost a split-brain heal.
    Superseded,
    /// A writer of the space forced it.
    Broken,
}

impl fmt::Display for EndReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EndReason::Released => "released",
            EndReason::Withdrawn => "withdrawn",
            EndReason::Superseded => "superseded",
            EndReason::Broken => "broken",
        })
    }
}

/// A releaser's published head at release (§8): the next holder waits to
/// hold it before reporting the lock acquired.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Watermark {
    /// The releasing origin.
    pub origin: OriginId,
    /// The seq of its newest head when it released.
    pub seq: u64,
}

/// One frame of the lock exchange (§9.2).
///
/// postcard numbers variants by position, so the order is the wire; the ALPN
/// carries the version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockMessage {
    /// Record this claim and answer with what you know of the lock.
    Claim {
        /// The lock.
        lock: LockName,
        /// The claim.
        claim: Claim,
    },
    /// The holder still holds this claim; answered like a claim.
    ///
    /// Carries the whole claim, so a peer that never saw it — one that
    /// restarted — learns it from the renewal.
    Renew {
        /// The lock.
        lock: LockName,
        /// The held claim.
        claim: Claim,
    },
    /// This claim ended; answered with [`LockMessage::Ack`].
    End {
        /// The lock.
        lock: LockName,
        /// The claim that ended.
        id: ClaimId,
        /// Why.
        reason: EndReason,
        /// The releaser's head, on a release.
        watermark: Option<Watermark>,
    },
    /// Answer with what you know of the lock, recording nothing.
    Inspect {
        /// The lock.
        lock: LockName,
    },
    /// What the answering node knows of a lock.
    Answer {
        /// Every claim it holds live, expired, or held — its own included.
        reports: Vec<Report>,
        /// Claims it knows ended, and why.
        ended: Vec<(ClaimId, EndReason)>,
        /// The handoff watermarks it knows for the lock.
        watermarks: Vec<Watermark>,
    },
    /// An end was recorded.
    Ack,
    /// The request was refused: not a writer of the space, or over a limit.
    Refused {
        /// Why.
        reason: String,
    },
}

impl LockMessage {
    /// Checks the bounds a decoded frame must keep before it is acted on.
    pub fn check(&self) -> Result<(), String> {
        match self {
            LockMessage::Claim { lock, claim } | LockMessage::Renew { lock, claim } => {
                lock.check().map_err(|e| e.to_string())?;
                claim.check()
            }
            LockMessage::End { lock, .. } | LockMessage::Inspect { lock } => {
                lock.check().map_err(|e| e.to_string())
            }
            LockMessage::Answer {
                reports,
                ended,
                watermarks,
            } => {
                if reports.len() > MAX_LOCK_REPORTS
                    || ended.len() > MAX_LOCK_ENDED
                    || watermarks.len() > MAX_LOCK_WATERMARKS
                {
                    return Err("an answer over the lock limits".into());
                }
                reports.iter().try_for_each(|r| r.claim.check())
            }
            LockMessage::Ack | LockMessage::Refused { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_round_trips_and_keeps_a_dashed_origin_whole() {
        let id = ClaimId {
            ticket: Ticket {
                lamport: 42,
                origin: OriginId::named("build-box", "cluster.example").unwrap(),
            },
            nonce: 0xdead_beef,
        };
        assert_eq!(ClaimId::parse_token(&id.token()), Some(id));
        assert_eq!(ClaimId::parse_token("not a token"), None);
    }

    #[test]
    fn tickets_order_by_lamport_before_origin() {
        let a = OriginId::named("a", "x.example").unwrap();
        let z = OriginId::named("z", "x.example").unwrap();
        let low = Ticket {
            lamport: 1,
            origin: z,
        };
        let high = Ticket {
            lamport: 2,
            origin: a,
        };
        assert!(low < high);
    }

    #[test]
    fn lock_names_are_space_and_name() {
        let lock = LockName::parse("infra/env/prod/state.tflock").unwrap();
        assert_eq!(lock.space, "infra");
        assert_eq!(lock.name, "env/prod/state.tflock");
        assert_eq!(lock.to_string(), "infra/env/prod/state.tflock");
        assert_eq!(LockName::parse("nospace"), Err(LockNameError::Shape));
        assert_eq!(LockName::parse("infra/"), Err(LockNameError::Name));
        assert!(LockName::parse(&format!("infra/{}", "x".repeat(513))).is_err());
    }
}
