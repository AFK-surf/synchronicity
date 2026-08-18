//! iroh endpoint, the two ALPN protocols, and DNSSEC membership.
//!
//! `sync/mpt/1` carries head gossip and trie fetches (§5); `sync/blob/1`
//! carries verified bao slices (§6.4). Both are gated on the bindings table, so
//! a device key with no live binding is closed out immediately after the QUIC
//! handshake (§3.2).
#![deny(missing_docs)]

pub mod blob;
mod blocking;
pub mod chain;
pub mod dns;
pub mod endpoint;
pub mod error;
pub mod frame;
pub mod mpt;
pub mod rekor;
mod serve;
/// Test machinery — a simulated signed zone, transparency log and TUF
/// repository. Behind the non-default `sim` feature: it is 1300 lines with
/// no place in a shipped binary, and no business being part of this crate's
/// stable surface.
#[cfg(feature = "sim")]
#[doc(hidden)]
pub mod sim;
#[cfg(test)]
mod testing;
pub mod tuf;
pub mod x509;
pub mod zonecert;

pub use blob::{BlobClient, BlobProtocol, Proof, ProofOutcome, Slice};
pub use dns::{
    DialHint, DnssecResolver, MemberRecord, MemberResolver, MemberSet, RecordError, RekorPolicy,
    ResolverOptions,
};
pub use endpoint::{Net, NetOptions, DIAL_TIMEOUT, REQUEST_TIMEOUT};
pub use error::{NetError, Result};
pub use mpt::{
    HeadExchange, HeadSink, MptClient, MptProtocol, NodesResponse, OfferOutcome, ValuesResponse,
};
pub use rekor::{ProofError, RekorProof};
pub use tuf::{PinState, TufError, TufMetadata};
