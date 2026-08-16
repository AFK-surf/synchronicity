//! iroh endpoint, the two ALPN protocols, reconciliation, and DNSSEC membership.
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
pub mod reconcile;
pub mod rekor;
/// Test support: a signed zone, a transparency log and a TUF repository a
/// client cannot tell from the real things.
///
/// Behind the `sim` feature, which nothing that ships turns on. It is a
/// thousand lines of fixture machinery with no place in a production call
/// path, and leaving it ungated put every one of its types in this library's
/// API surface — the suites in this repo enable it through their
/// dev-dependencies, which is the whole audience it has.
#[cfg(feature = "sim")]
#[doc(hidden)]
pub mod sim;
pub mod tuf;
pub mod x509;
pub mod zonecert;

pub use blob::{BlobClient, BlobProtocol, Slice};
pub use dns::{
    DnssecResolver, MemberRecord, MemberResolver, MemberSet, RecordError, RekorPolicy,
    ResolverOptions,
};
pub use endpoint::{Net, NetOptions};
pub use error::{NetError, Result};
pub use mpt::{HeadExchange, MptClient, MptProtocol, NodesResponse, ValuesResponse};
pub use reconcile::{FetchOutcome, HeadOutcome, SyncReport, Syncer};
pub use rekor::{ProofError, RekorProof};
pub use tuf::{PinState, TufBundle, TufError};
