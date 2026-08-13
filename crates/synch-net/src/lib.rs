//! iroh endpoint, the two ALPN protocols, reconciliation, and DNSSEC membership.
//!
//! `sync/mpt/1` carries head gossip and trie fetches (§5); `sync/blob/1`
//! carries verified bao slices (§6.4). Both are gated on the bindings table, so
//! a device key with no live binding is closed out immediately after the QUIC
//! handshake (§3.2).
#![deny(missing_docs)]

pub mod blob;
pub mod dns;
pub mod endpoint;
pub mod error;
pub mod frame;
pub mod mpt;
pub mod reconcile;

pub use blob::{BlobClient, BlobProtocol, Slice};
pub use dns::{
    DnssecResolver, MemberRecord, MemberResolver, MemberSet, RecordError, ResolverOptions,
};
pub use endpoint::{Net, NetOptions};
pub use error::{NetError, Result};
pub use mpt::{HeadExchange, MptClient, MptProtocol, NodesResponse, ValuesResponse};
pub use reconcile::{FetchOutcome, HeadOutcome, SyncReport, Syncer};
