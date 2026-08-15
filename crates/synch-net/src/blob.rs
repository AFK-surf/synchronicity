//! The `sync/blob/1` ALPN: verified bao slice transfer (§6.4).
//!
//! The blob ALPN carries nothing but `GetSlice`/`SliceEnd` and the slice bytes
//! themselves. `SliceEnd` reports what the provider actually had, which is how
//! the fetcher learns exact availability — span summaries in `BlobAd` are hints,
//! not promises.

use std::sync::Arc;

use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use synch_core::{now_ns, BlobMessage, ChunkRanges, Hash, MAX_RANGES, MAX_SLICE_GROUPS};
use synch_store::Store;

use crate::{
    error::NetError,
    frame::{read_bytes, read_frame, write_bytes, write_frame},
};

/// How many consecutive empty windows a provider may answer with before a
/// fetch gives up on it and lets the caller try someone else.
const MAX_BARREN_WINDOWS: u32 = 4;

/// The `sync/blob/1` protocol handler.
#[derive(Debug, Clone)]
pub struct BlobProtocol {
    store: Arc<Store>,
    on_unknown_key: Option<Arc<tokio::sync::Notify>>,
}

impl BlobProtocol {
    /// Builds a handler over a store.
    pub fn new(store: Arc<Store>) -> Self {
        BlobProtocol {
            store,
            on_unknown_key: None,
        }
    }

    /// Rings `wake` whenever a connection is refused for an unknown key (§3.4).
    pub fn on_unknown_key(mut self, wake: Option<Arc<tokio::sync::Notify>>) -> Self {
        self.on_unknown_key = wake;
        self
    }
}

impl ProtocolHandler for BlobProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        match self.store.is_trusted_key(&remote, now_ns()) {
            Ok(true) => {}
            _ => {
                if let Some(wake) = &self.on_unknown_key {
                    wake.notify_waiters();
                }
                connection.close(0u32.into(), b"untrusted");
                return Err(AcceptError::from_err(std::io::Error::other(
                    "peer has no live binding",
                )));
            }
        }

        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            // §3.2 enforcement is per message, not just per connection: a
            // binding revoked or expired mid-connection must cut off further
            // requests, not linger for the life of the QUIC session.
            if !matches!(self.store.is_trusted_key(&remote, now_ns()), Ok(true)) {
                tracing::debug!(peer = %remote.fmt_short(), "closing connection: binding lapsed");
                connection.close(0u32.into(), b"untrusted");
                break;
            }
            if let Err(e) = self.handle_stream(&mut send, &mut recv).await {
                tracing::debug!(peer = %remote.fmt_short(), error = %e, "blob stream ended");
            }
            let _ = send.finish();
        }
        Ok(())
    }
}

impl BlobProtocol {
    async fn handle_stream(
        &self,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Result<(), NetError> {
        match read_frame::<BlobMessage>(recv).await? {
            BlobMessage::GetSlice { root, ranges } => {
                // The range set arrives straight off the wire, unnormalized and
                // unbounded: the set operations below it are quadratic in the
                // number of ranges, so a request made of a million singleton
                // ranges costs the provider far more than it costs the asker
                // (§12). Bound it, and normalize before anything else reads it.
                if ranges.range_count() > MAX_RANGES {
                    return Err(NetError::Unexpected(format!(
                        "slice request of {} ranges exceeds the {MAX_RANGES} limit",
                        ranges.range_count()
                    )));
                }
                let ranges = ChunkRanges::from_ranges(ranges.ranges.iter().copied());
                // A provider serves the intersection of what was asked for and
                // what it verifiably holds. Encoding validates the local copy
                // against the root, so a corrupted payload fails here rather
                // than being served.
                //
                // It reads the payload and its outboard off disk to do it, and
                // a window is up to `MAX_SLICE_GROUPS` — so it runs on the
                // blocking pool. Serving one peer's large object must not stop
                // this node's connection tasks from polling (§10).
                let store = self.store.clone();
                let (encoded, served) =
                    crate::blocking::offload(move || match store.encode_slice(&root, &ranges) {
                        Ok(pair) => Ok(pair),
                        Err(synch_store::StoreError::MissingBlob(_)) => {
                            Ok((Vec::new(), ChunkRanges::empty()))
                        }
                        Err(e) => Err(e.into()),
                    })
                    .await?;
                write_bytes(send, &encoded).await?;
                write_frame(send, &BlobMessage::SliceEnd { served }).await?;
                Ok(())
            }
            BlobMessage::SliceEnd { .. } => Err(NetError::Unexpected(
                "SliceEnd is a response, not a request".into(),
            )),
        }
    }
}

/// A client for the `sync/blob/1` ALPN, over one established connection.
#[derive(Debug, Clone)]
pub struct BlobClient {
    connection: Connection,
}

/// A received slice, together with what the provider actually served.
#[derive(Debug, Clone)]
pub struct Slice {
    /// The bao-encoded slice bytes.
    pub encoded: Vec<u8>,
    /// The ranges the provider had, which is what the encoding covers.
    pub served: ChunkRanges,
}

impl BlobClient {
    /// Wraps an established `sync/blob/1` connection.
    pub fn new(connection: Connection) -> Self {
        BlobClient { connection }
    }

    /// The peer's device key.
    pub fn remote_id(&self) -> synch_core::NodeId {
        self.connection.remote_id()
    }

    /// Requests a verified slice.
    pub async fn get_slice(&self, root: Hash, ranges: &ChunkRanges) -> Result<Slice, NetError> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_frame(
            &mut send,
            &BlobMessage::GetSlice {
                root,
                ranges: ranges.clone(),
            },
        )
        .await?;
        let _ = send.finish();

        let encoded = read_bytes(&mut recv).await?;
        let served = match read_frame::<BlobMessage>(&mut recv).await? {
            BlobMessage::SliceEnd { served } => served,
            BlobMessage::GetSlice { .. } => {
                return Err(NetError::Unexpected("expected SliceEnd".into()))
            }
        };
        Ok(Slice { encoded, served })
    }

    /// Requests a slice and commits it to the local CAS, verifying every group
    /// against the object root before anything is stored.
    ///
    /// A provider serves at most [`MAX_SLICE_GROUPS`] groups per exchange, so
    /// anything larger is walked one window at a time until the request is
    /// covered — which is what lets an object bigger than one frame transfer at
    /// all. Each window is committed as it arrives, so an interrupted fetch
    /// keeps everything it verified.
    pub async fn fetch_into(
        &self,
        store: &Arc<Store>,
        root: Hash,
        size: u64,
        ranges: &ChunkRanges,
    ) -> Result<ChunkRanges, NetError> {
        let mut remaining = ChunkRanges::from_ranges(ranges.ranges.iter().copied());
        let mut got = ChunkRanges::empty();
        let mut barren = 0u32;
        while !remaining.is_empty() {
            let window = remaining.take(MAX_SLICE_GROUPS);
            let slice = self.get_slice(root, &window).await?;
            // The window is retired either way: an empty answer is the
            // provider telling us its advertised spans overstate what it has,
            // and asking again would only repeat the round trip.
            remaining = remaining.difference(&window);
            if slice.served.is_empty() {
                barren += 1;
                if barren >= MAX_BARREN_WINDOWS {
                    // A provider that claims an object and serves none of it
                    // must not be able to hold a fetch in an unbounded walk
                    // across the whole thing; the caller has other candidates.
                    break;
                }
                continue;
            }
            barren = 0;
            // Committing a window decodes it against the object root and
            // writes both the sparse payload and its outboard, then fsyncs
            // them before the bitmap advances — the heaviest disk work a fetch
            // does, and it happens once per window. Off the runtime it goes.
            let store = store.clone();
            let served = slice.served.clone();
            let encoded = slice.encoded;
            let written = crate::blocking::offload(move || {
                Ok(store.write_slice(&root, size, &served, &encoded, now_ns())?)
            })
            .await?;
            got = got.union(&written);
        }
        Ok(got)
    }
}
