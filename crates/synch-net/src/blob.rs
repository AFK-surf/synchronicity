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
use synch_core::{now_ns, BlobMessage, ChunkRanges, Hash};
use synch_store::Store;

use crate::{
    error::NetError,
    frame::{read_bytes, read_frame, write_bytes, write_frame},
};

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
                // A provider serves the intersection of what was asked for and
                // what it verifiably holds. Encoding validates the local copy
                // against the root, so a corrupted payload fails here rather
                // than being served.
                let (encoded, served) = match self.store.encode_slice(&root, &ranges) {
                    Ok(pair) => pair,
                    Err(synch_store::StoreError::MissingBlob(_)) => {
                        (Vec::new(), ChunkRanges::empty())
                    }
                    Err(e) => return Err(e.into()),
                };
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
    pub async fn fetch_into(
        &self,
        store: &Store,
        root: Hash,
        size: u64,
        ranges: &ChunkRanges,
    ) -> Result<ChunkRanges, NetError> {
        let slice = self.get_slice(root, ranges).await?;
        if slice.served.is_empty() {
            return Ok(ChunkRanges::empty());
        }
        Ok(store.write_slice(&root, size, &slice.served, &slice.encoded, now_ns())?)
    }
}
