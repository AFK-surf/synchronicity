//! The `sync/mpt/1` ALPN: head gossip, trie node and value fetch, provider
//! hints (§5.1).
//!
//! Each request occupies one bidirectional stream and the responder dispatches
//! on its first frame. The head-gossip stream is the one exception: it carries
//! a fixed five-message push-pull exchange, so one round trip both offers what
//! we have and pulls what we lack.

use std::sync::Arc;

use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use synch_core::{
    now_ns, BlobAd, Hash, HeadSummary, MptMessage, OriginId, SignedHead, MAX_BATCH, PROTO_VERSION,
};
use synch_mpt::NodeStore;
use synch_store::{Slot, Store};

use crate::{
    error::NetError,
    frame::{read_frame, write_frame},
    reconcile::Syncer,
};

/// The `sync/mpt/1` protocol handler.
#[derive(Debug, Clone)]
pub struct MptProtocol {
    syncer: Syncer,
}

impl MptProtocol {
    /// Builds a handler over a store.
    pub fn new(store: Arc<Store>) -> Self {
        MptProtocol {
            syncer: Syncer::new(store),
        }
    }

    fn store(&self) -> &Arc<Store> {
        self.syncer.store()
    }
}

impl ProtocolHandler for MptProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        let now = now_ns();
        // Enforcement at connection-accept time (§3.2): connections from device
        // keys with no live binding are closed immediately after the handshake.
        match self.store().is_trusted_key(&remote, now) {
            Ok(true) => {}
            _ => {
                tracing::debug!(peer = %remote.fmt_short(), "refusing connection: no live binding");
                connection.close(0u32.into(), b"untrusted");
                return Err(AcceptError::from_err(std::io::Error::other(
                    "peer has no live binding",
                )));
            }
        }
        let _ = self.store().record_peer_seen(&remote, None, now);

        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            if let Err(e) = self.handle_stream(&mut send, &mut recv).await {
                tracing::debug!(peer = %remote.fmt_short(), error = %e, "mpt stream ended");
                let _ = write_frame(
                    &mut send,
                    &MptMessage::Error {
                        reason: e.to_string(),
                    },
                )
                .await;
            }
            let _ = send.finish();
        }
        Ok(())
    }
}

impl MptProtocol {
    async fn handle_stream(
        &self,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Result<(), NetError> {
        let request: MptMessage = read_frame(recv).await?;
        match request {
            MptMessage::Hello { proto, heads: _ } => {
                if proto != PROTO_VERSION {
                    return Err(NetError::Unexpected(format!(
                        "unsupported protocol version {proto}"
                    )));
                }
                let ours = self.syncer.local_summaries()?;
                write_frame(
                    send,
                    &MptMessage::Hello {
                        proto: PROTO_VERSION,
                        heads: ours,
                    },
                )
                .await?;

                // The peer pushes what it has that we lack, then asks for what
                // we have that it lacks.
                match read_frame::<MptMessage>(recv).await? {
                    MptMessage::Heads { heads } => {
                        for head in heads {
                            let _ = self.syncer.offer_head(&head, now_ns())?;
                        }
                    }
                    other => return Err(unexpected("Heads", &other)),
                }
                match read_frame::<MptMessage>(recv).await? {
                    MptMessage::HeadsWant { origins } => {
                        let heads = self.heads_for(&origins)?;
                        write_frame(send, &MptMessage::Heads { heads }).await?;
                    }
                    other => return Err(unexpected("HeadsWant", &other)),
                }
                Ok(())
            }
            MptMessage::HeadPush { head } => {
                let outcome = self.syncer.offer_head(&head, now_ns())?;
                tracing::debug!(origin = %head.origin, ?outcome, "head pushed to us");
                // The ack tells the pusher we processed it; an empty Heads is
                // the smallest well-typed acknowledgement in the schema.
                write_frame(send, &MptMessage::Heads { heads: Vec::new() }).await?;
                Ok(())
            }
            MptMessage::GetNodes { hashes } => {
                check_batch(hashes.len())?;
                let mut nodes = Vec::new();
                let mut missing = Vec::new();
                for hash in hashes {
                    match self.store().get_node(&hash)? {
                        Some(data) => nodes.push((hash, data)),
                        None => missing.push(hash),
                    }
                }
                write_frame(send, &MptMessage::Nodes { nodes, missing }).await?;
                Ok(())
            }
            MptMessage::GetValues { hashes } => {
                check_batch(hashes.len())?;
                let mut values = Vec::new();
                let mut missing = Vec::new();
                for hash in hashes {
                    match self.store().get_value(&hash)? {
                        Some(data) => values.push((hash, data)),
                        None => missing.push(hash),
                    }
                }
                write_frame(send, &MptMessage::Values { values, missing }).await?;
                Ok(())
            }
            MptMessage::FindProviders { object_root } => {
                // Hints are unverified — content is hash-verified regardless,
                // so a wrong hint only wastes a dial (§5.1).
                let ads = self.store().providers(&object_root)?;
                write_frame(send, &MptMessage::Providers { ads }).await?;
                Ok(())
            }
            other => Err(unexpected("a request", &other)),
        }
    }

    fn heads_for(&self, origins: &[OriginId]) -> Result<Vec<SignedHead>, NetError> {
        let mut out = Vec::new();
        for origin in origins {
            // Only complete heads are handed out: we advertise what we can
            // actually back with a servable trie.
            if let Some(head) = self.store().head(origin, Slot::Complete)? {
                out.push(head.head);
            }
        }
        Ok(out)
    }
}

fn check_batch(len: usize) -> Result<(), NetError> {
    if len > MAX_BATCH {
        return Err(NetError::Unexpected(format!(
            "batch of {len} exceeds the {MAX_BATCH} limit"
        )));
    }
    Ok(())
}

fn unexpected(wanted: &str, got: &MptMessage) -> NetError {
    NetError::Unexpected(format!("expected {wanted}, got {}", message_name(got)))
}

fn message_name(msg: &MptMessage) -> &'static str {
    match msg {
        MptMessage::Hello { .. } => "Hello",
        MptMessage::HeadsWant { .. } => "HeadsWant",
        MptMessage::Heads { .. } => "Heads",
        MptMessage::HeadPush { .. } => "HeadPush",
        MptMessage::GetNodes { .. } => "GetNodes",
        MptMessage::Nodes { .. } => "Nodes",
        MptMessage::GetValues { .. } => "GetValues",
        MptMessage::Values { .. } => "Values",
        MptMessage::FindProviders { .. } => "FindProviders",
        MptMessage::Providers { .. } => "Providers",
        MptMessage::Error { .. } => "Error",
    }
}

/// A `Nodes` response.
#[derive(Debug, Clone, Default)]
pub struct NodesResponse {
    /// The served nodes.
    pub nodes: Vec<(Hash, Vec<u8>)>,
    /// The hashes the responder did not have.
    pub missing: Vec<Hash>,
}

/// A `Values` response.
#[derive(Debug, Clone, Default)]
pub struct ValuesResponse {
    /// The served values.
    pub values: Vec<(Hash, Vec<u8>)>,
    /// The hashes the responder did not have.
    pub missing: Vec<Hash>,
}

/// The outcome of a head-gossip exchange.
#[derive(Debug, Clone, Default)]
pub struct HeadExchange {
    /// The peer's advertised summaries.
    pub summaries: Vec<HeadSummary>,
    /// How many of our heads we pushed.
    pub pushed: usize,
    /// The signed heads the peer sent in response to our want list.
    pub received: Vec<SignedHead>,
}

/// A client for the `sync/mpt/1` ALPN, over one established connection.
#[derive(Debug, Clone)]
pub struct MptClient {
    connection: Connection,
}

impl MptClient {
    /// Wraps an established `sync/mpt/1` connection.
    pub fn new(connection: Connection) -> Self {
        MptClient { connection }
    }

    /// The underlying connection.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// The peer's device key, cryptographically established by the handshake.
    pub fn remote_id(&self) -> synch_core::NodeId {
        self.connection.remote_id()
    }

    /// Runs the five-message head-gossip exchange.
    ///
    /// `decide` is handed the peer's summaries and returns `(heads to push,
    /// origins to pull)`.
    pub async fn head_exchange<F>(
        &self,
        ours: Vec<HeadSummary>,
        decide: F,
    ) -> Result<HeadExchange, NetError>
    where
        F: FnOnce(&[HeadSummary]) -> (Vec<SignedHead>, Vec<OriginId>),
    {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_frame(
            &mut send,
            &MptMessage::Hello {
                proto: PROTO_VERSION,
                heads: ours,
            },
        )
        .await?;

        let summaries = match read_frame::<MptMessage>(&mut recv).await? {
            MptMessage::Hello { proto, heads } => {
                if proto != PROTO_VERSION {
                    return Err(NetError::Unexpected(format!(
                        "unsupported protocol version {proto}"
                    )));
                }
                heads
            }
            other => return Err(unexpected("Hello", &other)),
        };

        let (push, want) = decide(&summaries);
        let pushed = push.len();
        write_frame(&mut send, &MptMessage::Heads { heads: push }).await?;
        write_frame(&mut send, &MptMessage::HeadsWant { origins: want }).await?;

        let received = match read_frame::<MptMessage>(&mut recv).await? {
            MptMessage::Heads { heads } => heads,
            MptMessage::Error { reason } => return Err(NetError::Unexpected(reason)),
            other => return Err(unexpected("Heads", &other)),
        };
        let _ = send.finish();
        Ok(HeadExchange {
            summaries,
            pushed,
            received,
        })
    }

    /// Pushes a head reactively (§5.3).
    pub async fn push_head(&self, head: &SignedHead) -> Result<(), NetError> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_frame(&mut send, &MptMessage::HeadPush { head: head.clone() }).await?;
        let _ = send.finish();
        match read_frame::<MptMessage>(&mut recv).await? {
            MptMessage::Heads { .. } => Ok(()),
            MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
            other => Err(unexpected("an acknowledgement", &other)),
        }
    }

    /// Fetches trie nodes by hash.
    pub async fn get_nodes(&self, hashes: &[Hash]) -> Result<NodesResponse, NetError> {
        let batch: Vec<Hash> = hashes.iter().take(MAX_BATCH).copied().collect();
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_frame(&mut send, &MptMessage::GetNodes { hashes: batch }).await?;
        let _ = send.finish();
        match read_frame::<MptMessage>(&mut recv).await? {
            MptMessage::Nodes { nodes, missing } => Ok(NodesResponse { nodes, missing }),
            MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
            other => Err(unexpected("Nodes", &other)),
        }
    }

    /// Fetches out-of-line trie values by hash.
    pub async fn get_values(&self, hashes: &[Hash]) -> Result<ValuesResponse, NetError> {
        let batch: Vec<Hash> = hashes.iter().take(MAX_BATCH).copied().collect();
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_frame(&mut send, &MptMessage::GetValues { hashes: batch }).await?;
        let _ = send.finish();
        match read_frame::<MptMessage>(&mut recv).await? {
            MptMessage::Values { values, missing } => Ok(ValuesResponse { values, missing }),
            MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
            other => Err(unexpected("Values", &other)),
        }
    }

    /// Asks a peer who advertises an object, for bootstrapping a cold cache
    /// that holds no `b:` records for it yet (§6.3).
    pub async fn find_providers(
        &self,
        object_root: Hash,
    ) -> Result<Vec<(OriginId, BlobAd)>, NetError> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_frame(&mut send, &MptMessage::FindProviders { object_root }).await?;
        let _ = send.finish();
        match read_frame::<MptMessage>(&mut recv).await? {
            MptMessage::Providers { ads } => Ok(ads),
            MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
            other => Err(unexpected("Providers", &other)),
        }
    }
}
