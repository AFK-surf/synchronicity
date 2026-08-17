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
    now_ns, BlobAd, Hash, HeadSummary, MptMessage, NodeId, OriginId, SignedHead, MAX_BATCH,
    PROTO_VERSION,
};
use synch_mpt::NodeStore;
use synch_store::{Slot, Store};

use crate::{
    error::NetError,
    frame::{read_frame, write_frame},
    reconcile::Syncer,
};

/// How often a live session refreshes the sighting it recorded at accept.
const PEER_SEEN_REFRESH: std::time::Duration = std::time::Duration::from_secs(60);

/// The `sync/mpt/1` protocol handler.
#[derive(Debug, Clone)]
pub struct MptProtocol {
    syncer: Syncer,
    on_unknown_key: Option<Arc<tokio::sync::Notify>>,
}

impl MptProtocol {
    /// Builds a handler over a store.
    pub fn new(store: Arc<Store>) -> Self {
        MptProtocol {
            syncer: Syncer::new(store),
            on_unknown_key: None,
        }
    }

    /// Rings `wake` whenever a connection is refused for an unknown key.
    ///
    /// A peer whose key this node has not resolved yet — the far side of a key
    /// rotation, typically — arrives exactly this way, and §3.4 makes that
    /// refusal a trigger for an immediate DNS re-resolution.
    pub fn on_unknown_key(mut self, wake: Option<Arc<tokio::sync::Notify>>) -> Self {
        self.on_unknown_key = wake;
        self
    }

    /// Rings `wake` whenever a head this session accepts flips to complete —
    /// the serve side's half of the change bell (`Syncer::on_change`).
    pub fn on_change(mut self, wake: Option<Arc<tokio::sync::Notify>>) -> Self {
        self.syncer = self.syncer.on_change(wake);
        self
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
                if let Some(wake) = &self.on_unknown_key {
                    wake.notify_waiters();
                }
                connection.close(0u32.into(), b"untrusted");
                return Err(AcceptError::from_err(std::io::Error::other(
                    "peer has no live binding",
                )));
            }
        }
        let _ = self.store().record_peer_seen(&remote, None, now);

        // A session outlives the request that opened it, so "last seen" cannot
        // be recorded only at accept: a peer that has been syncing steadily
        // over one connection for an hour would read as an hour absent in
        // `synch peers`. Refreshed as requests arrive, but at most once an
        // interval — the sighting is for an operator's eyes, not worth a write
        // per stream.
        let mut refreshed = std::time::Instant::now();
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            // §3.2 enforcement is per message, not just per connection: a
            // binding revoked or expired mid-connection must cut off further
            // requests, not linger for the life of the QUIC session.
            if !matches!(self.store().is_trusted_key(&remote, now_ns()), Ok(true)) {
                tracing::debug!(peer = %remote.fmt_short(), "closing connection: binding lapsed");
                connection.close(0u32.into(), b"untrusted");
                break;
            }
            if refreshed.elapsed() >= PEER_SEEN_REFRESH {
                let _ = self.store().record_peer_seen(&remote, None, now_ns());
                refreshed = std::time::Instant::now();
            }
            if let Err(e) = self.handle_stream(remote, &mut send, &mut recv).await {
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
        peer: NodeId,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Result<(), NetError> {
        let request: MptMessage = read_frame(recv).await?;
        match request {
            MptMessage::Hello { proto, heads } => {
                if proto != PROTO_VERSION {
                    return Err(NetError::Unexpected(format!(
                        "unsupported protocol version {proto}"
                    )));
                }
                // A dialing peer's summaries are as good an observation as the
                // ones we collect by dialing out, and a node in recovery is
                // more likely to be called than to be calling (§3.4).
                //
                // Summarizing means asking the trie whether we hold each root
                // whole — a walk on the first ask for a root, memoized after —
                // so the pair runs on the blocking pool (§5.1).
                let syncer = self.syncer.clone();
                let ours = crate::blocking::offload(move || {
                    syncer.observe_summaries_from(Some(peer), &heads, now_ns())?;
                    syncer.local_summaries()
                })
                .await?;
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
                        // Each offer verifies a signature, records history, and
                        // may promote the head — which walks the trie and
                        // re-materializes the changed leaves in one
                        // transaction (§5.2).
                        let syncer = self.syncer.clone();
                        crate::blocking::offload(move || {
                            for head in heads {
                                let _ = syncer.offer_head(&head, now_ns())?;
                            }
                            Ok(())
                        })
                        .await?;
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
                let syncer = self.syncer.clone();
                let pushed = head.clone();
                let outcome =
                    crate::blocking::offload(move || syncer.offer_head(&pushed, now_ns())).await?;
                tracing::debug!(origin = %head.origin, ?outcome, "head pushed to us");
                // The ack tells the pusher we processed it; an empty Heads is
                // the smallest well-typed acknowledgement in the schema.
                write_frame(send, &MptMessage::Heads { heads: Vec::new() }).await?;
                Ok(())
            }
            // Both batch reads run on the blocking pool: `MAX_BATCH` row reads
            // out of SQLite is a bounded amount of work, but not a small one,
            // and a cold store answers them from disk.
            MptMessage::GetNodes { hashes } => {
                check_batch(hashes.len())?;
                let store = self.store().clone();
                let (nodes, missing) = crate::blocking::offload(move || {
                    let mut nodes = Vec::new();
                    let mut missing = Vec::new();
                    for hash in hashes {
                        match store.get_node(&hash)? {
                            Some(data) => nodes.push((hash, data)),
                            None => missing.push(hash),
                        }
                    }
                    Ok((nodes, missing))
                })
                .await?;
                write_frame(send, &MptMessage::Nodes { nodes, missing }).await?;
                Ok(())
            }
            MptMessage::GetValues { hashes } => {
                check_batch(hashes.len())?;
                let store = self.store().clone();
                let (values, missing) = crate::blocking::offload(move || {
                    let mut values = Vec::new();
                    let mut missing = Vec::new();
                    for hash in hashes {
                        match store.get_value(&hash)? {
                            Some(data) => values.push((hash, data)),
                            None => missing.push(hash),
                        }
                    }
                    Ok((values, missing))
                })
                .await?;
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
            MptMessage::GetBindings { origin } => {
                // What this peer currently holds bound, live keys only — a
                // lapsed binding is exactly what the asker wants to know is
                // gone (§3.4). Informational within the trusted cluster: the
                // caller is already an authorized member (§3.2, §12).
                let keys = self.store().keys_for_origin(&origin, now_ns())?;
                write_frame(send, &MptMessage::BindingsFor { origin, keys }).await?;
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
        MptMessage::GetBindings { .. } => "GetBindings",
        MptMessage::BindingsFor { .. } => "BindingsFor",
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

    /// Asks the peer which device keys it currently holds bound for an origin
    /// (§5.1).
    ///
    /// This is how `synch key ls` answers "have my peers picked up the new
    /// binding yet?" — the judgement §3.4 says a rotation's switch-over needs
    /// and that a node cannot make from its own view of DNS.
    pub async fn get_bindings(&self, origin: &OriginId) -> Result<Vec<NodeId>, NetError> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_frame(
            &mut send,
            &MptMessage::GetBindings {
                origin: origin.clone(),
            },
        )
        .await?;
        let _ = send.finish();
        match read_frame::<MptMessage>(&mut recv).await? {
            MptMessage::BindingsFor {
                origin: answered,
                keys,
            } if &answered == origin => Ok(keys),
            MptMessage::BindingsFor {
                origin: answered, ..
            } => Err(NetError::Unexpected(format!(
                "asked about {origin}, answered about {answered}"
            ))),
            MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
            other => Err(unexpected("BindingsFor", &other)),
        }
    }
}
