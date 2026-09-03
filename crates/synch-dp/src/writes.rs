//! The write tunnel: the control plane's file writes, taken by the hosted
//! node (`docs/CLOUD-WRITES.md` §5, §6).
//!
//! A second tunnel beside the browse tunnel the engine opens, and deliberately
//! not a fifth version of it. The browse tunnel's read-only property is a fact
//! about `synch_engine::cloud::frame` — no write opcode decodes — and this
//! module is where the write frames live instead: in the data plane, which the
//! daemon binary never links, so there is no code in a customer's daemon that
//! could turn a `put` frame into a write (§5.1).
//!
//! What crosses it is the mirror image of a download. The control plane sends
//! `put`, then content frames *downward* under credit, then `commit`; the node
//! stages the bytes through the engine's one tree-write seam
//! ([`synch_engine::TreeWriter`]) and publishes them as `cloud-1`'s own
//! version of the path. A `delete` withdraws `cloud-1`'s version and never a
//! customer's (§6.6).

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use synch_core::{EntryKind, Hash, OriginId};
use synch_engine::{EngineError, HostError, Node, PutCondition, SocketWriter};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

/// The newest write-tunnel protocol version this build speaks.
///
/// Its own counter, unrelated to the browse tunnel's: the two share a
/// handshake shape and nothing else.
pub const PROTOCOL_VERSION: u32 = 1;

/// The oldest settled version this build serves under.
const MIN_PROTOCOL_VERSION: u32 = 1;

/// The path the attach connection is made against, appended to each URL the
/// zone's control-plane record names.
const ATTACH_PATH: &str = "/dp/v1/attach";

/// The environment override that replaces discovery — the browse tunnel's own
/// test hook, honoured here for the same tests and with the same caveat: it
/// is process-global, so it speaks for every tenant on the pod.
const URL_ENV: &str = "SYNCH_CLOUD_URL";

/// The largest payload one content frame carries, matching the browse tunnel.
pub const MAX_CHUNK: usize = 64 * 1024;

/// The fixed header every content frame opens with: request id then
/// sequence, both big-endian `u32`.
const CHUNK_HEADER_LEN: usize = 8;

/// How many content frames the control plane may send ahead of the credit
/// this node returns for each one it has staged.
pub const CREDIT_WINDOW: u32 = 4;

/// The most writes and deletes one session may have in flight at once.
const MAX_INFLIGHT: usize = 64;

/// The largest text frame this node will read from the control plane. Content
/// frames are bounded separately by the chunk ceiling.
const MAX_DOWN_FRAME: usize = MAX_CHUNK + CHUNK_HEADER_LEN + 1024;

/// How long an open write may go without a frame or a commit before the node
/// abandons it and gives its staging back (`docs/CLOUD-WRITES.md` §5.4).
///
/// The control plane cancels a write it gives up on, but a control plane that
/// died mid-upload cancels nothing, and a reservation nobody ends is a
/// staging budget that only ever shrinks.
const WRITE_IDLE: Duration = Duration::from_secs(60);

const HEARTBEAT: Duration = Duration::from_secs(30);
const HEARTBEAT_MISSES: u32 = 2;
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_AHEAD: usize = 8;
const MIN_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const MIN_REDISCOVERY: Duration = Duration::from_secs(60);
const MAX_REDISCOVERY: Duration = Duration::from_secs(3600);

// -- the frames ---------------------------------------------------------------

/// What the control plane sends down the write tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum Down {
    /// The 32-byte nonce, hex, that the attach proof must cover.
    Challenge {
        /// The nonce, hex-encoded.
        nonce: String,
    },
    /// The proof was accepted and the session is live.
    Attached {
        /// The control plane's id for this session, for logs on both sides.
        session: String,
        /// The protocol version the control plane settled on.
        v: u32,
    },
    /// Open a write of exactly `size` bytes.
    Put {
        /// The request id.
        id: u32,
        /// The space.
        space: String,
        /// The path within the space.
        path: String,
        /// How many bytes the content frames will carry, in total.
        size: u64,
        /// Pin the condition to one origin's version; unset means `newest`.
        #[serde(default)]
        from: Option<String>,
        /// Commit only if the selected version has this content root, hex.
        #[serde(default)]
        if_match: Option<String>,
        /// Commit only if the path has no live version at all.
        #[serde(default)]
        if_none_match: bool,
    },
    /// Every byte of a write was sent; evaluate the condition and publish.
    Commit {
        /// The request id.
        id: u32,
    },
    /// Publish this node's tombstone for a path.
    Delete {
        /// The request id.
        id: u32,
        /// The space.
        space: String,
        /// The path within the space.
        path: String,
        /// Pin the condition to one origin's version; unset means `newest`.
        #[serde(default)]
        from: Option<String>,
        /// Withdraw only if the selected version has this content root, hex.
        #[serde(default)]
        if_match: Option<String>,
    },
    /// Abandon one write: the staging is dropped and nothing is published.
    Cancel {
        /// The request id.
        id: u32,
    },
    /// Liveness, answered with [`Up::Pong`].
    Ping,
    /// The answer to an [`Up::Ping`].
    Pong,
    /// A coded refusal, of one request or of the connection.
    Err {
        /// The request it refuses, or unset for the connection itself.
        #[serde(default)]
        id: Option<u32>,
        /// The stable code.
        code: String,
        /// What went wrong.
        message: String,
    },
}

/// What the node sends up the write tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum Up {
    /// The opening frame: who is attaching, for what, and speaking what.
    Hello {
        /// The protocol version this node speaks.
        v: u32,
        /// The membership domain this attach is for.
        network: String,
        /// This node's origin, canonically rendered.
        origin: String,
        /// The active device key, z-base-32.
        device: String,
        /// The hosting slot this node serves.
        slot: u32,
    },
    /// The signed challenge.
    Proof {
        /// The signature, hex.
        sig: String,
        /// The device key that produced it, z-base-32.
        key: String,
    },
    /// A write may begin.
    Opened {
        /// The request id.
        id: u32,
        /// How many content frames may be sent before the first credit.
        credit: u32,
    },
    /// More content frames may be sent on one write.
    Credit {
        /// The request id.
        id: u32,
        /// How many further frames.
        n: u32,
    },
    /// The version now exists.
    Committed {
        /// The request id.
        id: u32,
        /// The content root, hex.
        root: String,
        /// The object's size.
        size: u64,
        /// The seq the version was published at.
        seq: u64,
        /// The mtime the host stamped, unix nanoseconds.
        mtime_ns: i64,
        /// The publishing origin, canonically rendered.
        origin: String,
    },
    /// The tombstone was published, or there was nothing to withdraw.
    Deleted {
        /// The request id.
        id: u32,
        /// Whether some other origin still publishes a live version.
        still_published: bool,
        /// Whether this node had a version to withdraw, and did.
        withdrawn: bool,
    },
    /// Liveness.
    Ping,
    /// The answer to a [`Down::Ping`].
    Pong,
    /// A coded refusal of one request, or of the connection.
    Err {
        /// The request it refuses, or unset for the connection itself.
        #[serde(default)]
        id: Option<u32>,
        /// The stable code.
        code: String,
        /// What went wrong.
        message: String,
    },
}

/// Reads a content frame's header, returning the id, the sequence and the
/// payload behind it.
pub fn decode_chunk(frame: &[u8]) -> Option<(u32, u32, &[u8])> {
    if frame.len() < CHUNK_HEADER_LEN {
        return None;
    }
    let id = u32::from_be_bytes(frame[0..4].try_into().ok()?);
    let seq = u32::from_be_bytes(frame[4..8].try_into().ok()?);
    Some((id, seq, &frame[CHUNK_HEADER_LEN..]))
}

/// Wraps a payload in its content-frame header, as the control plane does.
pub fn encode_chunk(id: u32, seq: u32, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CHUNK_HEADER_LEN + data.len());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

// -- what a tenant's writes are bounded by -----------------------------------

/// The per-tenant staging bound (`docs/CLOUD-WRITES.md` §5.4).
///
/// Staging lands on the pod's shared ephemeral disk before the CAS ingest
/// uploads it, and a pod is many tenants: this is what keeps one org's
/// uploads from filling the volume out from under another's tenant. A `put`
/// whose `size` does not fit is refused before any byte moves.
#[derive(Debug)]
pub struct StagingBudget {
    free: AtomicU64,
}

impl StagingBudget {
    /// A budget of `bytes` in total.
    pub fn new(bytes: u64) -> Arc<Self> {
        Arc::new(Self {
            free: AtomicU64::new(bytes),
        })
    }

    /// Takes `bytes` out of the budget for the life of the reservation.
    pub fn reserve(self: &Arc<Self>, bytes: u64) -> Option<StagingReservation> {
        let mut free = self.free.load(Ordering::Acquire);
        loop {
            if free < bytes {
                return None;
            }
            match self.free.compare_exchange_weak(
                free,
                free - bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(StagingReservation {
                        budget: self.clone(),
                        bytes,
                    })
                }
                Err(current) => free = current,
            }
        }
    }

    /// How much is left.
    pub fn free(&self) -> u64 {
        self.free.load(Ordering::Acquire)
    }
}

/// A reservation against a [`StagingBudget`], returned on drop.
#[derive(Debug)]
pub struct StagingReservation {
    budget: Arc<StagingBudget>,
    bytes: u64,
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        self.budget.free.fetch_add(self.bytes, Ordering::AcqRel);
    }
}

/// What every write on one tenant is bounded by.
#[derive(Debug, Clone)]
pub struct WriteLimits {
    /// The tenant's staging budget.
    pub staging: Arc<StagingBudget>,
    /// The org's storage ceiling, in bytes; zero means none.
    pub budget_bytes: u64,
}

// -- the attach loop ----------------------------------------------------------

/// Keeps this tenant's write tunnels up until `shutdown` fires
/// (`docs/CLOUD-WRITES.md` §6.1).
///
/// One tunnel per endpoint the deployment names, each with its own retry
/// clock — the browse tunnel's shape, for the browse tunnel's reason: the
/// registry of attached sessions is one control-plane node's memory, and a
/// node with no tunnel could answer no write however current its copy of the
/// database. Discovery is from the zone the tenant already validates, on the
/// record's TTL.
pub async fn run_cloud_writes(
    node: Node,
    resolver: Option<Arc<synch_net::DnssecResolver>>,
    domain: String,
    token: String,
    limits: WriteLimits,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let shutdown = std::pin::pin!(shutdown);
    let mut shutdown = shutdown;
    let mut running: HashMap<String, AbortOnDrop> = HashMap::new();
    let mut backoff = MIN_BACKOFF;
    loop {
        let wait = match discover(resolver.as_deref(), &domain).await {
            Ok((endpoints, ttl)) => {
                backoff = MIN_BACKOFF;
                running.retain(|url, task| {
                    endpoints.iter().any(|e| e == url) && !task.0.is_finished()
                });
                for url in endpoints {
                    if running.contains_key(&url) {
                        continue;
                    }
                    let node = node.clone();
                    let domain = domain.clone();
                    let token = token.clone();
                    let limits = limits.clone();
                    let endpoint = url.clone();
                    running.insert(
                        url,
                        AbortOnDrop(tokio::spawn(async move {
                            attach_endpoint_forever(node, domain, endpoint, token, limits).await
                        })),
                    );
                }
                ttl.clamp(MIN_REDISCOVERY, MAX_REDISCOVERY)
            }
            Err(e) => {
                tracing::debug!(domain, error = %e, "write-tunnel discovery failed");
                let wait = backoff;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                wait
            }
        };
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tokio::time::sleep(jittered(wait)) => {}
        }
    }
    // `AbortOnDrop` ends every tunnel when the map goes.
    drop(running);
}

/// A jittered delay: the floor plus up to a quarter of it, so a fleet that
/// lost its control plane at one instant does not redial it at one instant.
fn jittered(floor: Duration) -> Duration {
    let nanos = synch_core::now_ns().unsigned_abs();
    let extra = floor.as_millis() as u64 / 4;
    floor + Duration::from_millis(if extra == 0 { 0 } else { nanos % extra })
}

/// The endpoints this tenant's write tunnels attach to, and how long the
/// answer stands.
async fn discover(
    resolver: Option<&synch_net::DnssecResolver>,
    domain: &str,
) -> crate::Result<(Vec<String>, Duration)> {
    if let Ok(configured) = std::env::var(URL_ENV) {
        let urls: Vec<String> = configured
            .split(',')
            .map(|url| url.trim().trim_end_matches('/').to_string())
            .filter(|url| !url.is_empty())
            .collect();
        if urls.is_empty() {
            return Err(crate::DpError::Config(format!("{URL_ENV} is empty")));
        }
        return Ok((urls, MAX_REDISCOVERY));
    }
    let resolver = resolver.ok_or_else(|| {
        crate::DpError::Config(
            "this data plane runs no DNSSEC resolver, so it cannot discover a control plane".into(),
        )
    })?;
    let (records, ttl) = resolver
        .control_plane(domain)
        .await
        .map_err(|e| crate::DpError::Control(format!("{domain}: {e}")))?;
    Ok((records.into_iter().map(|record| record.url).collect(), ttl))
}

/// Keeps one endpoint's write tunnel up, with exponential backoff and jitter.
async fn attach_endpoint_forever(
    node: Node,
    domain: String,
    endpoint: String,
    token: String,
    limits: WriteLimits,
) {
    let mut backoff = MIN_BACKOFF;
    loop {
        let started = Instant::now();
        match attach_once(&node, &domain, &endpoint, &token, &limits).await {
            Ok(()) => tracing::info!(domain, endpoint, "write tunnel closed cleanly"),
            Err(e) => tracing::debug!(domain, endpoint, error = %e, "write tunnel failed"),
        }
        if started.elapsed() > MAX_BACKOFF {
            backoff = MIN_BACKOFF;
        }
        tokio::time::sleep(jittered(backoff)).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Connects to one endpoint, proves, and serves one session to its end.
async fn attach_once(
    node: &Node,
    domain: &str,
    base: &str,
    token: &str,
    limits: &WriteLimits,
) -> crate::Result<()> {
    let url = format!("{base}{ATTACH_PATH}");
    let handshake = async {
        let mut config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
        config.max_message_size = Some(MAX_DOWN_FRAME);
        config.max_frame_size = Some(MAX_DOWN_FRAME);
        let connector = tokio_tungstenite::Connector::Rustls(
            synch_net::tls::client_config().map_err(|e| crate::DpError::Control(e.to_string()))?,
        );
        // The data-plane credential rides the upgrade request; the device
        // proof follows on the socket. Two credentials because a write needs
        // both proven (`docs/CLOUD-WRITES.md` §5.2).
        let mut request = websocket_url(&url)
            .into_client_request()
            .map_err(|e| crate::DpError::Control(format!("{url}: {e}")))?;
        let bearer = format!("Bearer {token}")
            .parse()
            .map_err(|_| crate::DpError::Control("the token is not a header value".into()))?;
        request.headers_mut().insert("authorization", bearer);
        let (socket, _) = tokio_tungstenite::connect_async_tls_with_config(
            request,
            Some(config),
            false,
            Some(connector),
        )
        .await
        .map_err(|e| crate::DpError::Control(format!("{url}: {e}")))?;
        let (mut sink, mut stream) = socket.split();

        send(
            &mut sink,
            &Up::Hello {
                v: PROTOCOL_VERSION,
                network: domain.to_string(),
                origin: node.origin().canonical(),
                device: node.node_id().to_z32(),
                slot: crate::SLOT,
            },
        )
        .await?;
        let nonce = match receive(&mut stream).await? {
            Down::Challenge { nonce } => decode_nonce(&nonce)?,
            Down::Err { code, message, .. } => {
                return Err(crate::DpError::Control(brief(&format!(
                    "{code}: {message}"
                ))))
            }
            other => {
                return Err(crate::DpError::Control(brief(&format!(
                    "expected a challenge, got {other:?}"
                ))))
            }
        };
        let signature = node.sign_write_attach(&url, &nonce);
        send(
            &mut sink,
            &Up::Proof {
                sig: hex::encode(signature.to_bytes()),
                key: node.node_id().to_z32(),
            },
        )
        .await?;
        let session = match receive(&mut stream).await? {
            Down::Attached { session, v }
                if (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&v) =>
            {
                tracing::info!(domain, session, url, "write tunnel established");
                session
            }
            Down::Attached { v, .. } => {
                return Err(crate::DpError::Control(format!(
                    "write-tunnel protocol mismatch: this node speaks v{MIN_PROTOCOL_VERSION} \
                     to v{PROTOCOL_VERSION}, the control plane settled on v{v}"
                )))
            }
            Down::Err { code, message, .. } => {
                return Err(crate::DpError::Control(brief(&format!(
                    "{code}: {message}"
                ))))
            }
            other => {
                return Err(crate::DpError::Control(brief(&format!(
                    "expected an attach, got {other:?}"
                ))))
            }
        };
        Ok((sink, stream, session))
    };
    let (sink, stream, session) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| {
            crate::DpError::Control(format!("{url}: the handshake did not finish in time"))
        })??;
    serve(node, sink, stream, &session, limits).await
}

fn websocket_url(url: &str) -> String {
    match url.split_once("://") {
        Some(("https", rest)) => format!("wss://{rest}"),
        Some(("http", rest)) => format!("ws://{rest}"),
        _ => url.to_string(),
    }
}

/// Renders text the control plane chose, for a log line or an error message.
fn brief(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

fn decode_nonce(text: &str) -> crate::Result<Vec<u8>> {
    let bytes = hex::decode(text)
        .map_err(|e| crate::DpError::Control(format!("the challenge nonce is not hex: {e}")))?;
    if bytes.len() != synch_engine::cloud::frame::NONCE_LEN {
        return Err(crate::DpError::Control(format!(
            "the challenge nonce is {} bytes, not {}",
            bytes.len(),
            synch_engine::cloud::frame::NONCE_LEN
        )));
    }
    Ok(bytes)
}

type Writer = mpsc::Sender<Message>;

/// What a write task is told by the session loop.
#[derive(Debug)]
enum WriteCmd {
    /// One content frame's payload, in order.
    Chunk(Vec<u8>),
    /// Every byte was sent.
    Commit,
}

/// A write in flight: the task staging it, and how many frames the control
/// plane has sent that this node has not yet staged.
#[derive(Debug)]
struct Write {
    cmds: mpsc::UnboundedSender<WriteCmd>,
    outstanding: u32,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Write {
    fn drop(&mut self) {
        // Aborting drops the `TreeWriter`, whose `Adoption` removes the
        // staging file: a cancelled write leaves nothing behind.
        self.task.abort();
    }
}

/// A message from a spawned task back to the session loop.
#[derive(Debug)]
enum Internal {
    /// A write task staged one frame, so one credit goes back.
    Consumed(u32),
    /// A write ended — committed, refused, or cancelled — so its entry goes.
    WriteDone(u32),
    /// A one-shot delete finished.
    RequestDone,
    /// The writer task gave up on the socket.
    WriterFailed(String),
}

#[derive(Debug)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serves frames until the connection ends.
///
/// The socket write lives in a dedicated task for the reason the browse
/// tunnel's does: a write blocked on a control plane that stopped reading
/// must not stall the heartbeat that would notice.
pub(crate) async fn serve<S, R>(
    node: &Node,
    sink: S,
    mut stream: R,
    session: &str,
    limits: &WriteLimits,
) -> crate::Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin
        + Send
        + 'static,
    R: futures_util::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    let (writes, mut outgoing) = mpsc::channel::<Message>(WRITE_AHEAD);
    let (internal, mut events) = mpsc::channel::<Internal>(WRITE_AHEAD * 4);

    let writer = {
        let internal = internal.clone();
        let mut sink = sink;
        tokio::spawn(async move {
            while let Some(message) = outgoing.recv().await {
                match tokio::time::timeout(WRITE_TIMEOUT, sink.send(message)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        let _ = internal
                            .send(Internal::WriterFailed(format!(
                                "the tunnel write failed: {e}"
                            )))
                            .await;
                        return;
                    }
                    Err(_) => {
                        let _ = internal
                            .send(Internal::WriterFailed(
                                "the control plane stopped reading; the write stalled".into(),
                            ))
                            .await;
                        return;
                    }
                }
            }
        })
    };
    let _writer_guard = AbortOnDrop(writer);

    let mut in_flight: HashMap<u32, Write> = HashMap::new();
    let mut requests: usize = 0;
    let mut beat = tokio::time::interval_at(tokio::time::Instant::now() + HEARTBEAT, HEARTBEAT);
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut unanswered = 0u32;

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(Internal::WriterFailed(why)) => return Err(crate::DpError::Control(why)),
                    Some(Internal::Consumed(id)) => {
                        if let Some(write) = in_flight.get_mut(&id) {
                            write.outstanding = write.outstanding.saturating_sub(1);
                        }
                    }
                    Some(Internal::WriteDone(id)) => { in_flight.remove(&id); }
                    Some(Internal::RequestDone) => requests = requests.saturating_sub(1),
                    None => return Ok(()),
                }
            }
            _ = beat.tick() => {
                if unanswered >= HEARTBEAT_MISSES {
                    return Err(crate::DpError::Control(format!(
                        "the control plane missed {unanswered} heartbeats; the session is dead"
                    )));
                }
                unanswered += 1;
                let _ = writes.try_send(text(&Up::Ping)?);
            }
            incoming = stream.next() => {
                let Some(incoming) = incoming else { return Ok(()) };
                let incoming = incoming
                    .map_err(|e| crate::DpError::Control(format!("the tunnel read failed: {e}")))?;
                match incoming {
                    Message::Text(body) => {
                        unanswered = 0;
                        let frame: Down = serde_json::from_str(&body).map_err(|e| {
                            crate::DpError::Control(format!("malformed tunnel frame: {e}"))
                        })?;
                        handle(node, session, limits, &writes, &internal, &mut in_flight, &mut requests, frame)?;
                    }
                    Message::Binary(frame) => {
                        unanswered = 0;
                        content(&writes, &mut in_flight, &frame)?;
                    }
                    Message::Close(_) => return Ok(()),
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => unanswered = 0,
                }
            }
        }
    }
}

/// One content frame from the control plane, routed to its write.
fn content(
    writes: &Writer,
    in_flight: &mut HashMap<u32, Write>,
    frame: &[u8],
) -> crate::Result<()> {
    let Some((id, _seq, data)) = decode_chunk(frame) else {
        return Err(crate::DpError::Control(
            "a content frame is shorter than its header".into(),
        ));
    };
    if data.len() > MAX_CHUNK {
        return Err(crate::DpError::Control(format!(
            "a content frame carries {} bytes; the ceiling is {MAX_CHUNK}",
            data.len()
        )));
    }
    let Some(write) = in_flight.get_mut(&id) else {
        // A frame for a write that has ended is late, not hostile: the
        // control plane may have sent it before it read our refusal.
        return Ok(());
    };
    if write.outstanding >= CREDIT_WINDOW {
        // Past its credit: the control plane is not honouring the window,
        // and buffering for it would be buffering without bound.
        refuse(
            writes,
            id,
            "invalid",
            format!("write {id} sent a frame it had no credit for"),
        );
        in_flight.remove(&id);
        return Ok(());
    }
    write.outstanding += 1;
    if write.cmds.send(WriteCmd::Chunk(data.to_vec())).is_err() {
        in_flight.remove(&id);
    }
    Ok(())
}

/// Serves one control frame. Never awaits: every answer is produced in a
/// spawned task and delivered through the writer channel.
#[allow(clippy::too_many_arguments)]
fn handle(
    node: &Node,
    session: &str,
    limits: &WriteLimits,
    writes: &Writer,
    internal: &mpsc::Sender<Internal>,
    in_flight: &mut HashMap<u32, Write>,
    requests: &mut usize,
    frame: Down,
) -> crate::Result<()> {
    match frame {
        Down::Ping => {
            let _ = writes.try_send(text(&Up::Pong)?);
        }
        Down::Pong => {}
        Down::Err { id, code, message } => {
            tracing::debug!(
                ?id,
                code = brief(&code),
                message = brief(&message),
                "the control plane refused a request"
            );
            if let Some(id) = id {
                in_flight.remove(&id);
            }
        }
        Down::Cancel { id } => {
            in_flight.remove(&id);
        }
        Down::Commit { id } => {
            if let Some(write) = in_flight.get(&id) {
                if write.cmds.send(WriteCmd::Commit).is_err() {
                    in_flight.remove(&id);
                }
            }
        }
        Down::Put {
            id,
            space,
            path,
            size,
            from,
            if_match,
            if_none_match,
        } => {
            if in_flight.contains_key(&id) {
                refuse(
                    writes,
                    id,
                    "invalid",
                    format!("request {id} is already in flight"),
                );
                return Ok(());
            }
            if over_capacity(writes, in_flight, *requests, id) {
                return Ok(());
            }
            let condition = match condition(from, if_match, if_none_match) {
                Ok(condition) => condition,
                Err(message) => {
                    refuse(writes, id, "invalid", message);
                    return Ok(());
                }
            };
            let (cmds, receiver) = mpsc::unbounded_channel();
            let task = {
                let node = node.clone();
                let writes = writes.clone();
                let internal = internal.clone();
                let limits = limits.clone();
                let via = format!("control-plane session {session} write {id}");
                tokio::spawn(async move {
                    let outcome = run_write(
                        &node, &writes, &internal, &limits, id, &space, &path, size, condition,
                        &via, receiver,
                    )
                    .await;
                    if let Err(refusal) = outcome {
                        if let Ok(message) = text(&Up::Err {
                            id: Some(id),
                            code: refusal.code.into(),
                            message: refusal.message,
                        }) {
                            let _ = writes.send(message).await;
                        }
                    }
                    let _ = internal.send(Internal::WriteDone(id)).await;
                })
            };
            in_flight.insert(
                id,
                Write {
                    cmds,
                    outstanding: 0,
                    task,
                },
            );
        }
        Down::Delete {
            id,
            space,
            path,
            from,
            if_match,
        } => {
            if over_capacity(writes, in_flight, *requests, id) {
                return Ok(());
            }
            let condition = match condition(from, if_match, false) {
                Ok(condition) => condition,
                Err(message) => {
                    refuse(writes, id, "invalid", message);
                    return Ok(());
                }
            };
            *requests += 1;
            let node = node.clone();
            let writes = writes.clone();
            let internal = internal.clone();
            let via = format!("control-plane session {session} delete {id}");
            tokio::spawn(async move {
                let frame = match run_delete(&node, id, &space, &path, condition, &via).await {
                    Ok(frame) => frame,
                    Err(refusal) => Up::Err {
                        id: Some(id),
                        code: refusal.code.into(),
                        message: refusal.message,
                    },
                };
                if let Ok(message) = text(&frame) {
                    let _ = writes.send(message).await;
                }
                let _ = internal.send(Internal::RequestDone).await;
            });
        }
        Down::Challenge { .. } | Down::Attached { .. } => {}
    }
    Ok(())
}

/// Whether a new request would exceed the per-session ceiling, refusing it
/// with a coded error if so.
fn over_capacity(
    writes: &Writer,
    in_flight: &HashMap<u32, Write>,
    requests: usize,
    id: u32,
) -> bool {
    if in_flight.len() + requests < MAX_INFLIGHT {
        return false;
    }
    refuse(
        writes,
        id,
        "unavailable",
        format!("this session already has {MAX_INFLIGHT} requests in flight"),
    );
    true
}

/// Sends one request's refusal from the session loop without blocking it.
///
/// Never `try_send`: a refusal dropped under writer backpressure leaves the
/// control plane waiting out its timeout for an answer that will not come.
/// The send is awaited in a task of its own, so the loop keeps polling the
/// heartbeat and the writer's own timeout still bounds a stalled peer.
fn refuse(writes: &Writer, id: u32, code: &'static str, message: String) {
    let writes = writes.clone();
    tokio::spawn(async move {
        if let Ok(frame) = text(&Up::Err {
            id: Some(id),
            code: code.into(),
            message,
        }) {
            let _ = writes.send(frame).await;
        }
    });
}

/// The condition a request's headers spell, in the engine's terms.
fn condition(
    from: Option<String>,
    if_match: Option<String>,
    if_none_match: bool,
) -> std::result::Result<PutCondition, String> {
    let from = match from {
        Some(origin) => Some(
            origin
                .parse::<OriginId>()
                .map_err(|e| format!("from: {e}"))?,
        ),
        None => None,
    };
    match (if_match, if_none_match) {
        (Some(_), true) => Err("if_match and if_none_match cannot both be set".into()),
        (Some(root), false) => {
            let root: Hash = root
                .parse()
                .map_err(|_| format!("{root} is not an object root"))?;
            Ok(PutCondition::Selected {
                from,
                root: Some(root),
            })
        }
        (None, true) => Ok(PutCondition::Selected { from, root: None }),
        (None, false) => Ok(PutCondition::Any),
    }
}

/// A coded refusal of one request.
#[derive(Debug)]
struct Refusal {
    code: &'static str,
    message: String,
}

impl Refusal {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<EngineError> for Refusal {
    fn from(e: EngineError) -> Self {
        let code = match &e {
            EngineError::NotFound(_) => "not-found",
            EngineError::InRecovery { .. } => "unavailable",
            EngineError::Invalid(_) | EngineError::Key(_) => "invalid",
            _ => "internal",
        };
        Refusal::new(code, e.to_string())
    }
}

impl From<HostError> for Refusal {
    fn from(e: HostError) -> Self {
        let code = match &e {
            HostError::NotFound => "not-found",
            HostError::NotReadable(_) | HostError::Denied(_) => "invalid",
            HostError::Conflict(_) => "precondition",
            HostError::Unavailable(_) => "unavailable",
            HostError::Io(_) => "internal",
        };
        Refusal::new(code, e.to_string())
    }
}

impl From<synch_store::StoreError> for Refusal {
    fn from(e: synch_store::StoreError) -> Self {
        Refusal::new("internal", e.to_string())
    }
}

impl From<crate::DpError> for Refusal {
    fn from(e: crate::DpError) -> Self {
        Refusal::new("internal", e.to_string())
    }
}

/// The gates every write and delete takes before touching the seam
/// (`docs/CLOUD-WRITES.md` §6.2): the node can publish, and the space is one
/// this tenant replicates — writes go into the network's existing namespaces,
/// never into one a request invents.
fn admit_space(node: &Node, space: &str) -> std::result::Result<(), Refusal> {
    node.ensure_publishable()?;
    if node.store().replica(space)?.is_none() {
        return Err(Refusal::new(
            "not-found",
            format!("this network has no space {space}"),
        ));
    }
    Ok(())
}

/// One write, from `opened` to `committed`.
#[allow(clippy::too_many_arguments)]
async fn run_write(
    node: &Node,
    writes: &Writer,
    internal: &mpsc::Sender<Internal>,
    limits: &WriteLimits,
    id: u32,
    space: &str,
    path: &str,
    size: u64,
    condition: PutCondition,
    via: &str,
    mut cmds: mpsc::UnboundedReceiver<WriteCmd>,
) -> std::result::Result<(), Refusal> {
    // Refused before any byte moves: the staging bound, then the org's
    // budget, then the engine's own gates at open.
    let Some(_reservation) = limits.staging.reserve(size) else {
        return Err(Refusal::new(
            "unavailable",
            format!(
                "this tenant has {} bytes of staging room and the write needs {size}",
                limits.staging.free()
            ),
        ));
    };
    if limits.budget_bytes > 0 {
        let held = crate::spaces::coverage(node).await?.held_bytes;
        if held.saturating_add(size) > limits.budget_bytes {
            return Err(Refusal::new(
                "over-budget",
                format!(
                    "this network holds {held} bytes of a {}-byte budget; the write needs {size}",
                    limits.budget_bytes
                ),
            ));
        }
    }
    let mut writer = {
        let node = node.clone();
        let (space, path, via) = (space.to_string(), path.to_string(), via.to_string());
        synch_core::offload(move || {
            // Everything that can refuse at open is asked *before* the space
            // becomes a source of ours: a write refused here has left no
            // trace (§6.2). What a later refusal — a lost condition at
            // commit — cannot undo is the source row the staging needed.
            admit_space(&node, &space).map_err(offload_err)?;
            synch_core::normalize_path(&path).map_err(|e| EngineError::invalid(e.to_string()))?;
            // Lazily, on the first write into a space: from here on cloud-1
            // both replicates the space and publishes into it (§6.2).
            node.add_api_source(&space)?;
            node.open_tree_write(&space, &path, &via)
        })
        .await
        .map_err(unwrap_offload)?
    };
    let _ = writes
        .send(text(&Up::Opened {
            id,
            credit: CREDIT_WINDOW,
        })?)
        .await;

    let mut received: u64 = 0;
    loop {
        // A write that goes quiet is abandoned, and its staging with it:
        // the control plane cancels what it gives up on, but a control plane
        // that died mid-upload cancels nothing.
        let Ok(cmd) = tokio::time::timeout(WRITE_IDLE, cmds.recv()).await else {
            return Err(Refusal::new(
                "unavailable",
                format!(
                    "the write was idle for {}s and was abandoned",
                    WRITE_IDLE.as_secs()
                ),
            ));
        };
        let Some(cmd) = cmd else {
            // Cancelled: the writer drops here and its staging with it.
            return Ok(());
        };
        match cmd {
            WriteCmd::Chunk(data) => {
                received = received.saturating_add(data.len() as u64);
                if received > size {
                    return Err(Refusal::new(
                        "invalid",
                        format!("the write announced {size} bytes and sent more"),
                    ));
                }
                writer.write(data).await?;
                // The credit goes back from here, awaited, so backpressure on
                // the writer delays it rather than drops it: a lost credit
                // would leave the control plane waiting for a frame that
                // never comes.
                let _ = writes.send(text(&Up::Credit { id, n: 1 })?).await;
                let _ = internal.send(Internal::Consumed(id)).await;
            }
            WriteCmd::Commit => {
                if received != size {
                    return Err(Refusal::new(
                        "invalid",
                        format!("the write announced {size} bytes and sent {received}"),
                    ));
                }
                // In a task of its own, so a cancellation landing now — the
                // session ending, hosting switched off — does not abort a
                // commit half way through the seam. The commit runs to its
                // end and publishes or fails whole; only the report of it
                // is lost (`docs/TREE-WRITES.md` §5.1 makes the same promise
                // for a killed invocation).
                let node = node.clone();
                let (space, path) = (space.to_string(), path.to_string());
                let committed = tokio::spawn(async move {
                    let receipt = writer.commit(condition).await?;
                    let (seq, mtime_ns) = {
                        let node = node.clone();
                        let (space, path) = (space.clone(), path.clone());
                        synch_core::offload(move || {
                            let normalized = synch_core::normalize_path(&path)
                                .map_err(|e| EngineError::invalid(e.to_string()))?;
                            Ok::<_, EngineError>(
                                node.store()
                                    .entry(node.origin(), &space, &normalized)?
                                    .map(|entry| (entry.seq, entry.mtime_ns))
                                    .unwrap_or((0, 0)),
                            )
                        })
                        .await?
                    };
                    Ok::<_, Refusal>(Up::Committed {
                        id,
                        root: receipt.root.to_hex().to_string(),
                        size: receipt.size,
                        seq,
                        mtime_ns,
                        origin: node.origin().canonical(),
                    })
                })
                .await
                .map_err(|e| Refusal::new("internal", format!("the commit task failed: {e}")))??;
                let _ = writes.send(text(&committed)?).await;
                return Ok(());
            }
        }
    }
}

/// One delete: withdraw `cloud-1`'s version where there is one, and publish
/// nothing where there is not (`docs/CLOUD-WRITES.md` §6.6).
async fn run_delete(
    node: &Node,
    id: u32,
    space: &str,
    path: &str,
    condition: PutCondition,
    via: &str,
) -> std::result::Result<Up, Refusal> {
    let normalized =
        synch_core::normalize_path(path).map_err(|e| Refusal::new("invalid", e.to_string()))?;
    let own = {
        let node = node.clone();
        let (space, normalized) = (space.to_string(), normalized.clone());
        synch_core::offload(move || {
            admit_space(&node, &space).map_err(offload_err)?;
            let api_source = node
                .store()
                .source(&space)?
                .is_some_and(|s| s.local_path.is_none());
            if !api_source {
                // Never a source of ours: cloud-1 has asserted nothing here.
                return Ok(None);
            }
            Ok(node
                .store()
                .entry(node.origin(), &space, &normalized)?
                .filter(|entry| entry.kind != EntryKind::Tombstone)
                .and_then(|entry| entry.content))
        })
        .await
        .map_err(unwrap_offload)?
    };
    let withdrawn = match own {
        None => {
            // Nothing to withdraw, but a stated condition is still the
            // caller's question, and "the cloud never asserted this" must not
            // read as "your precondition held" (§4.3).
            if let PutCondition::Selected { from, root } = &condition {
                let policy = match from {
                    Some(origin) => synch_store::VersionPolicy::Origin(origin.clone()),
                    None => synch_store::VersionPolicy::Newest,
                };
                let node = node.clone();
                let (in_space, at_path) = (space.to_string(), normalized.clone());
                let found = synch_core::offload(move || {
                    Ok::<_, EngineError>(match node.resolve(&in_space, &at_path, &policy) {
                        Ok(row) if row.kind == EntryKind::Tombstone => None,
                        Ok(row) => row.content,
                        Err(EngineError::NotFound(_)) => None,
                        Err(e) => return Err(e),
                    })
                })
                .await?;
                if found != *root {
                    return Err(Refusal::new(
                        "precondition",
                        format!("{space}/{path} does not select the expected version"),
                    ));
                }
            }
            false
        }
        Some(own_root) => {
            let mut writer = {
                let node = node.clone();
                let (space, path, via) = (space.to_string(), path.to_string(), via.to_string());
                synch_core::offload(move || node.open_tree_write(&space, &path, &via)).await?
            };
            // A stated condition is the caller's; otherwise the guard is our
            // own root, so two deletes of one path publish one tombstone.
            let unconditional = matches!(condition, PutCondition::Any);
            let guard = match condition {
                PutCondition::Any => PutCondition::Root(own_root),
                stated => stated,
            };
            match writer.delete_if(guard).await {
                Ok(()) => true,
                // Our version went between the read and the lock: somebody
                // else withdrew it, and the answer is the same.
                Err(HostError::Conflict(_)) if unconditional => false,
                Err(e) => return Err(e.into()),
            }
        }
    };
    let still_published = {
        let node = node.clone();
        let (space, normalized) = (space.to_string(), normalized);
        synch_core::offload(move || {
            let ours = node.origin().clone();
            Ok::<_, EngineError>(
                node.versions(&space, &normalized)?
                    .entries
                    .iter()
                    .any(|entry| entry.origin != ours && entry.kind != EntryKind::Tombstone),
            )
        })
        .await?
    };
    Ok(Up::Deleted {
        id,
        still_published,
        withdrawn,
    })
}

/// Carries a [`Refusal`] through `offload`, whose error type is the engine's.
fn offload_err(refusal: Refusal) -> EngineError {
    EngineError::invalid(format!("{}\u{1f}{}", refusal.code, refusal.message))
}

/// The inverse of [`offload_err`], for refusals that crossed the pool.
fn unwrap_offload(e: EngineError) -> Refusal {
    if let EngineError::Invalid(text) = &e {
        if let Some((code, message)) = text.split_once('\u{1f}') {
            let code: &'static str = match code {
                "not-found" => "not-found",
                "unavailable" => "unavailable",
                "invalid" => "invalid",
                "over-budget" => "over-budget",
                "precondition" => "precondition",
                _ => "internal",
            };
            return Refusal::new(code, message.to_string());
        }
    }
    e.into()
}

fn text(frame: &Up) -> crate::Result<Message> {
    serde_json::to_string(frame)
        .map(Message::text)
        .map_err(|e| crate::DpError::Control(format!("could not encode a tunnel frame: {e}")))
}

async fn send<S>(sink: &mut S, frame: &Up) -> crate::Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    sink.send(text(frame)?)
        .await
        .map_err(|e| crate::DpError::Control(format!("the tunnel write failed: {e}")))
}

async fn receive<R>(stream: &mut R) -> crate::Result<Down>
where
    R: futures_util::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    loop {
        let message = stream
            .next()
            .await
            .ok_or_else(|| {
                crate::DpError::Control("the control plane closed the connection".into())
            })?
            .map_err(|e| crate::DpError::Control(format!("the tunnel read failed: {e}")))?;
        match message {
            Message::Text(body) => {
                return serde_json::from_str(&body)
                    .map_err(|e| crate::DpError::Control(format!("malformed tunnel frame: {e}")))
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            Message::Binary(_) | Message::Close(_) => {
                return Err(crate::DpError::Control(
                    "the control plane ended the handshake early".into(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_engine::NodeConfig;

    fn down_msg(frame: &Down) -> Message {
        Message::text(serde_json::to_string(frame).unwrap())
    }

    /// The next text frame the node sent, decoded, skipping its own pings.
    async fn next_up(rx: &mut mpsc::UnboundedReceiver<Message>) -> Up {
        loop {
            match tokio::time::timeout(Duration::from_secs(30), rx.recv())
                .await
                .expect("the node answered in time")
                .expect("the node sent a frame")
            {
                Message::Text(body) => {
                    let up: Up = serde_json::from_str(&body).expect("a valid Up");
                    if matches!(up, Up::Ping) {
                        continue;
                    }
                    return up;
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }
    }

    /// A key-identified node with `docs` replicated, as a hosted tenant
    /// holds a space before anything is written into it.
    async fn tenant() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        synch_core::offload(move || Node::init(&path, None))
            .await
            .unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        let n = node.clone();
        synch_core::offload(move || {
            n.add_replica(
                "docs",
                synch_store::ReplicaPolicy::Current,
                None,
                None,
                None,
            )
        })
        .await
        .unwrap();
        (dir, node)
    }

    /// Runs `serve` over in-process channels: the returned sender is the
    /// control plane's end, the receiver is what the node sends up.
    fn session(
        node: &Node,
        limits: WriteLimits,
    ) -> (
        mpsc::UnboundedSender<Message>,
        mpsc::UnboundedReceiver<Message>,
        tokio::task::JoinHandle<crate::Result<()>>,
    ) {
        let (down_tx, down_rx) = mpsc::unbounded_channel::<Message>();
        let (up_tx, up_rx) = mpsc::unbounded_channel::<Message>();
        let sink = futures_util::sink::unfold(up_tx, |tx, message: Message| async move {
            tx.send(message)
                .map_err(|_| tokio_tungstenite::tungstenite::Error::ConnectionClosed)?;
            Ok::<_, tokio_tungstenite::tungstenite::Error>(tx)
        });
        let stream = tokio_stream_from(down_rx);
        let node = node.clone();
        let task = tokio::spawn(async move {
            serve(&node, Box::pin(sink), Box::pin(stream), "s1", &limits).await
        });
        (down_tx, up_rx, task)
    }

    fn tokio_stream_from(
        mut rx: mpsc::UnboundedReceiver<Message>,
    ) -> impl futures_util::Stream<
        Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
    > {
        futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx).map(|m| m.map(Ok)))
    }

    /// The next answer that is not a credit: a commit's or a delete's, with
    /// the credits still arriving for the frames before it skipped.
    async fn settled(rx: &mut mpsc::UnboundedReceiver<Message>) -> Up {
        loop {
            match next_up(rx).await {
                Up::Credit { .. } => continue,
                other => break other,
            }
        }
    }

    fn limits() -> WriteLimits {
        WriteLimits {
            staging: StagingBudget::new(1 << 20),
            budget_bytes: 0,
        }
    }

    /// A whole write round-trips: `put`, frames under credit, `commit`, and
    /// the version is readable back as this node's own.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_publishes_the_hosted_nodes_own_version() {
        let _scope = synch_core::BlockingScope::enter();
        let (_dir, node) = tenant().await;
        let (down, mut up, _task) = session(&node, limits());
        let payload = vec![7u8; 100_000];
        down.send(down_msg(&Down::Put {
            id: 1,
            space: "docs".into(),
            path: "q3/report.pdf".into(),
            size: payload.len() as u64,
            from: None,
            if_match: None,
            if_none_match: false,
        }))
        .unwrap();
        assert!(
            matches!(next_up(&mut up).await, Up::Opened { id: 1, credit } if credit == CREDIT_WINDOW)
        );
        let mut credit = CREDIT_WINDOW;
        for (seq, chunk) in payload.chunks(MAX_CHUNK).enumerate() {
            while credit == 0 {
                match next_up(&mut up).await {
                    Up::Credit { id: 1, n } => credit += n,
                    other => panic!("expected credit, got {other:?}"),
                }
            }
            down.send(Message::binary(encode_chunk(1, seq as u32, chunk)))
                .unwrap();
            credit -= 1;
        }
        down.send(down_msg(&Down::Commit { id: 1 })).unwrap();
        let committed = loop {
            match next_up(&mut up).await {
                Up::Credit { .. } => continue,
                other => break other,
            }
        };
        let Up::Committed {
            id,
            root,
            size,
            origin,
            ..
        } = committed
        else {
            panic!("expected committed, got {committed:?}");
        };
        assert_eq!(id, 1);
        assert_eq!(size, payload.len() as u64);
        assert_eq!(root, Hash::new(&payload).to_hex().to_string());
        assert_eq!(origin, node.origin().canonical());

        let n = node.clone();
        let row = synch_core::offload(move || {
            n.resolve("docs", "q3/report.pdf", &synch_store::VersionPolicy::Newest)
        })
        .await
        .unwrap();
        assert_eq!(row.content, Some(Hash::new(&payload)));
        assert_eq!(&row.origin, node.origin());

        // A write with `if_match` on the stale root loses and publishes
        // nothing; the next, with the next request id and current root, wins.
        for (request_id, expected, want_ok) in [
            (2, Hash::new(b"stale"), false),
            (3, Hash::new(&payload), true),
        ] {
            let body = b"v2".to_vec();
            down.send(down_msg(&Down::Put {
                id: request_id,
                space: "docs".into(),
                path: "q3/report.pdf".into(),
                size: body.len() as u64,
                from: None,
                if_match: Some(expected.to_hex().to_string()),
                if_none_match: false,
            }))
            .unwrap();
            assert!(matches!(next_up(&mut up).await, Up::Opened { id, .. } if id == request_id));
            down.send(Message::binary(encode_chunk(request_id, 0, &body)))
                .unwrap();
            down.send(down_msg(&Down::Commit { id: request_id }))
                .unwrap();
            let answer = loop {
                match next_up(&mut up).await {
                    Up::Credit { .. } => continue,
                    other => break other,
                }
            };
            match (want_ok, answer) {
                (
                    false,
                    Up::Err {
                        id: Some(id), code, ..
                    },
                ) if id == request_id => assert_eq!(code, "precondition"),
                (true, Up::Committed { id, .. }) if id == request_id => {}
                (_, other) => panic!("unexpected answer {other:?}"),
            }
        }
        node.shutdown().await.unwrap();
    }

    /// A short body is refused at commit and publishes nothing; a write into
    /// a space the tenant does not replicate is refused at open.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_short_body_and_an_unknown_space_publish_nothing() {
        let _scope = synch_core::BlockingScope::enter();
        let (_dir, node) = tenant().await;
        let (down, mut up, _task) = session(&node, limits());
        down.send(down_msg(&Down::Put {
            id: 5,
            space: "docs".into(),
            path: "short.bin".into(),
            size: 10,
            from: None,
            if_match: None,
            if_none_match: false,
        }))
        .unwrap();
        assert!(matches!(next_up(&mut up).await, Up::Opened { id: 5, .. }));
        down.send(Message::binary(encode_chunk(5, 0, b"abc")))
            .unwrap();
        down.send(down_msg(&Down::Commit { id: 5 })).unwrap();
        let answer = loop {
            match next_up(&mut up).await {
                Up::Credit { .. } => continue,
                other => break other,
            }
        };
        assert!(
            matches!(answer, Up::Err { id: Some(5), ref code, .. } if code == "invalid"),
            "{answer:?}"
        );

        down.send(down_msg(&Down::Put {
            id: 6,
            space: "nowhere".into(),
            path: "x".into(),
            size: 1,
            from: None,
            if_match: None,
            if_none_match: false,
        }))
        .unwrap();
        // A credit for write 5 may still be in flight behind its refusal:
        // credits ride the session loop while a refusal is sent straight
        // from the write's task.
        let answer = loop {
            match next_up(&mut up).await {
                Up::Credit { .. } => continue,
                other => break other,
            }
        };
        assert!(
            matches!(answer, Up::Err { id: Some(6), ref code, .. } if code == "not-found"),
            "{answer:?}"
        );

        let n = node.clone();
        let versions = synch_core::offload(move || n.versions("docs", "short.bin"))
            .await
            .unwrap();
        assert!(versions.entries.is_empty());
        node.shutdown().await.unwrap();
    }

    /// A delete of a path this node never asserted publishes nothing and says
    /// so; a delete of its own version withdraws it, and a second one is a
    /// no-op.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_delete_withdraws_only_the_hosted_nodes_own_version() {
        let _scope = synch_core::BlockingScope::enter();
        let (_dir, node) = tenant().await;
        let (down, mut up, _task) = session(&node, limits());
        down.send(down_msg(&Down::Delete {
            id: 1,
            space: "docs".into(),
            path: "never/mine".into(),
            from: None,
            if_match: None,
        }))
        .unwrap();
        assert!(matches!(
            next_up(&mut up).await,
            Up::Deleted {
                id: 1,
                still_published: false,
                withdrawn: false
            }
        ));

        let body = b"mine".to_vec();
        down.send(down_msg(&Down::Put {
            id: 2,
            space: "docs".into(),
            path: "mine.txt".into(),
            size: body.len() as u64,
            from: None,
            if_match: None,
            if_none_match: true,
        }))
        .unwrap();
        assert!(matches!(next_up(&mut up).await, Up::Opened { id: 2, .. }));
        down.send(Message::binary(encode_chunk(2, 0, &body)))
            .unwrap();
        down.send(down_msg(&Down::Commit { id: 2 })).unwrap();
        loop {
            match next_up(&mut up).await {
                Up::Credit { .. } => continue,
                Up::Committed { id: 2, .. } => break,
                other => panic!("expected committed, got {other:?}"),
            }
        }
        for (id, withdrawn) in [(3u32, true), (4u32, false)] {
            down.send(down_msg(&Down::Delete {
                id,
                space: "docs".into(),
                path: "mine.txt".into(),
                from: None,
                if_match: None,
            }))
            .unwrap();
            match next_up(&mut up).await {
                Up::Deleted {
                    id: got,
                    still_published: false,
                    withdrawn: got_withdrawn,
                } => {
                    assert_eq!(got, id);
                    assert_eq!(got_withdrawn, withdrawn);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let n = node.clone();
        let versions = synch_core::offload(move || n.versions("docs", "mine.txt"))
            .await
            .unwrap();
        assert!(versions
            .entries
            .iter()
            .all(|entry| entry.kind == EntryKind::Tombstone));
        node.shutdown().await.unwrap();
    }

    /// What a customer's version does to a write: a delete of a path only
    /// `nas` publishes withdraws nothing and says so; `If-None-Match: *`
    /// fails against `nas`'s version even though cloud-1 has none, as does an
    /// `If-Match` that names the wrong root on a delete; `If-Match` with
    /// `from=nas` pins the comparison to `nas`'s version and wins.
    #[tokio::test(flavor = "multi_thread")]
    async fn conditions_and_deletes_see_the_customers_versions() {
        let _scope = synch_core::BlockingScope::enter();
        let (_dir, node) = tenant().await;
        let nas = OriginId::named("nas", "x.example").unwrap();
        let theirs = b"theirs".to_vec();
        let their_root = {
            let (n, theirs, nas) = (node.clone(), theirs.clone(), nas.clone());
            synch_core::offload(move || {
                let root = n.store().ingest_bytes(&theirs, synch_core::now_ns())?;
                n.store().put_entry(
                    &nas,
                    "docs",
                    "shared.txt",
                    &synch_core::FileEntry::file(theirs.len() as u64, 1, root, 1),
                )?;
                Ok::<_, synch_store::StoreError>(root)
            })
            .await
            .unwrap()
        };
        let (down, mut up, _task) = session(&node, limits());

        // Only nas publishes it: nothing to withdraw, and the path stays.
        down.send(down_msg(&Down::Delete {
            id: 1,
            space: "docs".into(),
            path: "shared.txt".into(),
            from: None,
            if_match: None,
        }))
        .unwrap();
        assert!(matches!(
            next_up(&mut up).await,
            Up::Deleted {
                id: 1,
                still_published: true,
                withdrawn: false
            }
        ));
        // A stated condition is still answered when there is nothing to
        // withdraw.
        down.send(down_msg(&Down::Delete {
            id: 2,
            space: "docs".into(),
            path: "shared.txt".into(),
            from: None,
            if_match: Some(Hash::new(b"wrong").to_hex().to_string()),
        }))
        .unwrap();
        assert!(
            matches!(next_up(&mut up).await, Up::Err { id: Some(2), ref code, .. } if code == "precondition")
        );

        // Create-only loses to nas's version.
        let mine = b"mine".to_vec();
        down.send(down_msg(&Down::Put {
            id: 3,
            space: "docs".into(),
            path: "shared.txt".into(),
            size: mine.len() as u64,
            from: None,
            if_match: None,
            if_none_match: true,
        }))
        .unwrap();
        assert!(matches!(next_up(&mut up).await, Up::Opened { id: 3, .. }));
        down.send(Message::binary(encode_chunk(3, 0, &mine)))
            .unwrap();
        down.send(down_msg(&Down::Commit { id: 3 })).unwrap();
        assert!(
            matches!(settled(&mut up).await, Up::Err { id: Some(3), ref code, .. } if code == "precondition")
        );

        // Pinned to nas's version by `from`, the caller's root holds.
        down.send(down_msg(&Down::Put {
            id: 4,
            space: "docs".into(),
            path: "shared.txt".into(),
            size: mine.len() as u64,
            from: Some(nas.canonical()),
            if_match: Some(their_root.to_hex().to_string()),
            if_none_match: false,
        }))
        .unwrap();
        assert!(matches!(next_up(&mut up).await, Up::Opened { id: 4, .. }));
        down.send(Message::binary(encode_chunk(4, 0, &mine)))
            .unwrap();
        down.send(down_msg(&Down::Commit { id: 4 })).unwrap();
        assert!(matches!(
            settled(&mut up).await,
            Up::Committed { id: 4, .. }
        ));

        // Now both publish it: the cloud's version is withdrawn, nas's stays.
        down.send(down_msg(&Down::Delete {
            id: 5,
            space: "docs".into(),
            path: "shared.txt".into(),
            from: None,
            if_match: None,
        }))
        .unwrap();
        assert!(matches!(
            settled(&mut up).await,
            Up::Deleted {
                id: 5,
                still_published: true,
                withdrawn: true
            }
        ));
        node.shutdown().await.unwrap();
    }

    /// The staging bound refuses before a byte moves, and gives the room back
    /// when the write ends.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_staging_budget_bounds_writes_in_flight() {
        let _scope = synch_core::BlockingScope::enter();
        let (_dir, node) = tenant().await;
        let limits = WriteLimits {
            staging: StagingBudget::new(64),
            budget_bytes: 0,
        };
        let (down, mut up, _task) = session(&node, limits.clone());
        down.send(down_msg(&Down::Put {
            id: 1,
            space: "docs".into(),
            path: "big".into(),
            size: 65,
            from: None,
            if_match: None,
            if_none_match: false,
        }))
        .unwrap();
        assert!(
            matches!(next_up(&mut up).await, Up::Err { id: Some(1), ref code, .. } if code == "unavailable")
        );
        down.send(down_msg(&Down::Put {
            id: 2,
            space: "docs".into(),
            path: "fits".into(),
            size: 64,
            from: None,
            if_match: None,
            if_none_match: false,
        }))
        .unwrap();
        assert!(matches!(next_up(&mut up).await, Up::Opened { id: 2, .. }));
        assert_eq!(limits.staging.free(), 0);
        down.send(down_msg(&Down::Cancel { id: 2 })).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while limits.staging.free() != 64 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the reservation is returned on cancel");
        node.shutdown().await.unwrap();
    }

    /// The wire layout is the contract with the control plane, which decodes
    /// these by name in another language.
    #[test]
    fn the_wire_layout_is_pinned() {
        let put: serde_json::Value = serde_json::to_value(Down::Put {
            id: 3,
            space: "docs".into(),
            path: "a/b".into(),
            size: 9,
            from: None,
            if_match: Some("ab".repeat(32)),
            if_none_match: false,
        })
        .unwrap();
        assert_eq!(put["t"], "put");
        assert_eq!(put["size"], 9);
        assert_eq!(put["if_match"], "ab".repeat(32));
        let bare: Down =
            serde_json::from_str(r#"{"t":"put","id":1,"space":"s","path":"p","size":0}"#).unwrap();
        assert!(matches!(
            bare,
            Down::Put {
                from: None,
                if_match: None,
                if_none_match: false,
                ..
            }
        ));
        let committed: serde_json::Value = serde_json::to_value(Up::Committed {
            id: 3,
            root: "ff".repeat(32),
            size: 9,
            seq: 4,
            mtime_ns: 5,
            origin: "cloud-1@x.example".into(),
        })
        .unwrap();
        assert_eq!(committed["t"], "committed");
        assert_eq!(committed["seq"], 4);
        let deleted: serde_json::Value = serde_json::to_value(Up::Deleted {
            id: 1,
            still_published: true,
            withdrawn: false,
        })
        .unwrap();
        assert_eq!(deleted["still_published"], true);
        assert_eq!(deleted["withdrawn"], false);
        let frame = encode_chunk(7, 2, b"xyz");
        let (id, seq, data) = decode_chunk(&frame).unwrap();
        assert_eq!((id, seq, data), (7, 2, &b"xyz"[..]));
        assert!(decode_chunk(&[0, 0, 0]).is_none());
    }
}
