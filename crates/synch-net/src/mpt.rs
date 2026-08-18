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
    MAX_BATCH_PATH_BYTES, MAX_HEADS_PER_MESSAGE, MAX_PROVIDER_ADS, PROTO_VERSION,
};
use synch_mpt::{NodeStore, Trie, TrieNode};
use synch_store::Store;

use crate::{
    endpoint::{under_deadline, REQUEST_TIMEOUT},
    error::NetError,
    frame::{read_frame, write_frame},
};

/// What the `sync/mpt/1` responder needs from the layer that reconciles heads.
///
/// The serve side has to answer `Hello` with this node's summaries, record what
/// a dialing peer advertised, and offer pushed heads for adoption. None of that
/// is networking — it is the §5.2 acceptance rule, the binding check, and the
/// promotion transaction — so it is named here as a requirement and implemented
/// where it belongs, in the engine.
///
/// The methods are synchronous and are called from the blocking pool: each one
/// walks a trie or opens a transaction.
pub trait HeadSink: Send + Sync + std::fmt::Debug + 'static {
    /// The head summaries this node advertises in `Hello` (§5.1).
    fn local_summaries(&self) -> Result<Vec<HeadSummary>, NetError>;

    /// Records what a peer advertised for this node's own origin (§3.4).
    fn observe_summaries_from(
        &self,
        peer: NodeId,
        summaries: &[HeadSummary],
        now: i64,
    ) -> Result<(), NetError>;

    /// Offers a head for adoption under the §5.2 acceptance rule.
    fn offer_head(&self, head: &SignedHead, now: i64) -> Result<(), NetError>;

    /// The full signed heads for the origins a peer asked about (§5.1).
    ///
    /// Only heads this node can back with a servable trie: what a peer does
    /// with one is fetch the trie under it from us.
    fn heads_for(&self, origins: &[OriginId]) -> Result<Vec<SignedHead>, NetError>;
}

/// How often a live session refreshes the sighting it recorded at accept.
const PEER_SEEN_REFRESH: std::time::Duration = std::time::Duration::from_secs(60);

/// How many peers the sighting throttle remembers before it drops what has
/// lapsed.
///
/// The map is keyed by device key, so it is bounded by the membership in any
/// honest cluster (§12 sizes that at N ≤ 100) — but a key with no live binding
/// never reaches the sighting closure at all, so this is a backstop against a
/// membership larger than anyone has, not against a stranger.
const MAX_TRACKED_SIGHTINGS: usize = 4096;

/// The `sync/mpt/1` protocol handler.
#[derive(Debug, Clone)]
pub struct MptProtocol {
    store: Arc<Store>,
    heads: Arc<dyn HeadSink>,
    on_unknown_key: Option<Arc<tokio::sync::Notify>>,
    /// When each peer's sighting was last written, shared across every
    /// connection this handler serves.
    last_sighting: Arc<std::sync::Mutex<std::collections::HashMap<NodeId, std::time::Instant>>>,
}

impl MptProtocol {
    /// Builds a handler over a store and the reconciler that owns head state.
    pub fn new(store: Arc<Store>, heads: Arc<dyn HeadSink>) -> Self {
        MptProtocol {
            store,
            heads,
            on_unknown_key: None,
            last_sighting: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
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

    fn store(&self) -> &Arc<Store> {
        &self.store
    }
}

impl ProtocolHandler for MptProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // A session outlives the request that opened it, so "last seen" cannot
        // be recorded only at accept: a peer that has been syncing steadily
        // over one connection for an hour would read as an hour absent in
        // `synch peers`. Refreshed as requests arrive, but at most once an
        // interval — the sighting is for an operator's eyes, not worth a write
        // per stream.
        //
        // The throttle is shared across connections rather than captured per
        // `accept`, and the write goes to the blocking pool. Both matter: it is
        // a row update and a WAL frame on the store's one write connection, and
        // a per-connection throttle throttles nothing — a peer that opens N
        // sessions bought N writes on runtime workers for the price of N
        // handshakes.
        let store = self.store().clone();
        let last = self.last_sighting.clone();
        let sighting = move |peer: NodeId| {
            let store = store.clone();
            let last = last.clone();
            async move {
                {
                    let mut seen = last.lock().expect("the sighting lock");
                    if seen
                        .get(&peer)
                        .is_some_and(|at: &std::time::Instant| at.elapsed() < PEER_SEEN_REFRESH)
                    {
                        return;
                    }
                    // Stamped before the write, so concurrent streams do not
                    // each queue one while the first is still in flight.
                    if seen.len() >= MAX_TRACKED_SIGHTINGS {
                        seen.retain(|_, at| at.elapsed() < PEER_SEEN_REFRESH);
                    }
                    seen.insert(peer, std::time::Instant::now());
                }
                let recorded: Result<(), NetError> = crate::blocking::offload(move || {
                    Ok(store.record_peer_seen(&peer, None, now_ns())?)
                })
                .await;
                if let Err(e) = recorded {
                    tracing::debug!(peer = %peer.fmt_short(), error = %e, "could not record a sighting");
                }
            }
        };

        let handler = self.clone();
        crate::serve::serve_connection(
            &self.store.clone(),
            connection,
            self.on_unknown_key.as_ref(),
            sighting,
            move |peer, mut send, mut recv| {
                let handler = handler.clone();
                async move {
                    if let Err(e) = handler.handle_stream(peer, &mut send, &mut recv).await {
                        tracing::debug!(peer = %peer.fmt_short(), error = %e, "mpt stream ended");
                        // The peer is told what went wrong rather than left to
                        // read a closed stream.
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
            },
        )
        .await
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
            MptMessage::Hello { proto, heads, .. } => {
                if proto != PROTO_VERSION {
                    return Err(NetError::Unexpected(format!(
                        "unsupported protocol version {proto}"
                    )));
                }
                check_heads(heads.len(), "a Hello summary list")?;
                // A dialing peer's summaries are as good an observation as the
                // ones we collect by dialing out, and a node in recovery is
                // more likely to be called than to be calling (§3.4).
                //
                // Summarizing means asking the trie whether we hold each root
                // whole — a walk on the first ask for a root, memoized after —
                // so the pair runs on the blocking pool (§5.1).
                let sink = self.heads.clone();
                let store = self.store().clone();
                let (ours, scope) = crate::blocking::offload(move || {
                    sink.observe_summaries_from(peer, &heads, now_ns())?;
                    let summaries = sink.local_summaries()?;
                    // What this node will serve that peer, so a delegated one
                    // can learn the scope it is about to walk under (§8).
                    let scope = store.publish_scope_of_key(&peer, now_ns())?;
                    Ok((summaries, scope))
                })
                .await?;
                write_frame(
                    send,
                    &MptMessage::Hello {
                        proto: PROTO_VERSION,
                        heads: ours,
                        scope,
                    },
                )
                .await?;

                // The peer pushes what it has that we lack, then asks for what
                // we have that it lacks.
                match read_frame::<MptMessage>(recv).await? {
                    MptMessage::Heads { heads } => {
                        check_heads(heads.len(), "a Heads push")?;
                        // Each offer verifies a signature, records history, and
                        // may promote the head — which walks the trie and
                        // re-materializes the changed leaves in one
                        // transaction (§5.2).
                        // Containment is the sink's: it is the only side that
                        // can tell "this origin published something we cannot
                        // apply" from "our disk is full", and an error reaching
                        // here is the second kind. One origin must not stop an
                        // exchange that still owes this peer an answer to its
                        // `HeadsWant`; a local fault legitimately does.
                        let sink = self.heads.clone();
                        crate::blocking::offload(move || {
                            for head in heads {
                                sink.offer_head(&head, now_ns())?;
                            }
                            Ok(())
                        })
                        .await?;
                    }
                    other => return Err(unexpected("Heads", &other)),
                }
                match read_frame::<MptMessage>(recv).await? {
                    MptMessage::HeadsWant { origins } => {
                        check_heads(origins.len(), "a HeadsWant list")?;
                        // A database query per origin, so it goes to the
                        // blocking pool like every other head operation (§5.1).
                        let sink = self.heads.clone();
                        let heads =
                            crate::blocking::offload(move || sink.heads_for(&origins)).await?;
                        write_frame(send, &MptMessage::Heads { heads }).await?;
                    }
                    other => return Err(unexpected("HeadsWant", &other)),
                }
                Ok(())
            }
            MptMessage::HeadPush { head } => {
                let sink = self.heads.clone();
                let pushed = head.clone();
                crate::blocking::offload(move || sink.offer_head(&pushed, now_ns())).await?;
                tracing::debug!(origin = %head.origin, "head pushed to us");
                // The ack tells the pusher we processed it; an empty Heads is
                // the smallest well-typed acknowledgement in the schema.
                write_frame(send, &MptMessage::Heads { heads: Vec::new() }).await?;
                Ok(())
            }
            // Both batch reads run on the blocking pool: `MAX_BATCH` row reads
            // out of SQLite is a bounded amount of work, but not a small one,
            // and a cold store answers them from disk.
            MptMessage::GetNodes { root, wants } => {
                check_wants(&wants)?;
                let store = self.store().clone();
                let (nodes, missing) = crate::blocking::offload(move || {
                    let admitted = admit(&store, peer, root, &wants)?;
                    let mut nodes = Vec::new();
                    let mut missing = Vec::new();
                    let mut budget = ANSWER_BYTE_BUDGET;
                    // One answer per *distinct* hash. A requester may only ask
                    // once — `take_served` refuses a repeated payload as a
                    // protocol violation and ends the exchange — so answering a
                    // duplicated request literally would make this node look
                    // hostile for a fault on the asking side. Deduplicating
                    // here also stops a repeated hash from turning one bounded
                    // batch into `MAX_BATCH` copies of the same payload.
                    //
                    // After `admit`, never instead of it: the request is
                    // authorized by position and only then deduplicated by what
                    // those positions resolved to.
                    let mut answered = std::collections::HashSet::new();
                    for hash in admitted {
                        if !answered.insert(hash) {
                            continue;
                        }
                        match store.get_node(&hash)? {
                            Some(data) => {
                                // A short answer is an ordinary answer: the
                                // requester's walk defers everything it asked
                                // for and re-offers what did not come back
                                // (`MissingWalk::resume`). What is not ordinary
                                // is discovering the frame is too large *after*
                                // building it — `write_frame` serializes the
                                // whole message before it can check
                                // `MAX_FRAME_LEN`, so the cap has to be applied
                                // while the answer is being assembled.
                                match budget.checked_sub(data.len()) {
                                    Some(left) => {
                                        budget = left;
                                        nodes.push((hash, data));
                                    }
                                    None if nodes.is_empty() => nodes.push((hash, data)),
                                    None => break,
                                }
                            }
                            None => missing.push(hash),
                        }
                    }
                    Ok((nodes, missing))
                })
                .await?;
                write_frame(send, &MptMessage::Nodes { nodes, missing }).await?;
                Ok(())
            }
            MptMessage::GetValues { root, wants } => {
                check_wants(&wants)?;
                // Bounded in bytes as well as in count, and *here*. The count
                // cap alone was never a cost cap: a value is arbitrary bytes,
                // so `MAX_BATCH` of them is whatever the origin that published
                // them chose. This handler used to reason that a `b:` record is
                // ~20 KB and a `FileEntry` small — true of honest records, and
                // a claim about record shapes rather than an enforced bound.
                // `MAX_TRIE_VALUE_LEN` is the enforced one now, and the budget
                // below is what keeps even a full batch of them inside a frame.
                let store = self.store().clone();
                let (values, missing) = crate::blocking::offload(move || {
                    // A value is authorized by the position of the node that
                    // holds it: resolve that node, and serve the value only if
                    // the node genuinely carries it. Without the second half a
                    // scoped peer could name an in-scope node and any value
                    // hash it liked.
                    let admitted = admit(&store, peer, root, &wants)?;
                    let mut values = Vec::new();
                    let mut missing = Vec::new();
                    let mut budget = ANSWER_BYTE_BUDGET;
                    // One answer per distinct hash, as `GetNodes` above.
                    let mut answered = std::collections::HashSet::new();
                    for (holder, wanted) in admitted.into_iter().zip(wants.iter()) {
                        if !answered.insert(wanted.1) {
                            continue;
                        }
                        let carried = match store.get_node(&holder)? {
                            Some(data) => TrieNode::decode(&data)
                                .map(|node| node.value_hashes().contains(&wanted.1))
                                .unwrap_or(false),
                            None => false,
                        };
                        if !carried {
                            missing.push(wanted.1);
                            continue;
                        }
                        match store.get_value(&wanted.1)? {
                            Some(data) => match budget.checked_sub(data.len()) {
                                Some(left) => {
                                    budget = left;
                                    values.push((wanted.1, data));
                                }
                                // One payload always goes, whatever its size:
                                // a stored value larger than the whole budget
                                // predates the ceiling, and answering nothing
                                // would stall the requester's walk forever.
                                None if values.is_empty() => values.push((wanted.1, data)),
                                None => break,
                            },
                            None => missing.push(wanted.1),
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
                // so a wrong hint only wastes a dial (§5.1) — and bounded, so
                // one small request cannot buy the asker an unbounded table of
                // rows to write. The bound is applied by the query and by the
                // decode of each row's spans, not by the `truncate` below: a
                // cap after the work is not a cap on the work (§12).
                //
                // On the blocking pool with every other database read. Run on
                // a runtime worker it would take the single global connection
                // mutex there, so its cost would be borne by every other
                // connection and timer in the process.
                let store = self.store().clone();
                let mut ads =
                    crate::blocking::offload(move || Ok(store.providers(&object_root)?)).await?;
                ads.truncate(MAX_PROVIDER_ADS);
                write_frame(send, &MptMessage::Providers { ads }).await?;
                Ok(())
            }
            MptMessage::GetBindings { origin } => {
                // What this peer currently holds bound, live keys only — a
                // lapsed binding is exactly what the asker wants to know is
                // gone (§3.4). Informational within the trusted cluster: the
                // caller is already an authorized member (§3.2, §12).
                let store = self.store().clone();
                let asked = origin.clone();
                let keys =
                    crate::blocking::offload(move || Ok(store.keys_for_origin(&asked, now_ns())?))
                        .await?;
                write_frame(send, &MptMessage::BindingsFor { origin, keys }).await?;
                Ok(())
            }
            other => Err(unexpected("a request", &other)),
        }
    }
}

/// How many payload bytes one `Nodes` or `Values` answer may carry.
///
/// The request is capped at [`MAX_BATCH`] hashes; the answer it draws was capped
/// only by [`MAX_FRAME_LEN`](synch_core::MAX_FRAME_LEN), and discovered to
/// overrun it only *after* `write_frame` had serialized the whole message —
/// which is to say after the responder had already allocated it twice. Applied
/// while the answer is assembled, it is a bound on the work as well as on the
/// wire (§12).
///
/// Half a frame, so the postcard framing and the `missing` list have room and a
/// short answer is never produced for lack of a few hundred bytes.
const ANSWER_BYTE_BUDGET: usize = synch_core::MAX_FRAME_LEN / 2;

/// Resolves a batch of claimed positions and returns what stands at each,
/// refusing the whole request if any position lies outside the peer's scope.
///
/// This is where a scoped peer's view is enforced (§8). The peer says where it
/// believes a node sits; this descends from a root *this* node holds and
/// reports what is really there, so a fabricated root fails at the first step
/// and a lie about the position simply resolves to whatever is genuinely at
/// the path named — which is in scope by construction.
///
/// An out-of-scope position is refused rather than answered `missing`, because
/// it is not a race: an honest peer prunes its own frontier at the boundary
/// and never asks. A request that crosses it is a probe, and saying so is
/// worth more than quietly returning nothing.
fn admit(
    store: &Store,
    peer: NodeId,
    root: Hash,
    wants: &[(Vec<u8>, Hash)],
) -> Result<Vec<Hash>, NetError> {
    let scope = store.scope_for_key(&peer, now_ns())?;
    if !scope.is_full() {
        for (path, _) in wants {
            if !scope.admits_path(path) {
                tracing::warn!(
                    peer = %peer.fmt_short(),
                    "refusing a trie request outside the peer's scope"
                );
                return Err(NetError::Unexpected(
                    "requested a trie position outside this peer's scope".to_string(),
                ));
            }
        }
    }
    // The claimed hash is not what authorizes — the position is — but it is
    // still checked, so that a peer walking a different root than it thinks
    // learns that here rather than by failing verification later.
    let paths: Vec<Vec<u8>> = wants.iter().map(|(path, _)| path.clone()).collect();
    let resolved = Trie::new(store).resolve_paths(root, &paths)?;
    Ok(resolved
        .into_iter()
        .zip(wants.iter())
        .map(|(at, (_, claimed))| at.unwrap_or(*claimed))
        .collect())
}

/// Bounds one positioned batch on both axes.
///
/// The count is capped while decoding, like every other sequence on this wire.
/// The *paths* are not, and they are the axis that began mattering when these
/// requests started carrying positions: a responder descends every path it is
/// handed, so [`MAX_BATCH`] maximal ones would be megabytes of request for
/// megabytes of walking (§12). A real walk's batch shares nearly all of its
/// prefixes and comes nowhere near this.
fn check_wants(wants: &[(Vec<u8>, Hash)]) -> Result<(), NetError> {
    check_batch(wants.len())?;
    let bytes: usize = wants.iter().map(|(path, _)| path.len()).sum();
    if bytes > MAX_BATCH_PATH_BYTES {
        return Err(NetError::Unexpected(format!(
            "batch carries {bytes} path bytes, over the {MAX_BATCH_PATH_BYTES} limit"
        )));
    }
    Ok(())
}

/// A backstop behind the decode-time bound.
///
/// `MptMessage` refuses an over-long field while deserializing, which is what
/// actually caps the cost — this cannot normally fire. It is kept so the
/// responder still states its own contract, and so removing a `#[serde(...)]`
/// attribute does not silently remove the cap with it.
fn check_batch(len: usize) -> Result<(), NetError> {
    if len > MAX_BATCH {
        return Err(NetError::Unexpected(format!(
            "batch of {len} exceeds the {MAX_BATCH} limit"
        )));
    }
    Ok(())
}

/// Bounds a head-carrying message, which `MAX_BATCH` does not cover.
///
/// `GetNodes`/`GetValues` are capped at [`MAX_BATCH`] hashes because a cheap
/// request must not buy expensive work (§12). The head messages need a cap of
/// their own and are the more expensive of the two: bounded only by
/// `MAX_FRAME_LEN` (16 MiB), one `Heads` frame carries on the order of 110 000
/// `SignedHead`s, and each one costs an Ed25519 verification *and* a
/// `head_history` insert — the insert running before the ordering check, so
/// heads that lose the comparison are persisted too. `HeadsWant` is the same
/// shape with a database query per origin. Seconds of CPU and hundreds of
/// thousands of autocommit statements, for 16 MB of upload, repeatable per
/// stream.
///
/// The bound is generous next to any real cluster: §12 sizes membership at
/// N ≤ 100 origins, so a legitimate exchange names tens of heads, not
/// thousands.
/// A backstop behind the decode-time bound, as [`check_batch`] is.
fn check_heads(len: usize, what: &str) -> Result<(), NetError> {
    if len > MAX_HEADS_PER_MESSAGE {
        return Err(NetError::Unexpected(format!(
            "{what} of {len} exceeds the {MAX_HEADS_PER_MESSAGE} limit"
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
    /// The spaces the peer says it will serve us, or `None` for everything.
    pub scope: Option<Vec<String>>,
}

/// A client for the `sync/mpt/1` ALPN, over one established connection.
#[derive(Debug, Clone)]
pub struct MptClient {
    connection: Connection,
    /// How long any one exchange on this connection may wait for its answer.
    deadline: std::time::Duration,
}

impl MptClient {
    /// Wraps an established `sync/mpt/1` connection.
    pub fn new(connection: Connection) -> Self {
        MptClient {
            connection,
            deadline: REQUEST_TIMEOUT,
        }
    }

    /// The same client under a deadline of the caller's choosing, for tests
    /// that need a stall to be reported in milliseconds rather than minutes.
    #[cfg(test)]
    pub(crate) fn with_deadline(mut self, deadline: std::time::Duration) -> Self {
        self.deadline = deadline;
        self
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
        declared: Option<Vec<String>>,
        decide: F,
    ) -> Result<HeadExchange, NetError>
    where
        F: FnOnce(&[HeadSummary]) -> (Vec<SignedHead>, Vec<OriginId>),
    {
        under_deadline(self.deadline, "a head exchange", async {
            let (mut send, mut recv) = self.connection.open_bi().await?;
            write_frame(
                &mut send,
                &MptMessage::Hello {
                    proto: PROTO_VERSION,
                    heads: ours,
                    scope: declared,
                },
            )
            .await?;

            let (summaries, scope) = match read_frame::<MptMessage>(&mut recv).await? {
                MptMessage::Hello {
                    proto,
                    heads,
                    scope,
                } => {
                    if proto != PROTO_VERSION {
                        return Err(NetError::Unexpected(format!(
                            "unsupported protocol version {proto}"
                        )));
                    }
                    check_heads(heads.len(), "a Hello summary list")?;
                    (heads, scope)
                }
                // A responder that refuses says why, and the reason is the
                // error — reading it as a shape mismatch loses the only account
                // of what went wrong the peer will ever give.
                MptMessage::Error { reason } => return Err(NetError::Unexpected(reason)),
                other => return Err(unexpected("Hello", &other)),
            };

            let (push, want) = decide(&summaries);
            let pushed = push.len();
            write_frame(&mut send, &MptMessage::Heads { heads: push }).await?;
            write_frame(&mut send, &MptMessage::HeadsWant { origins: want }).await?;

            let received = match read_frame::<MptMessage>(&mut recv).await? {
                MptMessage::Heads { heads } => {
                    // The answer to our own `HeadsWant` is bounded like every
                    // other head-carrying message, and it is the easiest one to
                    // overlook: the responder caps its `Hello`, its `Heads`
                    // push and its `HeadsWant`, and this side caps the `Hello`
                    // it reads back — but a peer could answer a want-list of
                    // one origin with a full frame of heads, and `sync_with`
                    // offers every one of them, at an Ed25519 verification and
                    // a `head_history` insert apiece. Same rule as `Providers`
                    // on this side.
                    check_heads(heads.len(), "a Heads answer")?;
                    heads
                }
                MptMessage::Error { reason } => return Err(NetError::Unexpected(reason)),
                other => return Err(unexpected("Heads", &other)),
            };
            let _ = send.finish();
            Ok(HeadExchange {
                summaries,
                pushed,
                received,
                scope,
            })
        })
        .await
    }

    /// Pushes a head reactively (§5.3).
    pub async fn push_head(&self, head: &SignedHead) -> Result<(), NetError> {
        under_deadline(self.deadline, "a head push", async {
            let (mut send, mut recv) = self.connection.open_bi().await?;
            write_frame(&mut send, &MptMessage::HeadPush { head: head.clone() }).await?;
            let _ = send.finish();
            match read_frame::<MptMessage>(&mut recv).await? {
                MptMessage::Heads { .. } => Ok(()),
                MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
                other => Err(unexpected("an acknowledgement", &other)),
            }
        })
        .await
    }

    /// Fetches trie nodes by hash.
    ///
    /// At most [`MAX_BATCH`] hashes: the responder refuses a longer request
    /// outright, so a caller that oversteps loses the whole batch rather than
    /// the tail of it. `MissingWalk::next_batch` is the only caller and stops at
    /// the cap.
    pub async fn get_nodes(
        &self,
        root: Hash,
        wants: &[(Vec<u8>, Hash)],
    ) -> Result<NodesResponse, NetError> {
        debug_assert!(wants.len() <= MAX_BATCH, "a batch past the responder's cap");
        let batch: Vec<(Vec<u8>, Hash)> = wants.to_vec();
        under_deadline(self.deadline, "a trie node request", async {
            let (mut send, mut recv) = self.connection.open_bi().await?;
            write_frame(&mut send, &MptMessage::GetNodes { root, wants: batch }).await?;
            let _ = send.finish();
            match read_frame::<MptMessage>(&mut recv).await? {
                MptMessage::Nodes { nodes, missing } => Ok(NodesResponse { nodes, missing }),
                MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
                other => Err(unexpected("Nodes", &other)),
            }
        })
        .await
    }

    /// Fetches out-of-line trie values by hash.
    ///
    /// At most [`MAX_BATCH`] hashes, exactly as [`MptClient::get_nodes`].
    pub async fn get_values(
        &self,
        root: Hash,
        wants: &[(Vec<u8>, Hash)],
    ) -> Result<ValuesResponse, NetError> {
        debug_assert!(wants.len() <= MAX_BATCH, "a batch past the responder's cap");
        let batch: Vec<(Vec<u8>, Hash)> = wants.to_vec();
        under_deadline(self.deadline, "a trie value request", async {
            let (mut send, mut recv) = self.connection.open_bi().await?;
            write_frame(&mut send, &MptMessage::GetValues { root, wants: batch }).await?;
            let _ = send.finish();
            match read_frame::<MptMessage>(&mut recv).await? {
                MptMessage::Values { values, missing } => Ok(ValuesResponse { values, missing }),
                MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
                other => Err(unexpected("Values", &other)),
            }
        })
        .await
    }

    /// Asks a peer who advertises an object, for bootstrapping a cold cache
    /// that holds no `b:` records for it yet (§6.3).
    pub async fn find_providers(
        &self,
        object_root: Hash,
    ) -> Result<Vec<(OriginId, BlobAd)>, NetError> {
        under_deadline(self.deadline, "a provider hint request", async {
            let (mut send, mut recv) = self.connection.open_bi().await?;
            write_frame(&mut send, &MptMessage::FindProviders { object_root }).await?;
            let _ = send.finish();
            match read_frame::<MptMessage>(&mut recv).await? {
                MptMessage::Providers { ads } => {
                    if ads.len() > MAX_PROVIDER_ADS {
                        return Err(NetError::Unexpected(format!(
                            "a Providers answer of {} exceeds the {MAX_PROVIDER_ADS} limit",
                            ads.len()
                        )));
                    }
                    Ok(ads)
                }
                MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
                other => Err(unexpected("Providers", &other)),
            }
        })
        .await
    }

    /// Asks the peer which device keys it currently holds bound for an origin
    /// (§5.1).
    ///
    /// This is how `synch key ls` answers "have my peers picked up the new
    /// binding yet?" — the judgement §3.4 says a rotation's switch-over needs
    /// and that a node cannot make from its own view of DNS.
    pub async fn get_bindings(&self, origin: &OriginId) -> Result<Vec<NodeId>, NetError> {
        under_deadline(self.deadline, "a binding request", async {
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
                } if &answered == origin => {
                    // Bounded like every other list off the wire. A `NodeId`
                    // decodes through `VerifyingKey::from_bytes`, an Edwards
                    // point decompression apiece, so an unbounded answer buys
                    // seconds of curve arithmetic for one small request — the
                    // same shape `Providers` is capped against just below.
                    check_heads(keys.len(), "a BindingsFor answer")?;
                    Ok(keys)
                }
                MptMessage::BindingsFor {
                    origin: answered, ..
                } => Err(NetError::Unexpected(format!(
                    "asked about {origin}, answered about {answered}"
                ))),
                MptMessage::Error { reason } => Err(NetError::Unexpected(reason)),
                other => Err(unexpected("BindingsFor", &other)),
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{bare_endpoint, trusting_pair, ScriptedPeer, StalledPeer};
    use synch_core::{BlobAd, ALPN_MPT};

    /// A sink that refuses one origin's heads and takes every other.
    #[derive(Debug)]
    /// A sink that fails one origin outright, the way a *local* fault does.
    ///
    /// An origin fault — a record this node cannot apply — is contained by the
    /// sink itself, because the sink is the only side that can tell the two
    /// apart (`Syncer`'s `HeadSink` impl). What reaches the wire is the other
    /// kind, and the other kind legitimately ends the stream.
    struct Picky {
        refuse: OriginId,
        offered: std::sync::Mutex<Vec<OriginId>>,
        serving: std::collections::HashMap<OriginId, SignedHead>,
    }

    impl HeadSink for Picky {
        fn local_summaries(&self) -> Result<Vec<HeadSummary>, NetError> {
            Ok(Vec::new())
        }

        fn observe_summaries_from(
            &self,
            _peer: NodeId,
            _summaries: &[HeadSummary],
            _now: i64,
        ) -> Result<(), NetError> {
            Ok(())
        }

        fn offer_head(&self, head: &SignedHead, _now: i64) -> Result<(), NetError> {
            self.offered
                .lock()
                .expect("the lock")
                .push(head.origin.clone());
            if head.origin == self.refuse {
                // What an origin fault looks like from out here: contained by
                // the sink, so the exchange goes on.
                return Ok(());
            }
            Ok(())
        }

        fn heads_for(&self, origins: &[OriginId]) -> Result<Vec<SignedHead>, NetError> {
            Ok(origins
                .iter()
                .filter_map(|origin| self.serving.get(origin).cloned())
                .collect())
        }
    }

    /// How long a test waits before calling a request hung rather than slow.
    const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

    /// A peer that keeps the session open and answers nothing fails the
    /// request instead of holding the caller forever.
    ///
    /// Every client method reads a frame the peer is under no obligation to
    /// send, so each carries its own deadline: what comes back is an ordinary
    /// transport error, which is what puts a stalled peer on the same footing
    /// as an unreachable one — dropped, and the next candidate tried.
    #[tokio::test]
    async fn a_peer_that_answers_nothing_fails_every_request() {
        let peer = StalledPeer::bind(ALPN_MPT).await;
        let dialer = bare_endpoint(ALPN_MPT).await;
        let connection = dialer.connect(peer.addr.clone(), ALPN_MPT).await.unwrap();
        let client =
            MptClient::new(connection).with_deadline(std::time::Duration::from_millis(100));

        let origin = OriginId::named("stalled", "x.example").unwrap();
        let stalled: Vec<(&str, Result<(), NetError>)> = vec![
            (
                "get_nodes",
                tokio::time::timeout(
                    PATIENCE,
                    client.get_nodes(Hash::EMPTY, &[(Vec::new(), Hash::new(b"n"))]),
                )
                .await
                .expect("get_nodes must not hang")
                .map(|_| ()),
            ),
            (
                "get_values",
                tokio::time::timeout(
                    PATIENCE,
                    client.get_values(Hash::EMPTY, &[(Vec::new(), Hash::new(b"v"))]),
                )
                .await
                .expect("get_values must not hang")
                .map(|_| ()),
            ),
            (
                "find_providers",
                tokio::time::timeout(PATIENCE, client.find_providers(Hash::new(b"o")))
                    .await
                    .expect("find_providers must not hang")
                    .map(|_| ()),
            ),
            (
                "get_bindings",
                tokio::time::timeout(PATIENCE, client.get_bindings(&origin))
                    .await
                    .expect("get_bindings must not hang")
                    .map(|_| ()),
            ),
            (
                "head_exchange",
                tokio::time::timeout(
                    PATIENCE,
                    client.head_exchange(Vec::new(), None, |_| (Vec::new(), Vec::new())),
                )
                .await
                .expect("head_exchange must not hang")
                .map(|_| ()),
            ),
        ];
        for (what, outcome) in stalled {
            let err = outcome.expect_err(what);
            assert!(err.to_string().contains("went unanswered"), "{what}: {err}");
        }

        dialer.close().await;
        peer.shutdown().await;
    }

    /// A provider answer past the bound is refused before a row is written.
    ///
    /// Hints are unverified by design, but taking one still costs a row and
    /// nothing in the answer vouches that the origins in it exist — so the
    /// length is checked the way every other batch message's is.
    ///
    /// The refusal now happens *while decoding* (`MptMessage`'s per-field
    /// bounds) rather than on the materialized `Vec`, so the failure is a
    /// decode error rather than the handler's own message. That is the point:
    /// the post-hoc check spent the whole cost of the message before it could
    /// look at the length.
    #[tokio::test]
    async fn a_provider_answer_past_the_bound_is_refused() {
        let ads: Vec<(OriginId, BlobAd)> = (0..MAX_PROVIDER_ADS + 1)
            .map(|i| {
                (
                    OriginId::named(&format!("origin{i}"), "x.example").unwrap(),
                    BlobAd::complete(1000),
                )
            })
            .collect();
        let peer = ScriptedPeer::bind(ALPN_MPT, MptMessage::Providers { ads }).await;
        let dialer = bare_endpoint(ALPN_MPT).await;
        let connection = dialer.connect(peer.addr.clone(), ALPN_MPT).await.unwrap();
        let client = MptClient::new(connection);

        client
            .find_providers(Hash::new(b"object"))
            .await
            .expect_err("an over-long answer is refused");

        // One ad short of the bound is an ordinary answer.
        let ads: Vec<(OriginId, BlobAd)> = (0..MAX_PROVIDER_ADS)
            .map(|i| {
                (
                    OriginId::named(&format!("origin{i}"), "x.example").unwrap(),
                    BlobAd::complete(1000),
                )
            })
            .collect();
        let honest = ScriptedPeer::bind(ALPN_MPT, MptMessage::Providers { ads }).await;
        let connection = dialer.connect(honest.addr.clone(), ALPN_MPT).await.unwrap();
        assert_eq!(
            MptClient::new(connection)
                .find_providers(Hash::new(b"object"))
                .await
                .unwrap()
                .len(),
            MAX_PROVIDER_ADS
        );

        dialer.close().await;
        peer.shutdown().await;
        honest.shutdown().await;
    }

    /// The provider handler does not run SQLite on a runtime worker.
    ///
    /// `FindProviders` takes the single global connection mutex and decodes
    /// every row's spans under it. Run inline on a busy store that is an
    /// unbounded wait on a worker that also drives every other connection,
    /// timer and control request in the process (§10, §12).
    ///
    /// Measured by the runtime's own clock. The stream is opened *before* the
    /// store is made busy, so the per-stream binding check — a single bounded
    /// row read, and inline by design — is already behind us when the request
    /// body lands. What is left on the worker is the handler, and a handler that
    /// blocks it cannot poll the deadline below until the store comes free.
    #[tokio::test]
    async fn find_providers_never_blocks_the_runtime_on_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(synch_store::Store::open(dir.path()).unwrap());
        let root = Hash::new(b"an object someone advertises");
        store
            .put_provider(
                &root,
                &OriginId::named("holder", "x.example").unwrap(),
                &BlobAd::complete(1000),
            )
            .unwrap();
        let (server, client, _client_dir) =
            trusting_pair(store.clone(), crate::endpoint::NetOptions::loopback()).await;
        let mpt = client.connect_mpt(server.direct_addr()).await.unwrap();

        // The header of a `FindProviders`, and nothing else yet: the server has
        // accepted the stream, checked the binding, and is waiting on the body.
        let body = postcard::to_stdvec(&MptMessage::FindProviders { object_root: root }).unwrap();
        let (mut send, mut recv) = mpt.connection().open_bi().await.unwrap();
        send.write_all(&(body.len() as u32).to_le_bytes())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Now a writer takes the one connection, as a publish or a GC pass does.
        const HELD: std::time::Duration = std::time::Duration::from_millis(2_000);
        const PATIENCE: std::time::Duration = std::time::Duration::from_millis(400);
        let busy = store.clone();
        let holding = std::thread::spawn(move || {
            busy.transaction(|_txn| -> Result<(), synch_store::StoreError> {
                std::thread::sleep(HELD);
                Ok(())
            })
            .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        send.write_all(&body).await.unwrap();
        let started = std::time::Instant::now();
        let answer = tokio::time::timeout(PATIENCE, crate::frame::read_bytes(&mut recv)).await;
        assert!(
            answer.is_err(),
            "the answer waits on the store, which is busy"
        );
        assert!(
            started.elapsed() < HELD / 2,
            "the runtime kept its own timers running: {:?}",
            started.elapsed()
        );

        holding.join().unwrap();
        // And once the store is free the answer comes back.
        let ads = tokio::time::timeout(HELD, mpt.find_providers(root))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ads.len(), 1);
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    /// Every offered head reaches the sink, and the want is still answered.
    ///
    /// Containment is the sink's: it is the only side that can tell "this
    /// origin published something we cannot apply" from "our disk is full", and
    /// the string that crosses this seam cannot. So the wire relays the sink's
    /// verdict rather than guessing at one — and a sink that contains, as the
    /// real one does, leaves the exchange free to finish owing this peer an
    /// answer to its `HeadsWant`.
    #[tokio::test]
    async fn a_contained_origin_does_not_stop_a_hello_exchange() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(synch_store::Store::open(dir.path()).unwrap());
        let signer = iroh_base::SecretKey::generate();
        let bad = OriginId::named("bad", "x.example").unwrap();
        let good = OriginId::named("good", "x.example").unwrap();
        let served = OriginId::named("served", "x.example").unwrap();

        // A head the server can hand back when the exchange gets that far.
        let servable = SignedHead::sign(&signer, served.clone(), 3, Hash::new(b"root"), 0);
        let sink = std::sync::Arc::new(Picky {
            refuse: bad.clone(),
            offered: std::sync::Mutex::new(Vec::new()),
            serving: [(served.clone(), servable.clone())].into_iter().collect(),
        });
        let options = crate::endpoint::NetOptions {
            heads: Some(sink.clone() as std::sync::Arc<dyn HeadSink>),
            ..crate::endpoint::NetOptions::loopback()
        };
        let (server, client, _client_dir) = trusting_pair(store.clone(), options).await;

        let pushed = vec![
            SignedHead::sign(&signer, bad.clone(), 1, Hash::new(b"a"), 0),
            SignedHead::sign(&signer, good.clone(), 1, Hash::new(b"b"), 0),
        ];
        let exchange = client
            .connect_mpt(server.direct_addr())
            .await
            .unwrap()
            .head_exchange(Vec::new(), None, move |_| (pushed, vec![served.clone()]))
            .await
            .expect("the exchange completes");

        assert_eq!(
            *sink.offered.lock().unwrap(),
            vec![bad, good],
            "every offered head reaches the sink"
        );
        assert_eq!(
            exchange.received,
            vec![servable],
            "and the want list is still answered"
        );

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    /// A stream that stalls mid-message does not stop the connection serving
    /// the next request.
    ///
    /// The work behind a request runs on the blocking pool, so a connection
    /// that handles its streams one at a time cannot accept the next one while
    /// a window is being built — and a peer that opens a stream and then says
    /// nothing parks it indefinitely. One task per stream under a semaphore and
    /// a deadline is what keeps the session usable either way.
    #[tokio::test]
    async fn a_stalled_stream_does_not_hold_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(synch_store::Store::open(dir.path()).unwrap());
        let (server, client, _client_dir) =
            trusting_pair(store.clone(), crate::endpoint::NetOptions::loopback()).await;
        let mpt = client.connect_mpt(server.direct_addr()).await.unwrap();

        // A frame header promising bytes that never arrive: the responder has
        // accepted the stream and is waiting on the body.
        let (mut stalled, _recv) = mpt.connection().open_bi().await.unwrap();
        stalled.write_all(&64u32.to_le_bytes()).await.unwrap();

        // The next request on the same connection is answered regardless.
        let origin = OriginId::named("nas", "x.example").unwrap();
        let keys = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            mpt.get_bindings(&origin),
        )
        .await
        .expect("a stalled stream must not hold the connection")
        .unwrap();
        assert!(keys.is_empty());

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }
    /// A batch answer is bounded in bytes, not only in hashes.
    ///
    /// Two halves. A full legal batch of ceiling-sized values fits one frame and
    /// is served whole — that is what `MAX_TRIE_VALUE_LEN` buys. And a store that
    /// holds something larger than the ceiling, as one written before the ceiling
    /// existed does, still cannot be made to build an answer past the frame: the
    /// budget is applied while the answer is assembled rather than discovered by
    /// `write_frame` after the whole message has been serialized. A short answer
    /// is ordinary — the requester's walk defers what it asked for and re-offers
    /// whatever did not come back.
    #[tokio::test]
    async fn a_values_answer_is_bounded_in_bytes() {
        // Values are authorized by the position of the node carrying them
        // (§5.5), so the request has to name real positions in a real trie —
        // and the wants are produced the way a requester produces them, by
        // walking a store that holds the nodes and not yet the payloads.
        let plant = |store: &synch_store::Store, root: Hash, len: usize, tag: u64| {
            let mut payload = vec![0u8; len];
            payload[..8].copy_from_slice(&tag.to_le_bytes());
            Trie::new(store)
                .insert(
                    root,
                    &synch_core::file_key("s", &tag.to_string()).unwrap(),
                    &payload,
                )
                .unwrap()
        };
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(synch_store::Store::open(dir.path()).unwrap());

        // A full batch at the value ceiling.
        let mut ceiling_root = Hash::EMPTY;
        for i in 0..MAX_BATCH as u64 {
            ceiling_root = plant(&store, ceiling_root, synch_core::MAX_TRIE_VALUE_LEN, i);
        }
        // And three values from before the ceiling, each half the budget.
        let mut oversized_root = Hash::EMPTY;
        for i in 0..3u64 {
            oversized_root = plant(&store, oversized_root, ANSWER_BYTE_BUDGET / 2, 1_000 + i);
        }

        // The positions a requester would name: every node, none of the values.
        let positions = |root: Hash| -> (tempfile::TempDir, Vec<(Vec<u8>, Hash)>) {
            let dir = tempfile::tempdir().unwrap();
            let bare = synch_store::Store::open(dir.path()).unwrap();
            let reachable = Trie::new(store.as_ref()).reachable(root).unwrap();
            for node in &reachable.nodes {
                let bytes = synch_mpt::NodeStore::get_node(store.as_ref(), node)
                    .unwrap()
                    .unwrap();
                synch_mpt::NodeStore::put_node(&bare, node, &bytes).unwrap();
            }
            let missing = Trie::new(&bare).missing(root, MAX_BATCH).unwrap();
            assert!(missing.nodes.is_empty(), "every node was copied across");
            (dir, missing.values)
        };
        let (_at_dir, at_ceiling) = positions(ceiling_root);
        let (_over_dir, oversized) = positions(oversized_root);
        assert_eq!(at_ceiling.len(), MAX_BATCH);
        assert_eq!(oversized.len(), 3);

        let (server, client, _client_dir) =
            trusting_pair(store.clone(), crate::endpoint::NetOptions::loopback()).await;
        let mpt = client.connect_mpt(server.direct_addr()).await.unwrap();

        let answer = mpt.get_values(ceiling_root, &at_ceiling).await.unwrap();
        assert_eq!(
            answer.values.len(),
            MAX_BATCH,
            "a full batch at the ceiling is served whole"
        );
        assert!(answer.missing.is_empty());

        let answer = mpt.get_values(oversized_root, &oversized).await.unwrap();
        let bytes: usize = answer.values.iter().map(|(_, v)| v.len()).sum();
        assert!(bytes <= ANSWER_BYTE_BUDGET, "{bytes} bytes served");
        assert!(!answer.values.is_empty(), "and it is not empty");
        assert!(
            answer.values.len() < oversized.len(),
            "the budget bit: {} of {}",
            answer.values.len(),
            oversized.len()
        );
        let asked: Vec<Hash> = oversized.iter().map(|(_, hash)| *hash).collect();
        for (hash, payload) in &answer.values {
            assert_eq!(&Hash::new(payload), hash);
            assert!(asked.contains(hash));
        }

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }
}
