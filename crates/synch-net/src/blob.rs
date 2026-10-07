//! The `sync/blob/1` ALPN: verified bao slice transfer (§6.4) and the tree
//! proofs delta sync descends with (`docs/DELTA-SYNC.md` §3.1).
//!
//! The blob ALPN carries nothing but `GetSlice`/`SliceEnd`, `GetProof`/
//! `ProofEnd`, `GetStream` — a run of slice answers on one stream — and the
//! slice and proof bytes themselves. Both `End` messages
//! report what the provider actually had, which is how the fetcher learns exact
//! availability — span summaries in `BlobAd` are hints, not promises.
//!
//! A proof is the same exchange as a slice with the payload left out, and it is
//! deliberately not a protocol of its own: a provider that can serve a group can
//! prove it, because the bao slice it would have sent already carries every
//! hash on that group's path to the root.

use std::sync::Arc;

use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use synch_core::{
    now_ns, proof_nodes_upper_bound, BlobMessage, ChunkRanges, DirectSecret, GroupRange, Hash,
    MAX_PROOF_NODES, MAX_RANGES, MAX_SLICE_GROUPS, STREAM_WINDOW_GROUPS,
};
use synch_store::{
    cas::{Expect, SliceVerifier},
    Proven, Store,
};

use crate::{
    direct::{DirectListener, DirectMemo, DirectSource, RecordWriter, RunKeys, Sealing},
    endpoint::{under_deadline, REQUEST_TIMEOUT},
    error::NetError,
    frame::{read_answer, read_bytes, read_frame, write_bytes, write_frame, write_owned},
};

impl crate::frame::Answer for BlobMessage {
    /// The blob protocol has no in-band refusal frame: a provider that cannot
    /// serve answers with empty served ranges, and one that refuses outright
    /// resets the stream. Every frame is therefore its own answer.
    fn into_refusal(self) -> Result<Self, String> {
        Ok(self)
    }
}

/// How many consecutive empty windows a provider may answer with before a
/// fetch gives up on it and lets the caller try someone else.
const MAX_BARREN_WINDOWS: u32 = 4;

/// The window-retirement rule of a windowed fetch, held once because it must
/// hold on both paths — `fetch_into` and `fetch_proof_into` each documented
/// that their copy retires exactly as the other's does.
///
/// A window is retired whether or not the provider served it, and that is
/// what puts a ceiling on the exchange: one round trip per window,
/// `ceil(ranges / window)` of them, rather than one per *group the provider
/// felt like serving*. Retiring only what came back would leave no ceiling at
/// all — a provider answering each request with one valid group is never
/// barren, so [`MAX_BARREN_WINDOWS`] never fires and the deadline is per
/// exchange: the loop would run once per group of the object, millions of
/// times for a large one, and each turn costs the victim disk work and a
/// write-connection transaction (`docs/DELTA-SYNC.md` §3.3).
///
/// Nothing honest needs a second look at a window: a partial holder answers
/// `requested ∩ held` for the whole of it in one exchange, and what it did
/// not hold this time it will not hold on the next ask either. Ranges it left
/// behind stay visible to the caller through the outcome it accumulates, so
/// another provider still gets asked.
struct WindowedWalk {
    remaining: ChunkRanges,
    barren: u32,
}

/// What retiring one window tells the fetch loop to do.
enum WalkStep {
    /// The provider served something: commit it, then take the next window.
    Commit,
    /// An empty answer, not yet enough of them to give up.
    NextWindow,
    /// [`MAX_BARREN_WINDOWS`] consecutive empty answers: a provider that
    /// claims an object and serves none of it must not hold a fetch in an
    /// unbounded walk across the whole thing; the caller has other candidates.
    GiveUp,
}

impl WindowedWalk {
    fn over(ranges: &ChunkRanges) -> WindowedWalk {
        WindowedWalk {
            remaining: ChunkRanges::from_ranges(ranges.ranges.iter().copied()),
            barren: 0,
        }
    }

    /// Retires `window` — either way — given what the provider served in it.
    fn retire(&mut self, window: &ChunkRanges, served: &ChunkRanges) -> WalkStep {
        self.remaining = self.remaining.difference(window);
        if !served.is_empty() {
            self.barren = 0;
            return WalkStep::Commit;
        }
        self.barren += 1;
        match self.barren >= MAX_BARREN_WINDOWS {
            true => WalkStep::GiveUp,
            false => WalkStep::NextWindow,
        }
    }
}

/// The largest prefix of `remaining` whose proof fits one exchange.
///
/// Sized by [`proof_nodes_upper_bound`], so a provider holding everything
/// asked for still comes in under [`MAX_PROOF_NODES`] and never truncates.
/// Ranges are taken whole where they fit and split where they do not, and
/// the count is clamped to [`MAX_RANGES`] so the set operations under it
/// stay cheap on both sides (§12).
///
/// Public because a caller walking a large region in rounds has to cut it the
/// same way: what fits depends on the level and on how fragmented the ranges
/// are — a contiguous run costs one node per subtree plus a root path, a
/// scattered set costs a root path each — so any second answer to "how much
/// per round?" would disagree with this one.
pub fn proof_window(remaining: &ChunkRanges, level: u8) -> ChunkRanges {
    let mut taken: Vec<synch_core::GroupRange> = Vec::new();
    for range in remaining.ranges.iter().take(MAX_RANGES) {
        let candidate = ChunkRanges::from_ranges(taken.iter().copied().chain([*range]));
        if proof_nodes_upper_bound(&candidate, level) <= MAX_PROOF_NODES {
            taken.push(*range);
            continue;
        }
        // This range does not fit whole. Take as much of its head as does,
        // which is at worst nothing — in which case the window is what we have.
        let mut lo = range.start;
        let mut hi = range.end;
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            let probe = ChunkRanges::from_ranges(
                taken
                    .iter()
                    .copied()
                    .chain([synch_core::GroupRange::new(range.start, mid)]),
            );
            if proof_nodes_upper_bound(&probe, level) <= MAX_PROOF_NODES {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        if lo > range.start {
            taken.push(synch_core::GroupRange::new(range.start, lo));
        }
        break;
    }
    if taken.is_empty() {
        // Even one group does not fit the budget, which only happens for a
        // degenerate level; ask for a single group so the walk still advances.
        if let Some(first) = remaining.ranges.first() {
            taken.push(synch_core::GroupRange::new(first.start, first.start + 1));
        }
    }
    ChunkRanges::from_ranges(taken)
}

/// Validates what a provider says it served, before any set operation reads it.
///
/// Two bounds, and the request itself supplies both:
///
/// - **Range count.** The provider side rejects a request past [`MAX_RANGES`]
///   because the set operations under it are quadratic in the number of ranges
///   and the asker would not be paying for them (§12). The same holds in
///   reverse: `served` is decoded from a frame, so a provider could answer with
///   a million singleton ranges, and the requester intersects it on a runtime
///   worker.
/// - **Containment.** A provider can only have served what was asked for.
///   Anything outside the request is at best noise the requester would union
///   into its progress, and at worst a claim carried straight into
///   `write_slice` — so the slice path and the proof path both intersect it
///   away here, rather than one of them.
fn check_served(served: ChunkRanges, requested: &ChunkRanges) -> Result<ChunkRanges, NetError> {
    if served.range_count() > MAX_RANGES {
        return Err(NetError::Unexpected(format!(
            "provider claims {} served ranges, past the {MAX_RANGES} limit",
            served.range_count()
        )));
    }
    Ok(served.intersect(requested))
}

/// The `sync/blob/1` protocol handler.
#[derive(Debug, Clone)]
pub(crate) struct BlobProtocol {
    store: Arc<Store>,
    backend: Arc<dyn synch_store::backend::CasBackend>,
    on_unknown_key: Option<Arc<tokio::sync::Notify>>,
    /// The endpoint-wide in-flight gate, shared with every other ALPN mounted
    /// on this endpoint (`crate::serve::Inflight`).
    inflight: crate::serve::Inflight,
    /// The direct-TCP listener, when this node was started with one
    /// (`docs/DIRECT-TCP.md`).
    direct: Option<Arc<DirectListener>>,
}

impl BlobProtocol {
    /// Builds a handler over a store.
    pub(crate) fn new(
        store: Arc<Store>,
        backend: Arc<dyn synch_store::backend::CasBackend>,
    ) -> Self {
        BlobProtocol {
            store,
            backend,
            on_unknown_key: None,
            inflight: None,
            direct: None,
        }
    }

    /// Answers `GetDirect` with offers on `listener`.
    pub(crate) fn direct(mut self, listener: Option<Arc<DirectListener>>) -> Self {
        self.direct = listener;
        self
    }

    /// Gates this handler on the endpoint-wide in-flight semaphore.
    pub(crate) fn inflight(mut self, gate: crate::serve::Inflight) -> Self {
        self.inflight = gate;
        self
    }

    /// Rings `wake` whenever a connection is refused for an unknown key (§3.4).
    pub(crate) fn on_unknown_key(mut self, wake: Option<Arc<tokio::sync::Notify>>) -> Self {
        self.on_unknown_key = wake;
        self
    }
}

impl ProtocolHandler for BlobProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let handler = self.clone();
        // Answers go out in the order they were asked for. A requester with
        // several windows in flight hands them on in order, so a stream
        // round-robined against the ones behind it would only finish later —
        // and with it the read waiting on it — while costing the same to send.
        let asked = Arc::new(std::sync::atomic::AtomicI64::new(0));
        // A direct run's key lives no longer than the connection it was
        // offered on, so its stream's handler watches the connection.
        let held = connection.clone();
        crate::serve::serve_connection(
            &self.store.clone(),
            connection,
            self.on_unknown_key.as_ref(),
            &self.inflight,
            |_| std::future::ready(()),
            move |peer, mut send, mut recv, progress| {
                let handler = handler.clone();
                let connection = held.clone();
                let order = asked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _ = send.set_priority(i32::try_from(-order).unwrap_or(i32::MIN));
                async move {
                    if let Err(e) = handler
                        .handle_stream(peer, &connection, &mut send, &mut recv, &progress)
                        .await
                    {
                        tracing::debug!(error = %e, "blob stream ended");
                    }
                    let _ = send.finish();
                }
            },
        )
        .await
    }
}

impl BlobProtocol {
    /// Refuses an object a delegated peer has no granted path to (§3.5).
    ///
    /// `GetSlice` is keyed by object root and carries no space, so
    /// entitlement to the bytes has to be looked up: does any entry in one of
    /// this peer's granted spaces name this content?
    ///
    /// A rooted peer is unrestricted, but finding that out still costs a
    /// bindings read, and this runs once per slice — thousands of times across
    /// one large object. The cheap half of the answer is asked first: a store
    /// holding no delegation at all cannot have a scoped peer, which is the
    /// state of every cluster that does not use the feature.
    async fn check_content_scope(
        &self,
        peer: synch_core::NodeId,
        root: synch_core::Hash,
    ) -> Result<(), NetError> {
        let store = self.store.clone();
        let permitted = crate::blocking::offload(move || {
            if !store.has_delegations()? {
                return Ok(true);
            }
            let (scope, origins) =
                store.publish_scope_of_key_with_origins(&peer, synch_core::now_ns())?;
            let spaces = match scope {
                // A peer with no live binding gets nothing. The dial gate has
                // already refused it, so this is the second lock on the same
                // door rather than the only one — but it is the lock that would
                // matter if a binding lapsed mid-session.
                synch_store::PublishScope::Untrusted => return Ok(false),
                synch_store::PublishScope::Unrestricted => return Ok(true),
                synch_store::PublishScope::Confined(spaces) => spaces,
            };
            Ok(store.content_in_spaces(&root, &spaces, &origins)?)
        })
        .await?;
        match permitted {
            true => Ok(()),
            false => {
                tracing::warn!(
                    peer = %peer.fmt_short(),
                    "refusing content outside the peer's delegated spaces"
                );
                Err(NetError::Unexpected(
                    "requested an object outside this peer's scope".to_string(),
                ))
            }
        }
    }

    async fn handle_stream(
        &self,
        peer: synch_core::NodeId,
        connection: &Connection,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
        progress: &crate::serve::Progress,
    ) -> Result<(), NetError> {
        match read_frame::<BlobMessage>(recv).await? {
            BlobMessage::GetStream { root, run } => {
                self.serve_run(peer, &mut Sink::Quic(send), root, run, progress)
                    .await
            }
            BlobMessage::GetDirect { root, run } => {
                self.serve_direct(peer, connection, send, root, run, progress)
                    .await
            }
            BlobMessage::GetSlice { root, ranges } => {
                self.check_content_scope(peer, root).await?;
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
                let backend = self.backend.clone();
                let (encoded, served) = match backend.encode_slice(root, ranges).await {
                    Ok(pair) => pair,
                    Err(synch_store::StoreError::MissingBlob(_)) => {
                        (Vec::new(), ChunkRanges::empty())
                    }
                    Err(e) => return Err(e.into()),
                };
                write_owned(send, encoded).await?;
                write_frame(send, &BlobMessage::SliceEnd { served }).await?;
                Ok(())
            }
            BlobMessage::GetProof {
                root,
                ranges,
                level,
            } => {
                self.check_content_scope(peer, root).await?;
                // Bounded before anything reads it, for the same reason a slice
                // request is: the set operations under it are quadratic in the
                // number of ranges (§12).
                if ranges.range_count() > MAX_RANGES {
                    return Err(NetError::Unexpected(format!(
                        "proof request of {} ranges exceeds the {MAX_RANGES} limit",
                        ranges.range_count()
                    )));
                }
                let ranges = ChunkRanges::from_ranges(ranges.ranges.iter().copied());
                // Cheaper than a slice — a proof of a 16 MiB span is 32 bytes —
                // but it still walks a tree and reads an outboard off disk, and
                // the leaf-level round over a large edit walks a lot of one. It
                // goes to the blocking pool with everything else (§10).
                let backend = self.backend.clone();
                let (encoded, served) = match backend
                    .encode_proof(root, ranges, level, MAX_PROOF_NODES)
                    .await
                {
                    Ok(pair) => pair,
                    Err(synch_store::StoreError::MissingBlob(_)) => {
                        (Vec::new(), ChunkRanges::empty())
                    }
                    Err(e) => return Err(e.into()),
                };
                write_bytes(send, &encoded).await?;
                write_frame(send, &BlobMessage::ProofEnd { served }).await?;
                Ok(())
            }
            BlobMessage::SliceEnd { .. }
            | BlobMessage::ProofEnd { .. }
            | BlobMessage::DirectOffer { .. } => Err(NetError::Unexpected(
                "an End message or an offer is a response, not a request".into(),
            )),
        }
    }

    /// Answers a [`BlobMessage::GetStream`]: the run, a window of
    /// [`STREAM_WINDOW_GROUPS`] at a time, each exactly as a `GetSlice` for it
    /// would be answered, until the run ends or a window comes back short
    /// (§6.4).
    ///
    /// Every window is a fresh decision of the serve command, and before each
    /// one is encoded it meets the checks a separate request would: the
    /// peer's binding (§3.2) and its content scope (§3.5). A binding revoked
    /// mid-run therefore ends the run at the next window rather than at its
    /// end. Windows are encoded up to [`ENCODE_AHEAD`] ahead of the one being
    /// sent, so reading the payload off disk overlaps the sending; a window
    /// is only checked when it is about to be sent, so nothing encoded ahead
    /// reaches a peer whose binding lapsed in the meantime. The transport's
    /// flow control keeps the provider from running further ahead than that,
    /// so a run costs at most that many encoded windows, plus the one being
    /// sent, whatever its length.
    async fn serve_run(
        &self,
        peer: synch_core::NodeId,
        sink: &mut Sink<'_>,
        root: Hash,
        run: GroupRange,
        progress: &crate::serve::Progress,
    ) -> Result<(), NetError> {
        let window_at = |start: u64| {
            GroupRange::new(
                start,
                run.end.min(start.saturating_add(STREAM_WINDOW_GROUPS)),
            )
        };
        let mut next = window_at(run.start);
        if next.is_empty() {
            return Ok(());
        }
        // The first window is checked before any reading at all, so a peer
        // that may not have the run costs no disk.
        self.admit_window(peer, root).await?;
        let mut checked = true;
        let mut ahead = std::collections::VecDeque::new();
        loop {
            while ahead.len() < ENCODE_AHEAD && !next.is_empty() {
                ahead.push_back((next, self.encode_ahead(root, next)));
                next = window_at(next.end);
            }
            let Some((window, mut encoding)) = ahead.pop_front() else {
                break;
            };
            let (encoded, served) = (&mut encoding.0)
                .await
                .map_err(|e| NetError::Blocking(e.to_string()))??;
            if !checked {
                self.admit_window(peer, root).await?;
            }
            checked = false;
            let whole = served == ChunkRanges::from_ranges([window]);
            sink.send_window(encoded, served).await?;
            progress.mark();
            if !whole {
                // A partial holder's last word: what was encoded past it does
                // not continue it.
                break;
            }
        }
        sink.flush().await
    }

    /// Answers a [`BlobMessage::GetDirect`] (`docs/DIRECT-TCP.md`): offers a
    /// ticket and a fresh key, waits for the requester's TCP connection, and
    /// serves the run over it exactly as [`BlobProtocol::serve_run`] serves
    /// one on QUIC.
    ///
    /// Declines — ends the stream without a byte, which sends the requester
    /// to `GetStream` — when this node has no listener, the run is empty or
    /// longer than one key may carry, or the connection is relayed, so there
    /// is no direct path for the requester to dial.
    ///
    /// The key and the ticket live in this future and nowhere else that
    /// outlasts it, and it ends when the run does, when the requester stops
    /// the stream, or when the QUIC connection closes — whichever is first.
    /// That is what ties the key to the connection: a binding revoked
    /// mid-run closes the connection (`serve::still_admitted`), and the key
    /// and the TCP connection go with it, not at the next window.
    async fn serve_direct(
        &self,
        peer: synch_core::NodeId,
        connection: &Connection,
        send: &mut iroh::endpoint::SendStream,
        root: Hash,
        run: GroupRange,
        progress: &crate::serve::Progress,
    ) -> Result<(), NetError> {
        let Some(listener) = self.direct.clone() else {
            return Ok(());
        };
        if run.is_empty()
            || !crate::direct::within_key_limit(run)
            || crate::direct::direct_path(connection).is_none()
        {
            return Ok(());
        }
        self.admit_window(peer, root).await?;
        let ticket = crate::direct::draw()?;
        let secret = DirectSecret::from_bytes(crate::direct::draw()?);
        let (hello, key) = RunKeys::derive(&secret, &ticket, root, run).split()?;
        let (ticket_held, delivered) = listener.register(ticket, hello);
        crate::direct::write_offer(
            send,
            &BlobMessage::DirectOffer {
                port: listener.port(),
                ticket,
                secret,
            },
            crate::direct::OFFER_FRAME_MAX,
        )
        .await?;

        let stopped = send.stopped();
        tokio::pin!(stopped);
        let closed = connection.closed();
        tokio::pin!(closed);
        let socket = tokio::select! {
            delivered = tokio::time::timeout(crate::direct::accept_timeout(), delivered) => {
                match delivered {
                    Ok(Ok(socket)) => socket,
                    _ => return Ok(()),
                }
            }
            _ = &mut stopped => return Ok(()),
            _ = &mut closed => return Ok(()),
        };
        drop(ticket_held);
        let mut writer = RecordWriter::new(socket, key);
        let mut sink = Sink::Direct {
            writer: &mut writer,
            sealing: None,
        };
        tokio::select! {
            served = self.serve_run(peer, &mut sink, root, run, progress) => served?,
            _ = &mut stopped => {
                return Err(NetError::Direct("the requester stopped the run".into()))
            }
            _ = &mut closed => {
                return Err(NetError::Direct("the QUIC connection closed under the run".into()))
            }
        }
        writer.finish().await
    }

    /// The checks a window of a streamed run meets before it is encoded,
    /// which are the ones a request of its own would have met.
    async fn admit_window(&self, peer: synch_core::NodeId, root: Hash) -> Result<(), NetError> {
        if !crate::serve::trusted(&self.store, &peer).await {
            return Err(NetError::Untrusted(peer.fmt_short().to_string()));
        }
        self.check_content_scope(peer, root).await
    }

    /// Starts encoding one window of a streamed run, as a slice request for
    /// exactly that window would be served.
    fn encode_ahead(&self, root: Hash, window: GroupRange) -> Encoding {
        let backend = self.backend.clone();
        Encoding(tokio::spawn(async move {
            match backend
                .encode_slice(root, ChunkRanges::from_ranges([window]))
                .await
            {
                Ok(pair) => Ok(pair),
                Err(synch_store::StoreError::MissingBlob(_)) => {
                    Ok((Vec::new(), ChunkRanges::empty()))
                }
                Err(e) => Err(e.into()),
            }
        }))
    }
}

/// How many windows of a streamed run are encoded ahead of the one being
/// sent.
///
/// Encoding a window is mostly reading its payload, and one window at a
/// time leaves the run waiting on the disk's latency between windows
/// whenever the payload is not cached.
const ENCODE_AHEAD: usize = 4;

/// A window of a streamed run being encoded ahead of the one being sent.
///
/// A run that ends early — the requester hung up, a check failed — takes the
/// encoding it started with it.
struct Encoding(tokio::task::JoinHandle<Result<(Vec<u8>, ChunkRanges), NetError>>);

impl Drop for Encoding {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Where a streamed run's answer goes: the QUIC stream that asked for it, or
/// a direct run's TCP connection. The bytes are the same either way.
enum Sink<'a> {
    Quic(&'a mut iroh::endpoint::SendStream),
    Direct {
        writer: &'a mut RecordWriter,
        /// The window sealing while the one before it is sent.
        sealing: Option<Sealing>,
    },
}

impl Sink<'_> {
    /// Sends one window's answer: its length-prefixed encoding, then its
    /// `SliceEnd`. On a direct run the window is sealed off this task and
    /// sent once the next one has been handed over, so sealing one window
    /// and sending the one before it run side by side.
    async fn send_window(&mut self, encoded: Vec<u8>, served: ChunkRanges) -> Result<(), NetError> {
        let end = BlobMessage::SliceEnd { served };
        match self {
            Sink::Quic(send) => {
                write_owned(send, encoded).await?;
                write_frame(send, &end).await
            }
            Sink::Direct { writer, sealing } => {
                if encoded.len() > synch_core::MAX_FRAME_LEN {
                    return Err(NetError::FrameTooLarge(encoded.len()));
                }
                let prefix = (encoded.len() as u32).to_le_bytes().to_vec();
                let body =
                    postcard::to_stdvec(&end).map_err(|e| NetError::Encode(e.to_string()))?;
                let mut framed = Vec::with_capacity(4 + body.len());
                framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
                framed.extend_from_slice(&body);
                let next = writer.seal_ahead(vec![prefix, encoded, framed])?;
                match sealing.replace(next) {
                    Some(previous) => writer.write_sealed(previous).await,
                    None => Ok(()),
                }
            }
        }
    }

    /// Sends whatever window is still sealing.
    async fn flush(&mut self) -> Result<(), NetError> {
        match self {
            Sink::Quic(_) => Ok(()),
            Sink::Direct { writer, sealing } => match sealing.take() {
                Some(last) => writer.write_sealed(last).await,
                None => Ok(()),
            },
        }
    }
}

/// Where a streamed run's answer comes from: the QUIC stream it was asked
/// on, or a direct run's TCP connection.
#[derive(Debug)]
enum Source {
    Quic(iroh::endpoint::RecvStream),
    Direct(Box<DirectSource>),
}

impl Source {
    /// Fills `buf`, or `false` when the answer ended cleanly before its
    /// first byte.
    async fn read_or_end(&mut self, buf: &mut [u8]) -> Result<bool, NetError> {
        match self {
            Source::Quic(recv) => match recv.read_exact(buf).await {
                Ok(()) => Ok(true),
                Err(iroh::endpoint::ReadExactError::FinishedEarly(0)) => Ok(false),
                Err(e) => Err(e.into()),
            },
            Source::Direct(source) => source.read_or_end(buf).await,
        }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), NetError> {
        match self.read_or_end(buf).await? {
            true => Ok(()),
            false if buf.is_empty() => Ok(()),
            false => Err(NetError::Read("the answer ended early".into())),
        }
    }

    /// Reads one length-framed message.
    async fn read_message(&mut self) -> Result<BlobMessage, NetError> {
        let mut prefix = [0u8; 4];
        self.read_exact(&mut prefix).await?;
        let len = u32::from_le_bytes(prefix) as usize;
        if len > synch_core::MAX_FRAME_LEN {
            return Err(NetError::FrameTooLarge(len));
        }
        let mut body = vec![0u8; len];
        self.read_exact(&mut body).await?;
        postcard::from_bytes(&body).map_err(|e| NetError::Decode(e.to_string()))
    }
}

/// A client for the `sync/blob/1` ALPN, over one established connection.
#[derive(Debug, Clone)]
pub struct BlobClient {
    connection: Connection,
    /// How long any one exchange on this connection may wait for its answer.
    deadline: std::time::Duration,
    /// Present when this node asks for direct runs, with the peers whose
    /// direct path did not work (`docs/DIRECT-TCP.md`).
    direct: Option<Arc<DirectMemo>>,
}

/// A received slice, together with what the provider actually served.
#[derive(Debug, Clone)]
pub struct Slice {
    /// The bao-encoded slice bytes.
    pub encoded: Vec<u8>,
    /// The ranges the provider had, which is what the encoding covers.
    pub served: ChunkRanges,
}

/// A received proof, together with what the provider actually served.
#[derive(Debug, Clone)]
pub struct Proof {
    /// The pre-order node pairs.
    pub encoded: Vec<u8>,
    /// The ranges the proof covers.
    pub served: ChunkRanges,
}

/// What a run of proof exchanges established (`docs/DELTA-SYNC.md` §3.3).
#[derive(Debug, Clone)]
pub struct ProofOutcome {
    /// The subtrees whose chaining values are now proven against the root, in
    /// tree order — one per group at level 0, one per span higher up, with the
    /// root they were chained to.
    pub proven: Proven,
    /// The ranges they cover, which is what the requester can stop asking for.
    pub served: ChunkRanges,
}

impl BlobClient {
    /// Wraps an established `sync/blob/1` connection.
    pub fn new(connection: Connection) -> Self {
        BlobClient {
            connection,
            deadline: REQUEST_TIMEOUT,
            direct: None,
        }
    }

    /// The same client, asking for direct runs where it can.
    pub(crate) fn with_direct(mut self, memo: Option<Arc<DirectMemo>>) -> Self {
        self.direct = memo;
        self
    }

    /// Whether a direct run is worth asking this provider for: this node
    /// opted in, and the provider's direct path has not lately failed.
    pub fn direct_enabled(&self) -> bool {
        match &self.direct {
            Some(memo) => !memo.refused(&self.connection.remote_id()),
            None => false,
        }
    }

    /// The same client under a deadline of the caller's choosing, for tests
    /// that need a stall to be reported in milliseconds rather than minutes.
    #[cfg(test)]
    pub(crate) fn with_deadline(mut self, deadline: std::time::Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// The peer's device key.
    pub fn remote_id(&self) -> synch_core::NodeId {
        self.connection.remote_id()
    }

    /// Requests a verified slice.
    pub async fn get_slice(&self, root: Hash, ranges: &ChunkRanges) -> Result<Slice, NetError> {
        under_deadline(self.deadline, "a slice request", async {
            let request = BlobMessage::GetSlice {
                root,
                ranges: ranges.clone(),
            };
            let (encoded, end) = self.body_and_end(&request).await?;
            let served = match end {
                BlobMessage::SliceEnd { served } => check_served(served, ranges)?,
                _ => return Err(NetError::Unexpected("expected SliceEnd".into())),
            };
            Ok(Slice { encoded, served })
        })
        .await
    }

    /// Streams one window of an object and verifies it as it arrives, writing
    /// nothing (§6.4): the transient read's half of a slice exchange.
    ///
    /// Each parent node and each group is checked against the root the moment
    /// it is off the stream, and the payload lands in pieces of `piece` bytes
    /// rounded up to whole groups. A provider holding the whole window says so
    /// in its length prefix; any other answer is a partial holder's, read whole
    /// and verified against the run its `SliceEnd` names. Either way the answer
    /// is the verified run starting at `window.start`, or `None` when the
    /// provider served nothing usable there.
    pub async fn read_window(
        &self,
        root: Hash,
        size: u64,
        window: GroupRange,
        piece: usize,
    ) -> Result<Option<Vec<Vec<u8>>>, NetError> {
        under_deadline(self.deadline, "a slice request", async {
            let request = BlobMessage::GetSlice {
                root,
                ranges: ChunkRanges::from_ranges([window]),
            };
            let recv = crate::frame::request(&self.connection, &request).await?;
            let mut source = Source::Quic(recv);
            let len = read_window_len(&mut source)
                .await?
                .ok_or_else(|| NetError::Read("the slice ended before it began".into()))?;
            read_window_answer(&mut source, root, size, window, len, piece).await
        })
        .await
    }

    /// Asks for one contiguous run of an object as a single stream
    /// ([`BlobMessage::GetStream`]), to be read a window at a time with
    /// [`RunStream::next_window`] and verified exactly as
    /// [`BlobClient::read_window`] verifies one window (§6.4).
    ///
    /// One request for the whole run, where windows asked for one by one cost
    /// a request each and kept the provider waiting between them.
    pub async fn stream_run(
        &self,
        root: Hash,
        size: u64,
        run: GroupRange,
        piece: usize,
    ) -> Result<RunStream, NetError> {
        let request = BlobMessage::GetStream { root, run };
        let recv = under_deadline(
            self.deadline,
            "a stream request",
            crate::frame::request(&self.connection, &request),
        )
        .await?;
        Ok(RunStream::over(
            Source::Quic(recv),
            root,
            size,
            run,
            piece,
            self.deadline,
        ))
    }

    /// Asks for one contiguous run of an object over a direct TCP connection
    /// (`docs/DIRECT-TCP.md`), read exactly as a [`BlobClient::stream_run`]
    /// is.
    ///
    /// Fails with [`NetError::Direct`] when the path is not there — this node
    /// did not opt in, the connection is relayed, the provider makes no
    /// offer, its port does not accept — and the caller asks with
    /// [`BlobClient::stream_run`] instead. A provider whose path did not
    /// work is not asked again for a while.
    ///
    /// The run's key arrives in the offer, on this connection, and lives no
    /// longer than it: closing the connection destroys the key and fails
    /// the next read.
    pub async fn stream_run_direct(
        &self,
        root: Hash,
        size: u64,
        run: GroupRange,
        piece: usize,
    ) -> Result<RunStream, NetError> {
        let Some(memo) = self.direct.clone() else {
            return Err(NetError::Direct(
                "this node does not ask for direct runs".into(),
            ));
        };
        let peer = self.connection.remote_id();
        if memo.refused(&peer) {
            return Err(NetError::Direct(
                "the provider's direct path failed lately".into(),
            ));
        }
        let Some(mut addr) = crate::direct::direct_path(&self.connection) else {
            return Err(NetError::Direct("the connection has no direct path".into()));
        };
        let (control, offer) = under_deadline(self.deadline, "a direct run offer", async {
            let mut recv =
                crate::frame::request(&self.connection, &BlobMessage::GetDirect { root, run })
                    .await?;
            let offer =
                crate::direct::read_offer(&mut recv, crate::direct::OFFER_FRAME_MAX).await?;
            Ok((recv, offer))
        })
        .await?;
        let (port, ticket, secret) = match offer {
            Some(BlobMessage::DirectOffer {
                port,
                ticket,
                secret,
            }) => (port, ticket, secret),
            Some(_) => return Err(NetError::Unexpected("expected DirectOffer".into())),
            None => {
                memo.refuse(peer);
                return Err(NetError::Direct(
                    "the provider makes no direct offer".into(),
                ));
            }
        };
        let (hello, key) = RunKeys::derive(&secret, &ticket, root, run).split()?;
        drop(secret);
        addr.set_port(port);
        let socket = match crate::direct::dial(addr, &ticket, &hello).await {
            Ok(socket) => socket,
            Err(error) => {
                memo.refuse(peer);
                return Err(error);
            }
        };
        drop(hello);
        let source = DirectSource::new(socket, key, self.connection.clone(), control, memo);
        Ok(RunStream::over(
            Source::Direct(Box::new(source)),
            root,
            size,
            run,
            piece,
            self.deadline,
        ))
    }

    /// Requests the tree over a range, without its bytes.
    pub(crate) async fn get_proof(
        &self,
        root: Hash,
        ranges: &ChunkRanges,
        level: u8,
    ) -> Result<Proof, NetError> {
        under_deadline(self.deadline, "a proof request", async {
            let request = BlobMessage::GetProof {
                root,
                ranges: ranges.clone(),
                level,
            };
            let (encoded, end) = self.body_and_end(&request).await?;
            let served = match end {
                BlobMessage::ProofEnd { served } => check_served(served, ranges)?,
                _ => return Err(NetError::Unexpected("expected ProofEnd".into())),
            };
            Ok(Proof { encoded, served })
        })
        .await
    }

    /// Runs one blob exchange: the request, then the raw body and its End
    /// frame — the answer shape both blob requests share.
    async fn body_and_end(
        &self,
        request: &BlobMessage,
    ) -> Result<(Vec<u8>, BlobMessage), NetError> {
        let mut recv = crate::frame::request(&self.connection, request).await?;
        let encoded = read_bytes(&mut recv).await?;
        let end = read_answer::<BlobMessage>(&mut recv).await?;
        Ok((encoded, end))
    }

    /// Requests the tree over a range and commits it to the local CAS,
    /// verifying every node against the object root before anything is stored.
    ///
    /// The counterpart of [`BlobClient::fetch_into`] for the descent that comes
    /// *before* a fetch (`docs/DELTA-SYNC.md` §3.3): it answers "what does this
    /// object's tree look like here?", and the answer is what lets the caller
    /// discover that most of the object is already on this disk under another
    /// name. A provider serves one window of nodes per exchange, so a large
    /// range is walked window by window; each is verified and committed as it
    /// arrives, so an interrupted descent keeps what it proved.
    ///
    /// Accumulates into `out`, which the caller owns, and reports how the
    /// descent ended.
    ///
    /// The accumulator is caller-owned so a failure part-way through preserves
    /// every `ProvenSubtree` already received for `Store::promote`.
    pub async fn fetch_proof_into(
        &self,
        backend: &Arc<dyn synch_store::backend::CasBackend>,
        root: Hash,
        size: u64,
        ranges: &ChunkRanges,
        level: u8,
        out: &mut ProofOutcome,
    ) -> Result<(), NetError> {
        let mut walk = WindowedWalk::over(ranges);
        while !walk.remaining.is_empty() {
            // The window is the *requester's* to choose, and it is chosen so
            // the provider never has to truncate.
            //
            // Leaving it to the provider — offering the whole remainder and
            // letting `ProofEnd` report how much came back — makes an honest
            // short answer indistinguishable from a provider dribbling one
            // node per round trip, and forces the provider to discard a
            // truncated walk and redo it over the ranges that fit so both
            // sides agree node for node. All of that assumes the split is
            // unpredictable. It is not: the cost of a walk is bounded
            // by its ranges and level, and while the provider walks
            // `requested ∩ what it holds` — which we cannot know — a subset
            // never costs more than the whole. Sizing the window to fit
            // assuming a full holder therefore fits for every holder.
            let window = proof_window(&walk.remaining, level);
            let proof = self.get_proof(root, &window, level).await?;
            // Already clamped to the window by `check_served`.
            let served = proof.served.clone();
            match walk.retire(&window, &served) {
                WalkStep::GiveUp => break,
                WalkStep::NextWindow => continue,
                WalkStep::Commit => {}
            }
            let backend = backend.clone();
            let encoded = proof.encoded;
            let for_store = served.clone();
            // The fold goes over with the write it belongs to. `absorb`
            // deduplicates against everything proven so far, which for a
            // multi-window object is real CPU on whatever thread runs it —
            // and it touches no store connection, so leaving it out here put
            // it somewhere §10's checker cannot see.
            let mut carried = std::mem::replace(&mut out.proven, Proven::none(root, size));
            let proven = backend
                .write_proof(root, size, for_store, level, encoded, now_ns())
                .await?;
            out.proven = crate::blocking::offload(move || {
                carried.absorb(proven)?;
                Ok(carried)
            })
            .await?;
            out.served = out.served.union(&served);
        }
        Ok(())
    }

    /// Requests a slice and commits it to the local CAS, verifying every group
    /// against the object root before anything is stored.
    ///
    /// A provider serves at most [`MAX_SLICE_GROUPS`] groups per exchange, so
    /// anything larger is walked one window at a time until the request is
    /// covered — which is what lets an object bigger than one frame transfer at
    /// all. Each window is committed as it arrives, so an interrupted fetch
    /// keeps everything it verified.
    /// Accumulates into `got`, which the caller owns, so a failure part-way
    /// through does not lose the windows already committed: the groups are in the
    /// bitmap either way, and a caller that had to rediscover that asked another
    /// provider for bytes this node already held and re-decoded them.
    pub async fn fetch_into(
        &self,
        backend: &Arc<dyn synch_store::backend::CasBackend>,
        root: Hash,
        size: u64,
        ranges: &ChunkRanges,
        got: &mut ChunkRanges,
    ) -> Result<(), NetError> {
        let mut walk = WindowedWalk::over(ranges);
        while !walk.remaining.is_empty() {
            let window = walk.remaining.take(MAX_SLICE_GROUPS);
            let slice = self.get_slice(root, &window).await?;
            match walk.retire(&window, &slice.served) {
                WalkStep::GiveUp => break,
                WalkStep::NextWindow => continue,
                WalkStep::Commit => {}
            }
            // Committing a window decodes it against the object root and
            // writes both the sparse payload and its outboard, then fsyncs
            // them before the bitmap advances — the heaviest disk work a fetch
            // does, and it happens once per window. Off the runtime it goes.
            let backend = backend.clone();
            let served = slice.served.clone();
            let encoded = slice.encoded;
            let written = backend
                .write_slice(root, size, served, encoded, now_ns())
                .await?;
            *got = got.union(&written.groups);
        }
        Ok(())
    }
}

/// How many windows of a run are verified at once.
///
/// Verifying a window — BLAKE3 over every group — costs more per byte than
/// reading it off the connection, and it is independent of every other
/// window, since each carries its own path from the root. Done one at a time
/// on the task reading the connection, it is one core's work and the reading
/// stops while it runs; done on the blocking pool, several windows hash at
/// once while the next ones are read. Each costs its encoding in memory until
/// it is handed out.
const VERIFY_AHEAD: usize = 4;

/// One run of an object arriving on a single stream, a window at a time
/// (see [`BlobClient::stream_run`]).
#[derive(Debug)]
pub struct RunStream {
    source: Source,
    root: Hash,
    size: u64,
    /// The group the next window read off the stream starts at.
    next: u64,
    /// Where the run ends.
    end: u64,
    piece: usize,
    deadline: std::time::Duration,
    /// Whether any window has been answered yet.
    started: bool,
    /// Whether nothing more is read off the stream: the run is complete, a
    /// window came back short, or reading failed.
    read_all: bool,
    /// Windows read and being verified, in run order.
    verifying: std::collections::VecDeque<Verifying>,
    /// How reading failed, handed out once every window read before it has
    /// been.
    failed: Option<NetError>,
}

/// A window read off a run's stream, verifying on the blocking pool.
#[derive(Debug)]
struct Verifying(tokio::task::JoinHandle<Result<Option<Vec<Vec<u8>>>, NetError>>);

impl Drop for Verifying {
    /// A run that ends early takes the windows it was verifying with it.
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl RunStream {
    fn over(
        source: Source,
        root: Hash,
        size: u64,
        run: GroupRange,
        piece: usize,
        deadline: std::time::Duration,
    ) -> RunStream {
        RunStream {
            source,
            root,
            size,
            next: run.start,
            end: run.end,
            piece,
            deadline,
            started: false,
            read_all: false,
            verifying: std::collections::VecDeque::new(),
            failed: None,
        }
    }

    /// Whether this run travels over a direct TCP connection.
    pub fn is_direct(&self) -> bool {
        matches!(self.source, Source::Direct(_))
    }

    /// The next window's verified pieces, or `None` once the run is over —
    /// complete, or ended by the provider at a window it did not hold whole.
    ///
    /// A window may come back short: the verified run from its start that a
    /// partial holder had, after which the provider stops and so does this.
    /// A provider that ends the stream before answering anything predates
    /// [`BlobMessage::GetStream`], and the error says so
    /// ([`NetError::StreamUnsupported`]) so the caller can ask it window by
    /// window instead. Each window is read under the deadline a request of
    /// its own would have.
    ///
    /// Windows are read ahead of the one handed out and verified up to
    /// [`VERIFY_AHEAD`] at once, but handed out strictly in order, and a
    /// failure — of the stream or of a window's verification — is handed out
    /// in its place, after every window before it.
    pub async fn next_window(&mut self) -> Result<Option<Vec<Vec<u8>>>, NetError> {
        loop {
            let hand_out = match self.verifying.front() {
                Some(front) => {
                    front.0.is_finished() || self.verifying.len() >= VERIFY_AHEAD || self.read_all
                }
                None => self.read_all,
            };
            if hand_out {
                return self.hand_out().await;
            }
            self.read_ahead().await;
        }
    }

    /// The oldest window's verification, or how reading failed once there is
    /// none left.
    async fn hand_out(&mut self) -> Result<Option<Vec<Vec<u8>>>, NetError> {
        let Some(mut oldest) = self.verifying.pop_front() else {
            return match self.failed.take() {
                Some(error) => Err(error),
                None => Ok(None),
            };
        };
        let verified = match (&mut oldest.0).await {
            Ok(verified) => verified,
            Err(e) => Err(NetError::Blocking(e.to_string())),
        };
        if verified.is_err() {
            // Nothing after a window that failed is the continuation of the
            // bytes handed out, so the rest of the run goes with it.
            self.verifying.clear();
            self.failed = None;
            self.read_all = true;
        }
        verified
    }

    /// Reads the next window off the stream and starts verifying it.
    async fn read_ahead(&mut self) {
        if self.next >= self.end {
            self.read_all = true;
            return;
        }
        let window = GroupRange::new(
            self.next,
            self.end.min(self.next.saturating_add(STREAM_WINDOW_GROUPS)),
        );
        let (root, size, started) = (self.root, self.size, self.started);
        let direct = self.is_direct();
        let source = &mut self.source;
        let body = under_deadline(self.deadline, "a streamed window", async move {
            match read_window_len(source).await? {
                Some(len) => read_window_body(source, size, window, len).await,
                None if started => {
                    Err(NetError::Read("the stream ended before its run did".into()))
                }
                None if direct => Err(NetError::Direct(
                    "the run ended before its first window".into(),
                )),
                None => Err(NetError::StreamUnsupported),
            }
        })
        .await;
        // A direct run that stalls is the TCP path's failure until shown
        // otherwise: the same provider is asked again over QUIC.
        let body = match body {
            Err(NetError::Endpoint(stalled)) if direct => Err(NetError::Direct(stalled)),
            body => body,
        };
        self.started = true;
        let body = match body {
            Ok(body) => body,
            Err(error) => {
                self.read_all = true;
                self.failed = Some(error);
                return;
            }
        };
        // A whole window is the run's continuation; anything else is a
        // partial holder's last word.
        match &body {
            WindowBody::Whole(_) => self.next = window.end,
            WindowBody::Partial { .. } => self.read_all = true,
        }
        let piece = self.piece;
        self.verifying
            .push_back(Verifying(tokio::spawn(crate::blocking::offload(
                move || verify_window_body(root, size, window, body, piece),
            ))));
    }
}

/// Reads the length prefix of one window's encoding, or `None` when the
/// stream ended cleanly before a byte of it.
async fn read_window_len(source: &mut Source) -> Result<Option<usize>, NetError> {
    let mut header = [0u8; 4];
    if !source.read_or_end(&mut header).await? {
        return Ok(None);
    }
    let len = u32::from_le_bytes(header) as usize;
    if len > synch_core::MAX_FRAME_LEN {
        return Err(NetError::FrameTooLarge(len));
    }
    Ok(Some(len))
}

/// The rest of one window's answer after its length prefix — its encoding
/// and its `SliceEnd` — read and verified (see [`read_window_body`] and
/// [`verify_window_body`]).
async fn read_window_answer(
    source: &mut Source,
    root: Hash,
    size: u64,
    window: GroupRange,
    len: usize,
    piece: usize,
) -> Result<Option<Vec<Vec<u8>>>, NetError> {
    let body = read_window_body(source, size, window, len).await?;
    crate::blocking::offload(move || verify_window_body(root, size, window, body, piece)).await
}

/// One window's answer off the stream, not yet verified.
#[derive(Debug)]
enum WindowBody {
    /// The encoding of the whole window.
    Whole(Vec<u8>),
    /// A partial holder's answer, and the groups its `SliceEnd` says it
    /// covers.
    Partial {
        encoded: Vec<u8>,
        served: ChunkRanges,
    },
}

/// Reads the rest of one window's answer after its length prefix: the
/// encoding, then its `SliceEnd`.
///
/// The layout is the window's when the provider holds all of it — which the
/// length prefix says before a byte of the body. Any other answer is a
/// partial holder's, and `SliceEnd` names what it had.
async fn read_window_body(
    source: &mut Source,
    size: u64,
    window: GroupRange,
    len: usize,
) -> Result<WindowBody, NetError> {
    let requested = ChunkRanges::from_ranges([window]);
    let mut encoded = vec![0u8; len];
    source.read_exact(&mut encoded).await?;
    let served = match source.read_message().await? {
        BlobMessage::SliceEnd { served } => check_served(served, &requested)?,
        _ => return Err(NetError::Unexpected("expected SliceEnd".into())),
    };
    if len as u64 == SliceVerifier::encoded_len(size, &window) {
        // The body was the whole window and every byte of it will be
        // verified, so whatever `SliceEnd` says cannot unverify it; it was
        // still read, so a provider that breaks the exchange is still a
        // failed request.
        return Ok(WindowBody::Whole(encoded));
    }
    Ok(WindowBody::Partial { encoded, served })
}

/// Verifies one window's answer against the root: the verified run starting
/// at `window.start`, in pieces of `piece` bytes rounded up to whole groups,
/// the last one shorter; or `None` when the provider served nothing usable
/// there.
///
/// A whole window is walked as a [`SliceVerifier`] checks it, each parent
/// node and each group against the chaining value vouching for it, and each
/// group is copied into its piece as it verifies, so the pieces are the only
/// copy made. A partial holder's answer is verified as [`Store::verify_slice`]
/// does, and only the run that starts where the window does is any use: a
/// later run would leave a hole the stream cannot skip.
fn verify_window_body(
    root: Hash,
    size: u64,
    window: GroupRange,
    body: WindowBody,
    piece: usize,
) -> Result<Option<Vec<Vec<u8>>>, NetError> {
    // Pieces end on group boundaries, so no group is split between two.
    let group = synch_core::CHUNK_GROUP_SIZE as usize;
    let piece = piece.max(1).div_ceil(group) * group;
    let encoded = match body {
        WindowBody::Whole(encoded) => encoded,
        WindowBody::Partial { encoded, served } => {
            let Some(run) = served
                .ranges
                .first()
                .copied()
                .filter(|run| run.start == window.start && !run.is_empty())
            else {
                return Ok(None);
            };
            if served.ranges.len() != 1 {
                return Ok(None);
            }
            let bytes = Store::verify_slice(&root, size, &run, &encoded)?;
            return Ok(Some(bytes.chunks(piece).map(<[u8]>::to_vec).collect()));
        }
    };
    let mut verifier = SliceVerifier::new(&root, size, &window);
    let mut rest = encoded.as_slice();
    let mut take = |len: usize| -> Result<&[u8], NetError> {
        if rest.len() < len {
            return Err(NetError::Read("a window's encoding ended early".into()));
        }
        let (head, tail) = rest.split_at(len);
        rest = tail;
        Ok(head)
    };
    let mut pieces = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    while let Some(expect) = verifier.expect() {
        match expect {
            Expect::Parent => verifier.parent(take(synch_core::PROOF_NODE_LEN)?)?,
            Expect::Leaf(len) => {
                if current.len() + len > piece {
                    pieces.push(std::mem::take(&mut current));
                }
                if current.is_empty() {
                    current.reserve_exact(piece);
                }
                let at = current.len();
                current.extend_from_slice(take(len)?);
                verifier.leaf(&current[at..])?;
            }
        }
    }
    if !current.is_empty() {
        pieces.push(current);
    }
    Ok(Some(pieces))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{bare_endpoint, test_store, trusting_pair, StalledPeer};
    use synch_core::{GroupRange, AD_SPAN_LEVEL, ALPN_BLOB, CHUNK_GROUP_SIZE, MAX_PROOF_NODES};

    /// A peer that keeps the session open and answers nothing fails the
    /// request instead of holding the fetch forever.
    ///
    /// `STREAM_TIMEOUT` bounds what this node does for a peer; the deadline
    /// here bounds what a peer can do to this node, and the windowed fetches
    /// above apply it once per window so a long walk is never cut short for
    /// making steady progress.
    #[tokio::test]
    async fn a_peer_that_answers_nothing_fails_a_slice_and_a_proof() {
        let peer = StalledPeer::bind(ALPN_BLOB).await;
        let dialer = bare_endpoint(ALPN_BLOB).await;
        let connection = dialer.connect(peer.addr.clone(), ALPN_BLOB).await.unwrap();
        let client =
            BlobClient::new(connection).with_deadline(std::time::Duration::from_millis(100));
        let patience = std::time::Duration::from_secs(10);
        let root = Hash::new(b"object");
        let ranges = ChunkRanges::single(0, 4);

        let slice = tokio::time::timeout(patience, client.get_slice(root, &ranges))
            .await
            .expect("a slice request must not hang")
            .expect_err("a stalled peer serves no slice");
        assert!(slice.to_string().contains("went unanswered"), "{slice}");
        let proof = tokio::time::timeout(patience, client.get_proof(root, &ranges, 0))
            .await
            .expect("a proof request must not hang")
            .expect_err("a stalled peer serves no proof");
        assert!(proof.to_string().contains("went unanswered"), "{proof}");

        dialer.close().await;
        peer.shutdown().await;
    }

    /// A transient window yields only bytes that verified on their way in: an
    /// honest provider's window arrives whole and in pieces, a partial
    /// holder's answer yields the run it had from where the window starts, an
    /// answer starting anywhere else yields nothing, and one flipped bit —
    /// in a parent node, in a group, at the very end — fails the request.
    #[tokio::test]
    async fn a_streamed_window_yields_only_verified_bytes() {
        let (_dir, store) = test_store();
        let g = CHUNK_GROUP_SIZE;
        let size = 20 * g + 99;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 241) as u8).collect();
        let root = store.ingest_bytes(&bytes, now_ns()).unwrap();
        let window = GroupRange::new(2, 18);
        let encode = |run: GroupRange| {
            let served = ChunkRanges::from_ranges([run]);
            (store.encode_slice(&root, &served).unwrap().0, served)
        };
        let honest = encode(window);
        let flipped = |at: usize| {
            let (mut encoded, served) = honest.clone();
            encoded[at] ^= 1;
            (encoded, served)
        };
        // The provider's answers, one per request, in the order asked.
        let answers = vec![
            honest.clone(),
            encode(GroupRange::new(2, 7)),
            encode(GroupRange::new(3, 18)),
            flipped(0),
            flipped(honest.0.len() / 2),
            flipped(honest.0.len() - 1),
        ];

        let endpoint = bare_endpoint(ALPN_BLOB).await;
        let addr = crate::testing::direct_addr(&endpoint);
        let serving = endpoint.clone();
        let peer = tokio::spawn(async move {
            let mut answers = answers.into_iter();
            while let Some(incoming) = serving.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    let Ok(BlobMessage::GetSlice { .. }) = read_frame(&mut recv).await else {
                        break;
                    };
                    let (encoded, served) = answers.next().expect("one answer per request");
                    write_bytes(&mut send, &encoded).await.unwrap();
                    write_frame(&mut send, &BlobMessage::SliceEnd { served })
                        .await
                        .unwrap();
                    let _ = send.finish();
                }
            }
        });

        let dialer = bare_endpoint(ALPN_BLOB).await;
        let client = BlobClient::new(dialer.connect(addr, ALPN_BLOB).await.unwrap());
        let piece = 4 * g as usize;
        let span = |from: u64, to: u64| &bytes[(from * g) as usize..(to * g) as usize];

        let pieces = client
            .read_window(root, size, window, piece)
            .await
            .unwrap()
            .expect("an honest window");
        assert!(
            pieces.iter().all(|p| p.len() == piece),
            "whole pieces of whole groups"
        );
        assert!(pieces.concat() == span(2, 18));

        let prefix = client
            .read_window(root, size, window, piece)
            .await
            .unwrap()
            .expect("a partial holder's run from the window's start");
        assert!(prefix.concat() == span(2, 7));

        assert!(client
            .read_window(root, size, window, piece)
            .await
            .unwrap()
            .is_none());

        for at in ["a parent node", "a group", "the last byte"] {
            let refused = client.read_window(root, size, window, piece).await;
            assert!(
                matches!(
                    refused,
                    Err(NetError::Store(
                        synch_store::StoreError::Verification { .. }
                    ))
                ),
                "a flipped bit in {at} is refused: {refused:?}"
            );
        }

        peer.abort();
        dialer.close().await;
        endpoint.close().await;
    }

    /// A provider dribbling one group per answer cannot hold a descent open.
    ///
    /// Retiring only what came back would let a provider serving a valid
    /// proof of a single group per exchange reset the barren counter every
    /// time: `MAX_BARREN_WINDOWS` never fires, and the deadline is per
    /// exchange — one round trip per group of the object, each costing the
    /// victim an outboard write, an fsync and an immediate transaction on its
    /// one write connection. So the whole window is retired either way, on
    /// this path as on the slice path (`docs/DELTA-SYNC.md` §3.3).
    #[tokio::test]
    async fn a_provider_serving_one_group_at_a_time_cannot_stretch_a_descent() {
        let (_provider_dir, provider_store) = test_store();
        // Sixty-four groups, all of which one proof window covers, so the
        // ceiling under test is the only thing that can end the loop.
        let size = 64 * CHUNK_GROUP_SIZE;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let root = provider_store.ingest_bytes(&bytes, now_ns()).unwrap();
        let groups = synch_core::group_count(size);
        assert_eq!(
            proof_window(&ChunkRanges::single(0, groups), 0).count(),
            groups
        );

        // A peer that answers every proof request with the lowest group asked
        // for, and nothing else. Every answer is valid, so nothing else about
        // it looks hostile.
        let endpoint = bare_endpoint(ALPN_BLOB).await;
        let addr = crate::testing::direct_addr(&endpoint);
        let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let serving = endpoint.clone();
        let counter = asked.clone();
        let store_for_peer = provider_store.clone();
        let peer = tokio::spawn(async move {
            while let Some(incoming) = serving.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    let Ok(request) = read_frame::<BlobMessage>(&mut recv).await else {
                        break;
                    };
                    let BlobMessage::GetProof {
                        root,
                        ranges,
                        level,
                    } = request
                    else {
                        break;
                    };
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let first = ranges.ranges.first().copied().expect("a non-empty request");
                    let one = ChunkRanges::single(first.start, first.start + 1);
                    let (encoded, served) = store_for_peer
                        .encode_proof(&root, &one, level, MAX_PROOF_NODES)
                        .expect("the provider holds the object");
                    write_bytes(&mut send, &encoded).await.unwrap();
                    write_frame(&mut send, &BlobMessage::ProofEnd { served })
                        .await
                        .unwrap();
                    let _ = send.finish();
                }
            }
        });

        let (_fetcher_dir, fetcher) = test_store();
        let fetcher_backend: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::LocalFs::new(fetcher));
        let dialer = bare_endpoint(ALPN_BLOB).await;
        let connection = dialer.connect(addr, ALPN_BLOB).await.unwrap();
        let client = BlobClient::new(connection);
        let mut outcome = ProofOutcome {
            proven: Proven::none(root, size),
            served: ChunkRanges::empty(),
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client.fetch_proof_into(
                &fetcher_backend,
                root,
                size,
                &ChunkRanges::single(0, groups),
                0,
                &mut outcome,
            ),
        )
        .await
        .expect("the descent must not run for one round trip per group")
        .unwrap();

        // One window was asked for, and one window is what the exchange cost —
        // whatever the provider chose to put in it.
        assert_eq!(asked.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(
            outcome.served.count(),
            1,
            "and what it served is what we got"
        );

        peer.abort();
        dialer.close().await;
        endpoint.close().await;
    }

    /// The requester sizes each window so the provider never truncates.
    ///
    /// A predictable split is what bounds a descent at `ceil(ranges / window)`
    /// exchanges without either side having to signal or compensate for a walk
    /// that overran the frame.
    #[test]
    fn a_proof_window_always_fits_one_exchange() {
        let groups_in = |bytes: u64| bytes / CHUNK_GROUP_SIZE;
        let hundred_gb = ChunkRanges::single(0, groups_in(100_000_000_000));

        // The span-level round of a 100 GB object fits in one exchange whole —
        // that is the property the whole descent rests on.
        let span = proof_window(&hundred_gb, AD_SPAN_LEVEL);
        assert_eq!(span, hundred_gb, "a span round must not be split");
        assert!(proof_nodes_upper_bound(&span, AD_SPAN_LEVEL) <= MAX_PROOF_NODES);

        // The leaf round of the same object does not, so it is split — and each
        // window still fits.
        let leaf = proof_window(&hundred_gb, 0);
        assert!(!leaf.is_empty() && leaf != hundred_gb);
        assert!(proof_nodes_upper_bound(&leaf, 0) <= MAX_PROOF_NODES);

        // Fragmentation costs a root path per range, and the window shrinks to
        // suit rather than overrunning the budget.
        let scattered =
            ChunkRanges::from_ranges((0..1000u64).map(|i| GroupRange::new(i * 1024, i * 1024 + 1)));
        let window = proof_window(&scattered, 0);
        assert!(!window.is_empty());
        assert!(proof_nodes_upper_bound(&window, 0) <= MAX_PROOF_NODES);

        // Degenerate inputs still advance rather than returning nothing.
        assert!(proof_window(&ChunkRanges::empty(), 0).is_empty());
        assert!(!proof_window(&ChunkRanges::single(0, 1), 63).is_empty());
    }

    /// Reads a whole streamed run, window by window.
    async fn read_run(stream: &mut RunStream) -> Result<Vec<Vec<u8>>, NetError> {
        let mut windows = Vec::new();
        while let Some(pieces) = stream.next_window().await? {
            windows.push(pieces.concat());
        }
        Ok(windows)
    }

    /// A real provider answers a streamed run window by window on one stream:
    /// the whole run when it holds it, the windows it holds whole and the run
    /// it has of the next when it holds only part, and nothing past that.
    #[tokio::test]
    async fn a_provider_streams_a_run_and_stops_where_its_copy_does() {
        let g = CHUNK_GROUP_SIZE;
        let w = synch_core::STREAM_WINDOW_GROUPS;
        let size = (2 * w + 40) * g + 777;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 239) as u8).collect();
        let span = |from: u64, to: u64| &bytes[(from * g) as usize..((to * g).min(size)) as usize];
        let groups = synch_core::group_count(size);

        // The provider holds every group up to `held`, and none after.
        let (_source_dir, source) = test_store();
        let root = source.ingest_bytes(&bytes, now_ns()).unwrap();
        let (_dir, store) = test_store();
        let held = w + 50;
        for start in (0..held).step_by(MAX_SLICE_GROUPS as usize) {
            let run = ChunkRanges::single(start, held.min(start + MAX_SLICE_GROUPS));
            let (encoded, served) = source.encode_slice(&root, &run).unwrap();
            store
                .write_slice(&root, size, &served, &encoded, now_ns())
                .unwrap();
        }
        let (server, client, _client_dir) =
            trusting_pair(store.clone(), crate::endpoint::NetOptions::loopback()).await;
        let blob = client.connect_blob(server.direct_addr()).await.unwrap();
        let piece = 64 * g as usize;

        // From the start: one whole window, then the run of the next it has.
        let mut stream = blob
            .stream_run(root, size, GroupRange::new(0, groups), piece)
            .await
            .unwrap();
        let windows = read_run(&mut stream).await.unwrap();
        assert_eq!(windows.len(), 2);
        assert!(windows[0] == span(0, w));
        assert!(windows[1] == span(w, held));

        // From where its copy ends: nothing.
        let mut stream = blob
            .stream_run(root, size, GroupRange::new(held, groups), piece)
            .await
            .unwrap();
        assert!(read_run(&mut stream).await.unwrap().is_empty());

        // Once it holds everything, a run off a window boundary streams whole.
        for start in (held..groups).step_by(MAX_SLICE_GROUPS as usize) {
            let run = ChunkRanges::single(start, groups.min(start + MAX_SLICE_GROUPS));
            let (encoded, served) = source.encode_slice(&root, &run).unwrap();
            store
                .write_slice(&root, size, &served, &encoded, now_ns())
                .unwrap();
        }
        let mut stream = blob
            .stream_run(root, size, GroupRange::new(5, groups), piece)
            .await
            .unwrap();
        let windows = read_run(&mut stream).await.unwrap();
        assert_eq!(windows.len(), 3);
        assert!(windows.concat() == span(5, groups));

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    /// A binding revoked while a run streams ends the run at the next window
    /// the provider encodes, as it would have refused that window asked for
    /// on its own (§3.2).
    #[tokio::test]
    async fn a_revoked_binding_ends_a_streamed_run() {
        let g = CHUNK_GROUP_SIZE;
        let w = synch_core::STREAM_WINDOW_GROUPS;
        // Enough windows that the provider cannot have encoded them all before
        // the revocation lands.
        let size = 64 * w * g;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 233) as u8).collect();
        let (_dir, store) = test_store();
        let root = store.ingest_bytes(&bytes, now_ns()).unwrap();
        let (server, client, _client_dir) =
            trusting_pair(store.clone(), crate::endpoint::NetOptions::loopback()).await;
        let blob = client.connect_blob(server.direct_addr()).await.unwrap();
        let mut stream = blob
            .stream_run(
                root,
                size,
                GroupRange::new(0, synch_core::group_count(size)),
                64 * g as usize,
            )
            .await
            .unwrap();
        assert!(stream.next_window().await.unwrap().is_some());

        let key = client.id();
        assert!(store
            .remove_binding(
                &synch_core::OriginId::Key(key),
                &key,
                synch_store::BindingSource::Static
            )
            .unwrap());
        let mut windows = 1;
        let ended = loop {
            match stream.next_window().await {
                Ok(Some(_)) => windows += 1,
                other => break other,
            }
        };
        assert!(ended.is_err(), "the run ends in an error: {ended:?}");
        assert!(
            windows < 64,
            "the provider stopped short of the run after {windows} windows"
        );

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    /// A streamed run yields only bytes that verified, in order, failing at
    /// the window that did not verify or where the stream ended early, and a
    /// provider that cannot decode the request — one that predates it — is
    /// told apart from one that answers.
    #[tokio::test]
    async fn a_streamed_run_yields_only_verified_bytes() {
        let (_dir, store) = test_store();
        let g = CHUNK_GROUP_SIZE;
        let w = synch_core::STREAM_WINDOW_GROUPS;
        let size = 3 * w * g;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 241) as u8).collect();
        let root = store.ingest_bytes(&bytes, now_ns()).unwrap();
        let window = |k: u64| GroupRange::new(k * w, (k + 1) * w);
        let encode = |run: GroupRange| {
            let served = ChunkRanges::from_ranges([run]);
            (store.encode_slice(&root, &served).unwrap().0, served)
        };
        let honest: Vec<_> = (0..3).map(|k| encode(window(k))).collect();
        let mut tampered = honest.clone();
        let middle = tampered[1].0.len() / 2;
        tampered[1].0[middle] ^= 1;
        let truncated = honest[..1].to_vec();
        // The provider's answers, one run per request, in the order asked;
        // `None` is a provider that ends the stream without a byte.
        let answers = vec![Some(honest), Some(tampered), Some(truncated), None];

        let endpoint = bare_endpoint(ALPN_BLOB).await;
        let addr = crate::testing::direct_addr(&endpoint);
        let serving = endpoint.clone();
        let peer = tokio::spawn(async move {
            let mut answers = answers.into_iter();
            while let Some(incoming) = serving.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    let Ok(BlobMessage::GetStream { .. }) = read_frame(&mut recv).await else {
                        break;
                    };
                    let answer = answers.next().expect("one answer per request");
                    for (encoded, served) in answer.into_iter().flatten() {
                        // A requester that refused a window stops reading.
                        if write_bytes(&mut send, &encoded).await.is_err()
                            || write_frame(&mut send, &BlobMessage::SliceEnd { served })
                                .await
                                .is_err()
                        {
                            break;
                        }
                    }
                    let _ = send.finish();
                }
            }
        });

        let dialer = bare_endpoint(ALPN_BLOB).await;
        let client = BlobClient::new(dialer.connect(addr, ALPN_BLOB).await.unwrap());
        let run = GroupRange::new(0, 3 * w);
        let piece = 64 * g as usize;

        let mut stream = client.stream_run(root, size, run, piece).await.unwrap();
        assert!(read_run(&mut stream).await.unwrap().concat() == bytes);

        let mut stream = client.stream_run(root, size, run, piece).await.unwrap();
        assert!(stream.next_window().await.unwrap().is_some());
        let refused = stream.next_window().await;
        assert!(
            matches!(
                refused,
                Err(NetError::Store(
                    synch_store::StoreError::Verification { .. }
                ))
            ),
            "a flipped bit in the second window is refused: {refused:?}"
        );
        assert!(
            stream.next_window().await.unwrap().is_none(),
            "and ends the run"
        );
        drop(stream);

        // A stream that ends mid-run fails there, after the window before
        // it, however far ahead it was read.
        let mut stream = client.stream_run(root, size, run, piece).await.unwrap();
        assert!(stream.next_window().await.unwrap().unwrap().concat() == bytes[..(w * g) as usize]);
        let cut = stream.next_window().await;
        assert!(matches!(cut, Err(NetError::Read(_))), "{cut:?}");
        drop(stream);

        let mut stream = client.stream_run(root, size, run, piece).await.unwrap();
        assert!(matches!(
            stream.next_window().await,
            Err(NetError::StreamUnsupported)
        ));

        peer.abort();
        dialer.close().await;
        endpoint.close().await;
    }

    /// Options for a provider that offers direct runs on loopback.
    fn direct_provider() -> crate::endpoint::NetOptions {
        crate::endpoint::NetOptions {
            direct_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..crate::endpoint::NetOptions::loopback()
        }
    }

    /// Waits up to five seconds for `done` to hold.
    async fn eventually(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..500 {
            if done() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        done()
    }

    /// A direct run answers exactly as a QUIC run does — the windows a
    /// partial holder has and nothing past them, the whole run once it holds
    /// it — and its ticket is spent once the run is under way.
    #[tokio::test]
    async fn a_direct_run_yields_what_a_quic_run_does() {
        let g = CHUNK_GROUP_SIZE;
        let w = synch_core::STREAM_WINDOW_GROUPS;
        let size = (2 * w + 40) * g + 777;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 239) as u8).collect();
        let groups = synch_core::group_count(size);
        let (_source_dir, source) = test_store();
        let root = source.ingest_bytes(&bytes, now_ns()).unwrap();
        let (_dir, store) = test_store();
        let held = w + 50;
        let hold = |to: u64| {
            for start in (0..to).step_by(MAX_SLICE_GROUPS as usize) {
                let run = ChunkRanges::single(start, to.min(start + MAX_SLICE_GROUPS));
                let (encoded, served) = source.encode_slice(&root, &run).unwrap();
                store
                    .write_slice(&root, size, &served, &encoded, now_ns())
                    .unwrap();
            }
        };
        hold(held);
        let (server, client, _client_dir) = trusting_pair(store.clone(), direct_provider()).await;
        let blob = client
            .connect_blob(server.direct_addr())
            .await
            .unwrap()
            .with_direct(Some(Arc::new(DirectMemo::default())));
        let piece = 64 * g as usize;

        let compare = |run: GroupRange| {
            let blob = blob.clone();
            async move {
                let mut direct = blob
                    .stream_run_direct(root, size, run, piece)
                    .await
                    .unwrap();
                assert!(direct.is_direct());
                let mut quic = blob.stream_run(root, size, run, piece).await.unwrap();
                let over_tcp = read_run(&mut direct).await.unwrap();
                assert!(over_tcp == read_run(&mut quic).await.unwrap());
                over_tcp
            }
        };
        let partial = compare(GroupRange::new(0, groups)).await;
        assert!(partial.concat() == bytes[..(held * g) as usize]);
        hold(groups);
        let whole = compare(GroupRange::new(5, groups)).await;
        assert!(whole.concat() == bytes[(5 * g) as usize..]);
        assert_eq!(server.direct_pending(), 0);

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    /// A provider that makes no offer, and a node that never asked for
    /// direct runs, both leave the read on QUIC — and a refusal is
    /// remembered, so the next read does not pay for asking again.
    #[tokio::test]
    async fn a_run_without_a_direct_path_stays_on_quic() {
        let (_dir, store) = test_store();
        let bytes = vec![7u8; 3 * CHUNK_GROUP_SIZE as usize];
        let root = store.ingest_bytes(&bytes, now_ns()).unwrap();
        let size = bytes.len() as u64;
        let run = GroupRange::new(0, 3);
        let (server, client, _client_dir) =
            trusting_pair(store.clone(), crate::endpoint::NetOptions::loopback()).await;

        let not_asking = client.connect_blob(server.direct_addr()).await.unwrap();
        assert!(!not_asking.direct_enabled());
        assert!(matches!(
            not_asking.stream_run_direct(root, size, run, 1 << 20).await,
            Err(NetError::Direct(_))
        ));

        let asking = not_asking.with_direct(Some(Arc::new(DirectMemo::default())));
        assert!(asking.direct_enabled());
        assert!(matches!(
            asking.stream_run_direct(root, size, run, 1 << 20).await,
            Err(NetError::Direct(_))
        ));
        assert!(!asking.direct_enabled(), "the refusal is remembered");
        let mut quic = asking.stream_run(root, size, run, 1 << 20).await.unwrap();
        assert!(read_run(&mut quic).await.unwrap().concat() == bytes);

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    /// A direct run's key and ticket live no longer than the QUIC
    /// connection that carried the offer: closing it forgets an unpresented
    /// ticket on the provider, so the key in that offer admits nothing, and
    /// destroys the key of a run under way on the requester, so the run
    /// fails at the first window it had not read by then rather than
    /// carrying on over TCP.
    #[tokio::test]
    async fn a_direct_runs_key_and_ticket_end_with_its_quic_connection() {
        let g = CHUNK_GROUP_SIZE;
        let w = synch_core::STREAM_WINDOW_GROUPS;
        // Longer than the windows a run reads ahead, so some are still on
        // the wire when the connection closes.
        let windows = 4 * VERIFY_AHEAD as u64;
        let size = windows * w * g;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 233) as u8).collect();
        let (_dir, store) = test_store();
        let root = store.ingest_bytes(&bytes, now_ns()).unwrap();
        let run = GroupRange::new(0, windows * w);
        let (server, client, _client_dir) = trusting_pair(store.clone(), direct_provider()).await;

        // The provider's half: an offer whose connection closes before the
        // ticket is presented.
        let blob = client.connect_blob(server.direct_addr()).await.unwrap();
        let mut control =
            crate::frame::request(&blob.connection, &BlobMessage::GetDirect { root, run })
                .await
                .unwrap();
        let Some(BlobMessage::DirectOffer {
            port,
            ticket,
            secret,
        }) = crate::direct::read_offer(&mut control, crate::direct::OFFER_FRAME_MAX)
            .await
            .unwrap()
        else {
            panic!("a direct provider makes an offer");
        };
        assert_eq!(server.direct_pending(), 1);
        blob.connection.close(0u32.into(), b"done");
        assert!(eventually(|| server.direct_pending() == 0).await);
        let (hello, _) = RunKeys::derive(&secret, &ticket, root, run)
            .split()
            .unwrap();
        let mut late = crate::direct::dial(([127, 0, 0, 1], port).into(), &ticket, &hello)
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let answer = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read(&mut late, &mut byte),
        )
        .await
        .expect("a dead ticket's connection is closed, not held");
        assert!(matches!(answer, Ok(0) | Err(_)));

        // The requester's half: a run under way whose connection closes.
        let blob = client
            .connect_blob(server.direct_addr())
            .await
            .unwrap()
            .with_direct(Some(Arc::new(DirectMemo::default())));
        let mut stream = blob
            .stream_run_direct(root, size, run, 1 << 20)
            .await
            .unwrap();
        assert!(stream.next_window().await.unwrap().is_some());
        let holds_key = |stream: &RunStream| match &stream.source {
            Source::Direct(source) => source.holds_key(),
            Source::Quic(_) => false,
        };
        assert!(holds_key(&stream));
        blob.connection.close(0u32.into(), b"done");
        assert!(eventually(|| !holds_key(&stream)).await);
        // Windows read before the close were opened and verified then; the
        // first one after them fails.
        let mut handed_out = 1;
        let failed = loop {
            match stream.next_window().await {
                Ok(Some(_)) => handed_out += 1,
                ended => break ended,
            }
        };
        assert!(matches!(failed, Err(NetError::Direct(_))), "{failed:?}");
        assert!(
            handed_out < windows,
            "the whole run arrived after the close"
        );

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }
}
