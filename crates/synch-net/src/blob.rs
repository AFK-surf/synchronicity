//! The `sync/blob/1` ALPN: verified bao slice transfer (§6.4) and the tree
//! proofs delta sync descends with (`docs/DELTA-SYNC.md` §3.1).
//!
//! The blob ALPN carries nothing but `GetSlice`/`SliceEnd`, `GetProof`/
//! `ProofEnd`, and the slice and proof bytes themselves. Both `End` messages
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
    now_ns, proof_window, BlobMessage, ChunkRanges, Hash, MAX_PROOF_NODES, MAX_RANGES,
    MAX_SLICE_GROUPS,
};
use synch_store::{Proven, Store};

use crate::{
    endpoint::{under_deadline, REQUEST_TIMEOUT},
    error::NetError,
    frame::{read_bytes_stalled, read_frame, read_frame_stalled, write_bytes, write_frame},
};

/// How many empty windows a provider may answer with before a fetch gives up
/// on it and lets the caller try someone else.
///
/// Counted across the whole walk rather than consecutively: a provider that
/// serves one group and then answers empty forever must not get to keep the
/// fetch alive by never missing twice in a row.
const MAX_BARREN_WINDOWS: u32 = 4;

/// Validates what a provider says it served, before any set operation reads it.
///
/// Two bounds, and the request itself supplies both:
///
/// - **Range count.** The provider side rejects a request past [`MAX_RANGES`]
///   because the set operations under it are quadratic in the number of ranges
///   and the asker would not be paying for them (§12). The same is true in
///   reverse and was not checked: `served` is decoded from a frame, so a
///   provider could answer with a million singleton ranges, and the requester
///   intersects it on a runtime worker.
/// - **Containment.** A provider can only have served what was asked for.
///   Anything outside the request is at best noise the requester would union
///   into its progress, and the slice path fed it straight to `write_slice`
///   while the proof path already intersected it away — an asymmetry with no
///   reason behind it.
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
        let handler = self.clone();
        crate::serve::serve_connection(
            &self.store.clone(),
            connection,
            self.on_unknown_key.as_ref(),
            |_| {},
            move |_peer, mut send, mut recv| {
                let handler = handler.clone();
                async move {
                    if let Err(e) = handler.handle_stream(&mut send, &mut recv).await {
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
            BlobMessage::GetProof {
                root,
                ranges,
                level,
            } => {
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
                let store = self.store.clone();
                let (encoded, served) = crate::blocking::offload(move || {
                    match store.encode_proof(&root, &ranges, level, MAX_PROOF_NODES) {
                        Ok(pair) => Ok(pair),
                        Err(synch_store::StoreError::MissingBlob(_)) => {
                            Ok((Vec::new(), ChunkRanges::empty()))
                        }
                        Err(e) => Err(e.into()),
                    }
                })
                .await?;
                write_bytes(send, &encoded).await?;
                write_frame(send, &BlobMessage::ProofEnd { served }).await?;
                Ok(())
            }
            BlobMessage::SliceEnd { .. } | BlobMessage::ProofEnd { .. } => Err(
                NetError::Unexpected("an End message is a response, not a request".into()),
            ),
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
        BlobClient { connection }
    }

    /// Opens a stream and writes one request, under the exchange deadline.
    ///
    /// The deadline covers setup only: the request is one small bounded
    /// frame, so a total bound on this phase can never cut a transfer short.
    /// The answer is another story — a slice can be megabytes trickling over
    /// a slow link — so reading it is bounded by silence, never by duration
    /// (`read_bytes_stalled`).
    async fn request(
        &self,
        message: &BlobMessage,
        what: &'static str,
    ) -> Result<iroh::endpoint::RecvStream, NetError> {
        under_deadline(REQUEST_TIMEOUT, what, async {
            let (mut send, recv) = self.connection.open_bi().await?;
            write_frame(&mut send, message).await?;
            let _ = send.finish();
            Ok(recv)
        })
        .await
    }

    /// The peer's device key.
    pub fn remote_id(&self) -> synch_core::NodeId {
        self.connection.remote_id()
    }

    /// Requests a verified slice.
    pub async fn get_slice(&self, root: Hash, ranges: &ChunkRanges) -> Result<Slice, NetError> {
        let mut recv = self
            .request(
                &BlobMessage::GetSlice {
                    root,
                    ranges: ranges.clone(),
                },
                "a slice request",
            )
            .await?;
        let encoded = read_bytes_stalled(&mut recv).await?;
        let served = match read_frame_stalled::<BlobMessage>(&mut recv).await? {
            BlobMessage::SliceEnd { served } => check_served(served, ranges)?,
            _ => return Err(NetError::Unexpected("expected SliceEnd".into())),
        };
        Ok(Slice { encoded, served })
    }

    /// Requests the tree over a range, without its bytes.
    pub async fn get_proof(
        &self,
        root: Hash,
        ranges: &ChunkRanges,
        level: u8,
    ) -> Result<Proof, NetError> {
        let mut recv = self
            .request(
                &BlobMessage::GetProof {
                    root,
                    ranges: ranges.clone(),
                    level,
                },
                "a proof request",
            )
            .await?;
        let encoded = read_bytes_stalled(&mut recv).await?;
        let served = match read_frame_stalled::<BlobMessage>(&mut recv).await? {
            BlobMessage::ProofEnd { served } => check_served(served, ranges)?,
            _ => return Err(NetError::Unexpected("expected ProofEnd".into())),
        };
        Ok(Proof { encoded, served })
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
    /// Returns the proven subtrees and the ranges they cover — which may be
    /// less than was asked for, when the provider holds less than that.
    pub async fn fetch_proof_into(
        &self,
        store: &Arc<Store>,
        root: Hash,
        size: u64,
        ranges: &ChunkRanges,
        level: u8,
    ) -> Result<ProofOutcome, NetError> {
        let mut remaining = ChunkRanges::from_ranges(ranges.ranges.iter().copied());
        let mut out = ProofOutcome {
            proven: Proven::none(root, size),
            served: ChunkRanges::empty(),
        };
        let mut barren = 0u32;
        while !remaining.is_empty() {
            // The window is the *requester's* to choose, and it is chosen so
            // the provider never has to truncate.
            //
            // It used to be the provider's: the whole remainder was offered,
            // `ProofEnd` reported how much came back, and neither side could
            // tell an honest short answer from a provider dribbling one node
            // per round trip. The provider threw away a truncated walk and
            // *walked the whole thing again* over the ranges that fit, so both
            // sides would agree node for node. That existed only because the
            // split was unpredictable. It is not: the cost of a walk is bounded
            // by its ranges and level, and while the provider walks
            // `requested ∩ what it holds` — which we cannot know — a subset
            // never costs more than the whole. Sizing the window to fit
            // assuming a full holder therefore fits for every holder.
            let window = proof_window(&remaining, level, MAX_PROOF_NODES);
            let proof = self.get_proof(root, &window, level).await?;
            // Already clamped to the window by `check_served`.
            let served = proof.served.clone();
            // The window is retired either way, exactly as `fetch_into` retires
            // a slice window, and that is what puts a ceiling on the exchange:
            // one round trip per window, `ceil(ranges / window)` of them, rather
            // than one per *group the provider felt like serving*.
            //
            // Retiring only what came back left no ceiling at all. A provider
            // answering each request with a valid proof of a single group is
            // never barren, so `MAX_BARREN_WINDOWS` never fires and the deadline
            // is per exchange — so the loop ran once per group of the object,
            // millions of times for a large one, and each turn cost the victim
            // an outboard write, an fsync and an immediate transaction on its
            // one write connection (`docs/DELTA-SYNC.md` §3.3).
            //
            // Nothing honest needs a second look at a window: a partial holder
            // answers `requested ∩ held` for the whole of it in one walk, and
            // what it did not hold this time it will not hold on the next ask
            // either. Ranges it left behind stay in the caller's `remaining`
            // through `out.served`, so another provider still gets asked.
            remaining = remaining.difference(&window);
            if served.is_empty() {
                barren += 1;
                if barren >= MAX_BARREN_WINDOWS {
                    break;
                }
                continue;
            }
            let store = store.clone();
            let encoded = proof.encoded;
            let for_store = served.clone();
            let proven = crate::blocking::offload(move || {
                Ok(store.write_proof(&root, size, &for_store, level, &encoded, now_ns())?)
            })
            .await?;
            out.served = out.served.union(&served);
            out.proven.absorb(proven)?;
        }
        Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{bare_endpoint, StalledPeer};
    use synch_core::{ALPN_BLOB, CHUNK_GROUP_SIZE, MAX_PROOF_NODES};

    /// A peer that keeps the session open and answers nothing fails the
    /// request instead of holding the fetch forever.
    ///
    /// The read bound is silence, not duration: a provider steadily trickling
    /// a large slice over a slow link re-arms the clock with every read, while
    /// one that has stopped sending entirely is cut off in one bound however
    /// large the object (`STALL_TIMEOUT`, shortened to milliseconds under
    /// `cfg(test)` so this does not take minutes).
    #[tokio::test]
    async fn a_peer_that_answers_nothing_fails_a_slice_and_a_proof() {
        let peer = StalledPeer::bind(ALPN_BLOB).await;
        let dialer = bare_endpoint(ALPN_BLOB).await;
        let connection = dialer.connect(peer.addr.clone(), ALPN_BLOB).await.unwrap();
        let client = BlobClient::new(connection);
        let patience = std::time::Duration::from_secs(10);
        let root = Hash::new(b"object");
        let ranges = ChunkRanges::single(0, 4);

        let slice = tokio::time::timeout(patience, client.get_slice(root, &ranges))
            .await
            .expect("a slice request must not hang")
            .expect_err("a stalled peer serves no slice");
        assert!(slice.to_string().contains("sent nothing"), "{slice}");
        let proof = tokio::time::timeout(patience, client.get_proof(root, &ranges, 0))
            .await
            .expect("a proof request must not hang")
            .expect_err("a stalled peer serves no proof");
        assert!(proof.to_string().contains("sent nothing"), "{proof}");

        dialer.close().await;
        peer.shutdown().await;
    }

    /// A provider dribbling one group per answer cannot hold a descent open.
    ///
    /// `remaining` used to retire only what came back, so a provider serving a
    /// valid proof of a single group per exchange reset the barren counter every
    /// time, `MAX_BARREN_WINDOWS` never fired, and the deadline is per exchange
    /// — one round trip per group of the object, each costing the victim an
    /// outboard write, an fsync and an immediate transaction on its one write
    /// connection. The slice path always retired the whole window
    /// (`docs/DELTA-SYNC.md` §3.3); the proof path now does too.
    #[tokio::test]
    async fn a_provider_serving_one_group_at_a_time_cannot_stretch_a_descent() {
        let provider_dir = tempfile::tempdir().unwrap();
        let provider_store =
            std::sync::Arc::new(synch_store::Store::open(provider_dir.path()).unwrap());
        // Sixty-four groups, all of which one proof window covers, so the
        // ceiling under test is the only thing that can end the loop.
        let size = 64 * CHUNK_GROUP_SIZE;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let root = provider_store.ingest_bytes(&bytes, now_ns()).unwrap();
        let groups = synch_core::group_count(size);
        assert_eq!(
            proof_window(&ChunkRanges::single(0, groups), 0, MAX_PROOF_NODES).count(),
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

        let fetcher_dir = tempfile::tempdir().unwrap();
        let fetcher = std::sync::Arc::new(synch_store::Store::open(fetcher_dir.path()).unwrap());
        let dialer = bare_endpoint(ALPN_BLOB).await;
        let connection = dialer.connect(addr, ALPN_BLOB).await.unwrap();
        let client = BlobClient::new(connection);
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client.fetch_proof_into(&fetcher, root, size, &ChunkRanges::single(0, groups), 0),
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
}
