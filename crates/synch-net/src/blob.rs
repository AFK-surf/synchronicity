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
    now_ns, proof_nodes_upper_bound, BlobMessage, ChunkRanges, Hash, MAX_PROOF_NODES, MAX_RANGES,
    MAX_SLICE_GROUPS,
};
use synch_store::{Proven, Store};

use crate::{
    error::NetError,
    frame::{read_bytes, read_frame, write_bytes, write_frame},
};

/// How many consecutive empty windows a provider may answer with before a
/// fetch gives up on it and lets the caller try someone else.
const MAX_BARREN_WINDOWS: u32 = 4;

/// How many requests one connection may have in flight at once.
///
/// The bound that the old handle-one-stream-at-a-time loop looked like but was
/// not: that serialized a peer's requests without limiting what a peer could
/// cost us, since nothing capped connections.
const MAX_CONCURRENT_STREAMS: usize = 8;

/// How long one request may take, start to finish.
///
/// Covers the read as well as the work: without it a peer that opens a stream
/// and sends nothing holds a task indefinitely. Generous, because one window of
/// a large object is real disk work on the blocking pool.
const STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// The largest prefix of `remaining` whose proof fits one exchange.
///
/// Sized by [`proof_nodes_upper_bound`], so a provider holding everything asked
/// for still comes in under [`MAX_PROOF_NODES`] and never truncates. Ranges are
/// taken whole where they fit and split where they do not, and the count is
/// clamped to [`MAX_RANGES`] so the set operations under it stay cheap on both
/// sides (§12).
fn proof_window(remaining: &ChunkRanges, level: u8) -> ChunkRanges {
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

        // One task per stream, bounded by a semaphore.
        //
        // Handling streams one at a time to completion was not a concurrency
        // bound — it bounded nothing, since a peer can open more connections —
        // but it did bound *throughput*: because the encode runs on the
        // blocking pool via `.await`, the connection could not accept another
        // stream while one window was being built, so §6.3's "swarm behaviour
        // falls out naturally" did not survive any client that pipelines. The
        // semaphore is the real bound, and it is per connection.
        let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS));
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            // §3.2 enforcement is per message, not just per connection: a
            // binding revoked or expired mid-connection must cut off further
            // requests, not linger for the life of the QUIC session.
            if !matches!(self.store.is_trusted_key(&remote, now_ns()), Ok(true)) {
                tracing::debug!(peer = %remote.fmt_short(), "closing connection: binding lapsed");
                connection.close(0u32.into(), b"untrusted");
                break;
            }
            let Ok(permit) = limit.clone().acquire_owned().await else {
                break;
            };
            let handler = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                // A read timeout, because there was none anywhere in the blob
                // path: a trusted-key peer could open a stream, send nothing,
                // and hold the task forever with nothing to reap it — which
                // also defeated the per-message binding re-check above, since
                // the loop never came back round.
                let served = tokio::time::timeout(
                    STREAM_TIMEOUT,
                    handler.handle_stream(&mut send, &mut recv),
                )
                .await;
                match served {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::debug!(error = %e, "blob stream ended"),
                    Err(_) => tracing::debug!("blob stream timed out"),
                }
                let _ = send.finish();
            });
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
                    match store.encode_proof(&root, &ranges, level) {
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
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_frame(
            &mut send,
            &BlobMessage::GetProof {
                root,
                ranges: ranges.clone(),
                level,
            },
        )
        .await?;
        let _ = send.finish();

        let encoded = read_bytes(&mut recv).await?;
        let served = match read_frame::<BlobMessage>(&mut recv).await? {
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
            // per round trip. That needed two separate patches — the provider
            // threw away a truncated walk and *walked the whole thing again*
            // over the ranges that fit, so both sides would agree node for
            // node, and the requester carried a heuristic ceiling of three
            // magic constants to bound the number of round trips. Both existed
            // only because the split was unpredictable. It is not: the cost of
            // a walk is bounded by its ranges and level, and while the provider
            // walks `requested ∩ what it holds` — which we cannot know — a
            // subset never costs more than the whole. Sizing the window to fit
            // assuming a full holder therefore fits for every holder.
            let window = proof_window(&remaining, level);
            let proof = self.get_proof(root, &window, level).await?;
            // Already clamped to the window by `check_served`.
            let served = proof.served.clone();
            if served.is_empty() {
                barren += 1;
                if barren >= MAX_BARREN_WINDOWS {
                    break;
                }
                // Nothing came back for this window, and asking again would
                // only repeat the round trip.
                remaining = remaining.difference(&window);
                continue;
            }
            barren = 0;
            let store = store.clone();
            let encoded = proof.encoded;
            let for_store = served.clone();
            let proven = crate::blocking::offload(move || {
                Ok(store.write_proof(&root, size, &for_store, level, &encoded, now_ns())?)
            })
            .await?;
            remaining = remaining.difference(&served);
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

#[cfg(test)]
mod tests {
    use super::*;
    use synch_core::{GroupRange, AD_SPAN_LEVEL, CHUNK_GROUP_SIZE, MAX_PROOF_NODES};

    /// The requester sizes each window so the provider never truncates.
    ///
    /// This is what replaced a pair of compensating mechanisms: a provider that
    /// threw away a truncated walk and repeated it over the ranges that fit, and
    /// a requester-side round-trip ceiling built from three magic constants.
    /// Neither is needed once the split is predictable.
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
}
