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
use synch_core::{now_ns, BlobMessage, ChunkRanges, Hash, MAX_RANGES, MAX_SLICE_GROUPS};
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

/// How many windows one proof exchange may take before the requester walks away.
///
/// A ceiling on the exchange as a whole, not just on the empty answers. A
/// provider that serves one node per window is not barren — it is making
/// progress, a round trip at a time — and without a bound it can hold a descent
/// open for one RTT per node of the object's tree.
///
/// So the ceiling is based on what an *honest* answer costs. A proof stopping at
/// `level` names one subtree per `2^level` groups, and a walk that names `n`
/// subtrees emits fewer than `2n` interior nodes above them, plus at most one
/// path from the root per disjoint range asked about — a path being no deeper
/// than the 64 levels a `u64` group index can address. Divide by the window
/// ([`MAX_PROOF_NODES`](synch_core::MAX_PROOF_NODES)) for the number of windows
/// the honest answer takes, then
/// allow a small multiple of it and a floor, so a provider that splits its
/// answer differently than expected is not cut off for it. The ranges the
/// exchange did not reach simply go to the ordinary fetch (§6.4).
///
/// The count that used to stand here was `8 + groups * 2`, which reads as
/// generous and is not a bound at all: a span-level round over 100 GB names
/// about six thousand subtrees and needs one window, and that formula would have
/// allowed twelve million.
fn proof_window_ceiling(ranges: &ChunkRanges, level: u8) -> u64 {
    /// Windows allowed per window an honest answer needs.
    const SLACK: u64 = 4;
    /// The smallest ceiling, so a one-node proof still gets a few tries.
    const FLOOR: u64 = 8;
    /// The deepest a root-to-range path can be for a `u64` group index.
    const MAX_PATH: u64 = 64;

    let per_subtree = 1u64 << level.min(63);
    let subtrees = ranges.count().div_ceil(per_subtree);
    let nodes = subtrees
        .saturating_mul(2)
        .saturating_add((ranges.range_count() as u64).saturating_mul(MAX_PATH));
    let honest = nodes.div_ceil(synch_core::MAX_PROOF_NODES).max(1);
    honest.saturating_mul(SLACK).saturating_add(FLOOR)
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
        let mut windows = proof_window_ceiling(&remaining, level);
        while !remaining.is_empty() {
            if windows == 0 {
                tracing::debug!(root = %root, "proof exchange cut off: too many windows");
                break;
            }
            windows -= 1;
            // The window is the provider's to choose — it is counted in tree
            // nodes, not groups, and only the provider knows how the tree falls
            // — so the whole remainder is offered and `ProofEnd` says how much
            // of it came back. Only the range *count* is clamped here, because
            // that is the one part of the request the provider must not be made
            // to pay for (§12).
            let window =
                ChunkRanges::from_ranges(remaining.ranges.iter().take(MAX_RANGES).copied());
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

    /// The window ceiling tracks what an honest answer costs, not how much of
    /// the object was named.
    ///
    /// Counting groups made the ceiling scale with the thing the proof exists to
    /// avoid touching group by group: a span round over 100 GB names six
    /// thousand subtrees and one honest window, and the old `8 + groups * 2`
    /// granted twelve million round trips against it — a bound in name only.
    #[test]
    fn the_window_ceiling_is_based_on_windows_not_groups() {
        let groups_in = |bytes: u64| bytes / CHUNK_GROUP_SIZE;
        let hundred_gb = ChunkRanges::single(0, groups_in(100_000_000_000));

        // The span-level round of a 100 GB object: one honest window, so a
        // ceiling in the tens rather than the millions.
        let span_round = proof_window_ceiling(&hundred_gb, AD_SPAN_LEVEL);
        assert!(
            (1..64).contains(&span_round),
            "a span round over 100 GB should cost a handful of windows, not {span_round}"
        );

        // The leaf round of the same object is genuinely large, and the ceiling
        // grows with it — proportionally to the tree it has to move, which is
        // what "a few per window" means.
        let leaf_round = proof_window_ceiling(&hundred_gb, 0);
        let honest = hundred_gb.count() * 2 / MAX_PROOF_NODES;
        assert!(leaf_round > honest, "{leaf_round} vs {honest}");
        assert!(leaf_round < honest * 8, "{leaf_round} vs {honest}");

        // Fragmentation costs a root path per range and no more, so a request
        // split into many small ranges is bounded too.
        let scattered =
            ChunkRanges::from_ranges((0..1000u64).map(|i| GroupRange::new(i * 1024, i * 1024 + 1)));
        assert!(proof_window_ceiling(&scattered, 0) < 64);

        // And the floor holds for the degenerate cases rather than yielding a
        // ceiling of zero, which would refuse the first window outright.
        assert!(proof_window_ceiling(&ChunkRanges::empty(), 0) >= 8);
        assert!(proof_window_ceiling(&ChunkRanges::single(0, 1), 63) >= 8);
    }
}
