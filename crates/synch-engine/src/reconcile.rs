//! The §5.2 reconciliation algorithm.
//!
//! ```text
//! verify sig(H) under H.signed_by; check H.signed_by is bound to O (else ignore)
//! check (H.seq, H.root) > (local.seq, local.root) lexicographically (else ignore)
//! record H as pending_head(O)                            // durable
//! frontier ← { H.root }
//! while frontier ≠ ∅:
//!     want ← { h ∈ frontier : h ∉ trie_nodes }           // structural sharing
//!     if want = ∅: break
//!     nodes ← GetNodes(want)
//!     verify each node hashes to its requested hash      // reject & disconnect
//!     store nodes; frontier ← their children ∪ value hashes
//! atomically: set complete_head(O) ← H; clear pending
//! re-materialize changed leaves from the node-level diff
//! ```

use std::sync::Arc;

use synch_core::{now_ns, HeadSummary, OriginId, SignedHead, MAX_BATCH};
use synch_mpt::{Trie, TrieNode};
use synch_store::{Slot, Store};

use synch_net::{HeadSink, MptClient, NetError};

use crate::error::{EngineError, Result};

/// How many distinct roots one origin may have retained at a single seq.
///
/// Two is what proves equivocation (§4.4), and the proof is the reason those
/// rows are exempt from ordinary retention. Past that the rows add no evidence,
/// so an origin signing at one seq forever would grow every peer's
/// `head_history` without bound. A little headroom over two, so a genuinely
/// confused origin is recorded rather than truncated at the minimum.
///
/// A bound on what is *retained*, never on what is accepted. Refusing a head
/// because the fork is already wide enough would make acceptance depend on
/// arrival order and so destroy the `(seq, root)` maximum §5.2 converges to: an
/// origin signing nine roots at one seq would leave two honest peers holding
/// different heads, according to which of the nine each saw first, each then
/// refusing the other's forever.
/// The cap is applied by evicting the lowest-ordered retained roots at the seq
/// instead ([`synch_store::Txn::trim_forks`]), which is the same set on every
/// peer however the roots arrived.
pub const MAX_RETAINED_FORKS: usize = 8;

/// How many fetch rounds against one peer may make no progress before the
/// pending head is abandoned and head selection re-runs (§5.2).
///
/// Per fetch, not across every advertiser: the counter lives in the loop that
/// asks, so it only ever counts against a peer that was actually asked. A
/// pending head no peer advertises at or above is never fetched at all and so
/// never counted — that case is the maintenance pass's `pending_head_ttl`
/// sweep, and the two together are what §5.2 means by no wedging.
pub const MAX_UNPRODUCTIVE_ROUNDS: u32 = 3;

/// What happened when a head was offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadOutcome {
    /// The signature did not verify.
    BadSignature,
    /// The signer has no live binding to the claimed origin (§3.1).
    ///
    /// Trie heads whose signing key is not bound to the claimed origin are
    /// ignored even if relayed by a trusted peer.
    Unbound,
    /// The head is not strictly greater than what we already hold.
    NotNewer,
    /// The head was adopted as pending and its trie must be fetched.
    Pending,
    /// The head was adopted and its trie was already present, so the complete
    /// slot flipped immediately.
    Completed,
}

impl HeadOutcome {
    /// True if the head was adopted in either slot.
    pub fn accepted(&self) -> bool {
        matches!(self, HeadOutcome::Pending | HeadOutcome::Completed)
    }
}

/// What happened when a pending head's trie was fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// There was no pending head to fetch.
    Idle,
    /// The trie is now complete and the head flipped.
    Completed,
    /// Progress was made but the trie is still incomplete.
    Partial,
    /// Every candidate persistently returned `missing`; the pending head was
    /// abandoned and head selection re-runs (§5.2).
    Abandoned,
}

/// Reconciliation over one node's store.
#[derive(Debug, Clone)]
pub struct Syncer {
    store: Arc<Store>,
    /// Rung when a promotion flips a head to complete: the unified tree just
    /// changed, and anything materializing it — mirrors — should look again.
    on_change: Option<Arc<tokio::sync::Notify>>,
}

impl Syncer {
    /// Binds a syncer to a store.
    pub fn new(store: Arc<Store>) -> Self {
        Syncer {
            store,
            on_change: None,
        }
    }

    /// Rings `wake` whenever a head flips to complete (§5.2).
    ///
    /// Every merge path ends in [`Syncer::try_promote`] — the Hello exchange
    /// in either direction, a pushed head whose trie was already here, a
    /// pending head's completed fetch — so this one bell covers all of them.
    pub fn on_change(mut self, wake: Option<Arc<tokio::sync::Notify>>) -> Self {
        self.on_change = wake;
        self
    }

    /// The store this syncer reconciles into.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The head summaries this node advertises in `Hello` (§5.1).
    ///
    /// `complete` means "I hold the full trie under this root and can serve
    /// it"; a signed head alone proves nothing about that, so the flag is
    /// computed from the local trie, never assumed.
    pub fn local_summaries(&self) -> Result<Vec<HeadSummary>> {
        let trie = Trie::new(self.store.as_ref());
        let mut out = Vec::new();
        for stored in self.store.all_heads(Slot::Complete)? {
            let head = stored.head;
            let complete = trie.is_complete(head.root)?;
            out.push(HeadSummary {
                origin: head.origin,
                seq: head.seq,
                root: head.root,
                complete,
            });
        }
        // A pending head is advertised too — as strictly not complete — so a
        // peer learns the newer head exists without being told we can serve it.
        //
        // It is advertised *alongside* the complete head, never in place of it.
        // Collapsing the two slots into one summary per origin erased the fact
        // that we hold the older root whole, and two things read that fact: our
        // own push decision, which only pushes a head whose order key matches
        // the summary it just advertised, and every peer's servability filter,
        // which needs `complete` set to fetch trie nodes from us. A node with
        // any pending head therefore stopped propagating that origin entirely
        // and dropped out of the provider set for a root it could serve.
        for stored in self.store.all_heads(Slot::Pending)? {
            let head = stored.head;
            let already = out
                .iter()
                .any(|s| s.origin == head.origin && (s.seq, s.root.0) == (head.seq, head.root.0));
            if already {
                continue;
            }
            out.push(HeadSummary {
                origin: head.origin,
                seq: head.seq,
                root: head.root,
                complete: false,
            });
        }
        out.sort_by(|a, b| {
            a.origin
                .cmp(&b.origin)
                .then(a.order_key().cmp(&b.order_key()))
        });
        // The wire caps a head-carrying message at `MAX_HEADS_PER_MESSAGE`, and
        // the responder and the dialer both refuse one that overruns it — so a
        // node that built a longer list than it is allowed to send would fail
        // every exchange in both directions, permanently, with nothing to
        // repair it. Heads are never deleted when trust is removed, so the list
        // only grows. §12 sizes membership two orders of magnitude below the
        // cap, so this trims nothing in any real cluster; it is here so the
        // request this node makes is always one it is allowed to make.
        if out.len() > synch_core::MAX_HEADS_PER_MESSAGE {
            tracing::warn!(
                summaries = out.len(),
                cap = synch_core::MAX_HEADS_PER_MESSAGE,
                "more origins than one Hello can carry: advertising the lowest-sorting prefix"
            );
            out.truncate(synch_core::MAX_HEADS_PER_MESSAGE);
        }
        Ok(out)
    }

    /// Records what a peer advertised for *this node's own* origin (§3.4).
    ///
    /// A node that lost its key and its database holds no head of its own, and
    /// the heads its peers still hold for it are signed by the lost key: no
    /// longer bound, so they can never be accepted as heads (§4.4). Their
    /// existence is what recovery reads, and it is already in every `Hello`
    /// summary — no new wire message, and no unbound signature is trusted here.
    /// Summaries for other origins are ignored: for those, the ordinary
    /// acceptance rule is both sufficient and stricter.
    ///
    /// Returns the highest seq now observed for our origin.
    pub fn observe_summaries(&self, summaries: &[HeadSummary], now: i64) -> Result<Option<u64>> {
        self.observe_summaries_from(None, summaries, now)
    }

    /// The same, recording which peer made the claim (§3.4).
    ///
    /// Detection rests on unauthenticated summaries, so the attribution is
    /// what lets an operator judge a claim that holds a node in recovery.
    pub fn observe_summaries_from(
        &self,
        claimed_by: Option<synch_core::NodeId>,
        summaries: &[HeadSummary],
        now: i64,
    ) -> Result<Option<u64>> {
        let Some(own) = self.store.self_origin()? else {
            return Ok(None);
        };
        for summary in summaries.iter().filter(|s| s.origin == own) {
            if self.store.record_observed_head(
                &own,
                summary.seq,
                &summary.root,
                summary.complete,
                claimed_by.as_ref(),
                now,
            )? {
                tracing::info!(
                    origin = %own,
                    seq = summary.seq,
                    peer = claimed_by.map(|k| k.fmt_short().to_string()).unwrap_or_default(),
                    "a peer advertises a head for our own origin"
                );
            }
        }
        Ok(self.store.observed_head(&own)?.map(|o| o.seq))
    }

    /// The full signed heads for the origins a peer asked about (§5.1).
    ///
    /// Only complete heads are handed out: what this advertises is a head whose
    /// trie this node can serve, and the pending slot's is by definition one it
    /// cannot.
    pub fn heads_for(&self, origins: &[OriginId]) -> Result<Vec<SignedHead>> {
        let mut out = Vec::new();
        for origin in origins {
            if let Some(head) = self.store.head(origin, Slot::Complete)? {
                out.push(head.head);
            }
        }
        Ok(out)
    }

    /// Offers a head for adoption, applying the full §5.2 acceptance rule.
    pub fn offer_head(&self, head: &SignedHead, now: i64) -> Result<HeadOutcome> {
        // 1. The signature must verify under the key that claims to have made it.
        if head.verify_signature().is_err() {
            return Ok(HeadOutcome::BadSignature);
        }
        // 2. That key must be bound to the claimed origin, right now.
        if !self.store.is_bound(&head.origin, &head.signed_by, now)? {
            return Ok(HeadOutcome::Unbound);
        }
        // The ordering check and the write that acts on it are one transaction.
        // Read-then-write across two lock acquisitions would let two concurrent
        // offers — one per peer connection, all on the blocking pool — both
        // read the same floor, both decide they supersede it, and both write
        // the pending slot, so the lower one clobbers the higher and the higher
        // survives only in `head_history` with nothing to re-drive it.
        let outcome = self.store.transaction(|txn| -> Result<HeadOutcome> {
            // Verified heads are provable history and fork evidence even
            // when they lose the ordering comparison, so they are retained
            // either way (§4.4).
            txn.record_history(head, now)?;

            // 3. (seq, root) must be strictly greater, lexicographically.
            //    Strictly greater on seq alone would not converge: two
            //    peers receiving different same-seq heads in different
            //    orders would diverge permanently.
            //
            //    Nothing else may stand in front of this comparison. It is
            //    the join that makes head selection order-independent, so a
            //    head that beats the floor reaches the pending slot however
            //    many roots the origin has already signed at this seq — the
            //    width of the fork is a storage question, answered below,
            //    after the ordering has been settled.
            let floor = txn.head_floor(&head.origin)?;
            let outcome = if head.supersedes(floor.as_ref()) {
                txn.put_head(Slot::Pending, head, now, now)?;
                HeadOutcome::Pending
            } else {
                HeadOutcome::NotNewer
            };

            // Same-seq forks are exempt from `root_retention` until the
            // origin publishes past the forked seq, so a member signing an
            // unlimited number of roots at one seq would otherwise buy
            // permanent growth on every peer, surviving even `trust rm`.
            // Two roots prove the equivocation; past the cap the *lowest*
            // roots at the seq are evicted, which leaves every peer holding
            // the same [`MAX_RETAINED_FORKS`] greatest roots whatever order
            // they arrived in, and never touches the row a slot points at.
            let evicted = txn.trim_forks(&head.origin, head.seq, MAX_RETAINED_FORKS)?;
            if evicted > 0 {
                tracing::warn!(
                    origin = %head.origin,
                    seq = head.seq,
                    evicted,
                    "same-seq forks past the cap evicted: equivocation is already proven"
                );
            }
            Ok(outcome)
        })?;
        if !outcome.accepted() {
            return Ok(outcome);
        }
        if self.try_promote(&head.origin, now)? {
            Ok(HeadOutcome::Completed)
        } else {
            Ok(HeadOutcome::Pending)
        }
    }

    /// Flips the pending head to complete if its whole trie is present,
    /// re-materializing the derived views from the node-level diff.
    ///
    /// The flip and the materialization are one SQLite transaction (§5.2,
    /// §10): a crash between them would leave `entries` — what the unified
    /// tree, mirrors, and `synch-s3` serve from — missing a promoted head's
    /// delta, with nothing left to say so.
    pub fn try_promote(&self, origin: &OriginId, now: i64) -> Result<bool> {
        let promoted = self.store.transaction(|txn| -> Result<_> {
            let Some(pending) = txn.head(origin, Slot::Pending)? else {
                return Ok(None);
            };
            let trie = Trie::new(txn);
            if !trie.is_complete(pending.head.root)? {
                return Ok(None);
            }
            let displaced = txn.complete_head(origin)?;
            // The pending head must actually beat the complete one, rather than
            // rest on "pending is always greater", an invariant `offer_head`
            // maintains and two other writers do not: `publish` and the key
            // rotation in `activate` both derive their seq from the *complete*
            // slot alone and write it directly, never consulting pending. So a
            // peer relaying an older head of our own origin — signed by a key
            // of ours that is still bound, which is exactly the §3.4 recovery
            // shape — can sit in the pending slot while a local publish moves
            // the complete slot past it, and taking that invariant on trust
            // would install the lesser head and roll `entries` back to it.
            let floor = displaced.as_ref().map(|h| (h.seq, h.root));
            if !pending.head.supersedes(floor.as_ref()) {
                tracing::debug!(
                    origin = %origin,
                    pending = pending.head.seq,
                    complete = displaced.as_ref().map(|h| h.seq).unwrap_or(0),
                    "dropping a pending head the complete slot has overtaken"
                );
                txn.clear_head(origin, Slot::Pending)?;
                return Ok(None);
            }
            let old_root = displaced
                .as_ref()
                .map(|h| h.root)
                .unwrap_or(synch_core::Hash::EMPTY);
            // The displaced head is already retained: `put_head` recorded its
            // signature when it took the slot. Recording it again here would be
            // a second rule writing the same row, kept honest only by
            // `INSERT OR IGNORE` (§10, v11).
            txn.put_head(Slot::Complete, &pending.head, pending.received_at, now)?;
            txn.clear_head(origin, Slot::Pending)?;
            txn.materialize_diff(origin, old_root, pending.head.root)?;
            Ok(Some(pending.head))
        })?;
        match promoted {
            Some(head) => {
                tracing::debug!(origin = %origin, seq = head.seq, "head flipped to complete");
                if let Some(wake) = &self.on_change {
                    // One permit no matter how often this rings: passes
                    // coalesce, and a wake landing mid-pass is not lost.
                    wake.notify_one();
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Fetches the pending head's trie from `client`, verifying every node
    /// against the hash it was requested by.
    ///
    /// Nodes are content-addressed, so `client` need not be the origin, nor
    /// even the peer that told us about the head: any peer advertising a
    /// complete head for the origin at or above this seq will do.
    pub async fn fetch_pending(
        &self,
        client: &MptClient,
        origin: &OriginId,
    ) -> Result<FetchOutcome> {
        let Some(pending) = self.store.pending_head(origin)? else {
            return Ok(FetchOutcome::Idle);
        };
        // What this origin's trie looked like when we last held all of it. Every
        // subtree the new root shares with it is already here, so the walk can
        // skip it outright and descend only what changed (§5.2) — which is the
        // difference between an incremental sync costing the change and costing
        // the whole tree. Only a root we have *established* is complete will do:
        // that check is memoized, so it is a lookup after the first time.
        //
        // Establishing it the first time is a full walk, so it goes off the
        // runtime — as does every batch of the walk below, and every batch of
        // nodes and values committed between the round trips (§10).
        let reference = {
            let store = self.store.clone();
            let origin = origin.clone();
            crate::blocking::offload(move || {
                let trie = Trie::new(store.as_ref());
                Ok(match store.complete_head(&origin)? {
                    Some(head) if trie.is_complete(head.root)? => Some(head.root),
                    _ => None,
                })
            })
            .await?
        };
        let mut walk = synch_mpt::MissingWalk::since(reference, pending.root);
        let mut unproductive = 0u32;
        loop {
            // One walk across the whole fetch, resumed rather than restarted:
            // beginning again at the root for every batch makes a cold fetch
            // re-descend everything it has already pulled, once per batch. The
            // walk travels into the blocking pool and back so its position
            // survives each round trip.
            let store = self.store.clone();
            let (missing, returned) = crate::blocking::offload(move || {
                let trie = Trie::new(store.as_ref());
                let missing = walk.next_batch(&trie, MAX_BATCH)?;
                Ok((missing, walk))
            })
            .await?;
            walk = returned;
            if missing.is_empty() {
                if walk.is_exhausted() {
                    break;
                }
                walk.resume();
                continue;
            }

            let mut learned = 0usize;
            if !missing.nodes.is_empty() {
                let response = client.get_nodes(&missing.nodes).await?;
                let store = self.store.clone();
                let requested = missing.nodes.clone();
                learned += crate::blocking::offload(move || {
                    take_served(
                        &requested,
                        &response.nodes,
                        "node",
                        |bytes| TrieNode::hash_of_encoded(bytes).ok(),
                        |expected| NetError::NodeHashMismatch { expected },
                        |hash, bytes| {
                            Ok(synch_mpt::NodeStore::put_node(store.as_ref(), hash, bytes)?)
                        },
                    )
                })
                .await?;
            }
            if !missing.values.is_empty() {
                let response = client.get_values(&missing.values).await?;
                let store = self.store.clone();
                let requested = missing.values.clone();
                learned += crate::blocking::offload(move || {
                    take_served(
                        &requested,
                        &response.values,
                        "value",
                        |bytes| Some(synch_core::Hash::new(bytes)),
                        |expected| NetError::ValueHashMismatch { expected },
                        |hash, bytes| {
                            Ok(synch_mpt::NodeStore::put_value(
                                store.as_ref(),
                                hash,
                                bytes,
                            )?)
                        },
                    )
                })
                .await?;
            }

            if learned == 0 {
                unproductive += 1;
                if unproductive >= MAX_UNPRODUCTIVE_ROUNDS {
                    // No wedging on unservable heads: abandon the pending head
                    // and let head selection re-run. Structural sharing makes
                    // the restart cost proportional to what actually changed.
                    tracing::warn!(
                        origin = %origin,
                        seq = pending.seq,
                        "abandoning pending head: providers persistently missing nodes"
                    );
                    self.store.clear_head(origin, Slot::Pending)?;
                    return Ok(FetchOutcome::Abandoned);
                }
            } else {
                unproductive = 0;
            }
            // Everything just stored goes back on the frontier, so the nodes
            // that arrived expand into their own children.
            walk.resume();
        }

        // The walk drained with nothing missing, which *is* the answer to "do I
        // hold all of this?" — so record it rather than let the promotion below
        // and the next `Hello` each rediscover it by walking the trie again.
        // The promotion that follows re-materializes every changed leaf in one
        // transaction, so the pair stays off the runtime like the rest.
        let store = self.store.clone();
        let syncer = self.clone();
        let origin = origin.clone();
        let promoted = crate::blocking::offload(move || {
            synch_mpt::NodeStore::note_complete(store.as_ref(), &pending.root)?;
            syncer.try_promote(&origin, now_ns())
        })
        .await?;
        if promoted {
            Ok(FetchOutcome::Completed)
        } else {
            Ok(FetchOutcome::Partial)
        }
    }

    /// Runs a `Hello` exchange that pushes and pulls nothing, purely to read
    /// the peer's summaries (§3.4 step 2).
    ///
    /// This is what the recovery quiesce collects with. It is the ordinary
    /// exchange with an empty decision, so a recovering node learns how far
    /// peers say its origin had got without adopting anything.
    pub async fn observe_with(&self, client: &MptClient) -> Result<Vec<HeadSummary>> {
        let ours = self.summaries_off_runtime().await?;
        let exchange = client
            .head_exchange(ours, |_theirs| (Vec::new(), Vec::new()))
            .await?;
        let syncer = self.clone();
        let peer = client.remote_id();
        let summaries = exchange.summaries.clone();
        crate::blocking::offload(move || {
            syncer.observe_summaries_from(Some(peer), &summaries, now_ns())
        })
        .await?;
        Ok(exchange.summaries)
    }

    /// [`Syncer::offer_head`] on the blocking pool.
    async fn offer_head_off_runtime(&self, head: &SignedHead) -> Result<HeadOutcome> {
        let syncer = self.clone();
        let head = head.clone();
        crate::blocking::offload(move || syncer.offer_head(&head, now_ns())).await
    }

    /// [`Syncer::local_summaries`] on the blocking pool.
    ///
    /// Summarizing asks the trie whether each advertised root is held whole,
    /// which is a walk the first time it is asked of a root (§5.1) — not
    /// something to do on a runtime worker.
    async fn summaries_off_runtime(&self) -> Result<Vec<HeadSummary>> {
        let syncer = self.clone();
        crate::blocking::offload(move || syncer.local_summaries()).await
    }

    /// Runs one full `Hello` push-pull exchange with a peer, then fetches
    /// whatever it advertised that we do not have (§5.2, §5.3).
    pub async fn sync_with(&self, client: &MptClient) -> Result<SyncReport> {
        let ours = self.summaries_off_runtime().await?;
        let store = self.store.clone();

        let mut report = SyncReport::default();
        let theirs = client
            .head_exchange(ours.clone(), |theirs| {
                // Both slots may be advertised per origin, so the comparison is
                // against the best summary either side has for it, never the
                // first one that happens to match.
                let best = |set: &[HeadSummary], origin: &OriginId| {
                    set.iter()
                        .filter(|s| &s.origin == origin)
                        .map(|s| s.order_key())
                        .max()
                };
                // Push: the servable head we hold, whenever it beats theirs.
                // Keyed off the complete slot directly rather than off whichever
                // summary was advertised: what we can hand over is exactly what
                // the complete slot holds.
                let mut push = Vec::new();
                let mut pushed_for: Vec<OriginId> = Vec::new();
                for summary in &ours {
                    if pushed_for.contains(&summary.origin) {
                        continue;
                    }
                    let Ok(Some(head)) = store.complete_head(&summary.origin) else {
                        continue;
                    };
                    let mine = (head.seq, head.root.0);
                    if best(theirs, &summary.origin).is_none_or(|peer| mine > peer) {
                        pushed_for.push(summary.origin.clone());
                        push.push(head);
                    }
                }
                // Pull: origins where the peer is ahead of us.
                let mut want = Vec::new();
                for summary in theirs {
                    if want.contains(&summary.origin) {
                        continue;
                    }
                    if best(&ours, &summary.origin).is_none_or(|mine| summary.order_key() > mine) {
                        want.push(summary.origin.clone());
                    }
                }
                (push, want)
            })
            .await?;

        // Every exchange is also an observation of what peers hold for our own
        // origin, which is what `synch recover` reads (§3.4).
        {
            let syncer = self.clone();
            let peer = client.remote_id();
            let summaries = theirs.summaries.clone();
            crate::blocking::offload(move || {
                syncer.observe_summaries_from(Some(peer), &summaries, now_ns())
            })
            .await?;
        }

        report.heads_pushed = theirs.pushed;
        for head in theirs.received {
            // Adoption may promote the head, which walks the trie and
            // re-materializes every changed leaf in one transaction (§5.2).
            let outcome = match self.offer_head_off_runtime(&head).await {
                Ok(outcome) => outcome,
                Err(e) if is_origin_fault(&e) => {
                    contain(&head.origin, &e, &mut report);
                    continue;
                }
                Err(e) => return Err(e),
            };
            match outcome {
                HeadOutcome::Pending => {
                    report.heads_accepted += 1;
                    match self.fetch_pending(client, &head.origin).await {
                        Ok(FetchOutcome::Completed) => report.tries_completed += 1,
                        Ok(FetchOutcome::Abandoned) => report.heads_abandoned += 1,
                        Ok(_) => {}
                        Err(e) if is_origin_fault(&e) => contain(&head.origin, &e, &mut report),
                        Err(e) => return Err(e),
                    }
                }
                HeadOutcome::Completed => {
                    report.heads_accepted += 1;
                    report.tries_completed += 1;
                }
                HeadOutcome::BadSignature | HeadOutcome::Unbound => report.heads_rejected += 1,
                HeadOutcome::NotNewer => {}
            }
        }

        // A head can arrive by reactive push (§5.3) long before its trie does.
        // Such a head sits in the pending slot and is *not* newer than what we
        // hold, so the exchange above will not have asked for it — but §5.2
        // says its nodes may be fetched from any peer advertising a complete
        // head for that origin at or above its seq. Do exactly that here, which
        // is what turns "I heard about it" into "I can serve it".
        for stored in self.store.all_heads(Slot::Pending)? {
            let pending = stored.head;
            let servable = theirs.summaries.iter().any(|summary| {
                summary.origin == pending.origin
                    && summary.complete
                    && summary.order_key() >= (pending.seq, pending.root.0)
            });
            if !servable {
                continue;
            }
            match self.fetch_pending(client, &pending.origin).await {
                Ok(FetchOutcome::Completed) => report.tries_completed += 1,
                Ok(FetchOutcome::Abandoned) => report.heads_abandoned += 1,
                Ok(_) => {}
                Err(e) if is_origin_fault(&e) => contain(&pending.origin, &e, &mut report),
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }
}

/// Verifies one batch of what a peer served and commits it, refusing anything
/// that was not asked for.
///
/// Three things are checked and all three are containment: a payload has to hash
/// to the hash it was requested by, it has to be one of the hashes this walk
/// asked for, and it may appear only once. Without the second, a peer answering
/// every request with `missing` plus one self-consistent pair of its own counts
/// as progress on every round — the unproductive counter never fires, the fetch
/// loop never ends, and the junk lands in the trie tables.
///
/// The third is what bounds the answer's *size*. A request is capped at
/// [`MAX_BATCH`] hashes, but the response it draws is capped only by the frame
/// length: a peer could answer 256 wanted hashes with a 16 MiB frame repeating
/// one of them, every entry passing both other checks, and each repeat costs an
/// autocommit `INSERT OR IGNORE` on the store's single write connection — so a
/// cheap request would buy six figures of serialized statements, blocking every
/// other database user in the process. Counting repeats as `learned` would also
/// defeat the [`MAX_UNPRODUCTIVE_ROUNDS`] escape, since a peer serving one real
/// node and 10^5 copies of it makes progress forever.
///
/// Nodes and values differ only in how a payload is hashed, where it is stored
/// and which error names it, so the checks live here rather than in two loops
/// that have to be kept in step.
///
/// Returns how many were stored.
fn take_served(
    requested: &[synch_core::Hash],
    served: &[(synch_core::Hash, Vec<u8>)],
    what: &str,
    hash_of: impl Fn(&[u8]) -> Option<synch_core::Hash>,
    mismatch: impl Fn(synch_core::Hash) -> NetError,
    put: impl Fn(&synch_core::Hash, &[u8]) -> Result<()>,
) -> Result<usize> {
    // A wanted hash can be asked for once and so may be answered once. The set
    // is built from the request, never from the response, so the peer cannot
    // grow it.
    let mut outstanding: std::collections::HashSet<synch_core::Hash> =
        requested.iter().copied().collect();
    let mut stored = 0usize;
    for (hash, bytes) in served {
        // `remove` is the containment check and the repeat check at once: a
        // hash that was never asked for is not in the set, and one already
        // served has been taken out of it.
        if !outstanding.remove(hash) {
            return Err(EngineError::Net(NetError::Unexpected(format!(
                "peer served unrequested or repeated trie {what} {hash}"
            ))));
        }
        // A malicious or corrupt peer can withhold, never inject.
        if hash_of(bytes) != Some(*hash) {
            return Err(EngineError::Net(mismatch(*hash)));
        }
        put(hash, bytes)?;
        stored += 1;
    }
    Ok(stored)
}

/// The serve side's view of the reconciler (§5.2).
///
/// `synch-net` answers `Hello` and `HeadPush` by calling through this, so the
/// acceptance rule, the binding check and the promotion transaction stay here —
/// in the layer that owns head state — while the networking crate keeps only
/// the framing and the streams. It is also what lets one `Syncer` serve both
/// directions: the same object the node dials with is handed to the endpoint,
/// so a head flipping to complete rings the one bell either way, instead of a
/// `Notify` being threaded through the endpoint constructor to connect two
/// syncers that never knew about each other.
impl HeadSink for Syncer {
    fn local_summaries(&self) -> std::result::Result<Vec<HeadSummary>, NetError> {
        Syncer::local_summaries(self).map_err(to_net)
    }

    fn observe_summaries_from(
        &self,
        peer: synch_core::NodeId,
        summaries: &[HeadSummary],
        now: i64,
    ) -> std::result::Result<(), NetError> {
        Syncer::observe_summaries_from(self, Some(peer), summaries, now)
            .map(|_| ())
            .map_err(to_net)
    }

    fn offer_head(&self, head: &SignedHead, now: i64) -> std::result::Result<(), NetError> {
        Syncer::offer_head(self, head, now)
            .map(|_| ())
            .map_err(to_net)
    }

    fn heads_for(&self, origins: &[OriginId]) -> std::result::Result<Vec<SignedHead>, NetError> {
        Syncer::heads_for(self, origins).map_err(to_net)
    }
}

/// Renders an engine failure for the wire.
///
/// The seam is one-way by design: the engine names domain failures in its own
/// error type, and what crosses back into `synch-net` is a protocol-level
/// description of one. A `NetError` variant per storage fault is what would
/// make the transport enum a domain taxonomy.
fn to_net(error: EngineError) -> NetError {
    match error {
        EngineError::Net(e) => e,
        other => NetError::Unexpected(other.to_string()),
    }
}

/// True if a failure is about *one origin's* replicated data rather than about
/// the peer or the connection.
///
/// A record that will not decode, or a trie operation that will not complete
/// over it, is a fault in what some origin published — durable, and reproduced
/// on every exchange that reaches it. A protocol violation
/// ([`NetError::NodeHashMismatch`]) or a broken stream is about the peer we are
/// talking to, and still ends the exchange.
fn is_origin_fault(error: &EngineError) -> bool {
    matches!(error, EngineError::Store(_) | EngineError::Mpt(_))
}

/// Logs a contained per-origin failure and records it in the report.
///
/// One origin publishing something this node cannot materialize must not stop
/// it from converging with every *other* origin the same peer serves: the
/// failing head keeps its slot, the exchange carries on, and the count says
/// plainly that something was left behind (§5.2).
fn contain(origin: &OriginId, error: &EngineError, report: &mut SyncReport) {
    tracing::warn!(
        origin = %origin,
        error = %error,
        "origin left behind: its published data could not be applied"
    );
    report.heads_failed += 1;
}

/// What one exchange achieved, for logging and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Heads we pushed to the peer.
    pub heads_pushed: usize,
    /// Heads the peer sent that we adopted.
    pub heads_accepted: usize,
    /// Heads the peer sent that failed verification or the binding check.
    pub heads_rejected: usize,
    /// Tries that became complete during this exchange.
    pub tries_completed: usize,
    /// Pending heads abandoned because nobody could serve their nodes.
    pub heads_abandoned: usize,
    /// Origins skipped because their own published data could not be applied.
    pub heads_failed: usize,
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use synch_core::{file_key, FileEntry, Hash, OriginId, SignedHead};
    use synch_store::{Binding, BindingSource};

    use super::*;

    fn setup() -> (tempfile::TempDir, Arc<Store>, SecretKey, OriginId) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let key = SecretKey::generate();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&Binding {
                origin: origin.clone(),
                node_id: key.public(),
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        (dir, store, key, origin)
    }

    fn publish(store: &Store, files: &[&str]) -> Hash {
        let trie = Trie::new(store);
        let mut root = Hash::EMPTY;
        for path in files {
            let entry = FileEntry::file(7, 0, Hash::new(path.as_bytes()), 1);
            root = trie
                .insert(
                    root,
                    &file_key("s", path).unwrap(),
                    &postcard::to_stdvec(&entry).unwrap(),
                )
                .unwrap();
        }
        root
    }

    #[test]
    fn a_head_with_a_present_trie_completes_immediately() {
        let (_d, store, key, origin) = setup();
        let root = publish(&store, &["a", "b"]);
        let syncer = Syncer::new(store.clone());
        let head = SignedHead::sign(&key, origin.clone(), 1, root, 0);
        assert_eq!(syncer.offer_head(&head, 0).unwrap(), HeadOutcome::Completed);
        assert_eq!(store.complete_head(&origin).unwrap(), Some(head));
        assert_eq!(
            store
                .list_entries(Some(&origin), "s", "", None, None)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn a_head_with_a_missing_trie_stays_pending() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let head = SignedHead::sign(&key, origin.clone(), 1, Hash::new(b"unknown root"), 0);
        assert_eq!(syncer.offer_head(&head, 0).unwrap(), HeadOutcome::Pending);
        assert_eq!(store.pending_head(&origin).unwrap(), Some(head));
        // The complete slot is untouched while a fetch is in progress.
        assert_eq!(store.complete_head(&origin).unwrap(), None);
    }

    /// A member signing endlessly at one seq stops being *retained* — and is
    /// never refused.
    ///
    /// Same-seq forks outlive `root_retention` until the origin publishes past
    /// the forked seq, which an origin flooding one seq never does, so the
    /// width has to be bounded somewhere. It is bounded by eviction, not by
    /// refusal: the greatest root at the seq always wins the slot, so the
    /// answer does not depend on which roots arrived first.
    #[test]
    fn same_seq_forks_are_evicted_at_the_cap_and_never_refused() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        // Ascending roots, so each one supersedes the last.
        for i in 1..=MAX_RETAINED_FORKS as u8 {
            let head = SignedHead::sign(&key, origin.clone(), 1, Hash([i; 32]), 0);
            assert!(
                syncer.offer_head(&head, 0).unwrap().accepted(),
                "fork {i} is evidence and is taken"
            );
        }
        assert_eq!(store.fork_width(&origin, 1).unwrap(), MAX_RETAINED_FORKS);

        // Past the cap the heads keep being accepted on their merits, and the
        // retained set stays at the cap by dropping its lowest roots.
        for i in 1..=4u8 {
            let flood = SignedHead::sign(
                &key,
                origin.clone(),
                1,
                Hash([MAX_RETAINED_FORKS as u8 + i; 32]),
                0,
            );
            assert_eq!(syncer.offer_head(&flood, 0).unwrap(), HeadOutcome::Pending);
        }
        assert_eq!(
            store.fork_width(&origin, 1).unwrap(),
            MAX_RETAINED_FORKS,
            "the retained set stops at the cap"
        );
        let retained: Vec<u8> = store
            .head_history(&origin)
            .unwrap()
            .iter()
            .filter(|h| h.seq == 1)
            .map(|h| h.root.0[0])
            .collect();
        assert_eq!(
            retained,
            (5..=12u8).rev().collect::<Vec<_>>(),
            "the greatest roots are what is kept, whatever arrived first"
        );
        assert_eq!(
            store.head_floor(&origin).unwrap().unwrap().1,
            Hash([MAX_RETAINED_FORKS as u8 + 4; 32]),
            "and the greatest root of all holds the slot"
        );
        // The evidence a fork exists is still there.
        assert_eq!(store.equivocations().unwrap().len(), 1);

        // A head at a later seq is the origin moving on, and is taken normally.
        let next = SignedHead::sign(&key, origin.clone(), 2, Hash([1u8; 32]), 0);
        assert!(syncer.offer_head(&next, 0).unwrap().accepted());
    }

    /// The same head set, offered in any order, settles on the same head.
    ///
    /// This is the join-semilattice §5.2 rests on, and the fork cap must not
    /// break it: refusing the ninth root at a seq would leave a node that met
    /// the greatest root early holding it while a node that met it tenth never
    /// took it, and the two would then refuse each other's heads forever.
    /// Acceptance is decided by `supersedes` alone, so the greatest
    /// `(seq, root)` wins from every arrival order.
    #[test]
    fn arrival_order_cannot_change_which_head_a_node_settles_on() {
        let roots: Vec<u8> = (1..=9).collect();
        let key = SecretKey::generate();
        let origin = OriginId::named("nas", "x.example").unwrap();
        let heads: Vec<SignedHead> = roots
            .iter()
            .map(|i| SignedHead::sign(&key, origin.clone(), 1, Hash([*i; 32]), 0))
            .collect();

        // Ascending, descending, and the shape that stresses it hardest: the
        // greatest root first, so every later offer loses the comparison.
        let mut orders: Vec<Vec<usize>> = vec![
            (0..heads.len()).collect(),
            (0..heads.len()).rev().collect(),
            std::iter::once(heads.len() - 1)
                .chain(0..heads.len() - 1)
                .collect(),
        ];
        // And a handful of shuffles, so this is not three hand-picked cases.
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..8 {
            let mut order: Vec<usize> = (0..heads.len()).collect();
            for i in (1..order.len()).rev() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                order.swap(i, (state >> 33) as usize % (i + 1));
            }
            orders.push(order);
        }

        let mut settled = Vec::new();
        let mut dirs = Vec::new();
        for order in &orders {
            // One node per arrival order, each with the one key bound.
            let dir = tempfile::tempdir().unwrap();
            let store = Arc::new(Store::open(dir.path()).unwrap());
            store
                .put_binding(&Binding {
                    origin: origin.clone(),
                    node_id: key.public(),
                    source: BindingSource::Static,
                    domain: None,
                    note: None,
                    added_at: 0,
                    expires_at: None,
                })
                .unwrap();
            let syncer = Syncer::new(store.clone());
            for i in order {
                assert!(
                    matches!(
                        syncer.offer_head(&heads[*i], 0).unwrap(),
                        HeadOutcome::Pending | HeadOutcome::Completed | HeadOutcome::NotNewer
                    ),
                    "every offer is judged on the ordering rule alone"
                );
            }
            settled.push(store.head_floor(&origin).unwrap().unwrap());
            dirs.push(dir);
        }
        assert!(
            settled.windows(2).all(|w| w[0] == w[1]),
            "every arrival order settles on the same head: {settled:?}"
        );
        assert_eq!(settled[0], (1, Hash([9u8; 32])));
    }

    /// A peer may only answer with what it was asked for.
    ///
    /// A self-consistent pair nobody requested counts as progress if it is
    /// taken: the unproductive counter resets on every round, the fetch never
    /// gives up on the peer, and the junk is written to the trie tables. Values
    /// are held to it exactly as nodes are, which is why one helper does both.
    #[test]
    fn a_peer_may_not_answer_with_what_was_not_asked_for() {
        let wanted = Hash::new(b"wanted");
        let junk = b"nobody asked for this".to_vec();
        let unrequested = Hash::new(&junk);
        let stored = std::cell::RefCell::new(Vec::new());
        let take = |requested: &[Hash], served: &[(Hash, Vec<u8>)]| {
            take_served(
                requested,
                served,
                "value",
                |bytes| Some(Hash::new(bytes)),
                |expected| NetError::ValueHashMismatch { expected },
                |hash, _| {
                    stored.borrow_mut().push(*hash);
                    Ok(())
                },
            )
        };

        let err = take(&[wanted], &[(unrequested, junk.clone())])
            .expect_err("an unrequested value is refused");
        assert!(err.to_string().contains("unrequested"), "{err}");
        assert!(stored.borrow().is_empty(), "and nothing was written");

        // What was asked for is taken, and a payload that does not hash to the
        // hash it was requested by is still refused on its own terms.
        assert_eq!(take(&[unrequested], &[(unrequested, junk)]).unwrap(), 1);
        assert!(matches!(
            take(
                &[unrequested],
                &[(unrequested, b"different bytes".to_vec())]
            ),
            Err(EngineError::Net(NetError::ValueHashMismatch { .. }))
        ));
        assert_eq!(*stored.borrow(), vec![unrequested]);
    }

    /// A peer may answer each wanted hash once.
    ///
    /// Containment alone bounds *which* hashes may come back, not how many
    /// times: a request capped at `MAX_BATCH` draws a response capped only by
    /// the frame length, so one wanted node repeated to fill 16 MiB would pass
    /// every other check and cost an autocommit insert apiece on the store's
    /// single write connection. Counting the repeats as progress would also
    /// defeat `MAX_UNPRODUCTIVE_ROUNDS`, so a peer serving one real node and a
    /// hundred thousand copies of it would never look stuck.
    #[test]
    fn a_peer_may_not_answer_the_same_hash_twice() {
        let payload = b"a node that really was asked for".to_vec();
        let wanted = Hash::new(&payload);
        let stored = std::cell::RefCell::new(Vec::new());
        let take = |requested: &[Hash], served: &[(Hash, Vec<u8>)]| {
            take_served(
                requested,
                served,
                "value",
                |bytes| Some(Hash::new(bytes)),
                |expected| NetError::ValueHashMismatch { expected },
                |hash, _| {
                    stored.borrow_mut().push(*hash);
                    Ok(())
                },
            )
        };

        let err = take(
            &[wanted],
            &[(wanted, payload.clone()), (wanted, payload.clone())],
        )
        .expect_err("a repeat is refused");
        assert!(err.to_string().contains("repeated"), "{err}");
        // The first copy was taken before the second was seen; what matters is
        // that the answer does not run past the request.
        assert_eq!(*stored.borrow(), vec![wanted]);

        // The honest shape — every wanted hash at most once — still passes.
        stored.borrow_mut().clear();
        let other = b"a second wanted node".to_vec();
        let other_hash = Hash::new(&other);
        assert_eq!(
            take(
                &[wanted, other_hash],
                &[(wanted, payload), (other_hash, other)]
            )
            .unwrap(),
            2
        );
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let mut head = SignedHead::sign(&key, origin.clone(), 1, Hash::EMPTY, 0);
        head.seq = 99;
        assert_eq!(
            syncer.offer_head(&head, 0).unwrap(),
            HeadOutcome::BadSignature
        );
        assert_eq!(store.complete_head(&origin).unwrap(), None);
        assert!(store.head_history(&origin).unwrap().is_empty());
    }

    #[test]
    fn an_unbound_signer_is_rejected_even_when_the_signature_verifies() {
        // §3.2: heads whose signing key is not bound to the claimed origin are
        // ignored even if relayed by a trusted peer.
        let (_d, store, _key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let stranger = SecretKey::generate();
        let head = SignedHead::sign(&stranger, origin.clone(), 1, Hash::EMPTY, 0);
        head.verify_signature().unwrap();
        assert_eq!(syncer.offer_head(&head, 0).unwrap(), HeadOutcome::Unbound);
        assert_eq!(store.complete_head(&origin).unwrap(), None);
    }

    #[test]
    fn an_expired_binding_no_longer_admits_heads() {
        // The instants are real ones: an expiry is compared against a clock,
        // and a reading below `MIN_TRUSTED_NS` dates nothing, so a binding
        // offered at "now = 50" is not live at all (§3.2).
        let before = synch_core::MIN_TRUSTED_NS + 50;
        let expiry = synch_core::MIN_TRUSTED_NS + 100;
        let after = synch_core::MIN_TRUSTED_NS + 200;
        let (_d, store, _k, origin) = setup();
        let rotated = SecretKey::generate();
        store
            .put_binding(&Binding {
                origin: origin.clone(),
                node_id: rotated.public(),
                source: BindingSource::Dns,
                domain: Some("x.example".into()),
                note: None,
                added_at: 0,
                expires_at: Some(expiry),
            })
            .unwrap();
        let syncer = Syncer::new(store.clone());
        let head = SignedHead::sign(&rotated, origin.clone(), 1, Hash::EMPTY, 0);
        assert_eq!(
            syncer.offer_head(&head, before).unwrap(),
            HeadOutcome::Completed
        );
        let later = SignedHead::sign(&rotated, origin, 2, Hash::new(b"x"), 0);
        assert_eq!(
            syncer.offer_head(&later, after).unwrap(),
            HeadOutcome::Unbound
        );
    }

    #[test]
    fn the_seq_root_rule_accepts_equal_seq_greater_root() {
        // Strictly-greater-on-seq alone would not converge: two peers receiving
        // different same-seq heads in different orders would diverge forever.
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let low = SignedHead::sign(&key, origin.clone(), 1, Hash([1u8; 32]), 0);
        let high = SignedHead::sign(&key, origin.clone(), 1, Hash([2u8; 32]), 0);

        assert!(syncer.offer_head(&low, 0).unwrap().accepted());
        assert!(syncer.offer_head(&high, 0).unwrap().accepted());
        assert_eq!(
            store.head_floor(&origin).unwrap().unwrap().1,
            Hash([2u8; 32])
        );
        // And the reverse order converges to the same head.
        assert_eq!(syncer.offer_head(&low, 0).unwrap(), HeadOutcome::NotNewer);
    }

    #[test]
    fn same_seq_forks_are_both_retained_as_evidence() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        syncer
            .offer_head(
                &SignedHead::sign(&key, origin.clone(), 1, Hash([1u8; 32]), 0),
                0,
            )
            .unwrap();
        syncer
            .offer_head(
                &SignedHead::sign(&key, origin.clone(), 1, Hash([2u8; 32]), 0),
                0,
            )
            .unwrap();
        let equivocations = store.equivocations().unwrap();
        assert_eq!(equivocations.len(), 1);
        assert_eq!(equivocations[0].heads.len(), 2);
        for head in &equivocations[0].heads {
            head.verify_signature().unwrap();
        }
    }

    #[test]
    fn older_heads_are_ignored() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let new = SignedHead::sign(&key, origin.clone(), 5, Hash([5u8; 32]), 0);
        syncer.offer_head(&new, 0).unwrap();
        let old = SignedHead::sign(&key, origin.clone(), 4, Hash([9u8; 32]), 0);
        assert_eq!(syncer.offer_head(&old, 0).unwrap(), HeadOutcome::NotNewer);
        assert_eq!(store.head_floor(&origin).unwrap().unwrap().0, 5);
    }

    /// §3.4 step 2: a peer advertising a head for *our* origin is recorded as
    /// an observation, never adopted — the head behind it is signed by a key
    /// that is no longer bound.
    #[test]
    fn summaries_for_our_own_origin_are_observed_not_adopted() {
        let (_d, store, lost_key, origin) = setup();
        store.set_self_origin(&origin).unwrap();
        // The lost key is no longer bound to the origin: recovery starts from a
        // database that knows only the new key.
        store
            .remove_binding(&origin, &lost_key.public(), BindingSource::Static)
            .unwrap();
        let syncer = Syncer::new(store.clone());

        let observed = syncer
            .observe_summaries(
                &[
                    HeadSummary {
                        origin: origin.clone(),
                        seq: 100,
                        root: Hash([7u8; 32]),
                        complete: true,
                    },
                    HeadSummary {
                        origin: OriginId::named("laptop", "x.example").unwrap(),
                        seq: 4,
                        root: Hash([1u8; 32]),
                        complete: true,
                    },
                ],
                42,
            )
            .unwrap();
        assert_eq!(observed, Some(100));
        assert_eq!(store.observed_head(&origin).unwrap().unwrap().seq, 100);
        // Only our own origin is tracked this way.
        assert_eq!(
            store
                .observed_head(&OriginId::named("laptop", "x.example").unwrap())
                .unwrap(),
            None
        );
        // And nothing became a head: the signer is unbound.
        assert_eq!(store.complete_head(&origin).unwrap(), None);
        let head = SignedHead::sign(&lost_key, origin.clone(), 100, Hash([7u8; 32]), 0);
        assert_eq!(syncer.offer_head(&head, 0).unwrap(), HeadOutcome::Unbound);
        assert_eq!(store.head_floor(&origin).unwrap(), None);
    }

    #[test]
    fn a_store_with_no_identity_observes_nothing() {
        let (_d, store, _key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        assert_eq!(
            syncer
                .observe_summaries(
                    &[HeadSummary {
                        origin: origin.clone(),
                        seq: 9,
                        root: Hash::EMPTY,
                        complete: true,
                    }],
                    0,
                )
                .unwrap(),
            None
        );
        assert_eq!(store.observed_head(&origin).unwrap(), None);
    }

    #[test]
    fn summaries_report_completeness_honestly() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let root = publish(&store, &["a"]);
        syncer
            .offer_head(&SignedHead::sign(&key, origin.clone(), 1, root, 0), 0)
            .unwrap();
        let summaries = syncer.local_summaries().unwrap();
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].complete);

        // A pending head for an unknown root shows up as explicitly incomplete
        // — *alongside* the complete head, not in place of it. Both facts are
        // load-bearing: the peer needs to know the newer head exists, and it
        // needs to know we can still serve the older root, or it will neither
        // pull from us nor count us as a provider for it.
        syncer
            .offer_head(
                &SignedHead::sign(&key, origin, 2, Hash::new(b"unknown"), 0),
                0,
            )
            .unwrap();
        let summaries = syncer.local_summaries().unwrap();
        assert_eq!(summaries.len(), 2);
        let complete: Vec<_> = summaries.iter().filter(|s| s.complete).collect();
        assert_eq!(complete.len(), 1, "the servable root is still advertised");
        assert_eq!(complete[0].seq, 1);
        assert_eq!(complete[0].root, root);
        let pending: Vec<_> = summaries.iter().filter(|s| !s.complete).collect();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].seq, 2);
    }

    #[test]
    fn a_promotion_that_fails_to_materialize_does_not_flip_the_head() {
        // §5.2: the flip and the materialization are one transaction, so a
        // crash can never leave `entries` missing a promoted head's delta. A
        // record the materializer cannot decode stands in for the crash.
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());

        let good = publish(&store, &["a"]);
        let complete = SignedHead::sign(&key, origin.clone(), 1, good, 0);
        assert!(matches!(
            syncer.offer_head(&complete, 0).unwrap(),
            HeadOutcome::Completed
        ));

        // A pending head whose trie is fully present but carries a well-formed
        // `f:` key with a value that is not a `FileEntry`.
        let trie = Trie::new(store.as_ref());
        let poisoned = trie
            .insert(good, &file_key("s", "poisoned").unwrap(), &[0xffu8; 8])
            .unwrap();
        let pending = SignedHead::sign(&key, origin.clone(), 2, poisoned, 0);
        store
            .put_head(synch_store::Slot::Pending, &pending, 0, 0)
            .unwrap();

        let err = syncer.try_promote(&origin, 0).unwrap_err().to_string();
        assert!(err.contains("corrupt record"), "{err}");

        // The complete head is untouched and the pending head is still pending.
        //
        // The poisoned root *is* in `head_history` — every head in a slot has
        // its signature there by construction (§10, v11), and a pending head is
        // no exception. What must not have happened is the flip, so that is what
        // is asserted: the complete slot still names the good root.
        let complete = store.complete_head(&origin).unwrap().unwrap();
        assert_eq!(complete.seq, 1);
        assert_eq!(complete.root, good);
        assert_ne!(complete.root, poisoned);
        assert_eq!(store.pending_head(&origin).unwrap().unwrap().seq, 2);
        assert!(store.entry(&origin, "s", "poisoned").unwrap().is_none());
        // And the entry the *complete* head materialized is still there.
        assert!(store.entry(&origin, "s", "a").unwrap().is_some());
    }
}
