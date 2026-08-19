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

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use synch_core::{now_ns, Hash, HeadSummary, OriginId, SignedHead, MAX_BATCH};
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

/// What a promotion attempt concluded.
///
/// Three states rather than a `bool`, because the callers cannot tell them apart
/// and kept getting it wrong: a promotion that did nothing because the trie is
/// still arriving and one that retired the head on a verdict already in the memo
/// are both "did not flip", and reporting the second as the first counted a
/// discarded head as accepted. Inferring it by re-reading the slot afterwards was
/// no better — it cost a lock on every ordinary adoption and still could not see
/// which case it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Promotion {
    /// The pending head's trie was wholly present and the complete slot flipped.
    Flipped,
    /// A pending head stands and its trie is not all here yet: it needs a fetch.
    Waiting,
    /// This promotion is in the refusal memo, so the head was retired unjudged.
    Refused,
    /// Nothing is pending now: there was no pending head, or the complete slot
    /// had overtaken the one there and it was dropped.
    ///
    /// Distinct from `Waiting`, which the two used to share. The caller has to
    /// tell them apart: `Waiting` means a head is sitting there needing its trie,
    /// so it is reported accepted and rings the fetch bell, and doing that for a
    /// head that was just dropped counted a discarded head as accepted and woke
    /// the anti-entropy loop for something that no longer existed. The overtake
    /// is reachable whenever a local `publish` or an `activate` moves the
    /// complete slot between the offer's transaction and this one — both derive
    /// their seq from the complete slot alone (§3.4).
    Idle,
}

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
    /// The head was adopted, and this node has already judged that it cannot
    /// materialize this promotion, so the head was retired again rather than
    /// re-judged (see [`Syncer::try_promote`]).
    ///
    /// Counted as a failure for this origin, because it is one: §12 requires the
    /// count of origins left behind to be in the sync report, and this is the
    /// only outcome that carries it after the first exchange.
    Refused,
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
    /// Rung when a head is adopted as *pending*: its trie is not here and
    /// nothing in this process is going to fetch it until somebody dials.
    on_pending: Option<Arc<tokio::sync::Notify>>,
    /// Promotions this node has tried and cannot repeat, so it does not spend
    /// the diff again. Owned by [`Syncer::try_promote`], which is the only
    /// place the pair a verdict is about is known.
    refused: Arc<Mutex<HashSet<Verdict>>>,
}

/// What a promotion verdict is about: the head, and the root it would be
/// materialized *from*.
///
/// Both, because the verdict is a property of the pair. `materialize_diff`
/// prunes at equal node hashes and pays only for what differs, so a root that
/// outruns the walk's position budget from a far-behind complete slot promotes
/// cleanly once an intermediate head has landed. Keyed on the new root alone
/// this node would refuse that root for the rest of its life while every peer
/// held it — silent per-origin divergence.
type Verdict = (OriginId, u64, Hash, Hash);

/// How many refused promotions are remembered before the set is dropped
/// wholesale.
///
/// None at all in a healthy cluster. Dropped rather than evicted one at a time,
/// like the completeness memo: forgetting costs one more attempt, and no
/// correctness rests on the memory.
const MAX_REFUSED_HEADS: usize = 1024;

impl Syncer {
    /// Binds a syncer to a store.
    pub fn new(store: Arc<Store>) -> Self {
        Syncer {
            store,
            on_change: None,
            on_pending: None,
            refused: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Whether this exact promotion has already been tried and failed.
    fn is_refused(&self, key: &Verdict) -> bool {
        self.refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(key)
    }

    /// Remembers that this promotion failed on the origin's own data.
    ///
    /// In memory rather than in the schema: the verdict is about what *this
    /// build* can decode, so an upgraded node should re-attempt it, and a restart
    /// is the cheapest expression of that.
    fn refuse(&self, key: Verdict) {
        let mut refused = self
            .refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if refused.len() >= MAX_REFUSED_HEADS {
            refused.clear();
        }
        refused.insert(key);
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

    /// Rings `wake` whenever a head is adopted as pending (§5.3).
    ///
    /// A head that arrives by push names a root this node has never seen, by
    /// construction — that is what makes it worth pushing. The serve side
    /// adopts it into the pending slot and there the matter rested: nothing
    /// scheduled the fetch, so the trie under it arrived only when this node's
    /// own anti-entropy round next happened to dial a peer advertising it
    /// complete, one jittered interval later. What propagated in the sub-second
    /// §5.3 claims for reactive push was a pointer that no reading surface —
    /// `entries`, mirrors, the S3 gateway — looks at, because all of them sit
    /// behind promotion.
    pub fn on_pending(mut self, wake: Option<Arc<tokio::sync::Notify>>) -> Self {
        self.on_pending = wake;
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
        // The greatest summary for our origin, and only that one. What the row
        // records is a maximum — `record_observed_head` keeps the higher of what
        // is stored and what arrives — so offering it each of a message's
        // summaries in turn wrote the same answer many times over.
        //
        // That was the cost, not the semantics. A `Hello` may carry
        // `MAX_HEADS_PER_MESSAGE` summaries, summaries are unauthenticated by
        // design (§3.4), and our own origin is public — so a peer could set
        // every one of them to it and buy thousands of autocommit writes on the
        // store's single write connection for one message, repeatable per
        // stream. Picking the maximum first makes it one.
        // A seq the store cannot represent is dropped here rather than carried
        // to `record_observed_head`, which refuses it — correctly, because
        // clamping would silently invert every ordering over the column. But a
        // refusal there is an `Err`, and both callers propagate it: the serve
        // side aborts the stream before it has read the peer's push or answered
        // its want, and the dial side aborts before the adoption loop. A
        // summary is an unauthenticated *claim* (§3.4), so an unusable one has
        // to cost the claim and not the exchange — §12's containment rule, the
        // same one `offer_head` and the pending sweep hold to.
        let representable = |s: &&HeadSummary| {
            if s.seq > i64::MAX as u64 {
                tracing::warn!(
                    origin = %own,
                    seq = s.seq,
                    peer = claimed_by.map(|k| k.fmt_short().to_string()).unwrap_or_default(),
                    "a peer claims a head for our own origin at an unrepresentable seq; ignored"
                );
                return false;
            }
            true
        };
        let best = summaries
            .iter()
            .filter(|s| s.origin == own)
            .filter(representable)
            .max_by_key(|s| s.order_key());
        if let Some(summary) = best {
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
            // Acceptance deliberately does not consult the refusal memo: a
            // verdict is about a *promotion*, which is a pair of roots, and
            // only `try_promote` knows both. A head this node has already
            // failed on is adopted here and retired there, which costs two
            // indexed writes rather than the diff.
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
        match self.try_promote(&head.origin, now)? {
            Promotion::Flipped => Ok(HeadOutcome::Completed),
            // Rung here, not before the promotion. A refused head is adopted and
            // retired in the same breath — adopting it is what makes it beat the
            // floor again — so ringing on adoption woke the anti-entropy loop for
            // a head that no longer exists. `notify_one` keeps a permit and the
            // loop is not parked during a round, so the permit was always waiting
            // when the round ended: one unapplicable head held by one peer pinned
            // the node to back-to-back rounds, forever, at the `REACTIVE_FLOOR`
            // rather than the interval. It also bought a pointless extra round
            // for every head whose trie was already here.
            Promotion::Waiting => {
                if let Some(wake) = &self.on_pending {
                    // One permit no matter how often this rings, exactly as the
                    // promotion bell does — a wake landing mid-round must not be
                    // lost, and the loop is parked on this only between rounds
                    // (§5.3).
                    wake.notify_one();
                }
                Ok(HeadOutcome::Pending)
            }
            Promotion::Refused => Ok(HeadOutcome::Refused),
            // Adopted, and then dropped again by the promotion because the
            // complete slot had overtaken it. Nothing is pending, so this is not
            // an acceptance and there is nothing to fetch.
            Promotion::Idle => Ok(HeadOutcome::NotNewer),
        }
    }

    /// Flips the pending head to complete if its whole trie is present,
    /// re-materializing the derived views from the node-level diff.
    ///
    /// The flip and the materialization are one SQLite transaction (§5.2,
    /// §10): a crash between them would leave `entries` — what the unified
    /// tree, mirrors, and `synch-s3` serve from — missing a promoted head's
    /// delta, with nothing left to say so.
    ///
    /// An origin fault is condemned here, because this is the only place that
    /// knows which head was judged. Both callers arrive with a head from an
    /// earlier snapshot — `offer_head` has committed and released the connection,
    /// and the maintenance sweep is a promotion diff per origin behind its
    /// `all_heads` list — while `HeadPush` writes this slot from the blocking
    /// pool throughout. A caller condemning "its" head therefore retired, and
    /// permanently refused, whatever happened to be in the slot, and left the
    /// head that actually failed unrecorded.
    pub fn try_promote(&self, origin: &OriginId, now: i64) -> Result<Promotion> {
        // What the transaction judged, for the fault arm: it rolls back, so the
        // head cannot be recovered from the slot afterwards.
        let judged: std::cell::RefCell<Option<Verdict>> = std::cell::RefCell::new(None);
        let promoted = self.store.transaction(|txn| -> Result<Promotion> {
            let Some(pending) = txn.head(origin, Slot::Pending)? else {
                return Ok(Promotion::Idle);
            };
            // The displaced root, the verdict key and the memo check all come
            // before the completeness walk, because the walk is the most likely
            // thing here to raise and `judged` has to be set before anything
            // that can: `is_complete` descends a peer's node graph and refuses a
            // structurally invalid node, which `is_origin_fault` classifies as
            // the origin's fault — and with `judged` still unset the fault arm
            // retired nothing and remembered nothing, so the head kept the slot
            // until the sweep took it and the next exchange re-adopted it. That
            // is the cycle the memo exists to break, and it was worse than
            // before the memo existed. None of this work depends on
            // completeness, and doing the cheap checks first is free.
            let displaced = txn.complete_head(origin)?;
            let old_root = displaced
                .as_ref()
                .map(|h| h.root)
                .unwrap_or(synch_core::Hash::EMPTY);
            let key: Verdict = (
                pending.head.origin.clone(),
                pending.head.seq,
                pending.head.root,
                old_root,
            );
            // Tried before, from this same root, and failed. Retire it without
            // paying the diff again — leaving it in the slot would hold
            // `head_floor` above everything this node can serve.
            if self.is_refused(&key) {
                txn.clear_head(origin, Slot::Pending)?;
                return Ok(Promotion::Refused);
            }
            *judged.borrow_mut() = Some(key);
            let trie = Trie::new(txn);
            if !trie.is_complete(pending.head.root)? {
                return Ok(Promotion::Waiting);
            }
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
                return Ok(Promotion::Idle);
            }
            // The displaced head is already retained: `put_head` recorded its
            // signature when it took the slot. Recording it again here would be
            // a second rule writing the same row, kept honest only by
            // `INSERT OR IGNORE` (§10, v11).
            txn.put_head(Slot::Complete, &pending.head, pending.received_at, now)?;
            txn.clear_head(origin, Slot::Pending)?;
            txn.materialize_diff(origin, old_root, pending.head.root)?;
            Ok(Promotion::Flipped)
        });
        let promoted = match promoted {
            Ok(promoted) => promoted,
            Err(e) if is_origin_fault(&e) => {
                if let Some(key) = judged.into_inner() {
                    // Retire it, and do not try this pair again. The retire
                    // stops it holding the floor; the memo stops the
                    // adopt/diff/fail cycle repeating once per exchange.
                    let (_, seq, root, _) = key.clone();
                    self.refuse(key);
                    self.store
                        .clear_head_at(origin, Slot::Pending, seq, &root)?;
                    tracing::warn!(
                        origin = %origin,
                        seq,
                        error = %e,
                        "origin left behind: a head this node cannot materialize \
                         does not hold the floor"
                    );
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        if promoted == Promotion::Flipped {
            tracing::debug!(origin = %origin, "head flipped to complete");
            if let Some(wake) = &self.on_change {
                // One permit no matter how often this rings: passes coalesce,
                // and a wake landing mid-pass is not lost.
                wake.notify_one();
            }
        }
        Ok(promoted)
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
        let Some(pending) = ({
            let store = self.store.clone();
            let origin = origin.clone();
            crate::blocking::offload(move || Ok(store.pending_head(&origin)?)).await?
        }) else {
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
                    // One transaction per batch, not one per node. Written
                    // through the `Store`, each `put_node` is a bare `execute`
                    // in autocommit — its own transaction, its own acquisition
                    // of the one write connection, its own WAL frame — so a
                    // `MAX_BATCH` response cost up to 256 of them, and a cold
                    // bootstrap of an n-node trie cost n. Measured at 3.8x on
                    // 10 240 puts. The batch is also atomic this way, which is
                    // what §10 asks of a multi-step write; nothing is lost by a
                    // rollback either, since trie nodes are content-addressed
                    // and simply re-fetched.
                    store.transaction(|txn| {
                        take_served(
                            &requested,
                            &response.nodes,
                            "node",
                            |bytes| TrieNode::hash_of_encoded(bytes).ok(),
                            |expected| NetError::NodeHashMismatch { expected },
                            |hash, bytes| {
                                synch_mpt::NodeStore::put_node(txn, hash, bytes)?;
                                Ok(true)
                            },
                        )
                    })
                })
                .await?;
            }
            if !missing.values.is_empty() {
                let response = client.get_values(&missing.values).await?;
                let store = self.store.clone();
                let requested = missing.values.clone();
                learned += crate::blocking::offload(move || {
                    // One transaction per batch, as for nodes above.
                    store.transaction(|txn| {
                        take_served(
                            &requested,
                            &response.values,
                            "value",
                            |bytes| Some(synch_core::Hash::new(bytes)),
                            |expected| NetError::ValueHashMismatch { expected },
                            |hash, bytes| {
                                // Two bounds on what an origin may put in a
                                // value, and both are refusals of *that origin's*
                                // data rather than of the peer relaying it — the
                                // serving peer sent exactly what it was asked for
                                // (§12).
                                //
                                // A value small enough to be inline must *be*
                                // inline. `ValueRef::for_value` makes that true of
                                // everything this node builds, and nothing made it
                                // true of what arrives: `check_invariants` rejects
                                // an oversized inline value and had no rule the
                                // other way, because the payload is not in the
                                // node. This is the first place both are in hand.
                                // Left unchecked it is a second root for the same
                                // key/value map — the thing structural sharing and
                                // the reference-pruning walk rest on not happening
                                // — plus an extra round trip and an extra
                                // `trie_values` row per leaf, at the publisher's
                                // choosing.
                                //
                                // And a value has an upper bound at last
                                // (`MAX_TRIE_VALUE_LEN`): the key side was bounded
                                // three ways and this side by the frame alone, at
                                // 16 MiB each with no limit on how many, which is
                                // what let one small trie cost every peer
                                // gigabytes to serve and terabytes to materialize.
                                //
                                // *Refused*, not raised. Returning an error here
                                // rolled the whole batch back — losing the
                                // legitimate values in it — and propagated out of
                                // `fetch_pending` through `?`, so `learned == 0`
                                // was never reached, `unproductive` never advanced,
                                // and the `MAX_UNPRODUCTIVE_ROUNDS` escape the
                                // comment claimed could not fire for this fault at
                                // all: the head sat holding `head_floor` until the
                                // `pending_head_ttl` sweep took it, thirty times
                                // longer. Skipping the value leaves the walk asking
                                // for it and the counter counting, which is what
                                // the rule was always meant to do.
                                if bytes.len() <= synch_core::INLINE_VALUE_MAX {
                                    tracing::warn!(
                                        %hash,
                                        len = bytes.len(),
                                        ceiling = synch_core::INLINE_VALUE_MAX,
                                        "refusing an out-of-line value small enough to be inline"
                                    );
                                    return Ok(false);
                                }
                                if bytes.len() > synch_core::MAX_TRIE_VALUE_LEN {
                                    tracing::warn!(
                                        %hash,
                                        len = bytes.len(),
                                        ceiling = synch_core::MAX_TRIE_VALUE_LEN,
                                        "refusing a trie value past the size ceiling"
                                    );
                                    return Ok(false);
                                }
                                synch_mpt::NodeStore::put_value(txn, hash, bytes)?;
                                Ok(true)
                            },
                        )
                    })
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
                    // The head this fetch judged, not whatever is in the slot
                    // now: a `HeadPush` accepted while we were between round
                    // trips would otherwise be deleted by a verdict that was
                    // never about it.
                    let store = self.store.clone();
                    let (origin, seq, root) = (origin.clone(), pending.seq, pending.root);
                    let dropped = crate::blocking::offload(move || {
                        Ok(store.clear_head_at(&origin, Slot::Pending, seq, &root)?)
                    })
                    .await?;
                    if !dropped {
                        tracing::debug!(
                            "a newer head arrived while this one was being fetched; \
                             leaving the slot to it"
                        );
                    }
                    return Ok(FetchOutcome::Abandoned);
                }
            } else {
                unproductive = 0;
                // Progress restarts the slot's staleness clock. The clock is on
                // the slot rather than on the head occupying it (see
                // `put_head_in`), so without this a trie that legitimately
                // takes longer than `pending_head_ttl` to fetch would be swept
                // out from under the fetch that is filling it.
                //
                // Named, because this fetch has been working on `pending.root`
                // since before the first round trip and the slot may have moved
                // on since: stamping whatever is there would let progress on
                // this root hold the sweep off a head nobody can serve.
                let store = self.store.clone();
                let touched = origin.clone();
                let (seq, root) = (pending.seq, pending.root);
                crate::blocking::offload(move || {
                    Ok(store.touch_pending_at(&touched, seq, &root, now_ns())?)
                })
                .await?;
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
        if promoted == Promotion::Flipped {
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

    /// What this node advertises, and the heads it can actually hand over.
    ///
    /// Read together because the push decision needs both and because the
    /// second used to be read from inside the exchange closure, on a runtime
    /// worker. One walk per unproven root and one query per origin, once.
    async fn advertisement_off_runtime(&self) -> Result<(Vec<HeadSummary>, Vec<SignedHead>)> {
        let syncer = self.clone();
        crate::blocking::offload(move || {
            let summaries = syncer.local_summaries()?;
            let servable = syncer
                .store
                .all_heads(Slot::Complete)?
                .into_iter()
                .map(|stored| stored.head)
                .collect();
            Ok((summaries, servable))
        })
        .await
    }

    /// Runs one full `Hello` push-pull exchange with a peer, then fetches
    /// whatever it advertised that we do not have (§5.2, §5.3).
    pub async fn sync_with(&self, client: &MptClient) -> Result<SyncReport> {
        // The summaries and the servable heads behind them come over together,
        // in one hop to the blocking pool. The decision below used to read the
        // complete slot once per advertised origin *inside* the closure, which
        // `head_exchange` calls on the runtime worker driving the connection —
        // a two-table join per origin behind the store's one global mutex, on
        // the thread the endpoint and every timer in the process share (§10).
        // Nothing about the decision needs the store: it needs the heads, and
        // the heads are already being read.
        let (ours, servable) = self.advertisement_off_runtime().await?;

        let mut report = SyncReport::default();
        let theirs = client
            .head_exchange(ours.clone(), |theirs| {
                // Both slots may be advertised per origin, so the comparison is
                // against the best summary either side has for it, never the
                // first one that happens to match. Indexed once rather than
                // re-scanned per origin: the scan was quadratic in the number
                // of summaries, on both sides of the decision.
                let best_of = |set: &[HeadSummary]| {
                    let mut best: std::collections::HashMap<OriginId, (u64, [u8; 32])> =
                        std::collections::HashMap::new();
                    for summary in set {
                        let key = summary.order_key();
                        best.entry(summary.origin.clone())
                            .and_modify(|held| {
                                if key > *held {
                                    *held = key;
                                }
                            })
                            .or_insert(key);
                    }
                    best
                };
                let theirs_best = best_of(theirs);
                let ours_best = best_of(&ours);

                // Push: the servable head we hold, whenever it beats theirs.
                // Keyed off the complete slot directly rather than off whichever
                // summary was advertised: what we can hand over is exactly what
                // the complete slot holds.
                let push: Vec<SignedHead> = servable
                    .iter()
                    .filter(|head| {
                        let mine = (head.seq, head.root.0);
                        theirs_best
                            .get(&head.origin)
                            .is_none_or(|peer| mine > *peer)
                    })
                    .cloned()
                    .collect();
                // Pull: origins where the peer is ahead of us.
                let mut want = Vec::new();
                let mut asked: std::collections::HashSet<&OriginId> =
                    std::collections::HashSet::new();
                for summary in theirs {
                    if !asked.insert(&summary.origin) {
                        continue;
                    }
                    if ours_best
                        .get(&summary.origin)
                        .is_none_or(|mine| summary.order_key() > *mine)
                    {
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
                // §12: the count of origins left behind belongs in the sync
                // report, and after the first exchange this is the only outcome
                // that carries it — the fault propagates once, and every later
                // offer is answered from the memo without re-deriving it.
                HeadOutcome::Refused => report.left_behind(&head.origin),
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
        let pending_heads = {
            let store = self.store.clone();
            crate::blocking::offload(move || Ok(store.all_heads(Slot::Pending)?)).await?
        };
        for stored in pending_heads {
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
/// The third check is now a backstop rather than the bound it was: `Nodes.nodes`
/// and `Values.values` are capped at [`MAX_BATCH`] *while decoding*, so a
/// response cannot carry more entries than the request carried hashes. It stays
/// because the containment set is what enforces it either way, and because a
/// repeat must not count as progress even if one arrives.
///
/// Returns how many were stored.
fn take_served(
    requested: &[synch_core::Hash],
    served: &[(synch_core::Hash, Vec<u8>)],
    what: &str,
    hash_of: impl Fn(&[u8]) -> Option<synch_core::Hash>,
    mismatch: impl Fn(synch_core::Hash) -> NetError,
    put: impl Fn(&synch_core::Hash, &[u8]) -> Result<bool>,
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
        // `put` decides whether the payload is one this node will keep: a rule
        // about what the *origin* published — a value small enough to be inline,
        // or one past the size ceiling — refuses the payload without failing the
        // batch. Refused payloads are not progress, so the unproductive counter
        // still runs and the head is retired by the §5.2 rule rather than by the
        // TTL sweep half an hour later.
        if put(hash, bytes)? {
            stored += 1;
        }
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

    /// Contained here, not at the wire.
    ///
    /// §12's rule is that a record this node cannot apply fails *its own
    /// origin* and no other, and `to_net` flattens every engine failure into
    /// one `NetError::Unexpected(String)` — so a caller on the far side of this
    /// seam cannot tell an undecodable `f:` record from `SQLITE_BUSY`. Both
    /// `synch-net` arms used to guess, and they guessed differently: the
    /// `Hello` loop logged everything as "origin left behind" including a full
    /// disk, and `HeadPush` eleven lines below failed the stream. Doing it on
    /// this side is what gives one rule one implementation — the classifier is
    /// already here, and `try_promote` has retired the head by the time an
    /// origin fault reaches this point — whenever it got far enough to judge
    /// one. A fault raised before that leaves the slot to the maintenance
    /// sweep rather than to this handler.
    fn offer_head(&self, head: &SignedHead, now: i64) -> std::result::Result<(), NetError> {
        match Syncer::offer_head(self, head, now) {
            Ok(_) => Ok(()),
            Err(e) if is_origin_fault(&e) => {
                tracing::warn!(
                    origin = %head.origin,
                    seq = head.seq,
                    error = %e,
                    "origin left behind: its pushed head could not be applied"
                );
                Ok(())
            }
            Err(e) => Err(to_net(e)),
        }
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
/// this node, the peer, or the connection.
///
/// Three kinds of failure reach this, and only one of them is an origin's.
///
/// - **An origin's**: a record that will not decode, a node that breaks a
///   structural invariant, a value at a depth no key reaches. Durable,
///   reproduced on every exchange that reaches it, and *contained* — one member
///   publishing something this node cannot apply must not stop it converging
///   with every other origin the same peer serves (§12).
/// - **The peer's**: a protocol violation or a broken stream. Ends the exchange.
/// - **Ours**: `SQLITE_BUSY` from another process, a full disk, an I/O error.
///   These used to be contained too, because `StoreError` spans both categories
///   and this matched the whole enum — so a full disk logged "origin left
///   behind: its published data could not be applied" once per origin, blamed a
///   member for a local fault, and reported the round a success. They propagate
///   now, which is what puts them where an operator will see them.
///
/// [`EngineError::Blocking`] and [`EngineError::Io`] were already excluded, so
/// the split was intended; this completes it inside `StoreError` and `MptError`.
pub(crate) fn is_origin_fault(error: &EngineError) -> bool {
    match error {
        EngineError::Store(e) => is_origin_store_fault(e),
        EngineError::Mpt(e) => is_origin_mpt_fault(e),
        _ => false,
    }
}

/// Whether a store failure is about replicated data rather than about this
/// node's own disk or database.
///
/// `Invalid` is "a caller supplied an argument the store refuses", and on the
/// paths this guards the argument is always something a peer or an origin
/// supplied: a summary claiming a seq past the representable range, a head whose
/// `(origin, seq, root)` already retains a different signature. The store's other
/// `Invalid`s — a schema stamp this build cannot read, a migration that failed —
/// belong to `Store::open` and are unreachable from an exchange.
fn is_origin_store_fault(error: &synch_store::StoreError) -> bool {
    match error {
        // What a peer published, read back and refused.
        synch_store::StoreError::Decode(_)
        | synch_store::StoreError::Column { .. }
        | synch_store::StoreError::Invalid(_) => true,
        synch_store::StoreError::Mpt(e) => is_origin_mpt_fault(e),
        // Ours: the database, the filesystem, or an object this node holds.
        _ => false,
    }
}

/// Whether a trie failure is about the structure a peer served rather than
/// about the store under it.
fn is_origin_mpt_fault(error: &synch_mpt::MptError) -> bool {
    !matches!(
        error,
        synch_mpt::MptError::Store(_) | synch_mpt::MptError::WalkStopped
    )
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
    report.left_behind(origin);
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
    /// Which origins `heads_failed` counts, so counting one twice cannot inflate
    /// it. Not part of the rendered report.
    failed_origins: std::collections::HashSet<OriginId>,
}

impl SyncReport {
    /// Records that this origin was left behind, once however often it is said.
    ///
    /// The number is rendered as "N origin(s) left behind", and two paths reach
    /// this verdict for the same origin in one exchange: the fault propagates
    /// from the first offer of a head, and every later offer of it is answered
    /// from the refusal memo. Nothing dedups the head list a peer sends, so a
    /// repeated head counted its origin once per copy.
    fn left_behind(&mut self, origin: &OriginId) {
        if self.failed_origins.insert(origin.clone()) {
            self.heads_failed += 1;
        }
    }
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
                    Ok(true)
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
                    Ok(true)
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
        // And the head that failed no longer holds the slot. `try_promote` owns
        // that now — it is the only party that knows which head it judged — so a
        // direct call retires it too, where before this test's caller would have
        // had to.
        assert_eq!(store.pending_head(&origin).unwrap(), None);
        assert!(store.entry(&origin, "s", "poisoned").unwrap().is_none());
        // And the entry the *complete* head materialized is still there.
        assert!(store.entry(&origin, "s", "a").unwrap().is_some());
    }
}

#[cfg(test)]
mod containment_tests {
    use iroh_base::SecretKey;
    use synch_core::{file_key, FileEntry, Hash, OriginId, SignedHead};
    use synch_store::{Binding, BindingSource, Slot, Store};

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

    /// A head this node cannot materialize does not keep the pending slot.
    ///
    /// `head_floor` is the best of both slots, so a poisoned head sitting there
    /// holds the floor above every servable head for its origin — and the
    /// maintenance sweep then drops it and the next exchange re-adopts it,
    /// paying a full promotion diff under the write lock every round until an
    /// operator intervenes. The evidence stays: the head is in `head_history`
    /// either way.
    #[test]
    fn a_head_that_cannot_be_materialized_does_not_hold_the_floor() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let trie = Trie::new(store.as_ref());

        // A canonical trie whose one `f:` value is not a `FileEntry`.
        let poisoned = trie
            .insert(Hash::EMPTY, &file_key("s", "a.txt").unwrap(), &[0xffu8; 8])
            .unwrap();
        let head = SignedHead::sign(&key, origin.clone(), 5, poisoned, 0);
        let err = syncer
            .offer_head(&head, 0)
            .expect_err("the record cannot be materialized");
        assert!(err.to_string().contains("corrupt record"), "{err}");

        assert_eq!(store.pending_head(&origin).unwrap(), None);
        assert_eq!(store.complete_head(&origin).unwrap(), None);
        assert_eq!(store.head_floor(&origin).unwrap(), None);
        assert_eq!(
            store.head_history(&origin).unwrap().len(),
            1,
            "the head is still provable history"
        );

        // And a lesser head this node *can* serve is adoptable again, which the
        // held floor would have refused.
        let good = trie
            .insert(
                Hash::EMPTY,
                &file_key("s", "a.txt").unwrap(),
                &postcard::to_stdvec(&FileEntry::file(1, 0, Hash::new(b"c"), 1)).unwrap(),
            )
            .unwrap();
        let servable = SignedHead::sign(&key, origin.clone(), 4, good, 0);
        assert_eq!(
            syncer.offer_head(&servable, 0).unwrap(),
            HeadOutcome::Completed
        );
    }

    /// A structurally invalid trie is condemned like any other origin fault.
    ///
    /// The fault this raises comes from `is_complete`, which descends the peer's
    /// node graph — so it fires *before* the promotion diff, and before the code
    /// had recorded which head it was about. The fault arm then retired nothing
    /// and remembered nothing: the head kept the pending slot, holding
    /// `head_floor` above everything this node could serve until the sweep took
    /// it, and the next exchange re-adopted it and repeated. That was worse than
    /// before the memo existed, which is why the key is built before the walk.
    #[test]
    fn a_head_whose_trie_is_structurally_invalid_is_retired_and_remembered() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());

        // An extension whose child is a leaf, which no canonical trie contains:
        // an extension above anything but a branch would have been merged (§4.3).
        // Stored through `put_node` directly, because this is what a peer serving
        // a hand-built graph looks like and `Trie::insert` cannot produce it.
        //
        // The fault this raises comes from the *completeness walk*, not from the
        // promotion diff — which is the whole point: it fires before the diff, so
        // it is the case where the verdict key must already have been built.
        let (value, _) = synch_mpt::ValueRef::for_value(&[7u8; 4]);
        let child = synch_mpt::TrieNode::Leaf {
            key_rest: synch_mpt::Nibbles::from_nibbles(&[1, 2]),
            value,
        };
        let child_hash = child.hash();
        let root = synch_mpt::TrieNode::Ext {
            prefix: synch_mpt::Nibbles::from_nibbles(&[4]),
            child: child_hash,
        };
        let root_hash = root.hash();
        synch_mpt::NodeStore::put_node(store.as_ref(), &child_hash, &child.encode()).unwrap();
        synch_mpt::NodeStore::put_node(store.as_ref(), &root_hash, &root.encode()).unwrap();

        let head = SignedHead::sign(&key, origin.clone(), 4, root_hash, 0);
        let err = syncer
            .offer_head(&head, 0)
            .expect_err("a non-canonical node is the origin's fault");
        assert!(is_origin_fault(&err), "{err}");

        // Retired: the floor is back to what this node can serve.
        assert_eq!(store.head_floor(&origin).unwrap(), None);
        // And remembered: the second offer does not walk it again, so it does not
        // raise, and it leaves nothing pending — while still counting against the
        // origin, which §12 requires the sync report to carry.
        assert_eq!(
            syncer.offer_head(&head, 0).unwrap(),
            HeadOutcome::Refused,
            "the verdict must be remembered, not re-derived every exchange"
        );
        assert_eq!(store.pending_head(&origin).unwrap(), None);
    }

    /// A promotion judged unpromotable once is not attempted again.
    ///
    /// Retiring the head from the pending slot is what lets the node serve again
    /// — and it is also what makes the same head beat `head_floor` on the next
    /// offer. With no memory of the verdict the node re-adopted it, walked the
    /// trie, ran the promotion diff and failed, once per exchange, forever, each
    /// turn holding the single write connection.
    ///
    /// The memory is keyed on the *pair* `(head, root-it-would-diff-from)`,
    /// because that is what the verdict is a function of.
    #[test]
    fn a_promotion_judged_unpromotable_is_not_attempted_again() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let trie = Trie::new(store.as_ref());

        let poisoned = trie
            .insert(Hash::EMPTY, &file_key("s", "a.txt").unwrap(), &[0xffu8; 8])
            .unwrap();
        let head = SignedHead::sign(&key, origin.clone(), 5, poisoned, 0);
        syncer
            .offer_head(&head, 0)
            .expect_err("the record cannot be materialized");
        assert_eq!(
            store.head_floor(&origin).unwrap(),
            None,
            "and it was retired"
        );

        // Offered again — which is what every later exchange with a peer holding
        // it does. The diff must not run a second time, so no error surfaces; and
        // the outcome must be counted against the origin, or `synch sync` — which
        // prints the "N origin(s) left behind" line from `heads_failed` — reports
        // nothing at all for an origin this node permanently cannot apply, since
        // the fault itself propagates only on the first offer.
        assert_eq!(
            syncer.offer_head(&head, 0).unwrap(),
            HeadOutcome::Refused,
            "the promotion is not re-attempted, and the origin is still counted"
        );
        assert_eq!(
            store.head_floor(&origin).unwrap(),
            None,
            "and it does not keep the floor"
        );

        // The verdict is about one promotion, not about the origin: a different
        // root at a higher seq is still judged on its merits.
        let good = trie
            .insert(
                Hash::EMPTY,
                &file_key("s", "a.txt").unwrap(),
                &postcard::to_stdvec(&FileEntry::file(1, 0, Hash::new(b"c"), 1)).unwrap(),
            )
            .unwrap();
        let later = SignedHead::sign(&key, origin.clone(), 6, good, 0);
        assert_eq!(
            syncer.offer_head(&later, 0).unwrap(),
            HeadOutcome::Completed
        );
    }

    /// The pending bell survives a ring nobody is parked on.
    ///
    /// This is the whole of what the reactive fetch rests on, and the reason it
    /// cannot be a `notify_waiters`: the anti-entropy loop is parked on this
    /// only *between* rounds, and spends the rest of its life inside
    /// `anti_entropy_round` dialling peers — which is exactly when the pushes
    /// it needs to hear about land, since a publisher pushes to the whole
    /// membership at once (§5.3). A bell that keeps nothing for an unparked
    /// listener is a bell that is silent for every push that arrives during a
    /// round, and the fetch waits for the next interval after all.
    #[tokio::test]
    async fn a_pending_head_rung_mid_round_is_not_lost() {
        let (_d, store, key, origin) = setup();
        let wake = Arc::new(tokio::sync::Notify::new());
        let syncer = Syncer::new(store.clone()).on_pending(Some(wake.clone()));

        // Rung with no listener parked, which is the mid-round case.
        let head = SignedHead::sign(&key, origin.clone(), 1, Hash([1u8; 32]), 0);
        assert_eq!(syncer.offer_head(&head, 0).unwrap(), HeadOutcome::Pending);

        // A listener arriving afterwards still has to see it.
        tokio::time::timeout(std::time::Duration::from_secs(5), wake.notified())
            .await
            .expect("a wake that landed while the loop was busy must still be there");
    }

    /// A head the memo already refuses does not ring the fetch bell.
    ///
    /// The bell wakes the anti-entropy loop to go and fetch a trie. A refused
    /// head is adopted and retired in the same breath — adopting it is what makes
    /// it beat the floor again — so ringing on adoption woke the loop for a head
    /// that no longer existed, and `notify_one` keeps a permit while the loop is
    /// not parked during a round: one such head held by one peer pinned the node
    /// to back-to-back rounds at the reactive floor, permanently.
    #[tokio::test]
    async fn a_refused_head_does_not_ring_the_fetch_bell() {
        let (_d, store, key, origin) = setup();
        let wake = Arc::new(tokio::sync::Notify::new());
        let syncer = Syncer::new(store.clone()).on_pending(Some(wake.clone()));
        let trie = Trie::new(store.as_ref());

        let poisoned = trie
            .insert(Hash::EMPTY, &file_key("s", "a.txt").unwrap(), &[0xffu8; 8])
            .unwrap();
        let head = SignedHead::sign(&key, origin.clone(), 5, poisoned, 0);
        syncer
            .offer_head(&head, 0)
            .expect_err("the record cannot be materialized");
        // The first offer did adopt it before judging it, so it may have rung.
        // Drain that permit; what must not ring is the *refusal*.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(50), wake.notified()).await;

        assert_eq!(
            syncer.offer_head(&head, 0).unwrap(),
            HeadOutcome::Refused,
            "answered from the memo"
        );
        tokio::time::timeout(std::time::Duration::from_millis(200), wake.notified())
            .await
            .expect_err("a refused head has no trie to fetch and must not wake the loop");
    }

    /// The pending slot ages, not the head occupying it.
    ///
    /// `pending_head_ttl` is §5.2's only time-based escape from a floor pinned
    /// by a head nobody can serve, and it reads `heads.received_at`. Taking
    /// that from each newly adopted head reset the clock on every arrival, so
    /// an origin publishing faster than the TTL kept the sweep from ever
    /// firing.
    #[test]
    fn a_newer_pending_head_inherits_the_slots_clock() {
        let (_d, store, key, origin) = setup();
        let first = SignedHead::sign(&key, origin.clone(), 1, Hash([1u8; 32]), 0);
        let second = SignedHead::sign(&key, origin.clone(), 2, Hash([2u8; 32]), 0);

        store.put_head(Slot::Pending, &first, 100, 100).unwrap();
        store
            .put_head(Slot::Pending, &second, 9_000, 9_000)
            .unwrap();
        let stored = store.head(&origin, Slot::Pending).unwrap().unwrap();
        assert_eq!(stored.head.seq, 2, "the newer head took the slot");
        assert_eq!(
            stored.received_at, 100,
            "but the slot has been occupied since 100"
        );

        // A fetch that commits something restarts it, so a trie that genuinely
        // takes longer than the TTL to arrive is not swept mid-transfer.
        assert!(
            !store
                .touch_pending_at(&origin, 1, &Hash([1u8; 32]), 9_500)
                .unwrap(),
            "a fetch of a head the slot has moved past must not restart the clock"
        );
        assert_eq!(
            store
                .head(&origin, Slot::Pending)
                .unwrap()
                .unwrap()
                .received_at,
            100,
            "the slot keeps ageing while an unservable head occupies it"
        );
        assert!(store
            .touch_pending_at(&origin, 2, &Hash([2u8; 32]), 9_500)
            .unwrap());
        assert_eq!(
            store
                .head(&origin, Slot::Pending)
                .unwrap()
                .unwrap()
                .received_at,
            9_500
        );

        // An empty slot starts its own clock.
        assert!(store
            .clear_head_at(&origin, Slot::Pending, 2, &Hash([2u8; 32]))
            .unwrap());
        store
            .put_head(Slot::Pending, &first, 20_000, 20_000)
            .unwrap();
        assert_eq!(
            store
                .head(&origin, Slot::Pending)
                .unwrap()
                .unwrap()
                .received_at,
            20_000
        );
        assert!(
            !store
                .touch_pending_at(
                    &OriginId::named("other", "x.example").unwrap(),
                    1,
                    &Hash([1u8; 32]),
                    1
                )
                .unwrap(),
            "and there is nothing to touch for an origin with no pending head"
        );
    }

    /// Abandoning a head names the head being abandoned.
    ///
    /// `clear_head` deletes whatever occupies the slot, and both abandonment
    /// paths reach their verdict on a snapshot taken before several network
    /// round trips or a trie walk. A newer head accepted in that window went
    /// with the old one's verdict.
    #[test]
    fn clearing_a_slot_leaves_a_head_that_arrived_since() {
        let (_d, store, key, origin) = setup();
        let stale = SignedHead::sign(&key, origin.clone(), 1, Hash([1u8; 32]), 0);
        let fresh = SignedHead::sign(&key, origin.clone(), 2, Hash([2u8; 32]), 0);
        store.put_head(Slot::Pending, &stale, 0, 0).unwrap();

        // The slot moves on while a fetch is between round trips.
        store.put_head(Slot::Pending, &fresh, 0, 0).unwrap();

        assert!(
            !store
                .clear_head_at(&origin, Slot::Pending, stale.seq, &stale.root)
                .unwrap(),
            "the verdict was about a head the slot no longer holds"
        );
        assert_eq!(store.pending_head(&origin).unwrap(), Some(fresh.clone()));

        // And the head it *is* about goes.
        assert!(store
            .clear_head_at(&origin, Slot::Pending, fresh.seq, &fresh.root)
            .unwrap());
        assert_eq!(store.pending_head(&origin).unwrap(), None);
    }

    /// Our own next seq is above everything this node has ever recorded for the
    /// origin, not just above the complete slot.
    #[test]
    fn the_next_own_seq_clears_the_pending_slot_and_the_history() {
        let (_d, store, key, origin) = setup();
        store.set_self_origin(&origin).unwrap();
        assert_eq!(store.next_own_seq(&origin).unwrap(), 1);

        // A peer relays one of our own heads back, at a seq the complete slot
        // knows nothing about. This is the §3.4 recovery shape, and it is what a
        // restored backup meets.
        let relayed = SignedHead::sign(&key, origin.clone(), 9, Hash([9u8; 32]), 0);
        assert_eq!(
            Syncer::new(store.clone()).offer_head(&relayed, 0).unwrap(),
            HeadOutcome::Pending
        );
        assert_eq!(store.complete_head(&origin).unwrap(), None);
        assert_eq!(
            store.next_own_seq(&origin).unwrap(),
            10,
            "the pending slot and the history both count"
        );

        // Even once the pending slot is cleared, the retained history still does.
        store
            .clear_head_at(&origin, Slot::Pending, 9, &Hash([9u8; 32]))
            .unwrap();
        assert_eq!(store.next_own_seq(&origin).unwrap(), 10);
    }
}
