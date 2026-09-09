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
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use synch_core::{
    now_ns, DeclaredScope, Hash, HeadSummary, NodeId, OriginId, SignedHead, MAX_BATCH,
};
use synch_mpt::{Scope, Trie};
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
/// instead (inside Lean acceptance), which is the same set on every
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

/// One pending origin's share of a peer exchange.
///
/// The whole periodic peer turn is capped at thirty seconds. Giving one origin
/// a smaller cap lets a peer that stalls only that origin neither consume the
/// turn forever nor keep every later pending origin at the front of the next
/// turn. Trie admission commits each verified batch, so a large honest origin
/// accumulates progress across these slices.
const PENDING_FETCH_BUDGET: Duration = Duration::from_secs(5);
/// Pending origins admitted to one peer exchange. Combined with the per-origin
/// budget this leaves the outer peer deadline room to finish and persist turns.
const PENDING_ORIGIN_FANOUT: usize = 4;

/// What a promotion attempt concluded.
///
/// Four states rather than a `bool`: a trie still arriving, a memoized refusal,
/// and a head overtaken by the complete slot all mean "did not flip" but require
/// different follow-up work.
///
/// Returned rather than inferred to avoid re-reading the slot after promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Promotion {
    /// The pending head's trie was wholly present and the complete slot flipped.
    Flipped,
    /// A pending head stands and its trie is not all here yet: it needs a fetch.
    Waiting,
    /// The head was retired without flipping because this node's own rules
    /// refuse the promotion: the pair is in the refusal memo, the origin has
    /// no live binding here, or it is delegated and its trie publishes
    /// outside its spaces (§3.5).
    Refused,
    /// Nothing is pending now: there was no pending head, or the complete slot
    /// had overtaken the one there and it was dropped.
    ///
    /// Distinct from `Waiting`: only a pending head that still needs its trie
    /// should be reported accepted and wake the anti-entropy loop. An overtake
    /// is possible whenever local `publish` or `activate` moves the complete
    /// slot between the offer's transaction and this one — both derive
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
    /// Nothing changed for this origin.
    ///
    /// Usually because the head is not strictly greater than what we already
    /// hold. Also the answer when a head *was* adopted and then stopped being
    /// pending before the promotion looked: the complete slot had overtaken it,
    /// or another holder of the write connection promoted it in the gap. Both
    /// leave nothing to fetch, which is what this outcome tells the caller;
    /// distinguishing them would cost a second read of the complete slot on
    /// every adoption, to move a head between two counters.
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
    /// The trie is now complete and the head flipped.
    Completed,
    /// The head did not flip and there is nothing more to do with the origin
    /// this exchange.
    ///
    /// There was no pending head to fetch; or the fetch ran and the trie is
    /// still incomplete; or the slot had moved on before the promotion looked.
    /// No caller has ever needed these apart: each means this exchange is
    /// done with the origin, with nothing to report.
    NoFlip,
    /// This node's own rules refused the head, and it was retired: the pair
    /// was already in the refusal memo, so no fetch was made; or the trie
    /// arrived whole and the promotion refused it — no live binding for the
    /// origin, or a delegated origin publishing outside its spaces. The
    /// origin counts as left behind (§12), which is why this is not `NoFlip`.
    Refused,
    /// Every candidate persistently returned `missing`; the pending head was
    /// abandoned and head selection re-runs (§5.2).
    Abandoned,
}

/// Reconciliation over one node's store.
#[derive(Debug, Clone)]
pub struct Syncer {
    store: Arc<Store>,
    /// Rung when a promotion flips a head to complete: the unified tree just
    /// changed, and any checkout materializing it should look again.
    on_change: Option<Arc<tokio::sync::Notify>>,
    /// Rung by the same events as `on_change`, for the replication loop.
    ///
    /// Its own bell rather than a second waiter on `on_change`, because the
    /// bell is `notify_one`: two loops waiting on one permit means each wake
    /// reaches whichever of them happened to be waiting, and the other sleeps
    /// out its interval on a tree that changed.
    on_replica: Option<Arc<tokio::sync::Notify>>,
    /// Rung when a head is adopted as *pending*: its trie is not here and
    /// nothing in this process is going to fetch it until somebody dials.
    on_pending: Option<Arc<tokio::sync::Notify>>,
    /// Promotions this node has tried and cannot repeat, so it does not spend
    /// the diff again. Owned by [`Syncer::try_promote`], which is the only
    /// place the pair a verdict is about is known.
    refused: Arc<Mutex<HashSet<Verdict>>>,
    /// Last origin included in an oversized Hello page, independently for each
    /// peer. A global cursor can phase-lock with peer contact rotation so one
    /// peer repeatedly sees the same page. Complete and pending summaries for
    /// one origin always travel in the same page.
    advertisement_cursors: Arc<Mutex<HashMap<NodeId, OriginId>>>,
    /// Last pending origin whose fetch attempt finished (including a local
    /// slice timeout). A cancelled exchange leaves the in-flight origin here,
    /// so it is retried; completed attempts rotate later origins to the front.
    pending_cursor: Arc<Mutex<Option<OriginId>>>,
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

/// What one side brings to a `Hello`: its summaries, the scope it will serve
/// the peer, and the heads it can actually hand over.
///
/// Read in one hop off the runtime. Every field is a store read, and §10 puts
/// those on the blocking pool — the exchange itself then needs no store at all.
struct Advertisement {
    summaries: Vec<HeadSummary>,
    /// Reserved cursor for this page. Persisted only after the Hello attempt
    /// returns; cancellation before then leaves the peer's old cursor intact.
    cursor: Option<OriginId>,
    declared: DeclaredScope,
    servable: Vec<SignedHead>,
}

/// Selects the next wire-sized page without separating one origin's two slots.
///
/// `summaries` is ordered by origin and then version. The store has at most one
/// complete and one pending slot per origin, so every group fits in the wire
/// cap. Starting strictly after the last completed group makes repeated Hello
/// construction cover the whole stable set instead of returning the same
/// lowest-sorting prefix forever.
fn page_summaries(
    summaries: Vec<HeadSummary>,
    cursor: Option<&OriginId>,
    maximum: usize,
) -> Result<(Vec<HeadSummary>, Option<OriginId>)> {
    debug_assert!(maximum >= 2);
    if summaries.len() <= maximum {
        return Ok((summaries, None));
    }

    let mut groups: Vec<Vec<HeadSummary>> = Vec::new();
    for summary in summaries {
        match groups.last_mut() {
            Some(group) if group[0].origin == summary.origin => group.push(summary),
            _ => groups.push(vec![summary]),
        }
    }
    let plan = synch_verified::replication::plan_origins(
        groups
            .iter()
            .map(|group| synch_verified::replication::OriginItem {
                origin: group[0].origin.canonical(),
                weight: group.len() as u64,
            })
            .collect(),
        cursor.map(OriginId::canonical),
        maximum as u64,
    )
    .map_err(|error| EngineError::Record(error.to_string()))?;
    let mut selected = Vec::with_capacity(maximum);
    for position in plan.positions {
        let group = groups
            .get(position as usize)
            .ok_or_else(|| EngineError::Record("invalid Lean origin position".into()))?;
        selected.extend(group.iter().cloned());
    }
    let next = selected.last().map(|last| last.origin.clone());
    Ok((selected, next))
}

/// Plans from one peer's independently completed position without advancing it.
fn page_summaries_for_peer(
    summaries: Vec<HeadSummary>,
    cursors: &HashMap<NodeId, OriginId>,
    peer: NodeId,
    maximum: usize,
) -> Result<(Vec<HeadSummary>, Option<OriginId>)> {
    page_summaries(summaries, cursors.get(&peer), maximum)
}

/// Starts after the last completed pending attempt while retaining the store's
/// stable origin order. The caller advances the cursor only after an attempt
/// has returned or reached its local slice deadline.
fn rotate_pending<T>(
    pending: Vec<T>,
    cursor: Option<&OriginId>,
    maximum: usize,
    origin: impl Fn(&T) -> &OriginId,
) -> Result<Vec<T>> {
    let plan = synch_verified::replication::plan_origins(
        pending
            .iter()
            .map(|item| synch_verified::replication::OriginItem {
                origin: origin(item).canonical(),
                weight: 1,
            })
            .collect(),
        cursor.map(OriginId::canonical),
        maximum as u64,
    )
    .map_err(|error| EngineError::Record(error.to_string()))?;
    let mut pending = pending.into_iter().map(Some).collect::<Vec<_>>();
    let mut selected = Vec::with_capacity(plan.positions.len());
    for position in plan.positions {
        selected.push(
            pending
                .get_mut(position as usize)
                .and_then(Option::take)
                .ok_or_else(|| EngineError::Record("invalid Lean origin position".into()))?,
        );
    }
    Ok(selected)
}

impl Syncer {
    /// Binds a syncer to a store.
    pub fn new(store: Arc<Store>) -> Self {
        Syncer {
            store,
            on_change: None,
            on_replica: None,
            on_pending: None,
            refused: Arc::new(Mutex::new(HashSet::new())),
            advertisement_cursors: Arc::new(Mutex::new(HashMap::new())),
            pending_cursor: Arc::new(Mutex::new(None)),
        }
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

    /// Invalidates every process-local decision made under the prior scope.
    ///
    /// Trie completeness certificates already include scope in their key and
    /// the durable derived views are cleared by `set_read_scope`. Refusal
    /// verdicts do not include scope, so retaining one would let a structural
    /// outcome from an old view suppress rebuilding the same head under the
    /// new permission for the rest of this process.
    pub(crate) fn scope_changed(&self) {
        self.refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        for wake in [&self.on_change, &self.on_replica].into_iter().flatten() {
            wake.notify_one();
        }
    }

    /// Rings `wake` whenever a head flips to complete (§5.2).
    ///
    /// Every merge path ends in [`Syncer::try_promote`] — the Hello exchange
    /// in either direction, a pushed head whose trie was already here, a
    /// pending head's completed fetch — so this one bell covers all of them.
    pub(crate) fn on_replica(mut self, wake: Arc<tokio::sync::Notify>) -> Self {
        self.on_replica = Some(wake);
        self
    }

    /// The bell rung when a promotion flips a head to complete.
    pub(crate) fn on_change(mut self, wake: Arc<tokio::sync::Notify>) -> Self {
        self.on_change = Some(wake);
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
    /// `entries`, checkouts, the S3 gateway — looks at, because all of them sit
    /// behind promotion.
    pub(crate) fn on_pending(mut self, wake: Arc<tokio::sync::Notify>) -> Self {
        self.on_pending = Some(wake);
        self
    }

    /// The store this syncer reconciles into.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// A deterministic wire-sized view of the local head summaries (§5.1).
    ///
    /// Callers without a peer identity get the first page without advancing
    /// any scheduling state. Actual exchanges use [`Self::local_summaries_for`]
    /// so each peer progresses through an oversized set independently.
    ///
    /// `complete` means "I hold the full trie under this root and can serve
    /// it"; a signed head alone proves nothing about that, so the flag is
    /// computed from the local trie, never assumed.
    pub fn local_summaries(&self) -> Result<Vec<HeadSummary>> {
        let mut out = self.all_local_summaries()?;
        if out.len() > synch_core::MAX_HEADS_PER_MESSAGE {
            (out, _) = page_summaries(out, None, synch_core::MAX_HEADS_PER_MESSAGE)?;
        }
        Ok(out)
    }

    /// The next summary page for one peer.
    ///
    /// Cursors are peer-keyed: combining one global advertisement cursor with
    /// the independently rotating contact scheduler can phase-lock a peer to a
    /// strict subset of pages. Planning reserves the next cursor but does not
    /// persist it; the caller does so only after its Hello attempt returns.
    fn local_summaries_for(&self, peer: NodeId) -> Result<(Vec<HeadSummary>, Option<OriginId>)> {
        let mut out = self.all_local_summaries()?;
        let mut next = None;
        if out.len() > synch_core::MAX_HEADS_PER_MESSAGE {
            tracing::warn!(
                summaries = out.len(),
                cap = synch_core::MAX_HEADS_PER_MESSAGE,
                peer = %peer.fmt_short(),
                "more origins than one Hello can carry: advertising this peer's next origin page"
            );
            let cursors = self
                .advertisement_cursors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (out, next) =
                page_summaries_for_peer(out, &cursors, peer, synch_core::MAX_HEADS_PER_MESSAGE)?;
        }
        Ok((out, next))
    }

    /// Persists a reserved advertisement cursor after the corresponding Hello
    /// attempt completed. A dropped future never calls this method.
    fn summaries_attempted(&self, peer: NodeId, cursor: Option<OriginId>) {
        if let Some(cursor) = cursor {
            self.advertisement_cursors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(peer, cursor);
        }
    }

    /// All summary slots before applying the wire cap.
    fn all_local_summaries(&self) -> Result<Vec<HeadSummary>> {
        let trie = Trie::new(self.store.as_ref());
        let now = now_ns();
        let mut out = Vec::new();
        for stored in self.store.all_heads(Slot::Complete)? {
            let head = stored.head;
            // With provenance for a confined origin (§5.5): a trie of that
            // origin's this node holds whole but was not served as its is not
            // one it can vouch for, and `complete` is the vouching.
            let owner = self.store.provenance_owner(&head.origin, now)?;
            let complete =
                trie.is_complete_scoped_for(owner.as_ref(), head.root, &Scope::full())?;
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
                .canonical()
                .cmp(&b.origin.canonical())
                .then(a.order_key().cmp(&b.order_key()))
        });
        Ok(out)
    }

    /// Records what a peer advertised for *this node's own* origin (§3.4),
    /// and which peer made the claim.
    ///
    /// A node that lost its key and its database holds no head of its own, and
    /// the heads its peers still hold for it are signed by the lost key: no
    /// longer bound, so they can never be accepted as heads (§4.4). Their
    /// existence is what recovery reads, and it is already in every `Hello`
    /// summary — no new wire message, and no unbound signature is trusted here.
    /// Summaries for other origins are ignored: for those, the ordinary
    /// acceptance rule is both sufficient and stricter. Detection rests on
    /// unauthenticated summaries, so the attribution is what lets an operator
    /// judge a claim that holds a node in recovery.
    ///
    /// Returns the highest seq now observed for our origin.
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
    /// Only heads this node can back with a *servable trie*: what a peer does
    /// with one is fetch the trie under it from us, so handing over a head
    /// whose trie is not here costs the puller the whole
    /// [`MAX_UNPRODUCTIVE_ROUNDS`] escape and ends with the head abandoned.
    ///
    /// The complete slot is not that claim. A slot says this node promoted the
    /// head; whether the trie under it is whole is what
    /// [`Syncer::local_summaries`] answers with `complete` in the same
    /// exchange, and a delegate's slot holds every foreign origin over a
    /// partial trie by construction. Memoized per root.
    pub fn heads_for(&self, origins: &[OriginId]) -> Result<Vec<SignedHead>> {
        let trie = Trie::new(self.store.as_ref());
        let now = now_ns();
        let mut out = Vec::new();
        for origin in origins {
            let Some(stored) = self.store.head(origin, Slot::Complete)? else {
                continue;
            };
            let owner = self.store.provenance_owner(origin, now)?;
            if !trie.is_complete_scoped_for(owner.as_ref(), stored.head.root, &Scope::full())? {
                tracing::debug!(
                    origin = %origin,
                    "not serving a head whose trie this node does not hold whole"
                );
                continue;
            }
            out.push(stored.head);
        }
        Ok(out)
    }

    /// Offers a head for adoption, applying the full §5.2 acceptance rule.
    pub fn offer_head(&self, head: &SignedHead, now: i64) -> Result<HeadOutcome> {
        let outcome = self.store.accept_head(head, now, MAX_RETAINED_FORKS)?;
        match outcome {
            synch_store::Acceptance::BadSignature => return Ok(HeadOutcome::BadSignature),
            synch_store::Acceptance::Unbound => return Ok(HeadOutcome::Unbound),
            synch_store::Acceptance::NotNewer => return Ok(HeadOutcome::NotNewer),
            synch_store::Acceptance::Pending => {}
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
    /// tree, checkouts, and `synch-s3` serve from — missing a promoted head's
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
        let refused = self
            .refused
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|key| &key.0 == origin)
            .map(|key| (key.1, key.2, key.3))
            .collect();
        let promoted = self
            .store
            .promote_head(origin, now, refused, |seq, root, old| {
                self.refuse((origin.clone(), seq, root, old));
            })?;
        let promoted = match promoted {
            synch_store::Promotion::Flipped => Promotion::Flipped,
            synch_store::Promotion::Waiting => Promotion::Waiting,
            synch_store::Promotion::Refused => Promotion::Refused,
            synch_store::Promotion::Idle => Promotion::Idle,
        };
        if promoted == Promotion::Flipped {
            tracing::debug!(origin = %origin, "head flipped to complete");
            // One permit no matter how often this rings: passes coalesce,
            // and a wake landing mid-pass is not lost.
            for wake in [&self.on_change, &self.on_replica].into_iter().flatten() {
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
        self.fetch_pending_slot(client, origin, None).await
    }

    /// [`Syncer::fetch_pending`] for one specific head, skipped if the slot has
    /// moved on.
    ///
    /// The pending slot is per origin and only ever rises, so when two
    /// exchanges run at once — several peers dialed concurrently, or a
    /// `HeadPush` landing mid-round — the head one of them just offered can be
    /// displaced by a greater one from the other before either fetches. Both
    /// would then walk the *winner's* root, and the peer that never advertised
    /// it cannot serve a node of it: it spends its unproductive rounds, then
    /// abandons that head and clears the slot by name — legitimately, since by
    /// then it is the head it was fetching — out from under the peer that was
    /// transferring it. The successful fetch has nothing left to promote, and a
    /// head the two peers between them could deliver is adopted by neither.
    ///
    /// Fetching only what this peer handed over keeps every walk, and every
    /// abandonment, on a root its own peer advertised. Nothing is lost by
    /// standing down: the head that took the slot is being driven by the
    /// exchange that offered it, and the pending pass of any later round picks
    /// up one that was not.
    pub(crate) async fn fetch_pending_head(
        &self,
        client: &MptClient,
        head: &SignedHead,
    ) -> Result<FetchOutcome> {
        self.fetch_pending_slot(client, &head.origin, Some((head.seq, head.root)))
            .await
    }

    async fn fetch_pending_slot(
        &self,
        client: &MptClient,
        origin: &OriginId,
        expected: Option<(u64, Hash)>,
    ) -> Result<FetchOutcome> {
        let refused = self
            .refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|key| &key.0 == origin)
            .map(|key| (key.1, key.2, key.3))
            .collect();
        // Lean retains the whole requesting walk on one blocking worker. Only
        // owned requests and replies cross to the runtime; no continuation,
        // database session or connection guard crosses a network wait.
        use synch_verified::suspend::{PeerReply, PeerRequest};
        let (requests_tx, mut requests_rx) = tokio::sync::mpsc::channel(1);
        let store = self.store.clone();
        let fetch_origin = origin.clone();
        let syncer = self.clone();
        let fetching = crate::blocking::offload(move || {
            let fetched = store
                .fetch_pending(
                    &fetch_origin,
                    expected,
                    refused,
                    MAX_BATCH as u64,
                    MAX_UNPRODUCTIVE_ROUNDS.into(),
                    |request| {
                        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
                        requests_tx
                            .blocking_send((request.clone(), reply_tx))
                            .ok()?;
                        reply_rx.recv().ok()
                    },
                )
                .map_err(|error| match error {
                    synch_verified::CommandError::Operation(error) => fetch_operation_error(error),
                    synch_verified::CommandError::Domain(error) => {
                        reconciliation_domain_error(error)
                    }
                })?;
            let report = fetched.report;
            if let Some((seq, (root, old))) = report.refused {
                let root =
                    Hash::from_slice(&root).map_err(|e| EngineError::invalid(e.to_string()))?;
                let old =
                    Hash::from_slice(&old).map_err(|e| EngineError::invalid(e.to_string()))?;
                syncer.refuse((fetch_origin, seq, root, old));
            }
            if let Some(error) = report.failure {
                return Err(reconciliation_domain_error(error));
            }
            if fetched.abandoned {
                return Ok(FetchOutcome::Abandoned);
            }
            Ok(match report.promotion {
                synch_store::Promotion::Flipped => {
                    for wake in [&syncer.on_change, &syncer.on_replica]
                        .into_iter()
                        .flatten()
                    {
                        wake.notify_one();
                    }
                    FetchOutcome::Completed
                }
                synch_store::Promotion::Refused => FetchOutcome::Refused,
                synch_store::Promotion::Waiting | synch_store::Promotion::Idle => {
                    FetchOutcome::NoFlip
                }
            })
        });
        tokio::pin!(fetching);
        let fetched = loop {
            tokio::select! {
                result = &mut fetching => break result,
                request = requests_rx.recv() => {
                    let Some((request, reply_tx)) = request else {
                        break fetching.await;
                    };
                    let (root, wants, values) = match request {
                        PeerRequest::Nodes { root, wants } => (root, wants, false),
                        PeerRequest::Values { root, wants } => (root, wants, true),
                    };
                    let root = Hash::from_slice(&root).map_err(|e| EngineError::invalid(e.to_string()))?;
                    let wants = wants.into_iter().map(|(path, hash)| {
                        Hash::from_slice(&hash).map(|hash| (path, hash))
                            .map_err(|e| EngineError::invalid(e.to_string()))
                    }).collect::<Result<Vec<_>>>()?;
                    let reply = if values {
                        let response = client.get_values(root, &wants).await?;
                        PeerReply::Values {
                            served: response.values.into_iter().map(|(h, b)| (h.as_bytes().to_vec(), b)).collect(),
                            missing: response.missing.into_iter().map(|h| h.as_bytes().to_vec()).collect(),
                        }
                    } else {
                        let response = client.get_nodes(root, &wants).await?;
                        PeerReply::Nodes {
                            served: response.nodes.into_iter().map(|(h, b)| (h.as_bytes().to_vec(), b)).collect(),
                            missing: response.missing.into_iter().map(|h| h.as_bytes().to_vec()).collect(),
                            redacted: response.redacted.into_iter().map(|h| h.as_bytes().to_vec()).collect(),
                        }
                    };
                    // A cancelled driver drops this sender. The blocked worker
                    // then drops the continuation with no live transaction.
                    let _ = reply_tx.send(reply);
                }
            }
        };
        fetched
    }

    /// Runs a `Hello` exchange that pushes and pulls nothing, purely to read
    /// the peer's summaries (§3.4 step 2).
    ///
    /// This is what the recovery quiesce collects with. It is the ordinary
    /// exchange with an empty decision, so a recovering node learns how far
    /// peers say its origin had got without adopting anything.
    pub(crate) async fn observe_with(&self, client: &MptClient) -> Result<Vec<HeadSummary>> {
        let ours = self.summaries_off_runtime(client.remote_id()).await?;
        let peer = client.remote_id();
        let attempted = client
            .head_exchange(ours.summaries, ours.declared, |_theirs| {
                (Vec::new(), Vec::new())
            })
            .await;
        self.summaries_attempted(peer, ours.cursor);
        let exchange = attempted?;
        let syncer = self.clone();
        let peer = client.remote_id();
        let summaries = exchange.summaries.clone();
        crate::blocking::offload(move || {
            syncer.observe_summaries_from(Some(peer), &summaries, now_ns())
        })
        .await?;
        Ok(exchange.summaries)
    }

    /// Fetches and adopts a peer-retained head for this node's own origin,
    /// provided it was signed by a device key this database still holds.
    ///
    /// This is restore readoption, not key-loss recovery: a Litestream restore
    /// may be behind while retaining every signing key, so the peer's full head
    /// is independently verifiable and can safely replace the restored one.
    pub(crate) async fn readopt_self_with(
        &self,
        client: &MptClient,
        held_keys: &std::collections::HashSet<synch_core::NodeId>,
    ) -> Result<()> {
        let Advertisement {
            summaries: ours,
            cursor,
            declared,
            ..
        } = self.advertisement_off_runtime(client.remote_id()).await?;
        let own = {
            let store = self.store.clone();
            crate::blocking::offload(move || {
                store
                    .self_origin()?
                    .ok_or_else(|| EngineError::invalid("the node has no self origin"))
            })
            .await?
        };
        let wanted = own.clone();
        let peer = client.remote_id();
        let attempted = client
            .head_exchange(ours, declared, move |summaries| {
                let peer_has_own = summaries.iter().any(|summary| summary.origin == wanted);
                (
                    Vec::new(),
                    peer_has_own.then_some(wanted.clone()).into_iter().collect(),
                )
            })
            .await;
        self.summaries_attempted(peer, cursor);
        let exchange = attempted?;

        {
            let syncer = self.clone();
            let scope = exchange.scope.clone();
            let summaries = exchange.summaries.clone();
            let peer = client.remote_id();
            crate::blocking::offload(move || syncer.adopt_scope(peer, &scope, &summaries)).await?;
        }
        {
            let syncer = self.clone();
            let summaries = exchange.summaries.clone();
            let peer = client.remote_id();
            crate::blocking::offload(move || {
                syncer.observe_summaries_from(Some(peer), &summaries, now_ns())
            })
            .await?;
        }

        for head in exchange.received {
            if head.origin != own || !held_keys.contains(&head.signed_by) {
                continue;
            }
            match self.offer_head_off_runtime(&head).await? {
                HeadOutcome::Pending => {
                    let _ = self.fetch_pending_head(client, &head).await?;
                }
                HeadOutcome::Completed
                | HeadOutcome::NotNewer
                | HeadOutcome::BadSignature
                | HeadOutcome::Unbound
                | HeadOutcome::Refused => {}
            }
        }
        Ok(())
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
    async fn summaries_off_runtime(&self, peer: synch_core::NodeId) -> Result<Advertisement> {
        let syncer = self.clone();
        crate::blocking::offload(move || {
            let (summaries, cursor) = syncer.local_summaries_for(peer)?;
            Ok(Advertisement {
                summaries,
                cursor,
                declared: syncer.declared_scope(peer)?,
                servable: Vec::new(),
            })
        })
        .await
    }

    /// What this node advertises, and the heads it can actually hand over.
    ///
    /// Read together because the push decision needs both. This performs one
    /// walk per unproven root and one query per origin off the runtime worker;
    /// the scope declaration travels with them.
    async fn advertisement_off_runtime(&self, peer: synch_core::NodeId) -> Result<Advertisement> {
        let syncer = self.clone();
        crate::blocking::offload(move || {
            let (summaries, cursor) = syncer.local_summaries_for(peer)?;
            let declared = syncer.declared_scope(peer)?;
            // Filtered by the summaries this same exchange carries, not by the
            // complete slot: a head is worth pushing only if this node can
            // serve the trie under it. Pushing one that cannot be served lands
            // it in the receiver's pending slot, pinning `head_floor` until it
            // times out — the same cost `heads_for` stopped paying, reached by
            // the other message (§5.1).
            let servable = syncer
                .store
                .all_heads(Slot::Complete)?
                .into_iter()
                .map(|stored| stored.head)
                .filter(|head| {
                    summaries.iter().any(|s| {
                        s.origin == head.origin
                            && s.root == head.root
                            && s.seq == head.seq
                            && s.complete
                    })
                })
                .collect();
            Ok(Advertisement {
                summaries,
                cursor,
                declared,
                servable,
            })
        })
        .await
    }

    /// What this node will serve the peer it is dialing (§5.5).
    ///
    /// A dialer declares the scope of the peer it is calling, exactly as a
    /// responder does, so the direction of the dial makes no difference to what
    /// either side may read.
    ///
    /// A store read, so it is only ever called from a blocking scope.
    ///
    /// A declaration is not a grant — every responder enforces its own scope on
    /// every request — so its only effect is on how far the *reader* narrows
    /// itself. The three-valued shape is deliberate: a peer whose binding has
    /// momentarily lapsed must not be told the same thing as one promoted to a
    /// full member, because the reader decides what to do with its own grant
    /// from exactly that difference.
    fn declared_scope(&self, peer: synch_core::NodeId) -> Result<DeclaredScope> {
        Ok(match self.store.publish_scope_of_key(&peer, now_ns())? {
            synch_store::PublishScope::Untrusted => DeclaredScope::Untrusted,
            synch_store::PublishScope::Unrestricted => DeclaredScope::Unrestricted,
            synch_store::PublishScope::Confined(spaces) => DeclaredScope::Confined(spaces),
        })
    }

    /// Adopts the scope a peer declared for us, clearing anything memoized
    /// against the old one.
    ///
    /// Narrowing or widening, a change makes every completeness answer
    /// computed under the previous scope an answer to a different question, so
    /// the memo goes with it. It is keyed by scope as well as root, so nothing
    /// stale can be read back — this only avoids a table of answers nobody
    /// will ask for again.
    ///
    /// A declaration is only ever a bootstrap: once this node's own grant is
    /// materialized — its `d:` record, which the walk under any scope always
    /// includes — the read scope is that grant, and nothing a peer says is
    /// remembered (§5.5). A declaration can therefore never widen what this
    /// node may read:
    ///
    /// - a live grant makes the grant authoritative, whatever the peer says:
    ///   a peer one head behind the `d:` record, or one whose binding for this
    ///   node has lapsed, sees no delegation and would otherwise widen the
    ///   delegate back to the whole keyspace;
    /// - with no grant, a `Confined` declaration is the bootstrap — the only
    ///   legitimate way to learn the grant, since the trie it lives in cannot
    ///   be read before the scope is known;
    /// - `Unrestricted` with no grant is a promotion to a full member — but
    ///   only one this node can vouch for itself (a rooted binding for its
    ///   own key in a foreign origin, the shape a promotion's zone record
    ///   leaves): any operator's local `trust add` produces the same wire
    ///   value, and a lapsed grant must not be widened back by it;
    /// - `Untrusted` with no grant collapses a dead grant (revocation) to the
    ///   empty scope — `m:self` and the `d:` namespace, no file data — and
    ///   leaves a fresh node's default `None` alone.
    fn adopt_scope(
        &self,
        peer: synch_core::NodeId,
        declared: &DeclaredScope,
        summaries: &[synch_core::HeadSummary],
    ) -> Result<()> {
        // And only a peer that holds the trie the grant is published in. A
        // delegation is a record in the issuing origin's trie, so a peer that
        // cannot serve that trie has not read it and will answer from its own
        // local `trust add` instead — two honest peers then tell this node two
        // different things, and with one node-wide scope it flips between them
        // once per round, discarding and refetching every foreign origin each
        // time (§5.5).
        //
        // This is the enforceable half of "a delegate syncs only with full
        // members of its cluster": membership is holding the cluster's tries,
        // not sharing a domain suffix, and `complete` is where a peer says so.
        // A node no delegation names skips the check, which is what lets one
        // bootstrap.
        let issuers = self.store.own_issuers(now_ns())?;
        if !issuers.is_empty()
            && !issuers
                .iter()
                .any(|issuer| summaries.iter().any(|s| &s.origin == issuer && s.complete))
        {
            tracing::debug!(
                peer = %peer.fmt_short(),
                "ignoring a read scope declared by a peer that does not hold this node's \
                 issuer's trie"
            );
            return Ok(());
        }
        // Only a peer this node holds a *rooted* binding for may narrow it.
        //
        // The declaration drives more than what this node asks for: it decides
        // what counts as a complete trie and what gets materialized. A delegate
        // that could set it would be able to stop an ordinary member
        // replicating spaces it has every right to — and a member never holds a
        // rooted binding for a delegate, which is exactly the distinction that
        // closes it. A delegate bootstrapping holds a static or DNS binding for
        // the peers it dials, so it still learns its own scope.
        let rooted = self.store.is_rooted_key(&peer, now_ns())?;
        if !rooted {
            if *declared != DeclaredScope::Untrusted {
                tracing::debug!(
                    peer = %peer.fmt_short(),
                    "ignoring a read scope declared by a peer this node has no rooted binding for"
                );
            }
            return Ok(());
        }
        // The effective scope, from the node's own grant and the peer's
        // declaration — the declaration can only narrow, never widen:
        // `own_grant` is the `d:` record this node materialized itself, so it
        // is the freshest truth it holds, and a declaration from a peer whose
        // view is stale (or hostile) must not reach past it.
        let own = self.store.own_grant(now_ns())?;
        let current = self.store.local_scope()?;
        // A promotion this node can vouch for itself: a rooted binding for
        // its own key in a foreign origin, the shape a promotion's zone
        // record leaves in this node's resolver.
        let promoted = self.store.own_rooted_in_foreign_origin(now_ns())?;
        let effective: Option<Vec<String>> = match (own, declared) {
            // The grant is authoritative; a declaration cannot widen it.
            (Some(grant), _) => Some(grant),
            // Bootstrap: no grant materialized yet, and a peer that holds one
            // tells us what the walk is about to find in the trie.
            (None, DeclaredScope::Confined(spaces)) if current.is_none() => Some(spaces.clone()),
            // A dead grant must not be re-adopted from a stale declaration;
            // only a materialized re-grant (a fresh `d:` record, which the
            // walk always includes) may widen the collapsed scope.
            (None, DeclaredScope::Confined(_)) => return Ok(()),
            // Promotion: the peer holds a rooted binding for this node. Only
            // a binding this node itself materialized may widen it — any
            // operator's local `trust add` produces the same wire value, and
            // a delegate whose grant lapsed must not be widened back to the
            // whole keyspace by one stale rooted view (§5.5).
            (None, DeclaredScope::Unrestricted) if promoted => None,
            // Not promoted: the no-binding case. A scope that was confined
            // collapses to the empty scope — `m:self` and the `d:` namespace,
            // no file data — while a fresh node's default `None` stays put:
            // a fresh node is not a delegate until it has replicated the
            // trie the granting record lives in, and a key-identified node
            // may equally be an ordinary peer replicating a rooted member in
            // full (the bootstrap, §5.5).
            (None, DeclaredScope::Unrestricted)
                if current.as_ref().is_some_and(|s| !s.is_empty()) =>
            {
                Some(Vec::new())
            }
            (None, DeclaredScope::Unrestricted) => return Ok(()),
            // Revocation: the peer holds no binding at all.
            (None, DeclaredScope::Untrusted) if current.as_ref().is_some_and(|s| !s.is_empty()) => {
                Some(Vec::new())
            }
            (None, DeclaredScope::Untrusted) => return Ok(()),
        };
        // The one path that moves the scope, and destructive by design (§5.5):
        // everything derived under the old one answers a question nobody is
        // asking any more, and no diff reconciles it.
        if self.store.set_read_scope(effective.as_deref())? {
            tracing::info!(
                spaces = ?effective,
                "the read scope moved: every foreign origin will be refetched and rebuilt under it"
            );
            self.scope_changed();
        }
        Ok(())
    }

    /// Runs one full `Hello` push-pull exchange with a peer, then fetches
    /// whatever it advertised that we do not have (§5.2, §5.3).
    pub async fn sync_with(&self, client: &MptClient) -> Result<SyncReport> {
        // A delegate pulls metadata only from a full member of its own cluster
        // (§5.5). The dial refuses this too; this is the check that decides,
        // because a session can outlive the binding it was opened under and an
        // inbound connection never passed through the dial at all.
        {
            let store = self.store.clone();
            let peer = client.remote_id();
            if let Some(reason) =
                crate::blocking::offload(move || Ok(store.refuse_metadata_sync(&peer, now_ns())?))
                    .await?
            {
                tracing::debug!(peer = %peer.fmt_short(), %reason, "declining a metadata exchange");
                return Ok(SyncReport::default());
            }
        }

        // Bring summaries and their servable heads over together in one hop to
        // the blocking pool. The decision below needs only those heads (§10).
        let Advertisement {
            summaries: ours,
            cursor,
            declared,
            servable,
        } = self.advertisement_off_runtime(client.remote_id()).await?;

        let mut report = SyncReport::default();
        let mut planning_failure = None;
        let peer = client.remote_id();
        let exchange = client
            .head_exchange(ours.clone(), declared, |theirs| {
                match exchange_plan(&ours, theirs, &servable) {
                    Ok(plan) => plan,
                    Err(error) => {
                        planning_failure = Some(error);
                        (Vec::new(), Vec::new())
                    }
                }
            })
            .await;
        self.summaries_attempted(peer, cursor);
        if let Some(error) = planning_failure {
            return Err(error);
        }
        let theirs = exchange?;

        // What the peer says it will serve us. Adopted before anything is
        // fetched, so the very first walk of this session is already confined
        // to it — which is how a delegated node comes to be able to read the
        // trie its own scope is published in (§5.5).
        {
            let syncer = self.clone();
            let scope = theirs.scope.clone();
            let peer = client.remote_id();
            let seen = theirs.summaries.clone();
            crate::blocking::offload(move || syncer.adopt_scope(peer, &scope, &seen)).await?;
        }

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
                    // Fetch after every offered head has reached its durable
                    // pending slot. Fetching inline let one stalling origin
                    // prevent later signed heads in this same answer from even
                    // being adopted. The cyclic pending pass below owns the
                    // bounded work and its cursor.
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
        let completed = self
            .pending_cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for stored in rotate_pending(
            pending_heads,
            completed.as_ref(),
            PENDING_ORIGIN_FANOUT,
            |stored| &stored.head.origin,
        )? {
            let pending = stored.head;
            if !serves_trie(
                &theirs.summaries,
                &pending.origin,
                pending.seq,
                pending.root.0,
            ) {
                // The origin received a completed scheduling turn even though
                // this peer cannot serve it. Retaining the cursor here would
                // let an unavailable prefix occupy every later round and hide
                // an origin this same peer can serve.
                *self
                    .pending_cursor
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(pending.origin.clone());
                continue;
            }
            let attempted = tokio::time::timeout(
                PENDING_FETCH_BUDGET,
                self.fetch_pending_head(client, &pending),
            )
            .await;
            // A timeout is a completed scheduling attempt: the requesting
            // continuation is dropped, while all verified batches it committed
            // remain. Advance only now. Cancellation of `sync_with` while the
            // future is pending never reaches this assignment and retries the
            // same origin next time.
            *self
                .pending_cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pending.origin.clone());
            let outcome = match attempted {
                Ok(outcome) => outcome,
                Err(_) => {
                    tracing::debug!(
                        origin = %pending.origin,
                        budget = ?PENDING_FETCH_BUDGET,
                        "pending trie fetch yielded its turn after reaching the per-origin budget"
                    );
                    continue;
                }
            };
            match outcome {
                Ok(FetchOutcome::Completed) => report.tries_completed += 1,
                Ok(FetchOutcome::Abandoned) => report.heads_abandoned += 1,
                Ok(FetchOutcome::Refused) => report.left_behind(&pending.origin),
                Ok(FetchOutcome::NoFlip) => {}
                Err(e) if is_origin_fault(&e) => contain(&pending.origin, &e, &mut report),
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }
}

/// True if `summaries` says the peer can serve the trie under this head (§5.1).
///
/// A signed head proves the origin published it; it says nothing about whether
/// the peer offering it holds the trie. `complete` is the claim that matters,
/// and it has to be checked against a seq at or above the one being fetched —
/// an older complete root cannot serve a newer head's nodes.
fn serves_trie(
    summaries: &[synch_core::HeadSummary],
    origin: &OriginId,
    seq: u64,
    root: [u8; 32],
) -> bool {
    summaries.iter().any(|summary| {
        &summary.origin == origin && summary.complete && summary.order_key() >= (seq, root)
    })
}

fn fetch_operation_error(
    error: synch_verified::trie::OperationError<synch_store::StoreError>,
) -> EngineError {
    use synch_verified::trie::OperationError;
    match error {
        OperationError::Host(error) => error.into(),
        OperationError::Protocol | OperationError::MalformedMetadata(_) => {
            EngineError::invalid("invalid native requesting-operation protocol")
        }
    }
}

fn reconciliation_domain_error(
    error: synch_verified::reconcile::ReconcileDomainError,
) -> EngineError {
    match error {
        synch_verified::reconcile::ReconcileDomainError::Fetch(error) => fetch_domain_error(error),
        synch_verified::reconcile::ReconcileDomainError::Missing(error) => {
            fetch_domain_error(synch_verified::trie::TrieFetchDomainError::Walk(error))
        }
        error => EngineError::Store(error.into()),
    }
}

fn fetch_domain_error(error: synch_verified::trie::TrieFetchDomainError) -> EngineError {
    use synch_mpt::MptError;
    use synch_verified::trie::{
        NodeRefusal, TrieFetchDomainError as Fetch, TrieMissingDomainError as Walk,
    };
    let hash =
        |bytes: &[u8]| Hash::from_slice(bytes).map_err(|e| EngineError::invalid(e.to_string()));
    match error {
        Fetch::Origin(refusal) => EngineError::Mpt(match refusal {
            NodeRefusal::Decode(message) => MptError::Decode(message),
            NodeRefusal::NonCanonical(message) => MptError::NonCanonical(message),
            NodeRefusal::KeyTooLong(size) => {
                MptError::KeyTooLong(usize::try_from(size).unwrap_or(usize::MAX))
            }
        }),
        Fetch::NodeHash(bytes) => match hash(&bytes) {
            Ok(expected) => NetError::NodeHashMismatch { expected }.into(),
            Err(error) => error,
        },
        Fetch::ValueHash(bytes) => match hash(&bytes) {
            Ok(expected) => NetError::ValueHashMismatch { expected }.into(),
            Err(error) => error,
        },
        Fetch::Unsolicited { value, hash: bytes } => NetError::Unexpected(format!(
            "peer served unrequested or repeated trie {} {}",
            if value { "value" } else { "node" },
            hex::encode(bytes),
        ))
        .into(),
        Fetch::Walk(error) => EngineError::Mpt(match error {
            Walk::Decode(message) => MptError::Decode(message),
            Walk::NodeDepth(depth) => MptError::NonCanonical(format!(
                "a trie node sits past the maximum depth at {depth}"
            )),
            Walk::ValueDepth(depth) => MptError::NonCanonical(format!(
                "a trie value sits past the maximum depth at {depth}"
            )),
            Walk::ExpectedBranch(bytes) => MptError::NonCanonical(format!(
                "node {} sits under an extension but is not a branch",
                hex::encode(bytes)
            )),
            Walk::ValueLength {
                hash,
                size,
                routing,
            } => MptError::NonCanonical(format!(
                "addressed value {} has invalid length {size} for a {} holder",
                hex::encode(hash),
                if routing { "routing" } else { "legacy" },
            )),
            Walk::Exhausted => {
                MptError::NonCanonical("the requesting walk outran its work budget".into())
            }
        }),
        Fetch::Exhausted => EngineError::invalid("the requesting operation outran its work budget"),
    }
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
    fn local_summaries(
        &self,
        peer: NodeId,
    ) -> std::result::Result<(Vec<HeadSummary>, Option<OriginId>), NetError> {
        self.local_summaries_for(peer).map_err(to_net)
    }

    fn summaries_attempted(
        &self,
        peer: NodeId,
        cursor: Option<OriginId>,
    ) -> std::result::Result<(), NetError> {
        Syncer::summaries_attempted(self, peer, cursor);
        Ok(())
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
    /// seam cannot tell an undecodable `f:` record from `SQLITE_BUSY`. Classify
    /// here, where `try_promote` has retired any head it could judge. A fault
    /// raised earlier leaves the slot to the maintenance sweep.
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

/// The whole exchange decision lives in Lean. This adapter only translates
/// identities and returns the original signed heads selected by the command.
/// Both advertised slots are supplied; the native planner owns comparisons,
/// duplicate handling and push/request selection.
fn exchange_plan(
    ours: &[HeadSummary],
    theirs: &[HeadSummary],
    servable: &[SignedHead],
) -> Result<(Vec<SignedHead>, Vec<OriginId>)> {
    use synch_verified::replication::{plan_exchange, Advertised};
    let summaries = |heads: &[HeadSummary]| {
        heads
            .iter()
            .map(|head| Advertised {
                origin: head.origin.canonical(),
                seq: head.seq,
                root: head.root.0.to_vec(),
            })
            .collect()
    };
    let plan = plan_exchange(
        summaries(ours),
        summaries(theirs),
        servable
            .iter()
            .map(|head| Advertised {
                origin: head.origin.canonical(),
                seq: head.seq,
                root: head.root.0.to_vec(),
            })
            .collect(),
    )
    .map_err(|error| EngineError::Record(error.to_string()))?;
    let push = plan
        .push
        .into_iter()
        .map(|position| {
            usize::try_from(position)
                .ok()
                .and_then(|position| servable.get(position))
                .cloned()
                .ok_or_else(|| EngineError::Record("invalid Lean exchange head position".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut want = plan
        .want
        .into_iter()
        .map(|origin| {
            origin
                .parse::<OriginId>()
                .map_err(|error| EngineError::Record(error.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    // Preserve the wire's existing OriginId ordering (key origins first,
    // then named origins by domain/id), which differs from canonical text.
    want.sort();
    Ok((push, want))
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
///   These propagate so an operator can see them.
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
    /// Whether this exchange completed locally visible state.
    ///
    /// Pushing heads advances the peer, accepting a pending head only records a
    /// pointer, and abandoning or refusing one merely unwedges the slot. None
    /// stops periodic fallback to another candidate; only a completed trie has
    /// moved what local readers can observe.
    pub(crate) fn made_local_progress(&self) -> bool {
        self.tries_completed > 0
    }

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

    pub(super) fn setup() -> (tempfile::TempDir, Arc<Store>, SecretKey, OriginId) {
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
                issuer: None,
                spaces: Vec::new(),
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

    /// DoS bound: an origin flooding one seq is evicted at the cap, never
    /// refused — the greatest roots keep the slot, whatever arrived first.
    #[test]
    fn same_seq_forks_are_evicted_at_the_cap_and_never_refused() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        // Ascending roots, past the cap: each one supersedes the last.
        for i in 1..=MAX_RETAINED_FORKS as u8 + 4 {
            let head = SignedHead::sign(&key, origin.clone(), 1, Hash([i; 32]), 0);
            assert!(
                syncer.offer_head(&head, 0).unwrap().accepted(),
                "fork {i} is evidence and is taken"
            );
        }
        assert_eq!(store.fork_width(&origin, 1).unwrap(), MAX_RETAINED_FORKS);
        let roots: Vec<u8> = store
            .head_history(&origin)
            .unwrap()
            .iter()
            .filter(|h| h.seq == 1)
            .map(|h| h.root.0[0])
            .collect();
        assert_eq!(*roots.iter().min().unwrap(), MAX_RETAINED_FORKS as u8 - 3);
        assert_eq!(
            store.head_floor(&origin).unwrap().unwrap().1,
            Hash([MAX_RETAINED_FORKS as u8 + 4; 32]),
            "and the greatest root of all holds the slot"
        );
        // The evidence a fork exists is still there.
        assert_eq!(store.equivocations().unwrap().len(), 1);

        // A head at a later seq is the origin moving on, and is taken normally.
        let next = SignedHead::sign(&key, origin, 2, Hash([1u8; 32]), 0);
        assert!(syncer.offer_head(&next, 0).unwrap().accepted());
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

        // §3.2: a valid signature from a key that is not bound to the origin
        // is refused even if relayed by a trusted peer.
        let stranger = SecretKey::generate();
        let relayed = SignedHead::sign(&stranger, origin.clone(), 1, Hash::EMPTY, 0);
        relayed.verify_signature().unwrap();
        assert_eq!(
            syncer.offer_head(&relayed, 0).unwrap(),
            HeadOutcome::Unbound
        );
        assert_eq!(store.complete_head(&origin).unwrap(), None);
    }

    #[test]
    fn an_expired_binding_no_longer_admits_heads() {
        // The instants are real ones: an expiry is compared against a clock,
        // and a reading below `MIN_TRUSTED_NS` dates nothing (§3.2).
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
                issuer: None,
                spaces: Vec::new(),
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

    /// Two-slot advertising: a pending head is advertised *alongside* the
    /// servable complete head, never in its place — a propagation-killing shape.
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
    fn oversized_summary_pages_rotate_without_splitting_an_origins_slots() {
        let origins = (0..(synch_core::MAX_HEADS_PER_MESSAGE / 2 + 1))
            .map(|index| OriginId::named(&format!("node-{index:05}"), "x.example").unwrap())
            .collect::<Vec<_>>();
        let summaries = origins
            .iter()
            .flat_map(|origin| {
                [
                    HeadSummary {
                        origin: origin.clone(),
                        seq: 1,
                        root: Hash::EMPTY,
                        complete: true,
                    },
                    HeadSummary {
                        origin: origin.clone(),
                        seq: 2,
                        root: Hash::new(origin.canonical().as_bytes()),
                        complete: false,
                    },
                ]
            })
            .collect::<Vec<_>>();
        // Match the canonical text ordering consumed by the verified planner
        // rather than relying on construction order.
        let mut summaries = summaries;
        summaries.sort_by(|a, b| {
            a.origin
                .canonical()
                .cmp(&b.origin.canonical())
                .then(a.order_key().cmp(&b.order_key()))
        });
        let (first, cursor) =
            page_summaries(summaries.clone(), None, synch_core::MAX_HEADS_PER_MESSAGE).unwrap();
        let (second, _) = page_summaries(
            summaries.clone(),
            cursor.as_ref(),
            synch_core::MAX_HEADS_PER_MESSAGE,
        )
        .unwrap();

        assert_eq!(first.len(), synch_core::MAX_HEADS_PER_MESSAGE);
        assert_eq!(second.len(), synch_core::MAX_HEADS_PER_MESSAGE);
        let tail = origins.last().unwrap();
        assert!(
            !first.iter().any(|summary| &summary.origin == tail),
            "the old fixed prefix reproduces the starvation this test guards"
        );
        let tail_slots = second
            .iter()
            .filter(|summary| &summary.origin == tail)
            .collect::<Vec<_>>();
        assert_eq!(tail_slots.len(), 2, "complete and pending travel together");
        assert!(tail_slots.iter().any(|summary| summary.complete));
        assert!(tail_slots.iter().any(|summary| !summary.complete));

        let peer_a = SecretKey::generate().public();
        let peer_b = SecretKey::generate().public();
        let mut cursors = HashMap::new();
        let (first_a, reserved_a) = page_summaries_for_peer(
            summaries.clone(),
            &cursors,
            peer_a,
            synch_core::MAX_HEADS_PER_MESSAGE,
        )
        .unwrap();
        let (cancelled_a, _) = page_summaries_for_peer(
            summaries.clone(),
            &cursors,
            peer_a,
            synch_core::MAX_HEADS_PER_MESSAGE,
        )
        .unwrap();
        assert_eq!(first_a, cancelled_a, "cancellation retains the old cursor");
        cursors.insert(peer_a, reserved_a.unwrap());
        let (second_a, _) = page_summaries_for_peer(
            summaries.clone(),
            &cursors,
            peer_a,
            synch_core::MAX_HEADS_PER_MESSAGE,
        )
        .unwrap();
        let (first_b, _) = page_summaries_for_peer(
            summaries,
            &cursors,
            peer_b,
            synch_core::MAX_HEADS_PER_MESSAGE,
        )
        .unwrap();
        assert_eq!(first_a, first_b, "a new peer starts on its own first page");
        assert_ne!(
            first_a, second_a,
            "one peer advances without moving another"
        );
    }

    #[test]
    fn pending_rotation_resumes_after_the_last_finished_attempt() {
        let key = SecretKey::generate();
        let stored = |name: &str| {
            let origin = OriginId::named(name, "x.example").unwrap();
            SignedHead::sign(&key, origin, 1, Hash::EMPTY, 0)
        };
        let pending = vec![stored("a"), stored("b"), stored("c")];

        // If `a` consumed its bounded slice, persisting that completed attempt
        // makes `b` lead the next round. A cancellation before completion simply
        // does not update this cursor and therefore retries the in-flight item.
        let a = pending[0].origin.clone();
        assert_eq!(
            rotate_pending(pending.clone(), None, 3, |head| &head.origin).unwrap()[0].origin,
            a,
            "fixed ordering makes the stalled prefix lead every fresh pass"
        );
        let rotated = rotate_pending(pending, Some(&a), 3, |head| &head.origin).unwrap();
        assert_eq!(
            rotated[0].origin,
            OriginId::named("b", "x.example").unwrap()
        );
        assert_eq!(
            rotated[1].origin,
            OriginId::named("c", "x.example").unwrap()
        );
        assert_eq!(rotated[2].origin, a);
    }

    #[test]
    fn changing_scope_forgets_process_local_refusal_verdicts() {
        let (_dir, store, _key, origin) = setup();
        let syncer = Syncer::new(store);
        syncer.refuse((origin, 7, Hash::new(b"new"), Hash::new(b"old")));
        assert_eq!(syncer.refused.lock().unwrap().len(), 1);

        syncer.scope_changed();

        assert!(syncer.refused.lock().unwrap().is_empty());
    }

    #[test]
    fn promotion_of_our_own_version_requires_the_whole_view() {
        use synch_mpt::NodeStore;

        let (_d, store, key, origin) = setup();
        store.set_self_origin(&origin).unwrap();
        store.set_read_scope(Some(&["photos".into()])).unwrap();
        let pending = SignedHead::sign(&key, origin.clone(), 1, Hash::new(b"unfetched"), 0);
        store.put_head(Slot::Pending, &pending, 0, 0).unwrap();
        store.note_redacted(&pending.root, &[]).unwrap();

        // A refusal could satisfy the restricted foreign-origin walk. Our
        // recovered version is materialized in full, so that answer cannot
        // justify replacing our own view with an empty one.
        assert_eq!(
            Syncer::new(store.clone()).try_promote(&origin, 0).unwrap(),
            Promotion::Waiting
        );
        assert_eq!(store.complete_head(&origin).unwrap(), None);
        assert_eq!(store.pending_head(&origin).unwrap(), Some(pending));
    }

    #[test]
    fn promotion_after_revocation_preserves_the_accepted_view() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let root = publish(&store, &["kept"]);
        let accepted = SignedHead::sign(&key, origin.clone(), 1, root, 0);
        assert_eq!(
            syncer.offer_head(&accepted, 0).unwrap(),
            HeadOutcome::Completed
        );
        // The empty newer version would remove the accepted file if stale
        // rooted authority were used when this pending work is promoted.
        let pending = SignedHead::sign(&key, origin.clone(), 2, Hash::EMPTY, 0);
        store.put_head(Slot::Pending, &pending, 0, 0).unwrap();
        store
            .remove_binding(&origin, &key.public(), BindingSource::Static)
            .unwrap();
        assert_eq!(syncer.try_promote(&origin, 0).unwrap(), Promotion::Refused);
        assert_eq!(store.complete_head(&origin).unwrap(), Some(accepted));
        assert!(store.entry(&origin, "s", "kept").unwrap().is_some());
        assert_eq!(store.pending_head(&origin).unwrap(), None);
    }

    /// §5.2: the flip and the materialization are one transaction — a record
    /// the materializer cannot decode stands in for the crash.
    #[test]
    fn a_promotion_that_fails_to_materialize_does_not_flip_the_head() {
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

        // What must not have happened is the flip: the complete slot still
        // names the good root (the poisoned root *is* in `head_history` — the
        // signature is there by construction — so that table is no oracle).
        let complete = store.complete_head(&origin).unwrap().unwrap();
        assert_eq!(complete.seq, 1);
        assert_eq!(complete.root, good);
        assert_ne!(complete.root, poisoned);
        // And the head that failed no longer holds the slot, and the good
        // head's entry is still materialized.
        assert_eq!(store.pending_head(&origin).unwrap(), None);
        assert!(store.entry(&origin, "s", "poisoned").unwrap().is_none());
        assert!(store.entry(&origin, "s", "a").unwrap().is_some());
    }
}

#[cfg(test)]
mod containment_tests {
    use synch_core::{file_key, FileEntry, Hash, OriginId, SignedHead};
    use synch_store::Slot;

    use super::tests::setup;
    use super::*;

    fn pending_received_at(store: &Store, origin: &OriginId) -> i64 {
        store
            .head(origin, Slot::Pending)
            .unwrap()
            .unwrap()
            .received_at
    }

    /// A poisoned head must not pin `head_floor` above servable heads; the
    /// verdict is remembered (re-offer Refused from the memo, a different
    /// root judged on its merits), the evidence stays in `head_history`.
    ///
    /// Two ways to poison a trie, one verdict: a non-`FileEntry` value, and a
    /// node the walk refuses (§4.3) — the walk fires before the promotion
    /// diff, so the verdict key is built before it.
    #[test]
    fn a_promotion_judged_unpromotable_holds_no_floor_and_is_not_attempted_again() {
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
        assert_eq!(store.head_history(&origin).unwrap().len(), 1);

        // Offered again — which is what every later exchange with a peer
        // holding it does: no error surfaces, the outcome is still counted
        // against the origin, and it does not keep the floor.
        assert_eq!(
            syncer.offer_head(&head, 0).unwrap(),
            HeadOutcome::Refused,
            "the promotion is not re-attempted, and the origin is still counted"
        );
        assert_eq!(store.head_floor(&origin).unwrap(), None);

        // The same verdict by the other route: a trie that is structurally
        // invalid — an extension whose child is a leaf, which no canonical
        // trie contains (§4.3). Stored through `put_node` directly, because
        // this is what a peer serving a hand-built graph looks like.
        let value = synch_mpt::ValueRef::Inline(vec![7u8; 4]);
        let child = synch_mpt::TrieNode::Leaf {
            key_rest: synch_mpt::Nibbles::from_nibbles(&[1, 2]),
            value,
        };
        let child_hash = child.hash();
        let structural = synch_mpt::TrieNode::Ext {
            prefix: synch_mpt::Nibbles::from_nibbles(&[4]),
            child: child_hash,
        };
        let structural_root = structural.hash();
        synch_mpt::NodeStore::put_node(store.as_ref(), &child_hash, &child.encode()).unwrap();
        synch_mpt::NodeStore::put_node(store.as_ref(), &structural_root, &structural.encode())
            .unwrap();
        let bad = SignedHead::sign(&key, origin.clone(), 7, structural_root, 0);
        let err = syncer
            .offer_head(&bad, 0)
            .expect_err("a non-canonical node is the origin's fault");
        assert!(is_origin_fault(&err), "{err}");
        assert_eq!(store.pending_head(&origin).unwrap(), None);
        assert_eq!(
            store.head_floor(&origin).unwrap(),
            None,
            "retired: the floor is back to what this node can serve"
        );

        // A good root this node *can* serve is adoptable again — a lesser
        // one, which the held floor would have refused...
        let good_value = postcard::to_stdvec(&FileEntry::file(1, 0, Hash::new(b"c"), 1)).unwrap();
        let good = trie
            .insert(Hash::EMPTY, &file_key("s", "a.txt").unwrap(), &good_value)
            .unwrap();
        let lesser = SignedHead::sign(&key, origin.clone(), 4, good, 0);
        assert_eq!(
            syncer.offer_head(&lesser, 0).unwrap(),
            HeadOutcome::Completed,
            "a lesser servable head must be adoptable again"
        );

        // ...and a later one is the origin moving on, taken normally.
        let later = SignedHead::sign(&key, origin, 6, good, 0);
        assert_eq!(
            syncer.offer_head(&later, 0).unwrap(),
            HeadOutcome::Completed
        );
    }

    /// The fetch bell (§5.3): a pending head rung mid-round — when the loop
    /// is dialling peers rather than parked — must still wake a listener that
    /// parks afterwards, and a refused head must not ring at all: a Notify
    /// keeps one permit per ring, so either fault would fail a check.
    #[tokio::test]
    async fn the_fetch_bell_keeps_mid_round_rings_and_stays_silent_for_refusals() {
        let (_d, store, key, origin) = setup();
        let wake = Arc::new(tokio::sync::Notify::new());
        let syncer = Syncer::new(store.clone()).on_pending(wake.clone());

        // Rung with no listener parked, which is the mid-round case.
        let head = SignedHead::sign(&key, origin.clone(), 1, Hash([1u8; 32]), 0);
        assert_eq!(syncer.offer_head(&head, 0).unwrap(), HeadOutcome::Pending);
        // A listener arriving afterwards still has to see it.
        tokio::time::timeout(std::time::Duration::from_secs(5), wake.notified())
            .await
            .expect("a wake that landed while the loop was busy must still be there");

        // A poisoned head rings nothing: neither the fault on arrival nor the
        // memo refusal.
        let trie = Trie::new(store.as_ref());
        let poisoned = trie
            .insert(Hash::EMPTY, &file_key("s", "a.txt").unwrap(), &[0xffu8; 8])
            .unwrap();
        let bad = SignedHead::sign(&key, origin.clone(), 5, poisoned, 0);
        syncer
            .offer_head(&bad, 0)
            .expect_err("the record cannot be materialized");
        assert_eq!(
            syncer.offer_head(&bad, 0).unwrap(),
            HeadOutcome::Refused,
            "answered from the memo"
        );
        for _ in 0..2 {
            tokio::time::timeout(std::time::Duration::from_millis(200), wake.notified())
                .await
                .expect_err("a retired or refused head must not ring the fetch bell");
        }
    }

    /// The pending slot ages, not the head occupying it: taking `received_at`
    /// from each new head reset the sweep clock, so a fast publisher outran
    /// the TTL forever.
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
        assert_eq!(stored.received_at, 100);

        // A fetch that commits something restarts it, so a trie that genuinely
        // takes longer than the TTL to arrive is not swept mid-transfer.
        assert!(
            !store
                .touch_pending_at(&origin, 1, &Hash([1u8; 32]), 9_500)
                .unwrap(),
            "a fetch of a head the slot has moved past must not restart the clock"
        );
        let received = pending_received_at(&store, &origin);
        assert_eq!(received, 100);
        assert!(store
            .touch_pending_at(&origin, 2, &Hash([2u8; 32]), 9_500)
            .unwrap());
        let received = pending_received_at(&store, &origin);
        assert_eq!(received, 9_500);

        // An empty slot starts its own clock.
        assert!(store
            .clear_head_at(&origin, Slot::Pending, 2, &Hash([2u8; 32]))
            .unwrap());
        store
            .put_head(Slot::Pending, &first, 20_000, 20_000)
            .unwrap();
        let received = pending_received_at(&store, &origin);
        assert_eq!(received, 20_000);
        let other = OriginId::named("other", "x.example").unwrap();
        assert!(
            !store
                .touch_pending_at(&other, 1, &Hash([1u8; 32]), 1)
                .unwrap(),
            "and there is nothing to touch for an origin with no pending head"
        );
    }

    /// Our own next seq counts the pending slot and the retained history, not
    /// just the complete slot — the §3.4 recovery shape a restored backup meets.
    #[test]
    fn the_next_own_seq_clears_the_pending_slot_and_the_history() {
        let (_d, store, key, origin) = setup();
        store.set_self_origin(&origin).unwrap();
        assert_eq!(store.next_own_seq(&origin).unwrap(), 1);

        // A peer relays one of our own heads back, at a seq the complete slot
        // knows nothing about.
        let relayed = SignedHead::sign(&key, origin.clone(), 9, Hash([9u8; 32]), 0);
        assert_eq!(
            Syncer::new(store.clone()).offer_head(&relayed, 0).unwrap(),
            HeadOutcome::Pending
        );
        assert_eq!(store.complete_head(&origin).unwrap(), None);
        assert_eq!(store.next_own_seq(&origin).unwrap(), 10);

        // Even once the pending slot is cleared, the retained history still does.
        store
            .clear_head_at(&origin, Slot::Pending, 9, &Hash([9u8; 32]))
            .unwrap();
        assert_eq!(store.next_own_seq(&origin).unwrap(), 10);
    }
}
