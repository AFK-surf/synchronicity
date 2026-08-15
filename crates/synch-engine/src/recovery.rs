//! Key-loss recovery (§3.4).
//!
//! When the operator replaces an origin's TXT record with a fresh key, the
//! cluster sees an ordinary rotation without the overlap window. The node on
//! the other end of it does not: it comes up with the same `id=` name, an empty
//! database, and no way to know whether the peers it can reach hold that
//! origin's latest history. So recovery is a distinct, explicitly driven state
//! rather than something a node does on startup:
//!
//! 1. **Detection** — a node that holds no head of its own but finds peers
//!    advertising heads for its own origin is *in recovery*, and refuses to
//!    publish. A node that silently started over at `seq = 1` would have every
//!    peer correctly reject it, and the reason would be invisible.
//! 2. **Observation** — those heads are signed by the lost key and can never be
//!    accepted (§4.4), but their existence arrives for free in every peer's
//!    `Hello` summary (§5.1). No new wire message, and no unbound signature is
//!    ever trusted.
//! 3. **Resumption** — [`Node::recover`] collects those summaries from every
//!    reachable peer for at least `recovery_quiesce`, then sets the publishing
//!    floor to `max_observed_seq + seq_gap`. The gap makes a same-seq collision
//!    with history held only by an unreachable peer improbable rather than
//!    merely unlikely.
//!
//! Recovery is operator-driven for the same reason rotation is: the node cannot
//! see the peers it cannot reach, so "how far had I got?" is a judgement made on
//! partial information. An operator knows whether the NAS holding the newest
//! history is merely asleep or genuinely gone; the node does not.

use std::{
    collections::BTreeSet,
    fmt,
    time::{Duration, Instant},
};

use synch_core::{now_ns, Hash, NodeId, OriginId};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    error::{EngineError, Result},
    node::Node,
};

/// How long `synch recover` collects peer summaries by default (§3.4).
pub const DEFAULT_RECOVERY_QUIESCE: Duration = Duration::from_secs(3600);

/// How far above the highest observed seq publishing resumes, by default
/// (§3.4).
pub const DEFAULT_SEQ_GAP: u64 = 1_000;

/// Where this node stands with respect to key-loss recovery (§3.4 step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryState {
    /// This node's own origin.
    pub origin: OriginId,
    /// True if this node holds no head of its own while peers advertise heads
    /// for its origin at or above the seq it would publish at.
    pub in_recovery: bool,
    /// The highest seq any peer has advertised for our origin.
    pub observed_seq: Option<u64>,
    /// The root advertised at that seq, for the operator to recognize.
    pub observed_root: Option<Hash>,
    /// Which peer claimed that seq, when it is known (§3.4).
    ///
    /// Detection rests on peers' unauthenticated summaries — deliberately,
    /// since the true heads are signed by the lost key and cannot validate — so
    /// within the §12 trust stance any member could assert a huge seq and hold
    /// a fresh node in recovery. The attribution is what lets an operator judge
    /// the claim rather than merely obey it.
    pub observed_by: Option<NodeId>,
    /// The seq of this node's own complete head, if it holds one.
    pub own_seq: Option<u64>,
    /// The durable publishing floor, once `synch recover` has set one.
    pub floor: Option<u64>,
    /// The seq this node's next publish would carry.
    pub next_seq: u64,
}

/// One entry of pre-recovery history we hold and cannot reconcile (§3.4, §4.4).
///
/// A head verified while its signer was bound stays provable history even after
/// the binding is gone. When such a head sits at or above the origin's current
/// published head, the origin's new history does not supersede it: that is a
/// fork, and it is resolved by the origin's operator, never silently by the
/// protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreconciledHistory {
    /// The origin the history belongs to.
    pub origin: OriginId,
    /// The seq of the retained head.
    pub seq: u64,
    /// Its root.
    pub root: Hash,
    /// The key that signed it, which is no longer bound to the origin.
    pub signed_by: NodeId,
    /// The seq of the origin's current complete head, if we hold one.
    pub current_seq: Option<u64>,
}

/// How `synch recover` runs (§3.4 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOptions {
    /// How long to keep collecting summaries before setting the floor.
    pub wait: Duration,
    /// How far above the highest observed seq the floor is set.
    pub gap: u64,
    /// How long to wait between collection rounds.
    pub poll: Duration,
}

/// What one collection round saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObserveRound {
    /// Peers that answered a `Hello` exchange.
    pub reached: Vec<NodeId>,
    /// Peers that could not be reached, or failed mid-exchange.
    pub unreachable: Vec<NodeId>,
    /// The highest seq observed for our own origin after this round.
    pub observed_seq: Option<u64>,
}

/// A progress report streamed while the quiesce runs.
///
/// A one-hour wait must not look like a hung command, so every round reports
/// what it reached and how much of the wait is left (§9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProgress {
    /// Which collection round this is, from 1.
    pub round: usize,
    /// How long the quiesce has been running.
    pub elapsed: Duration,
    /// How much of it is left.
    pub remaining: Duration,
    /// How many peers answered this round.
    pub reached: usize,
    /// How many did not.
    pub unreachable: usize,
    /// The highest seq observed for our origin so far.
    pub observed_seq: Option<u64>,
}

impl fmt::Display for RecoveryProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "round {}: {} peer(s) answered, {} unreachable · highest seq seen {} · {}s elapsed, {}s left",
            self.round,
            self.reached,
            self.unreachable,
            match self.observed_seq {
                Some(seq) => seq.to_string(),
                None => "none".to_string(),
            },
            self.elapsed.as_secs(),
            self.remaining.as_secs(),
        )
    }
}

/// What `synch recover` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// The origin recovered.
    pub origin: OriginId,
    /// The highest seq any reachable peer advertised for it.
    pub observed_seq: Option<u64>,
    /// The publishing floor now in force, if one was set.
    pub floor: Option<u64>,
    /// The gap applied above the highest observed seq.
    pub gap: u64,
    /// How many collection rounds ran.
    pub rounds: usize,
    /// How many distinct peers answered at least once.
    pub reached: usize,
    /// How many were never reached.
    pub unreachable: usize,
    /// How long the quiesce actually took.
    pub waited: Duration,
}

impl Node {
    /// The recovery settings this node was opened with.
    pub fn recovery_options(&self) -> RecoveryOptions {
        RecoveryOptions {
            wait: self.config().recovery_quiesce,
            gap: self.config().seq_gap,
            poll: self.config().aae_interval,
        }
    }

    /// The highest seq any peer has advertised for this node's own origin.
    pub fn observed_seq(&self) -> Result<Option<u64>> {
        Ok(self
            .store()
            .observed_head(self.origin())?
            .map(|observed| observed.seq))
    }

    /// Whether this node is in key-loss recovery, and what it has seen (§3.4).
    pub fn recovery_state(&self) -> Result<RecoveryState> {
        let own_seq = self.store().complete_head(self.origin())?.map(|h| h.seq);
        let observed = self.store().observed_head(self.origin())?;
        let next_seq = self.next_seq()?;
        // Holding a head of our own settles the question: whatever peers say,
        // we have published under this origin ourselves. Otherwise a peer
        // advertising a head at or above what we would publish at means our
        // next publish would be correctly rejected — which is the state the
        // operator has to resolve.
        let in_recovery = own_seq.is_none() && observed.as_ref().is_some_and(|o| o.seq >= next_seq);
        Ok(RecoveryState {
            origin: self.origin().clone(),
            in_recovery,
            observed_seq: observed.as_ref().map(|o| o.seq),
            observed_root: observed.as_ref().map(|o| o.root),
            observed_by: observed.as_ref().and_then(|o| o.claimed_by),
            own_seq,
            floor: self.store().publish_floor()?,
            next_seq,
        })
    }

    /// Refuses the publish if this node is in recovery (§3.4 step 1).
    ///
    /// Publishing from a wiped database would mint heads every peer rejects,
    /// with nothing on either side saying why. The error names the command that
    /// resolves it.
    ///
    /// Public so that callers which do irreversible work *before* publishing —
    /// hashing a tree, dropping a space — can refuse before doing it rather
    /// than after.
    pub fn ensure_publishable(&self) -> Result<()> {
        let state = self.recovery_state()?;
        if state.in_recovery {
            return Err(EngineError::InRecovery {
                origin: state.origin,
                observed_seq: state.observed_seq.unwrap_or_default(),
                would_publish: state.next_seq,
            });
        }
        Ok(())
    }

    /// Runs one collection round: a `Hello` exchange with every dialable peer,
    /// adopting nothing (§3.4 step 2).
    pub async fn observe_peers(&self) -> Result<ObserveRound> {
        let mut round = ObserveRound::default();
        for peer in self.dialable_peers()? {
            let addr = self
                .peer_addr(&peer)?
                .unwrap_or_else(|| iroh::EndpointAddr::new(peer));
            match self.net().connect_mpt(addr).await {
                Ok(client) => match self.syncer().observe_with(&client).await {
                    Ok(_summaries) => {
                        self.store().record_peer_seen(&peer, None, now_ns())?;
                        round.reached.push(peer);
                    }
                    Err(e) => {
                        tracing::debug!(peer = %peer.fmt_short(), error = %e, "head exchange failed");
                        round.unreachable.push(peer);
                    }
                },
                Err(e) => {
                    tracing::debug!(peer = %peer.fmt_short(), error = %e, "peer unreachable");
                    round.unreachable.push(peer);
                }
            }
        }
        round.observed_seq = self.observed_seq()?;
        Ok(round)
    }

    /// Collects peer summaries for the quiesce, then lifts the publishing floor
    /// above everything seen (§3.4 step 3).
    ///
    /// Progress is streamed on `progress` as each round completes, so an hour's
    /// wait is visible rather than silent. Dropping the receiving end — a CLI
    /// client that walked away — interrupts the quiesce and leaves the floor
    /// untouched: recovery is one deliberate act, not a half-applied one.
    pub async fn recover(
        &self,
        options: RecoveryOptions,
        progress: UnboundedSender<RecoveryProgress>,
    ) -> Result<RecoveryReport> {
        if options.gap == 0 {
            return Err(EngineError::invalid(
                "a recovery gap of 0 would set the floor to a seq peers have already seen: \
                 the gap is what makes a collision with history held only by an unreachable \
                 peer improbable (§3.4)",
            ));
        }
        let started = Instant::now();
        let deadline = started + options.wait;
        let mut rounds = 0usize;
        let mut reached: BTreeSet<NodeId> = BTreeSet::new();
        let mut unreachable: BTreeSet<NodeId> = BTreeSet::new();

        loop {
            let round = self.observe_peers().await?;
            rounds += 1;
            for peer in &round.reached {
                reached.insert(*peer);
                unreachable.remove(peer);
            }
            for peer in &round.unreachable {
                if !reached.contains(peer) {
                    unreachable.insert(*peer);
                }
            }

            let now = Instant::now();
            let update = RecoveryProgress {
                round: rounds,
                elapsed: now.saturating_duration_since(started),
                remaining: deadline.saturating_duration_since(now),
                reached: round.reached.len(),
                unreachable: round.unreachable.len(),
                observed_seq: round.observed_seq,
            };
            if progress.send(update).is_err() {
                return Err(EngineError::invalid(
                    "recovery was interrupted before the quiesce elapsed; \
                     the publishing floor is unchanged",
                ));
            }
            if now >= deadline {
                break;
            }
            // One sleep per round, bounded by what is left of the quiesce: the
            // wait costs a timer, never a spin.
            tokio::time::sleep(options.poll.min(deadline - now)).await;
        }

        let observed = self.store().observed_head(self.origin())?;
        let mut report = RecoveryReport {
            origin: self.origin().clone(),
            observed_seq: observed.as_ref().map(|o| o.seq),
            floor: self.store().publish_floor()?,
            gap: options.gap,
            rounds,
            reached: reached.len(),
            unreachable: unreachable.len(),
            waited: started.elapsed(),
        };
        let Some(observed) = observed else {
            // Nothing to resume from: no peer claims this origin ever
            // published. A genuinely fresh node is exactly this case, and it
            // must keep starting at seq 1.
            return Ok(report);
        };

        // A node holding its own current head is not resuming from loss, and
        // peers echoing our published history back is not history to leap
        // over: re-running recover after a successful recovery used to burn
        // another gap's worth of seqs every time. Only an observation beyond
        // our own head says some peer holds history we lost.
        if let Some(own) = self.store().complete_head(self.origin())? {
            if own.seq >= observed.seq {
                tracing::info!(
                    origin = %self.origin(),
                    own = own.seq,
                    observed = observed.seq,
                    "peers advertise nothing beyond our own head; the floor stays put"
                );
                return Ok(report);
            }
        }

        // Never below what this node would publish anyway, and never below a
        // floor already in force.
        let floor = observed
            .seq
            .saturating_add(options.gap)
            .max(self.next_seq()?);
        let floor = self.store().raise_publish_floor(floor)?;
        report.floor = Some(floor);
        tracing::info!(
            origin = %self.origin(),
            observed = observed.seq,
            floor,
            "recovery complete: publishing resumes above every seq peers advertised"
        );
        Ok(report)
    }

    /// Pre-recovery history we hold that the current head does not supersede
    /// (§3.4, §4.4).
    ///
    /// A head signed by a key that is no longer bound to its origin, at or
    /// above that origin's current published head, is history the origin's new
    /// key has not spoken for. On a peer that was partitioned through someone
    /// else's recovery, that is the fork evidence — retained *with* its
    /// signature, so it is provable rather than merely asserted.
    pub fn unreconciled_history(&self, origin: &OriginId) -> Result<Vec<UnreconciledHistory>> {
        let now = now_ns();
        let current_seq = self.store().complete_head(origin)?.map(|h| h.seq);
        let mut out = Vec::new();
        for head in self.store().head_history(origin)? {
            if head.seq < current_seq.unwrap_or(0) {
                continue;
            }
            if self.store().is_bound(origin, &head.signed_by, now)? {
                continue;
            }
            out.push(UnreconciledHistory {
                origin: origin.clone(),
                seq: head.seq,
                root: head.root,
                signed_by: head.signed_by,
                current_seq,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use iroh_base::SecretKey;
    use synch_core::SignedHead;
    use synch_store::{Binding, BindingSource, Slot};

    /// One staged file entry, encoded the way the scanner encodes them.
    fn staged_file() -> crate::node::StagedChange {
        let entry = synch_core::FileEntry::file(3, 0, Hash::new(b"payload"), 1);
        (
            synch_core::file_key("s", "a.txt").unwrap(),
            Some(postcard::to_stdvec(&entry).unwrap()),
        )
    }

    async fn node(origin: OriginId) -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), Some(origin)).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        (dir, node)
    }

    fn nas() -> OriginId {
        OriginId::named("nas", "cluster.example").unwrap()
    }

    /// The regression that matters most: a node nobody has ever heard of is not
    /// in recovery, and publishes at seq 1 exactly as before.
    #[tokio::test]
    async fn a_fresh_node_is_not_in_recovery() {
        let (_d, node) = node(nas()).await;
        let state = node.recovery_state().unwrap();
        assert!(!state.in_recovery);
        assert_eq!(state.observed_seq, None);
        assert_eq!(state.next_seq, 1);
        node.ensure_publishable().unwrap();
        node.shutdown().await.unwrap();
    }

    /// A peer advertising a *different* origin says nothing about ours.
    #[tokio::test]
    async fn summaries_for_other_origins_do_not_trigger_recovery() {
        let (_d, node) = node(nas()).await;
        node.store()
            .record_observed_head(
                &OriginId::named("laptop", "cluster.example").unwrap(),
                900,
                &Hash([3u8; 32]),
                true,
                None,
                now_ns(),
            )
            .unwrap();
        assert!(!node.recovery_state().unwrap().in_recovery);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_observation_for_our_own_origin_blocks_publishing() {
        let (_d, node) = node(nas()).await;
        node.store()
            .record_observed_head(node.origin(), 100, &Hash([1u8; 32]), true, None, now_ns())
            .unwrap();

        let state = node.recovery_state().unwrap();
        assert!(state.in_recovery);
        assert_eq!(state.observed_seq, Some(100));
        assert_eq!(state.own_seq, None);

        let err = node.publish(&[staged_file()]).unwrap_err();
        assert!(matches!(err, EngineError::InRecovery { .. }));
        assert!(err.to_string().contains("synch recover"), "{err}");
        node.shutdown().await.unwrap();
    }

    /// A node that already holds a head of its own is not in recovery, whatever
    /// peers advertise: it has published under this origin itself (§3.4).
    #[tokio::test]
    async fn holding_our_own_head_settles_the_question() {
        let (_d, node) = node(nas()).await;
        node.publish(&[staged_file()]).unwrap().unwrap();
        node.store()
            .record_observed_head(node.origin(), 100, &Hash([1u8; 32]), true, None, now_ns())
            .unwrap();
        assert!(!node.recovery_state().unwrap().in_recovery);
        node.ensure_publishable().unwrap();
        node.shutdown().await.unwrap();
    }

    /// `--wait 0` collects one round and returns; the floor lands above
    /// everything seen, and a second observation below it changes nothing.
    #[tokio::test]
    async fn recover_sets_the_floor_above_every_observation() {
        let (_d, node) = node(nas()).await;
        node.store()
            .record_observed_head(node.origin(), 100, &Hash([1u8; 32]), true, None, now_ns())
            .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let report = node
            .recover(
                RecoveryOptions {
                    wait: Duration::ZERO,
                    gap: 1_000,
                    poll: Duration::from_secs(30),
                },
                tx,
            )
            .await
            .unwrap();
        assert_eq!(report.rounds, 1);
        assert_eq!(report.observed_seq, Some(100));
        assert_eq!(report.floor, Some(1_100));
        assert_eq!(rx.try_recv().unwrap().round, 1);

        assert_eq!(node.next_seq().unwrap(), 1_100);
        assert!(!node.recovery_state().unwrap().in_recovery);
        node.ensure_publishable().unwrap();

        // An observation below the floor is not a return to recovery: the floor
        // already clears it.
        node.store()
            .record_observed_head(node.origin(), 200, &Hash([2u8; 32]), true, None, now_ns())
            .unwrap();
        assert!(!node.recovery_state().unwrap().in_recovery);

        // One above it is: publishing at the floor would now collide.
        node.store()
            .record_observed_head(node.origin(), 5_000, &Hash([3u8; 32]), true, None, now_ns())
            .unwrap();
        assert!(node.recovery_state().unwrap().in_recovery);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn recover_on_a_node_no_peer_knows_leaves_seq_1_alone() {
        let (_d, node) = node(nas()).await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let report = node
            .recover(
                RecoveryOptions {
                    wait: Duration::ZERO,
                    gap: 1_000,
                    poll: Duration::from_secs(30),
                },
                tx,
            )
            .await
            .unwrap();
        assert_eq!(report.observed_seq, None);
        assert_eq!(report.floor, None);
        assert_eq!(node.next_seq().unwrap(), 1);
        node.shutdown().await.unwrap();
    }

    /// Re-running recover on a node that holds its own head leaves the floor
    /// alone: peers echoing our published history back is not history to leap
    /// over, and each accidental re-run used to burn another gap of seqs.
    #[tokio::test]
    async fn recover_is_idempotent_once_the_node_holds_its_own_head() {
        let (_d, node) = node(nas()).await;
        node.publish(&[staged_file()]).unwrap().unwrap();
        let own = node.store().complete_head(node.origin()).unwrap().unwrap();
        node.store()
            .record_observed_head(node.origin(), own.seq, &own.root, true, None, now_ns())
            .unwrap();

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let report = node
            .recover(
                RecoveryOptions {
                    wait: Duration::ZERO,
                    gap: 1_000,
                    poll: Duration::from_secs(30),
                },
                tx,
            )
            .await
            .unwrap();
        assert_eq!(report.floor, None, "{report:?}");
        assert_eq!(node.next_seq().unwrap(), own.seq + 1);

        // A peer holding genuinely newer history than our own head still
        // raises the floor: only the echo is ignored, not real evidence.
        node.store()
            .record_observed_head(
                node.origin(),
                own.seq + 50,
                &Hash([9u8; 32]),
                true,
                None,
                now_ns(),
            )
            .unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let report = node
            .recover(
                RecoveryOptions {
                    wait: Duration::ZERO,
                    gap: 1_000,
                    poll: Duration::from_secs(30),
                },
                tx,
            )
            .await
            .unwrap();
        assert_eq!(report.floor, Some(own.seq + 50 + 1_000));
        node.shutdown().await.unwrap();
    }

    /// The gap is not an optimization to remove: a floor at the highest seq
    /// peers advertised is exactly the collision it exists to prevent.
    #[tokio::test]
    async fn a_zero_gap_is_refused() {
        let (_d, node) = node(nas()).await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let err = node
            .recover(
                RecoveryOptions {
                    wait: Duration::ZERO,
                    gap: 0,
                    poll: Duration::from_secs(30),
                },
                tx,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("gap"), "{err}");
        node.shutdown().await.unwrap();
    }

    /// A client that walks away interrupts the quiesce, and nothing is written.
    #[tokio::test]
    async fn a_dropped_progress_receiver_interrupts_the_quiesce() {
        let (_d, node) = node(nas()).await;
        node.store()
            .record_observed_head(node.origin(), 100, &Hash([1u8; 32]), true, None, now_ns())
            .unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        drop(rx);
        let err = node
            .recover(
                RecoveryOptions {
                    wait: Duration::from_secs(3_600),
                    gap: 1_000,
                    poll: Duration::from_millis(10),
                },
                tx,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("interrupted"), "{err}");
        assert_eq!(node.store().publish_floor().unwrap(), None);
        assert!(node.recovery_state().unwrap().in_recovery);
        node.shutdown().await.unwrap();
    }

    /// The quiesce sleeps between rounds rather than spinning: a short wait
    /// takes about as long as it says and costs a handful of rounds.
    #[tokio::test]
    async fn the_quiesce_waits_without_spinning() {
        let (_d, node) = node(nas()).await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let started = Instant::now();
        let report = node
            .recover(
                RecoveryOptions {
                    wait: Duration::from_millis(300),
                    gap: 1_000,
                    poll: Duration::from_millis(100),
                },
                tx,
            )
            .await
            .unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(280), "{elapsed:?}");
        // A round costs a timer, not a spin: polling every 100 ms for 300 ms is
        // a handful of rounds. Busy-waiting would be thousands, and the upper
        // bound is loose enough for the slowest runner in the matrix.
        assert!((1..=8).contains(&report.rounds), "{report:?}");
        let mut updates = Vec::new();
        while let Ok(update) = rx.try_recv() {
            updates.push(update);
        }
        assert_eq!(updates.len(), report.rounds);
        assert_eq!(updates.last().unwrap().remaining, Duration::ZERO);
        node.shutdown().await.unwrap();
    }

    /// §4.4: a head verified while its signer was bound stays provable history.
    /// Above the origin's current head, with the signer no longer bound, it is
    /// unreconciled pre-recovery history.
    #[tokio::test]
    async fn history_above_the_current_head_by_an_unbound_key_is_unreconciled() {
        let (_d, node) = node(OriginId::named("laptop", "cluster.example").unwrap()).await;
        let lost = SecretKey::generate();
        let peer_origin = nas();
        node.store()
            .put_binding(&Binding {
                origin: peer_origin.clone(),
                node_id: lost.public(),
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();

        let old = SignedHead::sign(&lost, peer_origin.clone(), 99, Hash([9u8; 32]), 0);
        let head = SignedHead::sign(&lost, peer_origin.clone(), 100, Hash([1u8; 32]), 0);
        node.syncer().offer_head(&old, now_ns()).unwrap();
        node.syncer().offer_head(&head, now_ns()).unwrap();
        node.store()
            .put_head(Slot::Complete, &head, now_ns(), now_ns())
            .unwrap();

        // While the key is still bound, nothing is unreconciled.
        assert!(node.unreconciled_history(&peer_origin).unwrap().is_empty());

        // The operator rebinds the origin to a fresh key: the lost one no
        // longer speaks for it.
        let recovered = SecretKey::generate().public();
        node.store()
            .remove_binding(&peer_origin, &lost.public(), BindingSource::Static)
            .unwrap();
        node.trust_rebind(&peer_origin, recovered).unwrap();

        let unreconciled = node.unreconciled_history(&peer_origin).unwrap();
        assert_eq!(unreconciled.len(), 1, "{unreconciled:?}");
        assert_eq!(unreconciled[0].seq, 100);
        assert_eq!(unreconciled[0].signed_by, lost.public());
        assert_eq!(unreconciled[0].current_seq, Some(100));

        // Once the recovered origin publishes above it, the fork is behind the
        // current head and no longer unreconciled.
        let head = SignedHead::sign(&lost, peer_origin.clone(), 1_100, Hash([2u8; 32]), 0);
        node.store()
            .put_head(Slot::Complete, &head, now_ns(), now_ns())
            .unwrap();
        assert!(node.unreconciled_history(&peer_origin).unwrap().is_empty());
        node.shutdown().await.unwrap();
    }

    #[test]
    fn progress_reads_as_a_status_line() {
        let update = RecoveryProgress {
            round: 3,
            elapsed: Duration::from_secs(90),
            remaining: Duration::from_secs(3_510),
            reached: 2,
            unreachable: 1,
            observed_seq: Some(100),
        };
        let text = update.to_string();
        assert!(text.contains("round 3"), "{text}");
        assert!(text.contains("2 peer(s) answered"), "{text}");
        assert!(text.contains("highest seq seen 100"), "{text}");
        assert!(text.contains("3510s left"), "{text}");

        let none = RecoveryProgress {
            observed_seq: None,
            ..update
        };
        assert!(none.to_string().contains("highest seq seen none"));
    }

    #[tokio::test]
    async fn recovery_state_names_the_peer_that_claimed_the_seq() {
        // §3.4: the claim is a peer's unverified summary, so the operator's
        // judgement depends on knowing whose it is.
        let (_d, node) = node(nas()).await;
        let claimant = iroh_base::SecretKey::generate().public();
        node.store()
            .record_observed_head(
                node.origin(),
                900,
                &Hash([4u8; 32]),
                true,
                Some(&claimant),
                now_ns(),
            )
            .unwrap();

        let state = node.recovery_state().unwrap();
        assert!(state.in_recovery);
        assert_eq!(state.observed_seq, Some(900));
        assert_eq!(state.observed_by, Some(claimant));

        // And the doctor report carries it through.
        assert_eq!(node.doctor().unwrap().recovery.observed_by, Some(claimant));
        node.shutdown().await.unwrap();
    }
}
