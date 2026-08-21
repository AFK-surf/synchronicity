//! Holding a whole copy of a space (`docs/REPLICATION.md`).
//!
//! A replicated space is one this node holds *every* version of — every
//! origin's version of every path, not the one a policy would select — fetched
//! as it appears and pinned for as long as its policy says. It materializes
//! nothing onto the filesystem and publishes nothing; the checkout half of a
//! space is independent of this one and either may be absent.
//!
//! Three tasks, deliberately separate:
//!
//! - the **sweep** ([`Node::sweep_replicas`]) reconciles what the tree
//!   references against what this node holds and wants, and is the only place
//!   that decides anything from a *listing*;
//! - the **fetch loop** ([`Node::fetch_replica_wants`]) is the only one that
//!   touches the network, and so the only one that needs rate limiting;
//! - the **live path** (`Store::apply_change`, via
//!   [`Node::note_replicated_change`]) reacts to one promotion at a time and is
//!   the only one that ever has positive evidence that a root left the tree.
//!
//! The asymmetry between the last two is the load-bearing rule of the whole
//! design, and §3.6 is where it is argued: **a release is driven by an observed
//! change; absence of a reference is not evidence that a reference was
//! removed.** `entries` empties routinely without anything being deleted —
//! `set_read_scope` discards every foreign origin's rows by design,
//! `rematerialize` empties one origin transiently, a lapsed binding empties
//! another — and a sweep that scheduled releases from any of those would let go
//! of a store that nothing is wrong with.

use std::time::Duration;

use synch_core::{now_ns, Hash};
use synch_store::{PinHolder, ReplicaCoverage, ReplicaPolicy, SpaceRow};

use crate::{
    error::{EngineError, Result},
    node::Node,
};

/// How many failed attempts turn a want from a backlog into an alarm.
///
/// Five, at the backoff below, is roughly a day of trying. A want that has
/// failed that many times is not slow: its last provider left before this node
/// reached it, and the version is most likely already gone from the cluster.
pub const UNREACHABLE_ATTEMPTS: i64 = 5;

/// The shortest wait before a failed want is tried again.
const MIN_BACKOFF: Duration = Duration::from_secs(60);

/// The longest, reached after a handful of failures.
const MAX_BACKOFF: Duration = Duration::from_secs(6 * 3600);

/// What one sweep did to one space.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Objects newly wanted.
    pub wanted: usize,
    /// Scheduled releases called off because the tree names the root again.
    pub reprieved: usize,
    /// Claims scheduled to end, because nothing names the root any more.
    pub scheduled: usize,
    /// Claims that reached their scheduled release and were dropped.
    pub released: usize,
}

/// What one pass of the fetch loop did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchReport {
    /// Objects fetched and taken possession of.
    pub held: usize,
    /// Objects attempted and not held.
    pub failed: usize,
    /// Bytes that crossed the network.
    pub fetched_bytes: u64,
    /// Bytes a local donor supplied instead (`docs/DELTA-SYNC.md` §3.3).
    pub reused_bytes: u64,
    /// Objects not attempted because a space is at its budget.
    pub over_budget: usize,
}

/// Whether this node's view of the tree is complete enough to release from
/// (§3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewState {
    /// Every bound origin has a complete head materialized.
    Complete,
    /// It does not, and this is why. Releases are paused; fetching continues.
    Incomplete(String),
}

impl ViewState {
    /// True if releases may run.
    pub fn is_complete(&self) -> bool {
        matches!(self, ViewState::Complete)
    }

    /// The reason, for `space ls` and `doctor`.
    pub fn reason(&self) -> Option<&str> {
        match self {
            ViewState::Complete => None,
            ViewState::Incomplete(why) => Some(why),
        }
    }
}

/// Everything `space ls <id>` reports about one replicated space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaStatus {
    /// The space.
    pub space: SpaceRow,
    /// What it holds and wants.
    pub coverage: ReplicaCoverage,
    /// When the oldest outstanding want was first wanted.
    pub oldest_want: Option<i64>,
    /// When the soonest scheduled release falls due.
    pub next_release: Option<i64>,
    /// Whether releases are running.
    pub view: ViewState,
}

impl Node {
    /// Turns replication on, off, or over to another policy for a space.
    ///
    /// `release` drops what the space was holding. It is not the default and
    /// should not become one: `--no-replicate` on a space of consequence is
    /// undone by typing it again, while `--no-replicate --release` is undone by
    /// re-fetching every byte from whoever still has them, if anyone does.
    pub fn set_space_replication(
        &self,
        id: &str,
        policy: Option<ReplicaPolicy>,
        grace: Option<i64>,
        budget: Option<u64>,
        release: bool,
    ) -> Result<()> {
        let Some(space) = self.store().space(id)? else {
            return Err(EngineError::not_found(format!("no space {id}")));
        };
        // A delegate holds what it may read and no more. The scope decides what
        // its `entries` ever contained, so replicating outside it would be a
        // standing want for content this node can never learn the size of.
        if policy.is_some() {
            if let Some(scope) = self.store().local_scope()? {
                if !scope.iter().any(|granted| granted == id) {
                    return Err(EngineError::invalid(format!(
                        "this node's read scope does not cover {id}, so it cannot replicate it"
                    )));
                }
            }
        }
        self.store()
            .set_space_replication(id, policy, grace, budget)?;
        if policy.is_none() {
            let holder = space.holder();
            self.store().drop_wants(&holder)?;
            if release {
                self.store().unpin_all(&holder)?;
            }
        }
        self.replica_wake().notify_one();
        Ok(())
    }

    /// Reconciles every replicated space — or one — against the unified tree.
    ///
    /// Staging is safe from a listing: the worst a spurious want costs is a
    /// fetch of something already held, which the fetch loop resolves in one
    /// local lookup. Releasing is not, so it happens here only behind
    /// [`Node::view_state`], and the live path (§3.4) is what schedules
    /// releases in the ordinary case.
    pub fn sweep_replicas(&self, only: Option<&str>) -> Result<Vec<(String, SweepReport)>> {
        let now = self.store().read_instant()?;
        let view = self.view_state()?;
        let mut out = Vec::new();
        for space in self.store().replicated_spaces()? {
            if only.is_some_and(|id| id != space.id) {
                continue;
            }
            let holder = space.holder();
            // Reprieve before scheduling, so a root that left one path and
            // arrived at another inside one interval is never briefly marked
            // for release on the strength of the half of that the sweep saw.
            let reprieved = self.store().clear_returned_releases(&holder)?;
            let wanted = self.store().stage_space_wants(&space.id, &holder, now)?;
            let scheduled =
                if space.replicate.is_some_and(ReplicaPolicy::releases) && view.is_complete() {
                    let at = now.saturating_add(space.grace_secs().saturating_mul(1_000_000_000));
                    self.store().schedule_stale_releases(&holder, at)?
                } else {
                    0
                };
            // Expiry runs even when the view is incomplete. These releases were
            // decided when it was complete — by the live path, or by an earlier
            // sweep — and holding them back would mean one unreachable peer
            // froze every space's grace window indefinitely.
            let released = self.store().expire_pins_of(&holder, now)?;
            out.push((
                space.id.clone(),
                SweepReport {
                    wanted,
                    reprieved,
                    scheduled,
                    released,
                },
            ));
        }
        Ok(out)
    }

    /// Whether releases may run (§3.6).
    ///
    /// Three preconditions, all locally checkable, all cheap. The question they
    /// answer is not "is this node healthy" but the narrower "is `entries` a
    /// faithful picture of what the cluster currently publishes" — because that
    /// is the only thing a release is entitled to be decided from.
    pub fn view_state(&self) -> Result<ViewState> {
        // A pending head is a head whose trie this node does not hold, so the
        // origin's entries are either absent or stale for as long as it sits
        // there. Its content is not garbage; this node's knowledge of it is
        // incomplete, which is exactly the case absence cannot distinguish.
        let pending = self.store().all_heads(synch_store::heads::Slot::Pending)?;
        if let Some(head) = pending.first() {
            return Ok(ViewState::Incomplete(format!(
                "{} has a head this node cannot materialize yet",
                head.head.origin
            )));
        }
        // A bound origin with no complete head has never been synced here, or
        // was reset. Either way its entries are missing rather than deleted.
        for binding in self.store().bindings()? {
            if binding.origin == *self.origin() {
                continue;
            }
            if self.store().complete_head(&binding.origin)?.is_none() {
                return Ok(ViewState::Incomplete(format!(
                    "{} is bound but has published nothing this node holds",
                    binding.origin
                )));
            }
        }
        Ok(ViewState::Complete)
    }

    /// Fetches what the replicated spaces want, rarest first.
    ///
    /// One pass takes at most `replica_concurrency` objects. Everything about
    /// the fetch itself is the ordinary §6.4 path — provider fanout, delta
    /// descent against the recorded donor, resumption — so a replica gets the
    /// best case of the descent for free: it is fetching version *n+1* of a
    /// file whose version *n* it is guaranteed to hold.
    pub async fn fetch_replica_wants(&self) -> Result<FetchReport> {
        let mut report = FetchReport::default();
        let limit = self.config().replica_concurrency.max(1);
        let wants = {
            let store = self.store().clone();
            crate::blocking::offload(move || {
                let now = store.read_instant()?;
                Ok(store.wants_to_attempt(
                    now,
                    MIN_BACKOFF.as_nanos() as i64,
                    MAX_BACKOFF.as_nanos() as i64,
                    limit,
                )?)
            })
            .await?
        };
        for want in wants {
            let Some(space) = want.holder.space().map(str::to_string) else {
                // A want whose holder is not a replica's belongs to nothing
                // this loop drives. Left alone rather than deleted: it is
                // another version's row, and §3.1 keeps those.
                continue;
            };
            let configured = {
                let store = self.store().clone();
                let space = space.clone();
                crate::blocking::offload(move || Ok(store.space(&space)?)).await?
            };
            let Some(configured) = configured.filter(|row| row.replicate.is_some()) else {
                // The space stopped being replicated between the sweep and now.
                let store = self.store().clone();
                let (root, holder) = (want.root, want.holder.clone());
                crate::blocking::offload(move || Ok(store.drop_want(&root, &holder)?)).await?;
                continue;
            };
            if self.over_budget(&configured, want.size).await? {
                report.over_budget += 1;
                continue;
            }
            match self
                .hold_object(&want.root, want.size, want.prev.as_ref(), &want.holder)
                .await
            {
                Ok(fetched) => {
                    report.held += 1;
                    report.fetched_bytes += fetched.0;
                    report.reused_bytes += fetched.1;
                }
                Err(e) => {
                    report.failed += 1;
                    let store = self.store().clone();
                    let (root, holder, reason) = (want.root, want.holder.clone(), e.to_string());
                    let now = now_ns();
                    crate::blocking::offload(move || {
                        Ok(store.record_want_failure(&root, &holder, now, &reason)?)
                    })
                    .await?;
                    tracing::debug!(root = %want.root, space = %space, error = %e, "replica fetch failed");
                }
            }
        }
        Ok(report)
    }

    /// Fetches one object and takes possession of it for a holder.
    ///
    /// Finalize, *then* pin. On a cloud backend a pin is a promise about
    /// durable storage rather than about a scratch cache — `pin_object` already
    /// works this way, and `docs/SERVERLESS.md` §6.3 makes cache-only content
    /// evictable by design — so a claim written before the object is durable is
    /// a promise about bytes the backend is entitled to drop.
    async fn hold_object(
        &self,
        root: &Hash,
        size: u64,
        prev: Option<&Hash>,
        holder: &PinHolder,
    ) -> Result<(u64, u64)> {
        // A donor with no bytes here is a wasted pass over the proof list,
        // which is what `donors_for` filters for on the read path. The check
        // reads the blob row, so it goes over the blocking pool rather than
        // running on the worker polling this future (§10) — the guard aborts
        // the process for it, and a test that has entered a `BlockingScope`
        // will not notice.
        let donors: Vec<synch_store::Donor> = match prev.copied() {
            None => Vec::new(),
            Some(prev) => {
                let node = self.clone();
                crate::blocking::offload(move || {
                    Ok(match node.holds_any_of(&prev)? {
                        true => vec![synch_store::Donor(prev)],
                        false => Vec::new(),
                    })
                })
                .await?
            }
        };
        let fetched = self.fetch_all_from(root, size, &donors).await?;
        if !fetched.complete {
            return Err(EngineError::not_found(format!(
                "no provider could serve the complete object {root}"
            )));
        }
        self.finalize_cloud_object(root, true).await?;
        let store = self.store().clone();
        let (root, holder) = (*root, holder.clone());
        let now = now_ns();
        let held =
            crate::blocking::offload(move || Ok(store.take_possession(&root, &holder, now)?))
                .await?;
        if !held {
            return Err(EngineError::not_found(format!(
                "object {root} left the store before it could be held"
            )));
        }
        Ok((
            bytes_of(&fetched.fetched, size),
            bytes_of(&fetched.promoted, size),
        ))
    }

    /// Whether taking one more object would put a space past its budget.
    ///
    /// Reaching the budget stops fetching and never shortens a release: a
    /// replica that let go of its grace window because a disk filled up would
    /// drop the recovery story exactly when nobody was watching (§3.8).
    async fn over_budget(&self, space: &SpaceRow, incoming: u64) -> Result<bool> {
        let Some(budget) = space.budget else {
            return Ok(false);
        };
        let store = self.store().clone();
        let holder = space.holder();
        let coverage = crate::blocking::offload(move || {
            Ok(store.replica_coverage(&holder, UNREACHABLE_ATTEMPTS)?)
        })
        .await?;
        Ok(coverage.held_bytes.saturating_add(incoming) > budget)
    }

    /// What `space ls <id>` reports.
    pub fn replica_status(&self, id: &str) -> Result<ReplicaStatus> {
        let Some(space) = self.store().space(id)? else {
            return Err(EngineError::not_found(format!("no space {id}")));
        };
        let holder = space.holder();
        Ok(ReplicaStatus {
            coverage: self
                .store()
                .replica_coverage(&holder, UNREACHABLE_ATTEMPTS)?,
            oldest_want: self.store().oldest_want(&holder)?,
            next_release: self.store().next_release(&holder)?,
            view: self.view_state()?,
            space,
        })
    }

    /// Runs the standing replication loop until `shutdown` resolves.
    ///
    /// A sweep runs on every wake — a head flipping complete, a local publish,
    /// a space newly replicated — and once before the first wait, so a node
    /// restarted with a backlog starts working through it rather than waiting
    /// out an interval. The fetch loop runs after each sweep and then keeps
    /// running while it is making progress: one pass takes at most
    /// `replica_concurrency` objects, and a cold replica has millions.
    pub async fn run_replicas(&self, shutdown: impl std::future::Future<Output = ()>) {
        let shutdown = std::pin::pin!(shutdown);
        let mut shutdown = shutdown;
        let wake = self.replica_wake();
        loop {
            self.replica_pass_logged().await;
            tokio::select! {
                _ = &mut shutdown => return,
                _ = wake.notified() => {}
                _ = tokio::time::sleep(crate::aae::jittered(self.config().replica_interval)) => {}
            }
        }
    }

    /// One sweep and as much fetching as it turns up, logged rather than
    /// streamed: the standing loop has no client on the other end.
    async fn replica_pass_logged(&self) {
        let node = self.clone();
        let swept = crate::blocking::offload(move || node.sweep_replicas(None)).await;
        match swept {
            Ok(reports) => {
                for (space, report) in reports {
                    if report != SweepReport::default() {
                        tracing::info!(
                            space = %space,
                            wanted = report.wanted,
                            reprieved = report.reprieved,
                            scheduled = report.scheduled,
                            released = report.released,
                            "replica sweep"
                        );
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "replica sweep failed"),
        }
        // Keep fetching while a pass is doing something. A pass that holds
        // nothing has either drained the queue or hit every backoff, and either
        // way the next wake is soon enough.
        loop {
            match self.fetch_replica_wants().await {
                Ok(report) if report.held > 0 => {
                    tracing::info!(
                        held = report.held,
                        failed = report.failed,
                        fetched_bytes = report.fetched_bytes,
                        reused_bytes = report.reused_bytes,
                        over_budget = report.over_budget,
                        "replica fetch pass"
                    );
                }
                Ok(_) => return,
                Err(e) => {
                    tracing::warn!(error = %e, "replica fetch pass failed");
                    return;
                }
            }
        }
    }
}

/// Bytes a set of chunk groups covers, clamped to the object.
///
/// Counted in bytes rather than groups so the tail group of a 100-byte file
/// does not report 16 KiB.
fn bytes_of(groups: &synch_core::ChunkRanges, size: u64) -> u64 {
    groups
        .ranges
        .iter()
        .map(|r| {
            let end = r.end.saturating_mul(synch_core::CHUNK_GROUP_SIZE).min(size);
            end.saturating_sub(r.start.saturating_mul(synch_core::CHUNK_GROUP_SIZE))
        })
        .sum()
}
