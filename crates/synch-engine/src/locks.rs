//! Best-effort cluster locks without consensus (`docs/LOCKS.md`).
//!
//! A lock is granted by a claim exchange among every peer that may write its
//! space: the claimant takes a ticket above every ticket it has heard of,
//! sends its claim to all of them at once, and holds iff, once every peer has
//! answered or its claim window Δ has run out, its ticket is the least it
//! knows of and no other claim it knows of is held (§3.3). That is exclusive
//! while contenders reach each other within Δ, and an AP lock otherwise: a
//! partition can grant on both sides, and the renewal that next crosses the
//! healed link names one survivor by a rule every node computes alike (§6).
//!
//! The pure rules — the decision, the heal order, the observer's lease — are
//! the free functions at the bottom of this file; [`LockManager`] is the
//! table and the network around them. Observers' state is soft and in memory;
//! only this node's own holds and its Lamport clock are persisted (§9.2).

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

use synch_core::{
    now_ns, Claim, ClaimId, ClaimState, EndReason, LockMessage, LockName, NodeId, OriginId, Report,
    Ticket, Watermark, MAX_LOCK_ENDED, MAX_LOCK_OWNER_BYTES, MAX_LOCK_PAYLOAD_BYTES,
    MAX_LOCK_REPORTS, MAX_LOCK_SUPERSEDES, MAX_LOCK_TTL_MS, MAX_LOCK_WATERMARKS, MIN_LOCK_TTL_MS,
};
use synch_store::{LockHoldRow, PublishScope, Store};
use tokio::sync::watch;

use crate::{
    error::{EngineError, LockFailure, Result},
    node::{Node, WeakNode},
};

/// The lease a claim asks for when the caller names none (§14).
pub const DEFAULT_LOCK_TTL: Duration = Duration::from_secs(30);

/// Clock-rate tolerance ρ (§5): an observer keeps a claim `ttl·(1 + 2ρ)`
/// after receipt, so its expiry never precedes the holder's own.
const RHO: f64 = 1e-3;

/// How long an ended claim is remembered, so a late message never revives
/// it (§4) — twice the longest lease a claim may ask for.
const ENDED_MEMORY: Duration = Duration::from_secs(2 * 3600);

/// How many ended ids one node remembers in all (§14).
const MAX_ENDED_IDS: usize = 65_536;

/// How many live claims one node's table holds in all (§14).
const MAX_TABLE_CLAIMS: usize = 65_536;

/// How many live claims one origin may have in a node's table (§14).
const MAX_CLAIMS_PER_ORIGIN: usize = 1_024;

/// How often the standing loop renews holds and sweeps the table.
const TICK: Duration = Duration::from_millis(250);

/// Who renews a hold (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldMode {
    /// The daemon, while the client's control stream is open; never persisted.
    Session,
    /// The client, by renewing before its deadline.
    Lease,
    /// The daemon, until release or break.
    Sticky,
}

impl HoldMode {
    /// The name `synch lock ls` prints.
    pub fn as_str(self) -> &'static str {
        match self {
            HoldMode::Session => "session",
            HoldMode::Lease => "lease",
            HoldMode::Sticky => "sticky",
        }
    }
}

/// What a caller asks of [`LockManager::acquire`].
#[derive(Debug, Clone)]
pub struct LockRequest {
    /// The lock.
    pub lock: LockName,
    /// The lease observers keep without a renewal.
    pub ttl: Duration,
    /// How long to keep retrying a lock somebody else holds.
    pub wait: Duration,
    /// Display only: who on this node is asking.
    pub owner: String,
    /// Opaque: an S3 lock key's body.
    pub payload: Vec<u8>,
    /// Who renews.
    pub mode: HoldMode,
    /// Report the lock acquired even if the last holder's writes are not here
    /// yet (§8).
    pub allow_behind: bool,
}

/// Why a hold was lost, as a session client is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lost {
    /// The claim ended: released here, or broken by a writer of the space.
    Ended(EndReason),
    /// A split-brain heal kept the claim named (§6).
    Superseded(ClaimId),
}

impl std::fmt::Display for Lost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Lost::Ended(reason) => write!(f, "the claim was {reason}"),
            Lost::Superseded(by) => write!(f, "a split-brain heal kept {}", by.token()),
        }
    }
}

/// A lock this node now holds.
#[derive(Debug, Clone)]
pub struct Acquired {
    /// The lock.
    pub lock: LockName,
    /// The claim, whose token is the fencing token (§7).
    pub id: ClaimId,
    /// How long the client may use it before renewing: the holder's lease
    /// less one claim window (§5).
    pub valid_for: Duration,
    /// Peers that did not answer within the claim window.
    pub waited_on: Vec<NodeId>,
    /// The last holders' heads this node waited to hold (§8).
    pub handoff: Vec<Watermark>,
    /// Becomes `Some` when the hold is lost.
    pub lost: watch::Receiver<Option<Lost>>,
}

/// What this node knows of one claim on a lock.
#[derive(Debug, Clone)]
pub struct LockView {
    /// The lock.
    pub lock: LockName,
    /// The claim.
    pub claim: Claim,
    /// What this node knows of it.
    pub state: ClaimState,
    /// For this node's own claim, how it is renewed.
    pub mode: Option<HoldMode>,
    /// Whether this node's own claim is still waiting for answers.
    pub contending: bool,
    /// How long it stays without a renewal.
    pub remaining: Duration,
}

/// One peer's answer to an inspection.
#[derive(Debug, Clone)]
pub struct PeerView {
    /// The peer's device key.
    pub peer: NodeId,
    /// What it reported, or why it did not answer.
    pub answer: std::result::Result<Vec<Report>, String>,
}

/// A lock as `synch lock status` shows it.
#[derive(Debug, Clone)]
pub struct LockStatus {
    /// The lock.
    pub lock: LockName,
    /// This node's own view of the lock's claims.
    pub views: Vec<LockView>,
    /// The handoff watermarks this node knows for it (§8).
    pub watermarks: Vec<Watermark>,
    /// Each reachable peer's view, when asked for.
    pub peers: Vec<PeerView>,
}

/// The phase of this node's own claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for answers.
    Contending,
    /// Held.
    Held,
    /// Restored after a restart and not yet renewed (§5).
    Unconfirmed,
}

#[derive(Debug)]
struct Own {
    claim: Claim,
    phase: Phase,
    mode: HoldMode,
    /// The holder's lease end: the last claim or renewal sent, plus ttl.
    deadline: Instant,
    /// A lease-mode client's deadline.
    client_deadline: Option<Instant>,
    /// When the last renewal went out; `None` renews at the next tick.
    last_renew: Option<Instant>,
    renewing: bool,
    lost: watch::Sender<Option<Lost>>,
    acquired_at: i64,
}

impl Own {
    fn held(&self) -> bool {
        self.phase != Phase::Contending
    }
}

#[derive(Debug)]
struct Observed {
    claim: Claim,
    held: bool,
    until: Instant,
    expired: bool,
}

impl Observed {
    fn state(&self) -> ClaimState {
        if self.expired {
            ClaimState::Expired
        } else if self.held {
            ClaimState::Held
        } else {
            ClaimState::Live
        }
    }
}

#[derive(Debug, Default)]
struct Entry {
    observed: HashMap<ClaimId, Observed>,
    ended: HashMap<ClaimId, (EndReason, Instant)>,
    watermarks: HashMap<OriginId, (u64, Instant)>,
    own: Option<Own>,
}

impl Entry {
    fn is_empty(&self) -> bool {
        self.observed.is_empty()
            && self.ended.is_empty()
            && self.watermarks.is_empty()
            && self.own.is_none()
    }

    fn end(&mut self, id: &ClaimId, reason: EndReason, now: Instant) {
        self.observed.remove(id);
        self.ended.insert(id.clone(), (reason, now));
    }

    fn watermark(&mut self, mark: &Watermark, now: Instant) {
        let slot = self
            .watermarks
            .entry(mark.origin.clone())
            .or_insert((0, now));
        if mark.seq >= slot.0 {
            *slot = (mark.seq, now);
        }
    }

    /// What this node answers about the lock (§3.3 step 2).
    fn answer(&self, now: Instant) -> LockMessage {
        let mut reports = Vec::new();
        if let Some(own) = &self.own {
            reports.push(Report {
                claim: own.claim.clone(),
                state: if own.held() {
                    ClaimState::Held
                } else {
                    ClaimState::Live
                },
                remaining_ms: millis(own.deadline.saturating_duration_since(now)),
            });
        }
        let mut observed: Vec<&Observed> = self.observed.values().collect();
        observed.sort_by_key(|o| (std::cmp::Reverse(o.state()), o.claim.id.clone()));
        let room = MAX_LOCK_REPORTS.saturating_sub(reports.len());
        reports.extend(observed.into_iter().take(room).map(|o| Report {
            claim: o.claim.clone(),
            state: o.state(),
            remaining_ms: millis(o.until.saturating_duration_since(now)),
        }));
        let mut ended: Vec<(&ClaimId, &(EndReason, Instant))> = self.ended.iter().collect();
        ended.sort_by_key(|(_, (_, at))| std::cmp::Reverse(*at));
        let mut watermarks: Vec<(&OriginId, &(u64, Instant))> = self.watermarks.iter().collect();
        watermarks.sort_by_key(|(_, (_, at))| std::cmp::Reverse(*at));
        LockMessage::Answer {
            reports,
            ended: ended
                .into_iter()
                .take(MAX_LOCK_ENDED)
                .map(|(id, (reason, _))| (id.clone(), *reason))
                .collect(),
            watermarks: watermarks
                .into_iter()
                .take(MAX_LOCK_WATERMARKS)
                .map(|(origin, (seq, _))| Watermark {
                    origin: origin.clone(),
                    seq: *seq,
                })
                .collect(),
        }
    }

    fn views(&self, lock: &LockName, now: Instant) -> Vec<LockView> {
        let mut views = Vec::new();
        if let Some(own) = &self.own {
            views.push(LockView {
                lock: lock.clone(),
                claim: own.claim.clone(),
                state: if own.held() {
                    ClaimState::Held
                } else {
                    ClaimState::Live
                },
                mode: Some(own.mode),
                contending: !own.held(),
                remaining: own
                    .client_deadline
                    .unwrap_or(own.deadline)
                    .saturating_duration_since(now),
            });
        }
        let mut observed: Vec<&Observed> = self.observed.values().collect();
        observed.sort_by_key(|o| o.claim.id.clone());
        views.extend(observed.into_iter().map(|o| LockView {
            lock: lock.clone(),
            claim: o.claim.clone(),
            state: o.state(),
            mode: None,
            contending: false,
            remaining: o.until.saturating_duration_since(now),
        }));
        views
    }
}

fn millis(d: Duration) -> u32 {
    d.as_millis().min(u32::MAX as u128) as u32
}

#[derive(Debug, Default)]
struct Table {
    /// The Lamport clock: at or above every ticket this node has heard of.
    clock: u64,
    /// The highest value written to the store.
    saved: u64,
    locks: HashMap<LockName, Entry>,
}

impl Table {
    fn hear(&mut self, lamport: u64) {
        self.clock = self.clock.max(lamport);
    }

    fn claims(&self) -> usize {
        self.locks.values().map(|e| e.observed.len()).sum()
    }

    fn claims_of(&self, origin: &OriginId) -> usize {
        self.locks
            .values()
            .flat_map(|e| e.observed.keys())
            .filter(|id| &id.ticket.origin == origin)
            .count()
    }
}

/// The cluster-lock table and the exchange around it.
#[derive(Debug)]
pub struct LockManager {
    store: Arc<Store>,
    origin: OriginId,
    claim_window: Duration,
    handoff_window: Duration,
    table: std::sync::Mutex<Table>,
    /// Rung whenever a claim ends or expires, so waiters retry at once.
    changed: tokio::sync::Notify,
    /// Serializes this node's own attempts on one lock.
    attempts: std::sync::Mutex<HashMap<LockName, Arc<tokio::sync::Mutex<()>>>>,
    /// Held for read by a fenced commit and for write by whatever ends this
    /// node's hold, so a hold cannot end under a commit it fenced (§7).
    fences: std::sync::Mutex<HashMap<LockName, Arc<tokio::sync::RwLock<()>>>>,
}

impl LockManager {
    /// A manager for `origin`'s locks.
    pub(crate) fn new(
        store: Arc<Store>,
        origin: OriginId,
        claim_window: Duration,
        handoff_window: Duration,
    ) -> Self {
        LockManager {
            store,
            origin,
            claim_window,
            handoff_window,
            table: Default::default(),
            changed: tokio::sync::Notify::new(),
            attempts: Default::default(),
            fences: Default::default(),
        }
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn attempt_gate(&self, lock: &LockName) -> Arc<tokio::sync::Mutex<()>> {
        self.attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(lock.clone())
            .or_default()
            .clone()
    }

    fn fence_gate(&self, lock: &LockName) -> Arc<tokio::sync::RwLock<()>> {
        self.fences
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(lock.clone())
            .or_default()
            .clone()
    }

    // ---- persistence (§5, §9.2) --------------------------------------------

    /// Restores the clock and this node's persisted holds, as unconfirmed.
    ///
    /// Blocking: reads the store. A lease-mode hold whose client deadline
    /// passed while the daemon was down is dropped rather than renewed — the
    /// one place a wall clock is read, and only to give a lock up.
    pub(crate) fn restore(&self) -> Result<()> {
        let clock = self.store.lock_clock()?;
        let rows = self.store.lock_holds()?;
        let now = Instant::now();
        let wall = now_ns();
        let mut table = self.table();
        table.hear(clock);
        table.saved = table.saved.max(clock);
        for row in rows {
            let origin: Option<OriginId> = row.origin.parse().ok();
            let lapsed = !row.sticky && row.lease_until.is_some_and(|until| until <= wall);
            let lock = LockName::new(row.space.clone(), row.name.clone());
            if origin.as_ref() != Some(&self.origin) || lapsed || lock.is_err() {
                self.store
                    .remove_lock_hold(&row.space, &row.name, row.lamport, row.nonce)?;
                continue;
            }
            let Ok(lock) = lock else { continue };
            table.hear(row.lamport);
            let claim = Claim {
                id: ClaimId {
                    ticket: Ticket {
                        lamport: row.lamport,
                        origin: self.origin.clone(),
                    },
                    nonce: row.nonce,
                },
                ttl_ms: row.ttl_ms,
                owner: row.owner,
                payload: row.payload,
                supersedes: postcard::from_bytes(&row.supersedes).unwrap_or_default(),
            };
            let client_deadline = row
                .lease_until
                .map(|until| now + Duration::from_nanos(until.saturating_sub(wall).max(0) as u64));
            table.locks.entry(lock).or_default().own = Some(Own {
                deadline: now + Duration::from_millis(row.ttl_ms.into()),
                claim,
                phase: Phase::Unconfirmed,
                mode: if row.sticky {
                    HoldMode::Sticky
                } else {
                    HoldMode::Lease
                },
                client_deadline,
                last_renew: None,
                renewing: false,
                lost: watch::channel(None).0,
                acquired_at: row.acquired_at,
            });
        }
        Ok(())
    }

    /// The row a hold persists as, or `None` for a session hold.
    fn hold_row(&self, lock: &LockName, own: &Own) -> Result<Option<LockHoldRow>> {
        if own.mode == HoldMode::Session {
            return Ok(None);
        }
        let wall = now_ns();
        Ok(Some(LockHoldRow {
            space: lock.space.clone(),
            name: lock.name.clone(),
            origin: self.origin.to_string(),
            lamport: own.claim.id.ticket.lamport,
            nonce: own.claim.id.nonce,
            ttl_ms: own.claim.ttl_ms,
            sticky: own.mode == HoldMode::Sticky,
            owner: own.claim.owner.clone(),
            payload: own.claim.payload.clone(),
            supersedes: postcard::to_stdvec(&own.claim.supersedes)
                .map_err(|e| EngineError::Record(e.to_string()))?,
            acquired_at: own.acquired_at,
            lease_until: own.client_deadline.map(|deadline| {
                let left = deadline.saturating_duration_since(Instant::now());
                wall.saturating_add(left.as_nanos().min(i64::MAX as u128) as i64)
            }),
        }))
    }

    async fn persist_hold(&self, row: Option<LockHoldRow>) -> Result<()> {
        if let Some(row) = row {
            let store = self.store.clone();
            crate::blocking::offload(move || Ok(store.put_lock_hold(&row)?)).await?;
        }
        Ok(())
    }

    async fn forget_hold(&self, lock: &LockName, id: &ClaimId) -> Result<()> {
        let store = self.store.clone();
        let (lock, id) = (lock.clone(), id.clone());
        crate::blocking::offload(move || {
            Ok(store.remove_lock_hold(&lock.space, &lock.name, id.ticket.lamport, id.nonce)?)
        })
        .await
    }

    async fn persist_clock(&self) -> Result<()> {
        let pending = {
            let table = self.table();
            (table.clock > table.saved).then_some(table.clock)
        };
        if let Some(clock) = pending {
            let store = self.store.clone();
            crate::blocking::offload(move || Ok(store.raise_lock_clock(clock)?)).await?;
            let mut table = self.table();
            table.saved = table.saved.max(clock);
        }
        Ok(())
    }

    // ---- authorization (§3.1) ----------------------------------------------

    /// The origins `peer` speaks for that may write `space`. Blocking.
    fn writer_origins(&self, peer: &NodeId, space: &str) -> Result<Vec<OriginId>> {
        let now = now_ns();
        let (_, origins) = self.store.publish_scope_of_key_with_origins(peer, now)?;
        let mut writers = Vec::new();
        for origin in origins {
            if may_publish(&self.store.publish_scope(&origin, now)?, space) {
                writers.push(origin);
            }
        }
        Ok(writers)
    }

    /// Whether `peer` may read `space`. Blocking.
    fn may_read(&self, peer: &NodeId, space: &str) -> Result<bool> {
        Ok(may_publish(
            &self.store.publish_scope_of_key(peer, now_ns())?,
            space,
        ))
    }

    /// Refuses a lock in a space this node itself may not write.
    async fn check_own_authority(&self, space: &str) -> Result<()> {
        let store = self.store.clone();
        let space = space.to_string();
        crate::blocking::offload(move || {
            let now = now_ns();
            let refused = match store.own_grant(now)? {
                Some(grant) => {
                    !grant.iter().any(|s| s == &space)
                        || store.own_read_only(now)?.iter().any(|s| s == &space)
                }
                None => false,
            };
            if refused {
                return Err(EngineError::invalid(format!(
                    "this node may not write {space}, so it may not lock in it"
                )));
            }
            Ok(())
        })
        .await
    }

    /// The peers that may contend for a lock in `space`: every dialable key
    /// some writer origin of the space is bound to.
    async fn targets(&self, node: &Node, space: &str) -> Result<Vec<(NodeId, iroh::EndpointAddr)>> {
        let candidates = node.dial_targets().await?;
        let locks = node.locks().clone();
        let space = space.to_string();
        crate::blocking::offload(move || {
            let mut targets = Vec::new();
            for (peer, addr) in candidates {
                if !locks.writer_origins(&peer, &space)?.is_empty() {
                    targets.push((peer, addr));
                }
            }
            Ok(targets)
        })
        .await
    }

    /// Sends `message` to every target at once, each bounded by the claim
    /// window, dial included.
    async fn broadcast(
        &self,
        node: &Node,
        targets: &[(NodeId, iroh::EndpointAddr)],
        message: &LockMessage,
    ) -> Vec<(NodeId, std::result::Result<LockMessage, String>)> {
        let window = self.claim_window;
        let net = node.net();
        let sends = targets.iter().map(|(peer, addr)| {
            let net = net.clone();
            let addr = addr.clone();
            async move {
                let attempt = async {
                    let client = net.connect_lock(addr).await?;
                    client.request(message, window).await
                };
                let answer = match tokio::time::timeout(window, attempt).await {
                    Ok(Ok(answer)) => Ok(answer),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err(format!("no answer within {window:?}")),
                };
                (*peer, answer)
            }
        });
        crate::join::futures_join(sends).await
    }

    // ---- acquiring (§3.3) --------------------------------------------------

    /// Takes a lock, retrying for up to `request.wait` while somebody else
    /// holds it.
    pub async fn acquire(&self, node: &Node, request: LockRequest) -> Result<Acquired> {
        check_request(&request)?;
        self.check_own_authority(&request.lock.space).await?;
        let gate = self.attempt_gate(&request.lock);
        let give_up = Instant::now() + request.wait;
        let mut retries = 0u32;
        loop {
            let changed = self.changed.notified();
            let failure = {
                let _attempt = gate.lock().await;
                match self.held_here(&request.lock) {
                    Some(failure) => failure,
                    None => match self.attempt(node, &request).await? {
                        Ok(acquired) => return Ok(acquired),
                        Err(failure) => failure,
                    },
                }
            };
            if Instant::now() >= give_up {
                return Err(failure);
            }
            retries += 1;
            // A lost simultaneous claim is retried at once, behind a short
            // jitter so two losers do not collide again; a held lock is
            // waited on until its claim ends or a back-off passes.
            let backoff = match &failure {
                EngineError::Lock {
                    failure: LockFailure::Contended,
                    ..
                } => Duration::from_millis(10 + jitter(50 * u64::from(retries.min(10)))),
                _ => {
                    (request.ttl / 6).min(Duration::from_secs(1))
                        + Duration::from_millis(jitter(250))
                }
            };
            tokio::select! {
                _ = changed => {}
                _ = tokio::time::sleep(backoff) => {}
                _ = tokio::time::sleep_until(give_up.into()) => {}
            }
        }
    }

    /// The failure an acquire meets at once when this node already holds or
    /// is claiming the lock.
    fn held_here(&self, lock: &LockName) -> Option<EngineError> {
        let table = self.table();
        let own = table.locks.get(lock)?.own.as_ref()?;
        Some(EngineError::lock(
            LockFailure::Held,
            format!(
                "{lock} is held by this node ({}), token {}",
                display_owner(&own.claim.owner),
                own.claim.id.token()
            ),
        ))
    }

    /// One claim exchange: `Ok(Ok)` holds, `Ok(Err)` is a failure worth
    /// retrying within the caller's wait, `Err` is one that is not.
    async fn attempt(
        &self,
        node: &Node,
        request: &LockRequest,
    ) -> Result<std::result::Result<Acquired, EngineError>> {
        let targets = self.targets(node, &request.lock.space).await?;
        let lock = request.lock.clone();
        let ttl = request.ttl;
        let (claim, lost) = {
            let mut table = self.table();
            let heard = table.locks.get(&lock).map_or(0, |entry| {
                entry
                    .observed
                    .keys()
                    .chain(entry.ended.keys())
                    .map(|id| id.ticket.lamport)
                    .max()
                    .unwrap_or(0)
            });
            let lamport = table.clock.max(heard) + 1;
            table.clock = lamport;
            let claim = Claim {
                id: ClaimId {
                    ticket: Ticket {
                        lamport,
                        origin: self.origin.clone(),
                    },
                    nonce: nonce(),
                },
                ttl_ms: millis(ttl),
                owner: request.owner.clone(),
                payload: request.payload.clone(),
                supersedes: Vec::new(),
            };
            let (lost, receiver) = watch::channel(None);
            let now = Instant::now();
            table.locks.entry(lock.clone()).or_default().own = Some(Own {
                claim: claim.clone(),
                phase: Phase::Contending,
                mode: request.mode,
                deadline: now + ttl,
                client_deadline: (request.mode == HoldMode::Lease).then_some(now + ttl),
                last_renew: Some(now),
                renewing: false,
                lost,
                acquired_at: now_ns(),
            });
            (claim, receiver)
        };
        // Persisted before the claim leaves, so no restart reissues its
        // ticket (§7).
        if let Err(e) = self.persist_clock().await {
            self.table()
                .locks
                .get_mut(&lock)
                .map(|entry| entry.own.take_if(|own| own.claim.id == claim.id));
            return Err(e);
        }
        let sent = Instant::now();
        let answers = self
            .broadcast(
                node,
                &targets,
                &LockMessage::Claim {
                    lock: lock.clone(),
                    claim: claim.clone(),
                },
            )
            .await;

        let mut waited_on = Vec::new();
        let mut gathered = Gathered::default();
        for (peer, answer) in &answers {
            match answer {
                Ok(LockMessage::Answer {
                    reports,
                    ended,
                    watermarks,
                }) => gathered.add(reports, ended, watermarks),
                // A peer that refuses has answered: it is no writer of the
                // space as it sees it, so it cannot contend.
                Ok(LockMessage::Refused { reason }) => {
                    tracing::debug!(peer = %peer.fmt_short(), %reason, %lock, "a lock peer refused a claim");
                }
                Ok(_) => waited_on.push(*peer),
                // Silent past the window: under §2's assumption, not running.
                Err(e) => {
                    tracing::debug!(peer = %peer.fmt_short(), error = %e, %lock, "a lock peer did not answer");
                    waited_on.push(*peer);
                }
            }
        }

        let decided = {
            let mut table = self.table();
            for lamport in gathered.tickets() {
                table.hear(lamport);
            }
            let now = Instant::now();
            let entry = table.locks.entry(lock.clone()).or_default();
            for (id, reason) in &gathered.ended {
                if id != &claim.id {
                    entry.end(id, *reason, now);
                }
            }
            for mark in gathered.watermarks.values() {
                entry.watermark(mark, now);
            }
            let still_ours = entry
                .own
                .as_ref()
                .is_some_and(|own| own.claim.id == claim.id && !own.held());
            if !still_ours || gathered.ended.contains_key(&claim.id) {
                // A writer of the space broke the claim while it waited.
                entry.own.take_if(|own| own.claim.id == claim.id);
                Decided::Yield(EngineError::lock(
                    LockFailure::Contended,
                    format!("{lock}: the claim was broken while it waited for answers"),
                ))
            } else {
                // What this node itself has recorded counts too: a claim that
                // reached it during the wait is one it knows of (§3.3 step 3).
                for observed in entry.observed.values() {
                    gathered.note(&observed.claim, observed.state());
                }
                let ended: BTreeMap<ClaimId, EndReason> = entry
                    .ended
                    .iter()
                    .map(|(id, (reason, _))| (id.clone(), *reason))
                    .collect();
                match decide(&claim.id, &gathered.known, &ended) {
                    Verdict::Hold { supersedes } => {
                        let own = entry.own.as_mut().expect("checked above");
                        own.claim.supersedes = supersedes;
                        own.phase = Phase::Held;
                        own.deadline = sent + ttl;
                        // Renewed at the next tick: the renewal is what marks
                        // the claim held at peers that answered before it held.
                        own.last_renew = None;
                        Decided::Hold(self.hold_row(&lock, own)?)
                    }
                    Verdict::Yield { to, reclaim } => {
                        entry.own = None;
                        entry.end(&claim.id, EndReason::Withdrawn, now);
                        Decided::Withdraw(yield_error(&lock, to, reclaim))
                    }
                }
            }
        };

        match decided {
            Decided::Hold(row) => {
                self.persist_hold(row).await?;
                let handoff: Vec<Watermark> = gathered
                    .watermarks
                    .into_values()
                    .filter(|mark| mark.origin != self.origin)
                    .collect();
                if !request.allow_behind {
                    if let Err(missing) = self.await_handoff(node, &handoff).await {
                        let _ = self.release(node, &lock, Some(&claim.id)).await;
                        return Ok(Err(EngineError::lock(
                            LockFailure::HandoffPending,
                            format!(
                                "{lock}: the last holder's writes are not here yet ({missing}); \
                                 the lock was released — retry, or allow acquiring behind if \
                                 nothing is read from the tree under it"
                            ),
                        )));
                    }
                }
                Ok(Ok(Acquired {
                    lock,
                    id: claim.id,
                    valid_for: ttl
                        .saturating_sub(sent.elapsed())
                        .saturating_sub(self.claim_window),
                    waited_on,
                    handoff,
                    lost,
                }))
            }
            Decided::Yield(failure) => Ok(Err(failure)),
            Decided::Withdraw(failure) => {
                self.changed.notify_waiters();
                let end = LockMessage::End {
                    lock,
                    id: claim.id,
                    reason: EndReason::Withdrawn,
                    watermark: None,
                };
                // Told in the background: a lost withdrawal costs liveness,
                // never safety (§4), and the caller is waiting.
                let node = node.clone();
                tokio::spawn(async move {
                    let locks = node.locks().clone();
                    locks.broadcast(&node, &targets, &end).await;
                });
                Ok(Err(failure))
            }
        }
    }

    /// Waits until this node's complete head for each releaser reaches its
    /// watermark, asking for it directly (§8). The error names what is
    /// missing.
    async fn await_handoff(
        &self,
        node: &Node,
        marks: &[Watermark],
    ) -> std::result::Result<(), String> {
        if marks.is_empty() {
            return Ok(());
        }
        let until = Instant::now() + self.handoff_window;
        loop {
            let missing = {
                let store = self.store.clone();
                let marks = marks.to_vec();
                crate::blocking::offload(move || {
                    let mut missing = Vec::new();
                    for mark in marks {
                        let held = store.complete_head(&mark.origin)?.map_or(0, |h| h.seq);
                        if held < mark.seq {
                            missing.push(mark);
                        }
                    }
                    Ok(missing)
                })
                .await
                .map_err(|e: EngineError| e.to_string())?
            };
            if missing.is_empty() {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(missing
                    .iter()
                    .map(|m| format!("{} at seq {}", m.origin, m.seq))
                    .collect::<Vec<_>>()
                    .join(", "));
            }
            for mark in &missing {
                let keys = {
                    let store = self.store.clone();
                    let origin = mark.origin.clone();
                    crate::blocking::offload(move || Ok(store.keys_for_origin(&origin, now_ns())?))
                        .await
                        .unwrap_or_default()
                };
                for key in keys {
                    let left = until.saturating_duration_since(Instant::now());
                    if let Ok(Err(e)) = tokio::time::timeout(left, node.sync_with_peer(&key)).await
                    {
                        tracing::debug!(peer = %key.fmt_short(), error = %e, "handoff sync failed");
                    }
                }
            }
            let left = until.saturating_duration_since(Instant::now());
            tokio::time::sleep(Duration::from_millis(100).min(left)).await;
        }
    }

    // ---- holding (§5, §6) --------------------------------------------------

    /// Extends a lease-mode hold, optionally replacing its payload; returns
    /// how long the client may now use it.
    pub async fn renew(
        &self,
        lock: &LockName,
        token: &ClaimId,
        ttl: Option<Duration>,
        payload: Option<Vec<u8>>,
    ) -> Result<Duration> {
        if let Some(ttl) = ttl {
            if !(u128::from(MIN_LOCK_TTL_MS)..=u128::from(MAX_LOCK_TTL_MS))
                .contains(&ttl.as_millis())
            {
                return Err(ttl_error());
            }
        }
        if payload
            .as_ref()
            .is_some_and(|p| p.len() > MAX_LOCK_PAYLOAD_BYTES)
        {
            return Err(EngineError::invalid("a lock payload is at most 16 KiB"));
        }
        let (valid, row) = {
            let mut table = self.table();
            let own = table
                .locks
                .get_mut(lock)
                .and_then(|e| e.own.as_mut())
                .filter(|own| &own.claim.id == token && own.held())
                .ok_or_else(|| not_held(lock, token))?;
            let ttl = ttl.unwrap_or(Duration::from_millis(own.claim.ttl_ms.into()));
            if own.mode == HoldMode::Lease {
                own.client_deadline = Some(Instant::now() + ttl);
            }
            if let Some(payload) = payload {
                own.claim.payload = payload;
                own.last_renew = None;
            }
            let valid = own
                .client_deadline
                .unwrap_or(own.deadline)
                .saturating_duration_since(Instant::now())
                .saturating_sub(self.claim_window);
            (valid, self.hold_row(lock, own)?)
        };
        self.persist_hold(row).await?;
        Ok(valid)
    }

    /// Releases this node's hold: flushes its writes, then tells every peer
    /// with the handoff watermark (§4, §8).
    pub async fn release(
        &self,
        node: &Node,
        lock: &LockName,
        token: Option<&ClaimId>,
    ) -> Result<ClaimId> {
        let fence = self.fence_gate(lock);
        let _exclusive = fence.write().await;
        let id = {
            let table = self.table();
            table
                .locks
                .get(lock)
                .and_then(|e| e.own.as_ref())
                .filter(|own| token.is_none_or(|t| &own.claim.id == t))
                .map(|own| own.claim.id.clone())
                .ok_or_else(|| match token {
                    Some(token) => not_held(lock, token),
                    None => EngineError::not_found(format!("this node does not hold {lock}")),
                })?
        };
        if let Err(e) = node.flush_staged().await {
            tracing::warn!(error = %e, %lock, "releasing without flushing staged writes");
        }
        let watermark = {
            let store = self.store.clone();
            let origin = self.origin.clone();
            crate::blocking::offload(move || Ok(store.complete_head(&origin)?))
                .await?
                .map(|head| Watermark {
                    origin: self.origin.clone(),
                    seq: head.seq,
                })
        };
        {
            let now = Instant::now();
            let mut table = self.table();
            let entry = table.locks.entry(lock.clone()).or_default();
            if let Some(own) = entry.own.take_if(|own| own.claim.id == id) {
                let _ = own.lost.send(Some(Lost::Ended(EndReason::Released)));
            }
            entry.end(&id, EndReason::Released, now);
            if let Some(mark) = &watermark {
                entry.watermark(mark, now);
            }
        }
        self.changed.notify_waiters();
        self.forget_hold(lock, &id).await?;
        let targets = self.targets(node, &lock.space).await?;
        self.broadcast(
            node,
            &targets,
            &LockMessage::End {
                lock: lock.clone(),
                id: id.clone(),
                reason: EndReason::Released,
                watermark,
            },
        )
        .await;
        Ok(id)
    }

    /// Loses this node's hold to a heal, after the fence.
    async fn lose(&self, node: &Node, lock: &LockName, id: &ClaimId, why: Lost) {
        let fence = self.fence_gate(lock);
        let _exclusive = fence.write().await;
        let reason = match &why {
            Lost::Ended(reason) => *reason,
            Lost::Superseded(_) => EndReason::Superseded,
        };
        {
            let mut table = self.table();
            let entry = table.locks.entry(lock.clone()).or_default();
            let Some(own) = entry.own.take_if(|own| &own.claim.id == id) else {
                return;
            };
            tracing::warn!(%lock, token = %id.token(), why = %why, "lost a cluster lock");
            let _ = own.lost.send(Some(why.clone()));
            entry.end(id, reason, Instant::now());
        }
        self.changed.notify_waiters();
        if let Err(e) = self.forget_hold(lock, id).await {
            tracing::warn!(error = %e, "could not forget a lost lock hold");
        }
        // A claim a peer already ended needs no telling; a heal's loser tells
        // everyone it yielded.
        if matches!(why, Lost::Superseded(_)) {
            if let Ok(targets) = self.targets(node, &lock.space).await {
                self.broadcast(
                    node,
                    &targets,
                    &LockMessage::End {
                        lock: lock.clone(),
                        id: id.clone(),
                        reason,
                        watermark: None,
                    },
                )
                .await;
            }
        }
    }

    /// Ends other nodes' claims on a lock (§4): every live claim, or only
    /// `holder`'s. This node's own hold is released instead.
    pub async fn break_lock(
        &self,
        node: &Node,
        lock: &LockName,
        holder: Option<&OriginId>,
    ) -> Result<Vec<ClaimId>> {
        lock.check()
            .map_err(|e| EngineError::invalid(e.to_string()))?;
        self.check_own_authority(&lock.space).await?;
        if holder.is_none_or(|h| h == &self.origin) && self.own_id(lock).is_some() {
            return Ok(vec![self.release(node, lock, None).await?]);
        }
        let targets = self.targets(node, &lock.space).await?;
        let answers = self
            .broadcast(node, &targets, &LockMessage::Inspect { lock: lock.clone() })
            .await;
        let mut gathered = Gathered::default();
        for (_, answer) in &answers {
            if let Ok(LockMessage::Answer {
                reports,
                ended,
                watermarks,
            }) = answer
            {
                gathered.add(reports, ended, watermarks);
            }
        }
        let victims: Vec<ClaimId> = {
            let mut table = self.table();
            let entry = table.locks.entry(lock.clone()).or_default();
            for observed in entry.observed.values() {
                gathered.note(&observed.claim, observed.state());
            }
            let victims: Vec<ClaimId> = gathered
                .known
                .iter()
                .filter(|(id, (_, state))| {
                    *state != ClaimState::Expired
                        && id.ticket.origin != self.origin
                        && holder.is_none_or(|h| h == &id.ticket.origin)
                        && !gathered.ended.contains_key(*id)
                        && !entry.ended.contains_key(*id)
                })
                .map(|(id, _)| id.clone())
                .collect();
            let now = Instant::now();
            for id in &victims {
                entry.end(id, EndReason::Broken, now);
            }
            victims
        };
        self.changed.notify_waiters();
        for id in &victims {
            tracing::warn!(%lock, token = %id.token(), "breaking another node's lock claim");
            self.broadcast(
                node,
                &targets,
                &LockMessage::End {
                    lock: lock.clone(),
                    id: id.clone(),
                    reason: EndReason::Broken,
                    watermark: None,
                },
            )
            .await;
        }
        Ok(victims)
    }

    fn own_id(&self, lock: &LockName) -> Option<ClaimId> {
        self.table()
            .locks
            .get(lock)?
            .own
            .as_ref()
            .map(|own| own.claim.id.clone())
    }

    /// Takes the fence for a commit under `token` (§7): the guard holds off
    /// anything that would end the hold until the commit is done.
    pub async fn fence(&self, lock: &LockName, token: &ClaimId) -> Result<FenceGuard> {
        let guard = self.fence_gate(lock).read_owned().await;
        let now = Instant::now();
        let current = self
            .table()
            .locks
            .get(lock)
            .and_then(|e| e.own.as_ref())
            .is_some_and(|own| {
                &own.claim.id == token
                    && own.held()
                    && own.client_deadline.is_none_or(|deadline| deadline > now)
            });
        if !current {
            return Err(EngineError::lock(
                LockFailure::Lost,
                format!(
                    "{lock} is not held by this node with token {}: the write was refused",
                    token.token()
                ),
            ));
        }
        Ok(FenceGuard { _guard: guard })
    }

    // ---- the standing loop -------------------------------------------------

    /// One tick: expire observers' claims, release lapsed leases, renew what
    /// is due, and persist the clock.
    async fn tick(&self, node: &Node) {
        let now = Instant::now();
        let mut lapsed = Vec::new();
        let mut due = Vec::new();
        let mut expired_any = false;
        {
            let mut table = self.table();
            for (lock, entry) in table.locks.iter_mut() {
                for observed in entry.observed.values_mut() {
                    if !observed.expired && observed.until <= now {
                        observed.expired = true;
                        expired_any = true;
                    }
                }
                entry
                    .observed
                    .retain(|_, o| !o.expired || now.duration_since(o.until) < ENDED_MEMORY);
                entry
                    .ended
                    .retain(|_, (_, at)| now.duration_since(*at) < ENDED_MEMORY);
                entry
                    .watermarks
                    .retain(|_, (_, at)| now.duration_since(*at) < ENDED_MEMORY);
                let Some(own) = entry.own.as_mut().filter(|own| own.held()) else {
                    continue;
                };
                if own.client_deadline.is_some_and(|d| d <= now) {
                    lapsed.push((lock.clone(), own.claim.id.clone()));
                    continue;
                }
                let interval = Duration::from_millis(own.claim.ttl_ms.into()) / 3;
                if !own.renewing && own.last_renew.is_none_or(|at| now >= at + interval) {
                    own.renewing = true;
                    own.last_renew = Some(now);
                    due.push((lock.clone(), own.claim.clone()));
                }
            }
            table.locks.retain(|_, entry| !entry.is_empty());
            trim_ended(&mut table);
        }
        if expired_any {
            self.changed.notify_waiters();
        }
        for (lock, id) in lapsed {
            // A lapsed lease is released as the client would have: its writes
            // flushed and a watermark sent (§5).
            if let Err(e) = self.release(node, &lock, Some(&id)).await {
                tracing::debug!(%lock, error = %e, "could not release a lapsed lease");
            }
        }
        let renewals = due
            .into_iter()
            .map(|(lock, claim)| self.renew_once(node, lock, claim));
        crate::join::futures_join(renewals).await;
        if let Err(e) = self.persist_clock().await {
            tracing::debug!(error = %e, "could not persist the lock clock");
        }
    }

    /// Sends one renewal and acts on what the answers say (§5, §6).
    async fn renew_once(&self, node: &Node, lock: LockName, claim: Claim) {
        let targets = match self.targets(node, &lock.space).await {
            Ok(targets) => targets,
            Err(e) => {
                tracing::debug!(%lock, error = %e, "no renewal targets");
                Vec::new()
            }
        };
        let sent = Instant::now();
        let answers = self
            .broadcast(
                node,
                &targets,
                &LockMessage::Renew {
                    lock: lock.clone(),
                    claim: claim.clone(),
                },
            )
            .await;
        let mut gathered = Gathered::default();
        for (_, answer) in &answers {
            if let Ok(LockMessage::Answer {
                reports,
                ended,
                watermarks,
            }) = answer
            {
                gathered.add(reports, ended, watermarks);
            }
        }
        let verdict = {
            let mut table = self.table();
            for lamport in gathered.tickets() {
                table.hear(lamport);
            }
            let now = Instant::now();
            let Some(entry) = table.locks.get_mut(&lock) else {
                return;
            };
            for mark in gathered.watermarks.values() {
                entry.watermark(mark, now);
            }
            let Some(own) = entry.own.as_mut().filter(|own| own.claim.id == claim.id) else {
                return;
            };
            own.renewing = false;
            // The holder's lease runs from the renewal it sent (§5): a
            // partitioned holder keeps its lock, which is the AP choice.
            let verdict = heal(&own.claim, &gathered);
            if verdict.is_none() {
                own.deadline = sent + Duration::from_millis(own.claim.ttl_ms.into());
                if own.phase == Phase::Unconfirmed {
                    own.phase = Phase::Held;
                }
            }
            verdict
        };
        if let Some(why) = verdict {
            self.lose(node, &lock, &claim.id, why).await;
        }
    }

    // ---- reading -----------------------------------------------------------

    /// Every claim this node knows of, optionally in one space.
    pub fn list(&self, space: Option<&str>) -> Vec<LockView> {
        let now = Instant::now();
        let table = self.table();
        let mut views: Vec<LockView> = table
            .locks
            .iter()
            .filter(|(lock, _)| space.is_none_or(|s| s == lock.space))
            .flat_map(|(lock, entry)| entry.views(lock, now))
            .collect();
        views.sort_by(|a, b| (&a.lock, &a.claim.id).cmp(&(&b.lock, &b.claim.id)));
        views
    }

    /// The claim that holds a lock as this node sees it: its own hold, else a
    /// claim reported held, else the least live one.
    pub fn current(&self, lock: &LockName) -> Option<LockView> {
        let now = Instant::now();
        let table = self.table();
        let views = table.locks.get(lock)?.views(lock, now);
        views
            .iter()
            .find(|v| v.mode.is_some() && !v.contending)
            .or_else(|| {
                views
                    .iter()
                    .find(|v| v.mode.is_none() && v.state == ClaimState::Held)
            })
            .or_else(|| {
                views
                    .iter()
                    .filter(|v| v.mode.is_none() && v.state == ClaimState::Live)
                    .min_by(|a, b| a.claim.id.cmp(&b.claim.id))
            })
            .cloned()
    }

    /// This node's view of a lock, and each reachable peer's when `peers`.
    pub async fn status(&self, node: &Node, lock: &LockName, peers: bool) -> Result<LockStatus> {
        lock.check()
            .map_err(|e| EngineError::invalid(e.to_string()))?;
        let mut peer_views = Vec::new();
        if peers {
            let targets = self.targets(node, &lock.space).await?;
            for (peer, answer) in self
                .broadcast(node, &targets, &LockMessage::Inspect { lock: lock.clone() })
                .await
            {
                peer_views.push(PeerView {
                    peer,
                    answer: match answer {
                        Ok(LockMessage::Answer { reports, .. }) => Ok(reports),
                        Ok(LockMessage::Refused { reason }) => Err(reason),
                        Ok(_) => Err("answered out of turn".into()),
                        Err(e) => Err(e),
                    },
                });
            }
            peer_views.sort_by_key(|v| v.peer);
        }
        let now = Instant::now();
        let table = self.table();
        let (views, watermarks) = match table.locks.get(lock) {
            Some(entry) => (
                entry.views(lock, now),
                entry
                    .watermarks
                    .iter()
                    .map(|(origin, (seq, _))| Watermark {
                        origin: origin.clone(),
                        seq: *seq,
                    })
                    .collect(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        Ok(LockStatus {
            lock: lock.clone(),
            views,
            watermarks,
            peers: peer_views,
        })
    }

    // ---- serving (§3.3 step 2) ---------------------------------------------

    /// Records a claim or renewal from `peer` and answers with the table.
    fn record(
        &self,
        peer: &NodeId,
        lock: LockName,
        claim: Claim,
        renewal: bool,
    ) -> Result<LockMessage> {
        let now = Instant::now();
        if claim.id.ticket.origin == self.origin {
            // Another device key of this origin, mid-rotation (§3.4). It is
            // not a rival, and recording it would make this node defer to
            // its own claim.
            return Ok(self.answer(&lock, now));
        }
        if !self
            .writer_origins(peer, &lock.space)?
            .contains(&claim.id.ticket.origin)
        {
            return Ok(refused(format!(
                "{} is not a writer of {}",
                claim.id.ticket.origin, lock.space
            )));
        }
        let mut table = self.table();
        table.hear(claim.id.ticket.lamport);
        let fresh = table
            .locks
            .get(&lock)
            .is_none_or(|e| !e.observed.contains_key(&claim.id));
        if fresh
            && (table.claims() >= MAX_TABLE_CLAIMS
                || table.claims_of(&claim.id.ticket.origin) >= MAX_CLAIMS_PER_ORIGIN)
        {
            return Ok(refused("the lock table is full".to_string()));
        }
        let entry = table.locks.entry(lock).or_default();
        if !entry.ended.contains_key(&claim.id) {
            let until = now + observer_lease(claim.ttl_ms);
            let observed = entry
                .observed
                .entry(claim.id.clone())
                .or_insert_with(|| Observed {
                    claim: claim.clone(),
                    held: false,
                    until,
                    expired: false,
                });
            // A renewal of a claim this node expired re-admits it: expiry is
            // not an end, and only a superseding hold makes it one (§6).
            observed.claim = claim;
            observed.until = until;
            observed.expired = false;
            observed.held |= renewal;
        }
        Ok(entry.answer(now))
    }

    fn answer(&self, lock: &LockName, now: Instant) -> LockMessage {
        self.table()
            .locks
            .get(lock)
            .map_or_else(|| Entry::default().answer(now), |entry| entry.answer(now))
    }

    /// Records an end from `peer`.
    fn record_end(
        &self,
        peer: &NodeId,
        lock: LockName,
        id: ClaimId,
        reason: EndReason,
        watermark: Option<Watermark>,
    ) -> Result<LockMessage> {
        let writers = self.writer_origins(peer, &lock.space)?;
        let allowed = match reason {
            EndReason::Broken => !writers.is_empty(),
            _ => writers.contains(&id.ticket.origin),
        };
        if !allowed {
            return Ok(refused(format!(
                "not a writer of {} for that claim",
                lock.space
            )));
        }
        let now = Instant::now();
        if self.own_id(&lock).as_ref() == Some(&id) {
            // A writer broke this node's own hold. Ended under the fence, so
            // a fenced commit in flight finishes first (§7).
            let gate = self.fence_gate(&lock);
            let _exclusive = gate.blocking_write();
            let mut table = self.table();
            let entry = table.locks.entry(lock.clone()).or_default();
            if let Some(own) = entry.own.take_if(|own| own.claim.id == id) {
                tracing::warn!(%lock, token = %id.token(), peer = %peer.fmt_short(), "a peer ended this node's lock");
                let _ = own.lost.send(Some(Lost::Ended(reason)));
            }
            entry.end(&id, reason, now);
            drop(table);
            self.store
                .remove_lock_hold(&lock.space, &lock.name, id.ticket.lamport, id.nonce)?;
        } else {
            let mut table = self.table();
            let entry = table.locks.entry(lock).or_default();
            entry.end(&id, reason, now);
            if let Some(mark) = watermark.filter(|m| m.origin == id.ticket.origin) {
                entry.watermark(&mark, now);
            }
        }
        self.changed.notify_waiters();
        Ok(LockMessage::Ack)
    }

    fn serve_request(&self, peer: NodeId, request: LockMessage) -> Result<LockMessage> {
        match request {
            LockMessage::Claim { lock, claim } => self.record(&peer, lock, claim, false),
            LockMessage::Renew { lock, claim } => self.record(&peer, lock, claim, true),
            LockMessage::End {
                lock,
                id,
                reason,
                watermark,
            } => self.record_end(&peer, lock, id, reason, watermark),
            LockMessage::Inspect { lock } => {
                if !self.may_read(&peer, &lock.space)? {
                    return Ok(refused(format!("not a reader of {}", lock.space)));
                }
                Ok(self.answer(&lock, Instant::now()))
            }
            LockMessage::Answer { .. } | LockMessage::Ack | LockMessage::Refused { .. } => {
                Ok(refused("not a request".to_string()))
            }
        }
    }
}

impl synch_net::LockService for LockManager {
    fn serve(&self, peer: NodeId, request: LockMessage) -> LockMessage {
        self.serve_request(peer, request)
            .unwrap_or_else(|e| refused(e.to_string()))
    }
}

/// A fenced commit's hold on the lock: nothing ends the hold while it lives.
#[derive(Debug)]
pub struct FenceGuard {
    _guard: tokio::sync::OwnedRwLockReadGuard<()>,
}

/// The renewal loop's task, owned by the node like the pusher.
#[derive(Debug, Default)]
pub(crate) struct LockTask {
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl LockTask {
    /// Starts the loop for `node`, holding it weakly so the task does not
    /// keep the node alive (`Node::downgrade`).
    pub(crate) fn start(&self, node: &Node) {
        let task = tokio::spawn(run(node.downgrade()));
        *self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    }

    /// Stops the loop and waits for it to end.
    pub(crate) async fn stop(&self) {
        let task = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for LockTask {
    fn drop(&mut self) {
        if let Some(task) = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

async fn run(weak: WeakNode) {
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let Some(node) = weak.upgrade() else { return };
        let locks = node.locks().clone();
        locks.tick(&node).await;
    }
}

enum Decided {
    Hold(Option<LockHoldRow>),
    Yield(EngineError),
    Withdraw(EngineError),
}

fn trim_ended(table: &mut Table) {
    let total: usize = table.locks.values().map(|e| e.ended.len()).sum();
    if total <= MAX_ENDED_IDS {
        return;
    }
    let mut ended: Vec<(LockName, ClaimId, Instant)> = table
        .locks
        .iter()
        .flat_map(|(lock, entry)| {
            entry
                .ended
                .iter()
                .map(|(id, (_, at))| (lock.clone(), id.clone(), *at))
        })
        .collect();
    ended.sort_by_key(|(_, _, at)| *at);
    for (lock, id, _) in ended.into_iter().take(total - MAX_ENDED_IDS) {
        if let Some(entry) = table.locks.get_mut(&lock) {
            entry.ended.remove(&id);
        }
    }
}

// ---- the pure rules --------------------------------------------------------

/// Whether an origin with publication scope `scope` may write `space`.
fn may_publish(scope: &PublishScope, space: &str) -> bool {
    match scope {
        PublishScope::Untrusted => false,
        PublishScope::Unrestricted => true,
        PublishScope::Confined(spaces) => spaces.iter().any(|s| s == space),
    }
}

/// How long an observer keeps a claim after receiving it (§5).
fn observer_lease(ttl_ms: u32) -> Duration {
    Duration::from_millis(u64::from(ttl_ms)).mul_f64(1.0 + 2.0 * RHO)
}

/// Everything a set of answers says about one lock.
#[derive(Debug, Default)]
struct Gathered {
    /// Each claim, and the strongest state any reporter gave it.
    known: BTreeMap<ClaimId, (Claim, ClaimState)>,
    ended: BTreeMap<ClaimId, EndReason>,
    watermarks: BTreeMap<OriginId, Watermark>,
}

impl Gathered {
    fn add(&mut self, reports: &[Report], ended: &[(ClaimId, EndReason)], marks: &[Watermark]) {
        for report in reports {
            self.note(&report.claim, report.state);
        }
        for (id, reason) in ended {
            self.ended.insert(id.clone(), *reason);
        }
        for mark in marks {
            let slot = self
                .watermarks
                .entry(mark.origin.clone())
                .or_insert(mark.clone());
            if mark.seq > slot.seq {
                *slot = mark.clone();
            }
        }
    }

    /// Records a claim; held outranks live outranks expired, so a reporter
    /// that heard the latest renewal wins over one that missed it (§3.3).
    fn note(&mut self, claim: &Claim, state: ClaimState) {
        let slot = self
            .known
            .entry(claim.id.clone())
            .or_insert((claim.clone(), state));
        if state > slot.1 {
            *slot = (claim.clone(), state);
        }
    }

    fn tickets(&self) -> impl Iterator<Item = u64> + '_ {
        self.known
            .keys()
            .chain(self.ended.keys())
            .map(|id| id.ticket.lamport)
    }
}

/// What a claimant does once its answers are in.
#[derive(Debug, PartialEq)]
enum Verdict {
    /// Hold, naming the expired claims this one takes over from.
    Hold { supersedes: Vec<ClaimId> },
    /// Withdraw: to the claim named and whether it is held; `reclaim` when a
    /// predecessor's ticket was above ours.
    Yield {
        to: Option<(Claim, bool)>,
        reclaim: bool,
    },
}

/// The decision (§3.3 step 3): hold iff this ticket is the least among the
/// live claims known and none of them is held.
fn decide(
    mine: &ClaimId,
    known: &BTreeMap<ClaimId, (Claim, ClaimState)>,
    ended: &BTreeMap<ClaimId, EndReason>,
) -> Verdict {
    let live = |id: &ClaimId| !ended.contains_key(id) && id != mine;
    // A predecessor *hold* above this ticket means this node's clock lost
    // increments: re-claim above it so fencing tokens stay monotone (§7). A
    // rival that withdrew above us is no predecessor, so withdrawals are not
    // counted — they are the ordinary way a simultaneous claim loses.
    let predecessor_above = ended.iter().any(|(id, reason)| {
        id > mine && id.ticket.origin != mine.ticket.origin && *reason != EndReason::Withdrawn
    });
    if predecessor_above {
        return Verdict::Yield {
            to: None,
            reclaim: true,
        };
    }
    let mut blocker: Option<(Claim, bool)> = None;
    for (id, (claim, state)) in known.iter().filter(|(id, _)| live(id)) {
        let held = *state == ClaimState::Held;
        if (held || (*state == ClaimState::Live && id < mine))
            && blocker
                .as_ref()
                .is_none_or(|(_, was_held)| held && !was_held)
        {
            blocker = Some((claim.clone(), held));
        }
    }
    match blocker {
        Some(to) => Verdict::Yield {
            to: Some(to),
            reclaim: false,
        },
        None => Verdict::Hold {
            supersedes: known
                .iter()
                .filter(|(id, (_, state))| live(id) && *state == ClaimState::Expired)
                .map(|(id, _)| id.clone())
                .take(MAX_LOCK_SUPERSEDES)
                .collect(),
        },
    }
}

/// The heal (§6): whether a renewal's answers say this holder lost.
///
/// Every node holding both claims ranks them alike: a claim that took over
/// from the other's expired lease keeps the lock, and otherwise the lesser
/// ticket does.
fn heal(mine: &Claim, gathered: &Gathered) -> Option<Lost> {
    if let Some(reason) = gathered.ended.get(&mine.id) {
        return Some(Lost::Ended(*reason));
    }
    for (id, (other, state)) in &gathered.known {
        if id == &mine.id
            || *state != ClaimState::Held
            || gathered.ended.contains_key(id)
            || mine.supersedes.contains(id)
        {
            continue;
        }
        if other.supersedes.contains(&mine.id) || id < &mine.id {
            return Some(Lost::Superseded(id.clone()));
        }
    }
    None
}

fn yield_error(lock: &LockName, to: Option<(Claim, bool)>, reclaim: bool) -> EngineError {
    match to {
        Some((holder, true)) => EngineError::lock(
            LockFailure::Held,
            format!(
                "{lock} is held by {} ({}), token {}",
                holder.id.ticket.origin,
                display_owner(&holder.owner),
                holder.id.token()
            ),
        ),
        Some((rival, false)) => EngineError::lock(
            LockFailure::Contended,
            format!(
                "{lock}: a simultaneous claim by {} won",
                rival.id.ticket.origin
            ),
        ),
        None if reclaim => EngineError::lock(
            LockFailure::Contended,
            format!("{lock}: a predecessor's ticket was above ours; claiming again"),
        ),
        None => EngineError::lock(LockFailure::Contended, format!("{lock}: the claim lost")),
    }
}

fn ttl_error() -> EngineError {
    EngineError::invalid(format!(
        "a lock lease is {}s to {}s",
        MIN_LOCK_TTL_MS / 1000,
        MAX_LOCK_TTL_MS / 1000
    ))
}

fn check_request(request: &LockRequest) -> Result<()> {
    request
        .lock
        .check()
        .map_err(|e| EngineError::invalid(e.to_string()))?;
    if !(u128::from(MIN_LOCK_TTL_MS)..=u128::from(MAX_LOCK_TTL_MS))
        .contains(&request.ttl.as_millis())
    {
        return Err(ttl_error());
    }
    if request.owner.len() > MAX_LOCK_OWNER_BYTES {
        return Err(EngineError::invalid("a lock owner is at most 128 bytes"));
    }
    if request.payload.len() > MAX_LOCK_PAYLOAD_BYTES {
        return Err(EngineError::invalid("a lock payload is at most 16 KiB"));
    }
    Ok(())
}

fn not_held(lock: &LockName, token: &ClaimId) -> EngineError {
    EngineError::lock(
        LockFailure::Lost,
        format!(
            "{lock} is not held by this node with token {}",
            token.token()
        ),
    )
}

fn refused(reason: String) -> LockMessage {
    LockMessage::Refused { reason }
}

fn display_owner(owner: &str) -> &str {
    if owner.is_empty() {
        "no owner given"
    } else {
        owner
    }
}

fn nonce() -> u64 {
    let mut bytes = [0u8; 8];
    // The nonce only separates two claims a restored database gave the same
    // ticket; a failure of the system RNG falls back to the clock.
    if aws_lc_rs::rand::fill(&mut bytes).is_err() {
        return now_ns() as u64;
    }
    u64::from_le_bytes(bytes)
}

fn jitter(max_ms: u64) -> u64 {
    if max_ms == 0 {
        0
    } else {
        nonce() % max_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(lamport: u64, who: &str) -> ClaimId {
        ClaimId {
            ticket: Ticket {
                lamport,
                origin: OriginId::named(who, "x.example").unwrap(),
            },
            nonce: 0,
        }
    }

    fn claim(id: ClaimId, supersedes: Vec<ClaimId>) -> Claim {
        Claim {
            id,
            ttl_ms: 30_000,
            owner: String::new(),
            payload: Vec::new(),
            supersedes,
        }
    }

    fn known(claims: &[(ClaimId, ClaimState)]) -> BTreeMap<ClaimId, (Claim, ClaimState)> {
        claims
            .iter()
            .map(|(id, state)| (id.clone(), (claim(id.clone(), Vec::new()), *state)))
            .collect()
    }

    #[test]
    fn the_least_live_ticket_holds_and_a_held_claim_outranks_any_ticket() {
        let mine = id(5, "b");
        let none = BTreeMap::new();
        let decided = |claims: &[(ClaimId, ClaimState)]| decide(&mine, &known(claims), &none);
        assert!(matches!(
            decided(&[(id(4, "a"), ClaimState::Live)]),
            Verdict::Yield {
                to: Some((_, false)),
                ..
            }
        ));
        assert!(matches!(
            decided(&[(id(6, "a"), ClaimState::Live)]),
            Verdict::Hold { .. }
        ));
        // An incumbent holds whatever its ticket (§3.4).
        assert!(matches!(
            decided(&[(id(9, "a"), ClaimState::Held)]),
            Verdict::Yield {
                to: Some((_, true)),
                ..
            }
        ));
        // An expired claim is taken over and named (§6).
        assert_eq!(
            decided(&[(id(4, "a"), ClaimState::Expired)]),
            Verdict::Hold {
                supersedes: vec![id(4, "a")]
            }
        );
    }

    #[test]
    fn ended_claims_never_block_and_only_ended_holds_force_a_reclaim() {
        let mine = id(5, "b");
        let rival = [(id(4, "a"), ClaimState::Live)];
        let ended = |id: ClaimId, reason| BTreeMap::from([(id, reason)]);
        assert_eq!(
            decide(
                &mine,
                &known(&rival),
                &ended(id(4, "a"), EndReason::Released)
            ),
            Verdict::Hold {
                supersedes: Vec::new()
            }
        );
        // A rival that withdrew above us lost a race; a hold released above
        // us is a predecessor this node's clock missed.
        assert!(matches!(
            decide(
                &mine,
                &BTreeMap::new(),
                &ended(id(8, "a"), EndReason::Withdrawn)
            ),
            Verdict::Hold { .. }
        ));
        assert_eq!(
            decide(
                &mine,
                &BTreeMap::new(),
                &ended(id(8, "a"), EndReason::Released)
            ),
            Verdict::Yield {
                to: None,
                reclaim: true
            }
        );
    }

    #[test]
    fn a_heal_keeps_the_superseder_then_the_lesser_ticket() {
        let stale = claim(id(3, "a"), Vec::new());
        let fresh = claim(id(7, "b"), vec![id(3, "a")]);
        let report = |c: &Claim| Gathered {
            known: [(c.id.clone(), (c.clone(), ClaimState::Held))].into(),
            ..Gathered::default()
        };
        // The stale holder loses to the claim that took over from it, though
        // its own ticket is lower, and the superseder keeps the lock.
        assert_eq!(
            heal(&stale, &report(&fresh)),
            Some(Lost::Superseded(fresh.id.clone()))
        );
        assert_eq!(heal(&fresh, &report(&stale)), None);
        // With no supersession the lesser ticket keeps it.
        let other = claim(id(7, "c"), Vec::new());
        assert_eq!(heal(&stale, &report(&other)), None);
        assert_eq!(
            heal(&other, &report(&stale)),
            Some(Lost::Superseded(stale.id.clone()))
        );
    }

    #[test]
    fn an_observer_keeps_a_claim_longer_than_its_holder() {
        assert!(observer_lease(30_000) > Duration::from_secs(30));
        assert!(observer_lease(30_000) < Duration::from_millis(30_100));
    }
}
