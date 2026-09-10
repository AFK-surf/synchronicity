//! The reactive head push, off the publisher's path (§5.3).
//!
//! A publish hands its new head here and returns. Telling peers means dialing
//! them, and a peer that is off costs a full dial deadline — so an `synch put`
//! on a cluster where one member was simply down answered ten seconds late,
//! with the write itself long since durable.
//!
//! Nothing about that wait was load-bearing. The push was never allowed to fail
//! a publish (`Node::flush_staged`), and what guarantees convergence is the
//! periodic round, which repairs whatever the push missed (§5.3). The push is
//! the optimistic half — usually first, never the reason a reader sees anything.
//!
//! What is load-bearing is that the push *starts* when the head is published
//! rather than at the next jittered interval: §5.3's sub-second propagation is
//! a claim about the push, so deferring the work would be a different bug than
//! the one being fixed.
//!
//! The work coalesces because heads are monotone. A peer that receives the
//! newest head fetches the trie under it and needs nothing older (§5.2 takes
//! the greater), so a head superseded before its push went out is dropped
//! rather than spent a dial on.
//!
//! The task is owned by the node rather than by a host. Every caller of
//! `flush_staged` has to be served, and the hosts that matter include the bare
//! `Node`s that embedders and tests build without running a single standing
//! loop — a host-spawned pusher would make the push a silent no-op exactly
//! there. So it starts with the node itself, like the socket pool, and stops
//! with it: abort in `Node::shutdown`, abort on drop.

use std::sync::Arc;

use synch_core::SignedHead;
use tokio::task::JoinHandle;

use crate::{
    aae::REACTIVE_PUSH_BUDGET,
    node::{Node, WeakNode},
};

/// The newest head a reactive push still owes peers.
///
/// One slot rather than a queue: everything older than the newest head is
/// subsumed by it, so a queue would order pushes that no receiver needs in
/// order.
#[derive(Debug)]
struct PushSlot {
    head: std::sync::Mutex<Option<SignedHead>>,
    wake: tokio::sync::Notify,
}

impl PushSlot {
    fn new() -> Self {
        PushSlot {
            head: std::sync::Mutex::new(None),
            wake: tokio::sync::Notify::new(),
        }
    }

    /// Stores `head` for the next pass, unless a greater seq is already waiting.
    ///
    /// Synchronous on purpose. This is called from `flush_staged`, which runs on
    /// control connections that are spawned detached and may be dropped at any
    /// await point — a stage with an await in it could be skipped entirely,
    /// leaving a publish whose head was never offered to anybody.
    ///
    /// The seq guard is the other half of being called from several places at
    /// once: the store assigns each publish its seq under its own lock, so the
    /// flush that reaches this slot second is not necessarily the one holding
    /// the newer head, and the older must not displace the newer.
    ///
    /// An equal seq replaces: the same head re-signed across a rotation, where
    /// taking the later signature is as good as taking the earlier one.
    fn stage(&self, head: &SignedHead) {
        let stored = {
            let mut slot = self
                .head
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match slot.as_ref() {
                Some(waiting) if waiting.seq > head.seq => false,
                _ => {
                    *slot = Some(head.clone());
                    true
                }
            }
        };
        // Only when something was stored: a ring for a head that lost the slot
        // would wake the loop for nothing. A ring is never *needed* for
        // correctness — the head is in the slot either way, and a loop that is
        // between `take` and its park sees the stored permit — but it is what
        // makes the next pass start now rather than at the one after.
        if stored {
            self.wake.notify_one();
        }
    }

    /// Takes the waiting head, if any.
    fn take(&self) -> Option<SignedHead> {
        self.head
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    async fn woken(&self) {
        self.wake.notified().await;
    }
}

/// The task that pushes this node's new heads to its peers.
#[derive(Debug)]
pub(crate) struct Pusher {
    slot: Arc<PushSlot>,
    /// The running task, taken by [`Pusher::stop`] and by `Drop`. `None` before
    /// [`Pusher::start`] and after a stop, so stopping twice is a no-op.
    task: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Pusher {
    pub(crate) fn new() -> Self {
        Pusher {
            slot: Arc::new(PushSlot::new()),
            task: std::sync::Mutex::new(None),
        }
    }

    /// Starts the pass loop for `node`.
    ///
    /// The task holds a [`WeakNode`]. The handle it is parked behind lives on
    /// the node's own inner state, so a strong reference here would be a cycle
    /// that keeps the node — and its database — alive for the life of the
    /// process (`Node::downgrade` names the same trap for the socket handler).
    pub(crate) fn start(&self, node: &Node) {
        let weak = node.downgrade();
        let slot = self.slot.clone();
        let task = tokio::spawn(run(weak, slot));
        let previous = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(task);
        debug_assert!(previous.is_none(), "a pusher was started twice");
    }

    /// Hands `head` to the pass loop without waiting for it.
    pub(crate) fn stage(&self, head: &SignedHead) {
        self.slot.stage(head);
    }

    /// Stops the loop and waits for it to end.
    ///
    /// Aborted rather than asked to stop: a pass is bounded per peer, but a
    /// whole membership of unreachable peers is not bounded usefully, and
    /// waiting one out is the stall this module exists to remove. What an abort
    /// drops is a *push* — never a publish, whose head is already durable, and
    /// which the next anti-entropy round carries in any case.
    pub(crate) async fn stop(&self) {
        let Some(task) = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        else {
            return;
        };
        task.abort();
        // Cancellation is the expected outcome, so saying nothing about it is
        // saying what happened. Anything else is a panic, which means the
        // reactive path stopped working at some earlier and unknown moment —
        // this is the only place that can still report it, since nothing joins
        // this task the way the daemon joins its standing loops.
        if let Err(e) = task.await {
            if !e.is_cancelled() {
                tracing::warn!(error = %e, "the head pusher ended abnormally");
            }
        }
    }
}

impl Drop for Pusher {
    /// Aborts a loop the node never stopped.
    ///
    /// The path every test takes: a node that is opened, used and dropped
    /// without `Node::shutdown`. Without this the task would park on a wake
    /// nothing can ever ring, and outlive the node it serves.
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

/// One pass per staged head, until the task is aborted.
async fn run(node: WeakNode, slot: Arc<PushSlot>) {
    loop {
        slot.woken().await;
        let Some(head) = slot.take() else { continue };
        // Upgraded per pass rather than held for the task's life: the node is
        // needed for the dial and for nothing else, and holding it would keep
        // a shut-down node's endpoint alive under the pusher.
        let Some(node) = node.upgrade() else { return };
        // Failures are the peers' business, not the publisher's: the same
        // per-peer `debug!` the push has always logged, now the only reporting
        // of a push that did not land.
        if let Err(e) = node.push_head_within(&head, REACTIVE_PUSH_BUDGET).await {
            tracing::debug!(error = %e, "could not push the new head");
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use synch_core::{Hash, OriginId};

    use super::*;

    fn head(key: &SecretKey, seq: u64) -> SignedHead {
        SignedHead::sign(
            key,
            OriginId::named("nas", "cluster.example").unwrap(),
            seq,
            Hash::EMPTY,
            1,
        )
    }

    #[test]
    fn the_greatest_seq_wins_the_slot() {
        let key = SecretKey::generate();
        let slot = PushSlot::new();
        for seq in [5, 7, 6] {
            slot.stage(&head(&key, seq));
        }
        assert_eq!(slot.take().map(|head| head.seq), Some(7));
        // And taking is what empties it: one pass per head staged, not one pass
        // per stage.
        assert!(slot.take().is_none());
    }

    #[test]
    fn a_head_staged_into_an_empty_slot_is_kept_even_if_it_is_old() {
        let key = SecretKey::generate();
        let slot = PushSlot::new();
        // Nothing is waiting to compare against — the previous head is out on a
        // pass — so this one is stored even though the pusher has already sent
        // something newer. Re-offering a head a peer refuses as `NotNewer` is
        // free; dropping one that peer never got is not.
        slot.stage(&head(&key, 9));
        slot.take();
        slot.stage(&head(&key, 4));
        assert_eq!(slot.take().map(|head| head.seq), Some(4));
    }
}
