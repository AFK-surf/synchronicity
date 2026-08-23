//! The invocation context: everything a helper can reach.
//!
//! Handed to `Program::run` as a resource, so a helper — which is a bare `fn`
//! pointer and can capture nothing — reaches it through
//! `HelperScope::with_resource_mut`. The state itself hangs off an [`Rc`] so
//! that the one helper which suspends can clone a handle into the future it
//! posts, rather than trying to hold a borrow across an await.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::Arc,
    time::Instant,
};

use synch_core::{Declaration, Hash};

use crate::{
    abi::{errno, poll},
    limits::{Limits, MAX_LABELS, MAX_METRIC_NAMES},
    policy::{EffectivePolicy, PeerIdentity, SocketId},
    runtime::{
        endpoint::{Endpoint, Readiness, State},
        map::SocketMaps,
    },
    ObjectInfo, SocketHost,
};

/// An object the guest opened for reading.
#[derive(Debug)]
pub(crate) struct ObjectSlot {
    pub(crate) info: ObjectInfo,
    /// A read is in flight.
    pub(crate) pending: Cell<bool>,
    /// What the last read produced: bytes, or the errno to report.
    pub(crate) result: RefCell<Option<Result<Vec<u8>, i64>>>,
    /// The `(offset, len)` the in-flight or completed read was for, so a guest
    /// that asks for a different range gets a fresh read rather than the
    /// previous answer.
    pub(crate) want: Cell<(u64, u64)>,
    pub(crate) ready: Rc<Readiness>,
}

impl ObjectSlot {
    fn revents(&self) -> u32 {
        match &*self.result.borrow() {
            Some(Ok(_)) => poll::IN,
            Some(Err(_)) => poll::ERR,
            None => 0,
        }
    }
}

/// A directory cursor.
#[derive(Debug)]
pub(crate) struct CursorSlot {
    pub(crate) names: Vec<String>,
    pub(crate) at: Cell<usize>,
}

/// What one handle refers to.
#[derive(Debug)]
pub(crate) enum Slot {
    Endpoint(Rc<Endpoint>),
    Object(Rc<ObjectSlot>),
    Cursor(Rc<CursorSlot>),
}

impl Slot {
    pub(crate) fn revents(&self) -> u32 {
        match self {
            Slot::Endpoint(ep) => ep.revents(),
            Slot::Object(obj) => obj.revents(),
            // A cursor is always ready: every answer it can give is already in
            // memory, so a program that polls one is told to go ahead.
            Slot::Cursor(_) => poll::IN,
        }
    }
}

/// The state behind every helper.
pub(crate) struct Inner {
    pub(crate) slots: RefCell<Vec<Option<Slot>>>,
    pub(crate) ready: Rc<Readiness>,
    pub(crate) policy: EffectivePolicy,
    pub(crate) peer: PeerIdentity,
    pub(crate) socket: SocketId,
    pub(crate) self_origin: String,
    pub(crate) meta: Vec<(String, String)>,
    pub(crate) host: Arc<dyn SocketHost>,
    pub(crate) maps: Arc<SocketMaps>,
    pub(crate) limits: Limits,
    pub(crate) started: Instant,
    /// When this invocation is considered idle.
    ///
    /// Pushed forward by [`Inner::made_progress`] whenever bytes move or a
    /// handle becomes ready, which is what makes it an *idle* deadline rather
    /// than a total wall-clock cap. There is deliberately no total cap: a
    /// socket that proxies is supposed to be long-lived, and its CPU is
    /// bounded by the timeslicer instead (`docs/SOCKETS.md` §10).
    pub(crate) deadline: Cell<Instant>,
    pub(crate) program_root: Hash,
    pub(crate) id: u64,

    pub(crate) log_buf: RefCell<Vec<u8>>,
    pub(crate) metrics: RefCell<Vec<(String, i64)>>,
    pub(crate) labels: RefCell<Vec<(String, String)>>,
    pub(crate) footprint: Cell<u64>,
    pub(crate) egress_open: Cell<usize>,

    /// Set while the `synchronicity.init` hook is running.
    ///
    /// The one flag that changes what a helper is allowed to be: a declaration
    /// helper called outside the hook, or an I/O helper called inside it, is
    /// `SY_EPERM`. The init hook runs with no endpoint table at all, so there
    /// is nothing for it to reach even if the check were missed.
    pub(crate) init_mode: bool,
    pub(crate) declaration: RefCell<Declaration>,

    /// Counters an operator reads while this is running.
    ///
    /// Written here on the worker thread and read by `synch socket ps` from
    /// another, which is why they are atomics rather than more `Cell`s.
    pub(crate) live: Arc<crate::registry::LiveStats>,
    /// Where `sy_log` lines are remembered for `synch socket log`.
    pub(crate) registry: Option<Arc<crate::registry::Registry>>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("id", &self.id)
            .field("socket", &self.socket)
            .field("program_root", &self.program_root)
            .field("init_mode", &self.init_mode)
            .finish_non_exhaustive()
    }
}

/// The resource a helper looks up.
#[derive(Debug, Clone)]
pub(crate) struct Ctx {
    pub(crate) inner: Rc<Inner>,
}

impl Inner {
    /// Looks a handle up.
    pub(crate) fn slot(&self, handle: i64) -> Option<Slot2> {
        if handle < 0 {
            return None;
        }
        let slots = self.slots.borrow();
        match slots.get(handle as usize).and_then(|s| s.as_ref()) {
            Some(Slot::Endpoint(ep)) => Some(Slot2::Endpoint(ep.clone())),
            Some(Slot::Object(obj)) => Some(Slot2::Object(obj.clone())),
            Some(Slot::Cursor(cur)) => Some(Slot2::Cursor(cur.clone())),
            None => None,
        }
    }

    /// The endpoint at `handle`, or `None` if it is something else.
    pub(crate) fn endpoint(&self, handle: i64) -> Option<Rc<Endpoint>> {
        match self.slot(handle) {
            Some(Slot2::Endpoint(ep)) => Some(ep),
            _ => None,
        }
    }

    /// Puts a slot in the table, returning its handle.
    pub(crate) fn insert(&self, slot: Slot) -> Result<i64, i64> {
        let mut slots = self.slots.borrow_mut();
        if let Some(index) = slots.iter().position(|s| s.is_none()) {
            slots[index] = Some(slot);
            return Ok(index as i64);
        }
        if slots.len() >= self.limits.max_handles {
            return Err(errno::ELIMIT);
        }
        slots.push(Some(slot));
        Ok(slots.len() as i64 - 1)
    }

    /// Drops a handle, releasing whatever it held.
    pub(crate) fn remove(&self, handle: i64) -> bool {
        if handle < 0 {
            return false;
        }
        let mut slots = self.slots.borrow_mut();
        let Some(entry) = slots.get_mut(handle as usize) else {
            return false;
        };
        match entry.take() {
            Some(Slot::Endpoint(ep)) => {
                // An outbound endpoint frees its place in the egress budget:
                // the bound is on how many are open at once, not on how many
                // were ever opened.
                if handle != crate::abi::SY_SELF {
                    self.egress_open
                        .set(self.egress_open.get().saturating_sub(1));
                }
                ep.close();
                true
            }
            Some(Slot::Object(obj)) => {
                let held = obj
                    .result
                    .borrow()
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .map(|b| b.len() as u64)
                    .unwrap_or(0);
                self.release(held);
                true
            }
            Some(Slot::Cursor(cur)) => {
                let held: u64 = cur.names.iter().map(|n| n.len() as u64).sum();
                self.release(held);
                true
            }
            None => false,
        }
    }

    /// Notes that something happened, and pushes the idle deadline out.
    ///
    /// Called from the places progress is observable: bytes copied in or out,
    /// and a poll that came back with a handle ready. A program blocked on a
    /// slow upstream is not idle, and one that has been parked in `sy_poll`
    /// for five minutes with nothing happening is.
    pub(crate) fn made_progress(&self) {
        self.deadline
            .set(Instant::now() + self.limits.idle_deadline);
    }

    /// Charges host-side bytes against this invocation's footprint.
    pub(crate) fn charge(&self, bytes: u64) -> Result<(), i64> {
        let next = self.footprint.get().saturating_add(bytes);
        if next > self.limits.max_footprint {
            return Err(errno::ELIMIT);
        }
        self.footprint.set(next);
        Ok(())
    }

    /// Gives bytes back.
    pub(crate) fn release(&self, bytes: u64) {
        self.footprint
            .set(self.footprint.get().saturating_sub(bytes));
    }

    /// Publishes the handle count, which only changes when the table does.
    pub(crate) fn publish_handles(&self) {
        let held = self.slots.borrow().iter().flatten().count() as u64;
        self.live
            .handles
            .store(held, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records a metric bump.
    pub(crate) fn metric(&self, name: &str, delta: i64) -> i64 {
        let mut metrics = self.metrics.borrow_mut();
        if let Some(slot) = metrics.iter_mut().find(|(n, _)| n == name) {
            slot.1 = slot.1.saturating_add(delta);
            drop(metrics);
            self.live.set_metrics(self.metrics.borrow().clone());
            return 0;
        }
        if metrics.len() >= MAX_METRIC_NAMES {
            return errno::ELIMIT;
        }
        metrics.push((name.to_string(), delta));
        drop(metrics);
        self.live.set_metrics(self.metrics.borrow().clone());
        0
    }

    /// Records a label.
    pub(crate) fn label(&self, key: &str, value: &str) -> i64 {
        let mut labels = self.labels.borrow_mut();
        if let Some(slot) = labels.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value.to_string();
            drop(labels);
            self.live.set_labels(self.labels.borrow().clone());
            return 0;
        }
        if labels.len() >= MAX_LABELS {
            return errno::ELIMIT;
        }
        labels.push((key.to_string(), value.to_string()));
        drop(labels);
        self.live.set_labels(self.labels.borrow().clone());
        0
    }

    /// Flushes whatever `sy_log` has buffered but not yet emitted.
    pub(crate) fn flush_log(&self) {
        let mut buf = self.log_buf.borrow_mut();
        if buf.is_empty() {
            return;
        }
        let line = sanitize(&buf);
        buf.clear();
        self.remember_log(&line);
    }

    /// Emits one log line: to the daemon's log, and to the socket's tail.
    ///
    /// Both, because they answer different questions. The daemon's log is the
    /// history an operator's tooling already points at; the tail is what
    /// `synch socket log` can show without asking them to go and find it.
    pub(crate) fn remember_log(&self, line: &str) {
        tracing::info!(
            socket = %self.socket.qualified(),
            invocation = self.id,
            "{line}"
        );
        if let Some(registry) = &self.registry {
            registry.log_line(
                &self.socket.qualified(),
                self.id,
                synch_core::now_ns(),
                line.to_string(),
            );
        }
    }

    /// True if every endpoint has closed, failed, or hung up.
    ///
    /// What the idle deadline is measured against: a program parked in
    /// `sy_poll` with nothing left that can ever become ready is not idle, it
    /// is finished, and it should be told so rather than waited out.
    pub(crate) fn all_quiet(&self) -> bool {
        let slots = self.slots.borrow();
        slots.iter().flatten().all(|slot| match slot {
            Slot::Endpoint(ep) => match ep.state() {
                State::Failed | State::Closed => true,
                State::Connecting => false,
                State::Open => ep.revents() & poll::HUP != 0,
            },
            // An object or a cursor with an answer waiting is not quiet.
            other => other.revents() == 0,
        })
    }
}

/// A handle's target, cloned out of the table so the borrow can be dropped.
#[derive(Debug)]
pub(crate) enum Slot2 {
    Endpoint(Rc<Endpoint>),
    Object(Rc<ObjectSlot>),
    Cursor(Rc<CursorSlot>),
}

/// Replaces anything a terminal should not be asked to render.
///
/// A guest chooses these bytes, and they land in an operator's log: escape
/// sequences, and anything that is not printable ASCII, become `?`.
pub(crate) fn sanitize(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| match b {
            b'\t' => '\t',
            0x20..=0x7e => *b as char,
            _ => '?',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_line_cannot_carry_an_escape_sequence_into_a_terminal() {
        assert_eq!(sanitize(b"ok"), "ok");
        assert_eq!(sanitize(b"\x1b[31mred"), "?[31mred");
        assert_eq!(sanitize("héllo".as_bytes()), "h??llo");
        assert_eq!(sanitize(b"a\tb"), "a\tb");
    }
}
