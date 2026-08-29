//! SSH protocol termination and the bounded event bridge to one guest.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use russh::{
    keys::{Algorithm, Certificate, PrivateKey, PublicKey},
    server::{Auth, ChannelOpenHandle, Handler, Msg, Session},
    Channel, ChannelId, ChannelOpenFailure, Pty, Sig,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{oneshot, Notify},
};

use crate::{
    limits::{
        AUTH_REJECTION_WINDOW_SECS, LANE_SEND_TIMEOUT_MS, MAX_AUTH_REJECTIONS_PER_IP,
        MAX_AUTH_REJECTIONS_PER_WINDOW, MAX_AUTH_USERNAME_BYTES, MAX_DISCARDED_LANES_PER_CHANNEL,
        MAX_OUTSTANDING_REQUESTS_PER_CHANNEL,
    },
    runtime::endpoint::Readiness,
};

pub(crate) const AUTH_NONE: u64 = 0x01;
pub(crate) const AUTH_PUBLICKEY: u64 = 0x02;
pub(crate) const AUTH_PASSWORD: u64 = 0x04;
pub(crate) const AUTH_ALL: u64 = AUTH_NONE | AUTH_PUBLICKEY | AUTH_PASSWORD;

/// Bridges one SSH channel to its guest endpoint while keeping half-close and
/// handle close distinct.
///
/// EOF in either direction leaves the other direction live. Only the explicit
/// notification from `sy_close(channel)` stops client input early; even then,
/// output already accepted from the guest drains before the channel is dropped
/// and emits CHANNEL_CLOSE.
pub(crate) async fn bridge_channel(
    channel: Channel<Msg>,
    bridge: tokio::io::DuplexStream,
    guest_closed: Arc<Notify>,
) {
    let (mut channel_read, mut channel_write) = tokio::io::split(channel.into_stream());
    let (mut guest_read, mut guest_write) = tokio::io::split(bridge);

    let guest_to_client = async {
        let _ = tokio::io::copy(&mut guest_read, &mut channel_write).await;
        let _ = channel_write.shutdown().await;
    };
    let client_to_guest = async {
        let _ = tokio::io::copy(&mut channel_read, &mut guest_write).await;
        let _ = guest_write.shutdown().await;
    };
    tokio::pin!(guest_to_client, client_to_guest);
    let closed = guest_closed.notified();
    tokio::pin!(closed);

    tokio::select! {
        () = &mut guest_to_client => {
            // `sy_shutdown` is only output EOF. Continue accepting client
            // input until it too ends or the guest closes the handle.
            tokio::select! {
                () = &mut client_to_guest => {}
                () = &mut closed => {}
            }
        }
        () = &mut client_to_guest => {
            // Client EOF is only a half-close. Keep forwarding output until
            // the guest sends EOF; an explicit close still drains that output.
            tokio::select! {
                () = &mut guest_to_client => {}
                () = &mut closed => guest_to_client.await,
            }
        }
        () = &mut closed => guest_to_client.await,
    }
}

pub(crate) const EVENT_AUTH_NONE: u32 = 1;
pub(crate) const EVENT_AUTH_PASSWORD: u32 = 2;
pub(crate) const EVENT_AUTH_PUBLICKEY_OFFER: u32 = 3;
pub(crate) const EVENT_AUTH_PUBLICKEY_VERIFIED: u32 = 4;
pub(crate) const EVENT_AUTHENTICATED: u32 = 5;
// 9, not 5: 5 is EVENT_AUTHENTICATED, and event kinds are a shared ABI.
// A certificate authentication is a real authentication: russh has validated
// its structure and signatures, while the guest must authorize its CA. It is
// not a public-key probe/offer.
pub(crate) const EVENT_AUTH_OPENSSH_CERT: u32 = 9;
pub(crate) const EVENT_CHANNEL_OPEN: u32 = 6;
pub(crate) const EVENT_CHANNEL_REQUEST: u32 = 7;
pub(crate) const EVENT_CHANNEL_EXTENDED_DATA: u32 = 8;

pub(crate) const FIELD_USERNAME: u32 = 1;
pub(crate) const FIELD_SERVICE: u32 = 2;
pub(crate) const FIELD_PASSWORD: u32 = 3;
pub(crate) const FIELD_PUBLIC_KEY_ALGORITHM: u32 = 4;
pub(crate) const FIELD_PUBLIC_KEY_BLOB: u32 = 5;
pub(crate) const FIELD_PUBLIC_KEY_SHA256: u32 = 6;
pub(crate) const FIELD_COMMAND: u32 = 8;
pub(crate) const FIELD_SUBSYSTEM: u32 = 9;
pub(crate) const FIELD_CHANNEL_TYPE: u32 = 10;
pub(crate) const FIELD_CHANNEL_OPEN_DATA: u32 = 11;
pub(crate) const FIELD_REQUEST_TYPE: u32 = 12;
pub(crate) const FIELD_REQUEST_DATA: u32 = 13;
pub(crate) const FIELD_DESTINATION_HOST: u32 = 14;
pub(crate) const FIELD_ORIGINATOR_HOST: u32 = 15;
pub(crate) const FIELD_SIGNAL: u32 = 16;
pub(crate) const FIELD_TERMINAL: u32 = 17;
pub(crate) const FIELD_ENV_NAME: u32 = 18;
pub(crate) const FIELD_ENV_VALUE: u32 = 19;
/// The 1-based auth-attempt ordinal for the connection, on every auth event.
pub(crate) const FIELD_AUTH_ATTEMPTS: u32 = 20;
/// Present on certificate auth events and on publickey offers that were
/// backed by an OpenSSH certificate.
pub(crate) const FIELD_AUTH_CERT_FLAG: u32 = 21;
/// SSH wire blob of the certificate's signing CA public key.
pub(crate) const FIELD_AUTH_CERT_CA_PUBLIC_KEY_BLOB: u32 = 22;
/// SHA-256 digest of [`FIELD_AUTH_CERT_CA_PUBLIC_KEY_BLOB`].
pub(crate) const FIELD_AUTH_CERT_CA_SHA256: u32 = 23;
/// CA-assigned certificate key id.
pub(crate) const FIELD_AUTH_CERT_KEY_ID: u32 = 24;
/// Certificate serial as one little-endian `u64`.
pub(crate) const FIELD_AUTH_CERT_SERIAL: u32 = 25;
/// OpenSSH certificate type as one little-endian `u32` (user=1, host=2).
pub(crate) const FIELD_AUTH_CERT_TYPE: u32 = 26;
/// Principals encoded as repeated little-endian `u32` length plus UTF-8 bytes.
pub(crate) const FIELD_AUTH_CERT_PRINCIPALS: u32 = 27;
/// Complete OpenSSH wire-format certificate blob.
pub(crate) const FIELD_AUTH_CERT_BLOB: u32 = 28;

pub(crate) const EVENT_WANT_REPLY: u32 = 0x01;

const MAX_EVENTS: usize = 32;
const MAX_EVENT_BYTES: usize = 16 * 1024;
const MAX_TOTAL_EVENT_BYTES: usize = 64 * 1024;
const MAX_CHANNELS: u64 = 8;

type LaneKey = (i64, u32);
type LaneBinding = (i64, tokio::sync::mpsc::Sender<Vec<u8>>);

#[derive(Debug)]
pub(crate) enum Decision {
    Auth {
        result: u32,
        next_methods: u64,
    },
    Channel {
        fd: i64,
        bridge: tokio::io::DuplexStream,
    },
    ChannelReject(ChannelOpenFailure),
    Request(bool),
    Done,
}

#[derive(Debug, Clone)]
pub(crate) struct PtyRequest {
    pub(crate) term: String,
    pub(crate) columns: u32,
    pub(crate) rows: u32,
    pub(crate) pixel_width: u32,
    pub(crate) pixel_height: u32,
    pub(crate) modes: Vec<(u8, u32)>,
}

#[derive(Debug)]
pub(crate) struct Event {
    pub(crate) id: u64,
    pub(crate) fd: i64,
    pub(crate) kind: u32,
    pub(crate) flags: u32,
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) d: u32,
    pub(crate) fields: BTreeMap<u32, Vec<u8>>,
    pub(crate) pty: Option<PtyRequest>,
    response: Option<oneshot::Sender<Decision>>,
}

impl Event {
    fn payload_len(&self) -> usize {
        self.fields.values().map(Vec::len).sum()
    }

    fn auth(kind: u32, username: &str, response: oneshot::Sender<Decision>) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_USERNAME, username.as_bytes().to_vec());
        fields.insert(FIELD_SERVICE, b"ssh-connection".to_vec());
        Self {
            id: 0,
            fd: -1,
            kind,
            flags: 0,
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            fields,
            pty: None,
            response: Some(response),
        }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        if self.kind == EVENT_AUTH_PASSWORD {
            if let Some(password) = self.fields.get_mut(&FIELD_PASSWORD) {
                password.fill(0);
            }
        }
    }
}

#[derive(Debug, Default)]
struct EventStore {
    queued: VecDeque<Event>,
    outstanding: HashMap<u64, Event>,
    payload_bytes: usize,
}

#[derive(Debug)]
struct ChannelBinding {
    id: ChannelId,
    kind: String,
    guest_closed: Arc<Notify>,
}

/// One activated SSH connection as seen by fd zero.
#[derive(Debug)]
pub(crate) struct SshState {
    events: Mutex<EventStore>,
    next_event: AtomicU64,
    ready: Arc<Readiness>,
    closed: AtomicU64,
    /// Claimed by the one close whose errno sticks; see [`SshState::close`].
    close_claimed: AtomicU64,
    errno: AtomicI64,
    session: Mutex<Option<russh::server::Handle>>,
    channels: Mutex<HashMap<i64, ChannelBinding>>,
    channel_slots: AtomicU64,
    lanes: Mutex<HashMap<LaneKey, LaneBinding>>,
    discarded_lanes: Mutex<HashSet<LaneKey>>,
    request_order: Mutex<HashMap<ChannelId, Arc<tokio::sync::Mutex<()>>>>,
    /// CHANNEL_REQUEST tasks currently parked per channel (bounded at
    /// MAX_OUTSTANDING_REQUESTS_PER_CHANNEL).
    requests: Mutex<HashMap<ChannelId, usize>>,
    /// Abort handles for those tasks, so closing a channel cancels its parked
    /// decisions before the numeric channel id can be reused.
    request_tasks: Mutex<HashMap<ChannelId, Vec<tokio::task::AbortHandle>>>,
    /// Ownership tokens binding an accepted channel's event to its endpoint
    /// fd, so a closed-and-reused fd can never capture a stale registration.
    accepts: Mutex<HashMap<i64, u64>>,
    /// Exit-status/exit-signal deliveries that could not be sent to the
    /// client; surfaced to the guest through `sy_ssh_exit_status_lost`.
    lost_exit_deliveries: AtomicU64,
    tasks: super::tasks::TaskSet,
}

/// One live slot in a channel's outstanding-request budget.
struct RequestGuard {
    state: Arc<SshState>,
    channel: ChannelId,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.state.dec_request(self.channel);
    }
}

impl SshState {
    pub(crate) fn new(ready: Arc<Readiness>) -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(EventStore::default()),
            next_event: AtomicU64::new(1),
            ready,
            closed: AtomicU64::new(0),
            close_claimed: AtomicU64::new(0),
            errno: AtomicI64::new(0),
            session: Mutex::new(None),
            channels: Mutex::new(HashMap::new()),
            channel_slots: AtomicU64::new(0),
            lanes: Mutex::new(HashMap::new()),
            discarded_lanes: Mutex::new(HashSet::new()),
            request_order: Mutex::new(HashMap::new()),
            requests: Mutex::new(HashMap::new()),
            request_tasks: Mutex::new(HashMap::new()),
            accepts: Mutex::new(HashMap::new()),
            lost_exit_deliveries: AtomicU64::new(0),
            tasks: super::tasks::TaskSet::default(),
        })
    }

    /// The refused event comes back boxed so the caller can retry it when the
    /// budget is transient backpressure rather than a hard refusal.
    ///
    /// A closed connection refuses everything: the guest's fd zero is gone,
    /// so an event pushed after `close` could never be answered and would
    /// park its handler on the full decision deadline for nothing.
    fn push(&self, mut event: Event) -> Result<u64, Box<Event>> {
        if self.is_closed() {
            return Err(Box::new(event));
        }
        let bytes = event.payload_len();
        if bytes > MAX_EVENT_BYTES {
            return Err(Box::new(event));
        }
        let mut store = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if store.queued.len() + store.outstanding.len() >= MAX_EVENTS
            || store.payload_bytes.saturating_add(bytes) > MAX_TOTAL_EVENT_BYTES
        {
            drop(store);
            return Err(Box::new(event));
        }
        event.id = self.next_event.fetch_add(1, Ordering::Relaxed).max(1);
        let id = event.id;
        store.payload_bytes += bytes;
        store.queued.push_back(event);
        drop(store);
        self.ready.bump();
        Ok(id)
    }

    pub(crate) fn next(&self) -> Option<EventHeader> {
        let mut store = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let event = store.queued.pop_front()?;
        let header = EventHeader::from(&event);
        store.outstanding.insert(event.id, event);
        Some(header)
    }

    pub(crate) fn field(&self, id: u64, field: u32) -> Option<Vec<u8>> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outstanding
            .get(&id)?
            .fields
            .get(&field)
            .cloned()
    }

    pub(crate) fn pty(&self, id: u64) -> Option<PtyRequest> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outstanding
            .get(&id)?
            .pty
            .clone()
    }

    pub(crate) fn event_kind(&self, id: u64) -> Option<u32> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outstanding
            .get(&id)
            .map(|event| event.kind)
    }

    pub(crate) fn reply(&self, id: u64, decision: Decision) -> Result<(), ()> {
        let mut store = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut event) = store.outstanding.remove(&id) else {
            return Err(());
        };
        store.payload_bytes = store.payload_bytes.saturating_sub(event.payload_len());
        let response = event.response.take();
        drop(store);
        if let Some(response) = response {
            response.send(decision).map_err(|_| ())?;
        }
        Ok(())
    }

    fn cancel_event(&self, id: u64) {
        let mut store = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let event = store.outstanding.remove(&id).or_else(|| {
            let position = store.queued.iter().position(|event| event.id == id)?;
            store.queued.remove(position)
        });
        if let Some(event) = event {
            store.payload_bytes = store.payload_bytes.saturating_sub(event.payload_len());
        }
    }

    pub(crate) fn revents(&self) -> u32 {
        let store = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bits = if store.queued.is_empty() {
            0
        } else {
            crate::abi::poll::IN
        };
        if self.closed.load(Ordering::Acquire) != 0 {
            bits |= crate::abi::poll::HUP;
            if self.errno() != 0 {
                bits |= crate::abi::poll::ERR;
            }
        }
        bits
    }

    pub(crate) fn errno(&self) -> i64 {
        self.errno.load(Ordering::Acquire)
    }

    /// Sends a best-effort orderly SSH disconnect to the peer.
    ///
    /// What `sy_close` on the control fd asks for: the SSH counterpart of
    /// closing the raw stream. The message races connection teardown and may
    /// be lost; the local state is authoritative either way.
    pub(crate) fn disconnect(&self) {
        if let Some(session) = self.session() {
            tokio::spawn(async move {
                let _ = session
                    .disconnect(
                        russh::Disconnect::ByApplication,
                        String::new(),
                        String::new(),
                    )
                    .await;
            });
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) != 0
    }

    /// The first close wins: a guest that ended the connection cleanly with
    /// `sy_close` must not have its errno rewritten when the serve task
    /// notices the transport going away moments later. The claim is separate
    /// from `closed` so the errno is in place before `revents` can report
    /// `HUP` — a reader that sees the end also sees why.
    pub(crate) fn close(&self, errno: i64) {
        if self.close_claimed.swap(1, Ordering::AcqRel) != 0 {
            return;
        }
        self.errno.store(errno, Ordering::Release);
        self.closed.store(1, Ordering::Release);
        let mut store = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.queued.clear();
        store.outstanding.clear();
        store.payload_bytes = 0;
        drop(store);
        // The aborting tasks below would otherwise leave their counts and
        // tokens behind; the state is dead after close, but the maps must not
        // retain them.
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.request_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.accepts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.tasks.abort_all();
        self.ready.bump();
    }

    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        let task = tokio::spawn(future);
        self.tasks.track(task.abort_handle());
    }

    /// Spawns a channel-request decision task and binds its lifetime to the
    /// channel. Closing the channel aborts the task, drops its request guard,
    /// and prevents a late reply from being delivered to a reused channel id.
    fn spawn_request(
        &self,
        channel: ChannelId,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let task = tokio::spawn(future);
        let abort = task.abort_handle();
        self.tasks.track(abort.clone());
        let mut request_tasks = self
            .request_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let channel_tasks = request_tasks.entry(channel).or_default();
        channel_tasks.retain(|task| !task.is_finished());
        channel_tasks.push(abort);
    }

    fn set_session(&self, handle: russh::server::Handle) {
        *self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
    }

    /// Registers `fd` as the guest-visible endpoint of channel `id`.
    ///
    /// Inbound accepts carry an ownership token: the event id of the channel
    /// open that produced the fd (recorded by `note_accept`). Registration is
    /// refused when the token is missing or stale — the fd was closed and
    /// possibly reused by a different accept — so one channel's data can never
    /// be routed to another channel's fd. The outbound path (`expected: None`)
    /// registers without a token, since its registration is synchronous in its
    /// own task. Returns the close notification when registration happened.
    fn register_channel(
        &self,
        fd: i64,
        id: ChannelId,
        channel_type: &str,
        expected: Option<u64>,
    ) -> Option<Arc<Notify>> {
        if let Some(expected) = expected {
            let mut accepts = self
                .accepts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if accepts.get(&fd) != Some(&expected) {
                // The guest reserved a channel slot before creating the fd.
                // If the fd was closed before this asynchronous registration
                // ran, no entry was ever installed in `channels`, so the close
                // path had nothing from which to release that reservation.
                self.release_channel();
                return None;
            }
            // The token is single-use: consumed by the successful
            // registration, and invalidated by `remove_channel_fd` on close.
            accepts.remove(&fd);
        }
        let guest_closed = Arc::new(Notify::new());
        self.channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                fd,
                ChannelBinding {
                    id,
                    kind: channel_type.to_string(),
                    guest_closed: guest_closed.clone(),
                },
            );
        Some(guest_closed)
    }

    /// Binds the accepted channel event `event_id` to its endpoint fd.
    ///
    /// Called by the guest-side accept helper immediately after the endpoint
    /// slot is allocated and before the accept decision is replied.
    pub(crate) fn note_accept(&self, fd: i64, event_id: u64) {
        self.accepts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(fd, event_id);
    }

    /// Drops the ownership token for `fd` (accept-reply error path).
    pub(crate) fn forget_accept(&self, fd: i64) {
        self.accepts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&fd);
    }

    /// Reserves one outstanding CHANNEL_REQUEST slot for `id`.
    fn try_request(self: &Arc<Self>, id: ChannelId) -> Option<RequestGuard> {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = requests.entry(id).or_insert(0);
        if *count >= MAX_OUTSTANDING_REQUESTS_PER_CHANNEL {
            return None;
        }
        *count += 1;
        Some(RequestGuard {
            state: self.clone(),
            channel: id,
        })
    }

    /// Uncounts one outstanding CHANNEL_REQUEST for `id`.
    fn dec_request(&self, id: ChannelId) {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match requests.get_mut(&id) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                requests.remove(&id);
            }
            None => {}
        }
    }

    /// Counts an exit-status/exit-signal delivery that could not be sent.
    pub(crate) fn note_lost_exit_delivery(&self) {
        self.lost_exit_deliveries.fetch_add(1, Ordering::Relaxed);
    }

    /// How many exit-status/exit-signal deliveries were lost so far.
    pub(crate) fn lost_exit_deliveries(&self) -> u64 {
        self.lost_exit_deliveries.load(Ordering::Relaxed)
    }

    fn remove_channel_id(&self, id: ChannelId) {
        let before = self
            .channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut channels = before;
        let len = channels.len();
        channels.retain(|_, binding| binding.id != id);
        if channels.len() != len {
            self.release_channel();
        }
        self.request_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        if let Some(tasks) = self
            .request_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id)
        {
            for task in tasks {
                task.abort();
            }
        }
    }

    pub(crate) fn remove_channel_fd(&self, fd: i64) {
        let removed = self
            .channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&fd);
        if let Some(binding) = removed {
            // `notify_one` retains a permit if registration won the race but
            // the bridge task has not started waiting yet.
            binding.guest_closed.notify_one();
            self.release_channel();
            self.request_order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&binding.id);
            if let Some(tasks) = self
                .request_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&binding.id)
            {
                for task in tasks {
                    task.abort();
                }
            }
        }
        self.lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(parent, _), (lane, _)| *parent != fd && *lane != fd);
        self.discarded_lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(parent, _)| *parent != fd);
        // A closed fd loses its accept token: a later accept that reuses the
        // slot starts from a clean slate.
        self.accepts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&fd);
    }

    pub(crate) fn reserve_channel(&self) -> bool {
        self.channel_slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |open| {
                (open < MAX_CHANNELS).then_some(open + 1)
            })
            .is_ok()
    }

    pub(crate) fn release_channel(&self) {
        let _ = self
            .channel_slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |open| {
                (open > 0).then_some(open - 1)
            });
    }

    pub(crate) fn channel(&self, fd: i64) -> Option<(russh::server::Handle, ChannelId, String)> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()?;
        let channels = self
            .channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let binding = channels.get(&fd)?;
        Some((session, binding.id, binding.kind.clone()))
    }

    fn fd_for_channel(&self, id: ChannelId) -> Option<i64> {
        self.channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find_map(|(fd, binding)| (binding.id == id).then_some(*fd))
    }

    fn request_order(&self, id: ChannelId) -> Arc<tokio::sync::Mutex<()>> {
        self.request_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    pub(crate) fn session(&self) -> Option<russh::server::Handle> {
        self.session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn add_outbound_channel(
        &self,
        fd: i64,
        id: ChannelId,
        channel_type: &str,
    ) -> Arc<Notify> {
        // The outbound path is synchronous in its own task; no ownership
        // token is needed (None registers unconditionally).
        self.register_channel(fd, id, channel_type, None)
            .expect("outbound registration has no ownership token to reject")
    }

    pub(crate) fn register_lane(
        &self,
        fd: i64,
        data_type: u32,
        lane_fd: i64,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        self.lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((fd, data_type), (lane_fd, sender));
        self.discarded_lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(fd, data_type));
        if let Some(event_id) = self.extended_event(fd, data_type) {
            let _ = self.reply(event_id, Decision::Done);
        }
    }

    pub(crate) fn lane_handle(&self, fd: i64, data_type: u32) -> Option<i64> {
        self.lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(fd, data_type))
            .map(|(handle, _)| *handle)
    }

    fn lane(&self, fd: i64, data_type: u32) -> Option<tokio::sync::mpsc::Sender<Vec<u8>>> {
        self.lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(fd, data_type))
            .map(|(_, sender)| sender.clone())
    }

    fn remove_lane_if(
        &self,
        fd: i64,
        data_type: u32,
        expected: &tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        let mut lanes = self
            .lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lanes
            .get(&(fd, data_type))
            .is_some_and(|(_, current)| current.same_channel(expected))
        {
            lanes.remove(&(fd, data_type));
        }
    }

    fn extended_event(&self, fd: i64, data_type: u32) -> Option<u64> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outstanding
            .values()
            .find(|event| {
                event.kind == EVENT_CHANNEL_EXTENDED_DATA && event.fd == fd && event.a == data_type
            })
            .map(|event| event.id)
    }

    fn lane_discarded(&self, fd: i64, data_type: u32) -> bool {
        self.discarded_lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&(fd, data_type))
    }

    /// Remembers that the guest declined a lane, so the same `data_type` does
    /// not raise a second event.
    ///
    /// Bounded per channel: `data_type` is wire-controlled and the event
    /// carries no payload, so this set is the one piece of per-connection
    /// state a client could otherwise grow for free
    /// ([`MAX_DISCARDED_LANES_PER_CHANNEL`]). Past the cap nothing is
    /// remembered — the bytes are discarded either way, and re-offering an
    /// event is governed by the event queue's own bounds.
    fn discard_lane(&self, fd: i64, data_type: u32) {
        let mut discarded = self
            .discarded_lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if discarded.iter().filter(|(seen, _)| *seen == fd).count()
            >= MAX_DISCARDED_LANES_PER_CHANNEL
        {
            return;
        }
        discarded.insert((fd, data_type));
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EventHeader {
    pub(crate) id: u64,
    pub(crate) fd: i64,
    pub(crate) kind: u32,
    pub(crate) flags: u32,
    pub(crate) data_len: u32,
    pub(crate) aux_len: u32,
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) d: u32,
}

impl From<&Event> for EventHeader {
    fn from(event: &Event) -> Self {
        let mut lengths = event.fields.values().map(Vec::len);
        Self {
            id: event.id,
            fd: event.fd,
            kind: event.kind,
            flags: event.flags,
            data_len: lengths.next().unwrap_or(0) as u32,
            aux_len: lengths.next().unwrap_or(0) as u32,
            a: event.a,
            b: event.b,
            c: event.c,
            d: event.d,
        }
    }
}

/// The method name-list advertised to the client in `USERAUTH_FAILURE`.
///
/// `none` is deliberately never in it: RFC 4252 §5.2 forbids listing `none`
/// as a supported method. The `SY_SSH_AUTH_NONE` bit controls only whether a
/// `none` *attempt* may reach the guest and be accepted.
fn advertised_methods(bits: u64) -> russh::MethodSet {
    let mut methods = russh::MethodSet::empty();
    if bits & AUTH_PUBLICKEY != 0 {
        methods.push(russh::MethodKind::PublicKey);
    }
    if bits & AUTH_PASSWORD != 0 {
        methods.push(russh::MethodKind::Password);
    }
    methods
}

/// The method bit an authentication event kind belongs to.
fn method_bit(kind: u32) -> u64 {
    match kind {
        EVENT_AUTH_NONE => AUTH_NONE,
        EVENT_AUTH_PASSWORD => AUTH_PASSWORD,
        _ => AUTH_PUBLICKEY,
    }
}

/// Host-side, cross-connection throttle on authentication rejections.
///
/// Rejections are remembered over a sliding window, per peer IP and per
/// socket; when either cap is reached further attempts are refused without
/// consulting the guest — fail-closed against online brute force that would
/// otherwise pace itself with one fresh connection per batch. A guest that
/// accepts everything is never throttled: that is the guest's own policy.
///
/// One throttle serves the whole daemon pool, so *which* counters an attempt
/// is measured against decides who a flood can hurt. Both are scoped to
/// something the attacker has to own:
///
/// * per IP, across every socket, because that is the attacker's own axis and
///   moving between sockets must not buy a fresh budget;
/// * per socket, across every IP, as the backstop against a distributed
///   flood — but *per socket*, not node-wide.
///
/// The node-wide total this replaces made one socket's attacker everybody's
/// problem: four IPs spending 16 rejections each inside the window filled a
/// 64-entry global bucket, and for the rest of that window every SSH socket on
/// the node refused every authentication attempt, `none` included. That is a
/// node-wide outage for about one attempt per second of effort. Scoping the
/// backstop per socket keeps the protection and confines the damage to the
/// socket actually under attack.
#[derive(Debug, Default)]
pub(crate) struct AuthThrottle {
    inner: Mutex<VecDeque<Rejection>>,
}

/// One remembered rejection.
#[derive(Debug)]
struct Rejection {
    at: Instant,
    ip: String,
    socket: String,
}

/// The most rejections retained across all sockets and IPs.
///
/// Bookkeeping only, not an admission rule: with per-socket windows the deque
/// grows with the number of sockets under attack, and something has to bound
/// it. Generous enough that no legitimate per-socket or per-IP window is ever
/// evicted early by it.
const MAX_RETAINED_REJECTIONS: usize = 4096;

impl AuthThrottle {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Records one rejected auth attempt from `ip` against `socket`.
    pub(crate) fn note_rejection(&self, socket: &str, ip: &str) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.push_back(Rejection {
            at: Instant::now(),
            ip: ip.to_string(),
            socket: socket.to_string(),
        });
        while inner.len() > MAX_RETAINED_REJECTIONS {
            inner.pop_front();
        }
    }

    /// Whether another auth attempt from `ip` against `socket` is admitted.
    ///
    /// Entries older than the window are evicted; admission requires both the
    /// per-IP total and this socket's total to be under their caps.
    pub(crate) fn admit(&self, socket: &str, ip: &str) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        let cutoff = now
            .checked_sub(Duration::from_secs(AUTH_REJECTION_WINDOW_SECS))
            .unwrap_or(now);
        inner.retain(|entry| entry.at >= cutoff);
        let per_ip = inner.iter().filter(|entry| entry.ip == ip).count();
        let per_socket = inner.iter().filter(|entry| entry.socket == socket).count();
        per_ip < MAX_AUTH_REJECTIONS_PER_IP && per_socket < MAX_AUTH_REJECTIONS_PER_WINDOW
    }
}

#[derive(Debug)]
struct SshHandler {
    state: Arc<SshState>,
    username: Option<String>,
    /// The methods the guest currently permits: `sy_ssh_start`'s initial set,
    /// then whatever `next_methods` the last rejection or partial success
    /// named. An attempt outside this set is rejected without waking the
    /// guest — the guest, not the client, chooses what may be attempted.
    methods: u64,
    throttle: Arc<AuthThrottle>,
    ip: String,
    /// Which socket this connection is serving, as the throttle's per-socket
    /// window is keyed.
    socket: String,
    /// 1-based count of auth attempts on this connection, as the guest sees
    /// them in FIELD_AUTH_ATTEMPTS.
    attempts: u64,
}

impl SshHandler {
    async fn auth(&mut self, event: Event) -> Result<Auth, russh::Error> {
        if self.methods & method_bit(event.kind) == 0 {
            return Ok(Auth::Reject {
                proceed_with_methods: Some(advertised_methods(self.methods)),
                partial_success: false,
            });
        }
        if !self.throttle.admit(&self.socket, &self.ip) {
            // Fail-closed under a rejection flood: the guest is not consulted
            // when the host-side throttle is exhausted.
            return Ok(Auth::Reject {
                proceed_with_methods: Some(advertised_methods(self.methods)),
                partial_success: false,
            });
        }
        if self
            .username
            .as_ref()
            .is_some_and(|username| event.fields[&FIELD_USERNAME] != username.as_bytes())
        {
            return Err(russh::Error::Disconnect);
        }
        if self
            .username
            .as_ref()
            .is_some_and(|u| u.len() > MAX_AUTH_USERNAME_BYTES)
            || (self.username.is_none()
                && event.fields[&FIELD_USERNAME].len() > MAX_AUTH_USERNAME_BYTES)
        {
            // An oversized wire-controlled username is an ordinary auth
            // failure, never a disconnect: a one-packet pre-auth connection
            // kill must not be possible. russh drops the method, fail-closed.
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
        if self.username.is_none() {
            self.username = Some(String::from_utf8_lossy(&event.fields[&FIELD_USERNAME]).into());
        }
        let (tx, rx) = oneshot::channel();
        let mut event = event;
        event.response = Some(tx);
        self.attempts += 1;
        event
            .fields
            .insert(FIELD_AUTH_ATTEMPTS, self.attempts.to_le_bytes().to_vec());
        let event_id = match self.state.push(event) {
            Ok(id) => id,
            Err(_) => {
                // The event store is full or the payload is over cap (an
                // oversized publickey blob): an ordinary auth failure, never
                // a disconnect. The store must never be a new way to kill the
                // connection.
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }
        };
        let decision = match tokio::time::timeout(Duration::from_secs(60), rx).await {
            Ok(Ok(decision)) => decision,
            _ => {
                self.state.cancel_event(event_id);
                return Err(russh::Error::Disconnect);
            }
        };
        let Decision::Auth {
            result,
            next_methods,
        } = decision
        else {
            return Err(russh::Error::Disconnect);
        };
        let auth = match result {
            1 => Auth::Accept,
            3 => {
                self.methods = next_methods;
                Auth::Reject {
                    proceed_with_methods: Some(advertised_methods(next_methods)),
                    partial_success: true,
                }
            }
            _ => {
                self.methods = next_methods;
                Auth::Reject {
                    proceed_with_methods: Some(advertised_methods(next_methods)),
                    partial_success: false,
                }
            }
        };
        if !matches!(auth, Auth::Accept) {
            // Partial-success rejections count as failures for the throttle.
            self.throttle.note_rejection(&self.socket, &self.ip);
        }
        Ok(auth)
    }

    async fn open_channel(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        channel_type: &str,
        fields: BTreeMap<u32, Vec<u8>>,
        a: u32,
        b: u32,
    ) -> Result<(), russh::Error> {
        let mut event = Event {
            id: 0,
            fd: -1,
            kind: EVENT_CHANNEL_OPEN,
            flags: 0,
            a,
            b,
            c: 0,
            d: 0,
            fields,
            pty: None,
            response: None,
        };
        event
            .fields
            .insert(FIELD_CHANNEL_TYPE, channel_type.as_bytes().to_vec());
        let (tx, rx) = oneshot::channel();
        event.response = Some(tx);
        // A full event budget rejects this one open rather than ending the
        // connection: the client is told "resource shortage", exactly as if
        // the guest had run out of channel slots (§9).
        let event_id = match self.state.push(event) {
            Ok(id) => id,
            Err(_) => {
                reply.reject(ChannelOpenFailure::ResourceShortage).await;
                return Ok(());
            }
        };
        let state = self.state.clone();
        let channel_type = channel_type.to_owned();
        self.state.spawn(async move {
            match tokio::time::timeout(Duration::from_secs(60), rx).await {
                Ok(Ok(Decision::Channel { fd, bridge })) => {
                    let Some(guest_closed) =
                        state.register_channel(fd, channel.id(), &channel_type, Some(event_id))
                    else {
                        // The accepted fd was closed or reused since the
                        // accept: its ownership token is gone, so registration
                        // is dropped and the channel is rejected — fail-closed
                        // rather than routing one channel's data to another
                        // channel's fd.
                        reply.reject(ChannelOpenFailure::ResourceShortage).await;
                        return;
                    };
                    reply.accept().await;
                    bridge_channel(channel, bridge, guest_closed).await;
                }
                Ok(Ok(Decision::ChannelReject(reason))) => reply.reject(reason).await,
                _ => {
                    state.cancel_event(event_id);
                    reply.reject(ChannelOpenFailure::ResourceShortage).await;
                }
            }
        });
        Ok(())
    }

    async fn request(
        &self,
        channel: ChannelId,
        request_type: &str,
        fields: BTreeMap<u32, Vec<u8>>,
        pty: Option<PtyRequest>,
        dims: [u32; 4],
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let Ok(reply) = session.take_channel_request_reply(channel) else {
            // A request on a never-opened or already-closed channel: russh
            // already drops CHANNEL_REQUESTs for unestablished channels, and
            // there is no reply token to answer with. Dropping the request is
            // fail-closed behavior, not a disconnect.
            return Ok(());
        };
        let Some(fd) = self.state.fd_for_channel(channel) else {
            reply
                .reply(false)
                .await
                .map_err(|_| russh::Error::Disconnect)?;
            return Ok(());
        };
        // Bound the CHANNEL_REQUEST tasks parked per channel: a client that
        // pipelines requests faster than the guest answers (each decision can
        // take up to 60s) must not grow unbounded task memory. The excess is
        // answered immediately with false, fail-closed; the cap is counted
        // against the parked tasks themselves, not the event store.
        let Some(request_guard) = self.state.try_request(channel) else {
            let _ = tokio::time::timeout(Duration::from_secs(1), reply.reply(false)).await;
            return Ok(());
        };
        let mut event = Event {
            id: 0,
            fd,
            kind: EVENT_CHANNEL_REQUEST,
            flags: if reply.wants_reply() {
                EVENT_WANT_REPLY
            } else {
                0
            },
            a: dims[0],
            b: dims[1],
            c: dims[2],
            d: dims[3],
            fields,
            pty,
            response: None,
        };
        event
            .fields
            .insert(FIELD_REQUEST_TYPE, request_type.as_bytes().to_vec());
        let (tx, rx) = oneshot::channel();
        event.response = Some(tx);
        let state = self.state.clone();
        let order = state.request_order(channel);
        self.state.spawn_request(channel, async move {
            let _request_guard = request_guard;
            let _ordered = order.lock().await;
            let Ok(event_id) = state.push(event) else {
                let _ = reply.reply(false).await;
                return;
            };
            match tokio::time::timeout(Duration::from_secs(60), rx).await {
                Ok(Ok(Decision::Request(true))) => {
                    let _ = reply.reply(true).await;
                }
                _ => {
                    state.cancel_event(event_id);
                    let _ = reply.reply(false).await;
                }
            }
        });
        Ok(())
    }
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        let (tx, _rx) = oneshot::channel();
        self.auth(Event::auth(EVENT_AUTH_NONE, user, tx)).await
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let (tx, _rx) = oneshot::channel();
        let mut event = Event::auth(EVENT_AUTH_PASSWORD, user, tx);
        event
            .fields
            .insert(FIELD_PASSWORD, password.as_bytes().to_vec());
        self.auth(event).await
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let event = public_key_event(EVENT_AUTH_PUBLICKEY_OFFER, user, public_key)?;
        let decision = self.auth(event).await?;
        Ok(match decision {
            Auth::Accept => Auth::Accept,
            other => other,
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth(public_key_event(
            EVENT_AUTH_PUBLICKEY_VERIFIED,
            user,
            public_key,
        )?)
        .await
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        cert: &Certificate,
    ) -> Result<Auth, Self::Error> {
        // russh has validated the certificate structure, user principal,
        // validity, internal signature and the client's possession signature.
        // The event also carries the signing CA identity so the guest can make
        // the distinct trust decision before accepting it.
        self.auth(certificate_event(EVENT_AUTH_OPENSSH_CERT, user, cert)?)
            .await
    }

    async fn auth_publickey_offered_cert(
        &mut self,
        user: &str,
        cert: &Certificate,
    ) -> Result<Auth, Self::Error> {
        // Same event shape as a plain key offer, marked as certificate-backed
        // so the guest can gate offers differently.
        self.auth(certificate_event(EVENT_AUTH_PUBLICKEY_OFFER, user, cert)?)
            .await
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        self.state.set_session(_session.handle());
        let event = Event {
            id: 0,
            fd: -1,
            kind: EVENT_AUTHENTICATED,
            flags: 0,
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            fields: BTreeMap::new(),
            pty: None,
            response: None,
        };
        // Deliberately still a disconnect on push failure: EVENT_AUTHENTICATED
        // is the guest's go-signal, and an undeliverable one must fail the
        // session rather than leave the guest waiting on it forever. Every
        // other push-failure path turns into an ordinary rejection or a
        // bounded discard; this one keeps the fail-closed teardown.
        self.state
            .push(event)
            .map(|_| ())
            .map_err(|_| russh::Error::Disconnect)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.open_channel(channel, reply, "session", BTreeMap::new(), 0, 0)
            .await
    }

    async fn channel_open_x11(
        &mut self,
        channel: Channel<Msg>,
        originator: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_ORIGINATOR_HOST, originator.as_bytes().to_vec());
        fields.insert(
            FIELD_CHANNEL_OPEN_DATA,
            encode_open_data(&[(originator.as_bytes(), None)], &[originator_port]),
        );
        self.open_channel(channel, reply, "x11", fields, originator_port, 0)
            .await
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        originator: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_DESTINATION_HOST, host.as_bytes().to_vec());
        fields.insert(FIELD_ORIGINATOR_HOST, originator.as_bytes().to_vec());
        fields.insert(
            FIELD_CHANNEL_OPEN_DATA,
            encode_tcp_open_data(host, port, originator, originator_port),
        );
        self.open_channel(
            channel,
            reply,
            "direct-tcpip",
            fields,
            port,
            originator_port,
        )
        .await
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        originator: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_DESTINATION_HOST, host.as_bytes().to_vec());
        fields.insert(FIELD_ORIGINATOR_HOST, originator.as_bytes().to_vec());
        fields.insert(
            FIELD_CHANNEL_OPEN_DATA,
            encode_tcp_open_data(host, port, originator, originator_port),
        );
        self.open_channel(
            channel,
            reply,
            "forwarded-tcpip",
            fields,
            port,
            originator_port,
        )
        .await
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let data = encode_open_data(&[(socket_path.as_bytes(), None), (b"", None)], &[0]);
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_DESTINATION_HOST, socket_path.as_bytes().to_vec());
        fields.insert(FIELD_CHANNEL_OPEN_DATA, data);
        self.open_channel(
            channel,
            reply,
            "direct-streamlocal@openssh.com",
            fields,
            0,
            0,
        )
        .await
    }

    async fn channel_open_forwarded_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let data = encode_open_data(&[(socket_path.as_bytes(), None), (b"", None)], &[]);
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_DESTINATION_HOST, socket_path.as_bytes().to_vec());
        fields.insert(FIELD_CHANNEL_OPEN_DATA, data);
        self.open_channel(
            channel,
            reply,
            "forwarded-streamlocal@openssh.com",
            fields,
            0,
            0,
        )
        .await
    }

    async fn channel_open_agent(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.open_channel(
            channel,
            reply,
            "auth-agent@openssh.com",
            BTreeMap::new(),
            0,
            0,
        )
        .await
    }

    async fn channel_open_unknown(
        &mut self,
        channel: Channel<Msg>,
        channel_type: &str,
        payload: &[u8],
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_CHANNEL_OPEN_DATA, payload.to_vec());
        self.open_channel(channel, reply, channel_type, fields, 0, 0)
            .await
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.remove_channel_id(channel);
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        data_type: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(fd) = self.state.fd_for_channel(channel) else {
            return Ok(());
        };
        let mut data = data.to_vec();
        if let Some(lane) = self.state.lane(fd, data_type) {
            let expected = lane.clone();
            match tokio::time::timeout(Duration::from_millis(LANE_SEND_TIMEOUT_MS), lane.send(data))
                .await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => {
                    // The guest may close a lane independently of its parent.
                    // Treat a racing send exactly like the next packet after
                    // that close: forget the stale mapping and offer the bytes
                    // through a fresh extended-data event.
                    self.state.remove_lane_if(fd, data_type, &expected);
                    data = error.0;
                }
                Err(_) => {
                    // Bounded discard: the lane ring is full and the guest is
                    // not draining it. Drop the bytes but keep the lane — the
                    // send must never stall the run loop past the inactivity
                    // timer's polling interval (docs/SSH-SOCKETS.md §14.3).
                    return Ok(());
                }
            }
        }
        if self.state.lane_discarded(fd, data_type) {
            return Ok(());
        }
        // The decision is awaited here, in the connection's own read loop, so
        // an unanswered event stops the transport being read and the sender
        // runs out of window (§6.2) instead of growing a queue of unclaimed
        // packets. At most one packet is held, and the event deadline bounds
        // the wait: a guest that never answers selects bounded discard for
        // this data type rather than ending the connection.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let (tx, mut rx) = oneshot::channel();
        let mut event = Event {
            id: 0,
            fd,
            kind: EVENT_CHANNEL_EXTENDED_DATA,
            flags: 0,
            a: data_type,
            b: 0,
            c: 0,
            d: 0,
            fields: BTreeMap::new(),
            pty: None,
            response: Some(tx),
        };
        let event_id = loop {
            match self.state.push(event) {
                Ok(id) => break id,
                Err(back) => {
                    // A closed connection refuses every push; there is
                    // nothing left to offer the packet to.
                    if self.state.is_closed() {
                        return Ok(());
                    }
                    // The event budget is full of other work. Wait it out
                    // within the same deadline rather than disconnecting;
                    // the packet in hand is the backpressure. The deadline
                    // selects bounded discard (§6.2) here exactly as it does
                    // for an unanswered event below, so a guest that never
                    // drains its queue cannot stall this data type forever.
                    if tokio::time::Instant::now() >= deadline {
                        self.state.discard_lane(fd, data_type);
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    event = *back;
                }
            }
        };
        match tokio::time::timeout_at(deadline, &mut rx).await {
            Ok(Ok(_)) => {
                if let Some(lane) = self.state.lane(fd, data_type) {
                    let _ = tokio::time::timeout(
                        Duration::from_millis(LANE_SEND_TIMEOUT_MS),
                        lane.send(data),
                    )
                    .await;
                } else {
                    self.state.discard_lane(fd, data_type);
                }
            }
            _ => {
                self.state.cancel_event(event_id);
                self.state.discard_lane(fd, data_type);
            }
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        columns: u32,
        rows: u32,
        pixel_width: u32,
        pixel_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let pty = PtyRequest {
            term: term.to_owned(),
            columns,
            rows,
            pixel_width,
            pixel_height,
            modes: modes
                .iter()
                .map(|(mode, value)| (*mode as u8, *value))
                .collect(),
        };
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_TERMINAL, term.as_bytes().to_vec());
        self.request(
            channel,
            "pty-req",
            fields,
            Some(pty),
            [columns, rows, pixel_width, pixel_height],
            session,
        )
        .await
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        single_connection: bool,
        authentication_protocol: &str,
        authentication_cookie: &str,
        screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut payload = vec![u8::from(single_connection)];
        encode_ssh_string(&mut payload, authentication_protocol.as_bytes());
        encode_ssh_string(&mut payload, authentication_cookie.as_bytes());
        payload.extend_from_slice(&screen_number.to_be_bytes());
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_REQUEST_DATA, payload);
        self.request(
            channel,
            "x11-req",
            fields,
            None,
            [screen_number, u32::from(single_connection), 0, 0],
            session,
        )
        .await
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.request(channel, "shell", BTreeMap::new(), None, [0; 4], session)
            .await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_COMMAND, command.to_vec());
        self.request(channel, "exec", fields, None, [0; 4], session)
            .await
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        subsystem: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_SUBSYSTEM, subsystem.as_bytes().to_vec());
        self.request(channel, "subsystem", fields, None, [0; 4], session)
            .await
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_ENV_NAME, name.as_bytes().to_vec());
        fields.insert(FIELD_ENV_VALUE, value.as_bytes().to_vec());
        self.request(channel, "env", fields, None, [0; 4], session)
            .await
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        columns: u32,
        rows: u32,
        pixel_width: u32,
        pixel_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.request(
            channel,
            "window-change",
            BTreeMap::new(),
            None,
            [columns, rows, pixel_width, pixel_height],
            session,
        )
        .await
    }

    async fn agent_request_deferred(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<Option<bool>, Self::Error> {
        self.request(
            channel,
            "auth-agent-req@openssh.com",
            BTreeMap::new(),
            None,
            [0; 4],
            session,
        )
        .await?;
        Ok(None)
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut fields = BTreeMap::new();
        let signal = match signal {
            Sig::ABRT => "ABRT",
            Sig::ALRM => "ALRM",
            Sig::FPE => "FPE",
            Sig::HUP => "HUP",
            Sig::ILL => "ILL",
            Sig::INT => "INT",
            Sig::KILL => "KILL",
            Sig::PIPE => "PIPE",
            Sig::QUIT => "QUIT",
            Sig::SEGV => "SEGV",
            Sig::TERM => "TERM",
            Sig::USR1 => "USR1",
            Sig::Custom(ref name) => name,
        };
        fields.insert(FIELD_SIGNAL, signal.as_bytes().to_vec());
        self.request(channel, "signal", fields, None, [0; 4], session)
            .await
    }

    async fn channel_request_unknown(
        &mut self,
        channel: ChannelId,
        request_type: &str,
        payload: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let dims = match unknown_request_dimensions(request_type, payload) {
            Ok(dims) => dims,
            Err(()) => {
                session
                    .take_channel_request_reply(channel)?
                    .reply(false)
                    .await
                    .map_err(|_| russh::Error::Disconnect)?;
                return Ok(());
            }
        };
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_REQUEST_DATA, payload.to_vec());
        self.request(channel, request_type, fields, None, dims, session)
            .await
    }
}

fn unknown_request_dimensions(request_type: &str, payload: &[u8]) -> Result<[u32; 4], ()> {
    match (request_type, payload) {
        ("break", [a, b, c, d]) => Ok([u32::from_be_bytes([*a, *b, *c, *d]), 0, 0, 0]),
        ("break", _) => Err(()),
        _ => Ok([0; 4]),
    }
}

fn encode_ssh_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn encode_open_data(strings: &[(&[u8], Option<u32>)], trailing: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for (value, number) in strings {
        encode_ssh_string(&mut out, value);
        if let Some(number) = number {
            out.extend_from_slice(&number.to_be_bytes());
        }
    }
    for number in trailing {
        out.extend_from_slice(&number.to_be_bytes());
    }
    out
}

fn encode_tcp_open_data(host: &str, port: u32, originator: &str, originator_port: u32) -> Vec<u8> {
    let mut out = Vec::new();
    encode_ssh_string(&mut out, host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    encode_ssh_string(&mut out, originator.as_bytes());
    out.extend_from_slice(&originator_port.to_be_bytes());
    out
}

fn public_key_event(kind: u32, user: &str, key: &PublicKey) -> Result<Event, russh::Error> {
    let (tx, _rx) = oneshot::channel();
    let mut event = Event::auth(kind, user, tx);
    let blob = key.to_bytes().map_err(|_| russh::Error::Disconnect)?;
    event.fields.insert(
        FIELD_PUBLIC_KEY_ALGORITHM,
        key.algorithm().as_str().as_bytes().to_vec(),
    );
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &blob);
    event.fields.insert(FIELD_PUBLIC_KEY_BLOB, blob);
    event
        .fields
        .insert(FIELD_PUBLIC_KEY_SHA256, digest.as_ref().to_vec());
    Ok(event)
}

/// Builds a certificate auth event with both the subject key and the trust
/// material the guest needs to authorize the signing CA and identity.
fn certificate_event(kind: u32, user: &str, cert: &Certificate) -> Result<Event, russh::Error> {
    let subject = PublicKey::new(cert.public_key().clone(), "");
    let mut event = public_key_event(kind, user, &subject)?;
    let ca = PublicKey::new(cert.signature_key().clone(), "");
    let ca_blob = ca.to_bytes().map_err(|_| russh::Error::Disconnect)?;
    let ca_digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &ca_blob);
    let cert_blob = cert.to_bytes().map_err(|_| russh::Error::Disconnect)?;
    let mut principals = Vec::new();
    for principal in cert.valid_principals() {
        let len = u32::try_from(principal.len()).map_err(|_| russh::Error::Disconnect)?;
        principals.extend_from_slice(&len.to_le_bytes());
        principals.extend_from_slice(principal.as_bytes());
    }
    event.fields.insert(FIELD_AUTH_CERT_FLAG, vec![1]);
    event
        .fields
        .insert(FIELD_AUTH_CERT_CA_PUBLIC_KEY_BLOB, ca_blob);
    event
        .fields
        .insert(FIELD_AUTH_CERT_CA_SHA256, ca_digest.as_ref().to_vec());
    event
        .fields
        .insert(FIELD_AUTH_CERT_KEY_ID, cert.key_id().as_bytes().to_vec());
    event
        .fields
        .insert(FIELD_AUTH_CERT_SERIAL, cert.serial().to_le_bytes().to_vec());
    event.fields.insert(
        FIELD_AUTH_CERT_TYPE,
        u32::from(cert.cert_type()).to_le_bytes().to_vec(),
    );
    event.fields.insert(FIELD_AUTH_CERT_PRINCIPALS, principals);
    event.fields.insert(FIELD_AUTH_CERT_BLOB, cert_blob);
    Ok(event)
}

/// A stream rebuilt from independently boxed read and write halves.
pub(crate) struct JoinedStream {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
}

impl JoinedStream {
    pub(crate) fn new(stream: crate::DuplexStream) -> Self {
        Self {
            reader: stream.reader,
            writer: stream.writer,
        }
    }
}

impl AsyncRead for JoinedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for JoinedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// What the host-side auth throttle measures one connection against.
///
/// The shared counter plus the two axes it is keyed by, together because they
/// are only ever meaningful together: a throttle with no idea which socket or
/// which peer it is pacing is the node-wide bucket this replaced.
pub(crate) struct AuthContext {
    pub(crate) throttle: Arc<AuthThrottle>,
    /// The peer's IP, without its port (`peer_ip`).
    pub(crate) ip: String,
    /// The socket being served, as `space/path`.
    pub(crate) socket: String,
}

pub(crate) async fn serve(
    stream: crate::DuplexStream,
    state: Arc<SshState>,
    host_key: Arc<PrivateKey>,
    methods: u64,
    idle: Duration,
    auth: AuthContext,
) {
    let config = russh::server::Config {
        methods: advertised_methods(methods),
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![(*host_key).clone()],
        window_size: 64 * 1024,
        maximum_packet_size: 32 * 1024,
        channel_buffer_size: 16,
        event_buffer_size: 32,
        max_auth_attempts: 8,
        // The invocation's own idle deadline (`docs/SOCKETS.md` §10), so the
        // SSH transport and the invocation agree about when idle is over.
        inactivity_timeout: Some(idle),
        ..Default::default()
    };
    let handler = SshHandler {
        state: state.clone(),
        username: None,
        methods,
        throttle: auth.throttle,
        ip: auth.ip,
        socket: auth.socket,
        attempts: 0,
    };
    let outcome =
        match russh::server::run_stream(Arc::new(config), JoinedStream::new(stream), handler).await
        {
            Ok(session) => session.await,
            Err(error) => Err(error),
        };
    state.close(classify_outcome(outcome));
}

/// The guest errno for how the SSH connection ended (`docs/SSH-SOCKETS.md`
/// §13): zero for an orderly end — a disconnect message from either side,
/// which includes a guest decision deadline expiring — `SY_ETIMEDOUT` for
/// the transport deadlines, and `SY_ECONNRESET` for everything that broke.
fn classify_outcome(outcome: Result<(), russh::Error>) -> i64 {
    match outcome {
        Ok(()) => 0,
        Err(russh::Error::Disconnect) => 0,
        Err(
            russh::Error::ConnectionTimeout
            | russh::Error::KeepaliveTimeout
            | russh::Error::InactivityTimeout,
        ) => crate::abi::errno::ETIMEDOUT,
        Err(_) => crate::abi::errno::ECONNRESET,
    }
}

pub(crate) fn generate_host_key() -> Result<PrivateKey, russh::keys::ssh_key::Error> {
    PrivateKey::random(&mut rand_10::rng(), Algorithm::Ed25519)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use russh::server::Auth;
    use tokio::sync::oneshot;

    use super::{
        unknown_request_dimensions, AuthThrottle, Event, SshHandler, SshState, EVENT_AUTHENTICATED,
        EVENT_AUTH_NONE, EVENT_AUTH_OPENSSH_CERT, EVENT_AUTH_PUBLICKEY_OFFER,
        EVENT_AUTH_PUBLICKEY_VERIFIED, FIELD_AUTH_ATTEMPTS, FIELD_AUTH_CERT_FLAG,
        MAX_AUTH_USERNAME_BYTES, MAX_EVENTS,
    };
    use crate::{
        limits::{
            AUTH_REJECTION_WINDOW_SECS, MAX_AUTH_REJECTIONS_PER_IP, MAX_AUTH_REJECTIONS_PER_WINDOW,
            MAX_OUTSTANDING_REQUESTS_PER_CHANNEL,
        },
        runtime::endpoint::Readiness,
    };

    #[test]
    fn break_requests_expose_their_typed_duration() {
        assert_eq!(
            unknown_request_dimensions("break", &12_345u32.to_be_bytes()),
            Ok([12_345, 0, 0, 0])
        );
        assert_eq!(
            unknown_request_dimensions("other", &[0, 0, 0, 1]),
            Ok([0; 4])
        );
        assert_eq!(unknown_request_dimensions("break", &[0, 1]), Err(()));
    }

    fn handler_for(state: Arc<SshState>) -> SshHandler {
        SshHandler {
            state,
            username: None,
            methods: super::AUTH_ALL,
            throttle: Arc::new(AuthThrottle::new()),
            ip: "127.0.0.1".to_string(),
            socket: "code/test.sock".to_string(),
            attempts: 0,
        }
    }

    #[test]
    fn auth_throttle_admits_within_window_and_rejects_after() {
        const SOCK: &str = "code/a.sock";
        // admit() does not record; only note_rejection() does, so the cap is
        // reached by the MAX_AUTH_REJECTIONS_PER_IP-th note, not the admit.
        let throttle = AuthThrottle::new();
        let ip = "198.51.100.7";
        for _ in 0..MAX_AUTH_REJECTIONS_PER_IP - 1 {
            throttle.note_rejection(SOCK, ip);
            assert!(
                throttle.admit(SOCK, ip),
                "admitted while under the per-IP cap"
            );
        }
        throttle.note_rejection(SOCK, ip); // the cap-th rejection fills the per-IP cap
        assert!(!throttle.admit(SOCK, ip), "the per-IP cap is full");

        // The per-socket total is a separate bound, reached only when the
        // rejections are spread across more IPs than the per-IP cap.
        let throttle = AuthThrottle::new();
        for index in 0..MAX_AUTH_REJECTIONS_PER_WINDOW - 1 {
            let seen = format!("10.0.0.{index}");
            throttle.note_rejection(SOCK, &seen);
            assert!(throttle.admit(SOCK, &seen));
        }
        throttle.note_rejection(SOCK, "10.0.0.254"); // fills this socket's window
        assert!(
            !throttle.admit(SOCK, "10.0.0.99"),
            "the per-socket total is full"
        );

        // Entries older than the window are evicted, so admits resume — on a
        // fresh throttle (a full window stays full after evicting one entry).
        let throttle = AuthThrottle::new();
        let stale = Instant::now() - Duration::from_secs(AUTH_REJECTION_WINDOW_SECS + 1);
        throttle.inner.lock().unwrap().push_back(super::Rejection {
            at: stale,
            ip: "10.0.0.99".to_string(),
            socket: SOCK.to_string(),
        });
        assert!(
            throttle.admit(SOCK, "10.0.0.99"),
            "stale entries are evicted and admit resumes"
        );
    }

    /// One socket's attacker must not lock out any other socket on the node.
    ///
    /// The backstop used to be a node-wide total: four IPs spending their
    /// per-IP budget filled it, and every SSH socket on the daemon then
    /// refused every authentication attempt for the rest of the window.
    #[test]
    fn a_flood_against_one_socket_does_not_throttle_another() {
        let throttle = AuthThrottle::new();
        const UNDER_ATTACK: &str = "code/exposed.sock";
        const BYSTANDER: &str = "ops/admin.sock";

        // Fill the attacked socket's window, spread across enough IPs that no
        // single per-IP cap is what stops it.
        for index in 0..MAX_AUTH_REJECTIONS_PER_WINDOW {
            throttle.note_rejection(UNDER_ATTACK, &format!("203.0.113.{index}"));
        }
        assert!(
            !throttle.admit(UNDER_ATTACK, "203.0.113.1"),
            "the attacked socket is throttled"
        );

        // The bystander is untouched, including for an IP that was part of the
        // flood: its own per-IP budget there is what governs.
        assert!(
            throttle.admit(BYSTANDER, "198.51.100.4"),
            "an unrelated socket must still authenticate"
        );

        // And an attacker who moves between sockets still spends one per-IP
        // budget rather than a fresh one per socket.
        let throttle = AuthThrottle::new();
        for _ in 0..MAX_AUTH_REJECTIONS_PER_IP {
            throttle.note_rejection(UNDER_ATTACK, "203.0.113.9");
        }
        assert!(
            !throttle.admit(BYSTANDER, "203.0.113.9"),
            "the per-IP cap follows the attacker across sockets"
        );
    }

    #[test]
    fn oversized_username_is_an_auth_failure_not_a_disconnect() {
        let state = SshState::new(Arc::new(Readiness::default()));
        let mut handler = handler_for(state.clone());
        let huge = "u".repeat(MAX_AUTH_USERNAME_BYTES + 1);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = runtime.block_on(async {
            let (tx, _rx) = oneshot::channel();
            handler.auth(Event::auth(EVENT_AUTH_NONE, &huge, tx)).await
        });
        assert!(matches!(
            outcome,
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        ));
        assert!(
            state.next().is_none(),
            "no event was pushed for the oversized username"
        );
        assert_eq!(state.event_kind(1), None, "no event id was consumed");
    }

    #[test]
    fn auth_push_failure_is_a_rejection_not_a_disconnect() {
        let state = SshState::new(Arc::new(Readiness::default()));
        let mut handler = handler_for(state.clone());
        for _ in 0..MAX_EVENTS {
            let (tx, _rx) = oneshot::channel();
            state
                .push(Event::auth(EVENT_AUTH_NONE, "filler", tx))
                .expect("the store accepts MAX_EVENTS events");
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = runtime.block_on(async {
            let (tx, _rx) = oneshot::channel();
            handler.auth(Event::auth(EVENT_AUTH_NONE, "user", tx)).await
        });
        // A full store is an ordinary auth failure, never a disconnect.
        assert!(matches!(outcome, Ok(Auth::Reject { .. })));
        // The 33rd event never entered the store.
        assert_eq!(
            state.next().expect("filler is still queued").kind,
            EVENT_AUTH_NONE
        );
    }

    #[test]
    fn auth_attempts_field_carries_the_1_based_ordinal() {
        let state = SshState::new(Arc::new(Readiness::default()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (tx, _rx) = oneshot::channel();
            let mut handler = handler_for(state.clone());
            let task = tokio::spawn(async move {
                handler.auth(Event::auth(EVENT_AUTH_NONE, "user", tx)).await
            });
            // auth() pushes the event before parking on the guest decision;
            // the guest never answers here, so read the queued event.
            let mut header = None;
            for _ in 0..128 {
                if let Some(next) = state.next() {
                    header = Some(next);
                    break;
                }
                tokio::task::yield_now().await;
            }
            let header = header.expect("the attempt event was queued");
            assert_eq!(state.event_kind(header.id), Some(EVENT_AUTH_NONE));
            assert_eq!(
                state.field(header.id, FIELD_AUTH_ATTEMPTS),
                Some(1u64.to_le_bytes().to_vec()),
                "the first attempt carries ordinal 1"
            );
            task.abort();
        });
    }

    #[test]
    fn auth_reply_gate_accepts_cert_events_and_keeps_offer_accept_on_offers() {
        use crate::runtime::helpers::{auth_reply_result, peer_ip};
        // A certificate-signed event (kind 9), built through the same store
        // the live auth path pushes into: the kind the gate sees is the kind
        // the wire produced, not one the test invented.
        let state = SshState::new(Arc::new(Readiness::default()));
        let (tx, _rx) = oneshot::channel();
        let id = state
            .push(Event::auth(EVENT_AUTH_OPENSSH_CERT, "user", tx))
            .unwrap();
        let header = state.next().expect("the cert event was queued");
        assert_eq!(header.id, id);
        let kind = state.event_kind(id).expect("the cert event is outstanding");
        assert_eq!(kind, EVENT_AUTH_OPENSSH_CERT);
        // Accept, reject and partial are all valid on a cert event: russh has
        // validated its structure and signatures, while the guest owns CA
        // authorization policy.
        assert_eq!(auth_reply_result(kind, 1), Ok(1));
        assert_eq!(auth_reply_result(kind, 2), Ok(2));
        assert_eq!(auth_reply_result(kind, 3), Ok(3));
        // OFFER_ACCEPT (4) is the offer-only pre-signature accept; a cert
        // event must not accept it.
        assert_eq!(
            auth_reply_result(kind, 4),
            Err(crate::abi::errno::ESTATE),
            "OFFER_ACCEPT stays invalid on a signed certificate event"
        );
        // The offer path is unchanged: 4 maps to the library's pre-signature
        // accept, and every other auth kind keeps its own results.
        assert_eq!(auth_reply_result(EVENT_AUTH_PUBLICKEY_OFFER, 4), Ok(1));
        assert_eq!(
            auth_reply_result(EVENT_AUTH_PUBLICKEY_VERIFIED, 4),
            Err(crate::abi::errno::ESTATE)
        );
        // A non-auth kind is still refused outright.
        assert_eq!(
            auth_reply_result(EVENT_AUTHENTICATED, 1),
            Err(crate::abi::errno::ESTATE)
        );

        // The throttle key is the IP, never the "ip:port" address: a
        // reconnect is a fresh port, and a key that included the port would
        // make the per-IP cap unreachable.
        assert_eq!(peer_ip("198.51.100.7:44321"), "198.51.100.7");
        assert_eq!(peer_ip("127.0.0.1"), "127.0.0.1");
        assert_eq!(peer_ip("[2001:db8::1]:44321"), "2001:db8::1");
        assert_eq!(peer_ip("2001:db8::1"), "2001:db8::1");
        assert_eq!(peer_ip("2001:db8::1:44321"), "2001:db8::1:44321");
    }

    #[test]
    fn cert_auth_events_carry_the_cert_kind_and_flag() {
        assert_ne!(
            EVENT_AUTH_OPENSSH_CERT, EVENT_AUTHENTICATED,
            "9 must not collide with EVENT_AUTHENTICATED (5)"
        );
        let state = SshState::new(Arc::new(Readiness::default()));
        let (tx, _rx) = oneshot::channel();
        let mut event = Event::auth(EVENT_AUTH_OPENSSH_CERT, "user", tx);
        event.fields.insert(FIELD_AUTH_CERT_FLAG, vec![1]);
        let id = state.push(event).unwrap();
        let header = state.next().expect("the cert event was queued");
        assert_eq!(header.id, id);
        assert_eq!(
            state.event_kind(id),
            Some(EVENT_AUTH_OPENSSH_CERT),
            "the cert event keeps its kind"
        );
        assert_eq!(
            state.field(id, FIELD_AUTH_CERT_FLAG),
            Some(vec![1]),
            "the cert flag survives the store round trip"
        );
    }

    #[tokio::test]
    async fn closing_a_channel_aborts_and_releases_all_request_tasks() {
        use russh::keys::ssh_key::encoding::Decode;

        let state = SshState::new(Arc::new(Readiness::default()));
        let encoded = 7_u32.to_be_bytes();
        let mut encoded = encoded.as_slice();
        let channel = russh::ChannelId::decode(&mut encoded).unwrap();
        for _ in 0..MAX_OUTSTANDING_REQUESTS_PER_CHANNEL {
            let guard = state.try_request(channel).expect("request slot");
            state.spawn_request(channel, async move {
                let _guard = guard;
                std::future::pending::<()>().await;
            });
        }
        assert!(
            state.try_request(channel).is_none(),
            "the live request tasks fill the per-channel bound"
        );
        state.remove_channel_id(channel);
        for _ in 0..32 {
            if !state.requests.lock().unwrap().contains_key(&channel) {
                break;
            }
            tokio::task::yield_now().await;
        }
        let guards: Vec<_> = (0..MAX_OUTSTANDING_REQUESTS_PER_CHANNEL)
            .map(|_| {
                state
                    .try_request(channel)
                    .expect("aborted tasks release their request slots")
            })
            .collect();
        drop(guards);
    }

    #[tokio::test]
    async fn stale_inbound_accept_releases_its_channel_reservation() {
        use russh::keys::ssh_key::encoding::Decode;

        let state = SshState::new(Arc::new(Readiness::default()));
        let encoded = 11_u32.to_be_bytes();
        let mut encoded = encoded.as_slice();
        let channel = russh::ChannelId::decode(&mut encoded).unwrap();

        assert!(state.reserve_channel());
        state.note_accept(7, 99);
        // This is the race the ownership token protects: the guest closes the
        // newly accepted fd before the SSH task consumes the accept decision.
        state.remove_channel_fd(7);
        assert!(state
            .register_channel(7, channel, "session", Some(99))
            .is_none());

        for _ in 0..super::MAX_CHANNELS {
            assert!(
                state.reserve_channel(),
                "the stale accept must not consume one of the live channel slots"
            );
        }
        assert!(!state.reserve_channel());
    }

    #[tokio::test]
    async fn channel_close_before_bridge_wait_is_not_lost() {
        use russh::keys::ssh_key::encoding::Decode;

        let state = SshState::new(Arc::new(Readiness::default()));
        let encoded = 12_u32.to_be_bytes();
        let mut encoded = encoded.as_slice();
        let channel = russh::ChannelId::decode(&mut encoded).unwrap();

        assert!(state.reserve_channel());
        let guest_closed = state
            .register_channel(7, channel, "session", None)
            .expect("outbound registration cannot be rejected");
        state.remove_channel_fd(7);

        tokio::time::timeout(Duration::from_millis(100), guest_closed.notified())
            .await
            .expect("a close before the bridge starts waiting retains its notification");
    }
}
