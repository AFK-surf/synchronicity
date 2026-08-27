//! SSH protocol termination and the bounded event bridge to one guest.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use russh::{
    keys::{Algorithm, PrivateKey, PublicKey},
    server::{Auth, ChannelOpenHandle, Handler, Msg, Session},
    Channel, ChannelId, ChannelOpenFailure, Pty, Sig,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot,
};

use crate::runtime::endpoint::Readiness;

pub(crate) const AUTH_NONE: u64 = 0x01;
pub(crate) const AUTH_PUBLICKEY: u64 = 0x02;
pub(crate) const AUTH_PASSWORD: u64 = 0x04;
pub(crate) const AUTH_ALL: u64 = AUTH_NONE | AUTH_PUBLICKEY | AUTH_PASSWORD;

pub(crate) const EVENT_AUTH_NONE: u32 = 1;
pub(crate) const EVENT_AUTH_PASSWORD: u32 = 2;
pub(crate) const EVENT_AUTH_PUBLICKEY_OFFER: u32 = 3;
pub(crate) const EVENT_AUTH_PUBLICKEY_VERIFIED: u32 = 4;
pub(crate) const EVENT_AUTHENTICATED: u32 = 5;
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

/// One activated SSH connection as seen by fd zero.
#[derive(Debug)]
pub(crate) struct SshState {
    events: Mutex<EventStore>,
    next_event: AtomicU64,
    ready: Arc<Readiness>,
    closed: AtomicU64,
    errno: AtomicI64,
    session: Mutex<Option<russh::server::Handle>>,
    channels: Mutex<HashMap<i64, (ChannelId, String)>>,
    channel_slots: AtomicU64,
    lanes: Mutex<HashMap<LaneKey, LaneBinding>>,
    discarded_lanes: Mutex<HashSet<LaneKey>>,
    request_order: Mutex<HashMap<ChannelId, Arc<tokio::sync::Mutex<()>>>>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

impl SshState {
    pub(crate) fn new(ready: Arc<Readiness>) -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(EventStore::default()),
            next_event: AtomicU64::new(1),
            ready,
            closed: AtomicU64::new(0),
            errno: AtomicI64::new(0),
            session: Mutex::new(None),
            channels: Mutex::new(HashMap::new()),
            channel_slots: AtomicU64::new(0),
            lanes: Mutex::new(HashMap::new()),
            discarded_lanes: Mutex::new(HashSet::new()),
            request_order: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
        })
    }

    fn push(&self, mut event: Event) -> Result<u64, ()> {
        let bytes = event.payload_len();
        if bytes > MAX_EVENT_BYTES {
            return Err(());
        }
        let mut store = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if store.queued.len() + store.outstanding.len() >= MAX_EVENTS
            || store.payload_bytes.saturating_add(bytes) > MAX_TOTAL_EVENT_BYTES
        {
            return Err(());
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

    pub(crate) fn close(&self, errno: i64) {
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
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
        self.ready.bump();
    }

    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        let task = tokio::spawn(future);
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.is_finished());
        tasks.push(task.abort_handle());
    }

    fn set_session(&self, handle: russh::server::Handle) {
        *self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
    }

    fn register_channel(&self, fd: i64, id: ChannelId, channel_type: &str) {
        self.channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(fd, (id, channel_type.to_string()));
    }

    fn remove_channel_id(&self, id: ChannelId) {
        let before = self
            .channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut channels = before;
        let len = channels.len();
        channels.retain(|_, (candidate, _)| *candidate != id);
        if channels.len() != len {
            self.release_channel();
        }
        self.request_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
    }

    pub(crate) fn remove_channel_fd(&self, fd: i64) {
        let removed = self
            .channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&fd);
        if let Some((id, _)) = removed {
            self.release_channel();
            self.request_order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
        }
        self.lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(parent, _), _| *parent != fd);
        self.discarded_lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(parent, _)| *parent != fd);
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
        let (id, kind) = self
            .channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&fd)
            .cloned()?;
        Some((session, id, kind))
    }

    fn fd_for_channel(&self, id: ChannelId) -> Option<i64> {
        self.channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find_map(|(fd, (candidate, _))| (*candidate == id).then_some(*fd))
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

    pub(crate) fn add_outbound_channel(&self, fd: i64, id: ChannelId, channel_type: &str) {
        self.register_channel(fd, id, channel_type);
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

    fn discard_lane(&self, fd: i64, data_type: u32) {
        self.discarded_lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((fd, data_type));
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

fn method_set(bits: u64) -> russh::MethodSet {
    let mut methods = russh::MethodSet::empty();
    if bits & AUTH_PUBLICKEY != 0 {
        methods.push(russh::MethodKind::PublicKey);
    }
    if bits & AUTH_PASSWORD != 0 {
        methods.push(russh::MethodKind::Password);
    }
    if bits & AUTH_NONE != 0 {
        methods.push(russh::MethodKind::None);
    }
    methods
}

fn auth_from_decision(decision: Decision) -> Result<Auth, russh::Error> {
    let Decision::Auth {
        result,
        next_methods,
    } = decision
    else {
        return Err(russh::Error::Disconnect);
    };
    Ok(match result {
        1 => Auth::Accept,
        3 => Auth::Reject {
            proceed_with_methods: Some(method_set(next_methods)),
            partial_success: true,
        },
        _ => Auth::Reject {
            proceed_with_methods: Some(method_set(next_methods)),
            partial_success: false,
        },
    })
}

#[derive(Debug)]
struct SshHandler {
    state: Arc<SshState>,
    username: Option<String>,
}

impl SshHandler {
    async fn auth(&mut self, event: Event) -> Result<Auth, russh::Error> {
        if self
            .username
            .as_ref()
            .is_some_and(|username| event.fields[&FIELD_USERNAME] != username.as_bytes())
        {
            return Err(russh::Error::Disconnect);
        }
        if self.username.is_none() {
            self.username = Some(String::from_utf8_lossy(&event.fields[&FIELD_USERNAME]).into());
        }
        let (tx, rx) = oneshot::channel();
        let mut event = event;
        event.response = Some(tx);
        let event_id = self
            .state
            .push(event)
            .map_err(|_| russh::Error::Disconnect)?;
        let decision = match tokio::time::timeout(Duration::from_secs(60), rx).await {
            Ok(Ok(decision)) => decision,
            _ => {
                self.state.cancel_event(event_id);
                return Err(russh::Error::Disconnect);
            }
        };
        auth_from_decision(decision)
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
        let event_id = self
            .state
            .push(event)
            .map_err(|_| russh::Error::Disconnect)?;
        let state = self.state.clone();
        let channel_type = channel_type.to_owned();
        self.state.spawn(async move {
            match tokio::time::timeout(Duration::from_secs(60), rx).await {
                Ok(Ok(Decision::Channel { fd, mut bridge })) => {
                    state.register_channel(fd, channel.id(), &channel_type);
                    reply.accept().await;
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut bridge).await;
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut bridge).await;
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
        let Some(fd) = self.state.fd_for_channel(channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let mut event = Event {
            id: 0,
            fd,
            kind: EVENT_CHANNEL_REQUEST,
            flags: EVENT_WANT_REPLY,
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
        let handle = session.handle();
        let state = self.state.clone();
        let order = state.request_order(channel);
        self.state.spawn(async move {
            let _ordered = order.lock().await;
            let Ok(event_id) = state.push(event) else {
                let _ = handle.channel_failure(channel).await;
                return;
            };
            match tokio::time::timeout(Duration::from_secs(60), rx).await {
                Ok(Ok(Decision::Request(true))) => {
                    let _ = handle.channel_success(channel).await;
                }
                _ => {
                    state.cancel_event(event_id);
                    let _ = handle.channel_failure(channel).await;
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
        if let Some(lane) = self.state.lane(fd, data_type) {
            lane.send(data.to_vec())
                .await
                .map_err(|_| russh::Error::Disconnect)?;
            return Ok(());
        }
        if self.state.lane_discarded(fd, data_type) {
            return Ok(());
        }
        let (tx, rx) = oneshot::channel();
        let event_id = self
            .state
            .push(Event {
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
            })
            .map_err(|_| russh::Error::Disconnect)?;
        let state = self.state.clone();
        let data = data.to_vec();
        self.state.spawn(async move {
            if tokio::time::timeout(Duration::from_secs(60), rx)
                .await
                .ok()
                .and_then(Result::ok)
                .is_none()
            {
                state.cancel_event(event_id);
                return;
            }
            if let Some(lane) = state.lane(fd, data_type) {
                let _ = lane.send(data).await;
            } else {
                state.discard_lane(fd, data_type);
            }
        });
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
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_REQUEST_DATA, payload.to_vec());
        self.request(channel, request_type, fields, None, [0; 4], session)
            .await
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

pub(crate) async fn serve(
    stream: crate::DuplexStream,
    state: Arc<SshState>,
    host_key: Arc<PrivateKey>,
    methods: u64,
) {
    let config = russh::server::Config {
        methods: method_set(methods),
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![(*host_key).clone()],
        window_size: 64 * 1024,
        maximum_packet_size: 32 * 1024,
        channel_buffer_size: 16,
        event_buffer_size: 32,
        max_auth_attempts: 8,
        inactivity_timeout: Some(Duration::from_secs(300)),
        ..Default::default()
    };
    let handler = SshHandler {
        state: state.clone(),
        username: None,
    };
    let outcome =
        match russh::server::run_stream(Arc::new(config), JoinedStream::new(stream), handler).await
        {
            Ok(session) => session.await,
            Err(error) => Err(error),
        };
    state.close(if outcome.is_ok() {
        0
    } else {
        crate::abi::errno::ECONNRESET
    });
}

pub(crate) fn generate_host_key() -> Result<PrivateKey, russh::keys::ssh_key::Error> {
    PrivateKey::random(&mut rand_10::rng(), Algorithm::Ed25519)
}
