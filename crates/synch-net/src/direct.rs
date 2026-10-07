//! Direct-TCP streamed runs (`docs/DIRECT-TCP.md`).
//!
//! A [`GetDirect`](synch_core::BlobMessage::GetDirect) asks for a streamed run
//! to travel over a TCP connection between the two nodes rather than on the
//! QUIC stream that asked for it. The provider answers with a
//! [`DirectOffer`](synch_core::BlobMessage::DirectOffer) carrying a port, a
//! single-use ticket and the run's key; the requester dials that port on the
//! IP of the QUIC path it already uses, proves it holds the key, and reads the
//! run as AEAD records.
//!
//! A socket invocation asks the same way, in an
//! [`OpenDirect`](synch_core::SockRequest::OpenDirect), and its bytes then
//! travel both ways over the connection as records ([`stream`]).
//!
//! The key lives exactly as long as the QUIC connection that carried it, and
//! no longer than the run. On the provider it is held by the control stream's
//! task, which ends — dropping the key and forgetting the ticket — when the
//! run ends, the requester stops the stream, or the connection closes. On the
//! requester a watcher destroys it the moment the connection closes, whether
//! or not a read is in progress, and every record read is raced against the
//! same event.

use std::{
    collections::HashMap,
    io::IoSlice,
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use iroh::{
    endpoint::{Connection, RecvStream, SendStream},
    TransportAddr,
};
use serde::{de::DeserializeOwned, Serialize};
use synch_core::{DirectSecret, GroupRange, Hash, NodeId, CHUNK_GROUP_SIZE, DIRECT_TICKET_LEN};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};
use zeroize::Zeroizing;

use crate::error::NetError;

pub(crate) mod stream;

/// The send and receive buffer of every direct-run socket: 4 MiB, two
/// windows.
///
/// The kernel's default is 128 KiB on macOS — half a record — and on a fast
/// link autotuning does not grow it, because the round trip is too short to
/// ask for more. With that little in flight the two ends take turns: the
/// provider seals a record while the requester waits, then the requester
/// decrypts and hashes while the provider waits. Room for two windows lets
/// each end work on its own window while the other works on its.
const SOCKET_BUFFER: u32 = 4 << 20;

/// A TCP socket of the address's family, with [`SOCKET_BUFFER`] set before it
/// connects or listens, so the window it advertises from the first segment
/// reflects it (a listener's accepted sockets inherit it).
fn buffered_socket(addr: SocketAddr) -> std::io::Result<TcpSocket> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_send_buffer_size(SOCKET_BUFFER)?;
    socket.set_recv_buffer_size(SOCKET_BUFFER)?;
    Ok(socket)
}

/// The most plaintext one record carries: 256 KiB, the piece a transient read
/// hands out, so a record buffer costs what a piece already does.
pub(crate) const RECORD_LEN: usize = 256 * 1024;

/// The most a single run may carry under one key: 64 GiB, 2^18 full records,
/// far inside AES-GCM's per-key limits. A longer read asks for another run
/// where this one stopped, under a fresh key.
pub const DIRECT_MAX_RUN_BYTES: u64 = 64 << 30;

/// The least a transient read must have left before a direct run is worth
/// asking for: sixteen streamed windows. Below it, the extra round trip, the
/// TCP handshake and slow start cost more than the path saves.
pub const DIRECT_MIN_BYTES: u64 = 32 << 20;

/// How long a provider holds an offered ticket for its TCP connection.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an unauthenticated TCP connection may take to send its Hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a requester waits for the provider's port to accept.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How many TCP connections may be awaiting authentication at once.
///
/// Anyone who can reach the port reaches this, so it is bounded by count and
/// by time, does no store access, and allocates nothing the dialer chooses.
const PREAUTH_MAX: usize = 64;

/// How long a refused or broken direct path is left alone before a requester
/// asks the same peer again.
const REFUSAL_TTL: Duration = Duration::from_secs(600);

const MAGIC: &[u8; 8] = b"SYNCHDT1";
const MAC_LEN: usize = 32;
const HELLO_LEN: usize = MAGIC.len() + DIRECT_TICKET_LEN + MAC_LEN;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 5;
const KIND_DATA: u8 = 0;
const KIND_FINAL: u8 = 1;

/// Room for one `DirectOffer`: a variant tag, a port and the two fixed
/// arrays, with slack for postcard's varints.
pub(crate) const OFFER_FRAME_MAX: usize = 124;

const DATA_CONTEXT: &str = "synch direct-tcp v1 data";
const HELLO_CONTEXT: &str = "synch direct-tcp v1 hello";
const IV_CONTEXT: &str = "synch direct-tcp v1 iv";

/// Draws fresh key material for one offer from the OS RNG.
pub(crate) fn draw<const N: usize>() -> Result<[u8; N], NetError> {
    let mut bytes = [0u8; N];
    aws_lc_rs::rand::fill(&mut bytes)
        .map_err(|_| NetError::Direct("the system RNG failed".into()))?;
    Ok(bytes)
}

/// The run's three keys, derived from its secret and bound to its ticket and
/// to what was asked for, so no key serves two algorithms and decrypted bytes
/// are only ever read as the run that was requested.
pub(crate) struct RunKeys {
    data: Zeroizing<[u8; 32]>,
    hello: Zeroizing<[u8; 32]>,
    iv: Zeroizing<[u8; NONCE_LEN]>,
}

/// What every key of one offer is derived from: its secret, bound to its
/// ticket and to what was asked for.
fn key_input(
    secret: &DirectSecret,
    ticket: &[u8; DIRECT_TICKET_LEN],
    asked: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(32 + DIRECT_TICKET_LEN + asked.len()));
    input.extend_from_slice(secret.expose());
    input.extend_from_slice(ticket);
    input.extend_from_slice(asked);
    input
}

/// A record nonce base, derived under `context`.
fn derive_iv(context: &str, input: &[u8]) -> Zeroizing<[u8; NONCE_LEN]> {
    let iv = Zeroizing::new(blake3::derive_key(context, input));
    let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
    nonce.copy_from_slice(&iv[..NONCE_LEN]);
    nonce
}

impl RunKeys {
    pub(crate) fn derive(
        secret: &DirectSecret,
        ticket: &[u8; DIRECT_TICKET_LEN],
        root: Hash,
        run: GroupRange,
    ) -> RunKeys {
        let asked = postcard::to_stdvec(&(root, run)).expect("a hash and a range encode");
        let input = key_input(secret, ticket, &asked);
        RunKeys {
            data: Zeroizing::new(blake3::derive_key(DATA_CONTEXT, &input)),
            hello: Zeroizing::new(blake3::derive_key(HELLO_CONTEXT, &input)),
            iv: derive_iv(IV_CONTEXT, &input),
        }
    }

    /// Splits off the Hello key, which the provider's listener holds, from
    /// the record key, which the side that seals or opens records holds.
    pub(crate) fn split(self) -> Result<(HelloKey, RecordKey), NetError> {
        let RunKeys { data, hello, iv } = self;
        Ok((HelloKey(hello), RecordKey::new(&data, iv)?))
    }
}

/// The key a requester proves possession of on the TCP connection.
pub(crate) struct HelloKey(Zeroizing<[u8; 32]>);

impl HelloKey {
    fn mac(&self, ticket: &[u8; DIRECT_TICKET_LEN]) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(b"hello");
        hasher.update(ticket);
        hasher.finalize()
    }
}

/// One direction's AEAD key and its record counter.
///
/// The raw key bytes are zeroed when this is dropped; the expanded schedule
/// belongs to aws-lc-rs.
pub(crate) struct RecordKey {
    key: LessSafeKey,
    iv: Zeroizing<[u8; NONCE_LEN]>,
    seq: u64,
}

impl RecordKey {
    fn new(data: &[u8; 32], iv: Zeroizing<[u8; NONCE_LEN]>) -> Result<RecordKey, NetError> {
        let key = UnboundKey::new(&AES_256_GCM, data)
            .map_err(|_| NetError::Direct("the run key was rejected".into()))?;
        Ok(RecordKey {
            key: LessSafeKey::new(key),
            iv,
            seq: 0,
        })
    }

    /// The next record's nonce: the IV with the counter XORed into its low
    /// eight bytes. Every key encrypts exactly one run, so a counter from zero
    /// never repeats a nonce.
    fn next_nonce(&mut self) -> Result<Nonce, NetError> {
        let seq = self.seq;
        self.seq = seq
            .checked_add(1)
            .ok_or_else(|| NetError::Direct("the record counter is exhausted".into()))?;
        let mut nonce = *self.iv;
        for (byte, count) in nonce[NONCE_LEN - 8..].iter_mut().zip(seq.to_be_bytes()) {
            *byte ^= count;
        }
        Ok(Nonce::assume_unique_for_key(nonce))
    }
}

/// The record header, which is also its associated data: a forged length or
/// kind fails the tag.
fn header(len: usize, kind: u8) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&(len as u32).to_le_bytes());
    header[4] = kind;
    header
}

/// The IP of the QUIC connection's selected path, if it is a direct one.
///
/// This is the only address a requester dials: the provider names a port,
/// never a host, so an offer cannot point a requester's connect at a third
/// machine, and a relayed connection has no IP to offer at all.
pub(crate) fn direct_path(connection: &Connection) -> Option<SocketAddr> {
    connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .and_then(|path| match path.remote_addr() {
            TransportAddr::Ip(addr) => Some(*addr),
            _ => None,
        })
}

/// Writes a message carrying an offer as one frame of at most `max` bytes,
/// serialized into a buffer that is zeroed afterwards rather than one left to
/// the allocator.
///
/// The QUIC stack's own send and retransmit buffers hold a copy until the
/// peer acknowledges it, and those are beyond reach from here: this is
/// hygiene, not a guarantee. The process's memory is inside the trust
/// boundary either way.
pub(crate) async fn write_offer<T: Serialize>(
    send: &mut SendStream,
    offer: &T,
    max: usize,
) -> Result<(), NetError> {
    let mut frame = Zeroizing::new(vec![0u8; 4 + max]);
    let len = postcard::to_slice(offer, &mut frame[4..])
        .map_err(|e| NetError::Encode(e.to_string()))?
        .len();
    frame[..4].copy_from_slice(&(len as u32).to_le_bytes());
    send.write_all(&frame[..4 + len]).await?;
    Ok(())
}

/// Reads the answer to a request for an offer, at most `max` bytes, or `None`
/// when the peer ended the stream without one. Decoded out of a buffer that
/// is zeroed afterwards, like the one it was written from.
pub(crate) async fn read_offer<T: DeserializeOwned>(
    recv: &mut RecvStream,
    max: usize,
) -> Result<Option<T>, NetError> {
    let mut prefix = [0u8; 4];
    match recv.read_exact(&mut prefix).await {
        Ok(()) => {}
        Err(iroh::endpoint::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(prefix) as usize;
    if len > max {
        return Err(NetError::FrameTooLarge(len));
    }
    let mut frame = Zeroizing::new(vec![0u8; len]);
    recv.read_exact(&mut frame).await?;
    postcard::from_bytes(&frame)
        .map(Some)
        .map_err(|e| NetError::Decode(e.to_string()))
}

/// The provider's TCP listener and the tickets it is holding.
#[derive(Debug)]
pub(crate) struct DirectListener {
    port: u16,
    tickets: Arc<Tickets>,
    task: tokio::task::JoinHandle<()>,
}

/// Tickets offered and not yet presented, by id.
#[derive(Default)]
struct Tickets(Mutex<HashMap<[u8; DIRECT_TICKET_LEN], Pending>>);

impl std::fmt::Debug for Tickets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tickets")
            .field("pending", &self.lock().len())
            .finish()
    }
}

impl Tickets {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; DIRECT_TICKET_LEN], Pending>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// An offered ticket: the key its Hello must prove, and where to hand the
/// connection once it has.
struct Pending {
    hello: HelloKey,
    deliver: tokio::sync::oneshot::Sender<TcpStream>,
}

/// An offered ticket's place in the table, held by the control stream's task.
///
/// Dropping it forgets the ticket and zeroes its Hello key, which is what
/// ties both to the task's lifetime — and so to the QUIC stream and
/// connection that task is serving.
#[derive(Debug)]
pub(crate) struct TicketGuard {
    tickets: Arc<Tickets>,
    ticket: [u8; DIRECT_TICKET_LEN],
}

impl Drop for TicketGuard {
    fn drop(&mut self) {
        self.tickets.lock().remove(&self.ticket);
    }
}

impl DirectListener {
    /// Binds the listener and starts accepting.
    pub(crate) async fn bind(addr: SocketAddr) -> Result<DirectListener, NetError> {
        let listener = buffered_socket(addr)
            .and_then(|socket| {
                socket.set_reuseaddr(true)?;
                socket.bind(addr)?;
                socket.listen(1024)
            })
            .map_err(|e| {
                NetError::Endpoint(format!("could not bind direct listener {addr}: {e}"))
            })?;
        let port = listener
            .local_addr()
            .map_err(|e| NetError::Endpoint(e.to_string()))?
            .port();
        let tickets = Arc::new(Tickets::default());
        let task = tokio::spawn(accept_loop(listener, tickets.clone()));
        Ok(DirectListener {
            port,
            tickets,
            task,
        })
    }

    /// The port offers name.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Holds a ticket for its TCP connection until the guard is dropped.
    pub(crate) fn register(
        &self,
        ticket: [u8; DIRECT_TICKET_LEN],
        hello: HelloKey,
    ) -> (TicketGuard, tokio::sync::oneshot::Receiver<TcpStream>) {
        let (deliver, delivered) = tokio::sync::oneshot::channel();
        self.tickets
            .lock()
            .insert(ticket, Pending { hello, deliver });
        (
            TicketGuard {
                tickets: self.tickets.clone(),
                ticket,
            },
            delivered,
        )
    }

    /// Stops accepting connections.
    pub(crate) fn stop(&self) {
        self.task.abort();
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.tickets.lock().len()
    }
}

impl Drop for DirectListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn accept_loop(listener: TcpListener, tickets: Arc<Tickets>) {
    let preauth = Arc::new(tokio::sync::Semaphore::new(PREAUTH_MAX));
    loop {
        let socket = match listener.accept().await {
            Ok((socket, _)) => socket,
            Err(error) => {
                // Out of descriptors, most likely: back off rather than spin.
                tracing::debug!(%error, "direct listener accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = preauth.clone().try_acquire_owned() else {
            continue;
        };
        let tickets = tickets.clone();
        tokio::spawn(async move {
            let _permit = permit;
            authenticate(socket, &tickets).await;
        });
    }
}

/// Reads one Hello and hands the connection to the run it names, or drops it.
///
/// A ticket is forgotten only once a Hello for it has proved the key, so a
/// third party who saw the ticket id on the wire cannot burn it; and once
/// forgotten it authenticates nothing else, ever.
async fn authenticate(mut socket: TcpStream, tickets: &Tickets) {
    let mut hello = [0u8; HELLO_LEN];
    match tokio::time::timeout(HELLO_TIMEOUT, socket.read_exact(&mut hello)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    if &hello[..MAGIC.len()] != MAGIC {
        return;
    }
    let mut ticket = [0u8; DIRECT_TICKET_LEN];
    ticket.copy_from_slice(&hello[MAGIC.len()..MAGIC.len() + DIRECT_TICKET_LEN]);
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&hello[MAGIC.len() + DIRECT_TICKET_LEN..]);
    let deliver = {
        let mut table = tickets.lock();
        let Some(pending) = table.get(&ticket) else {
            return;
        };
        // `blake3::Hash` compares in constant time.
        if pending.hello.mac(&ticket) != blake3::Hash::from_bytes(mac) {
            return;
        }
        match table.remove(&ticket) {
            Some(pending) => pending.deliver,
            None => return,
        }
    };
    let _ = deliver.send(socket);
}

/// Connects to a provider's offered port and presents the Hello.
pub(crate) async fn dial(
    addr: SocketAddr,
    ticket: &[u8; DIRECT_TICKET_LEN],
    hello: &HelloKey,
) -> Result<TcpStream, NetError> {
    let connect = async { buffered_socket(addr)?.connect(addr).await };
    let mut socket = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(socket)) => socket,
        Ok(Err(e)) => return Err(NetError::Direct(format!("connecting to {addr}: {e}"))),
        Err(_) => {
            return Err(NetError::Direct(format!(
                "{addr} did not accept within {}s",
                CONNECT_TIMEOUT.as_secs()
            )))
        }
    };
    let _ = socket.set_nodelay(true);
    let mut frame = [0u8; HELLO_LEN];
    frame[..MAGIC.len()].copy_from_slice(MAGIC);
    frame[MAGIC.len()..MAGIC.len() + DIRECT_TICKET_LEN].copy_from_slice(ticket);
    frame[MAGIC.len() + DIRECT_TICKET_LEN..].copy_from_slice(hello.mac(ticket).as_bytes());
    socket
        .write_all(&frame)
        .await
        .map_err(|e| NetError::Direct(format!("sending the hello: {e}")))?;
    Ok(socket)
}

/// Whether a run is within what one key may carry.
pub(crate) fn within_key_limit(run: GroupRange) -> bool {
    (run.end - run.start).saturating_mul(CHUNK_GROUP_SIZE) <= DIRECT_MAX_RUN_BYTES
}

/// How long the provider waits for the TCP connection an offer names.
pub(crate) fn accept_timeout() -> Duration {
    ACCEPT_TIMEOUT
}

/// The provider's half of the TCP connection: seals the run's plaintext —
/// byte for byte what a `GetStream` answer writes on QUIC — into records.
pub(crate) struct RecordWriter {
    socket: TcpStream,
    key: RecordKey,
}

impl std::fmt::Debug for RecordWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordWriter").finish_non_exhaustive()
    }
}

impl RecordWriter {
    pub(crate) fn new(socket: TcpStream, key: RecordKey) -> RecordWriter {
        // Records are written whole, header to tag, in one vectored write;
        // Nagle would only hold the short ones back.
        let _ = socket.set_nodelay(true);
        RecordWriter { socket, key }
    }

    /// Seals and sends `bytes`, in place, a record at a time.
    pub(crate) async fn write(&mut self, mut bytes: Vec<u8>) -> Result<(), NetError> {
        for chunk in bytes.chunks_mut(RECORD_LEN) {
            self.seal(KIND_DATA, chunk).await?;
        }
        Ok(())
    }

    /// Ends the run: the final record, then the end of the stream. A
    /// connection that ends without it is a truncated run, not a short one.
    pub(crate) async fn finish(mut self) -> Result<(), NetError> {
        self.seal(KIND_FINAL, &mut []).await?;
        self.socket
            .shutdown()
            .await
            .map_err(|e| NetError::Direct(format!("closing the run: {e}")))
    }

    async fn seal(&mut self, kind: u8, chunk: &mut [u8]) -> Result<(), NetError> {
        let header = header(chunk.len(), kind);
        let nonce = self.key.next_nonce()?;
        let tag = self
            .key
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(header), chunk)
            .map_err(|_| NetError::Direct("sealing a record failed".into()))?;
        write_all_vectored(&mut self.socket, &[&header, chunk, tag.as_ref()])
            .await
            .map_err(|e| NetError::Direct(format!("sending a record: {e}")))
    }
}

async fn write_all_vectored(socket: &mut TcpStream, parts: &[&[u8]]) -> std::io::Result<()> {
    let mut slices: Vec<IoSlice<'_>> = parts.iter().map(|part| IoSlice::new(part)).collect();
    let mut remaining = &mut slices[..];
    IoSlice::advance_slices(&mut remaining, 0);
    while !remaining.is_empty() {
        let written = socket.write_vectored(remaining).await?;
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        IoSlice::advance_slices(&mut remaining, written);
    }
    Ok(())
}

/// Requesters' memory of peers whose direct path did not work, so a peer
/// without one costs a round trip — or a connect timeout — once rather than
/// on every read. Entries expire, and are bounded by the peers this node
/// dials, which are members.
#[derive(Debug, Default)]
pub(crate) struct DirectMemo(Mutex<HashMap<NodeId, Instant>>);

impl DirectMemo {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<NodeId, Instant>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn refused(&self, peer: &NodeId) -> bool {
        let mut refused = self.lock();
        match refused.get(peer) {
            Some(at) if at.elapsed() < REFUSAL_TTL => true,
            Some(_) => {
                refused.remove(peer);
                false
            }
            None => false,
        }
    }

    pub(crate) fn refuse(&self, peer: NodeId) {
        self.lock().insert(peer, Instant::now());
    }
}

/// The requester's record I/O: reads records off the TCP connection and
/// opens them under whatever key it is handed.
pub(crate) struct RecordReader {
    socket: TcpStream,
    /// The current record: ciphertext and tag while it is read, then its
    /// plaintext once opened.
    plain: Vec<u8>,
    at: usize,
    header: [u8; HEADER_LEN],
    ended: bool,
}

impl RecordReader {
    pub(crate) fn new(socket: TcpStream) -> RecordReader {
        RecordReader {
            socket,
            plain: Vec::new(),
            at: 0,
            header: [0u8; HEADER_LEN],
            ended: false,
        }
    }

    /// Copies out what is left of the opened record; zero once it is used up.
    fn take(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.plain.len() - self.at);
        buf[..n].copy_from_slice(&self.plain[self.at..self.at + n]);
        self.at += n;
        n
    }

    /// Reads the next record's header and sealed body, unopened.
    async fn read_sealed(&mut self) -> Result<(), NetError> {
        let read = async {
            self.socket.read_exact(&mut self.header).await?;
            let len = u32::from_le_bytes(self.header[..4].try_into().expect("four bytes")) as usize;
            if len > RECORD_LEN {
                return Err(std::io::Error::other(format!(
                    "a record of {len} bytes exceeds {RECORD_LEN}"
                )));
            }
            self.plain.resize(len + TAG_LEN, 0);
            self.socket.read_exact(&mut self.plain).await?;
            Ok(())
        };
        read.await
            .map_err(|e| NetError::Direct(format!("reading a record: {e}")))
    }

    /// Opens the record just read; `false` when it was the final one.
    ///
    /// A forged length or kind fails the tag, since the header is the
    /// associated data, and a connection that ends before the final record
    /// fails [`RecordReader::read_sealed`]: a truncated run is never mistaken
    /// for a complete one.
    fn open(&mut self, key: &mut RecordKey) -> Result<bool, NetError> {
        let nonce = key.next_nonce()?;
        let len = key
            .key
            .open_in_place(nonce, Aad::from(self.header), &mut self.plain)
            .map_err(|_| NetError::Direct("a record failed authentication".into()))?
            .len();
        self.plain.truncate(len);
        self.at = 0;
        match self.header[4] {
            KIND_DATA => Ok(true),
            KIND_FINAL if len == 0 => {
                self.ended = true;
                Ok(false)
            }
            kind => Err(NetError::Direct(format!("a record of unknown kind {kind}"))),
        }
    }
}

/// The requester's half of a direct run: the run's plaintext as a byte
/// stream.
///
/// Holds the control stream open — dropping it stops the stream, which ends
/// the run on the provider — and the run's key under a watcher that destroys
/// it the moment the QUIC connection closes, whether or not a read is in
/// progress. A read in progress is raced against the same event.
pub(crate) struct DirectSource {
    records: RecordReader,
    key: Arc<Mutex<Option<RecordKey>>>,
    connection: Connection,
    watcher: tokio::task::JoinHandle<()>,
    _control: RecvStream,
    memo: Arc<DirectMemo>,
    peer: NodeId,
}

impl std::fmt::Debug for DirectSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectSource")
            .field("peer", &self.peer.fmt_short().to_string())
            .field("ended", &self.records.ended)
            .finish_non_exhaustive()
    }
}

impl DirectSource {
    pub(crate) fn new(
        socket: TcpStream,
        key: RecordKey,
        connection: Connection,
        control: RecvStream,
        memo: Arc<DirectMemo>,
    ) -> DirectSource {
        let key = Arc::new(Mutex::new(Some(key)));
        let watcher = {
            let key = key.clone();
            let connection = connection.clone();
            tokio::spawn(async move {
                connection.closed().await;
                key.lock().unwrap_or_else(PoisonError::into_inner).take();
            })
        };
        let peer = connection.remote_id();
        DirectSource {
            records: RecordReader::new(socket),
            key,
            connection,
            watcher,
            _control: control,
            memo,
            peer,
        }
    }

    /// Fills `buf`, or `false` when the run ended — at its final record —
    /// before the first byte of it.
    pub(crate) async fn read_or_end(&mut self, buf: &mut [u8]) -> Result<bool, NetError> {
        let result = self.fill(buf).await;
        if result.is_err() {
            // Whatever broke the path will break it again: ask over QUIC.
            self.memo.refuse(self.peer);
            self.forget_key();
        }
        result
    }

    async fn fill(&mut self, buf: &mut [u8]) -> Result<bool, NetError> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.records.take(&mut buf[filled..]);
            filled += n;
            if n > 0 {
                continue;
            }
            if !self.next_record().await? {
                return match filled {
                    0 => Ok(false),
                    _ => Err(NetError::Direct("the run ended mid-message".into())),
                };
            }
        }
        Ok(true)
    }

    /// Reads and opens the next record; `false` at the final one, after
    /// which the key is gone.
    async fn next_record(&mut self) -> Result<bool, NetError> {
        if self.records.ended {
            return Ok(false);
        }
        let connection = self.connection.clone();
        tokio::select! {
            read = self.records.read_sealed() => read?,
            _ = connection.closed() => {
                return Err(NetError::Direct("the QUIC connection closed under the run".into()))
            }
        }
        let more = {
            let mut key = self.key.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(key) = key.as_mut() else {
                return Err(NetError::Direct(
                    "the run's key went with its QUIC connection".into(),
                ));
            };
            self.records.open(key)?
        };
        if !more {
            self.forget_key();
        }
        Ok(more)
    }

    fn forget_key(&self) {
        self.key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    #[cfg(test)]
    pub(crate) fn holds_key(&self) -> bool {
        self.key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
}

impl Drop for DirectSource {
    fn drop(&mut self) {
        self.forget_key();
        self.watcher.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(secret: u8, ticket: [u8; DIRECT_TICKET_LEN]) -> (HelloKey, RecordKey) {
        RunKeys::derive(
            &DirectSecret::from_bytes([secret; 32]),
            &ticket,
            Hash::new(b"object"),
            GroupRange::new(0, 4),
        )
        .split()
        .unwrap()
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (dialed, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (dialed.unwrap(), accepted.unwrap().0)
    }

    /// Whether the far end closed the connection without sending anything.
    async fn closed_by_peer(socket: &mut TcpStream) -> bool {
        let mut byte = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(5), socket.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    /// A ticket admits one TCP connection, and only one that proves the key:
    /// a Hello without it is dropped and leaves the ticket for its owner,
    /// and once the owner has presented it the same Hello admits nothing.
    #[tokio::test]
    async fn a_ticket_admits_one_connection_and_only_with_its_key() {
        let listener = DirectListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr: SocketAddr = ([127, 0, 0, 1], listener.port()).into();
        let ticket = [1u8; DIRECT_TICKET_LEN];
        let (hello, _) = keys(5, ticket);
        let (_held, delivered) = listener.register(ticket, hello);

        let (forged, _) = keys(6, ticket);
        let mut stranger = dial(addr, &ticket, &forged).await.unwrap();
        assert!(closed_by_peer(&mut stranger).await);
        assert_eq!(
            listener.pending(),
            1,
            "a wrong key must not burn the ticket"
        );

        let (hello, _) = keys(5, ticket);
        let _owner = dial(addr, &ticket, &hello).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), delivered)
            .await
            .expect("the owner's connection is handed over")
            .unwrap();
        assert_eq!(listener.pending(), 0);

        let mut replay = dial(addr, &ticket, &hello).await.unwrap();
        assert!(closed_by_peer(&mut replay).await);
    }

    /// Replays captured ciphertext to a fresh reader and opens what it can.
    async fn replay(sealed: Vec<u8>, ticket: [u8; DIRECT_TICKET_LEN]) -> Result<Vec<u8>, NetError> {
        let (mut from, to) = tcp_pair().await;
        tokio::spawn(async move {
            let _ = from.write_all(&sealed).await;
        });
        let (_, mut key) = keys(5, ticket);
        let mut reader = RecordReader::new(to);
        let mut opened = Vec::new();
        loop {
            reader.read_sealed().await?;
            if !reader.open(&mut key)? {
                return Ok(opened);
            }
            let mut piece = vec![0u8; RECORD_LEN];
            let n = reader.take(&mut piece);
            opened.extend_from_slice(&piece[..n]);
        }
    }

    /// Records open only as they were sealed, and only the final record ends
    /// a run: a flipped bit, a data record relabelled as final, or a
    /// connection that ends before the final record is a failure — never a
    /// short run the reader could take for a complete one.
    #[tokio::test]
    async fn records_open_only_as_sealed_and_a_truncated_run_is_not_an_end() {
        let ticket = [2u8; DIRECT_TICKET_LEN];
        let plaintext: Vec<u8> = (0..RECORD_LEN * 2 + 1000)
            .map(|i| (i % 251) as u8)
            .collect();
        let (to_wire, mut wire) = tcp_pair().await;
        let (_, key) = keys(5, ticket);
        let mut writer = RecordWriter::new(to_wire, key);
        let sending = plaintext.clone();
        let sent = tokio::spawn(async move {
            writer.write(sending).await.unwrap();
            writer.finish().await.unwrap();
        });
        let mut sealed = Vec::new();
        wire.read_to_end(&mut sealed).await.unwrap();
        sent.await.unwrap();
        assert!(!sealed.windows(64).any(|w| w == &plaintext[..64]));

        assert!(replay(sealed.clone(), ticket).await.unwrap() == plaintext);

        let mut flipped = sealed.clone();
        flipped[sealed.len() / 2] ^= 1;
        assert!(matches!(
            replay(flipped, ticket).await,
            Err(NetError::Direct(_))
        ));

        let mut relabelled = sealed.clone();
        relabelled[4] = KIND_FINAL;
        assert!(matches!(
            replay(relabelled, ticket).await,
            Err(NetError::Direct(_))
        ));

        let truncated = sealed[..sealed.len() - (HEADER_LEN + TAG_LEN)].to_vec();
        assert!(matches!(
            replay(truncated, ticket).await,
            Err(NetError::Direct(_))
        ));
    }
}
