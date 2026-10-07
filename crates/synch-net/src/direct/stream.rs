//! Direct-TCP socket streams (`docs/DIRECT-TCP.md`, "Sockets").
//!
//! A socket invocation's bytes go both ways, so its connection carries records
//! in both directions, each under a key of its own: *up* from the caller to the
//! callee and *down* back. The record format is the streamed run's, and so is
//! the rule that only a `final` record ends a direction cleanly: a TCP FIN or
//! reset before it — which anyone on the path can forge — is an error, never a
//! half-close the program could mistake for its peer's.
//!
//! Each half owns its key, and both share a watcher that destroys the keys and
//! shuts the TCP connection down the moment the invocation's QUIC stream or
//! connection goes, so a read or write waiting on the socket fails at once
//! rather than at the next record.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{ready, Context, Poll},
};

use aws_lc_rs::aead::Aad;
use synch_core::{DirectSecret, SockOpen, DIRECT_TICKET_LEN};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};
use zeroize::Zeroizing;

use super::{
    derive_iv, header, key_input, HelloKey, RecordKey, HEADER_LEN, KIND_DATA, KIND_FINAL,
    RECORD_LEN, TAG_LEN,
};
use crate::error::NetError;

const HELLO_CONTEXT: &str = "synch direct-tcp v1 sock hello";
const UP_CONTEXT: &str = "synch direct-tcp v1 sock up";
const UP_IV_CONTEXT: &str = "synch direct-tcp v1 sock up iv";
const DOWN_CONTEXT: &str = "synch direct-tcp v1 sock down";
const DOWN_IV_CONTEXT: &str = "synch direct-tcp v1 sock down iv";

/// How long a caller waits for the callee to confirm the connection it
/// dialed. The callee sends the confirmation the moment the connection is
/// handed over, so this bounds one round trip.
pub(crate) const CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One invocation's keys: the Hello key the callee's listener checks, and a
/// record key per direction.
pub(crate) struct SockKeys {
    pub(crate) hello: HelloKey,
    /// Seals what the caller writes; opens what the callee reads.
    pub(crate) up: RecordKey,
    /// Seals what the callee writes; opens what the caller reads.
    pub(crate) down: RecordKey,
}

impl SockKeys {
    /// Derives an invocation's keys from its offer, bound to the `Open` that
    /// asked for it and the invocation that answered, so decrypted bytes are
    /// only ever read as that invocation's. Labels distinct from a streamed
    /// run's keep a socket's keys from ever being a run's, and the two
    /// directions' from ever being each other's.
    pub(crate) fn derive(
        secret: &DirectSecret,
        ticket: &[u8; DIRECT_TICKET_LEN],
        open: &SockOpen,
        invocation: u64,
    ) -> Result<SockKeys, NetError> {
        let asked = postcard::to_stdvec(&(open, invocation))
            .map_err(|e| NetError::Encode(e.to_string()))?;
        let input = key_input(secret, ticket, &asked);
        let key = |context| Zeroizing::new(blake3::derive_key(context, &input));
        Ok(SockKeys {
            hello: HelloKey(key(HELLO_CONTEXT)),
            up: RecordKey::new(&key(UP_CONTEXT), derive_iv(UP_IV_CONTEXT, &input))?,
            down: RecordKey::new(&key(DOWN_CONTEXT), derive_iv(DOWN_IV_CONTEXT, &input))?,
        })
    }
}

/// A direction's key, which the watcher can take away from under its half.
type KeySlot = Arc<Mutex<Option<RecordKey>>>;

fn forget(slot: &KeySlot) {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take();
}

/// What both halves of one direct stream share, dropped with the last of them:
/// the invocation's QUIC stream, kept open because it is the invocation's
/// identity on the callee, and the watcher.
struct Shared {
    _control: Mutex<Box<dyn Send>>,
    watcher: tokio::task::JoinHandle<()>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

/// Splits an authenticated TCP connection into an invocation's two halves:
/// one opening records under `read`, one sealing them under `write`.
///
/// `gone` resolves when the invocation's QUIC stream or connection does; the
/// watcher then destroys both keys and shuts the connection down. `control`
/// is that QUIC stream, held until both halves are dropped.
pub(crate) fn split(
    socket: TcpStream,
    read: RecordKey,
    write: RecordKey,
    gone: impl Future<Output = ()> + Send + 'static,
    control: impl Send + 'static,
) -> Result<(DirectRead, DirectWrite), NetError> {
    let _ = socket.set_nodelay(true);
    // A second handle on the socket for the watcher, which has to be able to
    // fail a read or write in progress without owning either half.
    let socket = socket
        .into_std()
        .map_err(|e| NetError::Direct(format!("taking the connection: {e}")))?;
    let killer = socket
        .try_clone()
        .map_err(|e| NetError::Direct(format!("taking the connection: {e}")))?;
    let socket = TcpStream::from_std(socket)
        .map_err(|e| NetError::Direct(format!("taking the connection: {e}")))?;

    let read_key: KeySlot = Arc::new(Mutex::new(Some(read)));
    let write_key: KeySlot = Arc::new(Mutex::new(Some(write)));
    let watcher = {
        let (read_key, write_key) = (read_key.clone(), write_key.clone());
        tokio::spawn(async move {
            gone.await;
            forget(&read_key);
            forget(&write_key);
            let _ = killer.shutdown(std::net::Shutdown::Both);
        })
    };
    let shared = Arc::new(Shared {
        _control: Mutex::new(Box::new(control)),
        watcher,
    });
    let (reader, writer) = socket.into_split();
    Ok((
        DirectRead {
            socket: reader,
            key: read_key,
            header: [0u8; HEADER_LEN],
            body: Vec::new(),
            at: 0,
            state: ReadState::Header,
            _shared: shared.clone(),
        },
        DirectWrite {
            socket: writer,
            key: write_key,
            out: Vec::new(),
            sent: 0,
            accepted: 0,
            state: WriteState::Open,
            _shared: shared,
        },
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    /// Reading a record's header into `header[..at]`.
    Header,
    /// Reading a record's sealed body and tag into `body[..at]`.
    Body,
    /// Handing out the opened record's plaintext from `body[at..]`.
    Plain,
    /// The final record arrived: end of stream.
    Ended,
}

/// The reading half: the other side's records, opened, as a byte stream.
pub(crate) struct DirectRead {
    socket: OwnedReadHalf,
    key: KeySlot,
    header: [u8; HEADER_LEN],
    body: Vec<u8>,
    at: usize,
    state: ReadState,
    _shared: Arc<Shared>,
}

impl std::fmt::Debug for DirectRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectRead")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn broken(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, error)
}

impl DirectRead {
    /// Reads into `buf[*at..]` until it is full.
    fn poll_fill(
        socket: &mut OwnedReadHalf,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        at: &mut usize,
    ) -> Poll<std::io::Result<()>> {
        while *at < buf.len() {
            let mut read = ReadBuf::new(&mut buf[*at..]);
            ready!(Pin::new(&mut *socket).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                // A FIN can be forged; only the final record ends a stream.
                return Poll::Ready(Err(broken("the connection ended before its final record")));
            }
            *at += read.filled().len();
        }
        Poll::Ready(Ok(()))
    }

    /// Opens the record just read, leaving its plaintext in `body`.
    fn open(&mut self) -> std::io::Result<()> {
        let mut key = self.key.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(record_key) = key.as_mut() else {
            return Err(broken("the stream's key went with its QUIC connection"));
        };
        let nonce = record_key.next_nonce().map_err(broken)?;
        let len = record_key
            .key
            .open_in_place(nonce, Aad::from(self.header), &mut self.body)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a record failed authentication",
                )
            })?
            .len();
        self.body.truncate(len);
        self.at = 0;
        match self.header[4] {
            KIND_DATA => self.state = ReadState::Plain,
            KIND_FINAL if len == 0 => {
                self.state = ReadState::Ended;
                key.take();
            }
            kind => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("a record of unknown kind {kind}"),
                ))
            }
        }
        Ok(())
    }

    /// Reads and opens the next record, unless one is open or the stream
    /// has ended.
    fn poll_next_record(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match self.state {
                ReadState::Plain | ReadState::Ended => return Poll::Ready(Ok(())),
                ReadState::Header => {
                    ready!(Self::poll_fill(
                        &mut self.socket,
                        cx,
                        &mut self.header,
                        &mut self.at
                    ))?;
                    let len = u32::from_le_bytes(self.header[..4].try_into().expect("four bytes"))
                        as usize;
                    if len > RECORD_LEN {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("a record of {len} bytes exceeds {RECORD_LEN}"),
                        )));
                    }
                    self.body.resize(len + TAG_LEN, 0);
                    self.at = 0;
                    self.state = ReadState::Body;
                }
                ReadState::Body => {
                    ready!(Self::poll_fill(
                        &mut self.socket,
                        cx,
                        &mut self.body,
                        &mut self.at
                    ))?;
                    self.open()?;
                }
            }
        }
    }

    fn poll_record(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match self.state {
                ReadState::Ended => return Poll::Ready(Ok(())),
                ReadState::Plain if self.at < self.body.len() => {
                    let n = buf.remaining().min(self.body.len() - self.at);
                    buf.put_slice(&self.body[self.at..self.at + n]);
                    self.at += n;
                    return Poll::Ready(Ok(()));
                }
                ReadState::Plain => {
                    self.at = 0;
                    self.state = ReadState::Header;
                }
                ReadState::Header | ReadState::Body => ready!(self.poll_next_record(cx))?,
            }
        }
    }
}

impl DirectRead {
    /// Waits for the callee's confirmation that it took the connection up:
    /// an empty data record, the first thing it sends.
    ///
    /// Only the holder of the down key can seal it, so it proves the far end
    /// is the callee and not whatever else accepted a TCP connection on its
    /// port — a stale forward, a middlebox — which would otherwise leave the
    /// caller waiting on a stream nothing will ever write to.
    pub(crate) async fn confirmed(&mut self) -> std::io::Result<()> {
        std::future::poll_fn(|cx| self.poll_next_record(cx)).await?;
        match self.state {
            ReadState::Plain if self.body.is_empty() => {
                self.state = ReadState::Header;
                Ok(())
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the stream did not open with its confirmation",
            )),
        }
    }
}

impl AsyncRead for DirectRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let result = ready!(this.poll_record(cx, buf));
        if result.is_err() {
            // A stream that failed once is not read again.
            forget(&this.key);
        }
        Poll::Ready(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteState {
    Open,
    /// The final record is sealed into `out`.
    Closing,
    Closed,
}

/// The writing half: bytes written to it go out as records.
///
/// A write returns only once the record it sealed is entirely on the socket,
/// so nothing it accepted waits on a later flush — the runtime and the bridges
/// write without flushing. A write interrupted mid-record finishes that record
/// first the next time it is polled and reports what the record held, which
/// is right for every caller that offers the same bytes again
/// (`write_all`, `copy`): sealed bytes are committed to the stream.
pub(crate) struct DirectWrite {
    socket: OwnedWriteHalf,
    key: KeySlot,
    /// The sealed record being sent, from `sent` on.
    out: Vec<u8>,
    sent: usize,
    /// The plaintext bytes `out` holds, reported once it is sent.
    accepted: usize,
    state: WriteState,
    _shared: Arc<Shared>,
}

impl std::fmt::Debug for DirectWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectWrite")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl DirectWrite {
    /// Seals `plain` as one record of `kind` into `out`.
    fn seal(&mut self, kind: u8, plain: &[u8]) -> std::io::Result<()> {
        let mut key = self.key.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(record_key) = key.as_mut() else {
            return Err(broken("the stream's key went with its QUIC connection"));
        };
        let header = header(plain.len(), kind);
        let nonce = record_key.next_nonce().map_err(broken)?;
        self.out.clear();
        self.out.extend_from_slice(&header);
        self.out.extend_from_slice(plain);
        let tag = record_key
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(header), &mut self.out[HEADER_LEN..])
            .map_err(|_| broken("sealing a record failed"))?;
        self.out.extend_from_slice(tag.as_ref());
        self.sent = 0;
        Ok(())
    }

    /// Sends what is left of `out`.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.sent < self.out.len() {
            let n = ready!(Pin::new(&mut self.socket).poll_write(cx, &self.out[self.sent..]))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.out.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_write_record(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.state != WriteState::Open {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        if self.accepted == 0 {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(RECORD_LEN);
            self.seal(KIND_DATA, &buf[..n])?;
            self.accepted = n;
        }
        ready!(self.poll_send(cx))?;
        let accepted = std::mem::take(&mut self.accepted);
        if accepted > buf.len() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a write was abandoned mid-record for shorter bytes",
            )));
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match self.state {
                WriteState::Open => {
                    ready!(self.poll_send(cx))?;
                    self.seal(KIND_FINAL, &[])?;
                    self.state = WriteState::Closing;
                }
                WriteState::Closing => {
                    ready!(self.poll_send(cx))?;
                    ready!(Pin::new(&mut self.socket).poll_shutdown(cx))?;
                    self.state = WriteState::Closed;
                    forget(&self.key);
                }
                WriteState::Closed => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl DirectWrite {
    /// Sends the callee's confirmation that it took the connection up
    /// ([`DirectRead::confirmed`]).
    pub(crate) async fn confirm(&mut self) -> std::io::Result<()> {
        self.seal(KIND_DATA, &[])?;
        std::future::poll_fn(|cx| self.poll_send(cx)).await
    }
}

impl AsyncWrite for DirectWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = ready!(this.poll_write_record(cx, buf));
        if result.is_err() {
            forget(&this.key);
        }
        Poll::Ready(result)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.socket).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = ready!(this.poll_close(cx));
        if result.is_err() {
            forget(&this.key);
        }
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn keys() -> SockKeys {
        let open = SockOpen::new(
            synch_core::OriginId::Key(iroh::SecretKey::from_bytes(&[1; 32]).public()),
            "echo",
            vec![],
        );
        SockKeys::derive(
            &DirectSecret::from_bytes([5; 32]),
            &[2; DIRECT_TICKET_LEN],
            &open,
            9,
        )
        .unwrap()
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (dialed, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (dialed.unwrap(), accepted.unwrap().0)
    }

    /// Both halves of each end of a stream: the caller's and the callee's.
    async fn ends() -> ((DirectRead, DirectWrite), (DirectRead, DirectWrite)) {
        let (caller, callee) = tcp_pair().await;
        let (one, other) = (keys(), keys());
        let never = std::future::pending::<()>;
        let (mut caller_read, caller_write) = split(caller, one.down, one.up, never(), ()).unwrap();
        let (callee_read, mut callee_write) =
            split(callee, other.up, other.down, never(), ()).unwrap();
        callee_write.confirm().await.unwrap();
        caller_read.confirmed().await.unwrap();
        ((caller_read, caller_write), (callee_read, callee_write))
    }

    /// Bytes go both ways, each direction ending at its own half-close; a
    /// direction whose connection ends without the final record — a FIN
    /// anyone on the path could forge — is a failure, never an end; and a
    /// record altered on the wire does not open.
    #[tokio::test]
    async fn a_direct_stream_carries_both_ways_and_ends_only_at_a_final_record() {
        let ((mut caller_read, mut caller_write), (mut callee_read, mut callee_write)) =
            ends().await;
        let up: Vec<u8> = (0..RECORD_LEN * 3 + 1000)
            .map(|i| (i % 251) as u8)
            .collect();
        let sent = up.clone();
        let writing = tokio::spawn(async move {
            caller_write.write_all(&sent).await.unwrap();
            caller_write.shutdown().await.unwrap();
            caller_write
        });
        let mut got = Vec::new();
        callee_read.read_to_end(&mut got).await.unwrap();
        assert!(got == up);
        // The caller's half-close left the other direction open.
        let _caller_write = writing.await.unwrap();
        callee_write
            .write_all(b"after the caller's EOF")
            .await
            .unwrap();
        callee_write.shutdown().await.unwrap();
        let mut down = Vec::new();
        caller_read.read_to_end(&mut down).await.unwrap();
        assert_eq!(down, b"after the caller's EOF");

        let ((_, mut caller_write), (mut callee_read, _)) = ends().await;
        caller_write.write_all(b"cut short").await.unwrap();
        drop(caller_write);
        let mut got = Vec::new();
        let truncated = callee_read.read_to_end(&mut got).await;
        assert_eq!(got, b"cut short");
        assert!(truncated.is_err(), "a FIN is not an end: {truncated:?}");

        let (to_wire, mut wire) = tcp_pair().await;
        let (_, mut sealing) =
            split(to_wire, keys().down, keys().up, std::future::pending(), ()).unwrap();
        sealing.write_all(b"in transit").await.unwrap();
        sealing.shutdown().await.unwrap();
        let mut sealed = Vec::new();
        wire.read_to_end(&mut sealed).await.unwrap();
        assert!(!sealed.windows(10).any(|w| w == b"in transit"));
        sealed[HEADER_LEN + 2] ^= 1;
        let (mut from, to) = tcp_pair().await;
        from.write_all(&sealed).await.unwrap();
        let (mut opening, _) =
            split(to, keys().up, keys().down, std::future::pending(), ()).unwrap();
        let mut got = Vec::new();
        let tampered = opening.read_to_end(&mut got).await;
        assert!(got.is_empty());
        assert_eq!(
            tampered.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }
}
