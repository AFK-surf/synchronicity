//! Endpoints, their rings, and the readiness the guest polls.
//!
//! Everything the guest can see of the network is a byte in a ring the host
//! owns. `sy_read` and `sy_write` copy in and out of those rings and never
//! block; a pair of pump tasks per endpoint moves bytes between the rings and
//! the actual stream. That is what makes `sy_poll` the only helper that
//! suspends.
//!
//! Backpressure needs no implementation here, only a decision not to read: a
//! full rx ring stops the reader task, and QUIC's and TCP's own flow control
//! does the rest at the far end.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    net::IpAddr,
    rc::Rc,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Notify,
};

use crate::abi::{errno, poll};

/// How much one read syscall pulls in at a time.
const READ_CHUNK: usize = 16 * 1024;

/// Where an endpoint is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// An outbound connection that has not finished connecting.
    Connecting,
    /// Live.
    Open,
    /// Failed; `errno` says why.
    Failed,
    /// Closed by the guest.
    Closed,
}

/// The readiness signal shared by every endpoint of one invocation.
///
/// An epoch beside the [`Notify`] is what makes the wait race-free without
/// depending on the executor being single-threaded: a poller reads the epoch,
/// checks readiness, registers, and re-checks the epoch before sleeping, so a
/// change that lands in the window cannot be missed.
#[derive(Debug, Default)]
pub(crate) struct Readiness {
    epoch: Cell<u64>,
    notify: Notify,
}

impl Readiness {
    pub(crate) fn bump(&self) {
        self.epoch.set(self.epoch.get().wrapping_add(1));
        self.notify.notify_waiters();
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.get()
    }

    /// Waits for a readiness change, or for `timeout` to run out.
    ///
    /// Returns `true` if something changed, `false` on timeout.
    pub(crate) async fn wait(&self, since: u64, timeout: Duration) -> bool {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Register before re-reading the epoch, so a bump between the caller's
        // readiness check and this sleep wakes us rather than being lost.
        notified.as_mut().enable();
        if self.epoch.get() != since {
            return true;
        }
        tokio::select! {
            _ = notified => true,
            _ = tokio::time::sleep(timeout) => false,
        }
    }
}

/// One endpoint: the inbound stream, or something the guest connected to.
#[derive(Debug)]
pub(crate) struct Endpoint {
    rx: RefCell<VecDeque<u8>>,
    tx: RefCell<VecDeque<u8>>,
    cap: usize,
    state: Cell<State>,
    errno: Cell<i64>,
    /// The reader saw a clean EOF. `sy_read` returns 0 once `rx` drains.
    rx_eof: Cell<bool>,
    /// The guest asked to half-close; the writer shuts down once `tx` drains.
    tx_shutdown: Cell<bool>,
    /// Woken when the guest frees rx space, so the reader may continue.
    rx_room: Notify,
    /// Woken when the guest writes or half-closes, so the writer may continue.
    tx_data: Notify,
    /// Woken when anything the guest could poll on changes.
    ready: Rc<Readiness>,
    /// What `sy_endpoint_info` reports.
    peer: RefCell<String>,
    /// Bytes moved, for `synch socket ps`.
    pub(crate) bytes_in: Cell<u64>,
    /// Bytes moved, for `synch socket ps`.
    pub(crate) bytes_out: Cell<u64>,
}

impl Endpoint {
    pub(crate) fn new(cap: usize, ready: Rc<Readiness>, state: State, peer: String) -> Rc<Self> {
        Rc::new(Endpoint {
            rx: RefCell::new(VecDeque::new()),
            tx: RefCell::new(VecDeque::new()),
            cap,
            state: Cell::new(state),
            errno: Cell::new(0),
            rx_eof: Cell::new(false),
            tx_shutdown: Cell::new(false),
            rx_room: Notify::new(),
            tx_data: Notify::new(),
            ready,
            peer: RefCell::new(peer),
            bytes_in: Cell::new(0),
            bytes_out: Cell::new(0),
        })
    }

    pub(crate) fn state(&self) -> State {
        self.state.get()
    }

    pub(crate) fn errno(&self) -> i64 {
        self.errno.get()
    }

    pub(crate) fn peer(&self) -> String {
        self.peer.borrow().clone()
    }

    pub(crate) fn set_peer(&self, peer: String) {
        *self.peer.borrow_mut() = peer;
    }

    pub(crate) fn set_open(&self) {
        if self.state.get() == State::Connecting {
            self.state.set(State::Open);
            self.ready.bump();
        }
    }

    pub(crate) fn fail(&self, code: i64) {
        if matches!(self.state.get(), State::Failed | State::Closed) {
            return;
        }
        self.errno.set(code);
        self.state.set(State::Failed);
        // Both pumps are waiting on one of these; wake them so they can see
        // the state and stop rather than parking forever on a dead endpoint.
        self.rx_room.notify_waiters();
        self.tx_data.notify_waiters();
        self.ready.bump();
    }

    pub(crate) fn close(&self) {
        self.state.set(State::Closed);
        self.rx_room.notify_waiters();
        self.tx_data.notify_waiters();
        self.ready.bump();
    }

    fn finished(&self) -> bool {
        matches!(self.state.get(), State::Failed | State::Closed)
    }

    pub(crate) fn readable(&self) -> usize {
        self.rx.borrow().len()
    }

    /// Bytes the guest has written that the writer task has not yet pushed out.
    pub(crate) fn pending_out(&self) -> usize {
        self.tx.borrow().len()
    }

    pub(crate) fn writable(&self) -> usize {
        self.cap.saturating_sub(self.tx.borrow().len())
    }

    /// Copies out of the rx ring. `Ok(0)` is a clean EOF.
    pub(crate) fn read(&self, out: &mut [u8]) -> i64 {
        let mut rx = self.rx.borrow_mut();
        if rx.is_empty() {
            return match (self.rx_eof.get(), self.state.get()) {
                (_, State::Failed) => self.errno.get(),
                (true, _) => 0,
                (false, State::Closed) => 0,
                _ => errno::EAGAIN,
            };
        }
        let n = out.len().min(rx.len());
        for (slot, byte) in out.iter_mut().zip(rx.drain(..n)) {
            *slot = byte;
        }
        drop(rx);
        // The reader may have been parked on a full ring.
        self.rx_room.notify_waiters();
        self.bytes_in.set(self.bytes_in.get() + n as u64);
        n as i64
    }

    /// Copies into the tx ring. A short count is normal and is backpressure.
    pub(crate) fn write(&self, data: &[u8]) -> i64 {
        match self.state.get() {
            State::Failed => return self.errno.get(),
            State::Closed => return errno::EPIPE,
            // A connecting endpoint accepts writes into the ring: the guest
            // gets to prepare a request before the connection lands, and the
            // writer task drains it when it does.
            State::Connecting | State::Open => {}
        }
        if self.tx_shutdown.get() {
            return errno::EPIPE;
        }
        let room = self.writable();
        if room == 0 {
            return errno::EAGAIN;
        }
        let n = data.len().min(room);
        self.tx.borrow_mut().extend(&data[..n]);
        self.tx_data.notify_waiters();
        self.bytes_out.set(self.bytes_out.get() + n as u64);
        n as i64
    }

    /// Half-closes the write side once what is buffered has drained.
    pub(crate) fn shutdown(&self) {
        self.tx_shutdown.set(true);
        self.tx_data.notify_waiters();
    }

    /// The readiness bits this endpoint has right now.
    pub(crate) fn revents(&self) -> u32 {
        let mut bits = 0;
        match self.state.get() {
            State::Failed => bits |= poll::ERR,
            State::Closed => bits |= poll::HUP,
            State::Connecting => {}
            State::Open => {}
        }
        let buffered = self.readable();
        // Readable means "a read will not block": bytes, or an EOF that will
        // come back as a clean zero.
        if buffered > 0 || self.rx_eof.get() {
            bits |= poll::IN;
        }
        // Hung up means "nothing more will ever arrive" — which is not the same
        // as "the peer stopped writing", because what it already wrote may
        // still be in the ring. Reporting HUP with data buffered is how a
        // program that breaks on HUP silently drops the last response.
        if self.rx_eof.get() && buffered == 0 {
            bits |= poll::HUP;
        }
        if self.state.get() == State::Open && self.writable() > 0 && !self.tx_shutdown.get() {
            bits |= poll::OUT;
        }
        bits
    }

    fn set_rx_eof(&self) {
        self.rx_eof.set(true);
        self.ready.bump();
    }

    fn push_rx(&self, data: &[u8]) {
        self.rx.borrow_mut().extend(data);
        self.ready.bump();
    }

    fn take_tx(&self) -> Vec<u8> {
        let mut tx = self.tx.borrow_mut();
        let out: Vec<u8> = tx.drain(..).collect();
        drop(tx);
        if !out.is_empty() {
            // Room appeared, so a guest parked on OUT can proceed.
            self.ready.bump();
        }
        out
    }
}

/// Maps an I/O failure onto the errno a guest sees.
pub(crate) fn io_errno(e: &std::io::Error) -> i64 {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | ConnectionAborted | BrokenPipe => errno::ECONNRESET,
        TimedOut => errno::ETIMEDOUT,
        PermissionDenied => errno::EPERM,
        NotFound | AddrNotAvailable => errno::ENOENT,
        _ => errno::ECONNRESET,
    }
}

/// Moves bytes from the stream into the rx ring, and stops when it is full.
pub(crate) async fn reader_task(ep: Rc<Endpoint>, mut reader: Box<dyn AsyncRead + Unpin + Send>) {
    let mut scratch = vec![0u8; READ_CHUNK];
    loop {
        // Park while the guest has not consumed anything.
        loop {
            if ep.finished() {
                return;
            }
            let room = ep.cap.saturating_sub(ep.rx.borrow().len());
            if room > 0 {
                break;
            }
            let notified = ep.rx_room.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if ep.cap.saturating_sub(ep.rx.borrow().len()) > 0 || ep.finished() {
                continue;
            }
            notified.await;
        }
        let want = ep
            .cap
            .saturating_sub(ep.rx.borrow().len())
            .min(scratch.len());
        match reader.read(&mut scratch[..want]).await {
            Ok(0) => {
                ep.set_rx_eof();
                return;
            }
            Ok(n) => ep.push_rx(&scratch[..n]),
            Err(e) => {
                ep.fail(io_errno(&e));
                return;
            }
        }
    }
}

/// Moves bytes from the tx ring into the stream, and half-closes on request.
pub(crate) async fn writer_task(ep: Rc<Endpoint>, mut writer: Box<dyn AsyncWrite + Unpin + Send>) {
    loop {
        loop {
            if ep.finished() {
                let _ = writer.shutdown().await;
                return;
            }
            if !ep.tx.borrow().is_empty() || ep.tx_shutdown.get() {
                break;
            }
            let notified = ep.tx_data.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !ep.tx.borrow().is_empty() || ep.tx_shutdown.get() || ep.finished() {
                continue;
            }
            notified.await;
        }
        let chunk = ep.take_tx();
        if chunk.is_empty() {
            // Nothing left and a half-close asked for: send the FIN and stop.
            let _ = writer.shutdown().await;
            return;
        }
        if let Err(e) = writer.write_all(&chunk).await {
            ep.fail(io_errno(&e));
            return;
        }
    }
}

/// Resolves and connects an outbound endpoint, then starts its pumps.
///
/// The policy check on the *name* has already happened in the helper. What
/// happens here is the check the name-based list cannot make: a name is
/// somebody else's to point wherever they like, so the address it resolved to
/// is checked before anything is connected to it.
pub(crate) async fn connect_task(ep: Rc<Endpoint>, host: String, port: u16) {
    let addrs = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => {
            ep.fail(io_errno(&e));
            return;
        }
    };
    if addrs.is_empty() {
        ep.fail(errno::ENOENT);
        return;
    }
    let permitted: Vec<_> = addrs
        .into_iter()
        .filter(|a| crate::policy::resolved_address_allowed(&host, a.ip()))
        .collect();
    if permitted.is_empty() {
        tracing::warn!(
            host,
            port,
            "socket egress refused: the name resolved only into ranges a name may not reach"
        );
        ep.fail(errno::EPERM);
        return;
    }

    let mut last = errno::ECONNRESET;
    for addr in permitted {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                ep.set_peer(addr.to_string());
                let (r, w) = tokio::io::split(stream);
                ep.set_open();
                tokio::task::spawn_local(reader_task(ep.clone(), Box::new(r)));
                tokio::task::spawn_local(writer_task(ep.clone(), Box::new(w)));
                return;
            }
            Err(e) => last = io_errno(&e),
        }
    }
    ep.fail(last);
}

/// Whether an address is one a *name* may resolve to, exposed for the helper
/// that takes a literal.
pub(crate) fn literal_allowed(host: &str, addr: IpAddr) -> bool {
    crate::policy::resolved_address_allowed(host, addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(cap: usize) -> Rc<Endpoint> {
        Endpoint::new(
            cap,
            Rc::new(Readiness::default()),
            State::Open,
            String::new(),
        )
    }

    #[test]
    fn a_short_write_is_backpressure_and_not_failure() {
        let ep = endpoint(4);
        assert_eq!(ep.write(b"abcdef"), 4, "a full ring should take what fits");
        assert_eq!(ep.write(b"gh"), errno::EAGAIN);
        assert_eq!(ep.revents() & poll::OUT, 0, "a full ring is not writable");

        let mut out = [0u8; 2];
        // Draining the ring the way the writer task does makes room again.
        let taken = ep.take_tx();
        assert_eq!(taken, b"abcd");
        assert_eq!(ep.write(b"gh"), 2);
        assert_eq!(ep.read(&mut out), errno::EAGAIN, "nothing was received");
    }

    #[test]
    fn a_read_returns_zero_only_once_the_ring_has_drained() {
        let ep = endpoint(64);
        ep.push_rx(b"hello");
        ep.set_rx_eof();

        // EOF is pending, but there are bytes: readable, and emphatically not
        // hung up, or a program that breaks on HUP drops the last response.
        assert_ne!(ep.revents() & poll::IN, 0);
        assert_eq!(
            ep.revents() & poll::HUP,
            0,
            "HUP reported over buffered data"
        );

        let mut buf = [0u8; 5];
        assert_eq!(ep.read(&mut buf), 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(ep.read(&mut buf), 0, "a drained EOF reads as a clean zero");
        assert_ne!(ep.revents() & poll::HUP, 0);
    }

    #[test]
    fn a_failed_endpoint_reports_its_errno_rather_than_blocking() {
        let ep = endpoint(64);
        ep.fail(errno::ECONNRESET);
        let mut buf = [0u8; 4];
        assert_eq!(ep.read(&mut buf), errno::ECONNRESET);
        assert_eq!(ep.write(b"x"), errno::ECONNRESET);
        assert_ne!(ep.revents() & poll::ERR, 0);
    }

    #[test]
    fn writing_after_a_half_close_is_a_broken_pipe() {
        let ep = endpoint(64);
        assert_eq!(ep.write(b"req"), 3);
        ep.shutdown();
        assert_eq!(ep.write(b"more"), errno::EPIPE);
        assert_eq!(
            ep.revents() & poll::OUT,
            0,
            "a half-closed side is not writable"
        );
    }

    #[test]
    fn a_connecting_endpoint_takes_writes_but_is_not_writable_yet() {
        let ep = Endpoint::new(
            64,
            Rc::new(Readiness::default()),
            State::Connecting,
            String::new(),
        );
        // The guest may prepare a request before the connection lands.
        assert_eq!(ep.write(b"GET /"), 5);
        // ...but OUT is what says "connected", so it must not be set yet.
        assert_eq!(ep.revents() & poll::OUT, 0);
        ep.set_open();
        assert_ne!(ep.revents() & poll::OUT, 0);
    }

    #[tokio::test]
    async fn readiness_waits_are_not_lost_between_the_check_and_the_sleep() {
        let ready = Rc::new(Readiness::default());
        let epoch = ready.epoch();
        ready.bump();
        // The bump landed after the epoch was read, which is exactly the window
        // a bare Notify would drop.
        assert!(
            ready.wait(epoch, Duration::from_millis(50)).await,
            "a readiness change was lost"
        );
    }

    #[tokio::test]
    async fn a_wait_with_nothing_happening_times_out() {
        let ready = Rc::new(Readiness::default());
        assert!(!ready.wait(ready.epoch(), Duration::from_millis(10)).await);
    }
}
