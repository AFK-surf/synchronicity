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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
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
    epoch: AtomicU64,
    notify: Notify,
}

impl Readiness {
    pub(crate) fn bump(&self) {
        self.epoch.fetch_add(1, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
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
        if self.epoch() != since {
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
    /// Nothing more will be received: the reader stops wherever it is.
    ///
    /// Separate from [`Endpoint::abandoned`] because the two halves of a
    /// released endpoint are not released alike. A guest that lets go of an
    /// endpoint is done reading it immediately, and is *not* done writing it:
    /// what it queued is still owed to the far side ([`Endpoint::close_flushing`]).
    rx_stop: Notify,
    /// Set with `rx_stop`, for a reader parked between two of its own checks.
    rx_closed: Cell<bool>,
    /// The endpoint is being dropped where it stands: an in-flight write is
    /// cancelled and a connect attempt is abandoned. The hard counterpart to
    /// `rx_stop`, and what [`Endpoint::close`] and [`Endpoint::fail`] raise.
    abandoned: Notify,
    /// The writer task has stopped, so what was queued has either reached the
    /// stream or been given up on. What a teardown drain waits for.
    tx_done: Cell<bool>,
    /// See [`Endpoint::tx_done`].
    tx_finished: Notify,
    /// Woken when anything the guest could poll on changes.
    ready: Arc<Readiness>,
    /// What `sy_endpoint_info` reports.
    peer: RefCell<String>,
    /// Whether closing this endpoint returns one outbound-connect slot.
    egress_charge: Cell<bool>,
    /// Whether guest writes are meaningful for this endpoint.
    write_enabled: Cell<bool>,
    /// Bytes moved, for `synch socket ps`.
    pub(crate) bytes_in: Cell<u64>,
    /// Bytes moved, for `synch socket ps`.
    pub(crate) bytes_out: Cell<u64>,
}

impl Endpoint {
    pub(crate) fn new(cap: usize, ready: Arc<Readiness>, state: State, peer: String) -> Rc<Self> {
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
            rx_stop: Notify::new(),
            rx_closed: Cell::new(false),
            abandoned: Notify::new(),
            tx_done: Cell::new(false),
            tx_finished: Notify::new(),
            ready,
            peer: RefCell::new(peer),
            egress_charge: Cell::new(false),
            write_enabled: Cell::new(true),
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

    pub(crate) fn charge_egress(&self) {
        self.egress_charge.set(true);
    }

    pub(crate) fn take_egress_charge(&self) -> bool {
        self.egress_charge.replace(false)
    }

    pub(crate) fn set_read_only(&self) {
        self.write_enabled.set(false);
        self.ready.bump();
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
        self.stop_both();
    }

    /// Drops the endpoint where it stands, queued bytes and all.
    ///
    /// For an endpoint there is nothing left to send *to*: one that failed, one
    /// that never finished connecting, and the final teardown after
    /// [`Endpoint::close_flushing`] has been given its window. A guest closing
    /// a live endpoint goes through `close_flushing` instead.
    pub(crate) fn close(&self) {
        self.state.set(State::Closed);
        self.stop_both();
    }

    /// Releases the endpoint while letting what is queued reach the wire.
    ///
    /// The guest has let go of this endpoint, which says two different things
    /// about its two halves: nothing will ever read it again, and the bytes it
    /// already accepted for sending are still owed to the far side. So the
    /// receive half stops at once and the send half finishes on its own terms —
    /// drain, then FIN — exactly as `sy_shutdown` would have it.
    ///
    /// The invocation's own stream has been treated this way since sockets
    /// landed (`runtime::run` half-closes it and waits); an endpoint the
    /// program opened was not, and a proxy that queued its last bytes upstream
    /// and returned in the next line had them dropped by the teardown.
    ///
    /// An endpoint that is not open has nothing to flush and nowhere to flush
    /// it: a connecting one is abandoned rather than completed, since the guest
    /// has stopped waiting for the connection it would be finishing.
    pub(crate) fn close_flushing(&self) {
        if self.state.get() != State::Open {
            self.close();
            return;
        }
        // Drain, then FIN, under the writer's own timing.
        self.shutdown();
        // Nothing will read this again, so stop filling a ring nobody will
        // drain and give back what is already in it. Replaced rather than
        // cleared: `VecDeque::clear` is a truncate, which would leave the
        // endpoint holding a ring's worth of allocation for as long as its
        // write side takes to drain — which is exactly when it is held
        // longest.
        *self.rx.borrow_mut() = VecDeque::new();
        self.rx_eof.set(true);
        self.rx_closed.set(true);
        self.rx_room.notify_waiters();
        self.rx_stop.notify_waiters();
        self.ready.bump();
    }

    /// Wakes both pumps for a state they are meant to stop on.
    fn stop_both(&self) {
        self.rx_closed.set(true);
        self.rx_room.notify_waiters();
        self.tx_data.notify_waiters();
        self.rx_stop.notify_waiters();
        self.abandoned.notify_waiters();
        self.ready.bump();
    }

    fn finished(&self) -> bool {
        matches!(self.state.get(), State::Failed | State::Closed)
    }

    /// Whether the reader should stop, whatever the endpoint's state is.
    fn rx_stopped(&self) -> bool {
        self.finished() || self.rx_closed.get()
    }

    /// Notes that the writer task has stopped.
    fn mark_tx_done(&self) {
        self.tx_done.set(true);
        self.tx_finished.notify_waiters();
    }

    pub(crate) fn tx_done(&self) -> bool {
        self.tx_done.get()
    }

    /// Waits until nothing more is owed to the far side.
    ///
    /// Unbounded on purpose: the caller owns the deadline, because the window
    /// a teardown may spend flushing is one number for the whole invocation
    /// rather than one per endpoint.
    pub(crate) async fn wait_tx_done(&self) {
        loop {
            let notified = self.tx_finished.notified();
            tokio::pin!(notified);
            // Registered before the check, or a writer that finishes in the
            // window between the two is one this waits out in full.
            notified.as_mut().enable();
            if self.tx_done.get() {
                return;
            }
            notified.await;
        }
    }

    /// Whether both stream directions have reached shutdown for poll's HUP.
    ///
    /// Receive EOF alone is not terminal: as in Linux's TCP poll semantics,
    /// the local write half remains live until the guest shuts it down. Bytes
    /// received before EOF may still be buffered and readable after HUP.
    pub(crate) fn poll_terminal(&self) -> bool {
        self.finished() || (self.rx_eof.get() && self.tx_shutdown.get())
    }

    pub(crate) fn readable(&self) -> usize {
        self.rx.borrow().len()
    }

    pub(crate) fn writable(&self) -> usize {
        if self.write_enabled.get() {
            self.cap.saturating_sub(self.tx.borrow().len())
        } else {
            0
        }
    }

    /// Why an empty rx ring cannot be read: `0` at a clean EOF, this
    /// endpoint's errno if it failed, `EAGAIN` while it may still fill.
    ///
    /// Named because two helpers ask it now — a read and a splice see the same
    /// end of the same stream, and a day on which they disagreed about it is a
    /// program that treats an EOF as a reason to poll forever.
    fn drained_status(&self) -> i64 {
        match (self.rx_eof.get(), self.state.get()) {
            (_, State::Failed) => self.errno.get(),
            (true, _) => 0,
            (false, State::Closed) => 0,
            _ => errno::EAGAIN,
        }
    }

    /// Whether the tx side would take bytes at all, before any are taken from
    /// anywhere to give it.
    fn tx_status(&self) -> Result<(), i64> {
        if !self.write_enabled.get() {
            return Err(errno::EPERM);
        }
        match self.state.get() {
            State::Failed => return Err(self.errno.get()),
            State::Closed => return Err(errno::EPIPE),
            // A connecting endpoint accepts writes into the ring: the guest
            // gets to prepare a request before the connection lands, and the
            // writer task drains it when it does.
            State::Connecting | State::Open => {}
        }
        if self.tx_shutdown.get() {
            return Err(errno::EPIPE);
        }
        Ok(())
    }

    /// Copies out of the rx ring. `Ok(0)` is a clean EOF.
    pub(crate) fn read(&self, out: &mut [u8]) -> i64 {
        let mut rx = self.rx.borrow_mut();
        if rx.is_empty() {
            return self.drained_status();
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
        if let Err(code) = self.tx_status() {
            return code;
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

    /// Moves up to `max` bytes out of this endpoint's rx ring and into `to`'s
    /// tx ring, without them passing through the guest at all.
    ///
    /// This is [`Endpoint::read`] and [`Endpoint::write`] with the guest's
    /// buffer taken out of the middle, and taking it out is what removes the
    /// remainder: whatever does not fit is never picked up, so it stays in this
    /// endpoint's rx ring where the far side's flow control is already
    /// accounting for it. A short move is backpressure and needs no state
    /// anywhere — which is the whole reason `sy_splice` exists beside
    /// `sy_pump`, whose `struct sy_pump` is a remainder nobody can drop only
    /// because somebody remembered to carry it.
    ///
    /// `to` may be this same endpoint: `rx` and `tx` are separate cells, and
    /// splicing an endpoint into itself is an echo.
    pub(crate) fn splice_to(&self, to: &Endpoint, max: usize) -> i64 {
        // The destination is asked first. Bytes drained out of the source and
        // then refused by a broken destination would be bytes nobody has any
        // more, which is exactly the loss this helper exists to make
        // impossible.
        if let Err(code) = to.tx_status() {
            return code;
        }
        let avail = self.readable();
        if avail == 0 {
            return self.drained_status();
        }
        let n = avail.min(to.writable()).min(max);
        if n == 0 {
            return errno::EAGAIN;
        }

        let mut rx = self.rx.borrow_mut();
        to.tx.borrow_mut().extend(rx.drain(..n));
        drop(rx);
        // The same two wakeups a read and a write would have posted: the reader
        // task may have been parked on a full rx ring, and the writer task on
        // an empty tx one.
        self.rx_room.notify_waiters();
        to.tx_data.notify_waiters();
        self.bytes_in.set(self.bytes_in.get() + n as u64);
        to.bytes_out.set(to.bytes_out.get() + n as u64);
        n as i64
    }

    /// Half-closes the write side once what is buffered has drained.
    pub(crate) fn shutdown(&self) {
        let changed = !self.tx_shutdown.replace(true);
        self.tx_data.notify_waiters();
        if changed {
            // OUT disappeared; and if receive EOF was already present, the
            // endpoint just became a terminal, unconditional HUP.
            self.ready.bump();
        }
    }

    /// The readiness bits this endpoint has right now.
    pub(crate) fn revents(&self) -> u32 {
        let mut bits = 0;
        match self.state.get() {
            // A failed stream is also shut in both directions. Linux TCP
            // reports both EPOLLERR and EPOLLHUP once the socket reaches this
            // terminal state.
            State::Failed => bits |= poll::ERR | poll::HUP,
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
        // Linux separates receive-half shutdown from a terminal hangup.
        // RDHUP may accompany buffered data; IN tells the guest to keep
        // reading until read returns zero.
        if self.rx_eof.get() {
            bits |= poll::RDHUP;
            if self.tx_shutdown.get() {
                bits |= poll::HUP;
            }
        }
        if self.state.get() == State::Open && self.writable() > 0 && !self.tx_shutdown.get() {
            bits |= poll::OUT;
        }
        bits
    }

    /// Filters readiness for one guest poll entry.
    ///
    /// `ERR` and terminal `HUP` are unconditional, as with epoll. `RDHUP` is
    /// the maskable peer-write-half event; receive EOF also keeps `IN` ready so
    /// a guest can discover it by reading zero without requesting `RDHUP`.
    pub(crate) fn poll_revents(&self, events: u32) -> u32 {
        let bits = self.revents();
        bits & (events | poll::ERR | poll::HUP)
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
            if ep.rx_stopped() {
                return;
            }
            let room = ep.cap.saturating_sub(ep.rx.borrow().len());
            if room > 0 {
                break;
            }
            let notified = ep.rx_room.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if ep.cap.saturating_sub(ep.rx.borrow().len()) > 0 || ep.rx_stopped() {
                continue;
            }
            notified.await;
        }
        let want = ep
            .cap
            .saturating_sub(ep.rx.borrow().len())
            .min(scratch.len());
        let stop = ep.rx_stop.notified();
        tokio::pin!(stop);
        stop.as_mut().enable();
        if ep.rx_stopped() {
            return;
        }
        let read = tokio::select! {
            read = reader.read(&mut scratch[..want]) => read,
            _ = &mut stop => return,
        };
        if !absorb(&ep, read, &scratch) {
            return;
        }
    }
}

/// Applies one read result, and says whether to read again.
///
/// The check that opens it is the whole reason this is a function. `select!` is
/// unbiased, so a release that lands while a read is in flight can come back
/// with the read's answer rather than the stop's, and by then the endpoint is
/// one nobody will read again: pushing into a ring that was just given back
/// strands the bytes, and *failing* it is worse than that. `close_flushing`
/// deliberately leaves the endpoint open so its write side can drain, which
/// means `fail` here is no longer the no-op it was against a hard `close` — it
/// would cancel the in-flight write and discard the tx ring, silently undoing
/// the flush the release just promised, after the host had told the guest those
/// bytes were accepted.
fn absorb(ep: &Endpoint, read: std::io::Result<usize>, scratch: &[u8]) -> bool {
    if ep.rx_stopped() {
        return false;
    }
    match read {
        Ok(0) => {
            ep.set_rx_eof();
            false
        }
        Ok(n) => {
            ep.push_rx(&scratch[..n]);
            true
        }
        Err(e) => {
            ep.fail(io_errno(&e));
            false
        }
    }
}

/// Moves bytes from the tx ring into the stream, and half-closes on request.
///
/// Wrapped so that every way out of the pump — a drained half-close, a failed
/// write, an abandoned endpoint — arrives at the same statement: nothing more
/// is owed to the far side. That is what a teardown drain waits for, and a path
/// that forgot to say so would be one it waited out in full.
pub(crate) async fn writer_task(ep: Rc<Endpoint>, writer: Box<dyn AsyncWrite + Unpin + Send>) {
    write_pump(&ep, writer).await;
    ep.mark_tx_done();
}

async fn write_pump(ep: &Rc<Endpoint>, mut writer: Box<dyn AsyncWrite + Unpin + Send>) {
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
        let abandoned = ep.abandoned.notified();
        tokio::pin!(abandoned);
        abandoned.as_mut().enable();
        if ep.finished() {
            let _ = writer.shutdown().await;
            return;
        }
        let written = tokio::select! {
            written = writer.write_all(&chunk) => written,
            _ = &mut abandoned => return,
        };
        if let Err(e) = written {
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
/// Wrapped like [`writer_task`], and for the same reason with more paths to
/// forget: an endpoint whose writer never ran at all — a refused name, a
/// connection nobody answered — owes the far side nothing, and a teardown drain
/// must be told that rather than waiting out its window on it.
pub(crate) async fn connect_task(ep: Rc<Endpoint>, host: String, port: u16) {
    connect_and_pump(&ep, host, port).await;
    ep.mark_tx_done();
}

async fn connect_and_pump(ep: &Rc<Endpoint>, host: String, port: u16) {
    let abandoned = ep.abandoned.notified();
    tokio::pin!(abandoned);
    abandoned.as_mut().enable();
    if ep.finished() {
        return;
    }
    let lookup = tokio::select! {
        lookup = tokio::net::lookup_host((host.as_str(), port)) => lookup,
        _ = &mut abandoned => return,
    };
    let addrs = match lookup {
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
        let abandoned = ep.abandoned.notified();
        tokio::pin!(abandoned);
        abandoned.as_mut().enable();
        if ep.finished() {
            return;
        }
        let connected = tokio::select! {
            connected = tokio::net::TcpStream::connect(addr) => connected,
            _ = &mut abandoned => return,
        };
        match connected {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                ep.set_peer(addr.to_string());
                let (r, w) = tokio::io::split(stream);
                ep.set_open();
                tokio::join!(
                    reader_task(ep.clone(), Box::new(r)),
                    writer_task(ep.clone(), Box::new(w))
                );
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
            Arc::new(Readiness::default()),
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
    fn a_splice_leaves_what_did_not_fit_where_it_was() {
        let from = endpoint(64);
        let to = endpoint(4);
        from.push_rx(b"abcdefgh");

        // A short move, and the six bytes it could not place are still in the
        // source: nothing was picked up that had nowhere to go, which is the
        // difference from a read followed by a short write.
        assert_eq!(from.splice_to(&to, 8), 4);
        assert_eq!(to.take_tx(), b"abcd");
        assert_eq!(from.readable(), 4);

        // `max` bounds a call below what both sides could take.
        assert_eq!(from.splice_to(&to, 1), 1);
        assert_eq!(from.splice_to(&to, 64), 3);
        assert_eq!(to.take_tx(), b"efgh");
        assert_eq!(from.splice_to(&to, 64), errno::EAGAIN, "an empty source");
    }

    #[test]
    fn a_splice_reports_the_source_eof_and_the_destinations_failure() {
        let from = endpoint(64);
        let to = endpoint(64);
        from.push_rx(b"tail");
        from.set_rx_eof();

        assert_eq!(from.splice_to(&to, 64), 4);
        assert_eq!(
            from.splice_to(&to, 64),
            0,
            "a drained EOF splices as a clean zero, as it reads as one"
        );

        // A destination that cannot take bytes is asked before any are taken,
        // so the source still has them — for a caller with somewhere else to
        // put them, and for one that just wants to see the error again.
        let broken = endpoint(64);
        broken.fail(errno::ECONNRESET);
        let live = endpoint(64);
        live.push_rx(b"payload");
        assert_eq!(live.splice_to(&broken, 64), errno::ECONNRESET);
        assert_eq!(live.readable(), 7, "a refused splice consumed the source");

        let closing = endpoint(64);
        closing.shutdown();
        assert_eq!(live.splice_to(&closing, 64), errno::EPIPE);
        assert_eq!(live.readable(), 7);
    }

    #[test]
    fn an_endpoint_spliced_into_itself_is_an_echo() {
        let ep = endpoint(64);
        ep.push_rx(b"back");
        assert_eq!(ep.splice_to(&ep, 64), 4);
        assert_eq!(ep.take_tx(), b"back");
    }

    #[test]
    fn a_read_returns_zero_only_once_the_ring_has_drained() {
        let ep = endpoint(64);
        ep.push_rx(b"hello");
        ep.set_rx_eof();

        // Receive shutdown is visible immediately, even while the bytes that
        // preceded the FIN are still buffered. IN remains set until a read
        // observes EOF; HUP is reserved for shutdown in both directions.
        assert_eq!(
            ep.revents() & (poll::IN | poll::RDHUP | poll::HUP),
            poll::IN | poll::RDHUP
        );

        let mut buf = [0u8; 5];
        assert_eq!(ep.read(&mut buf), 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(ep.read(&mut buf), 0, "a drained EOF reads as a clean zero");
        assert_eq!(
            ep.revents() & (poll::IN | poll::RDHUP | poll::HUP),
            poll::IN | poll::RDHUP
        );
    }

    #[test]
    fn a_receive_half_close_does_not_wake_output_or_inactive_poll_entries() {
        let ep = endpoint(4);
        ep.set_rx_eof();

        assert_eq!(ep.poll_revents(0), 0, "an inactive entry woke on EOF");
        assert_eq!(
            ep.poll_revents(poll::OUT),
            poll::OUT,
            "receive EOF hid a still-writable output half"
        );
        assert_eq!(ep.write(b"full"), 4);
        assert_eq!(
            ep.poll_revents(poll::OUT),
            0,
            "receive EOF made a backpressured output wait spin"
        );
        assert_eq!(
            ep.poll_revents(poll::IN),
            poll::IN,
            "IN did not make the pending EOF readable"
        );
        assert_eq!(
            ep.poll_revents(poll::RDHUP),
            poll::RDHUP,
            "an explicitly requested receive shutdown was hidden"
        );
        assert_eq!(ep.poll_revents(poll::HUP), 0, "one live half became HUP");
    }

    #[test]
    fn shutting_both_halves_down_is_an_unconditional_hangup() {
        let ep = endpoint(4);
        ep.push_rx(b"last");
        ep.set_rx_eof();
        ep.shutdown();

        assert!(ep.poll_terminal());
        assert_eq!(
            ep.poll_revents(0),
            poll::HUP,
            "terminal HUP was masked by an empty interest set"
        );
        assert_eq!(
            ep.poll_revents(poll::IN | poll::RDHUP),
            poll::IN | poll::RDHUP | poll::HUP,
            "terminal HUP hid buffered input or receive shutdown"
        );
    }

    #[test]
    fn terminal_endpoint_events_need_no_explicit_interest() {
        let closed = endpoint(4);
        closed.close();
        assert_eq!(closed.poll_revents(0), poll::HUP);

        let failed = endpoint(4);
        failed.fail(errno::ECONNRESET);
        assert_eq!(failed.poll_revents(0), poll::ERR | poll::HUP);
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
            Arc::new(Readiness::default()),
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

    #[test]
    fn releasing_a_live_endpoint_keeps_what_it_accepted_and_drops_what_it_did_not_read() {
        let ep = endpoint(64);
        assert_eq!(ep.write(b"queued"), 6);
        ep.push_rx(b"never read");
        ep.close_flushing();

        // The send half finishes on its own terms — drain, then FIN — so the
        // bytes the host told the guest it had taken are still going out.
        assert_eq!(ep.state(), State::Open);
        assert_eq!(ep.take_tx(), b"queued");
        assert!(!ep.tx_done(), "the writer had not finished");
        // The receive half is over at once: nothing will read it again, and a
        // ring nobody will drain is a quarter megabyte held for no one. The
        // capacity is the assertion that matters — emptying the ring without
        // releasing it would hold the memory for exactly as long as draining
        // takes, which is when it is held longest.
        assert!(ep.rx_stopped());
        assert_eq!(ep.readable(), 0);
        assert_eq!(
            ep.rx.borrow().capacity(),
            0,
            "the ring was emptied, not freed"
        );
    }

    #[test]
    fn a_receive_error_on_a_released_endpoint_does_not_cancel_its_drain() {
        let ep = endpoint(64);
        assert_eq!(ep.write(b"queued"), 6);
        ep.close_flushing();

        // The read was already in flight when the guest let go of the endpoint,
        // and it came back an error. `select!` is unbiased, so this is the half
        // of the race where the reader is the one that gets to act — and
        // failing the endpoint here would cancel the write side's drain, after
        // the host had told the guest those bytes were accepted.
        assert!(!absorb(
            &ep,
            Err(std::io::ErrorKind::ConnectionReset.into()),
            &[]
        ));
        assert_eq!(ep.state(), State::Open);
        assert_eq!(ep.take_tx(), b"queued");

        // A live endpoint still fails on one, which is what the bit is for.
        let live = endpoint(64);
        assert!(!absorb(
            &live,
            Err(std::io::ErrorKind::ConnectionReset.into()),
            &[]
        ));
        assert_eq!(live.state(), State::Failed);
    }

    #[test]
    fn releasing_an_endpoint_that_never_connected_abandons_it() {
        let ep = Endpoint::new(
            64,
            Arc::new(Readiness::default()),
            State::Connecting,
            String::new(),
        );
        // A request prepared before the connection landed. There is nowhere to
        // flush it to, and finishing the connect to send it would be finishing
        // something the guest has stopped waiting for.
        assert_eq!(ep.write(b"request"), 7);
        ep.close_flushing();
        assert_eq!(ep.state(), State::Closed);
    }

    /// The writer's two endings, side by side, because the difference between
    /// them is the whole of what a released endpoint costs the far side.
    ///
    /// Both run with the writer already *inside* `write_all` and blocked on a
    /// pipe narrower than the payload. Releasing before the pump has run at all
    /// tests the flag it reads on its way past, which is the easy half; this is
    /// the half where the ending is decided by cancellation, and the half the
    /// split between `rx_stop` and `abandoned` exists for.
    #[tokio::test]
    async fn a_released_endpoint_finishes_the_write_it_was_inside_and_an_abandoned_one_does_not() {
        async fn last_words(release: impl FnOnce(&Endpoint)) -> Vec<u8> {
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let ep = endpoint(64);
                    assert_eq!(ep.write(b"last words"), 10);
                    // Four bytes of pipe for ten bytes of payload: the writer
                    // takes the whole chunk, places what fits, and is still
                    // holding the rest when the endpoint is released.
                    let (ours, theirs) = tokio::io::duplex(4);
                    let (_, writer) = tokio::io::split(ours);
                    let pump = tokio::task::spawn_local(writer_task(ep.clone(), Box::new(writer)));
                    // An empty tx ring is the writer holding its chunk.
                    tokio::time::timeout(Duration::from_secs(5), async {
                        while ep.writable() != 64 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .expect("the writer never picked the chunk up");

                    release(&ep);
                    // Read alongside the wait rather than after it: a release
                    // has to be able to finish, and it cannot finish into a
                    // pipe nobody is emptying.
                    let reading = tokio::task::spawn_local(async move {
                        let mut theirs = theirs;
                        let mut seen = Vec::new();
                        theirs.read_to_end(&mut seen).await.unwrap();
                        seen
                    });
                    tokio::time::timeout(Duration::from_secs(5), ep.wait_tx_done())
                        .await
                        .expect("the writer never said it had stopped");
                    pump.await.unwrap();
                    reading.await.unwrap()
                })
                .await
        }

        assert_eq!(
            last_words(Endpoint::close_flushing).await,
            b"last words",
            "a released endpoint dropped bytes the host had accepted"
        );
        let abandoned = last_words(Endpoint::close).await;
        assert!(
            abandoned.len() < 10,
            "an abandoned endpoint is dropped where it stands, mid-write: {abandoned:?}"
        );
    }

    #[tokio::test]
    async fn readiness_waits_are_not_lost_between_the_check_and_the_sleep() {
        let ready = Arc::new(Readiness::default());
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
        let ready = Arc::new(Readiness::default());
        assert!(!ready.wait(ready.epoch(), Duration::from_millis(10)).await);
    }
}
