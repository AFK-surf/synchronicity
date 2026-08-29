//! Exact pipe-backed processes and Unix PTYs for declared capabilities.

use std::{
    cell::{Cell, RefCell},
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    pin::Pin,
    process::Stdio,
    rc::Weak,
    sync::Mutex,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::{abi::errno, runtime::endpoint::Readiness};

/// Serializes PTY descriptor creation with every declared-process fork.
///
/// `openpty` has no close-on-exec flag, so setting `FD_CLOEXEC` afterward is
/// otherwise racy in this multi-worker daemon: another worker can fork between
/// the allocation and the `fcntl`. All runtime process spawns take the same
/// lock across `Command::spawn`, closing that inheritance window.
static PROCESS_SPAWN_FD_LOCK: Mutex<()> = Mutex::new(());

/// Inherited host variables that are useful to ordinary command-line tools
/// without exposing the daemon's application configuration or credentials.
const BASIC_PROCESS_ENVIRONMENT: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "TZ",
    "TMPDIR",
];

fn configure_process_environment(command: &mut std::process::Command) {
    command.env_clear();
    for name in BASIC_PROCESS_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env(
        "PATH",
        std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
    );
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ProcessStatus {
    pub(crate) exited: bool,
    pub(crate) exit_code: u32,
    pub(crate) signal: Option<String>,
    pub(crate) core_dumped: bool,
}

#[derive(Debug)]
pub(crate) enum Child {
    Pipe(tokio::process::Child),
    Pty(std::process::Child),
}

#[derive(Debug)]
pub(crate) struct ProcessSlot {
    pub(crate) child: RefCell<Option<Child>>,
    pub(crate) status: RefCell<ProcessStatus>,
    pub(crate) allowed_signals: u64,
    pub(crate) main: i64,
    pub(crate) stderr: Option<i64>,
}

impl ProcessSlot {
    pub(crate) fn refresh(&self) -> Result<ProcessStatus, i64> {
        if self.status.borrow().exited {
            return Ok(self.status.borrow().clone());
        }
        let mut child = self.child.borrow_mut();
        let status = match child.as_mut() {
            Some(Child::Pipe(child)) => child.try_wait(),
            Some(Child::Pty(child)) => child.try_wait(),
            None => return Ok(self.status.borrow().clone()),
        }
        .map_err(|_| errno::ECONNRESET)?;
        if let Some(status) = status {
            let mut out = ProcessStatus {
                exited: true,
                exit_code: status.code().unwrap_or(0).max(0) as u32,
                signal: None,
                core_dumped: false,
            };
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt as _;
                if let Some(signal) = status.signal() {
                    out.signal = Some(signal_name(signal).to_string());
                    out.core_dumped = status.core_dumped();
                }
            }
            *self.status.borrow_mut() = out.clone();
            child.take();
            Ok(out)
        } else {
            Ok(self.status.borrow().clone())
        }
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        match self.child.borrow().as_ref()? {
            Child::Pipe(child) => child.id(),
            Child::Pty(child) => Some(child.id()),
        }
    }

    /// Signals the child's process group, if the child is still ours to signal.
    ///
    /// Best-effort by design, and not containment. `pid()` is `None` once
    /// `refresh` has reaped the direct child — which `watch_exit` does on the
    /// first `SIGCHLD` after it exits — and after that there is no group leader
    /// left to name: a descendant that outlived its parent, or that called
    /// `setsid` for itself, keeps running under the daemon's UID and nothing
    /// here reaps it. That is the documented shape of a process capability
    /// (`docs/SSH-SOCKETS.md` §7.1, §12.10); an operator who needs a bound
    /// declares an executable that bounds itself.
    pub(crate) fn kill(&self) {
        let Some(pid) = self.pid() else { return };
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

/// Wakes a guest poll when this process changes state.
///
/// The signal receiver is installed before the process is spawned, and Tokio's
/// signal stream retains a notification until it is consumed. Sampling once
/// before each wait therefore closes both races: an exit before this task first
/// runs is found by `refresh`, and an exit after that sample wakes `recv`.
/// A weak reference lets closing the process handle still drop and kill it.
pub(crate) async fn watch_exit(
    process: Weak<ProcessSlot>,
    ready: std::sync::Arc<Readiness>,
    mut child_events: tokio::signal::unix::Signal,
) {
    loop {
        let Some(process) = process.upgrade() else {
            return;
        };
        let terminal = match process.refresh() {
            Ok(status) => status.exited,
            Err(_) => true,
        };
        drop(process);
        if terminal {
            ready.bump();
            return;
        }
        if child_events.recv().await.is_none() {
            ready.bump();
            return;
        }
    }
}

impl Drop for ProcessSlot {
    fn drop(&mut self) {
        let Some(child) = self.child.get_mut().take() else {
            return;
        };
        match child {
            Child::Pipe(mut child) => {
                // Group-kill first: the slot still owns the child, so its pid
                // is reserved and same-group descendants are still reachable
                // before the child is reaped by tokio's background reaper.
                // Reaching them is not the same as containing them — a
                // descendant in its own session is already out of range here
                // (see `ProcessSlot::kill`).
                if let Some(pid) = child.id() {
                    if let Ok(pid) = i32::try_from(pid) {
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                    }
                }
                let _ = child.start_kill();
            }
            Child::Pty(mut child) => {
                if let Ok(pid) = i32::try_from(child.id()) {
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                }
                // std::process::Child has no background reaper, and SIGKILL is
                // no guarantee of prompt death (a child stuck in uninterruptible
                // kernel I/O stays a zombie). Reap on a detached thread so a
                // stuck child can never block the worker thread this Drop runs
                // on; if the thread cannot spawn, dropping the Child unreaped
                // leaves a transient zombie until the daemon exits — never
                // block the worker.
                let _ = std::thread::Builder::new()
                    .name("synch-reap".into())
                    .spawn(move || {
                        let _ = child.wait();
                    });
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct PtySlot {
    pub(crate) master: File,
    pub(crate) slave: RefCell<Option<File>>,
    pub(crate) endpoint: i64,
    pub(crate) capability: u32,
    pub(crate) spawned: Cell<bool>,
    pub(crate) term: String,
}

impl PtySlot {
    pub(crate) fn resize(
        &self,
        columns: u32,
        rows: u32,
        pixel_width: u32,
        pixel_height: u32,
    ) -> Result<(), i64> {
        let size = libc::winsize {
            ws_row: rows.min(u16::MAX as u32) as u16,
            ws_col: columns.min(u16::MAX as u32) as u16,
            ws_xpixel: pixel_width.min(u16::MAX as u32) as u16,
            ws_ypixel: pixel_height.min(u16::MAX as u32) as u16,
        };
        let result = unsafe {
            libc::ioctl(
                std::os::fd::AsRawFd::as_raw_fd(&self.master),
                libc::TIOCSWINSZ,
                &size,
            )
        };
        (result == 0).then_some(()).ok_or(errno::EINVAL)
    }
}

#[allow(
    clippy::unnecessary_mut_passed,
    reason = "macOS declares openpty's winsize pointer mutable; Linux declares it const"
)]
pub(crate) fn open_pty(
    columns: u32,
    rows: u32,
    pixel_width: u32,
    pixel_height: u32,
) -> Result<(File, File), i64> {
    let _spawn_guard = PROCESS_SPAWN_FD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    let mut size = libc::winsize {
        ws_row: rows.min(u16::MAX as u32) as u16,
        ws_col: columns.min(u16::MAX as u32) as u16,
        ws_xpixel: pixel_width.min(u16::MAX as u32) as u16,
        ws_ypixel: pixel_height.min(u16::MAX as u32) as u16,
    };
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if result != 0 {
        return Err(errno::ELIMIT);
    }
    // The pty descriptors must not survive exec: the declared child runs via
    // the fork+exec path (a pre_exec closure is always installed), which does
    // not close stray descriptors, and an inherited master would let the
    // child forge "user input" to the guest. std's spawn clears
    // CLOEXEC on the stdio targets via dup2; `spawn_pty`'s pre_exec also
    // clears it on fds 0-2 as the belt-and-braces guard for a dup2 no-op.
    if set_cloexec(master).is_err() || set_cloexec(slave).is_err() {
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(errno::ELIMIT);
    }
    // SAFETY: openpty returned two newly owned descriptors.
    Ok(unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) })
}

/// Marks a descriptor close-on-exec.
fn set_cloexec(fd: libc::c_int) -> Result<(), i64> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(errno::ELIMIT);
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(errno::ELIMIT);
    }
    Ok(())
}

/// Applies the portable subset of RFC 4254 terminal modes. Unknown modes are
/// intentionally ignored, as required by the protocol.
pub(crate) fn apply_pty_modes(slave: &File, modes: &[(u8, u32)]) -> Result<(), i64> {
    let fd = slave.as_raw_fd();
    let mut attrs = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, attrs.as_mut_ptr()) } != 0 {
        return Err(errno::EINVAL);
    }
    let mut attrs = unsafe { attrs.assume_init() };
    for &(opcode, value) in modes {
        let enabled = value != 0;
        let set_flag = |flags: &mut libc::tcflag_t, flag: libc::tcflag_t| {
            if enabled {
                *flags |= flag;
            } else {
                *flags &= !flag;
            }
        };
        match opcode {
            1 => attrs.c_cc[libc::VINTR] = value as libc::cc_t,
            2 => attrs.c_cc[libc::VQUIT] = value as libc::cc_t,
            3 => attrs.c_cc[libc::VERASE] = value as libc::cc_t,
            4 => attrs.c_cc[libc::VKILL] = value as libc::cc_t,
            5 => attrs.c_cc[libc::VEOF] = value as libc::cc_t,
            6 => attrs.c_cc[libc::VEOL] = value as libc::cc_t,
            8 => attrs.c_cc[libc::VSTART] = value as libc::cc_t,
            9 => attrs.c_cc[libc::VSTOP] = value as libc::cc_t,
            10 => attrs.c_cc[libc::VSUSP] = value as libc::cc_t,
            30 => set_flag(&mut attrs.c_iflag, libc::IGNPAR),
            31 => set_flag(&mut attrs.c_iflag, libc::PARMRK),
            32 => set_flag(&mut attrs.c_iflag, libc::INPCK),
            33 => set_flag(&mut attrs.c_iflag, libc::ISTRIP),
            34 => set_flag(&mut attrs.c_iflag, libc::INLCR),
            35 => set_flag(&mut attrs.c_iflag, libc::IGNCR),
            36 => set_flag(&mut attrs.c_iflag, libc::ICRNL),
            38 => set_flag(&mut attrs.c_iflag, libc::IXON),
            40 => set_flag(&mut attrs.c_iflag, libc::IXOFF),
            50 => set_flag(&mut attrs.c_lflag, libc::ISIG),
            51 => set_flag(&mut attrs.c_lflag, libc::ICANON),
            53 => set_flag(&mut attrs.c_lflag, libc::ECHO),
            54 => set_flag(&mut attrs.c_lflag, libc::ECHOE),
            55 => set_flag(&mut attrs.c_lflag, libc::ECHOK),
            56 => set_flag(&mut attrs.c_lflag, libc::ECHONL),
            57 => set_flag(&mut attrs.c_lflag, libc::NOFLSH),
            58 => set_flag(&mut attrs.c_lflag, libc::TOSTOP),
            59 => set_flag(&mut attrs.c_lflag, libc::IEXTEN),
            70 => set_flag(&mut attrs.c_oflag, libc::OPOST),
            72 => set_flag(&mut attrs.c_oflag, libc::ONLCR),
            73 => set_flag(&mut attrs.c_oflag, libc::OCRNL),
            74 => set_flag(&mut attrs.c_oflag, libc::ONOCR),
            75 => set_flag(&mut attrs.c_oflag, libc::ONLRET),
            90 if enabled => {
                attrs.c_cflag = (attrs.c_cflag & !libc::CSIZE) | libc::CS7;
            }
            91 if enabled => {
                attrs.c_cflag = (attrs.c_cflag & !libc::CSIZE) | libc::CS8;
            }
            92 => set_flag(&mut attrs.c_cflag, libc::PARENB),
            93 => set_flag(&mut attrs.c_cflag, libc::PARODD),
            128 => set_speed(&mut attrs, value, true),
            129 => set_speed(&mut attrs, value, false),
            _ => {}
        }
    }
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &attrs) } != 0 {
        return Err(errno::EINVAL);
    }
    Ok(())
}

fn set_speed(attrs: &mut libc::termios, value: u32, input: bool) {
    let speed = match value {
        0 => libc::B0,
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        300 => libc::B300,
        600 => libc::B600,
        1_200 => libc::B1200,
        2_400 => libc::B2400,
        4_800 => libc::B4800,
        9_600 => libc::B9600,
        19_200 => libc::B19200,
        38_400 => libc::B38400,
        57_600 => libc::B57600,
        115_200 => libc::B115200,
        _ => return,
    };
    unsafe {
        if input {
            libc::cfsetispeed(attrs, speed);
        } else {
            libc::cfsetospeed(attrs, speed);
        }
    }
}

pub(crate) fn spawn_pipe(
    capability: &synch_core::ProcessCapability,
) -> Result<
    (
        tokio::process::Child,
        tokio::process::ChildStdout,
        tokio::process::ChildStdin,
        tokio::process::ChildStderr,
    ),
    i64,
> {
    let mut command = tokio::process::Command::new(&capability.executable);
    configure_process_environment(command.as_std_mut());
    command
        .args(capability.argv.iter().skip(1))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // The declared argv[0] is part of the reviewed capability; execve must
    // present exactly what the guest declared, not the executable path, or
    // argv-dispatching programs (busybox applets, bash's "sh" detection) run
    // something other than the reviewed command.
    if let Some(first) = capability.argv.first() {
        command.arg0(first);
    }
    configure_unix_command(command.as_std_mut(), false);
    let _spawn_guard = PROCESS_SPAWN_FD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut child = command.spawn().map_err(|_| errno::ENOENT)?;
    let stdout = child.stdout.take().ok_or(errno::ECONNRESET)?;
    let stdin = child.stdin.take().ok_or(errno::ECONNRESET)?;
    let stderr = child.stderr.take().ok_or(errno::ECONNRESET)?;
    Ok((child, stdout, stdin, stderr))
}

pub(crate) fn spawn_pty(
    capability: &synch_core::ProcessCapability,
    slave: File,
    term: &str,
) -> Result<std::process::Child, i64> {
    let stdin = slave.try_clone().map_err(|_| errno::ECONNRESET)?;
    let stdout = slave.try_clone().map_err(|_| errno::ECONNRESET)?;
    let mut command = std::process::Command::new(&capability.executable);
    configure_process_environment(&mut command);
    command
        .args(capability.argv.iter().skip(1))
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(slave));
    // The validated `pty-req` name, as sshd would export it. A client with no
    // local terminal sends an empty name; the child then gets no TERM at all
    // rather than an empty lie.
    if !term.is_empty() {
        command.env("TERM", term);
    }
    // The declared argv[0] is part of the reviewed capability; execve must
    // present exactly what the guest declared, not the executable path.
    if let Some(first) = capability.argv.first() {
        use std::os::unix::process::CommandExt as _;
        command.arg0(first);
    }
    configure_unix_command(&mut command, true);
    let _spawn_guard = PROCESS_SPAWN_FD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    command.spawn().map_err(|_| errno::ENOENT)
}

fn configure_unix_command(command: &mut std::process::Command, controlling_tty: bool) {
    use std::os::unix::process::CommandExt as _;
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if controlling_tty && libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The pty descriptors are close-on-exec and std's dup2 clears the
            // flag on the new stdio descriptors, but a stdio target fd that
            // already collides with a pty fd (a dup2 no-op) would keep it:
            // make the child's stdio survive exec unconditionally.
            for fd in 0..3 {
                let _ = libc::fcntl(fd, libc::F_SETFD, 0);
            }
            Ok(())
        });
    }
}

pub(crate) fn signal_number(name: &str) -> Option<(u64, i32)> {
    match name {
        "HUP" => Some((1 << 0, libc::SIGHUP)),
        "INT" => Some((1 << 1, libc::SIGINT)),
        "TERM" => Some((1 << 2, libc::SIGTERM)),
        _ => None,
    }
}

fn signal_name(signal: i32) -> &'static str {
    match signal {
        libc::SIGHUP => "HUP",
        libc::SIGINT => "INT",
        libc::SIGTERM => "TERM",
        libc::SIGKILL => "KILL",
        _ => "UNKNOWN",
    }
}

/// Starts the blocking read side of a PTY master and returns its adapter.
///
/// The channel between the thread and the adapter is bounded, so a guest
/// that stops reading parks the thread rather than growing a queue.
pub(crate) fn pty_reader(master: &File) -> Result<ChannelReader, i64> {
    let mut reader = master.try_clone().map_err(|_| errno::ECONNRESET)?;
    let (read_tx, read_rx) = tokio::sync::mpsc::channel(8);
    std::thread::Builder::new()
        .name("synch-pty-read".into())
        .spawn(move || {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) if read_tx.blocking_send(buffer[..n].to_vec()).is_err() => break,
                    Ok(_) => {}
                }
            }
        })
        .map_err(|_| errno::ELIMIT)?;
    Ok(ChannelReader::new(read_rx))
}

/// A clone of the PTY master for the bounded write bridge in the helper.
pub(crate) fn pty_writer(master: &File) -> Result<std::sync::Arc<File>, i64> {
    master
        .try_clone()
        .map(std::sync::Arc::new)
        .map_err(|_| errno::ECONNRESET)
}

/// One blocking write of a chunk to the PTY master, for `spawn_blocking`.
pub(crate) fn pty_write_all(master: &std::sync::Arc<File>, chunk: &[u8]) -> bool {
    (&**master).write_all(chunk).is_ok()
}

pub(crate) struct ChannelReader {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
}

impl ChannelReader {
    pub(crate) fn new(receiver: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            receiver,
            current: Vec::new(),
            offset: 0,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset == self.current.len() {
            // Skip empty chunks instead of letting one read as end of stream.
            // A zero-length SSH extended-data payload is a legal packet any
            // client may send at will, and `AsyncRead` gives a zero-byte fill
            // exactly one meaning: EOF. Forwarding one would half-close this
            // lane on the guest for the rest of the connection. Only the
            // sender going away ends the stream.
            loop {
                match self.receiver.poll_recv(cx) {
                    Poll::Ready(Some(bytes)) if bytes.is_empty() => continue,
                    Poll::Ready(Some(bytes)) => {
                        self.current = bytes;
                        self.offset = 0;
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        let n = out.remaining().min(self.current.len() - self.offset);
        out.put_slice(&self.current[self.offset..self.offset + n]);
        self.offset += n;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt as _;
    use tokio::io::AsyncReadExt as _;

    #[test]
    fn a_pty_child_inherits_home() {
        let Some(home) = std::env::var_os("HOME") else {
            eprintln!("skipping: the test process has no HOME");
            return;
        };
        let capability = synch_core::ProcessCapability {
            id: 15,
            flags: 0x01,
            executable: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "printf %s \"$HOME\"".into()],
            allowed_signals: 0,
        };
        let (mut master, slave) = open_pty(80, 24, 0, 0).unwrap();
        let mut child = spawn_pty(&capability, slave, "").unwrap();
        assert!(child.wait().unwrap().success());

        let mut output = Vec::new();
        let mut buffer = [0_u8; 256];
        loop {
            match master.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => output.extend_from_slice(&buffer[..n]),
            }
        }
        assert_eq!(output, home.as_os_str().as_bytes());
    }

    #[tokio::test]
    async fn a_pipe_process_runs_only_its_exact_declared_argv() {
        let capability = synch_core::ProcessCapability {
            id: 1,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "printf exact-process".into()],
            allowed_signals: 0,
        };
        let (mut child, mut stdout, stdin, mut stderr) = spawn_pipe(&capability).unwrap();
        drop(stdin);
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.unwrap();
        let mut error = Vec::new();
        stderr.read_to_end(&mut error).await.unwrap();
        assert!(child.wait().await.unwrap().success());
        assert_eq!(output, b"exact-process");
        assert!(error.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_child_may_create_a_new_session() {
        let Some(setsid) = ["/usr/bin/setsid", "/bin/setsid"]
            .into_iter()
            .find(|path| std::path::Path::new(path).is_file())
        else {
            eprintln!("skipping: util-linux setsid is unavailable");
            return;
        };
        let capability = synch_core::ProcessCapability {
            id: 14,
            flags: 0x02,
            executable: setsid.into(),
            argv: vec![
                "setsid".into(),
                "--fork".into(),
                "--wait".into(),
                "/bin/true".into(),
            ],
            allowed_signals: 0,
        };
        let (mut child, stdout, stdin, stderr) = spawn_pipe(&capability).unwrap();
        drop((stdout, stdin, stderr));
        assert!(child.wait().await.unwrap().success());
    }

    #[test]
    fn pty_slot_drop_returns_promptly_with_a_stuck_child() {
        let (master, slave) = open_pty(80, 24, 0, 0).unwrap();
        let capability = synch_core::ProcessCapability {
            id: 9,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "while :; do :; done".into()],
            allowed_signals: 0,
        };
        let child = spawn_pty(&capability, slave, "xterm").unwrap();
        let pid = child.id();
        let slot = ProcessSlot {
            child: RefCell::new(Some(Child::Pty(child))),
            status: RefCell::new(ProcessStatus::default()),
            allowed_signals: 0,
            main: -1,
            stderr: None,
        };
        // Let the child get going, then drop the slot: the group SIGKILL
        // fires and the reap happens on a detached thread, so the drop must
        // not block for the child's busy loop (a child stuck in
        // uninterruptible kernel I/O would otherwise wedge the worker).
        std::thread::sleep(std::time::Duration::from_millis(100));
        let start = std::time::Instant::now();
        drop(slot);
        drop(master);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "ProcessSlot::drop blocked on the pty child's wait()"
        );
        // The detached reaper must reap the child (no zombie leak).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if unsafe { libc::kill(pid as i32, 0) } != 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "pty child {pid} was never reaped"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn pty_descriptors_carry_fd_cloexec() {
        let (master, slave) = open_pty(80, 24, 0, 0).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0,
            "pty master must be close-on-exec"
        );
        assert_ne!(
            unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0,
            "pty slave must be close-on-exec"
        );
    }

    #[test]
    fn ssh_output_modes_use_their_rfc_opcodes() {
        let (_master, slave) = open_pty(80, 24, 0, 0).unwrap();
        let modes = [
            (72, libc::ONLCR),
            (73, libc::OCRNL),
            (74, libc::ONOCR),
            (75, libc::ONLRET),
        ];
        let mask = modes.iter().fold(0, |mask, &(_, flag)| mask | flag);

        apply_pty_modes(&slave, &modes.map(|(opcode, _)| (opcode, 0))).unwrap();
        for &(opcode, flag) in &modes {
            apply_pty_modes(&slave, &[(opcode, 1)]).unwrap();
            let mut attrs = std::mem::MaybeUninit::<libc::termios>::uninit();
            assert_eq!(
                unsafe { libc::tcgetattr(slave.as_raw_fd(), attrs.as_mut_ptr()) },
                0
            );
            let attrs = unsafe { attrs.assume_init() };
            assert_eq!(
                attrs.c_oflag & mask,
                flag,
                "SSH terminal mode opcode {opcode} set the wrong output flag"
            );
            apply_pty_modes(&slave, &[(opcode, 0)]).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spawned_pty_child_cannot_see_the_master_descriptor() {
        let (mut master, slave) = open_pty(80, 24, 0, 0).unwrap();
        let capability = synch_core::ProcessCapability {
            id: 10,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec![
                "sh".into(),
                "-c".into(),
                "i=0; while [ $i -le 128 ]; do [ -e /proc/self/fd/$i ] && echo $i; i=$((i+1)); done"
                    .into(),
            ],
            allowed_signals: 0,
        };
        let mut child = spawn_pty(&capability, slave, "xterm").unwrap();
        // The child's stdio is the pty slave; read its output from the master
        // until the slave side closes (read returns EIO on Linux).
        let mut output = Vec::new();
        let mut buffer = [0_u8; 256];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                Err(_) => break,
            }
        }
        let _ = child.wait();
        let listing = String::from_utf8_lossy(&output);
        let mut fds: Vec<i32> = listing
            .split_whitespace()
            .map(|fd| fd.parse().expect("fd number"))
            .collect();
        fds.sort_unstable();
        assert_eq!(
            fds,
            vec![0, 1, 2],
            "child inherited descriptors beyond its pty stdio: {listing:?}"
        );
    }

    #[tokio::test]
    async fn declared_argv0_reaches_the_child() {
        let capability = synch_core::ProcessCapability {
            id: 11,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "echo $0".into()],
            allowed_signals: 0,
        };
        let (mut child, mut stdout, stdin, mut stderr) = spawn_pipe(&capability).unwrap();
        drop(stdin);
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.unwrap();
        let mut error = Vec::new();
        stderr.read_to_end(&mut error).await.unwrap();
        assert!(child.wait().await.unwrap().success());
        assert_eq!(output, b"sh\n", "declared argv[0] must reach the child");
        assert!(error.is_empty());

        // A declared argv[0] different from the executable path is delivered
        // verbatim.
        let capability = synch_core::ProcessCapability {
            id: 12,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec!["guest-name".into(), "-c".into(), "echo $0".into()],
            allowed_signals: 0,
        };
        let (mut child, mut stdout, stdin, mut stderr) = spawn_pipe(&capability).unwrap();
        drop(stdin);
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.unwrap();
        let mut error = Vec::new();
        stderr.read_to_end(&mut error).await.unwrap();
        assert!(child.wait().await.unwrap().success());
        assert_eq!(output, b"guest-name\n");
        assert!(error.is_empty());
    }

    /// The PTY path end to end with no SSH in the way: allocate, spawn an
    /// interactive shell on it, type at the prompt, read the answer, log out.
    /// Isolates the runtime's PTY layer from the SSH adapter when a shell
    /// example fails on only one platform.
    #[test]
    fn a_pty_shell_answers_what_is_typed_at_it() {
        let capability = synch_core::ProcessCapability {
            id: 11,
            flags: 0x01,
            executable: "/bin/bash".into(),
            argv: vec!["bash".into()],
            allowed_signals: 0x07,
        };
        let (master, slave) = open_pty(80, 24, 0, 0).unwrap();
        apply_pty_modes(&slave, &[]).unwrap();
        let mut reader = master.try_clone().unwrap();
        let writer = pty_writer(&master).unwrap();
        let child = spawn_pty(&capability, slave, "").unwrap();
        let slot = ProcessSlot {
            child: RefCell::new(Some(Child::Pty(child))),
            status: RefCell::new(ProcessStatus::default()),
            allowed_signals: capability.allowed_signals,
            main: -1,
            stderr: None,
        };

        // Read until the shell settles at its prompt, then type, then read
        // until the answer appears, then log out — the interop tests' shape,
        // minus SSH. A reader thread keeps this test from blocking forever.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buffer[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let mut seen = Vec::new();
        let settle = std::time::Duration::from_millis(500);
        while let Ok(chunk) = rx.recv_timeout(settle) {
            seen.extend_from_slice(&chunk);
        }
        assert!(
            !seen.is_empty(),
            "the shell printed nothing before its prompt"
        );
        assert!(
            pty_write_all(&writer, b"echo pty-probe-$((6*7))\nexit 0\n"),
            "typing at the PTY failed"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !String::from_utf8_lossy(&seen).contains("pty-probe-42") {
            match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(chunk) => seen.extend_from_slice(&chunk),
                Err(_) => {
                    let status = slot.refresh();
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the shell never answered.\nprocess: {status:?}\nseen: {:?}",
                        String::from_utf8_lossy(&seen)
                    );
                }
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let status = slot.refresh().unwrap();
            if status.exited {
                assert_eq!(status.exit_code, 0, "the shell's own exit status");
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the shell never exited after `exit`"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}
