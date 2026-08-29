//! Exact pipe-backed processes and Unix PTYs for declared capabilities.

use std::{
    cell::{Cell, RefCell},
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    pin::Pin,
    process::Stdio,
    sync::Mutex,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::abi::errno;

pub(crate) const DEFAULT_MAX_PROCESSES: u64 = 8;
pub(crate) const DEFAULT_MAX_RUNTIME_MS: u64 = 24 * 60 * 60 * 1_000;
pub(crate) const DEFAULT_MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// Serializes PTY descriptor creation with every declared-process fork.
///
/// `openpty` has no close-on-exec flag, so setting `FD_CLOEXEC` afterward is
/// otherwise racy in this multi-worker daemon: another worker can fork between
/// the allocation and the `fcntl`. All runtime process spawns take the same
/// lock across `Command::spawn`, closing that inheritance window.
static PROCESS_SPAWN_FD_LOCK: Mutex<()> = Mutex::new(());

/// The UID-wide Linux task ceiling is based on one stable daemon baseline.
/// Recomputing it for every child would grant another block of headroom after
/// escaped or concurrent descendants had already consumed the previous block.
#[cfg(target_os = "linux")]
static LINUX_UID_TASK_CEILING: Mutex<Option<u64>> = Mutex::new(None);

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
    pub(crate) capability: u32,
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
            Some(Child::Pipe(child)) => {
                if let Some(pid) = child.id() {
                    kill_group_if_exited(pid);
                }
                child.try_wait()
            }
            Some(Child::Pty(child)) => {
                kill_group_if_exited(child.id());
                child.try_wait()
            }
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

    pub(crate) fn kill(&self) {
        let Some(pid) = self.pid() else { return };
        // A fresh process group is created at spawn, so negative pid reaches
        // descendants as well as the direct child.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }

    /// Kills the process group only while this slot still owns the child whose
    /// pid was observed when a watchdog was armed.
    ///
    /// Keeping the child borrowed across `kill` is intentional. A completed
    /// child that has not yet been reaped still reserves its pid; a child that
    /// `refresh` already reaped leaves the slot and cannot be mistaken for a
    /// later process which reused the same numeric pid.
    pub(crate) fn kill_if_pid(&self, expected: u32) {
        let child = self.child.borrow();
        let pid = match child.as_ref() {
            Some(Child::Pipe(child)) => child.id(),
            Some(Child::Pty(child)) => Some(child.id()),
            None => None,
        };
        if pid != Some(expected) {
            return;
        }
        if let Ok(pid) = i32::try_from(expected) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
}

/// Kills the process group of an exited-but-unreaped child, so same-group
/// descendants die with their leader instead of surviving as orphans.
///
/// `waitid` with `WNOWAIT` detects the exit without reaping: the child's pid
/// stays reserved until the subsequent `try_wait` in `refresh`, so the group
/// kill can never be aimed at an unrelated pid that reused the number. A child
/// that is still running (si_pid == 0) or that some other path already reaped
/// (waitid fails) is left alone.
fn kill_group_if_exited(pid: u32) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WNOHANG | libc::WEXITED | libc::WNOWAIT,
        )
    };
    if rc == 0 && waitid_si_pid(&info) == pid as i32 {
        // A fresh process group was created at spawn, so a negative pid
        // reaches same-group descendants as well as the leader.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

/// The child pid a waitid `siginfo_t` reports for an exited child.
///
/// libc exposes `si_pid` as an unsafe accessor on Linux (the field lives
/// inside a union), and as a plain field elsewhere.
#[cfg(target_os = "linux")]
fn waitid_si_pid(info: &libc::siginfo_t) -> libc::pid_t {
    unsafe { info.si_pid() }
}

/// See [`waitid_si_pid`].
#[cfg(not(target_os = "linux"))]
fn waitid_si_pid(info: &libc::siginfo_t) -> libc::pid_t {
    info.si_pid
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
    // sandboxed process forge "user input" to the guest. std's spawn clears
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
            72 => set_flag(&mut attrs.c_oflag, libc::OCRNL),
            73 => set_flag(&mut attrs.c_oflag, libc::ONOCR),
            74 => set_flag(&mut attrs.c_oflag, libc::ONLRET),
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
    command
        .args(capability.argv.iter().skip(1))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
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
    configure_unix_command(command.as_std_mut(), capability, false)?;
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
    command
        .args(capability.argv.iter().skip(1))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
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
    configure_unix_command(&mut command, capability, true)?;
    let _spawn_guard = PROCESS_SPAWN_FD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    command.spawn().map_err(|_| errno::ENOENT)
}

fn configure_unix_command(
    command: &mut std::process::Command,
    capability: &synch_core::ProcessCapability,
    controlling_tty: bool,
) -> Result<(), i64> {
    use std::os::unix::process::CommandExt as _;
    #[cfg(not(target_os = "macos"))]
    let memory = if capability.max_memory_bytes == 0 {
        DEFAULT_MAX_MEMORY_BYTES
    } else {
        capability.max_memory_bytes.min(DEFAULT_MAX_MEMORY_BYTES)
    };
    // RLIMIT_NPROC is charged to the real UID, not to this process group. Use
    // one stable baseline for the daemon lifetime: if every spawn counted the
    // descendants already created by earlier children, each child would gain a
    // fresh block of headroom and the supposed ceiling would grow without
    // bound.
    #[cfg(target_os = "linux")]
    let nproc_limit = linux_uid_task_ceiling().map_err(|_| errno::ELIMIT)?;
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
            #[cfg(not(target_os = "macos"))]
            let limit = libc::rlimit {
                rlim_cur: memory as libc::rlim_t,
                rlim_max: memory as libc::rlim_t,
            };
            // Darwin's RLIMIT_RSS is an alias for RLIMIT_AS, and a useful
            // address-space ceiling prevents dyld from loading even tiny
            // programs. The parent monitors aggregate physical footprint there.
            #[cfg(not(target_os = "macos"))]
            if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Bound fan-out above the daemon's original UID task baseline.
            #[cfg(target_os = "linux")]
            {
                let nproc = libc::rlimit {
                    rlim_cur: nproc_limit as libc::rlim_t,
                    rlim_max: nproc_limit as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_NPROC, &nproc) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // The direct child has already entered its fresh session.
                // From here on, deny the two syscalls descendants could use to
                // leave that process group. The filter is inherited across
                // fork and exec, so group cleanup reaches the whole tree.
                install_process_group_seccomp()?;
            }
            Ok(())
        });
    }
    Ok(())
}

/// The stable Linux task ceiling inherited by every declared child.
#[cfg(target_os = "linux")]
fn linux_uid_task_ceiling() -> std::io::Result<u64> {
    let mut ceiling = LINUX_UID_TASK_CEILING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Linux does not enforce RLIMIT_NPROC for UID 0 or for a process carrying
    // either of the capabilities that bypass the check. Refuse process-backed
    // capabilities in that configuration rather than present an unenforced
    // safety bound to a privileged daemon.
    if unsafe { libc::getuid() } == 0 || linux_nproc_limit_is_bypassed()? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "declared processes require an unprivileged daemon UID",
        ));
    }
    if let Some(ceiling) = *ceiling {
        return Ok(ceiling);
    }
    let current = linux_uid_task_count()?;
    let mut existing: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut existing) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let desired = current
        .saturating_add(crate::limits::MAX_PROCESSES_PER_GROUP)
        .max(crate::limits::MAX_PROCESSES_PER_GROUP)
        .min(existing.rlim_max as u64);
    *ceiling = Some(desired);
    Ok(desired)
}

/// Whether this process has a capability that exempts it from RLIMIT_NPROC.
#[cfg(target_os = "linux")]
fn linux_nproc_limit_is_bypassed() -> std::io::Result<bool> {
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_SYS_RESOURCE: u32 = 24;
    let status = std::fs::read_to_string("/proc/self/status")?;
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|text| u64::from_str_radix(text.trim(), 16).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "/proc/self/status has no valid CapEff field",
            )
        })?;
    Ok(effective & ((1 << CAP_SYS_ADMIN) | (1 << CAP_SYS_RESOURCE)) != 0)
}

/// Installs an inherited seccomp filter that keeps descendants in the process
/// group created by `setsid` above.
#[cfg(target_os = "linux")]
fn install_process_group_seccomp() -> std::io::Result<()> {
    let audit_arch = native_audit_arch().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "declared-process containment is unavailable on this Linux architecture",
        )
    })?;
    let stmt = |code: u16, k: u32| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    let load_abs = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let jump_eq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let mut filter = [
        stmt(load_abs, 4), // seccomp_data.arch
        jump(jump_eq, audit_arch, 1, 0),
        stmt(ret, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(load_abs, 0), // seccomp_data.nr
        jump(jump_eq, libc::SYS_setsid as u32, 0, 1),
        stmt(ret, denied),
        jump(jump_eq, libc::SYS_setpgid as u32, 0, 1),
        stmt(ret, denied),
        stmt(ret, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn native_audit_arch() -> Option<u32> {
    Some(0xc000_003e)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn native_audit_arch() -> Option<u32> {
    Some(0xc000_00b7)
}

#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
fn native_audit_arch() -> Option<u32> {
    Some(0xc000_00f3)
}

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))
))]
fn native_audit_arch() -> Option<u32> {
    None
}

/// Counts Linux tasks currently charged to this process's real UID.
///
/// RLIMIT_NPROC counts threads on Linux. `/proc/<pid>/status` gives both the
/// real UID and the thread count without walking every task directory. Races
/// with process exit only make the snapshot slightly conservative or lenient;
/// the kernel still enforces the resulting absolute ceiling.
#[cfg(target_os = "linux")]
fn linux_uid_task_count() -> std::io::Result<u64> {
    let uid = unsafe { libc::getuid() };
    let mut total = 0_u64;
    for entry in std::fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let real_uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|text| text.parse::<libc::uid_t>().ok());
        if real_uid != Some(uid) {
            continue;
        }
        let threads = status
            .lines()
            .find_map(|line| line.strip_prefix("Threads:"))
            .and_then(|text| text.trim().parse::<u64>().ok())
            .unwrap_or(1);
        total = total.saturating_add(threads);
    }
    Ok(total)
}

/// Returns the aggregate physical footprint in a Darwin process group.
///
/// A full PID buffer is reported as `u64::MAX`, so process fan-out fails
/// closed instead of hiding memory beyond the fixed accounting bound.
#[cfg(target_os = "macos")]
pub(crate) fn process_group_footprint_bytes(pgid: u32) -> Result<Option<u64>, ()> {
    const MAX_GROUP_PROCESSES: usize = 4_096;

    let pgid = libc::pid_t::try_from(pgid).map_err(|_| ())?;
    let mut pids = [0_i32; MAX_GROUP_PROCESSES];
    let buffer_bytes = std::mem::size_of_val(&pids);
    let returned = unsafe {
        libc::proc_listpgrppids(pgid, pids.as_mut_ptr().cast(), buffer_bytes as libc::c_int)
    };
    if returned < 0 {
        return Err(());
    }
    if returned == 0 {
        return Ok(None);
    }
    let returned = usize::try_from(returned).map_err(|_| ())?;
    if returned >= buffer_bytes {
        return Ok(Some(u64::MAX));
    }

    let mut total = 0_u64;
    let mut measured = false;
    for &pid in &pids[..returned / std::mem::size_of::<libc::pid_t>()] {
        if pid <= 0 {
            continue;
        }
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v0>::uninit();
        let result =
            unsafe { libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V0, info.as_mut_ptr().cast()) };
        if result != 0 {
            continue;
        }
        measured = true;
        total = total.saturating_add(unsafe { info.assume_init() }.ri_phys_footprint);
    }
    if measured {
        Ok(Some(total))
    } else {
        Err(())
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
            match self.receiver.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => {
                    self.current = bytes;
                    self.offset = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
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
    use tokio::io::AsyncReadExt as _;

    #[tokio::test]
    async fn a_pipe_process_runs_only_its_exact_declared_argv() {
        let capability = synch_core::ProcessCapability {
            id: 1,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "printf exact-process".into()],
            allowed_signals: 0,
            max_processes: 1,
            max_runtime_ms: 5_000,
            max_memory_bytes: 128 * 1024 * 1024,
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

    #[tokio::test]
    async fn a_watchdog_cannot_signal_after_its_child_was_reaped() {
        let capability = synch_core::ProcessCapability {
            id: 7,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "exit 0".into()],
            allowed_signals: 0,
            max_processes: 1,
            max_runtime_ms: 5_000,
            max_memory_bytes: 128 * 1024 * 1024,
        };
        let (child, stdout, stdin, stderr) = spawn_pipe(&capability).unwrap();
        drop((stdout, stdin, stderr));
        let pid = child.id().unwrap();
        let slot = ProcessSlot {
            child: RefCell::new(Some(Child::Pipe(child))),
            status: RefCell::new(ProcessStatus::default()),
            capability: capability.id,
            allowed_signals: 0,
            main: -1,
            stderr: None,
        };
        loop {
            if slot.refresh().unwrap().exited {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(slot.pid(), None);
        slot.kill_if_pid(pid);
        assert_eq!(slot.pid(), None);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn nproc_headroom_allows_children_when_the_uid_is_already_busy() {
        let capability = synch_core::ProcessCapability {
            id: 13,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "/bin/true && echo forked".into()],
            allowed_signals: 0,
            max_processes: 1,
            max_runtime_ms: 5_000,
            max_memory_bytes: 128 * 1024 * 1024,
        };
        let (mut child, mut stdout, stdin, mut stderr) = spawn_pipe(&capability).unwrap();
        drop(stdin);
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.unwrap();
        let mut error = Vec::new();
        stderr.read_to_end(&mut error).await.unwrap();
        assert!(child.wait().await.unwrap().success(), "stderr: {error:?}");
        assert_eq!(output, b"forked\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nproc_ceiling_does_not_grow_with_later_uid_tasks() {
        let first = linux_uid_task_ceiling().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    barrier.wait();
                })
            })
            .collect();
        barrier.wait();
        let while_busier = linux_uid_task_ceiling().unwrap();
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(
            while_busier, first,
            "later UID tasks must not grant fresh descendant headroom"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn descendants_cannot_create_a_new_session() {
        let Some(setsid) = ["/usr/bin/setsid", "/bin/setsid"]
            .into_iter()
            .find(|path| std::path::Path::new(path).is_file())
        else {
            eprintln!("skipping: util-linux setsid is unavailable");
            return;
        };
        // --fork makes the process that invokes setsid a descendant which is
        // not already the process-group leader; without the inherited filter
        // this succeeds. --wait propagates its failure to the direct child.
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
            max_processes: 1,
            max_runtime_ms: 5_000,
            max_memory_bytes: 128 * 1024 * 1024,
        };
        let (mut child, mut stdout, stdin, mut stderr) = spawn_pipe(&capability).unwrap();
        drop(stdin);
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.unwrap();
        let mut error = Vec::new();
        stderr.read_to_end(&mut error).await.unwrap();
        let status = child.wait().await.unwrap();
        assert!(
            !status.success(),
            "a descendant escaped the owned process group: stdout={output:?}, stderr={error:?}"
        );
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn refresh_kills_the_process_group_before_reaping() {
        let capability = synch_core::ProcessCapability {
            id: 8,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec![
                "sh".into(),
                "-c".into(),
                "sleep 60 >/dev/null 2>&1 & echo $!; sleep 1".into(),
            ],
            allowed_signals: 0,
            max_processes: 1,
            max_runtime_ms: 10_000,
            max_memory_bytes: 128 * 1024 * 1024,
        };
        let (child, mut stdout, stdin, stderr) = spawn_pipe(&capability).unwrap();
        drop((stdin, stderr));
        // The child prints the pid of its backgrounded grandchild before it
        // exits (the grandchild's stdio is redirected so the pipe EOFs with
        // the direct child).
        let mut line = String::new();
        stdout.read_to_string(&mut line).await.unwrap();
        let Some(grandchild) = line.trim().parse::<i32>().ok() else {
            // RLIMIT_NPROC is per-real-UID. A concurrent burst under the same
            // UID can consume the snapshot-based headroom before this child
            // forks, leaving no descendant to assert against; skip that race.
            eprintln!(
                "skipping: uid consumed the RLIMIT_NPROC headroom before the child forked a \
                 grandchild (stdout {line:?})"
            );
            return;
        };
        let slot = ProcessSlot {
            child: RefCell::new(Some(Child::Pipe(child))),
            status: RefCell::new(ProcessStatus::default()),
            capability: capability.id,
            allowed_signals: 0,
            main: -1,
            stderr: None,
        };
        // The direct child exits after ~1s; refresh() must detect the exit
        // without reaping first (waitid WNOWAIT), so the group SIGKILL still
        // reaches the same-group grandchild before the leader is reaped.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if slot.refresh().unwrap().exited {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "direct child never exited"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(slot.pid(), None, "a reaped child must leave the slot");
        // The grandchild must be dead. Without the fix the group is never
        // killed once the leader is reaped (kill() sees no pid) and the
        // grandchild survives past the invocation.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if unsafe { libc::kill(grandchild, 0) } != 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "grandchild {grandchild} survived the pre-reap group kill"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn pty_slot_drop_returns_promptly_with_a_stuck_child() {
        let (master, slave) = open_pty(80, 24, 0, 0).unwrap();
        // A fork-free busy loop keeps this cleanup test independent of
        // concurrent consumption of the per-uid RLIMIT_NPROC headroom.
        let capability = synch_core::ProcessCapability {
            id: 9,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "while :; do :; done".into()],
            allowed_signals: 0,
            max_processes: 1,
            max_runtime_ms: 60_000,
            max_memory_bytes: 128 * 1024 * 1024,
        };
        let child = spawn_pty(&capability, slave, "xterm").unwrap();
        let pid = child.id();
        let slot = ProcessSlot {
            child: RefCell::new(Some(Child::Pty(child))),
            status: RefCell::new(ProcessStatus::default()),
            capability: capability.id,
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
            max_processes: 1,
            max_runtime_ms: 10_000,
            max_memory_bytes: 128 * 1024 * 1024,
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
            max_processes: 1,
            max_runtime_ms: 5_000,
            max_memory_bytes: 128 * 1024 * 1024,
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
            max_processes: 1,
            max_runtime_ms: 5_000,
            max_memory_bytes: 128 * 1024 * 1024,
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

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_can_measure_its_process_group_footprint() {
        let pgid = u32::try_from(unsafe { libc::getpgrp() }).unwrap();
        assert!(process_group_footprint_bytes(pgid).unwrap().unwrap() > 0);
    }

    /// The exact query the memory watchdog makes: a freshly spawned child's
    /// own process group, not this test's. Documentation of what this host
    /// can account rather than an assertion — where per-child rusage is
    /// denied, the watchdog stands down instead of enforcing, and this test
    /// records which world CI runs in.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn darwin_reports_what_a_spawned_childs_group_accounting_says() {
        let capability = synch_core::ProcessCapability {
            id: 9,
            flags: 0x02,
            executable: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "sleep 5".into()],
            allowed_signals: 0,
            max_processes: 1,
            max_runtime_ms: 10_000,
            max_memory_bytes: 128 * 1024 * 1024,
        };
        let (mut child, stdout, stdin, stderr) = spawn_pipe(&capability).unwrap();
        drop((stdout, stdin, stderr));
        let pgid = child.id().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let measured = process_group_footprint_bytes(pgid);
        unsafe {
            libc::kill(-(pgid as i32), libc::SIGKILL);
        }
        let _ = child.start_kill();
        eprintln!("child group accounting on this host: {measured:?}");
        assert!(
            !matches!(measured, Ok(Some(u64::MAX))),
            "a two-process group overflowed the PID buffer: {measured:?}"
        );
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
            max_processes: 1,
            max_runtime_ms: 30_000,
            max_memory_bytes: 512 * 1024 * 1024,
        };
        let (master, slave) = open_pty(80, 24, 0, 0).unwrap();
        apply_pty_modes(&slave, &[]).unwrap();
        let mut reader = master.try_clone().unwrap();
        let writer = pty_writer(&master).unwrap();
        let child = spawn_pty(&capability, slave, "").unwrap();
        let slot = ProcessSlot {
            child: RefCell::new(Some(Child::Pty(child))),
            status: RefCell::new(ProcessStatus::default()),
            capability: capability.id,
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
