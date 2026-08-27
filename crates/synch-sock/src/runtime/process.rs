//! Exact pipe-backed processes and Unix PTYs for declared capabilities.

use std::{
    cell::{Cell, RefCell},
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    pin::Pin,
    process::Stdio,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::abi::errno;

pub(crate) const DEFAULT_MAX_PROCESSES: u64 = 8;
pub(crate) const DEFAULT_MAX_RUNTIME_MS: u64 = 24 * 60 * 60 * 1_000;
pub(crate) const DEFAULT_MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

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

    pub(crate) fn kill(&self) {
        let Some(pid) = self.pid() else { return };
        // A fresh process group is created at spawn, so negative pid reaches
        // descendants as well as the direct child.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

impl Drop for ProcessSlot {
    fn drop(&mut self) {
        let Some(mut child) = self.child.get_mut().take() else {
            return;
        };
        match &mut child {
            Child::Pipe(child) => {
                let _ = child.start_kill();
            }
            Child::Pty(child) => {
                if let Ok(pid) = i32::try_from(child.id()) {
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                }
                // std::process::Child does not have Tokio's background reaper.
                let _ = child.wait();
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
    // SAFETY: openpty returned two newly owned descriptors.
    Ok(unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) })
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
    configure_unix_command(command.as_std_mut(), capability, false);
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
        .env("TERM", term)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(slave));
    configure_unix_command(&mut command, capability, true);
    command.spawn().map_err(|_| errno::ENOENT)
}

fn configure_unix_command(
    command: &mut std::process::Command,
    capability: &synch_core::ProcessCapability,
    controlling_tty: bool,
) {
    use std::os::unix::process::CommandExt as _;
    #[cfg(not(target_os = "macos"))]
    let memory = if capability.max_memory_bytes == 0 {
        DEFAULT_MAX_MEMORY_BYTES
    } else {
        capability.max_memory_bytes.min(DEFAULT_MAX_MEMORY_BYTES)
    };
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if controlling_tty && libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(not(target_os = "macos"))]
            let limit = libc::rlimit {
                rlim_cur: memory as libc::rlim_t,
                rlim_max: memory as libc::rlim_t,
            };
            // Darwin's RLIMIT_RSS is an alias for RLIMIT_AS, and a useful
            // address-space ceiling prevents dyld from loading even tiny
            // programs. The parent monitors aggregate resident memory there.
            #[cfg(not(target_os = "macos"))]
            if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Returns the aggregate resident bytes in a Darwin process group.
///
/// A full PID buffer is reported as `u64::MAX`, so process fan-out fails
/// closed instead of hiding memory beyond the fixed accounting bound.
#[cfg(target_os = "macos")]
pub(crate) fn process_group_resident_bytes(pgid: u32) -> Result<Option<u64>, ()> {
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
        let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
        let expected = std::mem::size_of::<libc::proc_taskinfo>();
        let size = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTASKINFO,
                0,
                info.as_mut_ptr().cast(),
                expected as libc::c_int,
            )
        };
        if usize::try_from(size).ok() != Some(expected) {
            continue;
        }
        measured = true;
        total = total.saturating_add(unsafe { info.assume_init() }.pti_resident_size);
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

pub(crate) fn pty_adapters(master: &File) -> Result<(ChannelReader, ChannelWriter), i64> {
    let mut reader = master.try_clone().map_err(|_| errno::ECONNRESET)?;
    let mut writer = master.try_clone().map_err(|_| errno::ECONNRESET)?;
    let (read_tx, read_rx) = tokio::sync::mpsc::channel(8);
    let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
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
    std::thread::Builder::new()
        .name("synch-pty-write".into())
        .spawn(move || {
            while let Some(bytes) = write_rx.blocking_recv() {
                if writer.write_all(&bytes).is_err() {
                    break;
                }
            }
        })
        .map_err(|_| errno::ELIMIT)?;
    Ok((ChannelReader::new(read_rx), ChannelWriter(write_tx)))
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

pub(crate) struct ChannelWriter(pub(crate) tokio::sync::mpsc::UnboundedSender<Vec<u8>>);

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0
            .send(data.to_vec())
            .map(|()| Poll::Ready(Ok(data.len())))
            .unwrap_or_else(|_| {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "PTY closed",
                )))
            })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
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

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_can_measure_its_process_group() {
        let pgid = u32::try_from(unsafe { libc::getpgrp() }).unwrap();
        assert!(process_group_resident_bytes(pgid).unwrap().unwrap() > 0);
    }
}
