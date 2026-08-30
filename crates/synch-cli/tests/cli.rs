//! End-to-end tests that drive the real `synch` binary: `synch init` creates
//! the datadir, `synch daemon run` owns the node, every other command is a
//! control-socket request to that daemon (§9.1). The in-process
//! control-socket coverage lives in `tests/control.rs`.

use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn synch_bin() -> PathBuf {
    // Cargo puts integration-test binaries in target/<profile>/deps.
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(if cfg!(windows) { "synch.exe" } else { "synch" })
}

struct Cli {
    data_dir: PathBuf,
}

impl Cli {
    fn new(data_dir: &Path) -> Cli {
        Cli {
            data_dir: data_dir.to_path_buf(),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(synch_bin());
        command
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--offline")
            .args(args);
        command
    }

    fn output(&self, args: &[&str]) -> std::process::Output {
        self.command(args).output().expect("synch binary runs")
    }

    fn try_run(&self, args: &[&str]) -> (bool, String, String) {
        let output = self.output(args);
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn run(&self, args: &[&str]) -> String {
        let (ok, stdout, stderr) = self.try_run(args);
        assert!(ok, "synch {args:?} failed:\n{stdout}\n{stderr}");
        stdout
    }

    fn run_bytes(&self, args: &[&str]) -> Vec<u8> {
        let output = self.output(args);
        assert!(
            output.status.success(),
            "synch {args:?} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    /// Starts `synch daemon run` and waits until its control socket answers.
    fn daemon(&self) -> Daemon {
        let mut child = Command::new(synch_bin())
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--offline")
            .arg("--bind")
            .arg("127.0.0.1:0")
            .arg("daemon")
            .arg("run")
            .stdout(Stdio::piped())
            .spawn()
            .expect("daemon starts");

        let stdout = child.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let mut banner = String::new();
        reader
            .read_line(&mut banner)
            .expect("the daemon prints a banner");
        // Keep draining so the child never blocks on a full pipe.
        std::thread::spawn(move || {
            let mut sink = String::new();
            while reader.read_line(&mut sink).unwrap_or(0) > 0 {
                sink.clear();
            }
        });

        let address = banner
            .rsplit(" via ")
            .next()
            .unwrap_or_default()
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();

        // The banner precedes the daemon being fully open; wait until it is.
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.try_run(&["daemon", "status"]).0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Daemon { child, address }
    }
}

/// A running `synch daemon run` child.
struct Daemon {
    child: Child,
    address: String,
}

impl Daemon {
    /// Asks the daemon to stop and waits for the process to exit.
    fn stop(mut self, cli: &Cli) {
        cli.run(&["daemon", "stop"]);
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => panic!("waiting for the daemon: {e}"),
            }
        }
        panic!("the daemon did not exit after `daemon stop`");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn init_is_the_only_command_that_runs_without_a_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());

    // With no datadir at all, even `daemon run` has nothing to open.
    let (ok, _, stderr) = cli.try_run(&["daemon", "run"]);
    assert!(!ok);
    assert!(stderr.contains("synch init"), "{stderr}");

    let (ok, _, stderr) = cli.try_run(&["daemon", "start"]);
    assert!(!ok);
    assert!(stderr.contains("synch init"), "{stderr}");

    // No domain: the device key is the identity and nothing has to be
    // published for the node to know what it is (§3.1).
    let out = cli.run(&["init"]);
    assert!(out.contains("origin:"), "{out}");
    assert!(out.contains("synch daemon start"), "{out}");

    // Init is not idempotent: a second one must not silently replace the key.
    let (ok, _, _) = cli.try_run(&["init"]);
    assert!(!ok, "init must refuse to overwrite an identity");

    // Everything else needs the daemon, and says so.
    for args in [vec!["id"], vec!["daemon", "status"]] {
        let (ok, _, stderr) = cli.try_run(&args);
        assert!(!ok, "{args:?} must fail without a daemon");
        assert!(stderr.contains("synch daemon run"), "{args:?}: {stderr}");
        assert!(
            stderr.contains("control.sock") || stderr.contains("\\pipe\\synchronicity-"),
            "{args:?}: {stderr} must name the socket"
        );
    }
}

#[test]
fn daemon_start_returns_once_the_background_socket_is_ready() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    cli.run(&["init"]);

    let started = cli.run(&["daemon", "start"]);
    assert!(started.contains("daemon started (pid "), "{started}");
    assert!(started.contains("control socket:"), "{started}");
    assert!(started.contains("daemon.log"), "{started}");

    // Returning from start means the socket is usable immediately, without a
    // caller-side retry loop.
    assert!(cli.run(&["daemon", "status"]).contains("origin "));
    let (ok, _, stderr) = cli.try_run(&["daemon", "start"]);
    assert!(!ok);
    assert!(stderr.contains("already running"), "{stderr}");

    cli.run(&["daemon", "stop"]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if !cli.try_run(&["daemon", "status"]).0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the background daemon did not stop");
}

#[test]
fn simultaneous_daemon_starts_only_report_the_winning_child() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    cli.run(&["init"]);

    let mut first = cli.command(&["daemon", "start"]);
    first.stdout(Stdio::piped()).stderr(Stdio::piped());
    let first = first.spawn().expect("first launcher starts");
    let mut second = cli.command(&["daemon", "start"]);
    second.stdout(Stdio::piped()).stderr(Stdio::piped());
    let second = second.spawn().expect("second launcher starts");

    let first = first.wait_with_output().expect("first launcher exits");
    let second = second.wait_with_output().expect("second launcher exits");
    let successes = usize::from(first.status.success()) + usize::from(second.status.success());
    assert_eq!(
        successes, 1,
        "exactly one spawned daemon may own the datadir"
    );
    assert!(cli.run(&["daemon", "status"]).contains("origin "));

    cli.run(&["daemon", "stop"]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if !cli.try_run(&["daemon", "status"]).0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the winning background daemon did not stop");
}

#[test]
fn the_command_surface_works_over_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    cli.run(&["init"]);

    std::fs::create_dir_all(space.path().join("talks")).unwrap();
    std::fs::write(space.path().join("notes.txt"), b"hello").unwrap();
    std::fs::write(space.path().join("talks/a.txt"), b"talk").unwrap();

    let daemon = cli.daemon();

    // A key-identified origin renders as the key.
    let id = cli.run(&["id"]);
    let origin = format!("key:{}", key_of(&cli));
    assert!(id.contains(&origin), "{id}");
    assert!(id.contains("active"), "{id}");

    cli.run(&["source", "add", "media", &space.path().to_string_lossy()]);
    assert!(cli.run(&["source", "ls"]).contains("media"));
    let scan = cli.run(&["source", "scan", "media"]);
    assert!(scan.contains("hashed 2"), "{scan}");
    assert!(scan.contains("published seq"), "{scan}");

    let ls = cli.run(&["ls", "media"]);
    assert!(ls.contains("notes.txt"), "{ls}");
    assert!(ls.contains("talks/a.txt"), "{ls}");
    assert!(!cli.run(&["ls", "media/talks"]).contains("notes.txt"));

    // One cat form, and `get -o` writing the file.
    assert_eq!(cli.run_bytes(&["cat", "media/notes.txt"]), b"hello");
    let out = tempfile::tempdir().unwrap();
    let target = out.path().join("notes.txt");
    cli.run(&["get", "media/notes.txt", "-o", &target.to_string_lossy()]);
    assert_eq!(std::fs::read(&target).unwrap(), b"hello");

    // A replica checkout materializes only content held by the replica.
    let checkout_dir = tempfile::tempdir().unwrap();
    cli.run(&[
        "replica",
        "add",
        "media",
        "--checkout",
        &checkout_dir.path().to_string_lossy(),
    ]);
    assert!(cli.run(&["replica", "ls", "media"]).contains("current"));
    cli.run(&["replica", "sync", "media"]);
    assert_eq!(
        std::fs::read(checkout_dir.path().join("notes.txt")).unwrap(),
        b"hello"
    );
    assert!(cli.run(&["replica", "rm", "media"]).contains("removed"));

    // A adoption of a space whose every path this node already holds has nothing
    // to do, and says so without writing anything.
    let adoption = cli.run(&["adopt", "tree", "media", "--dry-run"]);
    assert!(adoption.contains("would adopt 0"), "{adoption}");
    assert!(adoption.contains("current 2"), "{adoption}");

    // A pin may name a path; the reading policy's version supplies the root (§8).
    let root = blake3::hash(b"hello").to_hex().to_string();
    assert!(cli.run(&["pin", "add", "media/notes.txt"]).contains(&root));
    assert!(cli.run(&["pin", "ls"]).contains(&root));
    let unpinned = cli.run(&["pin", "rm", "media/notes.txt"]);
    assert!(unpinned.contains(&root), "{unpinned}");
    assert!(
        unpinned.contains("still held by source:media"),
        "{unpinned}"
    );
    let pins = cli.run(&["pin", "ls"]);
    assert!(pins.contains(&root), "{pins}");
    assert!(pins.contains("source:media"), "{pins}");
    assert!(!pins.contains("operator"), "{pins}");

    // A daemon-side failure is this process's exit status, not a transport error.
    let (ok, _, stderr) = cli.try_run(&["pin", "add", "nothex"]);
    assert!(!ok);
    assert!(stderr.contains("hex"), "{stderr}");

    let doctor = cli.run(&["doctor"]);
    assert!(doctor.contains(&format!("origin: {origin}")), "{doctor}");
    assert!(doctor.contains("equivocation: none detected"), "{doctor}");
    assert!(cli.run(&["daemon", "status"]).contains("head: seq"));

    // `synch recover` with no peer ever advertising: one round, nothing to resume (§3.4).
    let recover = cli.run(&["recover", "--wait", "0"]);
    assert!(recover.contains("nothing to recover"), "{recover}");
    let (ok, _, stderr) = cli.try_run(&["recover", "--wait", "whenever"]);
    assert!(!ok);
    assert!(stderr.contains("--wait"), "{stderr}");

    daemon.stop(&cli);

    // With the daemon gone, the socket is gone with it.
    let (ok, _, stderr) = cli.try_run(&["id"]);
    assert!(!ok);
    assert!(stderr.contains("synch daemon run"), "{stderr}");
}

#[test]
fn two_nodes_converge_and_transfer_content_over_the_cli() {
    let nas_dir = tempfile::tempdir().unwrap();
    let nas_space = tempfile::tempdir().unwrap();
    let laptop_dir = tempfile::tempdir().unwrap();
    let nas = Cli::new(nas_dir.path());
    let laptop = Cli::new(laptop_dir.path());

    nas.run(&["init"]);
    laptop.run(&["init"]);

    let payload: Vec<u8> = (0..120_000u32).map(|i| (i * 13) as u8).collect();
    std::fs::write(nas_space.path().join("small.txt"), b"a small file").unwrap();
    std::fs::write(nas_space.path().join("big.bin"), &payload).unwrap();

    let nas_daemon = nas.daemon();
    let laptop_daemon = laptop.daemon();

    // Addresses are exchanged explicitly: discovery is off, and static trust
    // binds the key and names nobody (§3.2).
    let nas_key = key_of(&nas);
    let laptop_key = key_of(&laptop);
    nas.run(&[
        "trust",
        "add",
        &laptop_key,
        "--addr",
        &laptop_daemon.address,
    ]);
    laptop.run(&["trust", "add", &nas_key, "--addr", &nas_daemon.address]);

    nas.run(&[
        "source",
        "add",
        "media",
        &nas_space.path().to_string_lossy(),
    ]);
    nas.run(&["source", "scan", "media"]);

    // The push is reactive; the periodic round repairs what the push missed.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut converged = false;
    while Instant::now() < deadline {
        // The space 404s until the first head lands, then lists.
        let (ok, stdout, _) = laptop.try_run(&["ls", "media"]);
        if ok && stdout.contains("big.bin") {
            converged = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(converged, "the laptop never learned the NAS's entries");

    // Metadata matches; content still lives only on the NAS.
    let ls = laptop.run(&["ls", "media"]);
    assert!(ls.contains("small.txt"), "{ls}");
    assert!(ls.contains("120000"), "{ls}");

    // A verified full read, a range read, and a `get`, streamed over the socket.
    let nas_origin = format!("key:{nas_key}");
    let got = laptop.run_bytes(&["cat", &format!("{nas_origin}:media/small.txt")]);
    assert_eq!(got, b"a small file");
    let got = laptop.run_bytes(&[
        "cat",
        &format!("{nas_origin}:media/big.bin"),
        "--range",
        "60000..60100",
    ]);
    assert_eq!(got, &payload[60_000..60_100]);
    let out_dir = tempfile::tempdir().unwrap();
    let target = out_dir.path().join("fetched.bin");
    laptop.run(&[
        "get",
        &format!("{nas_origin}:media/big.bin"),
        "-o",
        &target.to_string_lossy(),
    ]);
    assert_eq!(std::fs::read(&target).unwrap(), payload);

    laptop_daemon.stop(&laptop);
    nas_daemon.stop(&nas);
}

fn key_of(cli: &Cli) -> String {
    let out = cli.run(&["id"]);
    out.lines()
        .find(|l| l.starts_with("  "))
        .expect("a device key line")
        .split_whitespace()
        .next()
        .expect("a key")
        .to_string()
}

/// The command surface must parse inside the smallest main-thread stack any
/// platform we ship on gives a process.
///
/// clap's derived parser is one builder chain per subcommand, in a single frame
/// with nothing inlined in a debug build, and it grew past a megabyte when the
/// `socket` subcommand landed. Linux gives the main thread eight megabytes and
/// noticed nothing; Windows gives it one, and every `synch` invocation aborted
/// before the program had done anything — including `--version`.
///
/// So the condition is reproduced here rather than left to the Windows job to
/// find. In a subprocess, because a stack overflow aborts and would take the
/// rest of this test binary with it, and under `RLIMIT_STACK` rather than a
/// sized thread, because it is the *main* thread's stack that differs between
/// platforms and only the kernel sets that one.
///
/// Linux only. Darwin refuses to shrink `RLIMIT_STACK` at all — `setrlimit`
/// answers `EINVAL` — so there is no way to ask a macOS process to start with
/// a smaller main stack than it was given. One platform that can pose the
/// question is enough for the answer to be checked on every push.
#[test]
#[cfg(target_os = "linux")]
fn the_cli_parses_within_the_smallest_main_thread_stack_we_ship_on() {
    use std::os::unix::process::CommandExt;

    // What Windows gives a process by default.
    const WINDOWS_DEFAULT: u64 = 1024 * 1024;

    let mut command = Command::new(synch_bin());
    command
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: `setrlimit` is async-signal-safe, which is the bar for a
    // `pre_exec` closure in the forked child.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: WINDOWS_DEFAULT,
                rlim_max: WINDOWS_DEFAULT,
            };
            if libc::setrlimit(libc::RLIMIT_STACK, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let output = command.output().expect("synch binary runs");
    assert!(
        output.status.success(),
        "`synch --version` did not survive a {WINDOWS_DEFAULT}-byte main stack — \
         which is what Windows gives it:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The one end-to-end check of `synch mcp` driving the real binary: the
/// protocol goes out on stdout and nothing else does.
///
/// The bridge's own behaviour is covered in `tests/mcp.rs`, over the same
/// dispatcher against an in-process daemon. What only a spawned process can
/// prove is the stdio contract itself — that no `println!`, no banner, and no
/// log line shares the channel the protocol is framed on.
#[test]
fn mcp_writes_protocol_to_stdout_and_diagnostics_to_stderr() {
    use std::io::Write as _;

    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    cli.run(&["init"]);
    let daemon = cli.daemon();

    let mut child = cli
        .command(&["mcp"])
        // Verbose on purpose: the logging that would corrupt the stream if it
        // went anywhere near stdout is exactly what this turns on.
        .arg("--verbose")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("synch mcp starts");

    let meta = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#;
    let script = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{{{meta}}}}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{{{meta}}}}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"synch_spaces\",\"arguments\":{{}},{meta}}}}}\n"
    );
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(script.as_bytes())
        .expect("the script is written");
    // Closing stdin is the shutdown signal, and the server still answers what
    // it already accepted before it exits.

    // Bounded, because closing stdin being the shutdown signal is part of what
    // this test asserts: a build where it stops working should fail here in a
    // minute rather than hang until the CI job's own timeout kills it, which
    // reads as an infrastructure problem rather than the regression it is.
    // Safe to poll rather than drain because the three responses above are far
    // inside the pipe buffer, so the child is never blocked writing them.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while child
        .try_wait()
        .expect("the child's state is readable")
        .is_none()
    {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            daemon.stop(&cli);
            panic!("`synch mcp` did not exit within 60s of its stdin closing");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("synch mcp exits");
    // The child is gone, so nothing below needs the daemon. Stopped here so an
    // assertion that fails does not leave it running for the rest of the run.
    daemon.stop(&cli);
    assert!(
        output.status.success(),
        "synch mcp exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let mut ids = Vec::new();
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        // Every line, not just the ones we care about: one stray byte on this
        // channel breaks the client's framing for good.
        let message: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("stdout line {line:?}: {e}"));
        assert_eq!(message["jsonrpc"], "2.0", "{line}");
        ids.push(
            message["id"]
                .as_i64()
                .expect("every response carries its id"),
        );
    }
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2, 3], "one response per request:\n{stdout}");

    // And the logging went where logging goes.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("serving MCP over stdio"),
        "the startup log should be on stderr:\n{stderr}"
    );
}
