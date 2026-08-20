//! End-to-end tests that drive the real `synch` binary.
//!
//! `synch init` creates the datadir; `synch daemon run` owns the node; every
//! other command is a control-socket request to that daemon (§9.1). These
//! tests walk that path through the actual binary — the in-process
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

    fn output(&self, args: &[&str]) -> std::process::Output {
        Command::new(synch_bin())
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--offline")
            .args(args)
            .output()
            .expect("synch binary runs")
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

        // The banner is printed after the socket is bound, but the first
        // command still has to find a daemon that has finished opening.
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

    // No domain: the device key is the identity and nothing has to be
    // published for the node to know what it is (§3.1).
    let out = cli.run(&["init"]);
    assert!(out.contains("origin:"), "{out}");
    assert!(out.contains("synch daemon run"), "{out}");

    // Init is not idempotent: a second one must not silently replace the key.
    let (ok, _, _) = cli.try_run(&["init"]);
    assert!(!ok, "init must refuse to overwrite an identity");

    // Everything else needs the daemon, and says so.
    for args in [
        vec!["id"],
        vec!["ls", "media"],
        vec!["doctor"],
        vec!["daemon", "status"],
    ] {
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
fn commands_refuse_to_run_without_an_identity() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    // No datadir at all: `daemon run` has nothing to open.
    let (ok, _, stderr) = cli.try_run(&["daemon", "run"]);
    assert!(!ok);
    assert!(stderr.contains("synch init"), "{stderr}");
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

    cli.run(&["space", "add", "media", &space.path().to_string_lossy()]);
    assert!(cli.run(&["space", "ls"]).contains("media"));
    let scan = cli.run(&["scan"]);
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

    // A mirror actually materializes content on disk.
    let mirror_dir = tempfile::tempdir().unwrap();
    cli.run(&[
        "mirror",
        "add",
        "media",
        &mirror_dir.path().to_string_lossy(),
        "--policy",
        "newest",
    ]);
    assert!(cli.run(&["mirror", "ls"]).contains("newest"));
    cli.run(&["mirror", "sync"]);
    assert_eq!(
        std::fs::read(mirror_dir.path().join("notes.txt")).unwrap(),
        b"hello"
    );
    assert!(cli
        .run(&["mirror", "rm", &mirror_dir.path().to_string_lossy()])
        .contains("removed"));

    // A pin may name a path, in which case the version the reading policy
    // selects supplies the root (§8).
    let root = blake3::hash(b"hello").to_hex().to_string();
    assert!(cli.run(&["pin", "add", "media/notes.txt"]).contains(&root));
    assert!(cli.run(&["pin", "ls"]).contains(&root));
    assert!(cli.run(&["pin", "rm", "media/notes.txt"]).contains(&root));
    assert!(!cli.run(&["pin", "ls"]).contains(&root));

    // A daemon-side failure is this process's exit status, not a transport
    // error.
    let (ok, _, stderr) = cli.try_run(&["pin", "add", "nothex"]);
    assert!(!ok);
    assert!(stderr.contains("hex"), "{stderr}");

    let doctor = cli.run(&["doctor"]);
    assert!(doctor.contains(&format!("origin: {origin}")), "{doctor}");
    assert!(doctor.contains("equivocation: none detected"), "{doctor}");
    assert!(cli.run(&["daemon", "status"]).contains("head: seq"));

    // `synch recover` on a node no peer has ever advertised: it collects one
    // round, finds nothing to resume from, and leaves the seq alone (§3.4).
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

    // Each side learns the other's key. Addresses are exchanged explicitly
    // because these nodes run with discovery disabled, and static trust
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

    nas.run(&["space", "add", "media", &nas_space.path().to_string_lossy()]);
    nas.run(&["scan"]);

    // The publish is pushed reactively; the periodic round repairs whatever
    // the push missed.
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

    // A verified full read, a verified range read, and a `get`, all streamed
    // from the laptop's daemon over the control socket.
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
