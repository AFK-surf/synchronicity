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

    let out = cli.run(&["init", "--id", "nas@cluster.example"]);
    assert!(out.contains("nas@cluster.example"), "{out}");
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
    cli.run(&["init", "--id", "nas@cluster.example"]);

    std::fs::create_dir_all(space.path().join("talks")).unwrap();
    std::fs::write(space.path().join("notes.txt"), b"hello").unwrap();
    std::fs::write(space.path().join("talks/a.txt"), b"talk").unwrap();

    let daemon = cli.daemon();

    let id = cli.run(&["id"]);
    assert!(id.contains("nas@cluster.example"), "{id}");
    assert!(id.contains("active"), "{id}");

    cli.run(&["space", "add", "media", &space.path().to_string_lossy()]);
    assert!(cli.run(&["space", "ls"]).contains("media"));

    let scan = cli.run(&["scan"]);
    assert!(scan.contains("hashed 2"), "{scan}");
    assert!(scan.contains("published seq"), "{scan}");

    let ls = cli.run(&["ls", "media"]);
    assert!(ls.contains("notes.txt"), "{ls}");
    assert!(ls.contains("talks/a.txt"), "{ls}");
    let ls = cli.run(&["ls", "media/talks"]);
    assert!(!ls.contains("notes.txt"), "{ls}");

    assert_eq!(
        cli.run_bytes(&["cat", "nas@cluster.example:media/notes.txt"]),
        b"hello"
    );
    let out = tempfile::tempdir().unwrap();
    let target = out.path().join("notes.txt");
    cli.run(&[
        "get",
        "nas@cluster.example:media/notes.txt",
        "-o",
        &target.to_string_lossy(),
    ]);
    assert_eq!(std::fs::read(&target).unwrap(), b"hello");

    assert!(cli.run(&["status", "media"]).contains("[agree]"));
    assert!(cli.run(&["log", "media/notes.txt"]).contains("seq 1"));

    let root = blake3::hash(b"hello").to_hex().to_string();
    cli.run(&["pin", "add", &root]);
    assert!(cli.run(&["pin", "ls"]).contains(&root));
    cli.run(&["pin", "rm", &root]);

    // A daemon-side failure is this process's exit status, not a transport
    // error.
    let (ok, _, stderr) = cli.try_run(&["pin", "add", "nothex"]);
    assert!(!ok);
    assert!(stderr.contains("hex"), "{stderr}");

    // Rotation, driven entirely by the operator (§3.4).
    let rotate = cli.run(&["key", "rotate"]);
    assert!(
        rotate.contains("_synchronicity.cluster.example."),
        "{rotate}"
    );
    assert!(rotate.contains("v=sync1 id=nas nk="), "{rotate}");
    let keys = cli.run(&["key", "ls"]);
    assert_eq!(keys.lines().count(), 2, "{keys}");
    assert_eq!(keys.matches("active").count(), 1, "{keys}");
    let new_key = keys
        .lines()
        .find(|line| line.contains("retiring"))
        .and_then(|line| line.split_whitespace().next())
        .expect("the generated key")
        .to_string();
    let old_key = keys
        .lines()
        .find(|line| line.contains("active"))
        .and_then(|line| line.split_whitespace().next())
        .expect("the active key")
        .to_string();

    let activated = cli.run(&["key", "activate", &new_key]);
    assert!(activated.contains(&new_key), "{activated}");
    assert!(cli.run(&["id"]).contains(&new_key));
    // Both keys serve until the old one is retired.
    assert!(cli.run(&["doctor"]).contains("retiring:"));
    cli.run(&["key", "retire", &old_key]);
    let keys = cli.run(&["key", "ls"]);
    assert_eq!(keys.lines().count(), 1, "{keys}");
    assert!(keys.contains(&new_key), "{keys}");

    // A publish after the rotation is signed by the new key and keeps counting
    // up from where the old one left off.
    std::fs::write(space.path().join("after.txt"), b"after").unwrap();
    let scan = cli.run(&["scan"]);
    assert!(scan.contains("published seq"), "{scan}");

    let doctor = cli.run(&["doctor"]);
    assert!(doctor.contains("origin: nas@cluster.example"), "{doctor}");
    assert!(doctor.contains("equivocation: none detected"), "{doctor}");
    assert!(cli.run(&["daemon", "status"]).contains("storage:"));

    daemon.stop(&cli);

    // With the daemon gone, the socket is gone with it.
    let (ok, _, stderr) = cli.try_run(&["id"]);
    assert!(!ok);
    assert!(stderr.contains("synch daemon run"), "{stderr}");
}

#[test]
fn domains_are_configurable_without_dns() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    cli.run(&["init", "--id", "nas@cluster.example"]);
    let daemon = cli.daemon();

    // `domain add` attempts a refresh; with no resolver or no records it must
    // still record the domain and fail closed rather than crash.
    let _ = cli.try_run(&["domain", "add", "cluster.example"]);
    assert!(cli.run(&["domain", "ls"]).contains("cluster.example"));
    assert!(cli.run(&["doctor"]).contains("domain cluster.example"));

    cli.run(&["domain", "rm", "cluster.example"]);
    assert!(cli.run(&["domain", "ls"]).trim().is_empty());
    daemon.stop(&cli);
}

#[test]
fn two_nodes_converge_and_transfer_content_over_the_cli() {
    let nas_dir = tempfile::tempdir().unwrap();
    let nas_space = tempfile::tempdir().unwrap();
    let laptop_dir = tempfile::tempdir().unwrap();
    let nas = Cli::new(nas_dir.path());
    let laptop = Cli::new(laptop_dir.path());

    nas.run(&["init", "--id", "nas@cluster.example"]);
    laptop.run(&["init", "--id", "laptop@cluster.example"]);

    let payload: Vec<u8> = (0..120_000u32).map(|i| (i * 13) as u8).collect();
    std::fs::write(nas_space.path().join("small.txt"), b"a small file").unwrap();
    std::fs::write(nas_space.path().join("big.bin"), &payload).unwrap();

    let nas_daemon = nas.daemon();
    let laptop_daemon = laptop.daemon();

    // Each side learns the other's key. Addresses are exchanged explicitly
    // because these nodes run with discovery disabled.
    let nas_key = key_of(&nas);
    let laptop_key = key_of(&laptop);
    nas.run(&[
        "trust",
        "add",
        &laptop_key,
        "--as",
        "laptop",
        "--domain",
        "cluster.example",
        "--addr",
        &laptop_daemon.address,
    ]);
    laptop.run(&[
        "trust",
        "add",
        &nas_key,
        "--as",
        "nas",
        "--domain",
        "cluster.example",
        "--addr",
        &nas_daemon.address,
    ]);

    // `ls` on the laptop is empty until the NAS publishes and pushes.
    assert!(laptop.run(&["ls", "media"]).trim().is_empty());

    nas.run(&["space", "add", "media", &nas_space.path().to_string_lossy()]);
    nas.run(&["scan"]);

    // The publish is pushed reactively; the periodic round repairs whatever
    // the push missed.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut converged = false;
    while Instant::now() < deadline {
        if laptop.run(&["ls", "media"]).contains("big.bin") {
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

    // A verified full read and a verified range read, both streamed from the
    // laptop's daemon over the control socket.
    let got = laptop.run_bytes(&["cat", "nas@cluster.example:media/small.txt"]);
    assert_eq!(got, b"a small file");

    let got = laptop.run_bytes(&[
        "cat",
        "nas@cluster.example:media/big.bin",
        "--range",
        "60000..60100",
    ]);
    assert_eq!(got, &payload[60_000..60_100]);

    let out_dir = tempfile::tempdir().unwrap();
    let target = out_dir.path().join("fetched.bin");
    laptop.run(&[
        "get",
        "nas@cluster.example:media/big.bin",
        "-o",
        &target.to_string_lossy(),
    ]);
    assert_eq!(std::fs::read(&target).unwrap(), payload);

    // `status` now shows both origins' views of the space.
    assert!(laptop
        .run(&["status", "media"])
        .contains("nas@cluster.example"));
    assert!(laptop.run(&["peers"]).contains(&nas_key));

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
