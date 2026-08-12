//! End-to-end tests that drive the real `synch` binary.
//!
//! Two nodes are wired together with static trust and explicit direct
//! addresses, then made to converge and transfer content — the same path a user
//! walks, exercised through the actual command surface.

use std::{
    path::{Path, PathBuf},
    process::Command,
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

    fn try_run(&self, args: &[&str]) -> (bool, String, String) {
        let output = Command::new(synch_bin())
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--offline")
            .args(args)
            .output()
            .expect("synch binary runs");
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
        let output = Command::new(synch_bin())
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--offline")
            .args(args)
            .output()
            .expect("synch binary runs");
        assert!(
            output.status.success(),
            "synch {args:?} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }
}

#[test]
fn init_id_and_doctor() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());

    let out = cli.run(&["init", "--id", "nas@cluster.example"]);
    assert!(out.contains("nas@cluster.example"), "{out}");

    // Init is not idempotent: a second one must not silently replace the key.
    let (ok, _, _) = cli.try_run(&["init"]);
    assert!(!ok, "init must refuse to overwrite an identity");

    let id = cli.run(&["id"]);
    assert!(id.contains("nas@cluster.example"), "{id}");
    assert!(id.contains("active"), "{id}");

    let doctor = cli.run(&["doctor"]);
    assert!(doctor.contains("origin: nas@cluster.example"), "{doctor}");
    assert!(doctor.contains("equivocation: none detected"), "{doctor}");
    assert!(doctor.contains("static trust only"), "{doctor}");
}

#[test]
fn commands_refuse_to_run_without_an_identity() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    let (ok, _, stderr) = cli.try_run(&["id"]);
    assert!(!ok);
    assert!(stderr.contains("synch init"), "{stderr}");
}

#[test]
fn spaces_scan_and_list() {
    let dir = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    cli.run(&["init"]);

    std::fs::create_dir_all(space.path().join("talks")).unwrap();
    std::fs::write(space.path().join("notes.txt"), b"hello").unwrap();
    std::fs::write(space.path().join("talks/a.txt"), b"talk").unwrap();

    cli.run(&["space", "add", "media", &space.path().to_string_lossy()]);
    assert!(cli.run(&["space", "ls"]).contains("media"));

    let scan = cli.run(&["scan"]);
    assert!(scan.contains("hashed 2"), "{scan}");
    assert!(scan.contains("published seq 1"), "{scan}");

    let ls = cli.run(&["ls", "media"]);
    assert!(ls.contains("notes.txt"), "{ls}");
    assert!(ls.contains("talks/a.txt"), "{ls}");

    // A directory listing is a prefix scan.
    let ls = cli.run(&["ls", "media/talks"]);
    assert!(ls.contains("talks/a.txt"), "{ls}");
    assert!(!ls.contains("notes.txt"), "{ls}");

    // A second scan finds nothing new.
    assert!(cli.run(&["scan"]).contains("nothing changed"));

    let status = cli.run(&["status", "media"]);
    assert!(status.contains("[agree]"), "{status}");

    // Deleting a file publishes a tombstone, visible as a "deleted" entry.
    std::fs::remove_file(space.path().join("notes.txt")).unwrap();
    cli.run(&["scan"]);
    let ls = cli.run(&["ls", "media"]);
    assert!(ls.contains("deleted"), "{ls}");

    let log = cli.run(&["log", "media/notes.txt"]);
    assert!(log.contains("seq 2"), "{log}");
    assert!(log.contains("seq 1"), "{log}");
}

#[test]
fn pins_and_trust_management() {
    let dir = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    cli.run(&["init"]);
    std::fs::write(space.path().join("a.txt"), b"pin me").unwrap();
    cli.run(&["space", "add", "media", &space.path().to_string_lossy()]);
    cli.run(&["scan"]);

    let root = blake3::hash(b"pin me").to_hex().to_string();
    cli.run(&["pin", "add", &root]);
    assert!(cli.run(&["pin", "ls"]).contains(&root));
    cli.run(&["pin", "rm", &root]);
    assert!(cli.run(&["pin", "ls"]).trim().is_empty());

    // A bogus root is rejected rather than silently ignored.
    let (ok, _, stderr) = cli.try_run(&["pin", "add", "nothex"]);
    assert!(!ok);
    assert!(stderr.contains("hex"), "{stderr}");

    // Static trust, named so it can rotate.
    let peer = tempfile::tempdir().unwrap();
    let peer_cli = Cli::new(peer.path());
    peer_cli.run(&["init"]);
    let peer_key = key_of(&peer_cli);

    cli.run(&[
        "trust",
        "add",
        &peer_key,
        "--as",
        "laptop",
        "--domain",
        "x.example",
    ]);
    let trust = cli.run(&["trust", "ls"]);
    assert!(trust.contains("laptop@x.example"), "{trust}");
    assert!(trust.contains("live"), "{trust}");

    cli.run(&["trust", "rm", "laptop@x.example"]);
    assert!(!cli.run(&["trust", "ls"]).contains("laptop@x.example"));
}

#[test]
fn domains_are_configurable_without_dns() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    cli.run(&["init", "--id", "nas@cluster.example"]);

    // `domain add` attempts a refresh; with no resolver or no records it must
    // still record the domain and fail closed rather than crash.
    let _ = cli.try_run(&["domain", "add", "cluster.example"]);
    assert!(cli.run(&["domain", "ls"]).contains("cluster.example"));
    let doctor = cli.run(&["doctor"]);
    assert!(doctor.contains("domain cluster.example"), "{doctor}");

    cli.run(&["domain", "rm", "cluster.example"]);
    assert!(cli.run(&["domain", "ls"]).trim().is_empty());
}

#[test]
fn key_rotation_prints_the_record_to_publish() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::new(dir.path());
    cli.run(&["init", "--id", "nas@cluster.example"]);

    let out = cli.run(&["key", "rotate"]);
    assert!(out.contains("_synchronicity.cluster.example."), "{out}");
    assert!(out.contains("v=sync1 id=nas nk="), "{out}");
    // Both keys are held during the window, exactly one of them active.
    let keys = cli.run(&["key", "ls"]);
    assert_eq!(keys.lines().count(), 2, "{keys}");
    assert_eq!(keys.matches("active").count(), 1, "{keys}");

    // A key-identified origin says so instead of printing a record.
    let other = tempfile::tempdir().unwrap();
    let other_cli = Cli::new(other.path());
    other_cli.run(&["init"]);
    let out = other_cli.run(&["key", "rotate"]);
    assert!(out.contains("cannot rotate"), "{out}");
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
    ]);
    laptop.run(&[
        "trust",
        "add",
        &nas_key,
        "--as",
        "nas",
        "--domain",
        "cluster.example",
    ]);

    // Publish on the NAS.
    let payload: Vec<u8> = (0..120_000u32).map(|i| (i * 13) as u8).collect();
    std::fs::write(nas_space.path().join("small.txt"), b"a small file").unwrap();
    std::fs::write(nas_space.path().join("big.bin"), &payload).unwrap();
    nas.run(&["space", "add", "media", &nas_space.path().to_string_lossy()]);
    nas.run(&["scan"]);

    // Bring the NAS up as a daemon so the laptop has something to dial.
    let mut daemon = Command::new(synch_bin())
        .arg("--data-dir")
        .arg(nas_dir.path())
        .arg("--offline")
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("daemon")
        .arg("run")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("daemon starts");

    let addr = read_daemon_address(&mut daemon);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Point the laptop at the running NAS and sync.
        laptop.run(&[
            "trust",
            "add",
            &nas_key,
            "--as",
            "nas",
            "--domain",
            "cluster.example",
            "--addr",
            &addr,
        ]);

        // `ls` on the laptop is empty until it syncs.
        assert!(laptop.run(&["ls", "media"]).trim().is_empty());

        // A `cat` triggers a sync-on-demand path: the laptop must first learn
        // the head. Drive that through the peers/anti-entropy path by running
        // the daemon briefly on the laptop side is heavy, so use `doctor` to
        // confirm the binding and then sync via a short daemon run.
        let mut laptop_daemon = Command::new(synch_bin())
            .arg("--data-dir")
            .arg(laptop_dir.path())
            .arg("--offline")
            .arg("--bind")
            .arg("127.0.0.1:0")
            .arg("daemon")
            .arg("run")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("laptop daemon starts");
        let _ = read_daemon_address(&mut laptop_daemon);

        // Wait for the laptop to converge; the first anti-entropy round fires
        // within one jittered interval, but the initial push from the NAS side
        // is not guaranteed to have happened yet.
        let mut converged = false;
        for _ in 0..120 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if laptop.run(&["ls", "media"]).contains("big.bin") {
                converged = true;
                break;
            }
        }
        let _ = laptop_daemon.kill();
        let _ = laptop_daemon.wait();
        assert!(converged, "the laptop never learned the NAS's entries");

        // Metadata matches; content still lives only on the NAS.
        let ls = laptop.run(&["ls", "media"]);
        assert!(ls.contains("small.txt"), "{ls}");
        assert!(ls.contains("120000"), "{ls}");

        // A verified full read and a verified range read.
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
        let status = laptop.run(&["status", "media"]);
        assert!(status.contains("nas@cluster.example"), "{status}");
    }));

    let _ = daemon.kill();
    let _ = daemon.wait();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
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

/// Reads the `origin ... via HOST:PORT` line a daemon prints on startup.
fn read_daemon_address(child: &mut std::process::Child) -> String {
    use std::io::{BufRead, BufReader};
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("daemon prints a banner");
    // Keep draining so the child never blocks on a full pipe.
    std::thread::spawn(move || {
        let mut sink = String::new();
        while reader.read_line(&mut sink).unwrap_or(0) > 0 {
            sink.clear();
        }
    });
    line.rsplit(" via ")
        .next()
        .unwrap_or_default()
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}
