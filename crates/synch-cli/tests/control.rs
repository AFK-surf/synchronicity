//! Control round-trips against a daemon in a temp datadir (§11).
//!
//! The daemon runs in process here — the same `Server`, transport, and
//! service the real binary serves — so the whole command surface is
//! exercised without paying for a process spawn per command. `tests/cli.rs`
//! keeps the end-to-end check through the actual binary.

use std::path::Path;

use iroh_base::SecretKey;
use synch_cli::control::{
    proto::{pb, CHUNK_SIZE, CONTROL_VERSION},
    Client, Command, ControlError, EntryInfo, ErrorCode, Frame, Server,
};
use synch_core::OriginId;
use synch_engine::{Node, NodeConfig};
use tokio::sync::broadcast;

/// Runs blocking store work the way production does — off the runtime.
///
/// Every test here runs on a multi-thread runtime deliberately: that is the
/// flavor the daemon binary starts, and it is the only one `Store::conn`'s
/// assertion can see a violation on (§10).
async fn off_runtime<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        f()
    })
    .await
    .expect("the blocking task should complete")
}

/// A daemon running in this process, with its control socket bound.
struct Daemon {
    node: Node,
    stop: broadcast::Sender<()>,
    served: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Daemon {
    async fn start(data_dir: &Path) -> Daemon {
        let dir = data_dir.to_path_buf();
        off_runtime(move || {
            Node::init_named_by_zone(&dir, OriginId::named("nas", "cluster.example").unwrap())
        })
        .await
        .unwrap();
        Daemon::reopen(data_dir).await
    }

    async fn reopen(data_dir: &Path) -> Daemon {
        let node = Node::open(NodeConfig::loopback(data_dir)).await.unwrap();
        let (stop, _) = broadcast::channel(1);
        let server = Server::bind(node.clone(), stop.clone()).await.unwrap();
        let served = tokio::spawn(server.run());
        Daemon { node, stop, served }
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = self.served.await;
        self.node.shutdown().await.unwrap();
    }

    /// Records a file another origin published, the way a completed sync
    /// would have left it: the bytes in the CAS, the entry in that origin's
    /// view.
    async fn peer_file(
        &self,
        origin: &OriginId,
        space: &str,
        path: &str,
        bytes: &[u8],
        mtime_ns: i64,
        seq: u64,
    ) {
        let (node, origin) = (self.node.clone(), origin.clone());
        let (space, path, bytes) = (space.to_string(), path.to_string(), bytes.to_vec());
        off_runtime(move || {
            let root = node
                .store()
                .ingest_bytes(&bytes, synch_core::now_ns())
                .unwrap();
            let entry = synch_core::FileEntry::file(bytes.len() as u64, mtime_ns, root, seq);
            node.store()
                .put_entry(&origin, &space, &path, &entry)
                .unwrap();
        })
        .await
    }

    /// The same for an assertion with no content behind it — a tombstone.
    async fn peer_entry(
        &self,
        origin: &OriginId,
        space: &str,
        path: &str,
        entry: synch_core::FileEntry,
    ) {
        let (node, origin) = (self.node.clone(), origin.clone());
        let (space, path) = (space.to_string(), path.to_string());
        off_runtime(move || {
            node.store()
                .put_entry(&origin, &space, &path, &entry)
                .unwrap();
        })
        .await
    }
}

/// Runs one command and collects every frame of its output.
async fn frames(data_dir: &Path, command: Command) -> Result<Vec<Frame>, ErrorCode> {
    let mut client = Client::connect(data_dir)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let mut frames = client.run(command).await.unwrap();
    let mut out = Vec::new();
    loop {
        match frames.next().await {
            Ok(Some(frame)) => out.push(frame),
            Ok(None) => return Ok(out),
            Err(e) => return Err(e.code),
        }
    }
}

/// The `Line` frames of a response, as one string.
async fn lines(data_dir: &Path, command: Command) -> String {
    let frames = frames(data_dir, command)
        .await
        .unwrap_or_else(|code| panic!("request failed: {}", code.as_str()));
    frames
        .into_iter()
        .filter_map(|frame| match frame {
            Frame::Line(text) => Some(text),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The daemon's error code for a command that must fail.
async fn failure(data_dir: &Path, command: Command) -> ErrorCode {
    frames(data_dir, command)
        .await
        .expect_err("the request should have failed")
}

/// The structured error a failing command produces, message and all.
async fn failure_message(
    data_dir: &Path,
    command: Command,
) -> synch_cli::control::proto::ControlError {
    let mut client = Client::connect(data_dir).await.unwrap();
    let mut frames = client.run(command).await.unwrap();
    loop {
        match frames.next().await {
            Ok(Some(_)) => {}
            Ok(None) => panic!("the command should have failed"),
            Err(e) => return e,
        }
    }
}

/// The progress reports of a command.
async fn progress_of(data_dir: &Path, command: Command) -> Vec<String> {
    frames(data_dir, command)
        .await
        .expect("the command should have succeeded")
        .into_iter()
        .filter_map(|frame| match frame {
            Frame::Progress(text) => Some(text),
            _ => None,
        })
        .collect()
}

/// Reads the chunked payload of a command.
async fn read(data_dir: &Path, command: Command) -> Vec<u8> {
    let frames = frames(data_dir, command).await.expect("a payload");
    frames
        .into_iter()
        .filter_map(|frame| match frame {
            Frame::Chunk(bytes) => Some(bytes),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Every entry of a listing.
async fn entries(data_dir: &Path, request: pb::ListRequest) -> Vec<EntryInfo> {
    let mut client = Client::connect(data_dir).await.unwrap();
    let mut listing = client
        .list(request)
        .await
        .unwrap_or_else(|e| panic!("list failed: {}", e.code.as_str()));
    let mut out = Vec::new();
    while let Some(entry) = listing
        .next()
        .await
        .unwrap_or_else(|e| panic!("list failed: {}", e.code.as_str()))
    {
        out.push(entry);
    }
    out
}

/// The one entry a resolve selects.
async fn resolve(data_dir: &Path, request: pb::ResolveRequest) -> Result<EntryInfo, ErrorCode> {
    Client::connect(data_dir)
        .await
        .unwrap()
        .resolve(request)
        .await
        .map_err(|e| e.code)
}

/// One config value from the `s3.*` namespace.
async fn config(data_dir: &Path, key: &str) -> Result<Vec<String>, ErrorCode> {
    Client::connect(data_dir)
        .await
        .unwrap()
        .config(key)
        .await
        .map_err(|e| e.code)
}

/// Appends one record to a config value in the `s3.*` namespace.
async fn append_config(data_dir: &Path, key: &str, record: &str) -> Result<(), ErrorCode> {
    Client::connect(data_dir)
        .await
        .unwrap()
        .append_config(key, record)
        .await
        .map_err(|e| e.code)
}

/// The whole payload of a structured read.
async fn tree_read(data_dir: &Path, request: pb::ReadRequest) -> Result<Vec<u8>, ErrorCode> {
    let mut client = Client::connect(data_dir).await.unwrap();
    let mut chunks = client.read(request).await.map_err(|e| e.code)?;
    let mut out = Vec::new();
    while let Some(bytes) = chunks.next().await.map_err(|e| e.code)? {
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

/// Runs the cheapest command there is, to see whether the daemon will serve
/// this client at all.
///
/// The version and the token are checked on every call, not once per
/// connection, so this is what a credential is admitted or refused by.
async fn admitted(mut client: Client) -> Result<(), ControlError> {
    let mut frames = client.run(Command::Id(pb::Id {})).await?;
    while frames.next().await?.is_some() {}
    Ok(())
}

fn space_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in files {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, bytes).unwrap();
    }
    dir
}

/// A fresh daemon with a space of files added and scanned. Returns the
/// scan's output, so tests can assert the numbers without rescanning.
async fn daemon_with_space(
    files: &[(&str, &[u8])],
) -> (tempfile::TempDir, Daemon, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let space = space_with(files);
    let data_dir = dir.path();
    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    let scan = lines(data_dir, Command::Scan(pb::Scan {})).await;
    (dir, daemon, space, scan)
}

/// Runs a command and asserts its output contains `needle`.
async fn says(data_dir: &Path, command: Command, needle: &str) -> String {
    let out = lines(data_dir, command).await;
    assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
    out
}

/// The most common command shapes, so the sweep reads as one call per
/// command rather than one struct literal per call.
fn cat(reference: &str, range: Option<&str>, from: Option<&str>) -> Command {
    Command::Cat(pb::Cat {
        reference: reference.into(),
        range: range.map(String::from),
        from: from.map(String::from),
        strict: false,
    })
}

fn ls(reference: &str) -> Command {
    Command::Ls(pb::Ls {
        reference: reference.into(),
        all: false,
    })
}

fn trust_add(key: &str, note: Option<&str>, addr: Option<&str>) -> Command {
    Command::TrustAdd(pb::TrustAdd {
        key: key.into(),
        note: note.map(String::from),
        addr: addr.map(String::from),
    })
}

fn trust_rm(origin: &str, key: Option<&str>) -> Command {
    Command::TrustRm(pb::TrustRm {
        origin: origin.into(),
        key: key.map(String::from),
    })
}

fn recover(wait: Option<&str>, gap: Option<u64>) -> Command {
    Command::Recover(pb::Recover {
        wait: wait.map(String::from),
        gap,
    })
}

fn resolve_req(space: &str, path: &str) -> pb::ResolveRequest {
    pb::ResolveRequest {
        space: space.into(),
        path: path.into(),
        policy: None,
    }
}

fn read_req(space: &str, path: &str, start: u64, len: Option<u64>) -> pb::ReadRequest {
    pb::ReadRequest {
        space: space.into(),
        path: path.into(),
        policy: None,
        start,
        len,
    }
}

fn list_req(space: &str, prefix: &str, start_after: Option<&str>) -> pb::ListRequest {
    pb::ListRequest {
        space: space.into(),
        prefix: prefix.into(),
        start_after: start_after.map(String::from),
        limit: None,
        policy: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_command_variant_round_trips() {
    // The only guard that every Command variant encodes, dispatches, and
    // answers over the socket — and the deepest key-rotation assertions
    // anywhere (node_id switch, retiring_endpoints, secret deletion).
    let (dir, daemon, _space, scan) =
        daemon_with_space(&[("notes.txt", b"hello"), ("talks/a.txt", b"talk")]).await;
    let data_dir = dir.path();
    let peer_key = SecretKey::generate().public().to_z32();

    // Identity and keys. One key, plus the line saying there was nobody to
    // ask about it (§3.4).
    let id = says(data_dir, Command::Id(pb::Id {}), "nas@cluster.example").await;
    assert!(id.contains("active"), "{id}");
    let keys = says(
        data_dir,
        Command::KeyLs(pb::KeyLs {}),
        "no trusted peers to ask",
    )
    .await;
    assert!(keys.contains("bound by 0 of 0 reachable peer(s)"), "{keys}");
    assert_eq!(keys.lines().count(), 2, "{keys}");
    // A manual round with nobody to run it against says so and succeeds.
    says(
        data_dir,
        Command::SyncNow(pb::SyncNow {}),
        "no dialable peers",
    )
    .await;

    // Spaces, scanning, and listing. The scan streams progress as it goes (§9.3).
    says(data_dir, Command::SpaceLs(pb::SpaceLs {}), "media").await;
    assert!(scan.contains("hashed 2"), "{scan}");
    assert!(scan.contains("published seq 1"), "{scan}");
    let progress = progress_of(data_dir, Command::Scan(pb::Scan {})).await;
    assert!(
        progress.iter().any(|l| l.contains("scanned media")),
        "{progress:?}"
    );
    let ls = says(data_dir, ls("media"), "notes.txt").await;
    assert!(ls.contains("talks/a.txt"), "{ls}");
    let status = says(
        data_dir,
        Command::Status(pb::Status {
            reference: Some("media".into()),
        }),
        "media/notes.txt  1 version(s)",
    )
    .await;
    assert!(status.contains("nas@cluster.example"), "{status}");

    // Reads, in full and by range.
    assert_eq!(
        read(
            data_dir,
            cat("nas@cluster.example:media/notes.txt", None, None)
        )
        .await,
        b"hello"
    );
    assert_eq!(
        read(data_dir, cat("media/notes.txt", Some("1..3"), None)).await,
        b"el"
    );
    says(
        data_dir,
        Command::Log(pb::Log {
            reference: "media/notes.txt".into(),
        }),
        "seq 1",
    )
    .await;

    // Membership. The key is the identity: static trust names nobody (§3.2).
    says(
        data_dir,
        trust_add(&peer_key, Some("a test peer"), Some("127.0.0.1:4433")),
        &peer_key,
    )
    .await;
    says(data_dir, Command::TrustLs(pb::TrustLs {}), "a test peer").await;
    says(data_dir, Command::Peers(pb::Peers {}), &peer_key).await;

    // Dropping one key's binding by name, then the whole origin. A
    // key-identified origin holds exactly one binding, so the two spellings
    // are the same removal — and a second attempt at either is a not-found.
    says(
        data_dir,
        trust_rm(&format!("key:{peer_key}"), Some(&peer_key)),
        "binding to",
    )
    .await;
    assert_eq!(
        failure(
            data_dir,
            trust_rm(&format!("key:{peer_key}"), Some(&peer_key))
        )
        .await,
        ErrorCode::NotFound
    );
    let second = SecretKey::generate().public().to_z32();
    lines(data_dir, trust_add(&second, None, None)).await;
    says(
        data_dir,
        trust_rm(&format!("key:{second}"), None),
        "removed 1 binding(s)",
    )
    .await;

    // The domain. `set` records it with no resolver here, pending the next
    // start (§3.1) — `domain ls` says so.
    let _ = frames(
        data_dir,
        Command::DomainSet(pb::DomainSet {
            domain: "cluster.example".into(),
        }),
    )
    .await;
    says(
        data_dir,
        Command::DomainLs(pb::DomainLs {}),
        "not yet resolved by this daemon",
    )
    .await;
    let _ = frames(data_dir, Command::DomainRefresh(pb::DomainRefresh {})).await;
    says(
        data_dir,
        Command::DomainClear(pb::DomainClear {}),
        "cleared",
    )
    .await;
    assert_eq!(
        failure(data_dir, Command::DomainClear(pb::DomainClear {})).await,
        ErrorCode::NotFound,
        "there is nothing left to clear"
    );

    // Mirrors.
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror_path = mirror_dir.path().to_string_lossy().into_owned();
    let mirroring = says(
        data_dir,
        Command::MirrorAdd(pb::MirrorAdd {
            space: "media".into(),
            path: mirror_path.clone(),
            policy: Some("origin=laptop@cluster.example".into()),
        }),
        "mirroring",
    )
    .await;
    assert!(
        mirroring.contains("origin=laptop@cluster.example"),
        "{mirroring}"
    );
    let mirror_ls = says(data_dir, Command::MirrorLs(pb::MirrorLs {}), "media").await;
    assert!(
        mirror_ls.contains("origin=laptop@cluster.example"),
        "{mirror_ls}"
    );
    let _ = frames(data_dir, Command::MirrorSync(pb::MirrorSync {}))
        .await
        .unwrap();
    says(
        data_dir,
        Command::MirrorRm(pb::MirrorRm {
            path: mirror_path.clone(),
        }),
        "removed",
    )
    .await;

    // Pins, by root.
    let root = blake3::hash(b"hello").to_hex().to_string();
    says(
        data_dir,
        Command::PinAdd(pb::PinAdd {
            target: root.clone(),
        }),
        &root,
    )
    .await;
    says(data_dir, Command::PinLs(pb::PinLs {}), &root).await;
    says(
        data_dir,
        Command::PinRm(pb::PinRm {
            target: root.clone(),
        }),
        &root,
    )
    .await;
    assert!(lines(data_dir, Command::PinLs(pb::PinLs {}))
        .await
        .is_empty());

    // Reports.
    let doctor = says(
        data_dir,
        Command::Doctor(pb::Doctor { rebuild: false }),
        "origin: nas@cluster.example",
    )
    .await;
    assert!(doctor.contains("equivocation: none detected"), "{doctor}");
    let rebuilt = lines(data_dir, Command::Doctor(pb::Doctor { rebuild: true })).await;
    assert!(rebuilt.contains("rebuilt"), "{rebuilt}");
    // Status is the glance, not the byte-identical twin of doctor.
    let status = says(
        data_dir,
        Command::DaemonStatus(pb::DaemonStatus {}),
        "origin nas@cluster.example",
    )
    .await;
    assert!(status.contains("spaces: 1 (media)"), "{status}");
    assert!(status.contains("head: seq"), "{status}");
    assert!(!status.contains("storage:"), "{status}");

    // Rotation, end to end and operator-driven (§3.4).
    let rotate = says(
        data_dir,
        Command::KeyRotate(pb::KeyRotate {}),
        "v=sync1 id=nas nk=",
    )
    .await;
    assert!(
        rotate.contains("_synchronicity.cluster.example."),
        "{rotate}"
    );
    let new_key = rotate
        .lines()
        .next()
        .unwrap()
        .rsplit(' ')
        .next()
        .unwrap()
        .to_string();
    let keys = lines(data_dir, Command::KeyLs(pb::KeyLs {})).await;
    assert_eq!(keys.lines().count(), 3, "{keys}");
    assert_eq!(keys.matches("active").count(), 1, "{keys}");
    let old_key = daemon.node.node_id().to_z32();
    says(
        data_dir,
        Command::KeyActivate(pb::KeyActivate {
            key: new_key.clone(),
            bind: None,
        }),
        &new_key,
    )
    .await;
    assert_eq!(daemon.node.node_id().to_z32(), new_key);
    assert_eq!(daemon.node.retiring_endpoints().len(), 1);
    says(
        data_dir,
        Command::KeyRetire(pb::KeyRetire {
            key: old_key.clone(),
        }),
        "secret deleted",
    )
    .await;
    assert!(daemon.node.retiring_endpoints().is_empty());
    // One key again, plus the nobody-to-ask line (§3.4).
    let keys = says(
        data_dir,
        Command::KeyLs(pb::KeyLs {}),
        "no trusted peers to ask",
    )
    .await;
    assert_eq!(keys.lines().count(), 2, "{keys}");

    // Cloud attach. These read and write `config` like every other command,
    // so they belong here: on a runtime worker a store read trips
    // `assert_off_runtime` and takes the whole daemon down (§10).
    says(
        data_dir,
        Command::CloudStatus(pb::CloudStatus {}),
        "cloud: enabled",
    )
    .await;
    says(
        data_dir,
        Command::CloudDisable(pb::CloudDisable {}),
        "disabled",
    )
    .await;
    says(
        data_dir,
        Command::CloudStatus(pb::CloudStatus {}),
        "opted out",
    )
    .await;
    says(data_dir, Command::CloudEnable(pb::CloudEnable {}), "media").await;

    // Removing the space unpublishes its entries.
    says(
        data_dir,
        Command::SpaceRm(pb::SpaceRm { id: "media".into() }),
        "unpublished",
    )
    .await;

    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errors_cross_the_socket_with_their_code() {
    // Daemon-side failures cross the socket with their code — NotFound vs
    // Invalid vs Unavailable — never as a transport error.
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    // A trusted peer with no address fails its dial immediately, which keeps
    // the SyncNow row below fast; the exit contract is the same as a timeout.
    lines(
        data_dir,
        trust_add(&SecretKey::generate().public().to_z32(), None, None),
    )
    .await;

    // Silence is reserved for "exists but empty": an unknown space, an
    // unknown origin, a path nothing publishes, and a ghost space each say
    // so instead of printing nothing and exiting 0.
    let cases: &[(Command, ErrorCode)] = &[
        (
            cat("nas@cluster.example:media/absent.txt", None, None),
            ErrorCode::NotFound,
        ),
        (ls("nospace"), ErrorCode::NotFound),
        (ls("stranger@cluster.example:media"), ErrorCode::NotFound),
        (
            Command::Status(pb::Status {
                reference: Some("media/gone.txt".into()),
            }),
            ErrorCode::NotFound,
        ),
        (
            Command::SpaceRm(pb::SpaceRm { id: "ghost".into() }),
            ErrorCode::NotFound,
        ),
        (
            Command::MirrorRm(pb::MirrorRm {
                path: "/no/such/mirror".into(),
            }),
            ErrorCode::NotFound,
        ),
        (
            Command::KeyActivate(pb::KeyActivate {
                key: SecretKey::generate().public().to_z32(),
                bind: None,
            }),
            ErrorCode::NotFound,
        ),
        // A key-identified origin has no name to rebind, and `take` of our
        // own entry is a mistake rather than a not-found.
        (
            cat(
                "nas@cluster.example:media/pinned.txt",
                None,
                Some("laptop@cluster.example"),
            ),
            ErrorCode::Invalid,
        ),
        (
            Command::PinAdd(pb::PinAdd {
                target: "not-hex".into(),
            }),
            ErrorCode::Invalid,
        ),
        (trust_add("not-a-key", None, None), ErrorCode::Invalid),
        (
            Command::Take(pb::Take {
                reference: "nas@cluster.example:media/a.txt".into(),
            }),
            ErrorCode::Invalid,
        ),
        // Reaching zero of one peer is a failure, with the per-peer lines
        // still streaming out before the error frame lands.
        (Command::SyncNow(pb::SyncNow {}), ErrorCode::Unavailable),
    ];
    for (command, code) in cases {
        assert_eq!(failure(data_dir, command.clone()).await, *code);
    }

    daemon.shutdown().await;
}

/// `synch recover` over the socket: the quiesce reports each round as it
/// goes, and the node it ran on can publish again (§3.4, §9.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recover_streams_its_quiesce_and_lifts_the_publishing_floor() {
    // A node that has never published is the point: a scan that published
    // seq 1 would own a head and settle the question before the peer's
    // advertisement arrives (§3.4).
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    let space = space_with(&[("notes.txt", b"hello")]);
    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;

    // A peer has advertised a head for this node's own origin at seq 100 —
    // the observation an ordinary `Hello` exchange leaves behind (§5.1).
    {
        let node = daemon.node.clone();
        off_runtime(move || {
            node.store().record_observed_head(
                node.origin(),
                100,
                &synch_core::Hash([7u8; 32]),
                true,
                None,
                synch_core::now_ns(),
            )
        })
        .await
        .unwrap();
    }

    // Scanning refuses before hashing anything, and says what to run. The
    // node is not broken and the request is not malformed — the state it
    // was made in is what is wrong — so the code says "unavailable" (§3.4).
    let error = failure_message(data_dir, Command::Scan(pb::Scan {})).await;
    assert_eq!(error.code, ErrorCode::Unavailable, "{error:?}");
    assert!(error.message.contains("synch recover"), "{error:?}");
    assert!(error.message.contains("seq 100"), "{error:?}");

    // Doctor says the same thing in its own words.
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor { rebuild: false })).await;
    assert!(doctor.contains("KEY-LOSS RECOVERY"), "{doctor}");
    assert!(doctor.contains("seq 100"), "{doctor}");

    let all = frames(data_dir, recover(Some("0"), Some(5)))
        .await
        .expect("recover should run");
    let progress: Vec<String> = all
        .iter()
        .filter_map(|f| match f {
            Frame::Progress(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(progress.len(), 1, "{progress:?}");
    assert!(progress[0].contains("round 1"), "{progress:?}");
    assert!(progress[0].contains("highest seq seen 100"), "{progress:?}");
    let text = all
        .iter()
        .filter_map(|f| match f {
            Frame::Line(text) => Some(text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("is in recovery"), "{text}");
    assert!(text.contains("publishing resumes at seq 105"), "{text}");

    // And the node publishes again, above everything that was advertised.
    let scan = lines(data_dir, Command::Scan(pb::Scan {})).await;
    assert!(scan.contains("published seq 105"), "{scan}");
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor { rebuild: false })).await;
    assert!(!doctor.contains("KEY-LOSS RECOVERY"), "{doctor}");

    // A duration this program cannot read fails before any waiting happens.
    let error = failure_message(data_dir, recover(Some("whenever"), None)).await;
    assert_eq!(error.code, ErrorCode::Invalid);
    assert!(error.message.contains("--wait"), "{error:?}");

    daemon.shutdown().await;
}

/// A client that walks away mid-quiesce leaves nothing behind: the daemon
/// keeps serving, and the publishing floor is untouched (§3.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_hangs_up_mid_quiesce_leaves_the_floor_alone() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    {
        let node = daemon.node.clone();
        off_runtime(move || {
            node.store().record_observed_head(
                node.origin(),
                100,
                &synch_core::Hash([7u8; 32]),
                true,
                None,
                synch_core::now_ns(),
            )
        })
        .await
        .unwrap();
    }

    // An hour-long quiesce, abandoned as soon as it has said something.
    let mut client = Client::connect(data_dir).await.unwrap();
    let mut frames = client.run(recover(Some("1h"), None)).await.unwrap();
    let first = tokio::time::timeout(std::time::Duration::from_secs(30), frames.next())
        .await
        .expect("the quiesce must report as it goes")
        .unwrap()
        .unwrap();
    assert!(matches!(first, Frame::Line(_) | Frame::Progress(_)));
    drop(frames);
    drop(client);

    // The daemon is still there, and nothing was half-applied.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let id = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        lines(data_dir, Command::Id(pb::Id {})),
    )
    .await
    .expect("the daemon must keep serving");
    assert!(id.contains("nas@cluster.example"), "{id}");
    let node = daemon.node.clone();
    let (floor, state) = off_runtime(move || {
        (
            node.store().publish_floor().unwrap(),
            node.recovery_state().unwrap(),
        )
    })
    .await;
    assert_eq!(floor, None);
    assert!(state.in_recovery);

    daemon.shutdown().await;
}

/// A multi-megabyte read must arrive as a sequence of bounded chunks, not as
/// one buffered payload (§9.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_multi_megabyte_cat_streams_in_chunks() {
    let size = 5 * 1024 * 1024 + 12_345;
    let payload: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let (dir, daemon, _space, _scan) = daemon_with_space(&[("big.bin", &payload)]).await;
    let data_dir = dir.path();

    let mut client = Client::connect(data_dir).await.unwrap();
    let mut frames = client.run(cat("media/big.bin", None, None)).await.unwrap();

    let mut chunks = 0usize;
    let mut received: Vec<u8> = Vec::new();
    let mut delivered_before_the_end = 0usize;
    while let Some(frame) = frames.next().await.unwrap() {
        match frame {
            Frame::Chunk(bytes) => {
                assert!(
                    !bytes.is_empty() && bytes.len() <= CHUNK_SIZE,
                    "a chunk of {} bytes",
                    bytes.len()
                );
                chunks += 1;
                // Bytes are usable as they arrive: at the first chunk the
                // daemon has sent a fraction of the object, not all of it.
                if chunks == 1 {
                    delivered_before_the_end = bytes.len();
                }
                received.extend_from_slice(&bytes);
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }

    assert_eq!(received, payload);
    assert_eq!(chunks, payload.len().div_ceil(CHUNK_SIZE));
    assert!(chunks >= 20, "{chunks} chunks for a 5 MiB object");
    assert!(
        delivered_before_the_end < payload.len() / 10,
        "the first chunk carried {delivered_before_the_end} of {} bytes",
        payload.len()
    );

    daemon.shutdown().await;
}

/// The structured requests §9.4 gives the gateway: a listing and a resolve
/// that answer in entry metadata rather than in rendered lines, and that
/// name space, path, and policy as fields — an S3 key may contain a colon,
/// which the text reference form would read as an origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tree_can_be_listed_and_resolved_structurally() {
    // A colon is fine in an S3 key and in this protocol, but not in a
    // Windows file name — writing `odd:key.txt` there creates an alternate
    // data stream on a file called `odd`. The colon-bearing case can only
    // be scanned out of a space where the filesystem can hold it.
    #[cfg(not(windows))]
    let files: &[(&str, &[u8])] = &[
        ("notes.txt", b"hello"),
        ("talks/a.txt", b"talk"),
        ("odd:key.txt", b"colon"),
    ];
    #[cfg(windows)]
    let files: &[(&str, &[u8])] = &[("notes.txt", b"hello"), ("talks/a.txt", b"talk")];
    let (dir, daemon, _space, _scan) = daemon_with_space(files).await;
    let data_dir = dir.path();

    let listed = entries(data_dir, list_req("media", "", None)).await;
    let paths: Vec<&str> = listed.iter().map(|e| e.path.as_str()).collect();
    #[cfg(not(windows))]
    assert!(paths.contains(&"odd:key.txt"), "{paths:?}");
    let notes = listed.iter().find(|e| e.path == "notes.txt").unwrap();
    assert_eq!(notes.size, 5);
    assert_eq!(notes.versions, 1);
    assert_eq!(notes.content, Some(synch_core::Hash::new(b"hello")));
    assert_eq!(notes.origin, "nas@cluster.example");

    // The cursor is exclusive: it resumes past a path.
    let listed = entries(data_dir, list_req("media", "", Some("notes.txt"))).await;
    assert!(
        listed.iter().all(|e| e.path != "notes.txt"),
        "the cursor is exclusive: {listed:?}"
    );

    // A key with a colon in it resolves and reads, which is the whole point
    // of the structured form.
    #[cfg(not(windows))]
    {
        let resolved = resolve(data_dir, resolve_req("media", "odd:key.txt"))
            .await
            .unwrap();
        assert_eq!(resolved.size, 5);
        let payload = tree_read(data_dir, read_req("media", "odd:key.txt", 1, Some(3)))
            .await
            .unwrap();
        assert_eq!(payload, b"olo");
    }

    assert_eq!(
        resolve(data_dir, resolve_req("media", "absent.txt"))
            .await
            .unwrap_err(),
        ErrorCode::NotFound
    );

    daemon.shutdown().await;
}

/// `synch compare` reports which files differ between the local node and a
/// peer, name-status only, over the control socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compare_reports_name_status_between_the_local_node_and_a_peer() {
    // The local node publishes these under its own origin (nas@cluster.example).
    let (dir, daemon, _space, _scan) = daemon_with_space(&[
        ("keep.txt", b"same"),
        ("changed.txt", b"ours"),
        ("only_local.txt", b"here"),
    ])
    .await;
    let data_dir = dir.path();

    // A peer publishes: keep.txt identical, changed.txt with other bytes,
    // and a file the local node does not have.
    let peer = OriginId::named("laptop", "cluster.example").unwrap();
    for (path, bytes) in [
        ("keep.txt", &b"same"[..]),
        ("changed.txt", &b"theirs"[..]),
        ("only_peer.txt", &b"new"[..]),
    ] {
        daemon.peer_file(&peer, "media", path, bytes, 1, 1).await;
    }

    // Default baseline is the local node; --to names the peer.
    let text = lines(
        data_dir,
        Command::Compare(pb::Compare {
            reference: "media".into(),
            from: None,
            to: "laptop@cluster.example".into(),
            json: false,
        }),
    )
    .await;
    assert!(text.contains("M  changed.txt"), "{text}");
    assert!(text.contains("A  only_peer.txt"), "{text}");
    assert!(text.contains("D  only_local.txt"), "{text}");
    assert!(
        !text.contains("keep.txt"),
        "identical file must not appear:\n{text}"
    );
    assert!(
        text.contains("1 created \u{00b7} 1 modified \u{00b7} 1 deleted"),
        "{text}"
    );

    // An unknown target origin is refused rather than reported as a full
    // delete.
    assert_eq!(
        failure(
            data_dir,
            Command::Compare(pb::Compare {
                reference: "media".into(),
                from: None,
                to: "ghost@cluster.example".into(),
                json: false
            })
        )
        .await,
        ErrorCode::NotFound
    );

    daemon.shutdown().await;
}

/// A streamed write crosses the socket a chunk at a time, lands in the
/// space, and commits with its staging file gone (§9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_put_publishes_without_buffering_the_object() {
    let (dir, daemon, space, _scan) = daemon_with_space(&[]).await;
    let data_dir = dir.path();

    let payload: Vec<u8> = (0..1_500_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut client = Client::connect(data_dir).await.unwrap();
    // The call returns once the daemon has taken its gates, which is what
    // tells the client the payload is wanted.
    let mut put = client.put("media", "uploads/report.bin").await.unwrap();
    for piece in payload.chunks(CHUNK_SIZE) {
        put.chunk(piece.to_vec()).await.unwrap();
    }
    let written = put.finish().await.unwrap();

    assert!(written.path.ends_with("report.bin"), "{}", written.path);
    assert_eq!(written.entry.size, payload.len() as u64);
    assert_eq!(written.entry.content, Some(synch_core::Hash::new(&payload)));
    assert_eq!(written.entry.origin, "nas@cluster.example");
    assert_eq!(
        std::fs::read(space.path().join("uploads/report.bin")).unwrap(),
        payload
    );
    // The staging file went away with the commit: nothing else is left.
    let left: Vec<String> = std::fs::read_dir(space.path().join("uploads"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["report.bin".to_string()]);

    daemon.shutdown().await;
}

/// A write is published only when the client says so. A handle that goes
/// out of scope — an early `?`, a cancelled future, a process that died —
/// or an explicit abort must leave the space exactly as it was, however
/// much of the payload arrived (§9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_write_publishes_nothing() {
    let (dir, daemon, space, _scan) = daemon_with_space(&[("kept.txt", b"kept")]).await;
    let data_dir = dir.path();

    // An explicit abort is refused with the same outcome.
    let mut client = Client::connect(data_dir).await.unwrap();
    let mut put = client.put("media", "kept.txt").await.unwrap();
    put.chunk(b"half an object".to_vec()).await.unwrap();
    let error = put.abort("the body was truncated").await;
    assert_eq!(error.code, ErrorCode::Invalid);
    assert!(error.message.contains("abandoned"), "{error}");
    assert_eq!(
        std::fs::read(space.path().join("kept.txt")).unwrap(),
        b"kept"
    );
    let left: Vec<String> = std::fs::read_dir(space.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        left,
        vec!["kept.txt".to_string()],
        "no staging file remains"
    );

    // A handle that goes out of scope — an early `?`, a cancelled future, a
    // process that died — leaves the space exactly as it was, however much
    // of the payload arrived (§9.4).
    {
        let mut client = Client::connect(data_dir).await.unwrap();
        let mut put = client.put("media", "uploads/half.bin").await.unwrap();
        for _ in 0..4 {
            put.chunk(vec![7u8; 200_000]).await.unwrap();
        }
        // No `finish`, no `abort`: just gone.
    }

    // No entry was published...
    assert_eq!(
        resolve(data_dir, resolve_req("media", "uploads/half.bin"))
            .await
            .unwrap_err(),
        ErrorCode::NotFound
    );
    // ...and the staging file goes on the daemon's own schedule, so this
    // waits for it to go rather than assuming it has already gone: what the
    // test is about is that nothing is *left*, not when the sweep happens.
    let staging = space.path().join("uploads");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let left = loop {
        let mut left: Vec<String> = std::fs::read_dir(&staging)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        if left.is_empty() || std::time::Instant::now() > deadline {
            break left;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(left.is_empty(), "no staging file remains: {left:?}");
    assert_eq!(
        std::fs::read(space.path().join("kept.txt")).unwrap(),
        b"kept"
    );

    daemon.shutdown().await;
}

/// The gateway's configuration is the daemon's to hold: appended a record at
/// a time, and fenced to the `s3.*` namespace so a socket client cannot
/// read one config row to reach another (§9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_config_appends_within_its_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    assert!(config(data_dir, "s3.buckets").await.unwrap().is_empty());
    for record in ["photos\tmedia\tnewest", "docs\tpapers\tstrict"] {
        append_config(data_dir, "s3.buckets", record).await.unwrap();
    }
    assert_eq!(
        config(data_dir, "s3.buckets").await.unwrap(),
        vec!["photos\tmedia\tnewest", "docs\tpapers\tstrict"],
        "records arrive in the order they were appended"
    );

    // Nothing outside the namespace is reachable, in either direction.
    for key in ["self_origin_id", "schema_version", "s3", "s3."] {
        assert_eq!(
            config(data_dir, key).await.unwrap_err(),
            ErrorCode::Invalid,
            "{key} must not be readable"
        );
        assert_eq!(
            append_config(data_dir, key, "x").await.unwrap_err(),
            ErrorCode::Invalid,
            "{key} must not be writable"
        );
    }
    let node = daemon.node.clone();
    let stored = off_runtime(move || node.store().config("self_origin_id").unwrap().unwrap()).await;
    assert_eq!(stored, "nas@cluster.example");

    // A record is one line: a newline would forge a second record.
    assert_eq!(
        append_config(data_dir, "s3.keys", "id\tsecret\nsmuggled\tin")
            .await
            .unwrap_err(),
        ErrorCode::Invalid
    );

    daemon.shutdown().await;
}

/// The version and the token are checked on every call, not once per
/// connection: forged or truncated tokens are refused with Unauthorized, a
/// version mismatch names both versions, and the real token still serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_token_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    for token in [vec![0u8; 32], vec![1u8; 8]] {
        let client = Client::connect_with_token(dir.path(), token).await.unwrap();
        let error = admitted(client)
            .await
            .expect_err("a forged or truncated token must not be served");
        assert_eq!(error.code, ErrorCode::Unauthorized);
        assert!(error.message.contains("control.token"), "{error}");
    }

    let client = Client::connect_as(dir.path(), CONTROL_VERSION + 7)
        .await
        .unwrap();
    let error = admitted(client)
        .await
        .expect_err("a different protocol version must not be served");
    assert_eq!(error.code, ErrorCode::VersionMismatch);
    assert!(
        error.message.contains(&format!("v{}", CONTROL_VERSION + 7)),
        "{error}"
    );
    assert!(
        error.message.contains(&format!("v{CONTROL_VERSION}")),
        "{error}"
    );

    // The real token still works; every daemon start mints a new one, so a
    // client holding the previous run's token is refused rather than
    // silently accepted.
    admitted(Client::connect(dir.path()).await.unwrap())
        .await
        .unwrap();
    let first = synch_cli::control::transport::read_token(dir.path()).unwrap();
    daemon.shutdown().await;
    let daemon = Daemon::reopen(dir.path()).await;
    let second = synch_cli::control::transport::read_token(dir.path()).unwrap();
    assert_ne!(first, second);
    let client = Client::connect_with_token(dir.path(), first).await.unwrap();
    let error = admitted(client)
        .await
        .expect_err("the previous run's token is worthless");
    assert_eq!(error.code, ErrorCode::Unauthorized);

    daemon.shutdown().await;
}

/// A daemon that was killed leaves its socket file behind; the next one must
/// notice that nothing answers it and take the address over.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_socket_is_cleared_on_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    off_runtime(move || {
        Node::init_named_by_zone(&path, OriginId::named("nas", "cluster.example").unwrap())
    })
    .await
    .unwrap();

    // What a killed daemon leaves: a bound socket file with nothing listening.
    let path = synch_cli::control::transport::socket_path(dir.path());
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    drop(listener);
    assert!(path.exists(), "the stale socket file is still there");
    assert!(tokio::net::UnixStream::connect(&path).await.is_err());

    let daemon = Daemon::reopen(dir.path()).await;
    assert!(lines(dir.path(), Command::Id(pb::Id {}))
        .await
        .contains("nas@cluster.example"));
    daemon.shutdown().await;
}

/// A call in flight must not be able to hold the daemon up: `synch recover`
/// waits an hour by default, and the operator who asked the daemon to stop
/// is not agreeing to wait it out (§9.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_call_does_not_hold_the_shutdown_open() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    // An hour-long quiesce, still running when the stop arrives.
    let mut client = Client::connect(data_dir).await.unwrap();
    let mut frames = client.run(recover(Some("1h"), None)).await.unwrap();
    let first = tokio::time::timeout(std::time::Duration::from_secs(30), frames.next())
        .await
        .expect("the quiesce reports as it goes")
        .unwrap()
        .unwrap();
    assert!(matches!(first, Frame::Line(_) | Frame::Progress(_)));

    let _ = daemon.stop.send(());
    tokio::time::timeout(std::time::Duration::from_secs(30), daemon.served)
        .await
        .expect("the server must come down while a call is still running")
        .unwrap()
        .unwrap();

    // The client is told why its call ended, rather than left holding a
    // connection to a daemon that is gone.
    let ended = loop {
        match frames.next().await {
            Ok(Some(_)) => {}
            Ok(None) => panic!("an interrupted call must not report success"),
            Err(e) => break e,
        }
    };
    assert_eq!(ended.code, ErrorCode::Unavailable, "{ended}");

    // And the datadir is left clean, so the next daemon starts from nothing.
    // Only Unix leaves a socket on disk; the token goes with the process.
    #[cfg(unix)]
    assert!(!synch_cli::control::transport::socket_path(data_dir).exists());
    assert!(!synch_cli::control::transport::token_path(data_dir).exists());
    daemon.node.shutdown().await.unwrap();
}

/// The token must not outlive the socket: while `control.token` is readable,
/// this datadir's socket is still bound, so a replacement daemon is refused
/// rather than allowed to mint a token the outgoing one then deletes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_daemon_is_refused_until_the_last_of_the_old_one_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    // While the old daemon is up, binding a second one for the datadir
    // fails — and its token is still the one a client would present.
    let taken = Server::bind(daemon.node.clone(), broadcast::channel(1).0)
        .await
        .expect_err("a second daemon for one datadir is refused");
    assert_eq!(taken.kind(), std::io::ErrorKind::AddrInUse, "{taken}");
    assert!(synch_cli::control::transport::token_path(data_dir).exists());

    daemon.shutdown().await;

    // Once it has finished, both are gone together and the next daemon binds.
    #[cfg(unix)]
    assert!(!synch_cli::control::transport::socket_path(data_dir).exists());
    assert!(!synch_cli::control::transport::token_path(data_dir).exists());
    let replacement = Daemon::reopen(data_dir).await;
    assert!(lines(data_dir, Command::Id(pb::Id {}))
        .await
        .contains("nas@cluster.example"));
    replacement.shutdown().await;
}

/// §8: `synch take` of a tombstone version deletes our local copy and
/// publishes our own tombstone. The live form is unchanged, which the same
/// test checks first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn take_adopts_a_peers_deletion_over_the_socket() {
    let (dir, daemon, space, _scan) =
        daemon_with_space(&[("shared.txt", b"ours"), ("kept.txt", b"ours")]).await;
    let data_dir = dir.path();

    let peer = OriginId::named("laptop", "cluster.example").unwrap();
    // The peer publishes a live version of `kept.txt` with the same bytes we
    // could fetch locally, and a tombstone for `shared.txt`.
    daemon
        .peer_file(&peer, "media", "kept.txt", b"theirs", 9_000, 4)
        .await;
    daemon
        .peer_entry(
            &peer,
            "media",
            "shared.txt",
            synch_core::FileEntry::tombstone(9_000, 4, None),
        )
        .await;

    // Taking a live version still works exactly as it did.
    let taken = lines(
        data_dir,
        Command::Take(pb::Take {
            reference: "laptop@cluster.example:media/kept.txt".into(),
        }),
    )
    .await;
    assert!(taken.contains("adopted into"), "{taken}");
    assert_eq!(
        std::fs::read(space.path().join("kept.txt")).unwrap(),
        b"theirs"
    );

    // Taking a deletion removes our copy and publishes our own tombstone.
    let taken = lines(
        data_dir,
        Command::Take(pb::Take {
            reference: "laptop@cluster.example:media/shared.txt".into(),
        }),
    )
    .await;
    assert!(taken.contains("removed"), "{taken}");
    assert!(taken.contains("published seq"), "{taken}");
    assert!(!space.path().join("shared.txt").exists());

    daemon.shutdown().await;
}

/// A daemon stops while its startup work is stalled on a peer.
///
/// The initial scan publishes and pushes, which reaches out to every peer
/// this node knows. A peer that completes the handshake and then answers
/// nothing holds that push for the whole request deadline, and the stop
/// signal has to be heard during it: an operator asking a daemon to stop
/// must not be told to wait on a stranger.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_stops_while_its_first_scan_is_stalled_on_a_peer() {
    let dir = tempfile::tempdir().unwrap();
    let space = space_with(&[("notes.txt", b"hello")]);

    // A peer that accepts the session and answers nothing.
    let silent = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(SecretKey::generate())
        .relay_mode(iroh::endpoint::RelayMode::Disabled)
        .clear_address_lookup()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .alpns(vec![synch_core::ALPN_MPT.to_vec()])
        .bind()
        .await
        .unwrap();
    let silent_addr = iroh::EndpointAddr::from_parts(
        silent.id(),
        silent
            .bound_sockets()
            .into_iter()
            .map(iroh::TransportAddr::Ip),
    );
    let listening = silent.clone();
    let accepting = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(incoming) = listening.accept().await {
            if let Ok(connection) = incoming.await {
                held.push(connection);
            }
        }
    });

    // A space with something to publish, and the silent peer trusted and
    // addressed, so the initial scan produces a head and pushes it there.
    let path = dir.path().to_path_buf();
    off_runtime(move || {
        Node::init_named_by_zone(&path, OriginId::named("nas", "cluster.example").unwrap())
    })
    .await
    .unwrap();
    {
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        let seeding = node.clone();
        let space_path = space.path().to_path_buf();
        let (peer_id, peer_addr) = (silent.id(), silent_addr.clone());
        off_runtime(move || {
            seeding.add_space("s", &space_path).unwrap();
            seeding
                .store()
                .put_binding(&synch_store::Binding {
                    origin: OriginId::named("silent", "cluster.example").unwrap(),
                    node_id: peer_id,
                    source: synch_store::BindingSource::Static,
                    domain: None,
                    issuer: None,
                    spaces: Vec::new(),
                    note: None,
                    added_at: 0,
                    expires_at: None,
                })
                .unwrap();
            seeding
                .store()
                .record_peer_seen(
                    &peer_id,
                    Some(&synch_engine::node::encode_addr(&peer_addr)),
                    synch_core::now_ns(),
                )
                .unwrap();
        })
        .await;
        node.shutdown().await.unwrap();
    }

    // Long enough that only the initial scan pushes anything during the test.
    let mut config = NodeConfig::loopback(dir.path());
    config.publish_quiesce = std::time::Duration::from_secs(300);
    let running = tokio::spawn(synch_cli::daemon::run(config));

    // Wait for the control socket, then ask the daemon to stop.
    let mut client = loop {
        match Client::connect(dir.path()).await {
            Ok(client) => break client,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    };
    let mut frames = client
        .run(Command::DaemonStop(pb::DaemonStop {}))
        .await
        .unwrap();
    while let Ok(Some(_)) = frames.next().await {}
    // The daemon sends the stop once its answer has been delivered.
    drop(frames);
    drop(client);

    tokio::time::timeout(std::time::Duration::from_secs(30), running)
        .await
        .expect("the daemon must stop while its initial scan is stalled")
        .expect("the daemon task did not panic")
        .unwrap();

    accepting.abort();
    silent.close().await;
}

/// Every trust knob is settable by environment variable, so which trust a
/// daemon enforces is not visible from its command line: `daemon status` and
/// `doctor` are what distinguish a `require` daemon from a `--rekor off`
/// one, and a resolver that cannot be built refreshes no membership at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_trust_configuration_and_the_resolver_state_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    // No resolver in this process at all: the state is named, not implied.
    let status = lines(data_dir, Command::DaemonStatus(pb::DaemonStatus {})).await;
    assert!(
        status.contains("trust: no membership resolver in this process"),
        "{status}"
    );

    daemon.node.set_dns_resolver(Err(
        "trust anchor /nope: no DNSKEY records in the file".into()
    ));
    let status = lines(data_dir, Command::DaemonStatus(pb::DaemonStatus {})).await;
    assert!(status.contains("NO RESOLVER"), "{status}");
    assert!(status.contains("membership cannot refresh"), "{status}");
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor { rebuild: false })).await;
    assert!(doctor.contains("no DNSKEY records"), "{doctor}");

    // A refresh asked for over the socket uses the daemon's resolver and
    // refuses when there is none, rather than building a fresh one per
    // request.
    {
        let node = daemon.node.clone();
        off_runtime(move || node.set_domain("cluster.example"))
            .await
            .unwrap();
    }
    let code = failure(data_dir, Command::DomainRefresh(pb::DomainRefresh {})).await;
    assert_eq!(code, ErrorCode::Unavailable);

    // With one installed, the whole effective policy is on the page.
    let resolver = std::sync::Arc::new(synch_net::DnssecResolver::with_defaults().unwrap());
    daemon.node.set_dns_resolver(Ok(resolver.clone()));
    let status = lines(data_dir, Command::DaemonStatus(pb::DaemonStatus {})).await;
    assert!(status.contains("rekor require"), "{status}");
    assert!(status.contains("anchor icann-root"), "{status}");
    assert!(status.contains("log key(s) pinned"), "{status}");
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor { rebuild: false })).await;
    assert!(doctor.contains("log key "), "{doctor}");
    assert!(doctor.contains("clock: usable"), "{doctor}");

    // And it is *one* resolver: the TUF walk's "once a day even when the
    // repository is down" bound lives in the resolver, so a per-request one
    // would re-walk on every command.
    assert!(std::sync::Arc::ptr_eq(
        &resolver,
        &daemon.node.dns_resolver().unwrap()
    ));
    daemon.shutdown().await;
}
