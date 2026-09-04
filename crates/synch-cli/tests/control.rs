//! Control round-trips against an in-process daemon: the same `Server`,
//! transport, and service the real binary serves, without a process spawn
//! per command (§11). `tests/cli.rs` keeps the end-to-end binary check.

use std::path::Path;

use iroh_base::SecretKey;
use synch_cli::control::{
    proto::{pb, CHUNK_SIZE, CONTROL_VERSION},
    Client, Command, ControlError, EntryInfo, ErrorCode, Frame, Server,
};
use synch_core::OriginId;
use synch_engine::{Node, NodeConfig};
use tokio::sync::broadcast;

/// Runs store work off the runtime, as production does (§10).
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

    /// Records a file as another origin published it, the way a sync would have.
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

/// A peer advertised a head for our origin the node has no history for — the
/// observation that puts a node into key-loss recovery (§3.4, §5.1).
async fn observed_head(node: &Node, seq: u64) {
    let node = node.clone();
    off_runtime(move || {
        node.store().record_observed_head(
            node.origin(),
            seq,
            &synch_core::Hash([7u8; 32]),
            true,
            None,
            synch_core::now_ns(),
        )
    })
    .await
    .unwrap();
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

/// Runs the cheapest command there is: version and token are checked on
/// every call, so this is what a credential is admitted or refused by.
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

/// A fresh daemon with a filesystem source added and scanned.
async fn daemon_with_space(
    files: &[(&str, &[u8])],
) -> (tempfile::TempDir, Daemon, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let space = space_with(files);
    let data_dir = dir.path();
    lines(
        data_dir,
        source_add("media", &space.path().to_string_lossy()),
    )
    .await;
    let scan = lines(data_dir, source_scan()).await;
    (dir, daemon, space, scan)
}

/// Runs a command and asserts its output contains `needle`.
async fn says(data_dir: &Path, command: Command, needle: &str) -> String {
    let out = lines(data_dir, command).await;
    assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
    out
}

/// The most common command shapes, so the sweep reads as one call per command.
fn cat(reference: &str, range: Option<&str>, origin: Option<&str>) -> Command {
    Command::Cat(pb::Cat {
        reference: reference.into(),
        range: range.map(String::from),
        root: None,
        select: origin.map(|origin| format!("origin={origin}")),
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

// The rest of the command surface, one helper per variant.
fn id() -> Command {
    Command::Id(pb::Id {})
}
fn key_ls() -> Command {
    Command::KeyLs(pb::KeyLs {})
}
fn source_ls() -> Command {
    Command::SourceLs(pb::SourceLs {
        space: String::new(),
    })
}
fn source_scan() -> Command {
    Command::SourceScan(pb::SourceScan {
        space: String::new(),
    })
}
fn peer_sync() -> Command {
    Command::PeerSync(pb::PeerSync {})
}
fn trust_ls() -> Command {
    Command::TrustLs(pb::TrustLs {})
}
fn peer_ls() -> Command {
    Command::PeerLs(pb::PeerLs {})
}
fn status(reference: Option<&str>) -> Command {
    Command::Status(pb::Status {
        reference: reference.map(String::from),
    })
}
fn log(reference: &str) -> Command {
    Command::Log(pb::Log {
        reference: reference.into(),
    })
}
fn domain_set(domain: &str) -> Command {
    Command::DomainSet(pb::DomainSet {
        domain: domain.into(),
        delegate: false,
    })
}

fn domain_set_delegate(domain: &str) -> Command {
    Command::DomainSet(pb::DomainSet {
        domain: domain.into(),
        delegate: true,
    })
}
fn domain_ls() -> Command {
    Command::DomainLs(pb::DomainLs {})
}
fn domain_refresh() -> Command {
    Command::DomainRefresh(pb::DomainRefresh {})
}
fn domain_clear() -> Command {
    Command::DomainClear(pb::DomainClear {})
}
fn adopt_tree(reference: &str, origin: Option<&str>, replace: bool, dry_run: bool) -> Command {
    Command::AdoptTree(pb::AdoptTree {
        reference: reference.into(),
        select: origin.map(|origin| format!("origin={origin}")),
        replace,
        dry_run,
    })
}
fn replica_with_checkout_add(space: &str, path: &str, policy: Option<&str>) -> Command {
    Command::ReplicaAdd(pb::ReplicaAdd {
        space: space.into(),
        retention: policy.unwrap_or("current").into(),
        grace: None,
        budget: None,
        checkout: Some(path.into()),
    })
}
fn replica_ls() -> Command {
    Command::ReplicaLs(pb::ReplicaLs {
        space: String::new(),
    })
}
fn replica_sync() -> Command {
    Command::ReplicaSync(pb::ReplicaSync {
        space: String::new(),
    })
}
fn replica_rm(path: &str) -> Command {
    Command::ReplicaRm(pb::ReplicaRm {
        space: path.into(),
        pin_held: false,
    })
}
fn pin_add(target: &str) -> Command {
    Command::PinAdd(pb::PinAdd {
        target: target.into(),
        select: None,
    })
}
fn pin_ls() -> Command {
    Command::PinLs(pb::PinLs {})
}
fn pin_rm(target: &str) -> Command {
    Command::PinRm(pb::PinRm {
        target: target.into(),
        select: None,
    })
}
fn doctor(rebuild: bool) -> Command {
    if rebuild {
        Command::RepairRebuildViews(pb::RepairRebuildViews {})
    } else {
        Command::Doctor(pb::Doctor {})
    }
}
fn daemon_status() -> Command {
    Command::DaemonStatus(pb::DaemonStatus {})
}
fn key_rotate() -> Command {
    Command::KeyRotate(pb::KeyRotate {})
}
fn key_activate(key: &str) -> Command {
    Command::KeyActivate(pb::KeyActivate {
        key: key.into(),
        bind: None,
    })
}
fn key_retire(key: &str) -> Command {
    Command::KeyRetire(pb::KeyRetire { key: key.into() })
}
fn control_plane_status() -> Command {
    Command::ControlPlaneStatus(pb::ControlPlaneStatus {})
}
fn control_plane_disable() -> Command {
    Command::ControlPlaneDisable(pb::ControlPlaneDisable {})
}
fn control_plane_enable() -> Command {
    Command::ControlPlaneEnable(pb::ControlPlaneEnable {})
}
fn replica_add(id: &str, path: &str, policy: &str, grace: i64) -> Command {
    let _ = path;
    Command::ReplicaAdd(pb::ReplicaAdd {
        space: id.into(),
        retention: policy.into(),
        grace: Some(grace),
        budget: None,
        checkout: None,
    })
}
fn replica_set(id: &str, grace: Option<i64>, budget: Option<u64>) -> Command {
    Command::ReplicaSet(pb::ReplicaSet {
        space: id.into(),
        retention: None,
        grace,
        budget,
        no_budget: false,
        checkout: None,
        no_checkout: false,
    })
}
fn replica_ls_one(id: &str) -> Command {
    Command::ReplicaLs(pb::ReplicaLs { space: id.into() })
}
fn source_add(id: &str, path: &str) -> Command {
    Command::SourceAdd(pb::SourceAdd {
        space: id.into(),
        path: path.into(),
        api: false,
    })
}
fn api_source_add(id: &str) -> Command {
    Command::SourceAdd(pb::SourceAdd {
        space: id.into(),
        path: String::new(),
        api: true,
    })
}
fn source_rm(id: &str) -> Command {
    Command::SourceRm(pb::SourceRm { space: id.into() })
}
fn adopt_path(reference: &str) -> Command {
    Command::AdoptPath(pb::AdoptPath {
        reference: reference.into(),
        select: None,
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
    // The one guard that every Command variant encodes, dispatches, and
    // answers over the socket; the rotation assertions live here too.
    let (dir, daemon, _space, _scan) =
        daemon_with_space(&[("notes.txt", b"hello"), ("talks/a.txt", b"talk")]).await;
    let data_dir = dir.path();
    let peer_key = SecretKey::generate().public().to_z32();

    // Identity and keys: one key, plus the nobody-to-ask line (§3.4).
    let id = says(data_dir, id(), "nas@cluster.example").await;
    assert!(id.contains("active"), "{id}");
    let keys = says(data_dir, key_ls(), "no trusted peers to ask").await;
    assert!(keys.contains("bound by 0 of 0 reachable peer(s)"), "{keys}");
    assert_eq!(keys.lines().count(), 2, "{keys}");
    // A manual round with nobody to run it against says so and succeeds.
    says(data_dir, peer_sync(), "no dialable peers").await;

    // Spaces, scanning, and listing. The scan streams progress as it goes (§9.3).
    says(data_dir, source_ls(), "media").await;
    let progress = progress_of(data_dir, source_scan()).await;
    assert!(
        progress.iter().any(|l| l.contains("scanned media")),
        "{progress:?}"
    );
    let ls = says(data_dir, ls("media"), "notes.txt").await;
    assert!(ls.contains("talks/a.txt"), "{ls}");
    let status = says(
        data_dir,
        status(Some("media")),
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
    says(data_dir, log("media/notes.txt"), "seq 1").await;

    // Membership. The key is the identity: static trust names nobody (§3.2).
    says(
        data_dir,
        trust_add(&peer_key, Some("a test peer"), Some("127.0.0.1:4433")),
        &peer_key,
    )
    .await;
    says(data_dir, trust_ls(), "a test peer").await;
    says(data_dir, peer_ls(), &peer_key).await;

    // Dropping one key's binding by name, then the whole origin: a
    // key-identified origin holds one binding, so both spellings are the same
    // removal, and a second attempt at either is a not-found.
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

    // Delegation, all three variants.
    let subject = SecretKey::generate().public().to_z32();
    let delegated = says(
        data_dir,
        Command::DelegateAdd(pb::DelegateAdd {
            key: subject.clone(),
            spaces: vec!["media".into()],
            until: Some("7d".into()),
            note: Some("a test laptop".into()),
        }),
        "delegated",
    )
    .await;
    // The grant names its spaces, and says what the subject will not see.
    assert!(delegated.contains("media"), "{delegated}");
    assert!(
        delegated.contains("it will not learn that any other space exists"),
        "{delegated}"
    );
    let listed = says(data_dir, Command::DelegateLs(pb::DelegateLs {}), &subject).await;
    assert!(listed.contains("this node"), "{listed}");
    says(
        data_dir,
        Command::DelegateRm(pb::DelegateRm {
            key: subject.clone(),
        }),
        "removed the delegation",
    )
    .await;
    says(
        data_dir,
        Command::DelegateLs(pb::DelegateLs {}),
        "no delegations",
    )
    .await;

    // The domain: `set` records it with no resolver here, pending the next
    // start (§3.1) — and `domain ls` says so.
    let set = says(
        data_dir,
        domain_set("cluster.example"),
        "_synchronicity.cluster.example. IN TXT",
    )
    .await;
    assert!(set.contains("synch domain clear"), "{set}");
    assert!(
        set.contains("--delegate"),
        "a member is told the other way out too: {set}"
    );

    // `--delegate` says the zone will *not* name this node, so the advice must
    // not turn round and tell the operator to publish a record for it.
    let as_delegate = says(
        data_dir,
        domain_set_delegate("cluster.example"),
        "this node is a delegate",
    )
    .await;
    assert!(
        !as_delegate.contains("must name this key"),
        "the delegate advice contradicted the flag just passed: {as_delegate}"
    );
    assert!(
        !as_delegate.contains("IN TXT"),
        "a delegate is not told to publish a record naming itself: {as_delegate}"
    );
    says(data_dir, domain_ls(), "not yet resolved by this daemon").await;
    let _ = frames(data_dir, domain_refresh()).await;
    says(data_dir, domain_clear(), "cleared").await;
    assert_eq!(
        failure(data_dir, domain_clear()).await,
        ErrorCode::NotFound,
        "there is nothing left to clear"
    );

    // Replica checkout.
    let checkout_dir = tempfile::tempdir().unwrap();
    let checkout_path = checkout_dir.path().to_string_lossy().into_owned();
    let replicating = says(
        data_dir,
        replica_with_checkout_add("media", &checkout_path, None),
        "replicating",
    )
    .await;
    assert!(replicating.contains("current"), "{replicating}");
    let replica_ls = says(data_dir, replica_ls(), "media").await;
    assert!(replica_ls.contains("checkout"), "{replica_ls}");
    let _ = frames(data_dir, replica_sync()).await.unwrap();
    says(data_dir, replica_rm("media"), "removed").await;

    // Pins, by root.
    let root = blake3::hash(b"hello").to_hex().to_string();
    says(data_dir, pin_add(&root), &root).await;
    says(data_dir, pin_ls(), &root).await;
    says(data_dir, pin_rm(&root), &root).await;
    let pins = lines(data_dir, pin_ls()).await;
    assert!(pins.contains("source:media"), "{pins}");
    assert!(!pins.contains("operator"), "{pins}");

    // Reports.
    let diag = says(data_dir, doctor(false), "origin: nas@cluster.example").await;
    assert!(diag.contains("equivocation: none detected"), "{diag}");
    let rebuilt = lines(data_dir, doctor(true)).await;
    assert!(rebuilt.contains("rebuilt"), "{rebuilt}");
    // Status is the glance, not the byte-identical twin of doctor.
    let status = says(data_dir, daemon_status(), "origin nas@cluster.example").await;
    assert!(status.contains("spaces: 1 (media)"), "{status}");
    assert!(status.contains("head: seq"), "{status}");
    assert!(!status.contains("storage:"), "{status}");

    // Rotation, end to end and operator-driven (§3.4).
    let rotate = says(data_dir, key_rotate(), "v=sync1 id=nas nk=").await;
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
    let keys = lines(data_dir, key_ls()).await;
    assert_eq!(keys.lines().count(), 3, "{keys}");
    assert_eq!(keys.matches("active").count(), 1, "{keys}");
    let old_key = daemon.node.node_id().to_z32();
    says(data_dir, key_activate(&new_key), &new_key).await;
    assert_eq!(daemon.node.node_id().to_z32(), new_key);
    says(data_dir, key_retire(&old_key), "secret deleted").await;
    // One key again, plus the nobody-to-ask line (§3.4).
    let keys = says(data_dir, key_ls(), "no trusted peers to ask").await;
    assert_eq!(keys.lines().count(), 2, "{keys}");

    // Cloud attach: config reads/writes like every other command (§10).
    says(data_dir, control_plane_status(), "control-plane: enabled").await;
    says(data_dir, control_plane_disable(), "disabled").await;
    says(data_dir, control_plane_status(), "opted out").await;
    says(data_dir, control_plane_enable(), "media").await;

    // Removing the space unpublishes its entries.
    says(data_dir, source_rm("media"), "unpublished").await;

    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errors_cross_the_socket_with_their_code() {
    // Failures cross with their code — NotFound vs Invalid vs Unavailable —
    // never as a transport error.
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    // A peer with no address fails its dial immediately, keeping PeerSync fast.
    lines(
        data_dir,
        trust_add(&SecretKey::generate().public().to_z32(), None, None),
    )
    .await;

    // An unknown space, origin, path, or ghost space each say so instead of
    // printing nothing and exiting 0.
    let cases: &[(Command, ErrorCode)] = &[
        (
            cat("nas@cluster.example:media/absent.txt", None, None),
            ErrorCode::NotFound,
        ),
        (ls("nospace"), ErrorCode::NotFound),
        (ls("stranger@cluster.example:media"), ErrorCode::NotFound),
        (status(Some("media/gone.txt")), ErrorCode::NotFound),
        (source_rm("ghost"), ErrorCode::NotFound),
        (replica_rm("/no/such/replica"), ErrorCode::NotFound),
        (
            adopt_tree("nospace", None, false, false),
            ErrorCode::NotFound,
        ),
        (
            key_activate(&SecretKey::generate().public().to_z32()),
            ErrorCode::NotFound,
        ),
        // A key-identified origin has no name to rebind. Adoption still
        // resolves the path before it can decide who published it, so an
        // absent own path is not found.
        (
            cat(
                "nas@cluster.example:media/pinned.txt",
                None,
                Some("laptop@cluster.example"),
            ),
            ErrorCode::Invalid,
        ),
        (pin_add("not-hex"), ErrorCode::Invalid),
        (trust_add("not-a-key", None, None), ErrorCode::Invalid),
        (
            adopt_path("nas@cluster.example:media/a.txt"),
            ErrorCode::NotFound,
        ),
        // Zero peers reached is a failure, the per-peer lines streaming first.
        (peer_sync(), ErrorCode::Unavailable),
    ];
    for (command, code) in cases {
        assert_eq!(
            failure(data_dir, command.clone()).await,
            *code,
            "unexpected error class for {command:?}"
        );
    }

    daemon.shutdown().await;
}

/// `synch adopt tree` over the socket (§7.2): a peer's content lands in the space
/// this node publishes from, a local file that differs is reported rather than
/// overwritten, and the adoption publishes what it placed before returning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tree_adoption_adds_a_peers_content_to_the_published_source() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    let space = space_with(&[("mine.txt", b"mine")]);
    // Backdated, so the peer's competing version below is unambiguously the
    // newer one: `newest` orders on the published mtime, and a file written
    // just now would win against any stamp a test can name.
    let ours = space.path().join("mine.txt");
    std::fs::File::options()
        .write(true)
        .open(&ours)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1)),
        )
        .unwrap();
    lines(
        data_dir,
        source_add("media", &space.path().to_string_lossy()),
    )
    .await;
    says(data_dir, source_scan(), "published seq").await;

    let peer = OriginId::named("laptop", "cluster.example").unwrap();
    daemon
        .peer_file(&peer, "media", "theirs.txt", b"theirs", 1_700_000_000, 1)
        .await;
    // The same path, published with newer bytes: the local copy is this node's
    // own assertion and an adoption leaves it standing.
    daemon
        .peer_file(&peer, "media", "mine.txt", b"not mine", 2_000_000_000, 1)
        .await;

    // The dry run decides everything and writes nothing.
    let planned = says(
        data_dir,
        adopt_tree("media", None, false, true),
        "would adopt 1",
    )
    .await;
    assert!(planned.contains("differing media/mine.txt"), "{planned}");
    assert!(!space.path().join("theirs.txt").exists(), "{planned}");

    let adopted = says(
        data_dir,
        adopt_tree("media", None, false, false),
        "adopted 1",
    )
    .await;
    assert!(adopted.contains("differing media/mine.txt"), "{adopted}");
    assert!(adopted.contains("published seq"), "{adopted}");
    assert_eq!(
        std::fs::read(space.path().join("theirs.txt")).unwrap(),
        b"theirs"
    );
    assert_eq!(
        std::fs::read(space.path().join("mine.txt")).unwrap(),
        b"mine",
        "an adoption never overwrites what is here without --replace"
    );

    // It was published before adoption returned, so it is already ours as
    // well: one version, two attestors.
    says(
        data_dir,
        status(Some("media/theirs.txt")),
        "media/theirs.txt  1 version(s)",
    )
    .await;

    // Nothing left to do, and `--replace` is what ends the standoff.
    says(
        data_dir,
        adopt_tree("media", None, false, false),
        "adopted 0",
    )
    .await;
    let forced = says(
        data_dir,
        adopt_tree("media", None, true, false),
        "adopted 1",
    )
    .await;
    assert!(forced.contains("replaced media/mine.txt"), "{forced}");
    assert_eq!(
        std::fs::read(space.path().join("mine.txt")).unwrap(),
        b"not mine"
    );

    // A strict adoption's whole answer is the paths it refused, so those reach
    // stdout with everything else: `lines()` drops progress frames, so this
    // assertion fails if they are ever demoted to progress.
    daemon
        .peer_file(&peer, "media", "split.txt", b"theirs", 2_000_000_000, 2)
        .await;
    daemon
        .peer_file(
            &OriginId::named("desktop", "cluster.example").unwrap(),
            "media",
            "split.txt",
            b"others",
            2_100_000_000,
            1,
        )
        .await;
    let strict = says(
        data_dir,
        Command::AdoptTree(pb::AdoptTree {
            reference: "media".into(),
            select: Some("strict".into()),
            replace: false,
            dry_run: false,
        }),
        "skipped media/split.txt",
    )
    .await;
    assert!(strict.contains("strict"), "{strict}");

    // A prefix that names nothing is a typo, not an empty directory.
    let typo = says(
        data_dir,
        adopt_tree("media/nosuchdir", None, false, false),
        "note: no path in media starts with nosuchdir/",
    )
    .await;
    assert!(typo.contains("adopted 0"), "{typo}");

    daemon.shutdown().await;
}

/// A streamed write is gated when it opens and again when it commits. The
/// window between is the client's to take, and a node floored by an inbound
/// `Hello` in the middle of it must not let the commit rename over a file it
/// can then publish no replacement for (§3.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_floored_mid_stream_does_not_commit() {
    // Deliberately not `daemon_with_space`: that scans, and a node holding a
    // complete head of its own is not in key-loss recovery however far ahead a
    // peer claims to be (§3.4).
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    let space = space_with(&[("kept.txt", b"kept")]);
    lines(
        data_dir,
        source_add("media", &space.path().to_string_lossy()),
    )
    .await;

    // Opened while the node is healthy: the header exchange takes its gates
    // and hands back a stream.
    let mut client = Client::connect(data_dir).await.unwrap();
    let mut put = client.put("media", "kept.txt").await.unwrap();
    put.chunk(b"theirs".to_vec()).await.unwrap();

    // A peer advertises a head for our own origin that we have no history for
    // — key-loss recovery, arriving while the body is still on the wire.
    observed_head(&daemon.node, 100).await;

    let error = put.finish().await.expect_err("the commit must be refused");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.message.contains("recover"), "{error}");
    assert_eq!(
        std::fs::read(space.path().join("kept.txt")).unwrap(),
        b"kept",
        "the file must survive a commit the node could never have published"
    );

    daemon.shutdown().await;
}

/// `synch recover` over the socket: the quiesce reports each round and the
/// node publishes again (§3.4, §9.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recover_streams_its_quiesce_and_lifts_the_publishing_floor() {
    // A node that has never published is the point: owning a head would
    // settle the question before the advertisement arrives (§3.4).
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    let space = space_with(&[("notes.txt", b"hello")]);
    lines(
        data_dir,
        source_add("media", &space.path().to_string_lossy()),
    )
    .await;

    // A peer advertised a head for our origin at seq 100 — what a `Hello`
    // exchange leaves behind (§5.1).
    observed_head(&daemon.node, 100).await;

    // Scanning refuses before hashing anything: the state, not the request,
    // is what is wrong, so the code says "unavailable" (§3.4).
    let error = failure_message(data_dir, source_scan()).await;
    assert_eq!(error.code, ErrorCode::Unavailable, "{error:?}");
    assert!(error.message.contains("synch recover"), "{error:?}");
    assert!(error.message.contains("seq 100"), "{error:?}");

    // Doctor says the same thing in its own words.
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor {})).await;
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
    let scan = lines(data_dir, source_scan()).await;
    assert!(scan.contains("published seq 105"), "{scan}");
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor {})).await;
    assert!(!doctor.contains("KEY-LOSS RECOVERY"), "{doctor}");

    daemon.shutdown().await;
}

/// In-flight recover work holds neither the daemon nor its floor: a client
/// that hangs up leaves nothing behind, and the daemon stops on request
/// even while a call is running — the operator is not told to wait out the
/// hour (§3.4, §9.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_flight_recover_work_holds_neither_the_daemon_nor_its_floor() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    observed_head(&daemon.node, 100).await;

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

    // A second quiesce, still running when the stop arrives.
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

    // The client is told why its call ended, not left holding a dead connection.
    let ended = loop {
        match frames.next().await {
            Ok(Some(_)) => {}
            Ok(None) => panic!("an interrupted call must not report success"),
            Err(e) => break e,
        }
    };
    assert_eq!(ended.code, ErrorCode::Unavailable, "{ended}");

    // The datadir is left clean. Only Unix leaves a socket on disk; the
    // token goes with the process.
    #[cfg(unix)]
    assert!(!synch_cli::control::transport::socket_path(data_dir).exists());
    assert!(!synch_cli::control::transport::token_path(data_dir).exists());
    daemon.node.shutdown().await.unwrap();
}

/// A multi-megabyte read arrives as bounded chunks, not one buffered payload (§9.3).
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
                // The first chunk is a fraction of the object, not all of it.
                if chunks == 1 {
                    delivered_before_the_end = bytes.len();
                }
                received.extend_from_slice(&bytes);
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }

    assert_eq!(received, payload);
    assert!(chunks >= 20, "{chunks} chunks for a 5 MiB object");
    assert!(
        delivered_before_the_end < payload.len() / 10,
        "the first chunk carried {delivered_before_the_end} of {} bytes",
        payload.len()
    );

    daemon.shutdown().await;
}

/// The structured requests §9.4 gives the gateway: a listing and a resolve
/// answering in entry metadata, naming space, path, and policy as fields —
/// an S3 key may contain a colon, which the text reference form reads as an
/// origin.
/// Replica configuration over the socket: what `add` says, what `ls` reports,
/// and that tuning one knob leaves the other alone.
///
/// The last of those is the one worth a test. Updating the budget must not reset
/// the grace window to its default — the whole recovery story for a deletion
/// under `current` — and say nothing about having done it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replication_is_configured_and_reported_over_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let space = space_with(&[("notes.txt", b"hello")]);
    let data_dir = dir.path();

    let added = lines(
        data_dir,
        replica_add(
            "media",
            &space.path().to_string_lossy(),
            "current",
            7 * 86400,
        ),
    )
    .await;
    assert!(
        added.contains("replicating media with current retention"),
        "{added}"
    );

    let listed = lines(data_dir, replica_ls_one("media")).await;
    assert!(listed.contains("current"), "{listed}");
    assert!(listed.contains("grace 7d"), "{listed}");

    // Tuning the budget must not touch the grace window.
    lines(data_dir, replica_set("media", None, Some(4096))).await;
    let listed = lines(data_dir, replica_ls_one("media")).await;
    assert!(
        listed.contains("grace 7d"),
        "setting a budget cleared the grace window: {listed}"
    );
    assert!(listed.contains("budget        4096 B"), "{listed}");

    // And the reverse.
    lines(data_dir, replica_set("media", Some(3600), None)).await;
    let listed = lines(data_dir, replica_ls_one("media")).await;
    assert!(listed.contains("grace 1h"), "{listed}");
    assert!(
        listed.contains("budget        4096 B"),
        "setting a grace window cleared the budget: {listed}"
    );

    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tree_can_be_listed_and_resolved_structurally() {
    // A colon is fine in a key but not in a Windows file name (alternate
    // data stream), so the colon-bearing case only runs where the
    // filesystem can hold it.
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

    // A key with a colon resolves and reads — the whole point of the form.
    #[cfg(not(windows))]
    {
        let resolved = resolve(data_dir, resolve_req("media", "odd:key.txt"))
            .await
            .unwrap();
        assert_eq!(resolved.size, 5);
        let mut client = Client::connect(data_dir).await.unwrap();
        let mut chunks = client
            .read(read_req("media", "odd:key.txt", 1, Some(3)))
            .await
            .unwrap();
        let mut payload = Vec::new();
        while let Some(bytes) = chunks.next().await.unwrap() {
            payload.extend_from_slice(&bytes);
        }
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

/// A write is published only when the client says so: a dropped handle —
/// early `?`, cancelled future, dead process — or an explicit abort leaves
/// the space as it was, however much of the payload arrived (§9.4).
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
    // waits for it: the test is that nothing is *left*, not when.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_api_source_put_publishes_from_the_cas_without_a_checkout() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    says(
        data_dir,
        api_source_add("media"),
        "publishing media through APIs",
    )
    .await;

    let mut client = Client::connect(data_dir).await.unwrap();
    let mut put = client.put("media", "nested/cloud.txt").await.unwrap();
    put.chunk(b"cloud bytes".to_vec()).await.unwrap();
    let written = put.finish().await.unwrap();
    assert_eq!(written.path, "media/nested/cloud.txt");
    assert_eq!(written.entry.size, 11);
    let root = written.entry.content.unwrap();
    let inspecting = daemon.node.clone();
    let (bytes, local_path, local_files) = synch_core::offload(move || {
        Ok::<_, synch_engine::EngineError>((
            inspecting.store().read_all(&root)?,
            inspecting.store().source("media")?.unwrap().local_path,
            inspecting.store().local_files("media")?,
        ))
    })
    .await
    .unwrap();
    assert_eq!(bytes, b"cloud bytes");
    assert_eq!(local_path, None);
    assert!(local_files.is_empty());

    let deleted = client.delete("media", "nested/cloud.txt").await.unwrap();
    assert!(!deleted.still_published);
    let inspecting = daemon.node.clone();
    let kind = synch_core::offload(move || {
        Ok::<_, synch_engine::EngineError>(
            inspecting
                .store()
                .entry(inspecting.origin(), "media", "nested/cloud.txt")?
                .unwrap()
                .kind,
        )
    })
    .await
    .unwrap();
    assert_eq!(kind, synch_core::EntryKind::Tombstone);
    daemon.shutdown().await;
}

/// A canned loopback HTTP/1.1 server for `synch fetch`: each connection is
/// answered from the route table with pre-built response bytes and closed.
async fn http_server(
    routes: Vec<(&'static str, Vec<u8>)>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes: std::collections::HashMap<&'static str, Vec<u8>> = routes.into_iter().collect();
    let served = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                let answer = routes.get(path).cloned().unwrap_or_else(|| {
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_vec()
                });
                let _ = stream.write_all(&answer).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, served)
}

fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// `synch fetch` streams a URL into the tree through the same write the S3
/// gateway uses, follows redirects, and completes a directory destination
/// with the file name the *final* URL carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_streams_a_url_into_the_tree() {
    let (dir, daemon, _space, _scan) = daemon_with_space(&[]).await;
    let data_dir = dir.path();

    // Larger than one control chunk, so the payload crosses the coalescing
    // path rather than fitting a single message.
    let payload: Vec<u8> = (0..600_000u32).map(|i| (i % 251) as u8).collect();
    let (addr, served) = http_server(vec![
        ("/1.txt", ok_response(b"hello from the web\n")),
        ("/moved.bin", redirect_response("/real/system.img")),
        ("/real/system.img", ok_response(&payload)),
    ])
    .await;

    // A directory destination keeps the URL's file name.
    let written = synch_cli::fetch::fetch(
        data_dir,
        &format!("http://{addr}/1.txt"),
        "media/documents/",
    )
    .await
    .unwrap();
    assert_eq!(written.entry.path, "documents/1.txt");
    assert_eq!(
        read(data_dir, cat("media/documents/1.txt", None, None)).await,
        b"hello from the web\n"
    );

    // A redirect is followed, and the entry is named after where it landed.
    let written = synch_cli::fetch::fetch(
        data_dir,
        &format!("http://{addr}/moved.bin"),
        "media/images/",
    )
    .await
    .unwrap();
    assert_eq!(written.entry.path, "images/system.img");
    assert_eq!(written.entry.size, payload.len() as u64);
    assert_eq!(
        read(data_dir, cat("media/images/system.img", None, None)).await,
        payload
    );

    // An explicit file destination is taken as written, whatever the URL.
    let written = synch_cli::fetch::fetch(
        data_dir,
        &format!("http://{addr}/1.txt"),
        "media/copies/renamed.txt",
    )
    .await
    .unwrap();
    assert_eq!(written.entry.path, "copies/renamed.txt");

    served.abort();
    daemon.shutdown().await;
}

/// A fetch that cannot complete publishes nothing: a non-success status is
/// refused before the write opens, and a body that stops short of its
/// declared length aborts the write, so a truncated download is never
/// published as this node's own assertion (§9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_fetch_publishes_nothing() {
    let (dir, daemon, _space, _scan) = daemon_with_space(&[]).await;
    let data_dir = dir.path();

    // The body stops 600 000 bytes short of its declared length, after enough
    // has arrived that a full control chunk was already streamed into the
    // daemon's staging file — the abort must throw *staged* bytes away, not
    // just an empty write.
    let mut truncated =
        b"HTTP/1.1 200 OK\r\ncontent-length: 900000\r\nconnection: close\r\n\r\n".to_vec();
    truncated.extend_from_slice(&[7u8; 300_000]);
    let (addr, served) = http_server(vec![("/gone.bin", truncated)]).await;

    let error = synch_cli::fetch::fetch(
        data_dir,
        &format!("http://{addr}/missing.txt"),
        "media/documents/",
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("404"), "{error:#}");

    let error = synch_cli::fetch::fetch(data_dir, &format!("http://{addr}/gone.bin"), "media/")
        .await
        .unwrap_err();
    // The error carries the daemon's own account of the abort, with the one
    // full chunk it had staged and threw away.
    assert!(
        format!("{error:#}").contains("abandoned after 262144 byte(s)"),
        "{error:#}"
    );
    assert_eq!(
        resolve(data_dir, resolve_req("media", "gone.bin"))
            .await
            .unwrap_err(),
        ErrorCode::NotFound
    );

    // A scheme fetch does not speak, and a malformed destination, both fail
    // before any connection is made — each with its own reason.
    let gone = format!("http://{addr}/gone.bin");
    for (url, destination, says) in [
        ("ftp://example.com/x", "media/", "http:// or https://"),
        ("not a url", "media/", "is not a URL"),
        (gone.as_str(), "media", "is not a destination"),
        (gone.as_str(), "nas@cluster.example:media/f", "own version"),
    ] {
        let error = synch_cli::fetch::fetch(data_dir, url, destination)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains(says),
            "{url} -> {destination}: {error:#}"
        );
    }

    served.abort();
    daemon.shutdown().await;
}

/// `synch put` streams a local file into the tree through the same write the
/// S3 gateway and `synch fetch` use, completes a directory destination with
/// the file's own name, and needs no checkout: on an API source the payload
/// is published from the CAS and nothing is materialized.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_streams_a_local_file_into_the_tree() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    says(
        data_dir,
        api_source_add("media"),
        "publishing media through APIs",
    )
    .await;

    let files = tempfile::tempdir().unwrap();
    // Larger than one control chunk, so the payload crosses the coalescing
    // path rather than fitting a single message.
    let payload: Vec<u8> = (0..600_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(files.path().join("1.txt"), b"hello from disk\n").unwrap();
    std::fs::write(files.path().join("system.img"), &payload).unwrap();
    std::fs::write(files.path().join("empty"), b"").unwrap();

    // A directory destination keeps the file's name.
    let written = synch_cli::write::put(data_dir, &files.path().join("1.txt"), "media/documents/")
        .await
        .unwrap();
    assert_eq!(written.entry.path, "documents/1.txt");
    assert_eq!(
        read(data_dir, cat("media/documents/1.txt", None, None)).await,
        b"hello from disk\n"
    );

    let written =
        synch_cli::write::put(data_dir, &files.path().join("system.img"), "media/images/")
            .await
            .unwrap();
    assert_eq!(written.entry.path, "images/system.img");
    assert_eq!(written.entry.size, payload.len() as u64);
    assert_eq!(
        read(data_dir, cat("media/images/system.img", None, None)).await,
        payload
    );

    // An explicit file destination is taken as written, whatever the file
    // was called; and an empty file is a file.
    let written = synch_cli::write::put(
        data_dir,
        &files.path().join("empty"),
        "media/copies/renamed.txt",
    )
    .await
    .unwrap();
    assert_eq!(written.entry.path, "copies/renamed.txt");
    assert_eq!(written.entry.size, 0);

    // Nothing was materialized: the API source has no directory and no local
    // files, and the bytes are in the CAS.
    let root = written.entry.content.unwrap();
    let inspecting = daemon.node.clone();
    let (bytes, local_path, local_files) = synch_core::offload(move || {
        Ok::<_, synch_engine::EngineError>((
            inspecting.store().read_all(&root)?,
            inspecting.store().source("media")?.unwrap().local_path,
            inspecting.store().local_files("media")?,
        ))
    })
    .await
    .unwrap();
    assert!(bytes.is_empty());
    assert_eq!(local_path, None);
    assert!(local_files.is_empty());

    daemon.shutdown().await;
}

/// `synch put` into a filesystem source lands the file in that source's
/// directory, exactly as a gateway write would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_into_a_filesystem_source_writes_the_file() {
    let (dir, daemon, space, _scan) = daemon_with_space(&[]).await;
    let data_dir = dir.path();
    let files = tempfile::tempdir().unwrap();
    std::fs::write(files.path().join("notes.txt"), b"kept\n").unwrap();

    let written = synch_cli::write::put(data_dir, &files.path().join("notes.txt"), "media/")
        .await
        .unwrap();
    assert_eq!(written.entry.path, "notes.txt");
    assert_eq!(
        std::fs::read(space.path().join("notes.txt")).unwrap(),
        b"kept\n"
    );
    assert_eq!(
        read(data_dir, cat("media/notes.txt", None, None)).await,
        b"kept\n"
    );

    daemon.shutdown().await;
}

/// A put that cannot complete publishes nothing, and one this process can
/// refuse on its own — a missing file, a directory, stdin without a name, a
/// malformed destination — is refused before any write opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_put_publishes_nothing() {
    let (dir, daemon, _space, _scan) = daemon_with_space(&[]).await;
    let data_dir = dir.path();
    let files = tempfile::tempdir().unwrap();
    std::fs::write(files.path().join("a.txt"), b"a").unwrap();

    let missing = files.path().join("missing.txt");
    let a = files.path().join("a.txt");
    for (file, destination, says) in [
        (missing.as_path(), "media/", "missing.txt"),
        (files.path(), "media/", "is a directory"),
        (
            std::path::Path::new("-"),
            "media/",
            "stdin carries no file name",
        ),
        (a.as_path(), "media", "is not a destination"),
        (a.as_path(), "nas@cluster.example:media/f", "own version"),
    ] {
        let error = synch_cli::write::put(data_dir, file, destination)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains(says),
            "{} -> {destination}: {error:#}",
            file.display()
        );
    }
    assert_eq!(
        resolve(data_dir, resolve_req("media", "a.txt"))
            .await
            .unwrap_err(),
        ErrorCode::NotFound
    );
    assert_eq!(
        resolve(data_dir, resolve_req("media", "missing.txt"))
            .await
            .unwrap_err(),
        ErrorCode::NotFound
    );

    daemon.shutdown().await;
}

/// `synch delete` publishes this node's tombstone through the same call the
/// gateway's `DeleteObject` uses, and says whether another origin still
/// publishes the path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_publishes_a_tombstone() {
    let (dir, daemon, _space, _scan) = daemon_with_space(&[("gone.txt", b"bytes")]).await;
    let data_dir = dir.path();
    assert_eq!(
        read(data_dir, cat("media/gone.txt", None, None)).await,
        b"bytes"
    );

    let (target, deleted) = synch_cli::write::delete(data_dir, "media/gone.txt")
        .await
        .unwrap();
    assert_eq!(
        (target.space.as_str(), target.path.as_str()),
        ("media", "gone.txt")
    );
    assert!(!deleted.still_published);
    assert_eq!(
        resolve(data_dir, resolve_req("media", "gone.txt"))
            .await
            .unwrap_err(),
        ErrorCode::NotFound
    );

    // A delete names one file: a directory, an origin-qualified reference, or
    // no path at all is refused before the daemon is asked.
    for (target, says) in [
        ("media/", "names no file"),
        ("media/docs/", "names no file"),
        ("media", "is not a destination"),
        ("nas@cluster.example:media/f", "own version"),
    ] {
        let error = synch_cli::write::delete(data_dir, target)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains(says), "{target}: {error:#}");
    }

    daemon.shutdown().await;
}

/// Gateway config lives in the daemon: appended a record at a time, fenced
/// to `s3.*` so one config row cannot reach another (§9.4).
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
    // A record is one line: a newline would forge a second record.
    assert_eq!(
        append_config(data_dir, "s3.keys", "id\tsecret\nsmuggled\tin")
            .await
            .unwrap_err(),
        ErrorCode::Invalid
    );

    daemon.shutdown().await;
}

/// Version and token are checked on every call: forged or truncated tokens
/// are Unauthorized, a mismatch names both versions, and the real one serves.
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

    // Every daemon start mints a new token, so a client holding the
    // previous run's is refused rather than silently accepted.
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

/// A killed daemon leaves its socket file behind; the next one must notice
/// nothing answers it and take the address over.
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

/// One daemon per datadir: while the old one is up a replacement bind is
/// refused (the token must not outlive the socket), and once it is gone — or
/// was killed, leaving a stale socket file behind — the next daemon takes
/// the address over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_daemon_per_datadir_until_the_old_one_is_fully_gone() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    // While the old daemon is up, a second bind for the datadir fails.
    let bind_error = Server::bind(daemon.node.clone(), broadcast::channel(1).0)
        .await
        .expect_err("a second daemon for one datadir is refused");
    assert_eq!(
        bind_error.kind(),
        std::io::ErrorKind::AddrInUse,
        "{bind_error}"
    );
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

    // What a killed daemon leaves: a socket file with nothing listening. The
    // next daemon must notice that and take the address over.
    #[cfg(unix)]
    {
        let path = synch_cli::control::transport::socket_path(data_dir);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        drop(listener);
        assert!(path.exists(), "the stale socket file is still there");
        assert!(tokio::net::UnixStream::connect(&path).await.is_err());
        let daemon = Daemon::reopen(data_dir).await;
        assert!(lines(data_dir, Command::Id(pb::Id {}))
            .await
            .contains("nas@cluster.example"));
        daemon.shutdown().await;
    }
}

/// §8: `synch adopt path` handles both live entries and tombstones.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adopt_path_adopts_a_peers_deletion_over_the_socket() {
    let (dir, daemon, space, _scan) =
        daemon_with_space(&[("shared.txt", b"ours"), ("kept.txt", b"ours")]).await;
    let data_dir = dir.path();

    let peer = OriginId::named("laptop", "cluster.example").unwrap();
    // The peer publishes a live `kept.txt` we could fetch, and a tombstone
    // for `shared.txt`.
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

    // A live version is copied into this node's filesystem source.
    let adopted = lines(
        data_dir,
        adopt_path("laptop@cluster.example:media/kept.txt"),
    )
    .await;
    assert!(adopted.contains("adopted into"), "{adopted}");
    assert_eq!(
        std::fs::read(space.path().join("kept.txt")).unwrap(),
        b"theirs"
    );

    // A deletion removes our copy and publishes our own tombstone.
    let adopted = lines(
        data_dir,
        adopt_path("laptop@cluster.example:media/shared.txt"),
    )
    .await;
    assert!(adopted.contains("removed"), "{adopted}");
    assert!(adopted.contains("published seq"), "{adopted}");
    assert!(!space.path().join("shared.txt").exists());

    daemon.shutdown().await;
}

/// A daemon stops while its startup work is stalled on a peer: the initial
/// scan pushes to every known peer, a peer that answers nothing holds that
/// push for the whole deadline, and the stop signal must be heard during it
/// — an operator stopping a daemon must not wait on a stranger.
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

    // The silent peer is trusted and addressed so the initial scan pushes to it.
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
            seeding.add_filesystem_source("s", &space_path).unwrap();
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

    // Long enough that only the initial scan talks to the peer during the
    // test. That must include anti-entropy: a round mid-request when the stop
    // arrives is allowed by design to run to its per-request deadline (the
    // daemon's join waits for it), so with the default interval whether this
    // test measured the scan's cancellation or that deadline was a jitter
    // draw.
    let mut config = NodeConfig::loopback(dir.path());
    config.publish_quiesce = std::time::Duration::from_secs(300);
    config.aae_interval = std::time::Duration::from_secs(300);
    // Bounds the startup readoption probe of the same silent peer, which runs
    // before the control server starts accepting and would otherwise hold the
    // stop request back for the full request deadline. The initial scan's
    // push keeps its deadline — the stop must be heard while it is stalled.
    config.sync_round_budget = std::time::Duration::from_secs(1);
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

/// Every trust knob is settable by environment variable, invisible on the
/// command line: `daemon status` and `doctor` are what distinguish a
/// `require` daemon from a `--rekor off` one.
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
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor {})).await;
    assert!(doctor.contains("no DNSKEY records"), "{doctor}");

    // A refresh over the socket uses the daemon's resolver, and refuses
    // when there is none, rather than building one per request.
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
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor {})).await;
    assert!(doctor.contains("log key "), "{doctor}");
    assert!(doctor.contains("clock: usable"), "{doctor}");

    // And it is *one* resolver: the TUF walk's once-a-day bound lives in it,
    // and a per-request one would re-walk on every command.
    assert!(std::sync::Arc::ptr_eq(
        &resolver,
        &daemon.node.dns_resolver().unwrap()
    ));
    daemon.shutdown().await;
}

// ---- sockets (`docs/SOCKETS.md`) -------------------------------------------

fn socket_activate(target: &str) -> Command {
    Command::SocketActivate(pb::SocketActivate {
        target: target.into(),
        config: vec![],
        max_streams: 32,
        note: String::new(),
    })
}

fn socket_ls(space: &str, long: bool) -> Command {
    Command::SocketLs(pb::SocketLs {
        space: space.into(),
        long,
    })
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn the_control_socket_can_invoke_this_nodes_own_socket() {
    let dir = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    daemon
        .node
        .add_filesystem_source("code", space.path())
        .unwrap();

    let elf = synch_cc::compile(
        include_str!("../../synch-sock/examples/echo.c"),
        "echo.c",
        &[("synch.h", synch_sock::sdk::HEADER)],
        &[],
    )
    .unwrap();
    std::fs::write(space.path().join("echo.sock"), elf).unwrap();
    daemon
        .node
        .socket_activate(&synch_store::SocketActivation::new(
            "code",
            "echo.sock",
            synch_core::now_ns(),
        ))
        .unwrap();
    daemon.node.scan_and_publish().unwrap();

    let (requests, rx) = tokio::sync::mpsc::channel(4);
    for kind in [
        pb::connect_request::Kind::Open(pb::ConnectOpen {
            reference: format!("{}:code/echo.sock", daemon.node.origin().canonical()),
            meta: Vec::new(),
        }),
        pb::connect_request::Kind::Data(b"through control".to_vec()),
        pb::connect_request::Kind::Fin(pb::ConnectFin {}),
    ] {
        requests
            .send(pb::ConnectRequest { kind: Some(kind) })
            .await
            .unwrap();
    }
    drop(requests);

    let mut client = Client::connect(dir.path()).await.unwrap();
    let mut responses = client
        .open_socket(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap();
    let mut output = Vec::new();
    let mut exit = None;
    while let Some(response) = responses.message().await.unwrap() {
        match response.kind {
            Some(pb::connect_response::Kind::Data(bytes)) => output.extend(bytes),
            Some(pb::connect_response::Kind::Closed(closed)) => exit = Some(closed.exit_code),
            _ => {}
        }
    }

    assert_eq!(output, b"through control");
    assert_eq!(exit, Some(output.len() as i32));
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_socket_is_activated_listed_and_deactivated() {
    let dir = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    lines(
        dir.path(),
        source_add("code", space.path().to_str().unwrap()),
    )
    .await;

    let out = lines(dir.path(), socket_activate("code/git.sock")).await;
    assert!(out.contains("activated code/git.sock"), "{out}");
    assert!(
        out.contains("deployment"),
        "the breadth of the grant has to be named where it is made: {out}"
    );

    // Activated but not published: the scanner has not run, so there is
    // nothing to serve yet, and the listing says so.
    let out = lines(dir.path(), socket_ls("", true)).await;
    assert!(out.contains("code/git.sock"), "{out}");
    assert!(out.contains("unpublished"), "{out}");

    let out = lines(
        dir.path(),
        Command::SocketDeactivate(pb::SocketDeactivate {
            target: "code/git.sock".into(),
        }),
    )
    .await;
    assert!(out.contains("deactivated"), "{out}");
    assert!(lines(dir.path(), socket_ls("", false))
        .await
        .contains("no sockets activated"),);

    // Deactivating what is not activated is a not-found, not a silent success.
    assert_eq!(
        failure(
            dir.path(),
            Command::SocketDeactivate(pb::SocketDeactivate {
                target: "code/git.sock".into(),
            })
        )
        .await,
        ErrorCode::NotFound
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_socket_target_must_name_this_nodes_own_space_and_path() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    // An origin-qualified target is refused: a socket is activated on the node
    // that publishes it, so naming somebody else's tree here is a mistake
    // worth saying out loud rather than quietly dropping.
    assert_eq!(
        failure(
            dir.path(),
            socket_activate("nas@cluster.example:code/git.sock")
        )
        .await,
        ErrorCode::Invalid
    );
    assert_eq!(
        failure(dir.path(), socket_activate("nopathhere")).await,
        ErrorCode::Invalid
    );
    // A space this node does not index has nothing to activate in.
    assert_eq!(
        failure(dir.path(), socket_activate("absent/git.sock")).await,
        ErrorCode::Invalid
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn the_sdk_header_is_served_by_the_daemon_that_defines_it() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    let header = lines(dir.path(), Command::SocketSdk(pb::SocketSdk {})).await;
    // A guest compiled against a stale header gets wrong answers rather than
    // errors, so the header travels with the build that defines the ABI.
    assert!(header.contains("#define SY_EAGAIN"), "{header}");
    assert!(header.contains("synchronicity.stream"), "{header}");
    assert!(header.contains("sy_poll"), "{header}");

    daemon.shutdown().await;
}

#[tokio::test]
async fn the_live_surface_answers_when_nothing_is_running() {
    let dir = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    lines(
        dir.path(),
        source_add("code", space.path().to_str().unwrap()),
    )
    .await;
    lines(dir.path(), socket_activate("code/git.sock")).await;

    // An empty answer is an answer, and saying so beats printing nothing and
    // leaving an operator wondering whether the command worked.
    let out = lines(
        dir.path(),
        Command::SocketPs(pb::SocketPs {
            target: String::new(),
        }),
    )
    .await;
    assert!(out.contains("no invocations running"), "{out}");

    let out = lines(
        dir.path(),
        Command::SocketLog(pb::SocketLog {
            target: "code/git.sock".into(),
        }),
    )
    .await;
    assert!(out.contains("said nothing recently"), "{out}");

    // Killing something that is not there is a not-found, not a silent success.
    assert_eq!(
        failure(
            dir.path(),
            Command::SocketKill(pb::SocketKill { invocation: 99 })
        )
        .await,
        ErrorCode::NotFound
    );

    // `ps` for one socket takes the same target shape everything else does.
    assert_eq!(
        failure(
            dir.path(),
            Command::SocketPs(pb::SocketPs {
                target: "nas@cluster.example:code/git.sock".into(),
            })
        )
        .await,
        ErrorCode::Invalid
    );

    daemon.shutdown().await;
}
