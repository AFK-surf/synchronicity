//! Control round-trips against a daemon in a temp datadir (§11).
//!
//! The daemon runs in process here — same `Server`, same transport, same
//! service the real binary serves — so the whole command surface can be
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
/// assertion can see a violation on (§10). A `current_thread` test would let a
/// blocking call on a request path pass silently, which is exactly the gap that
/// let several of them accumulate.
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

    /// Records a file another origin published, the way a completed sync would
    /// have left it: the bytes in the CAS, the entry in that origin's view.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_command_variant_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    let space = space_with(&[("notes.txt", b"hello"), ("talks/a.txt", b"talk")]);
    let peer_key = SecretKey::generate().public().to_z32();

    // Identity and keys.
    let id = lines(data_dir, Command::Id(pb::Id {})).await;
    assert!(id.contains("nas@cluster.example"), "{id}");
    assert!(id.contains("active"), "{id}");
    // One key, plus the line saying there was nobody to ask about it (§3.4).
    let keys = lines(data_dir, Command::KeyLs(pb::KeyLs {})).await;
    assert!(keys.contains("bound by 0 of 0 reachable peer(s)"), "{keys}");
    assert!(keys.contains("no trusted peers to ask"), "{keys}");
    assert_eq!(keys.lines().count(), 2, "{keys}");

    // A manual round with nobody to run it against says so and succeeds.
    let sync = lines(data_dir, Command::SyncNow(pb::SyncNow {})).await;
    assert!(sync.contains("no dialable peers"), "{sync}");

    // Spaces, scanning, and listing.
    assert!(lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        })
    )
    .await
    .contains("media"));
    assert!(lines(data_dir, Command::SpaceLs(pb::SpaceLs {}))
        .await
        .contains("media"));

    let scan = lines(data_dir, Command::Scan(pb::Scan {})).await;
    assert!(scan.contains("hashed 2"), "{scan}");
    assert!(scan.contains("published seq 1"), "{scan}");

    let ls = lines(
        data_dir,
        Command::Ls(pb::Ls {
            reference: "media".into(),
            all: false,
        }),
    )
    .await;
    assert!(ls.contains("notes.txt"), "{ls}");
    assert!(ls.contains("talks/a.txt"), "{ls}");

    let ls = lines(
        data_dir,
        Command::Ls(pb::Ls {
            reference: "media/talks".into(),
            all: true,
        }),
    )
    .await;
    assert!(ls.contains("talks/a.txt"), "{ls}");
    assert!(!ls.contains("notes.txt"), "{ls}");

    let status = lines(
        data_dir,
        Command::Status(pb::Status {
            reference: Some("media".into()),
        }),
    )
    .await;
    assert!(status.contains("media/notes.txt  1 version(s)"), "{status}");
    assert!(status.contains("nas@cluster.example"), "{status}");
    assert!(
        lines(data_dir, Command::Status(pb::Status { reference: None }))
            .await
            .contains("media/notes.txt")
    );

    // Reads, in full and by range.
    let payload = read(
        data_dir,
        Command::Cat(pb::Cat {
            reference: "nas@cluster.example:media/notes.txt".into(),
            range: None,
            from: None,
            strict: false,
        }),
    )
    .await;
    assert_eq!(payload, b"hello");
    let payload = read(
        data_dir,
        Command::Cat(pb::Cat {
            reference: "media/notes.txt".into(),
            range: Some("1..3".into()),
            from: None,
            strict: false,
        }),
    )
    .await;
    assert_eq!(payload, b"el");
    let payload = read(
        data_dir,
        Command::Get(pb::Get {
            reference: "media/notes.txt".into(),
            from: Some("nas@cluster.example".into()),
            strict: false,
        }),
    )
    .await;
    assert_eq!(payload, b"hello");

    let log = lines(
        data_dir,
        Command::Log(pb::Log {
            reference: "media/notes.txt".into(),
        }),
    )
    .await;
    assert!(log.contains("seq 1"), "{log}");

    // Membership.
    let trusted = lines(
        data_dir,
        Command::TrustAdd(pb::TrustAdd {
            key: peer_key.clone(),
            note: Some("a test peer".into()),
            addr: Some("127.0.0.1:4433".into()),
        }),
    )
    .await;
    // The key is the identity: static trust names nobody (§3.2).
    assert!(trusted.contains(&peer_key), "{trusted}");
    let trust_ls = lines(data_dir, Command::TrustLs(pb::TrustLs {})).await;
    assert!(trust_ls.contains("a test peer"), "{trust_ls}");
    assert!(lines(data_dir, Command::Peers(pb::Peers {}))
        .await
        .contains(&peer_key));

    // Dropping one key's binding by name, then the whole origin. A
    // key-identified origin holds exactly one binding, so the two spellings
    // are the same removal — and a second attempt at either is a not-found.
    assert!(lines(
        data_dir,
        Command::TrustRm(pb::TrustRm {
            origin: format!("key:{peer_key}"),
            key: Some(peer_key.clone()),
        })
    )
    .await
    .contains("binding to"));
    assert_eq!(
        failure(
            data_dir,
            Command::TrustRm(pb::TrustRm {
                origin: format!("key:{peer_key}"),
                key: Some(peer_key.clone()),
            })
        )
        .await,
        ErrorCode::NotFound
    );

    let second = SecretKey::generate().public().to_z32();
    lines(
        data_dir,
        Command::TrustAdd(pb::TrustAdd {
            key: second.clone(),
            note: None,
            addr: None,
        }),
    )
    .await;
    assert!(lines(
        data_dir,
        Command::TrustRm(pb::TrustRm {
            origin: format!("key:{second}"),
            key: None,
        })
    )
    .await
    .contains("removed 1 binding(s)"));

    // The domain. `set` attempts a refresh, which has no resolver here and
    // must still record the domain rather than fail.
    let _ = frames(
        data_dir,
        Command::DomainSet(pb::DomainSet {
            domain: "cluster.example".into(),
        }),
    )
    .await;
    assert!(lines(data_dir, Command::DomainLs(pb::DomainLs {}))
        .await
        .contains("cluster.example"));
    let _ = frames(data_dir, Command::DomainRefresh(pb::DomainRefresh {})).await;
    assert!(lines(data_dir, Command::DomainClear(pb::DomainClear {}))
        .await
        .contains("cleared"));
    assert_eq!(
        failure(data_dir, Command::DomainClear(pb::DomainClear {})).await,
        ErrorCode::NotFound,
        "there is nothing left to clear"
    );

    // Mirrors.
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror_path = mirror_dir.path().to_string_lossy().into_owned();
    let mirroring = lines(
        data_dir,
        Command::MirrorAdd(pb::MirrorAdd {
            space: "media".into(),
            path: mirror_path.clone(),
            policy: Some("origin=laptop@cluster.example".into()),
        }),
    )
    .await;
    assert!(mirroring.contains("mirroring"), "{mirroring}");
    assert!(
        mirroring.contains("origin=laptop@cluster.example"),
        "{mirroring}"
    );
    let mirror_ls = lines(data_dir, Command::MirrorLs(pb::MirrorLs {})).await;
    assert!(mirror_ls.contains("media"), "{mirror_ls}");
    assert!(
        mirror_ls.contains("origin=laptop@cluster.example"),
        "{mirror_ls}"
    );
    let _ = frames(data_dir, Command::MirrorSync(pb::MirrorSync {}))
        .await
        .unwrap();
    assert!(lines(
        data_dir,
        Command::MirrorRm(pb::MirrorRm {
            path: mirror_path.clone(),
        })
    )
    .await
    .contains("removed"));

    // Pins.
    let root = blake3::hash(b"hello").to_hex().to_string();
    assert!(lines(
        data_dir,
        Command::PinAdd(pb::PinAdd {
            target: root.clone()
        })
    )
    .await
    .contains(&root));
    assert!(lines(data_dir, Command::PinLs(pb::PinLs {}))
        .await
        .contains(&root));
    assert!(lines(
        data_dir,
        Command::PinRm(pb::PinRm {
            target: root.clone()
        })
    )
    .await
    .contains(&root));
    assert!(lines(data_dir, Command::PinLs(pb::PinLs {}))
        .await
        .is_empty());

    // Reports.
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor { rebuild: false })).await;
    assert!(doctor.contains("origin: nas@cluster.example"), "{doctor}");
    assert!(doctor.contains("equivocation: none detected"), "{doctor}");
    let rebuilt = lines(data_dir, Command::Doctor(pb::Doctor { rebuild: true })).await;
    assert!(rebuilt.contains("rebuilt"), "{rebuilt}");
    // Status is the glance, not the byte-identical twin of doctor.
    let status = lines(data_dir, Command::DaemonStatus(pb::DaemonStatus {})).await;
    assert!(status.contains("origin nas@cluster.example"), "{status}");
    assert!(status.contains("spaces: 1 (media)"), "{status}");
    assert!(status.contains("head: seq"), "{status}");
    assert!(!status.contains("storage:"), "{status}");

    // Rotation, end to end and operator-driven (§3.4).
    let rotate = lines(data_dir, Command::KeyRotate(pb::KeyRotate {})).await;
    assert!(
        rotate.contains("_synchronicity.cluster.example."),
        "{rotate}"
    );
    assert!(rotate.contains("v=sync1 id=nas nk="), "{rotate}");
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
    let activated = lines(
        data_dir,
        Command::KeyActivate(pb::KeyActivate {
            key: new_key.clone(),
            bind: None,
        }),
    )
    .await;
    assert!(activated.contains(&new_key), "{activated}");
    assert_eq!(daemon.node.node_id().to_z32(), new_key);
    assert_eq!(daemon.node.retiring_endpoints().len(), 1);

    let retired = lines(
        data_dir,
        Command::KeyRetire(pb::KeyRetire {
            key: old_key.clone(),
        }),
    )
    .await;
    assert!(retired.contains("secret deleted"), "{retired}");
    assert!(daemon.node.retiring_endpoints().is_empty());
    // One key, plus the line saying there was nobody to ask about it (§3.4).
    let keys = lines(data_dir, Command::KeyLs(pb::KeyLs {})).await;
    assert!(keys.contains("bound by 0 of 0 reachable peer(s)"), "{keys}");
    assert!(keys.contains("no trusted peers to ask"), "{keys}");
    assert_eq!(keys.lines().count(), 2, "{keys}");

    // Cloud attach. These read and write `config` like every other command
    // here, so they belong in the round trip for the same reason the rest do:
    // on a runtime worker a store read trips `assert_off_runtime` and takes
    // the whole daemon down (§10), and only running the command finds that.
    let status = lines(data_dir, Command::CloudStatus(pb::CloudStatus {})).await;
    assert!(status.contains("cloud: enabled"), "{status}");
    assert!(lines(data_dir, Command::CloudDisable(pb::CloudDisable {}))
        .await
        .contains("disabled"));
    let status = lines(data_dir, Command::CloudStatus(pb::CloudStatus {})).await;
    assert!(status.contains("opted out"), "{status}");
    assert!(lines(data_dir, Command::CloudEnable(pb::CloudEnable {}))
        .await
        .contains("media"));

    // Removing the space unpublishes its entries.
    assert!(lines(
        data_dir,
        Command::SpaceRm(pb::SpaceRm { id: "media".into() })
    )
    .await
    .contains("unpublished"));

    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sync_that_reaches_nobody_says_so_in_the_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    // A trusted peer with no address fails its dial immediately, which keeps
    // this test fast; the exit contract is the same as for a timeout.
    lines(
        data_dir,
        Command::TrustAdd(pb::TrustAdd {
            key: SecretKey::generate().public().to_z32(),
            note: None,
            addr: None,
        }),
    )
    .await;
    let frames = frames(data_dir, Command::SyncNow(pb::SyncNow {})).await;
    // The per-peer line still streams out before the error frame lands.
    assert_eq!(
        frames.expect_err("reaching zero of one peer is a failure"),
        ErrorCode::Unavailable
    );
    daemon.shutdown().await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errors_cross_the_socket_with_their_code() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    assert_eq!(
        failure(
            data_dir,
            Command::Cat(pb::Cat {
                reference: "nas@cluster.example:media/absent.txt".into(),
                range: None,
                from: None,
                strict: false,
            })
        )
        .await,
        ErrorCode::NotFound
    );
    // Silence is reserved for "exists but empty": an unknown space, an
    // unknown origin, a path nothing publishes, and a ghost space each say
    // so instead of printing nothing and exiting 0.
    assert_eq!(
        failure(
            data_dir,
            Command::Ls(pb::Ls {
                reference: "nospace".into(),
                all: false,
            })
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Command::Ls(pb::Ls {
                reference: "stranger@cluster.example:media".into(),
                all: false,
            })
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Command::Status(pb::Status {
                reference: Some("media/gone.txt".into()),
            })
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Command::SpaceRm(pb::SpaceRm { id: "ghost".into() })
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Command::MirrorRm(pb::MirrorRm {
                path: "/no/such/mirror".into(),
            })
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Command::Cat(pb::Cat {
                reference: "nas@cluster.example:media/pinned.txt".into(),
                range: None,
                from: Some("laptop@cluster.example".into()),
                strict: false,
            })
        )
        .await,
        ErrorCode::Invalid
    );
    assert_eq!(
        failure(
            data_dir,
            Command::PinAdd(pb::PinAdd {
                target: "not-hex".into()
            })
        )
        .await,
        ErrorCode::Invalid
    );
    assert_eq!(
        failure(
            data_dir,
            Command::TrustAdd(pb::TrustAdd {
                key: "not-a-key".into(),
                note: None,
                addr: None,
            })
        )
        .await,
        ErrorCode::Invalid
    );
    // A key-identified origin has no name to rebind, and `take` of our own
    // entry is a mistake rather than a not-found.
    assert_eq!(
        failure(
            data_dir,
            Command::Take(pb::Take {
                reference: "nas@cluster.example:media/a.txt".into(),
            })
        )
        .await,
        ErrorCode::Invalid
    );
    assert_eq!(
        failure(
            data_dir,
            Command::KeyActivate(pb::KeyActivate {
                key: SecretKey::generate().public().to_z32(),
                bind: None,
            })
        )
        .await,
        ErrorCode::NotFound
    );

    daemon.shutdown().await;
}

/// `scan` and `mirror sync` report what they are doing as they do it, in
/// frames the CLI renders and discards (§9.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_and_mirror_sync_stream_progress() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    let media = space_with(&[("a.txt", b"a")]);
    let notes = space_with(&[("b.txt", b"b")]);
    for (id, space) in [("media", &media), ("notes", &notes)] {
        lines(
            data_dir,
            Command::SpaceAdd(pb::SpaceAdd {
                id: id.into(),
                path: space.path().to_string_lossy().into_owned(),
            }),
        )
        .await;
    }

    let progress = progress_of(data_dir, Command::Scan(pb::Scan {})).await;
    assert!(
        progress.iter().any(|line| line.contains("scanned media")),
        "{progress:?}"
    );
    assert!(
        progress.iter().any(|line| line.contains("scanned notes")),
        "{progress:?}"
    );

    let target = tempfile::tempdir().unwrap();
    lines(
        data_dir,
        Command::MirrorAdd(pb::MirrorAdd {
            space: "media".into(),
            path: target.path().to_string_lossy().into_owned(),
            policy: None,
        }),
    )
    .await;
    let progress = progress_of(data_dir, Command::MirrorSync(pb::MirrorSync {})).await;
    let target_name = target
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        progress.iter().any(|line| line.contains(&target_name)),
        "{progress:?}"
    );

    daemon.shutdown().await;
}

/// `synch recover` over the socket: the quiesce reports each round as it goes,
/// and the node it ran on can publish again (§3.4, §9.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recover_streams_its_quiesce_and_lifts_the_publishing_floor() {
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

    // A peer has advertised a head for this node's own origin at seq 100 — the
    // observation an ordinary `Hello` exchange leaves behind (§5.1).
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
    // node is not broken and the request is not malformed — the state it was
    // made in is what is wrong — so the code says "unavailable" (§3.4).
    let error = failure_message(data_dir, Command::Scan(pb::Scan {})).await;
    assert_eq!(error.code, ErrorCode::Unavailable, "{error:?}");
    assert!(error.message.contains("synch recover"), "{error:?}");
    assert!(error.message.contains("seq 100"), "{error:?}");

    // Doctor says the same thing in its own words.
    let doctor = lines(data_dir, Command::Doctor(pb::Doctor { rebuild: false })).await;
    assert!(doctor.contains("KEY-LOSS RECOVERY"), "{doctor}");
    assert!(doctor.contains("seq 100"), "{doctor}");

    let request = Command::Recover(pb::Recover {
        wait: Some("0".into()),
        gap: Some(5),
    });
    let all = frames(data_dir, request).await.expect("recover should run");
    let progress: Vec<String> = all
        .iter()
        .filter_map(|frame| match frame {
            Frame::Progress(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(progress.len(), 1, "{progress:?}");
    assert!(progress[0].contains("round 1"), "{progress:?}");
    assert!(progress[0].contains("highest seq seen 100"), "{progress:?}");
    let text: Vec<String> = all
        .iter()
        .filter_map(|frame| match frame {
            Frame::Line(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    let text = text.join("\n");
    assert!(text.contains("is in recovery"), "{text}");
    assert!(text.contains("publishing resumes at seq 105"), "{text}");

    // And the node publishes again, above everything that was advertised.
    let scan = lines(data_dir, Command::Scan(pb::Scan {})).await;
    assert!(scan.contains("published seq 105"), "{scan}");

    let doctor = lines(data_dir, Command::Doctor(pb::Doctor { rebuild: false })).await;
    assert!(!doctor.contains("KEY-LOSS RECOVERY"), "{doctor}");

    // A duration this program cannot read fails before any waiting happens.
    let error = failure_message(
        data_dir,
        Command::Recover(pb::Recover {
            wait: Some("whenever".into()),
            gap: None,
        }),
    )
    .await;
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
    let mut frames = client
        .run(Command::Recover(pb::Recover {
            wait: Some("1h".into()),
            gap: None,
        }))
        .await
        .unwrap();
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

/// A multi-megabyte read must arrive as a sequence of bounded chunks, not as
/// one buffered payload (§9.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_multi_megabyte_cat_streams_in_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    let size = 5 * 1024 * 1024 + 12_345;
    let payload: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let space = space_with(&[("big.bin", &payload)]);
    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    lines(data_dir, Command::Scan(pb::Scan {})).await;

    let mut client = Client::connect(data_dir).await.unwrap();
    let mut frames = client
        .run(Command::Cat(pb::Cat {
            reference: "media/big.bin".into(),
            range: None,
            from: None,
            strict: false,
        }))
        .await
        .unwrap();

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

    assert_eq!(received.len(), payload.len());
    assert_eq!(received, payload);
    assert_eq!(chunks, payload.len().div_ceil(CHUNK_SIZE));
    assert!(chunks >= 20, "{chunks} chunks for a 5 MiB object");
    assert!(
        delivered_before_the_end < payload.len() / 10,
        "the first chunk carried {delivered_before_the_end} of {} bytes",
        payload.len()
    );

    // A bounded range streams the same way, and only the range.
    let ranged = read(
        data_dir,
        Command::Cat(pb::Cat {
            reference: "media/big.bin".into(),
            range: Some("1000000..1500000".into()),
            from: None,
            strict: false,
        }),
    )
    .await;
    assert_eq!(ranged, payload[1_000_000..1_500_000]);

    daemon.shutdown().await;
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

/// The structured requests §9.4 gives the gateway: a listing and a resolve that
/// answer in entry metadata rather than in rendered lines, and that name space,
/// path, and policy as fields — an S3 key may contain a colon, which the text
/// reference form would read as an origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tree_can_be_listed_and_resolved_structurally() {
    let dir = tempfile::tempdir().unwrap();
    // A colon is fine in an S3 key and in this protocol, but not in a Windows
    // file name — writing `odd:key.txt` there creates an alternate data
    // stream on a file called `odd`. The colon-bearing case can only be
    // scanned out of a space where the filesystem can hold it.
    #[cfg(not(windows))]
    let space = space_with(&[
        ("notes.txt", b"hello"),
        ("talks/a.txt", b"talk"),
        ("odd:key.txt", b"colon"),
    ]);
    #[cfg(windows)]
    let space = space_with(&[("notes.txt", b"hello"), ("talks/a.txt", b"talk")]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    lines(data_dir, Command::Scan(pb::Scan {})).await;

    let listed = entries(
        data_dir,
        pb::ListRequest {
            space: "media".into(),
            prefix: String::new(),
            start_after: None,
            limit: None,
            policy: None,
        },
    )
    .await;
    let paths: Vec<&str> = listed.iter().map(|e| e.path.as_str()).collect();
    #[cfg(not(windows))]
    assert_eq!(paths, vec!["notes.txt", "odd:key.txt", "talks/a.txt"]);
    #[cfg(windows)]
    assert_eq!(paths, vec!["notes.txt", "talks/a.txt"]);
    let notes = listed.iter().find(|e| e.path == "notes.txt").unwrap();
    assert_eq!(notes.size, 5);
    assert_eq!(notes.versions, 1);
    assert_eq!(notes.content, Some(synch_core::Hash::new(b"hello")));
    assert_eq!(notes.origin, "nas@cluster.example");

    // A prefix narrows it and a cursor resumes past a path.
    let listed = entries(
        data_dir,
        pb::ListRequest {
            space: "media".into(),
            prefix: "talks/".into(),
            start_after: None,
            limit: None,
            policy: None,
        },
    )
    .await;
    assert_eq!(listed.len(), 1, "{listed:?}");
    let listed = entries(
        data_dir,
        pb::ListRequest {
            space: "media".into(),
            prefix: String::new(),
            start_after: Some("notes.txt".into()),
            limit: None,
            policy: None,
        },
    )
    .await;
    assert!(
        listed.iter().all(|e| e.path != "notes.txt"),
        "the cursor is exclusive: {listed:?}"
    );

    // A key with a colon in it resolves and reads, which is the whole point of
    // the structured form.
    #[cfg(not(windows))]
    {
        let resolved = resolve(
            data_dir,
            pb::ResolveRequest {
                space: "media".into(),
                path: "odd:key.txt".into(),
                policy: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(resolved.size, 5);
        let payload = tree_read(
            data_dir,
            pb::ReadRequest {
                space: "media".into(),
                path: "odd:key.txt".into(),
                policy: None,
                start: 1,
                len: Some(3),
            },
        )
        .await
        .unwrap();
        assert_eq!(payload, b"olo");
    }

    assert_eq!(
        resolve(
            data_dir,
            pb::ResolveRequest {
                space: "media".into(),
                path: "absent.txt".into(),
                policy: None,
            }
        )
        .await
        .unwrap_err(),
        ErrorCode::NotFound
    );

    daemon.shutdown().await;
}

/// `synch compare` reports which files differ between the local node and a peer,
/// name-status only, over the control socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compare_reports_name_status_between_the_local_node_and_a_peer() {
    let dir = tempfile::tempdir().unwrap();
    // The local node publishes these under its own origin (nas@cluster.example).
    let space = space_with(&[
        ("keep.txt", b"same"),
        ("changed.txt", b"ours"),
        ("only_local.txt", b"here"),
    ]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    lines(data_dir, Command::Scan(pb::Scan {})).await;

    // A peer publishes: keep.txt identical, changed.txt with other bytes, and a
    // file the local node does not have.
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

    // JSON form carries the same three changes.
    let json = lines(
        data_dir,
        Command::Compare(pb::Compare {
            reference: "media".into(),
            from: None,
            to: "laptop@cluster.example".into(),
            json: true,
        }),
    )
    .await;
    assert!(
        json.contains("\"status\":\"modified\",\"path\":\"changed.txt\""),
        "{json}"
    );
    assert!(
        json.contains("\"status\":\"created\",\"path\":\"only_peer.txt\""),
        "{json}"
    );
    assert!(
        json.contains("\"status\":\"deleted\",\"path\":\"only_local.txt\""),
        "{json}"
    );

    // An unknown target origin is refused rather than reported as a full delete.
    assert_eq!(
        failure(
            data_dir,
            Command::Compare(pb::Compare {
                reference: "media".into(),
                from: None,
                to: "ghost@cluster.example".into(),
                json: false,
            }),
        )
        .await,
        ErrorCode::NotFound
    );

    daemon.shutdown().await;
}

/// A divergent path is left out of a `strict` listing rather than answered with
/// one side's metadata, and resolving it directly says what is wrong (§8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_strict_listing_omits_what_a_strict_resolve_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let space = space_with(&[("shared.txt", b"ours"), ("agreed.txt", b"only one")]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    lines(data_dir, Command::Scan(pb::Scan {})).await;

    let peer = OriginId::named("laptop", "cluster.example").unwrap();
    daemon
        .peer_file(&peer, "media", "shared.txt", b"theirs", i64::MAX, 4)
        .await;

    let strict = Some("strict".to_string());
    let listed = entries(
        data_dir,
        pb::ListRequest {
            space: "media".into(),
            prefix: String::new(),
            start_after: None,
            limit: None,
            policy: strict.clone(),
        },
    )
    .await;
    let paths: Vec<&str> = listed.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, vec!["agreed.txt"], "{listed:?}");

    assert_eq!(
        resolve(
            data_dir,
            pb::ResolveRequest {
                space: "media".into(),
                path: "shared.txt".into(),
                policy: strict,
            }
        )
        .await
        .unwrap_err(),
        ErrorCode::Divergent
    );

    // `newest` picks the winning version and says the path carries two.
    let resolved = resolve(
        data_dir,
        pb::ResolveRequest {
            space: "media".into(),
            path: "shared.txt".into(),
            policy: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(resolved.versions, 2);
    assert_eq!(resolved.origin, "laptop@cluster.example");

    daemon.shutdown().await;
}

/// A streamed write crosses the socket a chunk at a time, lands in the space,
/// and comes back as a published entry (§9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_put_publishes_without_buffering_the_object() {
    let dir = tempfile::tempdir().unwrap();
    let space = space_with(&[]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;

    let payload: Vec<u8> = (0..1_500_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut client = Client::connect(data_dir).await.unwrap();
    // The call returns once the daemon has taken its gates, which is what tells
    // the client the payload is wanted.
    let mut put = client.put("media", "uploads/report.bin").await.unwrap();
    for piece in payload.chunks(CHUNK_SIZE) {
        put.chunk(piece.to_vec()).await.unwrap();
    }
    let written = put.finish().await.unwrap();

    let published = written.entry;
    assert!(written.path.ends_with("report.bin"), "{}", written.path);
    assert_eq!(published.size, payload.len() as u64);
    assert_eq!(published.content, Some(synch_core::Hash::new(&payload)));
    assert_eq!(published.origin, "nas@cluster.example");
    assert_eq!(
        std::fs::read(space.path().join("uploads/report.bin")).unwrap(),
        payload
    );

    // It reads straight back out, and the space holds nothing else: the staging
    // file went away with the commit.
    let back = tree_read(
        data_dir,
        pb::ReadRequest {
            space: "media".into(),
            path: "uploads/report.bin".into(),
            policy: None,
            start: 0,
            len: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(back, payload);
    let left: Vec<String> = std::fs::read_dir(space.path().join("uploads"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["report.bin".to_string()]);

    daemon.shutdown().await;
}

/// A client that hangs up mid-payload leaves the space exactly as it was: half
/// an object must never become this node's signed assertion (§9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abandoned_write_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let space = space_with(&[("kept.txt", b"kept")]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    lines(data_dir, Command::Scan(pb::Scan {})).await;

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

    daemon.shutdown().await;
}

/// The gateway's configuration is the daemon's to hold: appended a record at a
/// time, and fenced to the `s3.*` namespace so a client of the socket cannot
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_token_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    let client = Client::connect_with_token(dir.path(), vec![0u8; 32])
        .await
        .unwrap();
    let error = admitted(client)
        .await
        .expect_err("a forged token must not be served");
    assert_eq!(error.code, ErrorCode::Unauthorized);
    assert!(error.message.contains("control.token"), "{error}");

    // A truncated token is rejected on length alone, and the real one still
    // works afterwards.
    let client = Client::connect_with_token(dir.path(), vec![1u8; 8])
        .await
        .unwrap();
    let error = admitted(client)
        .await
        .expect_err("a short token must not be served");
    assert_eq!(error.code, ErrorCode::Unauthorized);
    admitted(Client::connect(dir.path()).await.unwrap())
        .await
        .unwrap();

    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_mismatch_names_both_versions() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

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

    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn there_is_no_daemon_error_naming_the_socket_and_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    off_runtime(move || Node::init(&path, None)).await.unwrap();

    let error = Client::connect(dir.path())
        .await
        .expect_err("there is no daemon");
    assert!(error.message.contains("synch daemon run"), "{error}");
    assert!(
        error
            .message
            .contains(&synch_cli::control::transport::endpoint_name(dir.path())),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_daemon_for_one_datadir_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
    let (stop, _) = broadcast::channel(1);
    let error = Server::bind(node.clone(), stop)
        .await
        .expect_err("one daemon per datadir");
    assert!(
        error.to_string().contains("already running"),
        "{error}: {error:?}"
    );
    node.shutdown().await.unwrap();

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_stop_ends_the_server_and_clears_the_token() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    assert!(lines(dir.path(), Command::DaemonStop(pb::DaemonStop {}))
        .await
        .contains("stop"));
    let served = tokio::time::timeout(std::time::Duration::from_secs(10), daemon.served)
        .await
        .expect("the server stops")
        .expect("the server task did not panic");
    served.unwrap();

    // The token is gone, so a later client is told there is no daemon rather
    // than failing on a refused connection.
    let error = Client::connect(dir.path())
        .await
        .expect_err("the daemon stopped");
    assert!(error.message.contains("synch daemon run"), "{error}");

    daemon.node.shutdown().await.unwrap();
}

/// Every daemon start mints a new token, so a client holding the previous one
/// is refused rather than silently accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_is_regenerated_on_every_start() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
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

/// A call in flight must not be able to hold the daemon up: `synch recover`
/// waits an hour by default, and the operator who asked the daemon to stop is
/// not agreeing to wait it out (§9.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_call_does_not_hold_the_shutdown_open() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    // An hour-long quiesce, still running when the stop arrives.
    let mut client = Client::connect(data_dir).await.unwrap();
    let mut frames = client
        .run(Command::Recover(pb::Recover {
            wait: Some("1h".into()),
            gap: None,
        }))
        .await
        .unwrap();
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
    // Only Unix leaves anything behind to check: a named pipe has no on-disk
    // presence, and goes with the process that owned it.
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

    // While the old daemon is up, binding a second one for the datadir fails —
    // and its token is still the one a client would present.
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

/// A write is published only when the client says so. A handle that goes out
/// of scope — an early `?`, a cancelled future, a process that died — must
/// leave the space exactly as it was, however much of the payload arrived
/// (§9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_write_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let space = space_with(&[("kept.txt", b"kept")]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    lines(data_dir, Command::Scan(pb::Scan {})).await;

    {
        let mut client = Client::connect(data_dir).await.unwrap();
        let mut put = client.put("media", "uploads/half.bin").await.unwrap();
        for _ in 0..4 {
            put.chunk(vec![7u8; 200_000]).await.unwrap();
        }
        // No `finish`, no `abort`: just gone.
    }

    // The daemon keeps nothing: no entry, no staging file, and the space is
    // untouched.
    assert_eq!(
        resolve(
            data_dir,
            pb::ResolveRequest {
                space: "media".into(),
                path: "uploads/half.bin".into(),
                policy: None,
            }
        )
        .await
        .unwrap_err(),
        ErrorCode::NotFound
    );
    assert!(!space.path().join("uploads/half.bin").exists());

    // The daemon notices the abandonment on its own schedule, so this waits for
    // the staging file to go rather than assuming it has already gone: what the
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn take_adopts_a_peers_deletion_over_the_socket() {
    // §8: `synch take` of a tombstone version deletes our local copy and
    // publishes our own tombstone. The live form is unchanged, which the same
    // test checks first.
    let dir = tempfile::tempdir().unwrap();
    let space = space_with(&[("shared.txt", b"ours"), ("kept.txt", b"ours")]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    lines(
        data_dir,
        Command::SpaceAdd(pb::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    lines(data_dir, Command::Scan(pb::Scan {})).await;

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

    let node = daemon.node.clone();
    let set = off_runtime(move || node.versions("media", "shared.txt"))
        .await
        .unwrap();
    assert_eq!(set.version_count(), 1, "{:?}", set.versions);
    assert!(set.versions[0].is_tombstone());
    assert!(!set.exists(), "the path has left the unified tree");

    // Taking a deletion of something we never had says so rather than failing.
    daemon
        .peer_entry(
            &peer,
            "media",
            "never-ours.txt",
            synch_core::FileEntry::tombstone(9_000, 4, None),
        )
        .await;
    let taken = lines(
        data_dir,
        Command::Take(pb::Take {
            reference: "laptop@cluster.example:media/never-ours.txt".into(),
        }),
    )
    .await;
    assert!(taken.contains("already absent"), "{taken}");

    daemon.shutdown().await;
}

/// A daemon stops while its startup work is stalled on a peer.
///
/// The initial scan publishes and pushes, which reaches out to every peer this
/// node knows. A peer that completes the handshake and then answers nothing
/// holds that push for the whole request deadline, and the stop signal has to be
/// heard during it: an operator asking a daemon to stop must not be told to wait
/// on a stranger.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_trust_configuration_and_the_resolver_state_are_reported() {
    // Every trust knob is settable by environment variable, so which trust a
    // daemon enforces is not visible from its command line: `daemon status` and
    // `doctor` are what distinguish a `require` daemon from a `--rekor off` one.
    // And a resolver that cannot be built refreshes no membership at all, which
    // is the state most in need of naming and least visible without it.
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
    // refuses when there is none, rather than building a fresh one per request.
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
