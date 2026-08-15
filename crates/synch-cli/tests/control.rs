//! Control-socket round-trips against a daemon in a temp datadir (§11).
//!
//! The daemon runs in process here — same `Server`, same transport, same
//! framing the real binary uses — so the whole command surface can be exercised
//! without paying for a process spawn per command. `tests/cli.rs` keeps the
//! end-to-end check through the actual binary.

use std::path::Path;

use iroh_base::SecretKey;
use synch_cli::control::{
    proto::{Response, CHUNK_SIZE, CONTROL_VERSION},
    Client, EntryInfo, ErrorCode, Request, Server, Upload,
};
use synch_core::OriginId;
use synch_engine::{Node, NodeConfig};
use tokio::sync::broadcast;

/// A daemon running in this process, with its control socket bound.
struct Daemon {
    node: Node,
    stop: broadcast::Sender<()>,
    served: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Daemon {
    async fn start(data_dir: &Path) -> Daemon {
        Node::init(
            data_dir,
            Some(OriginId::named("nas", "cluster.example").unwrap()),
        )
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
}

/// Sends one request and collects every frame of the response.
async fn frames(data_dir: &Path, request: Request) -> Result<Vec<Response>, ErrorCode> {
    let mut client = Client::connect(data_dir)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    client.send(&request).await.unwrap();
    let mut out = Vec::new();
    loop {
        match client.next().await {
            Ok(Some(frame)) => out.push(frame),
            Ok(None) => return Ok(out),
            Err(e) => return Err(e.code),
        }
    }
}

/// The `Line` frames of a response, as one string.
async fn lines(data_dir: &Path, request: Request) -> String {
    let frames = frames(data_dir, request)
        .await
        .unwrap_or_else(|code| panic!("request failed: {}", code.as_str()));
    frames
        .into_iter()
        .filter_map(|frame| match frame {
            Response::Line(text) => Some(text),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The daemon's error code for a request that must fail.
async fn failure(data_dir: &Path, request: Request) -> ErrorCode {
    frames(data_dir, request)
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

#[tokio::test]
async fn every_command_variant_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    let space = space_with(&[("notes.txt", b"hello"), ("talks/a.txt", b"talk")]);
    let peer_key = SecretKey::generate().public().to_z32();

    // Identity and keys.
    let id = lines(data_dir, Request::Id).await;
    assert!(id.contains("nas@cluster.example"), "{id}");
    assert!(id.contains("active"), "{id}");
    // One key, plus the line saying there was nobody to ask about it (§3.4).
    let keys = lines(data_dir, Request::KeyLs).await;
    assert!(keys.contains("bound by 0 of 0 reachable peer(s)"), "{keys}");
    assert!(keys.contains("no trusted peers to ask"), "{keys}");
    assert_eq!(keys.lines().count(), 2, "{keys}");

    // A manual round with nobody to run it against says so and succeeds.
    let sync = lines(data_dir, Request::SyncNow).await;
    assert!(sync.contains("no dialable peers"), "{sync}");

    // Spaces, scanning, and listing.
    assert!(lines(
        data_dir,
        Request::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        }
    )
    .await
    .contains("media"));
    assert!(lines(data_dir, Request::SpaceLs).await.contains("media"));

    let scan = lines(data_dir, Request::Scan).await;
    assert!(scan.contains("hashed 2"), "{scan}");
    assert!(scan.contains("published seq 1"), "{scan}");

    let ls = lines(
        data_dir,
        Request::Ls {
            reference: "media".into(),
            all: false,
        },
    )
    .await;
    assert!(ls.contains("notes.txt"), "{ls}");
    assert!(ls.contains("talks/a.txt"), "{ls}");

    let ls = lines(
        data_dir,
        Request::Ls {
            reference: "media/talks".into(),
            all: true,
        },
    )
    .await;
    assert!(ls.contains("talks/a.txt"), "{ls}");
    assert!(!ls.contains("notes.txt"), "{ls}");

    let status = lines(
        data_dir,
        Request::Status {
            reference: Some("media".into()),
        },
    )
    .await;
    assert!(status.contains("media/notes.txt  1 version(s)"), "{status}");
    assert!(status.contains("nas@cluster.example"), "{status}");
    assert!(lines(data_dir, Request::Status { reference: None })
        .await
        .contains("media/notes.txt"));

    // Reads, in full and by range.
    let payload = read(
        data_dir,
        Request::Cat {
            reference: "nas@cluster.example:media/notes.txt".into(),
            range: None,
            from: None,
            strict: false,
        },
    )
    .await;
    assert_eq!(payload, b"hello");
    let payload = read(
        data_dir,
        Request::Cat {
            reference: "media/notes.txt".into(),
            range: Some("1..3".into()),
            from: None,
            strict: false,
        },
    )
    .await;
    assert_eq!(payload, b"el");
    let payload = read(
        data_dir,
        Request::Get {
            reference: "media/notes.txt".into(),
            from: Some("nas@cluster.example".into()),
            strict: false,
        },
    )
    .await;
    assert_eq!(payload, b"hello");

    let log = lines(
        data_dir,
        Request::Log {
            reference: "media/notes.txt".into(),
        },
    )
    .await;
    assert!(log.contains("seq 1"), "{log}");

    // Membership.
    let trusted = lines(
        data_dir,
        Request::TrustAdd {
            key: peer_key.clone(),
            name: Some("laptop".into()),
            domain: Some("cluster.example".into()),
            note: Some("a test peer".into()),
            addr: Some("127.0.0.1:4433".into()),
        },
    )
    .await;
    assert!(trusted.contains("laptop@cluster.example"), "{trusted}");
    let trust_ls = lines(data_dir, Request::TrustLs).await;
    assert!(trust_ls.contains("a test peer"), "{trust_ls}");
    assert!(lines(data_dir, Request::Peers).await.contains(&peer_key));

    let rebound = SecretKey::generate().public().to_z32();
    assert!(lines(
        data_dir,
        Request::TrustRebind {
            origin: "laptop@cluster.example".into(),
            key: rebound.clone(),
        }
    )
    .await
    .contains(&rebound));
    // The rotation-window cleanup: one key's binding goes, the other stays.
    assert!(lines(
        data_dir,
        Request::TrustRm {
            origin: "laptop@cluster.example".into(),
            key: Some(peer_key.clone()),
        }
    )
    .await
    .contains("binding to"));
    assert_eq!(
        failure(
            data_dir,
            Request::TrustRm {
                origin: "laptop@cluster.example".into(),
                key: Some(peer_key.clone()),
            }
        )
        .await,
        ErrorCode::NotFound
    );
    assert!(lines(
        data_dir,
        Request::TrustRm {
            origin: "laptop@cluster.example".into(),
            key: None,
        }
    )
    .await
    .contains("removed 1 binding(s)"));

    // Domains. `add` attempts a refresh, which has no resolver here and must
    // still record the domain rather than fail.
    let _ = frames(
        data_dir,
        Request::DomainAdd {
            domain: "cluster.example".into(),
        },
    )
    .await;
    assert!(lines(data_dir, Request::DomainLs)
        .await
        .contains("cluster.example"));
    let _ = frames(data_dir, Request::DomainRefresh { domain: None }).await;
    assert!(lines(
        data_dir,
        Request::DomainRm {
            domain: "cluster.example".into(),
        }
    )
    .await
    .contains("removed"));

    // Mirrors.
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror_path = mirror_dir.path().to_string_lossy().into_owned();
    let mirroring = lines(
        data_dir,
        Request::MirrorAdd {
            space: "media".into(),
            path: mirror_path.clone(),
            policy: Some("origin=laptop@cluster.example".into()),
        },
    )
    .await;
    assert!(mirroring.contains("mirroring"), "{mirroring}");
    assert!(
        mirroring.contains("origin=laptop@cluster.example"),
        "{mirroring}"
    );
    let mirror_ls = lines(data_dir, Request::MirrorLs).await;
    assert!(mirror_ls.contains("media"), "{mirror_ls}");
    assert!(
        mirror_ls.contains("origin=laptop@cluster.example"),
        "{mirror_ls}"
    );
    let _ = frames(data_dir, Request::MirrorSync).await.unwrap();
    assert!(lines(
        data_dir,
        Request::MirrorRm {
            path: mirror_path.clone(),
        }
    )
    .await
    .contains("removed"));

    // Pins.
    let root = blake3::hash(b"hello").to_hex().to_string();
    assert!(lines(
        data_dir,
        Request::PinAdd {
            target: root.clone()
        }
    )
    .await
    .contains(&root));
    assert!(lines(data_dir, Request::PinLs).await.contains(&root));
    assert!(lines(
        data_dir,
        Request::PinRm {
            target: root.clone()
        }
    )
    .await
    .contains(&root));
    assert!(lines(data_dir, Request::PinLs).await.is_empty());

    // Reports.
    let doctor = lines(data_dir, Request::Doctor { rebuild: false }).await;
    assert!(doctor.contains("origin: nas@cluster.example"), "{doctor}");
    assert!(doctor.contains("equivocation: none detected"), "{doctor}");
    let rebuilt = lines(data_dir, Request::Doctor { rebuild: true }).await;
    assert!(rebuilt.contains("rebuilt"), "{rebuilt}");
    // Status is the glance, not the byte-identical twin of doctor.
    let status = lines(data_dir, Request::DaemonStatus).await;
    assert!(status.contains("origin nas@cluster.example"), "{status}");
    assert!(status.contains("spaces: 1 (media)"), "{status}");
    assert!(status.contains("head: seq"), "{status}");
    assert!(!status.contains("storage:"), "{status}");

    // Rotation, end to end and operator-driven (§3.4).
    let rotate = lines(data_dir, Request::KeyRotate).await;
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
    let keys = lines(data_dir, Request::KeyLs).await;
    assert_eq!(keys.lines().count(), 3, "{keys}");
    assert_eq!(keys.matches("active").count(), 1, "{keys}");

    let old_key = daemon.node.node_id().to_z32();
    let activated = lines(
        data_dir,
        Request::KeyActivate {
            key: new_key.clone(),
            bind: None,
        },
    )
    .await;
    assert!(activated.contains(&new_key), "{activated}");
    assert_eq!(daemon.node.node_id().to_z32(), new_key);
    assert_eq!(daemon.node.retiring_endpoints().len(), 1);

    let retired = lines(
        data_dir,
        Request::KeyRetire {
            key: old_key.clone(),
        },
    )
    .await;
    assert!(retired.contains("secret deleted"), "{retired}");
    assert!(daemon.node.retiring_endpoints().is_empty());
    // One key, plus the line saying there was nobody to ask about it (§3.4).
    let keys = lines(data_dir, Request::KeyLs).await;
    assert!(keys.contains("bound by 0 of 0 reachable peer(s)"), "{keys}");
    assert!(keys.contains("no trusted peers to ask"), "{keys}");
    assert_eq!(keys.lines().count(), 2, "{keys}");

    // Removing the space unpublishes its entries.
    assert!(lines(data_dir, Request::SpaceRm { id: "media".into() })
        .await
        .contains("unpublished"));

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_sync_that_reaches_nobody_says_so_in_the_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    // A trusted peer with no address fails its dial immediately, which keeps
    // this test fast; the exit contract is the same as for a timeout.
    lines(
        data_dir,
        Request::TrustAdd {
            key: SecretKey::generate().public().to_z32(),
            name: Some("ghost".into()),
            domain: Some("cluster.example".into()),
            note: None,
            addr: None,
        },
    )
    .await;
    let frames = frames(data_dir, Request::SyncNow).await;
    // The per-peer line still streams out before the error frame lands.
    assert_eq!(
        frames.expect_err("reaching zero of one peer is a failure"),
        ErrorCode::Unavailable
    );
    daemon.shutdown().await;
}

/// Reads the `Chunk` payload of a response.
async fn read(data_dir: &Path, request: Request) -> Vec<u8> {
    let frames = frames(data_dir, request).await.expect("a payload");
    frames
        .into_iter()
        .filter_map(|frame| match frame {
            Response::Chunk(bytes) => Some(bytes),
            _ => None,
        })
        .flatten()
        .collect()
}

#[tokio::test]
async fn errors_cross_the_socket_with_their_code() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    assert_eq!(
        failure(
            data_dir,
            Request::Cat {
                reference: "nas@cluster.example:media/absent.txt".into(),
                range: None,
                from: None,
                strict: false,
            }
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
            Request::Ls {
                reference: "nospace".into(),
                all: false,
            }
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Request::Ls {
                reference: "stranger@cluster.example:media".into(),
                all: false,
            }
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Request::Status {
                reference: Some("media/gone.txt".into()),
            }
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(data_dir, Request::SpaceRm { id: "ghost".into() }).await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Request::MirrorRm {
                path: "/no/such/mirror".into(),
            }
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Request::Cat {
                reference: "nas@cluster.example:media/pinned.txt".into(),
                range: None,
                from: Some("laptop@cluster.example".into()),
                strict: false,
            }
        )
        .await,
        ErrorCode::Invalid
    );
    assert_eq!(
        failure(
            data_dir,
            Request::PinAdd {
                target: "not-hex".into()
            }
        )
        .await,
        ErrorCode::Invalid
    );
    assert_eq!(
        failure(
            data_dir,
            Request::TrustAdd {
                key: "not-a-key".into(),
                name: None,
                domain: None,
                note: None,
                addr: None,
            }
        )
        .await,
        ErrorCode::Invalid
    );
    // A key-identified origin has no name to rebind, and `take` of our own
    // entry is a mistake rather than a not-found.
    assert_eq!(
        failure(
            data_dir,
            Request::Take {
                reference: "nas@cluster.example:media/a.txt".into(),
            }
        )
        .await,
        ErrorCode::Invalid
    );
    assert_eq!(
        failure(
            data_dir,
            Request::KeyActivate {
                key: SecretKey::generate().public().to_z32(),
                bind: None,
            }
        )
        .await,
        ErrorCode::NotFound
    );

    daemon.shutdown().await;
}

/// `scan` and `mirror sync` report what they are doing as they do it, in
/// frames the CLI renders and discards (§9.3).
#[tokio::test]
async fn scan_and_mirror_sync_stream_progress() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    let media = space_with(&[("a.txt", b"a")]);
    let notes = space_with(&[("b.txt", b"b")]);
    for (id, space) in [("media", &media), ("notes", &notes)] {
        lines(
            data_dir,
            Request::SpaceAdd {
                id: id.into(),
                path: space.path().to_string_lossy().into_owned(),
            },
        )
        .await;
    }

    let progress = progress_of(data_dir, Request::Scan).await;
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
        Request::MirrorAdd {
            space: "media".into(),
            path: target.path().to_string_lossy().into_owned(),
            policy: None,
        },
    )
    .await;
    let progress = progress_of(data_dir, Request::MirrorSync).await;
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
#[tokio::test]
async fn recover_streams_its_quiesce_and_lifts_the_publishing_floor() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    let space = space_with(&[("notes.txt", b"hello")]);
    lines(
        data_dir,
        Request::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        },
    )
    .await;

    // A peer has advertised a head for this node's own origin at seq 100 — the
    // observation an ordinary `Hello` exchange leaves behind (§5.1).
    daemon
        .node
        .store()
        .record_observed_head(
            daemon.node.origin(),
            100,
            &synch_core::Hash([7u8; 32]),
            true,
            None,
            synch_core::now_ns(),
        )
        .unwrap();

    // Scanning refuses before hashing anything, and says what to run. The
    // node is not broken and the request is not malformed — the state it was
    // made in is what is wrong — so the code says "unavailable" (§3.4).
    let error = failure_message(data_dir, Request::Scan).await;
    assert_eq!(error.code, ErrorCode::Unavailable, "{error:?}");
    assert!(error.message.contains("synch recover"), "{error:?}");
    assert!(error.message.contains("seq 100"), "{error:?}");

    // Doctor says the same thing in its own words.
    let doctor = lines(data_dir, Request::Doctor { rebuild: false }).await;
    assert!(doctor.contains("KEY-LOSS RECOVERY"), "{doctor}");
    assert!(doctor.contains("seq 100"), "{doctor}");

    let request = Request::Recover {
        wait: Some("0".into()),
        gap: Some(5),
    };
    let all = frames(data_dir, request).await.expect("recover should run");
    let progress: Vec<String> = all
        .iter()
        .filter_map(|frame| match frame {
            Response::Progress(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(progress.len(), 1, "{progress:?}");
    assert!(progress[0].contains("round 1"), "{progress:?}");
    assert!(progress[0].contains("highest seq seen 100"), "{progress:?}");
    let text: Vec<String> = all
        .iter()
        .filter_map(|frame| match frame {
            Response::Line(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    let text = text.join("\n");
    assert!(text.contains("is in recovery"), "{text}");
    assert!(text.contains("publishing resumes at seq 105"), "{text}");

    // And the node publishes again, above everything that was advertised.
    let scan = lines(data_dir, Request::Scan).await;
    assert!(scan.contains("published seq 105"), "{scan}");

    let doctor = lines(data_dir, Request::Doctor { rebuild: false }).await;
    assert!(!doctor.contains("KEY-LOSS RECOVERY"), "{doctor}");

    // A duration this program cannot read fails before any waiting happens.
    let error = failure_message(
        data_dir,
        Request::Recover {
            wait: Some("whenever".into()),
            gap: None,
        },
    )
    .await;
    assert_eq!(error.code, ErrorCode::Invalid);
    assert!(error.message.contains("--wait"), "{error:?}");

    daemon.shutdown().await;
}

/// A client that walks away mid-quiesce leaves nothing behind: the daemon
/// keeps serving, and the publishing floor is untouched (§3.4).
#[tokio::test]
async fn a_client_that_hangs_up_mid_quiesce_leaves_the_floor_alone() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    daemon
        .node
        .store()
        .record_observed_head(
            daemon.node.origin(),
            100,
            &synch_core::Hash([7u8; 32]),
            true,
            None,
            synch_core::now_ns(),
        )
        .unwrap();

    // An hour-long quiesce, abandoned as soon as it has said something.
    let mut client = Client::connect(data_dir).await.unwrap();
    client
        .send(&Request::Recover {
            wait: Some("1h".into()),
            gap: None,
        })
        .await
        .unwrap();
    let first = tokio::time::timeout(std::time::Duration::from_secs(30), client.next())
        .await
        .expect("the quiesce must report as it goes")
        .unwrap()
        .unwrap();
    assert!(matches!(first, Response::Line(_) | Response::Progress(_)));
    drop(client);

    // The daemon is still there, and nothing was half-applied.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let id = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        lines(data_dir, Request::Id),
    )
    .await
    .expect("the daemon must keep serving");
    assert!(id.contains("nas@cluster.example"), "{id}");
    assert_eq!(daemon.node.store().publish_floor().unwrap(), None);
    assert!(daemon.node.recovery_state().unwrap().in_recovery);

    daemon.shutdown().await;
}

/// The structured error a failing request produces, message and all.
async fn failure_message(
    data_dir: &Path,
    request: Request,
) -> synch_cli::control::proto::ControlError {
    let mut client = Client::connect(data_dir).await.unwrap();
    client.send(&request).await.unwrap();
    loop {
        match client.next().await {
            Ok(Some(_)) => {}
            Ok(None) => panic!("the request should have failed"),
            Err(e) => return e,
        }
    }
}

/// The `Progress` frames of a response.
async fn progress_of(data_dir: &Path, request: Request) -> Vec<String> {
    frames(data_dir, request)
        .await
        .expect("the request should have succeeded")
        .into_iter()
        .filter_map(|frame| match frame {
            Response::Progress(text) => Some(text),
            _ => None,
        })
        .collect()
}

/// A multi-megabyte read must arrive as a sequence of bounded chunks, not as
/// one buffered payload (§9.3).
#[tokio::test]
async fn a_multi_megabyte_cat_streams_in_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    let size = 5 * 1024 * 1024 + 12_345;
    let payload: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let space = space_with(&[("big.bin", &payload)]);
    lines(
        data_dir,
        Request::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        },
    )
    .await;
    lines(data_dir, Request::Scan).await;

    let mut client = Client::connect(data_dir).await.unwrap();
    client
        .send(&Request::Cat {
            reference: "media/big.bin".into(),
            range: None,
            from: None,
            strict: false,
        })
        .await
        .unwrap();

    let mut chunks = 0usize;
    let mut received: Vec<u8> = Vec::new();
    let mut delivered_before_the_end = 0usize;
    while let Some(frame) = client.next().await.unwrap() {
        match frame {
            Response::Chunk(bytes) => {
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
        Request::Cat {
            reference: "media/big.bin".into(),
            range: Some("1000000..1500000".into()),
            from: None,
            strict: false,
        },
    )
    .await;
    assert_eq!(ranged, payload[1_000_000..1_500_000]);

    daemon.shutdown().await;
}

/// The `Entry` frames of a response.
async fn entries(data_dir: &Path, request: Request) -> Vec<EntryInfo> {
    frames(data_dir, request)
        .await
        .unwrap_or_else(|code| panic!("request failed: {}", code.as_str()))
        .into_iter()
        .filter_map(|frame| match frame {
            Response::Entry(info) => Some(*info),
            _ => None,
        })
        .collect()
}

/// The structured requests §9.4 gives the gateway: a listing and a resolve that
/// answer in entry metadata rather than in rendered lines, and that name space,
/// path, and policy as fields — an S3 key may contain a colon, which the text
/// reference form would read as an origin.
#[tokio::test]
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
        Request::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        },
    )
    .await;
    lines(data_dir, Request::Scan).await;

    let listed = entries(
        data_dir,
        Request::TreeList {
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
        Request::TreeList {
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
        Request::TreeList {
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
        let resolved = entries(
            data_dir,
            Request::TreeResolve {
                space: "media".into(),
                path: "odd:key.txt".into(),
                policy: None,
            },
        )
        .await;
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].size, 5);
        let payload = read(
            data_dir,
            Request::TreeRead {
                space: "media".into(),
                path: "odd:key.txt".into(),
                policy: None,
                start: 1,
                len: Some(3),
            },
        )
        .await;
        assert_eq!(payload, b"olo");
    }

    assert_eq!(
        failure(
            data_dir,
            Request::TreeResolve {
                space: "media".into(),
                path: "absent.txt".into(),
                policy: None,
            }
        )
        .await,
        ErrorCode::NotFound
    );

    daemon.shutdown().await;
}

/// A divergent path is left out of a `strict` listing rather than answered with
/// one side's metadata, and resolving it directly says what is wrong (§8).
#[tokio::test]
async fn a_strict_listing_omits_what_a_strict_resolve_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let space = space_with(&[("shared.txt", b"ours"), ("agreed.txt", b"only one")]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    lines(
        data_dir,
        Request::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        },
    )
    .await;
    lines(data_dir, Request::Scan).await;

    let peer = OriginId::named("laptop", "cluster.example").unwrap();
    let root = daemon
        .node
        .store()
        .ingest_bytes(b"theirs", synch_core::now_ns())
        .unwrap();
    daemon
        .node
        .store()
        .put_entry(
            &peer,
            "media",
            "shared.txt",
            &synch_core::FileEntry::file(6, i64::MAX, root, 4),
        )
        .unwrap();

    let strict = Some("strict".to_string());
    let listed = entries(
        data_dir,
        Request::TreeList {
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
        failure(
            data_dir,
            Request::TreeResolve {
                space: "media".into(),
                path: "shared.txt".into(),
                policy: strict,
            }
        )
        .await,
        ErrorCode::Divergent
    );

    // `newest` picks the winning version and says the path carries two.
    let resolved = entries(
        data_dir,
        Request::TreeResolve {
            space: "media".into(),
            path: "shared.txt".into(),
            policy: None,
        },
    )
    .await;
    assert_eq!(resolved[0].versions, 2);
    assert_eq!(resolved[0].origin, "laptop@cluster.example");

    daemon.shutdown().await;
}

/// A streamed write crosses the socket a chunk at a time, lands in the space,
/// and comes back as a published entry (§9.4).
#[tokio::test]
async fn a_streamed_put_publishes_without_buffering_the_object() {
    let dir = tempfile::tempdir().unwrap();
    let space = space_with(&[]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    lines(
        data_dir,
        Request::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        },
    )
    .await;

    let payload: Vec<u8> = (0..1_500_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut client = Client::connect(data_dir).await.unwrap();
    client
        .send(&Request::TreePut {
            space: "media".into(),
            path: "uploads/report.bin".into(),
        })
        .await
        .unwrap();
    assert!(
        matches!(client.next().await.unwrap(), Some(Response::Ready)),
        "the daemon acks a write before the first byte"
    );
    for piece in payload.chunks(CHUNK_SIZE) {
        client.upload(&Upload::Chunk(piece.to_vec())).await.unwrap();
    }
    client.upload(&Upload::End).await.unwrap();

    let mut published = None;
    while let Some(frame) = client.next().await.unwrap() {
        if let Response::Entry(info) = frame {
            published = Some(*info);
        }
    }
    let published = published.expect("the write answers with its published entry");
    assert_eq!(published.size, payload.len() as u64);
    assert_eq!(published.content, Some(synch_core::Hash::new(&payload)));
    assert_eq!(published.origin, "nas@cluster.example");
    assert_eq!(
        std::fs::read(space.path().join("uploads/report.bin")).unwrap(),
        payload
    );

    // It reads straight back out, and the space holds nothing else: the staging
    // file went away with the commit.
    let back = read(
        data_dir,
        Request::TreeRead {
            space: "media".into(),
            path: "uploads/report.bin".into(),
            policy: None,
            start: 0,
            len: None,
        },
    )
    .await;
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
#[tokio::test]
async fn an_abandoned_write_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let space = space_with(&[("kept.txt", b"kept")]);
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();
    lines(
        data_dir,
        Request::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        },
    )
    .await;
    lines(data_dir, Request::Scan).await;

    let mut client = Client::connect(data_dir).await.unwrap();
    client
        .send(&Request::TreePut {
            space: "media".into(),
            path: "kept.txt".into(),
        })
        .await
        .unwrap();
    assert!(
        matches!(client.next().await.unwrap(), Some(Response::Ready)),
        "the daemon acks a write before the first byte"
    );
    client
        .upload(&Upload::Chunk(b"half an object".to_vec()))
        .await
        .unwrap();
    client
        .upload(&Upload::Abort("the body was truncated".into()))
        .await
        .unwrap();
    let error = loop {
        match client.next().await {
            Ok(Some(_)) => {}
            Ok(None) => panic!("an abandoned write must fail"),
            Err(e) => break e,
        }
    };
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
#[tokio::test]
async fn gateway_config_appends_within_its_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let data_dir = dir.path();

    assert!(lines(
        data_dir,
        Request::ConfigGet {
            key: "s3.buckets".into()
        }
    )
    .await
    .is_empty());

    for record in ["photos\tmedia\tnewest", "docs\tpapers\tstrict"] {
        lines(
            data_dir,
            Request::ConfigAppend {
                key: "s3.buckets".into(),
                record: record.into(),
            },
        )
        .await;
    }
    let stored = lines(
        data_dir,
        Request::ConfigGet {
            key: "s3.buckets".into(),
        },
    )
    .await;
    assert_eq!(
        stored.lines().collect::<Vec<_>>(),
        vec!["photos\tmedia\tnewest", "docs\tpapers\tstrict"],
        "records arrive in the order they were appended"
    );

    // Nothing outside the namespace is reachable, in either direction.
    for key in ["self_origin_id", "schema_version", "s3", "s3."] {
        assert_eq!(
            failure(data_dir, Request::ConfigGet { key: key.into() }).await,
            ErrorCode::Invalid,
            "{key} must not be readable"
        );
        assert_eq!(
            failure(
                data_dir,
                Request::ConfigAppend {
                    key: key.into(),
                    record: "x".into(),
                }
            )
            .await,
            ErrorCode::Invalid,
            "{key} must not be writable"
        );
    }
    assert_eq!(
        daemon
            .node
            .store()
            .config("self_origin_id")
            .unwrap()
            .unwrap(),
        "nas@cluster.example"
    );

    // A record is one line: a newline would forge a second record.
    assert_eq!(
        failure(
            data_dir,
            Request::ConfigAppend {
                key: "s3.keys".into(),
                record: "id\tsecret\nsmuggled\tin".into(),
            }
        )
        .await,
        ErrorCode::Invalid
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_bad_token_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    let error = Client::connect_with_token(dir.path(), vec![0u8; 32])
        .await
        .expect_err("a forged token must not open a session");
    assert_eq!(error.code, ErrorCode::Unauthorized);
    assert!(error.message.contains("control.token"), "{error}");

    // A truncated token is rejected on length alone, and the real one still
    // works afterwards.
    let error = Client::connect_with_token(dir.path(), vec![1u8; 8])
        .await
        .expect_err("a short token must not open a session");
    assert_eq!(error.code, ErrorCode::Unauthorized);
    assert!(Client::connect(dir.path()).await.is_ok());

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_version_mismatch_names_both_versions() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    let error = Client::connect_as(dir.path(), CONTROL_VERSION + 7)
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

#[tokio::test]
async fn there_is_no_daemon_error_naming_the_socket_and_the_command() {
    let dir = tempfile::tempdir().unwrap();
    Node::init(dir.path(), None).unwrap();

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

#[tokio::test]
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
#[tokio::test]
async fn a_stale_socket_is_cleared_on_start() {
    let dir = tempfile::tempdir().unwrap();
    Node::init(
        dir.path(),
        Some(OriginId::named("nas", "cluster.example").unwrap()),
    )
    .unwrap();

    // What a killed daemon leaves: a bound socket file with nothing listening.
    let path = synch_cli::control::transport::socket_path(dir.path());
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    drop(listener);
    assert!(path.exists(), "the stale socket file is still there");
    assert!(tokio::net::UnixStream::connect(&path).await.is_err());

    let daemon = Daemon::reopen(dir.path()).await;
    assert!(lines(dir.path(), Request::Id)
        .await
        .contains("nas@cluster.example"));
    daemon.shutdown().await;
}

#[tokio::test]
async fn daemon_stop_ends_the_server_and_clears_the_token() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;

    assert!(lines(dir.path(), Request::DaemonStop)
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
#[tokio::test]
async fn the_token_is_regenerated_on_every_start() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path()).await;
    let first = synch_cli::control::transport::read_token(dir.path()).unwrap();
    daemon.shutdown().await;

    let daemon = Daemon::reopen(dir.path()).await;
    let second = synch_cli::control::transport::read_token(dir.path()).unwrap();
    assert_ne!(first, second);

    let error = Client::connect_with_token(dir.path(), first)
        .await
        .expect_err("the previous run's token is worthless");
    assert_eq!(error.code, ErrorCode::Unauthorized);
    daemon.shutdown().await;
}

#[tokio::test]
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
        Request::SpaceAdd {
            id: "media".into(),
            path: space.path().to_string_lossy().into_owned(),
        },
    )
    .await;
    lines(data_dir, Request::Scan).await;

    let peer = OriginId::named("laptop", "cluster.example").unwrap();
    // The peer publishes a live version of `kept.txt` with the same bytes we
    // could fetch locally, and a tombstone for `shared.txt`.
    let root = daemon
        .node
        .store()
        .ingest_bytes(b"theirs", synch_core::now_ns())
        .unwrap();
    daemon
        .node
        .store()
        .put_entry(
            &peer,
            "media",
            "kept.txt",
            &synch_core::FileEntry::file(6, 9_000, root, 4),
        )
        .unwrap();
    daemon
        .node
        .store()
        .put_entry(
            &peer,
            "media",
            "shared.txt",
            &synch_core::FileEntry::tombstone(9_000, 4, None),
        )
        .unwrap();

    // Taking a live version still works exactly as it did.
    let taken = lines(
        data_dir,
        Request::Take {
            reference: "laptop@cluster.example:media/kept.txt".into(),
        },
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
        Request::Take {
            reference: "laptop@cluster.example:media/shared.txt".into(),
        },
    )
    .await;
    assert!(taken.contains("removed"), "{taken}");
    assert!(taken.contains("published seq"), "{taken}");
    assert!(!space.path().join("shared.txt").exists());

    let set = daemon.node.versions("media", "shared.txt").unwrap();
    assert_eq!(set.version_count(), 1, "{:?}", set.versions);
    assert!(set.versions[0].is_tombstone());
    assert!(!set.exists(), "the path has left the unified tree");

    // Taking a deletion of something we never had says so rather than failing.
    daemon
        .node
        .store()
        .put_entry(
            &peer,
            "media",
            "never-ours.txt",
            &synch_core::FileEntry::tombstone(9_000, 4, None),
        )
        .unwrap();
    let taken = lines(
        data_dir,
        Request::Take {
            reference: "laptop@cluster.example:media/never-ours.txt".into(),
        },
    )
    .await;
    assert!(taken.contains("already absent"), "{taken}");

    daemon.shutdown().await;
}
