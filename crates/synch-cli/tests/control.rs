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
    Client, ErrorCode, Request, Server,
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
    assert_eq!(lines(data_dir, Request::KeyLs).await.lines().count(), 1);

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
    assert!(status.contains("[agree]"), "{status}");
    assert!(lines(data_dir, Request::Status { reference: None })
        .await
        .contains("media/notes.txt"));

    // Reads, in full and by range.
    let payload = read(
        data_dir,
        Request::Cat {
            reference: "nas@cluster.example:media/notes.txt".into(),
            range: None,
        },
    )
    .await;
    assert_eq!(payload, b"hello");
    let payload = read(
        data_dir,
        Request::Cat {
            reference: "nas@cluster.example:media/notes.txt".into(),
            range: Some("1..3".into()),
        },
    )
    .await;
    assert_eq!(payload, b"el");
    let payload = read(
        data_dir,
        Request::Get {
            reference: "nas@cluster.example:media/notes.txt".into(),
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
    assert!(lines(
        data_dir,
        Request::TrustRm {
            origin: "laptop@cluster.example".into(),
        }
    )
    .await
    .contains("removed 2 binding(s)"));

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
    let _ = frames(data_dir, Request::DomainRefresh).await;
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
    assert!(lines(
        data_dir,
        Request::MirrorAdd {
            reference: "laptop@cluster.example:media".into(),
            path: mirror_dir.path().to_string_lossy().into_owned(),
        }
    )
    .await
    .contains("mirroring"));
    assert!(lines(data_dir, Request::MirrorLs).await.contains("media"));
    let _ = frames(data_dir, Request::MirrorSync).await.unwrap();
    assert!(lines(
        data_dir,
        Request::MirrorRm {
            reference: "laptop@cluster.example:media".into(),
        }
    )
    .await
    .contains("removed"));

    // Pins.
    let root = blake3::hash(b"hello").to_hex().to_string();
    assert!(lines(data_dir, Request::PinAdd { root: root.clone() })
        .await
        .contains(&root));
    assert!(lines(data_dir, Request::PinLs).await.contains(&root));
    assert!(lines(data_dir, Request::PinRm { root: root.clone() })
        .await
        .contains(&root));
    assert!(lines(data_dir, Request::PinLs).await.is_empty());

    // Reports.
    let doctor = lines(data_dir, Request::Doctor { rebuild: false }).await;
    assert!(doctor.contains("origin: nas@cluster.example"), "{doctor}");
    assert!(doctor.contains("equivocation: none detected"), "{doctor}");
    let rebuilt = lines(data_dir, Request::Doctor { rebuild: true }).await;
    assert!(rebuilt.contains("rebuilt"), "{rebuilt}");
    assert!(lines(data_dir, Request::DaemonStatus)
        .await
        .contains("storage:"));

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
    assert_eq!(keys.lines().count(), 2, "{keys}");
    assert_eq!(keys.matches("active").count(), 1, "{keys}");

    let old_key = daemon.node.node_id().to_z32();
    let activated = lines(
        data_dir,
        Request::KeyActivate {
            key: new_key.clone(),
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
    assert_eq!(lines(data_dir, Request::KeyLs).await.lines().count(), 1);

    // Removing the space unpublishes its entries.
    assert!(lines(data_dir, Request::SpaceRm { id: "media".into() })
        .await
        .contains("unpublished"));

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
            }
        )
        .await,
        ErrorCode::NotFound
    );
    assert_eq!(
        failure(
            data_dir,
            Request::Cat {
                reference: "media/no-origin.txt".into(),
                range: None,
            }
        )
        .await,
        ErrorCode::Invalid
    );
    assert_eq!(
        failure(
            data_dir,
            Request::PinAdd {
                root: "not-hex".into()
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
            reference: "laptop@cluster.example:media".into(),
            path: target.path().to_string_lossy().into_owned(),
        },
    )
    .await;
    let progress = progress_of(data_dir, Request::MirrorSync).await;
    assert!(
        progress
            .iter()
            .any(|line| line.contains("laptop@cluster.example:media")),
        "{progress:?}"
    );

    daemon.shutdown().await;
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
            reference: "nas@cluster.example:media/big.bin".into(),
            range: None,
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
            reference: "nas@cluster.example:media/big.bin".into(),
            range: Some("1000000..1500000".into()),
        },
    )
    .await;
    assert_eq!(ranged, payload[1_000_000..1_500_000]);

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
