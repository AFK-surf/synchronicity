//! Drives the gateway over real HTTP on an ephemeral port with a plain client
//! (§11 testing strategy): GET/HEAD/LIST/PUT round-trips, a Range read, ETag
//! checks, and byte-exactness.
//!
//! The daemon is a real one — same `Server`, same control socket, same token —
//! and the gateway reaches it only through that socket, which is the property
//! §9.4 is actually about. Nothing here hands the gateway a `Node`, because
//! nothing can: it has no way to take one.

use std::{net::SocketAddr, path::Path};

use synch_cli::control::Server;
use synch_engine::{Node, NodeConfig};
use synch_s3::{
    auth::{AccessKey, AuthMode},
    buckets,
    daemon::Daemon,
    Gateway,
};
use tokio::sync::broadcast;

struct Harness {
    _data: tempfile::TempDir,
    _space: tempfile::TempDir,
    space_path: std::path::PathBuf,
    /// The node the *daemon* owns. Held here so a test can assert on the state
    /// behind the socket; the gateway has no access to it.
    node: Node,
    daemon: Daemon,
    stop: broadcast::Sender<()>,
    served: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    base: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl Harness {
    async fn start(auth: AuthMode) -> Harness {
        let data = tempfile::tempdir().unwrap();
        let space = tempfile::tempdir().unwrap();
        Node::init(data.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
        node.add_space("media", space.path()).unwrap();

        let (stop, _) = broadcast::channel(1);
        let control = Server::bind(node.clone(), stop.clone()).await.unwrap();
        let served = tokio::spawn(control.run());
        let daemon = Daemon::new(data.path());

        // The default policy over the unified tree, an origin pin on a
        // foreign origin, and a strict bucket over the same space (§9.4).
        buckets::add(&daemon, "my-media", "media", None)
            .await
            .unwrap();
        buckets::add(&daemon, "nas-media", "nas@cluster.example:media", None)
            .await
            .unwrap();
        buckets::add(&daemon, "strict-media", "media", Some("strict"))
            .await
            .unwrap();

        let gateway = Gateway::new(daemon.clone(), auth).await.unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let bound = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, gateway.router())
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });

        Harness {
            _data: data,
            space_path: space.path().to_path_buf(),
            _space: space,
            node,
            daemon,
            stop,
            served: Some(served),
            base: format!("http://{bound}"),
            shutdown: Some(tx),
            server: Some(server),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Writes a file into the local space and publishes it.
    fn publish(&self, path: &str, content: &[u8]) {
        write_into(&self.space_path, path, content);
        self.node.scan_and_publish().unwrap();
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(server) = self.server.take() {
            let _ = server.await;
        }
        let _ = self.stop.send(());
        if let Some(served) = self.served.take() {
            let _ = served.await;
        }
        self.node.shutdown().await.unwrap();
    }
}

fn write_into(root: &Path, path: &str, content: &[u8]) {
    let target = root.join(path);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(target, content).unwrap();
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}

#[tokio::test]
async fn get_head_list_and_range_round_trip() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i * 17 + 3) as u8).collect();
    harness.publish("notes.txt", b"hello from s3");
    harness.publish("talks/keynote.mp4", &payload);
    harness.publish("talks/slides.pdf", b"slides");

    let http = client();

    // GetObject, byte-exact, with the ETag as the quoted blake3 root.
    let response = http
        .get(harness.url("/my-media/notes.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let etag = response
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        etag,
        format!("\"{}\"", blake3::hash(b"hello from s3").to_hex())
    );
    // The Last-Modified *header* is RFC 7231 HTTP-date, not the RFC 3339 the
    // XML body carries — SDKs parse it strictly and rclone refused the
    // wrong shape outright.
    let last_modified = response
        .headers()
        .get("last-modified")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        last_modified.ends_with(" GMT")
            && last_modified.as_bytes()[3] == b','
            && !last_modified.contains('-'),
        "not an HTTP-date: {last_modified}"
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"hello from s3");

    // The SDK write path probes with HeadBucket and CreateBucket before an
    // upload; a mapped bucket answers both, an unmapped one 404s.
    for method in [reqwest::Method::HEAD, reqwest::Method::PUT] {
        let response = http
            .request(method.clone(), harness.url("/my-media"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{method} on a mapped bucket");
        let response = http
            .request(method.clone(), harness.url("/not-mapped"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "{method} on an unmapped bucket");
    }

    // A large object comes back byte-for-byte, and its declared length is the
    // object's — a streamed body must still say how long it is.
    let response = http
        .get(harness.url("/my-media/talks/keynote.mp4"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("content-length").unwrap(),
        &payload.len().to_string()
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), payload.as_slice());

    // HeadObject: metadata straight from the entry, no body.
    let response = http
        .head(harness.url("/my-media/talks/keynote.mp4"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("content-length").unwrap(),
        &payload.len().to_string()
    );
    assert_eq!(
        response.headers().get("etag").unwrap().to_str().unwrap(),
        format!("\"{}\"", blake3::hash(&payload).to_hex())
    );
    assert_eq!(response.headers().get("accept-ranges").unwrap(), "bytes");
    assert!(response.bytes().await.unwrap().is_empty());

    // A Range read, served as a verified range read.
    let response = http
        .get(harness.url("/my-media/talks/keynote.mp4"))
        .header("Range", "bytes=100000-100099")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 206);
    assert_eq!(
        response.headers().get("content-range").unwrap(),
        &format!("bytes 100000-100099/{}", payload.len())
    );
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        &payload[100_000..100_100]
    );

    // A suffix range.
    let response = http
        .get(harness.url("/my-media/notes.txt"))
        .header("Range", "bytes=-3")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 206);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b" s3");

    // An unsatisfiable range is refused, not silently clamped to nothing.
    let response = http
        .get(harness.url("/my-media/notes.txt"))
        .header("Range", "bytes=9999-99999")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 416);

    // ListObjectsV2 over the whole bucket.
    let body = http
        .get(harness.url("/my-media?list-type=2"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<Key>notes.txt</Key>"), "{body}");
    assert!(body.contains("<Key>talks/keynote.mp4</Key>"), "{body}");
    assert!(body.contains("<KeyCount>3</KeyCount>"), "{body}");
    assert!(
        body.contains(&format!("&quot;{}&quot;", blake3::hash(b"slides").to_hex())),
        "{body}"
    );

    // A prefix narrows it.
    let body = http
        .get(harness.url("/my-media?list-type=2&prefix=talks/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<Key>talks/keynote.mp4</Key>"), "{body}");
    assert!(!body.contains("<Key>notes.txt</Key>"), "{body}");

    // A delimiter rolls directories up into common prefixes.
    let body = http
        .get(harness.url("/my-media?list-type=2&delimiter=%2F"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<Key>notes.txt</Key>"), "{body}");
    assert!(body.contains("<Prefix>talks/</Prefix>"), "{body}");
    assert!(!body.contains("<Key>talks/keynote.mp4</Key>"), "{body}");

    // Continuation tokens page through the listing.
    let body = http
        .get(harness.url("/my-media?list-type=2&max-keys=1"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "{body}");
    assert!(body.contains("<Key>notes.txt</Key>"), "{body}");
    let token = body
        .split("<NextContinuationToken>")
        .nth(1)
        .and_then(|rest| rest.split("</NextContinuationToken>").next())
        .expect("a continuation token")
        .to_string();
    let body = http
        .get(harness.url(&format!(
            "/my-media?list-type=2&max-keys=5&continuation-token={}",
            urlencode(&token)
        )))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!body.contains("<Key>notes.txt</Key>"), "{body}");
    assert!(body.contains("<Key>talks/keynote.mp4</Key>"), "{body}");

    // A missing key and a missing bucket both produce the S3 error codes.
    let response = http
        .get(harness.url("/my-media/absent.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert!(response.text().await.unwrap().contains("NoSuchKey"));

    let response = http.get(harness.url("/no-bucket/x")).send().await.unwrap();
    assert_eq!(response.status(), 404);
    assert!(response.text().await.unwrap().contains("NoSuchBucket"));

    // ListBuckets at the service root.
    let body = http
        .get(harness.url("/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<Name>my-media</Name>"), "{body}");
    assert!(body.contains("<Name>nas-media</Name>"), "{body}");

    harness.stop().await;
}

/// An object far larger than one control-socket chunk crosses the gateway in
/// both directions without either process holding it (§9.4). Byte-exactness at
/// this size is the observable half of that; the bounded channel and the
/// daemon's staging file are the mechanism.
#[tokio::test]
async fn a_large_object_streams_through_in_both_directions() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let payload: Vec<u8> = (0..3_000_000u32).map(|i| (i * 31 % 251) as u8).collect();

    let response = http
        .put(harness.url("/my-media/uploads/big.bin"))
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("etag").unwrap().to_str().unwrap(),
        format!("\"{}\"", blake3::hash(&payload).to_hex())
    );

    let response = http
        .get(harness.url("/my-media/uploads/big.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), payload.as_slice());

    // A range in the middle of it reads without touching the rest.
    let response = http
        .get(harness.url("/my-media/uploads/big.bin"))
        .header("Range", "bytes=2000000-2000999")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 206);
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        &payload[2_000_000..2_001_000]
    );

    harness.stop().await;
}

#[tokio::test]
async fn put_object_publishes_into_the_local_space() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let payload: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();

    let response = http
        .put(harness.url("/my-media/uploads/report.bin"))
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("etag").unwrap().to_str().unwrap(),
        format!("\"{}\"", blake3::hash(&payload).to_hex())
    );

    // It landed in the local space directory and was published as our entry.
    assert_eq!(
        std::fs::read(harness.space_path.join("uploads/report.bin")).unwrap(),
        payload
    );
    let entry = harness
        .node
        .store()
        .entry(harness.node.origin(), "media", "uploads/report.bin")
        .unwrap()
        .unwrap();
    assert_eq!(entry.size, payload.len() as u64);

    // And it reads straight back out through the gateway.
    let got = http
        .get(harness.url("/my-media/uploads/report.bin"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(got.as_ref(), payload.as_slice());

    harness.stop().await;
}

/// A node in key-loss recovery cannot publish, so it cannot accept a write
/// either. That surfaces as an S3 error naming the command that clears it,
/// rather than a panic or a silently dropped upload (§3.4, §9.4).
#[tokio::test]
async fn put_object_is_refused_while_the_node_is_in_recovery() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    harness
        .node
        .store()
        .record_observed_head(
            harness.node.origin(),
            100,
            &synch_core::Hash([7u8; 32]),
            true,
            None,
            synch_core::now_ns(),
        )
        .unwrap();

    let response = client()
        .put(harness.url("/my-media/uploads/report.bin"))
        .body("some bytes")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let body = response.text().await.unwrap();
    assert!(body.contains("ServiceUnavailable"), "{body}");
    assert!(body.contains("synch recover"), "{body}");

    // Nothing was published under a seq the cluster would refuse, and nothing
    // was written into the space either.
    assert!(harness
        .node
        .store()
        .complete_head(harness.node.origin())
        .unwrap()
        .is_none());
    assert!(!harness.space_path.join("uploads").exists());

    harness.stop().await;
}

/// §9.4: a write is always a publish of the *local* node's view, so a bucket
/// pinned to a foreign origin still accepts it — but its reads keep serving
/// the pinned origin, which is why the gateway warns about that shape.
#[tokio::test]
async fn a_foreign_pinned_bucket_writes_our_view_and_reads_theirs() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let response = http
        .put(harness.url("/nas-media/ours.txt"))
        .body("ours")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // It landed in our own view...
    let response = http
        .get(harness.url("/my-media/ours.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"ours");

    // ...and not in the pinned origin's, which is what the bucket serves.
    let response = http
        .get(harness.url("/nas-media/ours.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    let ours = harness.daemon.origin().await.unwrap();
    let bucket = buckets::find(&harness.daemon, "nas-media").await.unwrap();
    assert!(bucket.pins_a_foreign_origin(&ours));
    let warning = bucket.foreign_pin_warning(&ours).unwrap();
    assert!(warning.contains("read-only"), "{warning}");
    harness.stop().await;
}

/// §8, §9.4: `newest` serves the winning version, `strict` answers a divergent
/// key with 409 naming the versions, and the unified listing shows one key.
#[tokio::test]
async fn divergent_keys_are_served_by_policy() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    harness.publish("shared.txt", b"ours");

    // A peer publishes a different version of the same path. Only the peer's
    // own assertion is ever written — this is the read model diverging, not a
    // write path into someone else's trie.
    let peer = synch_core::OriginId::named("nas", "cluster.example").unwrap();
    let theirs = b"theirs";
    let root = harness
        .node
        .store()
        .ingest_bytes(theirs, synch_core::now_ns())
        .unwrap();
    let ours = harness
        .node
        .store()
        .entry(harness.node.origin(), "media", "shared.txt")
        .unwrap()
        .unwrap();
    harness
        .node
        .store()
        .put_entry(
            &peer,
            "media",
            "shared.txt",
            &synch_core::FileEntry::file(theirs.len() as u64, ours.mtime_ns + 1_000, root, 1),
        )
        .unwrap();

    // The unified listing carries one key for the path, not one per origin.
    let body = http
        .get(harness.url("/my-media?list-type=2"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body.matches("<Key>shared.txt</Key>").count(), 1, "{body}");

    // `newest` serves the winning version, and its ETag is that version's root.
    let response = http
        .get(harness.url("/my-media/shared.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["etag"].to_str().unwrap(),
        format!("\"{}\"", blake3::hash(theirs).to_hex())
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), theirs);

    // A strict bucket refuses the key with 409 and names both versions.
    let response = http
        .get(harness.url("/strict-media/shared.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);
    let body = response.text().await.unwrap();
    assert!(body.contains("DivergentVersions"), "{body}");
    assert!(body.contains("nas@cluster.example"), "{body}");
    assert!(
        body.contains(&blake3::hash(theirs).to_hex().to_string()),
        "{body}"
    );
    assert!(body.contains("<Resource>shared.txt</Resource>"), "{body}");

    // HEAD refuses it the same way.
    let response = http
        .head(harness.url("/strict-media/shared.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);

    // An undisputed key in the same strict bucket still reads.
    harness.publish("undisputed.txt", b"only one");
    let response = http
        .get(harness.url("/strict-media/undisputed.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // And the strict bucket leaves the divergent key out of its listing
    // rather than handing over one side's metadata.
    let body = http
        .get(harness.url("/strict-media?list-type=2"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!body.contains("<Key>shared.txt</Key>"), "{body}");
    assert!(body.contains("<Key>undisputed.txt</Key>"), "{body}");
    harness.stop().await;
}

/// A symlink is not an S3 object: its version identity is its target rather
/// than content (§8), so it has no root to be an ETag and no bytes to serve.
/// It stays out of listings, and a direct read of it is a missing key —
/// otherwise the gateway would advertise a key whose GET can only fail.
#[cfg(unix)]
#[tokio::test]
async fn symlink_keys_are_not_objects() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    harness.publish("real.txt", b"the real thing");
    std::os::unix::fs::symlink("real.txt", harness.space_path.join("link.txt")).unwrap();
    harness.node.scan_and_publish().unwrap();

    // The daemon does track the symlink — this is the gateway declining to
    // present it, not the tree forgetting it.
    let entry = harness
        .node
        .store()
        .entry(harness.node.origin(), "media", "link.txt")
        .unwrap()
        .unwrap();
    assert_eq!(entry.kind, synch_core::EntryKind::Symlink);
    assert_eq!(entry.symlink_target.as_deref(), Some("real.txt"));

    let body = http
        .get(harness.url("/my-media?list-type=2"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<Key>real.txt</Key>"), "{body}");
    assert!(!body.contains("<Key>link.txt</Key>"), "{body}");
    assert!(body.contains("<KeyCount>1</KeyCount>"), "{body}");

    for method in ["GET", "HEAD"] {
        let response = http
            .request(method.parse().unwrap(), harness.url("/my-media/link.txt"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "{method}");
    }

    // Writing to the same key is still an ordinary write: it replaces the link
    // with a file, and the file is an object like any other.
    let response = http
        .put(harness.url("/my-media/link.txt"))
        .body("now a file")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response = http
        .get(harness.url("/my-media/link.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"now a file");

    harness.stop().await;
}

#[tokio::test]
async fn deferred_operations_report_not_implemented() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let response = http
        .delete(harness.url("/my-media/notes.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 501);
    assert!(response.text().await.unwrap().contains("NotImplemented"));
    harness.stop().await;
}

/// Buckets and access keys live in the daemon's `s3.*` config namespace, and
/// the gateway edits them by appending records over the socket (§9.4).
#[tokio::test]
async fn bucket_and_key_configuration_lives_in_the_daemon() {
    let harness = Harness::start(AuthMode::Anonymous).await;

    // The buckets the harness added are the daemon's rows, not a file of ours.
    let stored = harness
        .node
        .store()
        .config(buckets::BUCKETS_CONFIG)
        .unwrap()
        .unwrap();
    assert_eq!(stored.lines().count(), 3, "{stored}");

    // Replacing a mapping appends rather than rewriting, and the fold makes the
    // last record win.
    buckets::add(&harness.daemon, "my-media", "media", Some("strict"))
        .await
        .unwrap();
    let stored = harness
        .node
        .store()
        .config(buckets::BUCKETS_CONFIG)
        .unwrap()
        .unwrap();
    assert_eq!(stored.lines().count(), 4, "{stored}");
    let bucket = buckets::find(&harness.daemon, "my-media").await.unwrap();
    assert_eq!(bucket.policy.render(), "strict");

    // Removing is another record, and it takes the bucket out of the map.
    assert!(buckets::remove(&harness.daemon, "my-media").await.unwrap());
    assert!(buckets::find(&harness.daemon, "my-media").await.is_err());
    assert!(!buckets::remove(&harness.daemon, "my-media").await.unwrap());

    // A mapping the daemon would refuse is refused at `bucket add`, not at the
    // first GET days later.
    assert!(
        buckets::add(&harness.daemon, "bad-policy", "media", Some("whatever"))
            .await
            .is_err()
    );
    assert!(buckets::add(&harness.daemon, "UPPER", "media", None)
        .await
        .is_err());
    assert!(buckets::add(
        &harness.daemon,
        "two-pins",
        "nas@cluster.example:media",
        Some("strict")
    )
    .await
    .is_err());

    // Access keys take the same shape.
    let key = AccessKey {
        id: "AKID".into(),
        secret: "shh".into(),
    };
    synch_s3::auth::put_key(&harness.daemon, &key)
        .await
        .unwrap();
    assert_eq!(
        synch_s3::auth::load_keys(&harness.daemon).await.unwrap(),
        vec![key]
    );
    assert!(synch_s3::auth::remove_key(&harness.daemon, "AKID")
        .await
        .unwrap());
    assert!(synch_s3::auth::load_keys(&harness.daemon)
        .await
        .unwrap()
        .is_empty());

    harness.stop().await;
}

#[tokio::test]
async fn sigv4_is_enforced_when_keys_are_configured() {
    let keys = vec![AccessKey {
        id: "AKIDEXAMPLE".into(),
        secret: "wJalrXUtnFEMI/K7MDENG".into(),
    }];
    let harness = Harness::start(AuthMode::SigV4(keys.clone())).await;
    harness.publish("secret.txt", b"authenticated only");
    let http = client();

    // Unsigned requests are refused.
    let response = http
        .get(harness.url("/my-media/secret.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(response.text().await.unwrap().contains("AccessDenied"));

    // A garbage signature is refused.
    let response = http
        .get(harness.url("/my-media/secret.txt"))
        .header("x-amz-date", "20240102T030405Z")
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240102/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=00",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(response
        .text()
        .await
        .unwrap()
        .contains("SignatureDoesNotMatch"));

    // A correctly signed request succeeds.
    let host = harness.base.trim_start_matches("http://").to_string();
    let amz_date = "20240102T030405Z";
    let headers: std::collections::BTreeMap<String, String> = [
        ("host".to_string(), host.clone()),
        ("x-amz-date".to_string(), amz_date.to_string()),
    ]
    .into_iter()
    .collect();
    let header = synch_s3::auth::SigV4Header {
        access_key: "AKIDEXAMPLE".into(),
        date: "20240102".into(),
        region: "us-east-1".into(),
        service: "s3".into(),
        signed_headers: vec!["host".into(), "x-amz-date".into()],
        signature: String::new(),
    };
    let request = synch_s3::auth::SignedRequest {
        method: "GET",
        path: "/my-media/secret.txt",
        query: &[],
        headers: &headers,
        payload_hash: synch_s3::auth::UNSIGNED_PAYLOAD,
    };
    let signature =
        synch_s3::auth::expected_signature(&keys[0].secret, &header, amz_date, &request);

    let response = http
        .get(harness.url("/my-media/secret.txt"))
        .header("host", host)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", synch_s3::auth::UNSIGNED_PAYLOAD)
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240102/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-date, Signature={signature}"
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        b"authenticated only"
    );

    harness.stop().await;
}

/// With no daemon there is nothing to serve from, and the gateway says so in
/// the words the CLI uses rather than as a transport error (§9.1).
#[tokio::test]
async fn without_a_daemon_the_gateway_names_the_command_that_starts_one() {
    let dir = tempfile::tempdir().unwrap();
    Node::init(dir.path(), None).unwrap();
    let daemon = Daemon::new(dir.path());
    let error = buckets::load(&daemon)
        .await
        .expect_err("there is no daemon listening");
    assert_eq!(error.status, 503, "{error}");
    assert!(error.message.contains("synch daemon run"), "{error}");
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
