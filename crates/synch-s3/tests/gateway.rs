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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_head_list_and_range_round_trip() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

/// An object far larger than one control-protocol chunk crosses the gateway in
/// both directions without either process holding it (§9.4). Byte-exactness at
/// this size is the observable half of that; the bounded channel and the
/// daemon's staging file are the mechanism.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_object_streams_through_in_both_directions() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_object_publishes_into_the_local_space() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_object_is_refused_while_the_node_is_in_recovery() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_pinned_bucket_writes_our_view_and_reads_theirs() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn divergent_keys_are_served_by_policy() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn symlink_keys_are_not_objects() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_operations_report_not_implemented() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    // Deleting a *bucket* is not a thing HTTP may do: a bucket is a mapping the
    // operator made.
    let response = http.delete(harness.url("/my-media")).send().await.unwrap();
    assert_eq!(response.status(), 501);
    assert!(response.text().await.unwrap().contains("NotImplemented"));
    // Neither is the batch delete, which is its own API.
    let response = http
        .post(harness.url("/my-media?delete"))
        .body("<Delete><Object><Key>notes.txt</Key></Object></Delete>")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 501);
    harness.stop().await;
}

/// Buckets and access keys live in the daemon's `s3.*` config namespace, and
/// the gateway edits them by appending records over the socket (§9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bucket_and_key_configuration_lives_in_the_daemon() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigv4_is_enforced_when_keys_are_configured() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

    // Dates must fall within the gateway's clock-skew window (§12 replay bound),
    // so every signed request below is stamped from the current time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let amz_date = synch_s3::auth::format_amz_date(now);
    let scope_date = amz_date[..8].to_string();

    // A garbage signature is refused — with a fresh date, so the request reaches
    // the signature check rather than being turned away for a stale timestamp.
    let response = http
        .get(harness.url("/my-media/secret.txt"))
        .header("x-amz-date", &amz_date)
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope_date}/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-date, Signature=00"
            ),
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
    let headers: std::collections::BTreeMap<String, String> = [
        ("host".to_string(), host.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ]
    .into_iter()
    .collect();
    let header = synch_s3::auth::SigV4Header {
        access_key: "AKIDEXAMPLE".into(),
        date: scope_date.clone(),
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
        synch_s3::auth::expected_signature(&keys[0].secret, &header, &amz_date, &request);

    let response = http
        .get(harness.url("/my-media/secret.txt"))
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", synch_s3::auth::UNSIGNED_PAYLOAD)
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope_date}/us-east-1/s3/aws4_request, \
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_daemon_the_gateway_names_the_command_that_starts_one() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

// ---- multipart upload (§9.4) -----------------------------------------------

/// Pulls an element's text out of a response body, for the few fields these
/// tests read back.
fn element(xml: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml
        .find(&open)
        .unwrap_or_else(|| panic!("no <{tag}> in {xml}"))
        + open.len();
    let end = xml[start..].find(&close).expect("unclosed element") + start;
    xml[start..end].to_string()
}

/// Builds the body a `CompleteMultipartUpload` carries.
fn completion(parts: &[(u32, String)]) -> String {
    let mut body = String::from("<CompleteMultipartUpload>");
    for (number, etag) in parts {
        body.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
        ));
    }
    body.push_str("</CompleteMultipartUpload>");
    body
}

/// Creates an upload and returns its id.
async fn create_upload(http: &reqwest::Client, harness: &Harness, key: &str) -> String {
    let response = http
        .post(harness.url(&format!("/my-media/{key}?uploads")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    element(&response.text().await.unwrap(), "UploadId")
}

/// Uploads one part and returns the ETag the gateway answered with.
async fn upload_part(
    http: &reqwest::Client,
    harness: &Harness,
    key: &str,
    upload: &str,
    number: u32,
    body: Vec<u8>,
) -> String {
    let response = http
        .put(harness.url(&format!(
            "/my-media/{key}?partNumber={number}&uploadId={upload}"
        )))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "part {number} was refused");
    response
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

/// The whole multipart round trip, out of order and byte-exact.
///
/// Out-of-order parts are the case that matters: every SDK that fans parts out
/// concurrently delivers them in whatever order the network settled on, and the
/// object is defined by the part *numbers*, not by arrival.
#[tokio::test]
async fn multipart_upload_assembles_parts_in_order() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();

    // Two parts over the 5 MiB minimum and a short tail, which is the shape S3
    // permits and the one a real upload has.
    let first: Vec<u8> = (0..6_000_000u32).map(|i| (i % 251) as u8).collect();
    let second: Vec<u8> = (0..5_500_000u32).map(|i| (i % 241) as u8).collect();
    let third: Vec<u8> = b"the short final part".to_vec();

    let upload = create_upload(&http, &harness, "big/assembled.bin").await;

    // Uploaded 3, 1, 2 — the completion is what puts them in order.
    let etag3 = upload_part(
        &http,
        &harness,
        "big/assembled.bin",
        &upload,
        3,
        third.clone(),
    )
    .await;
    let etag1 = upload_part(
        &http,
        &harness,
        "big/assembled.bin",
        &upload,
        1,
        first.clone(),
    )
    .await;
    let etag2 = upload_part(
        &http,
        &harness,
        "big/assembled.bin",
        &upload,
        2,
        second.clone(),
    )
    .await;

    let response = http
        .post(harness.url(&format!("/my-media/big/assembled.bin?uploadId={upload}")))
        .body(completion(&[(1, etag1), (2, etag2), (3, etag3)]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert_eq!(element(&body, "Key"), "big/assembled.bin");
    let etag = element(&body, "ETag");

    // The object reads back as the concatenation, and the ETag it was given is
    // the root of exactly those bytes.
    let mut expected = first.clone();
    expected.extend_from_slice(&second);
    expected.extend_from_slice(&third);
    let response = http
        .get(harness.url("/my-media/big/assembled.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        expected.as_slice()
    );
    let root = blake3::hash(&expected);
    assert_eq!(etag, format!("&quot;{}&quot;", root.to_hex()));

    // And it is a published entry like any other, not a file that only the
    // gateway can see.
    let listed = http
        .get(harness.url("/my-media?list-type=2&prefix=big/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(listed.contains("<Key>big/assembled.bin</Key>"), "{listed}");
    harness.stop().await;
}

/// A single-part upload is the shape mountpoint-s3 uses for *every* file it
/// writes, so it has to work and it has to publish a live mtime.
#[tokio::test]
async fn a_single_part_upload_publishes_like_a_put() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let before = synch_core::now_ns();

    let upload = create_upload(&http, &harness, "small.txt").await;
    let etag = upload_part(&http, &harness, "small.txt", &upload, 1, b"tiny".to_vec()).await;
    let response = http
        .post(harness.url(&format!("/my-media/small.txt?uploadId={upload}")))
        .body(completion(&[(1, etag)]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = http
        .get(harness.url("/my-media/small.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"tiny");

    // The published mtime is the completion's, not some part's: §8 orders
    // versions by it, so a completion that published an old one would lose to
    // content it supersedes.
    let entry = harness
        .daemon
        .resolve("media", "small.txt", "newest")
        .await
        .unwrap();
    assert!(entry.mtime_ns >= before, "{} < {before}", entry.mtime_ns);
    harness.stop().await;
}

/// Every way a completion can be wrong gets the code S3 defines for it, because
/// clients branch on them: shrink a part, re-upload a part, or start over.
#[tokio::test]
async fn completion_errors_are_distinguishable() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let key = "errors.bin";
    let upload = create_upload(&http, &harness, key).await;
    // One part over the minimum and one under it, so each failure mode can be
    // provoked without tripping another first.
    let big = vec![7u8; 5 * 1024 * 1024 + 16];
    let small = vec![9u8; 1024];
    let etag1 = upload_part(&http, &harness, key, &upload, 1, big).await;
    let etag2 = upload_part(&http, &harness, key, &upload, 2, small).await;

    let complete = |body: String| {
        let http = http.clone();
        let url = harness.url(&format!("/my-media/{key}?uploadId={upload}"));
        async move { http.post(url).body(body).send().await.unwrap() }
    };

    // A part that was never uploaded — reported as missing even though part 2
    // is also too small to be an interior part.
    let response = complete(completion(&[
        (1, etag1.clone()),
        (2, etag2.clone()),
        (9, etag2.clone()),
    ]))
    .await;
    assert_eq!(response.status(), 400);
    let body = response.text().await.unwrap();
    assert!(body.contains("InvalidPart"), "{body}");
    assert!(!body.contains("EntityTooSmall"), "{body}");

    // Parts named out of order.
    let response = complete(completion(&[(2, etag2.clone()), (1, etag1.clone())])).await;
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("InvalidPartOrder"));

    // An interior part under the 5 MiB minimum; the last one is exempt.
    let response = complete(completion(&[(2, etag2.clone()), (3, etag2.clone())])).await;
    assert_eq!(response.status(), 400);
    let body = response.text().await.unwrap();
    assert!(body.contains("InvalidPart"), "{body}");
    let response = complete(completion(&[(1, etag1.clone()), (2, etag2.clone())])).await;
    assert_eq!(response.status(), 200, "a short *final* part is legal");

    harness.stop().await;
}

/// An interior part under the minimum is `EntityTooSmall`, on its own upload so
/// the completion above does not consume it.
#[tokio::test]
async fn an_interior_part_under_the_minimum_is_refused() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let key = "short-interior.bin";
    let upload = create_upload(&http, &harness, key).await;
    let etag1 = upload_part(&http, &harness, key, &upload, 1, vec![1u8; 1024]).await;
    let etag2 = upload_part(&http, &harness, key, &upload, 2, vec![2u8; 1024]).await;

    let response = http
        .post(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .body(completion(&[(1, etag1.clone()), (2, etag2)]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("EntityTooSmall"));

    // An ETag that does not match what is actually there.
    let response = http
        .post(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .body(completion(&[(
            1,
            format!("&quot;{}&quot;", "0".repeat(64)),
        )]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("InvalidPart"));

    // A body that is not a completion at all.
    let response = http
        .post(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .body("<nonsense/>".to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("MalformedXML"));

    // Every one of those was recoverable: the upload is still open, and the
    // completion the client fixes goes through.
    let response = http
        .post(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .body(completion(&[(1, etag1)]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    harness.stop().await;
}

/// An unknown upload is `NoSuchUpload`, not `NoSuchKey` — and an id is a bearer
/// token for one key, so quoting it against another is the same answer.
#[tokio::test]
async fn an_upload_id_names_one_key() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let upload = create_upload(&http, &harness, "mine.txt").await;

    let response = http
        .post(harness.url(&format!("/my-media/someone-elses.txt?uploadId={upload}")))
        .body(completion(&[(1, format!("\"{}\"", "a".repeat(64)))]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert!(response.text().await.unwrap().contains("NoSuchUpload"));

    // A part quoted against the wrong key is refused before any bytes land.
    let response = http
        .put(harness.url(&format!(
            "/my-media/someone-elses.txt?partNumber=1&uploadId={upload}"
        )))
        .body(vec![0u8; 16])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    let response = http
        .get(harness.url("/my-media/mine.txt?uploadId=deadbeefdeadbeefdeadbeefdeadbeef"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert!(response.text().await.unwrap().contains("NoSuchUpload"));
    harness.stop().await;
}

/// Listing, aborting, and what an abort leaves behind (nothing).
#[tokio::test]
async fn uploads_and_parts_list_and_abort() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let key = "listed.bin";
    let upload = create_upload(&http, &harness, key).await;
    upload_part(&http, &harness, key, &upload, 1, vec![1u8; 32]).await;
    upload_part(&http, &harness, key, &upload, 2, vec![2u8; 64]).await;

    let listed = http
        .get(harness.url("/my-media?uploads"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        listed.contains(&format!("<UploadId>{upload}</UploadId>")),
        "{listed}"
    );
    assert!(listed.contains("<Key>listed.bin</Key>"), "{listed}");

    let parts = http
        .get(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(parts.contains("<PartNumber>1</PartNumber>"), "{parts}");
    assert!(parts.contains("<Size>64</Size>"), "{parts}");

    let response = http
        .delete(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    // Gone, and its staged bytes with it.
    let response = http
        .get(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let listed = http
        .get(harness.url("/my-media?uploads"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!listed.contains(&upload), "{listed}");
    // Nothing was published: an abort is not a write.
    let response = http
        .get(harness.url(&format!("/my-media/{key}")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    harness.stop().await;
}

/// A re-uploaded part replaces the first attempt rather than joining it.
#[tokio::test]
async fn a_re_uploaded_part_wins() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let key = "rewritten.txt";
    let upload = create_upload(&http, &harness, key).await;

    upload_part(&http, &harness, key, &upload, 1, b"first attempt".to_vec()).await;
    let second = upload_part(&http, &harness, key, &upload, 1, b"second attempt".to_vec()).await;

    let response = http
        .post(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .body(completion(&[(1, second)]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = http
        .get(harness.url(&format!("/my-media/{key}")))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(body.as_ref(), b"second attempt");
    harness.stop().await;
}

/// A retried completion replays its answer instead of reporting an upload that
/// no longer exists.
///
/// Every S3 client retries a completion it did not see the response to, and the
/// object is already published by then — so "no such upload" would be a lie
/// that makes the client report a failed write of a file that is right there.
#[tokio::test]
async fn a_retried_completion_replays_its_answer() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let key = "retried.txt";
    let upload = create_upload(&http, &harness, key).await;
    let etag = upload_part(&http, &harness, key, &upload, 1, b"once".to_vec()).await;

    let first = http
        .post(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .body(completion(&[(1, etag.clone())]))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let first_etag = element(&first.text().await.unwrap(), "ETag");

    let again = http
        .post(harness.url(&format!("/my-media/{key}?uploadId={upload}")))
        .body(completion(&[(1, etag)]))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 200);
    assert_eq!(element(&again.text().await.unwrap(), "ETag"), first_etag);
    harness.stop().await;
}

/// An `aws-chunked` body is unwrapped rather than stored as its own framing.
///
/// Mountpoint sends `--upload-checksums crc32c` by default, so this is what its
/// every upload looks like on the wire. A gateway that stored the framing would
/// hash the framing, and the corruption would be undetectable downstream.
#[tokio::test]
async fn chunked_bodies_are_decoded_and_their_checksums_checked() {
    use base64::Engine;
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let payload = b"the payload, not the framing".to_vec();

    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI).checksum(&payload);
    let digest = base64::engine::general_purpose::STANDARD.encode(crc.to_be_bytes());
    let framed = format!(
        "{:x}\r\n{}\r\n0\r\nx-amz-checksum-crc32c:{digest}\r\n\r\n",
        payload.len(),
        String::from_utf8(payload.clone()).unwrap()
    );

    let response = http
        .put(harness.url("/my-media/framed.txt"))
        .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        .header("x-amz-decoded-content-length", payload.len().to_string())
        .header("content-encoding", "aws-chunked")
        .body(framed.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let stored = http
        .get(harness.url("/my-media/framed.txt"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(stored.as_ref(), payload.as_slice());

    // A checksum that does not match the payload fails the write rather than
    // publishing bytes the client already knows are wrong.
    let bad = framed.replace(&digest, "AAAAAA==");
    let response = http
        .put(harness.url("/my-media/corrupt.txt"))
        .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        .header("x-amz-decoded-content-length", payload.len().to_string())
        .body(bad)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_client_error() || response.status().is_server_error());
    let response = http
        .get(harness.url("/my-media/corrupt.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        404,
        "a failed checksum published an object"
    );
    harness.stop().await;
}

/// A header that says the payload is somewhere else is refused, not ignored.
///
/// This is the mountpoint `rename` bug: `PUT` + `x-amz-rename-source` with an
/// empty body used to answer `200`, creating a truncated destination and
/// leaving the source in place, and the client recorded the rename as done.
#[tokio::test]
async fn headers_that_relocate_the_payload_are_refused() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    harness.publish("source.txt", b"twenty-five bytes here!!!");
    let http = client();

    for header in ["x-amz-rename-source", "x-amz-copy-source"] {
        let response = http
            .put(harness.url("/my-media/destination.txt"))
            .header(header, "/my-media/source.txt")
            .body(Vec::new())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 501, "{header} was not refused");
        assert!(response.text().await.unwrap().contains("NotImplemented"));
    }

    // Nothing was created, and the source is untouched.
    let response = http
        .get(harness.url("/my-media/destination.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let source = http
        .get(harness.url("/my-media/source.txt"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(source.as_ref(), b"twenty-five bytes here!!!");
    harness.stop().await;
}

// ---- DeleteObject (§8, §9.4) -----------------------------------------------

/// A delete removes the local copy and publishes a tombstone, and the key
/// leaves the tree — listings, reads and all.
#[tokio::test]
async fn delete_object_removes_the_file_and_tombstones_the_key() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    harness.publish("notes.txt", b"delete me");
    harness.publish("keep.txt", b"but not me");
    let http = client();

    // It is there first, or the test proves nothing.
    let response = http
        .get(harness.url("/my-media/notes.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = http
        .delete(harness.url("/my-media/notes.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    assert!(
        response.bytes().await.unwrap().is_empty(),
        "204 carries no body"
    );

    // Gone from the space directory...
    assert!(!harness.space_path.join("notes.txt").exists());
    // ...gone to a reader...
    let response = http
        .get(harness.url("/my-media/notes.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let response = http
        .head(harness.url("/my-media/notes.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    // ...gone from the listing, without taking its neighbour with it.
    let listed = http
        .get(harness.url("/my-media?list-type=2"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!listed.contains("<Key>notes.txt</Key>"), "{listed}");
    assert!(listed.contains("<Key>keep.txt</Key>"), "{listed}");

    // And it is a published tombstone, not just a missing file: the entry this
    // node asserts for the path says deleted.
    let ours = synch_engine::VersionPolicy::Origin(harness.node.origin().clone());
    let set = harness.node.versions("media", "notes.txt").unwrap();
    let row = harness.node.resolve_set(&set, &ours).unwrap();
    assert_eq!(row.kind, synch_core::EntryKind::Tombstone);
    harness.stop().await;
}

/// Deleting a key that is not there succeeds, because S3 says so and every
/// `rm -f`, retry and concurrent-delete race depends on it.
#[tokio::test]
async fn delete_object_is_idempotent() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    harness.publish("once.txt", b"here");
    let http = client();

    for _ in 0..3 {
        let response = http
            .delete(harness.url("/my-media/once.txt"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
    }
    // A key that never existed at all is the same answer.
    let response = http
        .delete(harness.url("/my-media/never-existed.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    harness.stop().await;
}

/// A delete is a publish, so a node that cannot publish must refuse it rather
/// than unlink the file and be unable to tell anyone (§3.4).
#[tokio::test]
async fn delete_object_is_refused_while_the_node_is_in_recovery() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    // Written into the space but deliberately not published: recovery is the
    // state of a node that holds no head of its own, so publishing first would
    // settle the question and take the node out of it.
    write_into(&harness.space_path, "notes.txt", b"still here");
    // A peer advertising a head this node has no history for is what puts it
    // into recovery, the same way the write test does it.
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
    let http = client();

    let response = http
        .delete(harness.url("/my-media/notes.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert!(response
        .text()
        .await
        .unwrap()
        .contains("ServiceUnavailable"));
    // The file is still here: refusing has to mean nothing happened, or the
    // refusal loses the data it was protecting.
    assert!(harness.space_path.join("notes.txt").exists());
    harness.stop().await;
}

/// A delete round-trips against a write: PUT, DELETE, PUT again.
#[tokio::test]
async fn a_key_can_be_rewritten_after_it_is_deleted() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();

    for body in [b"first".as_slice(), b"second".as_slice()] {
        let response = http
            .put(harness.url("/my-media/cycle.txt"))
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let got = http
            .get(harness.url("/my-media/cycle.txt"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(got.as_ref(), body);

        let response = http
            .delete(harness.url("/my-media/cycle.txt"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
        let response = http
            .get(harness.url("/my-media/cycle.txt"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }
    harness.stop().await;
}

/// An `aws-chunked` body is unwrapped however the client declared it.
///
/// Keying only off an exact-case `x-amz-content-sha256` sentinel left the
/// framing stored as object content, behind a `200` and an ETag over the framed
/// bytes — the corruption the decoder exists to prevent.
#[tokio::test]
async fn framing_is_detected_from_either_header() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let payload = b"the payload, not the framing";
    let framed = format!(
        "{:x}\r\n{}\r\n0\r\n\r\n",
        payload.len(),
        String::from_utf8_lossy(payload)
    );

    let declarations: [(&str, Option<&str>); 3] = [
        ("streaming-unsigned-payload-trailer", None),
        ("UNSIGNED-PAYLOAD", Some("aws-chunked")),
        ("STREAMING-UNSIGNED-PAYLOAD-TRAILER", Some("aws-chunked")),
    ];
    for (i, (sha, encoding)) in declarations.iter().enumerate() {
        let key = format!("framed-{i}.txt");
        let mut request = http
            .put(harness.url(&format!("/my-media/{key}")))
            .header("x-amz-content-sha256", *sha)
            .header("x-amz-decoded-content-length", payload.len().to_string())
            .body(framed.clone());
        if let Some(encoding) = encoding {
            request = request.header("content-encoding", *encoding);
        }
        assert_eq!(
            request.send().await.unwrap().status(),
            200,
            "{sha}/{encoding:?}"
        );

        let stored = http
            .get(harness.url(&format!("/my-media/{key}")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(stored.as_ref(), payload, "{sha}/{encoding:?}");
    }

    // A declared length with no framing at all is a client disagreeing with us
    // about the shape of its own body, and is refused rather than guessed at.
    let response = http
        .put(harness.url("/my-media/mismatched.txt"))
        .header("x-amz-decoded-content-length", "10")
        .body("plain bytes")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    harness.stop().await;
}

/// A trailer checksum that does not match reaches the client as `BadDigest`.
///
/// SDKs branch on it: `BadDigest` means retry the upload, `InvalidArgument`
/// means give up. Flattening the decoder's verdict into the daemon's generic
/// "the write was abandoned" told every client the wrong one.
#[tokio::test]
async fn a_failed_trailer_checksum_is_reported_as_bad_digest() {
    use base64::Engine;
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let payload = b"checksummed payload".to_vec();
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI).checksum(&payload);
    let digest = base64::engine::general_purpose::STANDARD.encode(crc.to_be_bytes());
    let framed = |d: &str| {
        format!(
            "{:x}\r\n{}\r\n0\r\nx-amz-checksum-crc32c:{d}\r\n\r\n",
            payload.len(),
            String::from_utf8_lossy(&payload)
        )
    };

    // The honest one lands.
    let response = http
        .put(harness.url("/my-media/good.txt"))
        .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        .header("x-amz-decoded-content-length", payload.len().to_string())
        .body(framed(&digest))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // The mismatched one does not, and says why in the client's vocabulary.
    let response = http
        .put(harness.url("/my-media/corrupt.txt"))
        .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        .header("x-amz-decoded-content-length", payload.len().to_string())
        .body(framed("AAAAAA=="))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body = response.text().await.unwrap();
    assert!(body.contains("BadDigest"), "{body}");

    // And nothing was published for it.
    let response = http
        .get(harness.url("/my-media/corrupt.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    harness.stop().await;
}

/// A `partNumber` with no upload to attach it to is refused, not treated as a
/// whole-object write.
#[tokio::test]
async fn a_part_number_without_an_upload_is_refused() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();

    for query in ["?partNumber=3", "?partNumber=3&uploadId="] {
        let response = http
            .put(harness.url(&format!("/my-media/whole.bin{query}")))
            .body(vec![7u8; 64])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400, "{query}");
        assert!(response.text().await.unwrap().contains("InvalidArgument"));
    }
    // And nothing was written under the key.
    let response = http
        .get(harness.url("/my-media/whole.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    harness.stop().await;
}

/// `ListMultipartUploads` honours the cursor it hands out.
///
/// Saying `IsTruncated` and then ignoring the markers on the next request
/// returns the identical page forever, and every SDK paginator loops on it.
#[tokio::test]
async fn listing_uploads_paginates() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    for i in 0..5 {
        create_upload(&http, &harness, &format!("many/{i:02}.bin")).await;
    }

    let page = |marker: String| {
        let http = http.clone();
        let url = harness.url(&format!("/my-media?uploads&max-uploads=2{marker}"));
        async move { http.get(url).send().await.unwrap().text().await.unwrap() }
    };

    let first = page(String::new()).await;
    assert!(first.contains("<IsTruncated>true</IsTruncated>"), "{first}");
    assert!(first.contains("<Key>many/00.bin</Key>"), "{first}");
    assert!(first.contains("<Key>many/01.bin</Key>"), "{first}");
    assert!(!first.contains("<Key>many/02.bin</Key>"), "{first}");

    // The cursor it handed back moves the listing on rather than repeating it.
    let marker = element(&first, "NextKeyMarker");
    let id_marker = element(&first, "NextUploadIdMarker");
    let second = page(format!("&key-marker={marker}&upload-id-marker={id_marker}")).await;
    assert!(!second.contains("<Key>many/00.bin</Key>"), "{second}");
    assert!(second.contains("<Key>many/02.bin</Key>"), "{second}");

    // Walking to the end terminates.
    let mut seen = 2;
    let mut body = second;
    while element(&body, "IsTruncated") == "true" {
        let marker = element(&body, "NextKeyMarker");
        let id_marker = element(&body, "NextUploadIdMarker");
        body = page(format!("&key-marker={marker}&upload-id-marker={id_marker}")).await;
        seen += body.matches("<Upload>").count();
        assert!(seen <= 5, "the listing did not terminate");
    }
    harness.stop().await;
}

/// An abort of an upload that is not there is `NoSuchUpload`, not success.
#[tokio::test]
async fn aborting_an_unknown_upload_is_not_a_success() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let response = client()
        .delete(harness.url("/my-media/x.bin?uploadId=deadbeefdeadbeefdeadbeefdeadbeef"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert!(response.text().await.unwrap().contains("NoSuchUpload"));
    harness.stop().await;
}

/// A delete publishes a tombstone even when no `local_files` row backs the path.
///
/// The tombstone comes from the scanner's deletion sweep, which walks
/// `local_files` — so relying on that alone meant a path whose row was missing
/// produced no tombstone at all, and this node's *live* assertion for the key
/// stayed in its signed root for good, with the gateway answering `204`.
#[tokio::test]
async fn delete_object_tombstones_a_path_with_no_local_row() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    harness.publish("orphaned.txt", b"published once");
    let http = client();

    // The published entry, with its row taken out from under it — which is what
    // `reconcile_local_files` does after an interrupted publish.
    harness
        .node
        .store()
        .remove_local_file("media", "orphaned.txt")
        .unwrap();

    let response = http
        .delete(harness.url("/my-media/orphaned.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    // Not merely absent from the disk: tombstoned in what this node publishes.
    let ours = synch_engine::VersionPolicy::Origin(harness.node.origin().clone());
    let set = harness.node.versions("media", "orphaned.txt").unwrap();
    let row = harness.node.resolve_set(&set, &ours).unwrap();
    assert_eq!(
        row.kind,
        synch_core::EntryKind::Tombstone,
        "the delete left a live assertion published"
    );
    let response = http
        .get(harness.url("/my-media/orphaned.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    harness.stop().await;
}

/// A delete whose file is already gone still publishes the tombstone.
#[tokio::test]
async fn delete_object_publishes_even_when_the_file_is_already_gone() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    harness.publish("vanished.txt", b"here for now");
    // Removed behind the daemon's back, as an out-of-band `rm` would.
    std::fs::remove_file(harness.space_path.join("vanished.txt")).unwrap();

    let response = client()
        .delete(harness.url("/my-media/vanished.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    let ours = synch_engine::VersionPolicy::Origin(harness.node.origin().clone());
    let set = harness.node.versions("media", "vanished.txt").unwrap();
    let row = harness.node.resolve_set(&set, &ours).unwrap();
    assert_eq!(row.kind, synch_core::EntryKind::Tombstone);
    harness.stop().await;
}

/// Signs requests as one access key, for the cross-principal test.
struct Signer<'a> {
    key: &'a AccessKey,
    base: String,
    host: String,
}

impl<'a> Signer<'a> {
    fn new(key: &'a AccessKey, harness: &Harness) -> Signer<'a> {
        Signer {
            key,
            base: harness.base.clone(),
            host: harness.base.trim_start_matches("http://").to_string(),
        }
    }

    /// Sends one signed request and returns the response.
    async fn send(&self, method: &str, target: &str, body: Vec<u8>) -> reqwest::Response {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let amz_date = synch_s3::auth::format_amz_date(now);
        let scope_date = amz_date[..8].to_string();
        let (path, query_text) = match target.split_once('?') {
            Some((path, query)) => (path, query),
            None => (target, ""),
        };
        let query: Vec<(String, String)> = query_text
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (pair.to_string(), String::new()),
            })
            .collect();
        let headers: std::collections::BTreeMap<String, String> = [
            ("host".to_string(), self.host.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ]
        .into_iter()
        .collect();
        let header = synch_s3::auth::SigV4Header {
            access_key: self.key.id.clone(),
            date: scope_date.clone(),
            region: "us-east-1".into(),
            service: "s3".into(),
            signed_headers: vec!["host".into(), "x-amz-date".into()],
            signature: String::new(),
        };
        let request = synch_s3::auth::SignedRequest {
            method,
            path,
            query: &query,
            headers: &headers,
            payload_hash: synch_s3::auth::UNSIGNED_PAYLOAD,
        };
        let signature =
            synch_s3::auth::expected_signature(&self.key.secret, &header, &amz_date, &request);
        let id = &self.key.id;
        client()
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{}{target}", self.base),
            )
            .header("host", &self.host)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", synch_s3::auth::UNSIGNED_PAYLOAD)
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential={id}/{scope_date}/us-east-1/s3/aws4_request, \
                     SignedHeaders=host;x-amz-date, Signature={signature}"
                ),
            )
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn get(&self, target: &str) -> String {
        self.send("GET", target, Vec::new())
            .await
            .text()
            .await
            .unwrap()
    }

    async fn post(&self, target: &str, body: Vec<u8>) -> String {
        self.send("POST", target, body).await.text().await.unwrap()
    }

    async fn status(&self, method: &str, target: &str) -> u16 {
        self.send(method, target, Vec::new())
            .await
            .status()
            .as_u16()
    }
}

/// One client's upload id is not another client's to use.
///
/// The listing used to hand every open upload's id to every caller, which made
/// the id — the only thing authorizing a part upload or a completion — public.
/// Any key holder could then overwrite another client's parts and complete
/// them, publishing content of their choosing under this node's signature.
#[tokio::test]
async fn uploads_are_scoped_to_the_key_that_opened_them() {
    let keys = vec![
        AccessKey {
            id: "AKIAALICE".into(),
            secret: "alicesecretalicesecretalicesecret".into(),
        },
        AccessKey {
            id: "AKIAMALLORY".into(),
            secret: "mallorysecretmallorysecretmallory".into(),
        },
    ];
    let harness = Harness::start(AuthMode::SigV4(keys.clone())).await;
    let alice = Signer::new(&keys[0], &harness);
    let mallory = Signer::new(&keys[1], &harness);

    let body = alice.post("/my-media/alice.bin?uploads", Vec::new()).await;
    let upload = element(&body, "UploadId");

    // Alice sees her own upload; Mallory's listing is empty.
    assert!(alice.get("/my-media?uploads").await.contains(&upload));
    assert!(!mallory.get("/my-media?uploads").await.contains(&upload));

    // And Mallory cannot use the id even holding it: every way of asking is the
    // same answer, so a guessed id is never confirmed as real.
    for (method, path) in [
        (
            "PUT",
            format!("/my-media/alice.bin?partNumber=1&uploadId={upload}"),
        ),
        ("GET", format!("/my-media/alice.bin?uploadId={upload}")),
        ("DELETE", format!("/my-media/alice.bin?uploadId={upload}")),
    ] {
        let status = mallory.status(method, &path).await;
        assert_eq!(status, 404, "{method} {path}");
    }

    // Alice's upload is untouched, and still hers to finish.
    let parts = alice
        .get(&format!("/my-media/alice.bin?uploadId={upload}"))
        .await;
    assert!(parts.contains("<ListPartsResult"), "{parts}");
    harness.stop().await;
}
