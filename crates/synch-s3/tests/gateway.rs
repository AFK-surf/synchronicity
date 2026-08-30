//! Drives the gateway over real HTTP on an ephemeral port with a plain
//! client (§11): GET/HEAD/LIST/PUT round-trips, Range, ETags, byte-exactness.
//!
//! The daemon is real — same `Server`, socket, token — and the gateway
//! reaches it only through that socket, which is the property §9.4 is about.

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
    /// The node the daemon owns, held so a test can assert on the state
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
        node.add_filesystem_source("media", space.path()).unwrap();

        let (stop, _) = broadcast::channel(1);
        let control = Server::bind(node.clone(), stop.clone()).await.unwrap();
        let served = tokio::spawn(control.run());
        let daemon = Daemon::new(data.path());

        // One writable source view and three explicitly read-only selected views.
        buckets::add(
            &daemon,
            "my-media",
            "media",
            buckets::Access::ReadWrite,
            None,
        )
        .await
        .unwrap();
        buckets::add(
            &daemon,
            "nas-media",
            "media",
            buckets::Access::ReadOnly,
            Some("origin=nas@cluster.example"),
        )
        .await
        .unwrap();
        buckets::add(
            &daemon,
            "strict-media",
            "media",
            buckets::Access::ReadOnly,
            Some("strict"),
        )
        .await
        .unwrap();
        buckets::add(
            &daemon,
            "newest-media",
            "media",
            buckets::Access::ReadOnly,
            Some("newest"),
        )
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

    /// Sends one request against the gateway, unwrapping transport errors.
    async fn request(&self, method: reqwest::Method, path: &str) -> reqwest::Response {
        client()
            .request(method, self.url(path))
            .send()
            .await
            .unwrap()
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.request(reqwest::Method::GET, path).await
    }

    async fn head(&self, path: &str) -> reqwest::Response {
        client().head(self.url(path)).send().await.unwrap()
    }

    async fn put(&self, path: &str, body: impl Into<reqwest::Body>) -> reqwest::Response {
        client()
            .put(self.url(path))
            .body(body)
            .send()
            .await
            .unwrap()
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

/// A deterministic payload of `n` bytes.
fn payload(n: u32) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_head_list_and_range_round_trip() {
    // The runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let harness = Harness::start(AuthMode::Anonymous).await;
    let payload = payload(200_000);
    harness.publish("notes.txt", b"hello from s3");
    harness.publish("talks/keynote.mp4", &payload);
    harness.publish("talks/slides.pdf", b"slides");

    // GetObject, byte-exact, with the ETag as the quoted blake3 root.
    let response = harness.get("/my-media/notes.txt").await;
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
    // Last-Modified is RFC 7231 HTTP-date, not the RFC 3339 the XML body
    // carries — SDKs parse it strictly.
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

    // The SDK write path probes with HeadBucket/CreateBucket before upload:
    // a mapped bucket answers both, an unmapped one 404s.
    for method in [reqwest::Method::HEAD, reqwest::Method::PUT] {
        assert_eq!(
            harness.request(method.clone(), "/my-media").await.status(),
            200,
            "{method} on a mapped bucket"
        );
        assert_eq!(
            harness
                .request(method.clone(), "/not-mapped")
                .await
                .status(),
            404,
            "{method} on an unmapped bucket"
        );
    }

    // A large object comes back byte-for-byte, its declared length the
    // object's — a streamed body must still say how long it is.
    let response = harness.get("/my-media/talks/keynote.mp4").await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("content-length").unwrap(),
        &payload.len().to_string()
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), payload.as_slice());

    // HeadObject: metadata straight from the entry, no body.
    let response = harness.head("/my-media/talks/keynote.mp4").await;
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

    // A window in the middle, read as a verified range read.
    let response = client()
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
    let response = client()
        .get(harness.url("/my-media/notes.txt"))
        .header("Range", "bytes=-3")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 206);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b" s3");

    // An unsatisfiable range is refused, not silently clamped to nothing.
    let response = client()
        .get(harness.url("/my-media/notes.txt"))
        .header("Range", "bytes=9999-99999")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 416);

    // ListObjectsV2 over the whole bucket.
    let body = harness
        .get("/newest-media?list-type=2")
        .await
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
    let body = harness
        .get("/my-media?list-type=2&prefix=talks/")
        .await
        .text()
        .await
        .unwrap();
    assert!(body.contains("<Key>talks/keynote.mp4</Key>"), "{body}");
    assert!(!body.contains("<Key>notes.txt</Key>"), "{body}");

    // A delimiter rolls directories up into common prefixes.
    let body = harness
        .get("/my-media?list-type=2&delimiter=%2F")
        .await
        .text()
        .await
        .unwrap();
    assert!(body.contains("<Key>notes.txt</Key>"), "{body}");
    assert!(body.contains("<Prefix>talks/</Prefix>"), "{body}");
    assert!(!body.contains("<Key>talks/keynote.mp4</Key>"), "{body}");

    // Continuation tokens page through the listing.
    let body = harness
        .get("/my-media?list-type=2&max-keys=1")
        .await
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
    let body = harness
        .get(&format!(
            "/my-media?list-type=2&max-keys=5&continuation-token={}",
            urlencode(&token)
        ))
        .await
        .text()
        .await
        .unwrap();
    assert!(!body.contains("<Key>notes.txt</Key>"), "{body}");
    assert!(body.contains("<Key>talks/keynote.mp4</Key>"), "{body}");

    // A missing key and a missing bucket both produce the S3 error codes.
    let response = harness.get("/my-media/absent.txt").await;
    assert_eq!(response.status(), 404);
    assert!(response.text().await.unwrap().contains("NoSuchKey"));

    let response = harness.get("/no-bucket/x").await;
    assert_eq!(response.status(), 404);
    assert!(response.text().await.unwrap().contains("NoSuchBucket"));

    // ListBuckets at the service root.
    let body = harness.get("/").await.text().await.unwrap();
    assert!(body.contains("<Name>my-media</Name>"), "{body}");
    assert!(body.contains("<Name>nas-media</Name>"), "{body}");

    // A body larger than one control-protocol chunk streams through unheld by
    // either process (§9.3, §9.4): it lands in the space, publishes, and the
    // entry carries the right size.
    let big = (0..3_000_000u32)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<u8>>();
    let response = harness.put("/my-media/uploads/big.bin", big.clone()).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("etag").unwrap().to_str().unwrap(),
        format!("\"{}\"", blake3::hash(&big).to_hex())
    );
    assert_eq!(
        std::fs::read(harness.space_path.join("uploads/big.bin")).unwrap(),
        big
    );
    let entry = harness
        .node
        .store()
        .entry(harness.node.origin(), "media", "uploads/big.bin")
        .unwrap()
        .unwrap();
    assert_eq!(entry.size, big.len() as u64);

    harness.stop().await;
}

/// A node in key-loss recovery cannot publish, so it cannot accept a write
/// or a delete either: an S3 error naming the command that clears it, not a
/// panic, a silently dropped upload, or an unlinked file (§3.4, §9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writes_and_deletes_are_refused_while_the_node_is_in_recovery() {
    // The runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let harness = Harness::start(AuthMode::Anonymous).await;
    // A peer advertising a head this node has no history for is what puts it
    // into recovery (§3.4).
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
    // Nothing was published, and nothing was written into the space either.
    assert!(harness
        .node
        .store()
        .complete_head(harness.node.origin())
        .unwrap()
        .is_none());
    assert!(!harness.space_path.join("uploads").exists());

    // The delete half: in the space but deliberately unpublished (publishing
    // would leave recovery), so the delete must refuse and leave the file.
    write_into(&harness.space_path, "notes.txt", b"still here");
    let response = client()
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
    assert!(harness.space_path.join("notes.txt").exists());

    harness.stop().await;
}

/// A read-only selected view refuses writes before they can enter a source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_only_bucket_rejects_writes() {
    // The runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let harness = Harness::start(AuthMode::Anonymous).await;
    let response = harness.put("/nas-media/ours.txt", b"ours".to_vec()).await;
    assert_eq!(response.status(), 403);
    assert!(response.text().await.unwrap().contains("AccessDenied"));
    assert_eq!(
        harness
            .request(reqwest::Method::PUT, "/nas-media")
            .await
            .status(),
        403
    );

    // The writable local view has not changed.
    let response = harness.get("/my-media/ours.txt").await;
    assert_eq!(response.status(), 404);

    harness.stop().await;
}

/// §8, §9.4: `newest` serves the winning version, `strict` answers a divergent
/// key with 409 naming the versions, and the unified listing shows one key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn divergent_keys_are_served_by_policy() {
    // The runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let harness = Harness::start(AuthMode::Anonymous).await;
    harness.publish("shared.txt", b"ours");

    // A peer publishes a different version of the same path: only the peer's
    // own assertion is written — the read model diverges, not a write into
    // someone else's trie.
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
    let body = harness
        .get("/my-media?list-type=2")
        .await
        .text()
        .await
        .unwrap();
    assert_eq!(body.matches("<Key>shared.txt</Key>").count(), 1, "{body}");

    // `newest` serves the winning version, and its ETag is that version's root.
    let response = harness.get("/newest-media/shared.txt").await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["etag"].to_str().unwrap(),
        format!("\"{}\"", blake3::hash(theirs).to_hex())
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), theirs);

    // A strict bucket refuses the key with 409 and names both versions.
    let response = harness.get("/strict-media/shared.txt").await;
    assert_eq!(response.status(), 409);
    let body = response.text().await.unwrap();
    assert!(body.contains("DivergentVersions"), "{body}");
    assert!(body.contains("nas@cluster.example"), "{body}");
    assert!(
        body.contains(&blake3::hash(theirs).to_hex().to_string()),
        "{body}"
    );
    assert!(body.contains("<Resource>shared.txt</Resource>"), "{body}");

    // An undisputed key in the same strict bucket still lists.
    harness.publish("undisputed.txt", b"only one");

    // The strict bucket leaves the divergent key out of its listing too.
    let body = harness
        .get("/strict-media?list-type=2")
        .await
        .text()
        .await
        .unwrap();
    assert!(!body.contains("<Key>shared.txt</Key>"), "{body}");
    assert!(body.contains("<Key>undisputed.txt</Key>"), "{body}");
    harness.stop().await;
}

/// A symlink is not an S3 object: its identity is its target, not content
/// (§8), so it has no root for an ETag and no bytes to serve. It stays out of
/// listings and a direct read is a missing key — otherwise the gateway would
/// advertise a key whose GET can only fail.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn symlink_keys_are_not_objects() {
    // The runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let harness = Harness::start(AuthMode::Anonymous).await;
    harness.publish("real.txt", b"the real thing");
    std::os::unix::fs::symlink("real.txt", harness.space_path.join("link.txt")).unwrap();
    harness.node.scan_and_publish().unwrap();

    // The daemon tracks the symlink — the gateway declines to present it.
    let entry = harness
        .node
        .store()
        .entry(harness.node.origin(), "media", "link.txt")
        .unwrap()
        .unwrap();
    assert_eq!(entry.kind, synch_core::EntryKind::Symlink);
    assert_eq!(entry.symlink_target.as_deref(), Some("real.txt"));

    let body = harness
        .get("/my-media?list-type=2")
        .await
        .text()
        .await
        .unwrap();
    assert!(body.contains("<Key>real.txt</Key>"), "{body}");
    assert!(!body.contains("<Key>link.txt</Key>"), "{body}");
    assert!(body.contains("<KeyCount>1</KeyCount>"), "{body}");

    for method in ["GET", "HEAD"] {
        let response = harness
            .request(method.parse().unwrap(), "/my-media/link.txt")
            .await;
        assert_eq!(response.status(), 404, "{method}");
    }

    // Writing to the same key is an ordinary write: it replaces the link
    // with a file, an object like any other.
    let response = harness
        .put("/my-media/link.txt", b"now a file".to_vec())
        .await;
    assert_eq!(response.status(), 200);
    let response = harness.get("/my-media/link.txt").await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"now a file");

    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigv4_is_enforced_when_keys_are_configured() {
    // The runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let keys = vec![AccessKey {
        id: "AKIDEXAMPLE".into(),
        secret: "wJalrXUtnFEMI/K7MDENG".into(),
    }];
    let harness = Harness::start(AuthMode::SigV4(keys.clone())).await;
    harness.publish("secret.txt", b"authenticated only");

    // Unsigned requests are refused.
    let response = harness.get("/my-media/secret.txt").await;
    assert_eq!(response.status(), 403);
    assert!(response.text().await.unwrap().contains("AccessDenied"));

    // Dates must fall within the clock-skew window (§12), so every signed
    // request below is stamped from the current time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let amz_date = synch_s3::auth::format_amz_date(now);
    let scope_date = amz_date[..8].to_string();
    let http = client();

    // A garbage signature is refused — fresh date, so it reaches the
    // signature check rather than being turned away for staleness.
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
    let response = Signer::new(&keys[0], &harness)
        .send("GET", "/my-media/secret.txt", Vec::new())
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        b"authenticated only"
    );

    harness.stop().await;
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

/// Pulls an element's text out of a response body.
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

/// The whole multipart round trip, out of order and byte-exact: SDKs fan
/// parts out concurrently, and the object is defined by part numbers.
#[tokio::test]
async fn multipart_upload_assembles_parts_in_order() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();

    // Two parts over the 5 MiB minimum and a short tail: the shape S3
    // permits and a real upload has.
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

    // The object reads back as the concatenation; the ETag is the root of
    // exactly those bytes.
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

    // A single-part upload — the shape mountpoint-s3 uses for every file —
    // publishes with the completion's mtime, not a part's: §8 orders versions
    // by it, so a stale one would lose to content it supersedes.
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
    let entry = harness
        .daemon
        .resolve("media", "small.txt", "newest")
        .await
        .unwrap();
    assert!(entry.mtime_ns >= before, "{} < {before}", entry.mtime_ns);

    harness.stop().await;
}

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

    // The cursor it handed back moves the listing on, and walking to the end
    // terminates rather than repeating a page.
    let mut body = page(format!(
        "&key-marker={}&upload-id-marker={}",
        element(&first, "NextKeyMarker"),
        element(&first, "NextUploadIdMarker")
    ))
    .await;
    let mut seen = 2;
    while element(&body, "IsTruncated") == "true" {
        let marker = element(&body, "NextKeyMarker");
        let id_marker = element(&body, "NextUploadIdMarker");
        body = page(format!("&key-marker={marker}&upload-id-marker={id_marker}")).await;
        seen += body.matches("<Upload>").count();
        assert!(seen <= 5, "the listing did not terminate");
    }
    harness.stop().await;
}

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

/// Every way a completion can be wrong gets the code S3 defines for it —
/// clients branch on them.
#[tokio::test]
async fn completion_errors_are_distinguishable() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let key = "errors.bin";
    let upload = create_upload(&http, &harness, key).await;
    // One part over the minimum and one under it, so each failure mode can
    // be provoked without tripping another.
    let big = vec![7u8; 5 * 1024 * 1024 + 16];
    let small = vec![9u8; 1024];
    let etag1 = upload_part(&http, &harness, key, &upload, 1, big).await;
    let etag2 = upload_part(&http, &harness, key, &upload, 2, small).await;

    let complete = |body: String| {
        let http = http.clone();
        let url = harness.url(&format!("/my-media/{key}?uploadId={upload}"));
        async move { http.post(url).body(body).send().await.unwrap() }
    };

    // A part that was never uploaded, reported as missing even though part 2
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

    // The last part is exempt from the 5 MiB minimum.
    let response = complete(completion(&[(1, etag1.clone()), (2, etag2.clone())])).await;
    assert_eq!(response.status(), 200, "a short *final* part is legal");

    // A fresh upload with two parts under the minimum: an interior one is
    // `EntityTooSmall`, a bad ETag is `InvalidPart`, a body that is not a
    // completion at all is `MalformedXML` — and every one was recoverable,
    // the upload still open for the fixed completion.
    let upload = create_upload(&http, &harness, "short-interior.bin").await;
    let etag1 = upload_part(
        &http,
        &harness,
        "short-interior.bin",
        &upload,
        1,
        vec![1u8; 1024],
    )
    .await;
    let etag2 = upload_part(
        &http,
        &harness,
        "short-interior.bin",
        &upload,
        2,
        vec![2u8; 1024],
    )
    .await;
    let post = |body: String| {
        let http = http.clone();
        let url = harness.url(&format!("/my-media/short-interior.bin?uploadId={upload}"));
        async move { http.post(url).body(body).send().await.unwrap() }
    };
    let response = post(completion(&[(1, etag1.clone()), (2, etag2.clone())])).await;
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("EntityTooSmall"));
    let response = post(completion(&[(
        1,
        format!("&quot;{}&quot;", "0".repeat(64)),
    )]))
    .await;
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("InvalidPart"));
    let response = post("<nonsense/>".to_string()).await;
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("MalformedXML"));
    let response = post(completion(&[(1, etag1)])).await;
    assert_eq!(response.status(), 200);

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

    // An abort of an upload that is not there is `NoSuchUpload`, not success.
    let response = client()
        .delete(harness.url("/my-media/x.bin?uploadId=deadbeefdeadbeefdeadbeefdeadbeef"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert!(response.text().await.unwrap().contains("NoSuchUpload"));
    harness.stop().await;
}

/// A retried completion replays its answer instead of reporting an upload
/// that no longer exists — the object is already published, so "no such
/// upload" would report a failed write of a file that is right there.
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

/// An `aws-chunked` body is unwrapped rather than stored as its own framing,
/// however the client declared it, and its crc32c trailer is checked — a bad
/// checksum surfaces as `BadDigest` (SDKs retry on it), never as content
/// behind a `200` or a generic "write abandoned".
#[tokio::test]
async fn chunked_bodies_are_decoded_and_their_checksums_checked() {
    use base64::Engine;
    let harness = Harness::start(AuthMode::Anonymous).await;
    let http = client();
    let payload = b"the payload, not the framing".to_vec();
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI).checksum(&payload);
    let digest = base64::engine::general_purpose::STANDARD.encode(crc.to_be_bytes());
    let framed = |d: &str| {
        format!(
            "{:x}\r\n{}\r\n0\r\nx-amz-checksum-crc32c:{d}\r\n\r\n",
            payload.len(),
            String::from_utf8_lossy(&payload)
        )
    };

    // The mountpoint default — STREAMING-UNSIGNED-PAYLOAD-TRAILER, aws-chunked,
    // honest checksum — lands, stored as the payload, not the framing.
    let response = http
        .put(harness.url("/my-media/framed.txt"))
        .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        .header("x-amz-decoded-content-length", payload.len().to_string())
        .header("content-encoding", "aws-chunked")
        .body(framed(&digest))
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

    // The framing is detected from either declaration: the lowercase
    // sentinel alone, or `UNSIGNED-PAYLOAD` with the encoding header.
    let declarations: [(&str, Option<&str>); 2] = [
        ("streaming-unsigned-payload-trailer", None),
        ("UNSIGNED-PAYLOAD", Some("aws-chunked")),
    ];
    for (i, (sha, encoding)) in declarations.iter().enumerate() {
        let key = format!("framed-{i}.txt");
        let mut request = http
            .put(harness.url(&format!("/my-media/{key}")))
            .header("x-amz-content-sha256", *sha)
            .header("x-amz-decoded-content-length", payload.len().to_string())
            .body(framed(&digest));
        if let Some(encoding) = encoding {
            request = request.header("content-encoding", *encoding);
        }
        assert_eq!(request.send().await.unwrap().status(), 200, "{sha}");
        let stored = http
            .get(harness.url(&format!("/my-media/{key}")))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(stored.as_ref(), payload.as_slice(), "{sha}");
    }

    // A corrupt checksum is `BadDigest`, and nothing is published for it.
    let response = http
        .put(harness.url("/my-media/corrupt.txt"))
        .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        .header("x-amz-decoded-content-length", payload.len().to_string())
        .body(framed("AAAAAA=="))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("BadDigest"));
    let response = http
        .get(harness.url("/my-media/corrupt.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    // A declared length with no framing at all is a client disagreeing with
    // us about its own body, refused rather than guessed at.
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

/// A header that says the payload is somewhere else is refused, not ignored —
/// the mountpoint `rename` bug would truncate the destination behind a `200`.
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

    // Gone from the space directory, the listing, and a reader.
    assert!(!harness.space_path.join("notes.txt").exists());
    let response = http
        .get(harness.url("/my-media/notes.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
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

    // And it is a published tombstone, not a missing file: our asserted entry
    // for the path says deleted.
    let ours = synch_engine::VersionPolicy::Origin(harness.node.origin().clone());
    let set = harness.node.versions("media", "notes.txt").unwrap();
    let now = harness.node.store().read_instant().unwrap();
    let row = harness.node.resolve_set(&set, &ours, now).unwrap();
    assert_eq!(row.kind, synch_core::EntryKind::Tombstone);

    // Deleting a missing key succeeds: S3 says so, and `rm -f`-style retries
    // and concurrent-delete races depend on it.
    for _ in 0..3 {
        let response = http
            .delete(harness.url("/my-media/notes.txt"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
    }
    let response = http
        .delete(harness.url("/my-media/never-existed.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
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

/// A delete publishes a tombstone even when the backing file or its
/// `local_files` row is gone — the sweep walks rows, and without this a
/// missing row meant this node's *live* assertion stayed signed for good,
/// with the gateway answering `204`.
#[tokio::test]
async fn delete_object_tombstones_even_without_file_or_row() {
    let harness = Harness::start(AuthMode::Anonymous).await;
    harness.publish("orphaned.txt", b"published once");
    let http = client();

    // The published entry, with its row taken out from under it — which is
    // what `reconcile_local_files` does after an interrupted publish.
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

    // A file removed out of band, as an out-of-band `rm` would, is the same:
    // the delete must not depend on the file being there either.
    harness.publish("vanished.txt", b"here for now");
    std::fs::remove_file(harness.space_path.join("vanished.txt")).unwrap();
    let response = http
        .delete(harness.url("/my-media/vanished.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    // Not merely absent from the disk: tombstoned in what this node publishes.
    for key in ["orphaned.txt", "vanished.txt"] {
        let ours = synch_engine::VersionPolicy::Origin(harness.node.origin().clone());
        let set = harness.node.versions("media", key).unwrap();
        let now = harness.node.store().read_instant().unwrap();
        let row = harness.node.resolve_set(&set, &ours, now).unwrap();
        assert_eq!(
            row.kind,
            synch_core::EntryKind::Tombstone,
            "the delete left a live assertion published"
        );
        let response = http
            .get(harness.url(&format!("/my-media/{key}")))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }
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

/// One client's upload id is not another's to use.
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
