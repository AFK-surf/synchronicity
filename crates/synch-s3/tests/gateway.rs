//! Drives the gateway over real HTTP on an ephemeral port with a plain client
//! (§11 testing strategy): GET/HEAD/LIST/PUT round-trips, a Range read, ETag
//! checks, and byte-exactness.

use std::net::SocketAddr;

use synch_engine::{Node, NodeConfig};
use synch_s3::{
    auth::{AccessKey, AuthMode},
    buckets, Gateway,
};

struct Harness {
    _data: tempfile::TempDir,
    _space: tempfile::TempDir,
    space_path: std::path::PathBuf,
    node: Node,
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

        let reference = format!("{}:media", node.origin().canonical());
        buckets::add(&node, "my-media", &reference).unwrap();
        buckets::add(&node, "nas-media", "nas@cluster.example:media").unwrap();

        let gateway = Gateway::new(node.clone(), auth);
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
        let target = self.space_path.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(target, content).unwrap();
        self.node.scan_and_publish().unwrap();
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(server) = self.server.take() {
            let _ = server.await;
        }
        self.node.shutdown().await.unwrap();
    }
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
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"hello from s3");

    // A large object comes back byte-for-byte.
    let response = http
        .get(harness.url("/my-media/talks/keynote.mp4"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
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

    // Nothing was published under a seq the cluster would refuse.
    assert!(harness
        .node
        .store()
        .complete_head(harness.node.origin())
        .unwrap()
        .is_none());

    harness.stop().await;
}

#[tokio::test]
async fn foreign_buckets_are_read_only() {
    // §9.4: buckets whose origin is not the local node are read-only, because
    // the version model forbids publishing someone else's view.
    let harness = Harness::start(AuthMode::Anonymous).await;
    let response = client()
        .put(harness.url("/nas-media/anything.txt"))
        .body("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let body = response.text().await.unwrap();
    assert!(body.contains("read-only"), "{body}");
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
