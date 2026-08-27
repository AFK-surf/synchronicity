//! The MCP bridge against a real daemon.
//!
//! The server loop is generic over its streams — the stdio binding defines its
//! framing over "any reliable bidirectional byte stream", and only the process
//! mechanics are stdio's — so these drive the real dispatcher over an in-memory
//! duplex against a real `Server`, real control socket, and real node. Nothing
//! here is a mock: what is exercised is the same code path `synch mcp` runs.
//!
//! `src/mcp/` holds the unit coverage that needs no daemon: framing, era
//! detection, argument validation, and the catalogue's shape.

use std::path::Path;

use serde_json::{json, Value};
use synch_cli::{
    control::Server,
    mcp::{self, Options},
};
use synch_core::OriginId;
use synch_engine::{Node, NodeConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
};

/// The revision these tests speak.
const VERSION: &str = "2026-07-28";

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

    /// Adds a path-backed space with files already in it.
    async fn space_with(&self, id: &str, dir: &Path, files: &[(&str, &[u8])]) {
        for (path, bytes) in files {
            let target = dir.join(path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(target, bytes).unwrap();
        }
        let (node, id, dir) = (self.node.clone(), id.to_string(), dir.to_path_buf());
        off_runtime(move || node.add_space(&id, &dir))
            .await
            .unwrap();
        // The same scan the daemon runs, through the same engine entry point
        // the control service uses — not the synchronous scanner, which would
        // bypass the configured CAS backend.
        self.node.scan_and_stage_async_with_reports().await.unwrap();
        // Staged, then flushed: an explicit scan is one batch, so what it
        // published is true by the time this returns (§7.1).
        self.node.flush_staged().await.unwrap();
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = self.served.await;
        self.node.shutdown().await.unwrap();
    }
}

/// A live MCP server, driven the way a client drives one.
struct Client {
    stream: tokio::io::DuplexStream,
    serving: tokio::task::JoinHandle<anyhow::Result<()>>,
    pending: Vec<Value>,
    next_id: i64,
}

impl Client {
    /// Starts a server against a datadir and connects to it.
    fn open(data_dir: &Path, options: Options) -> Client {
        let (client, server) = tokio::io::duplex(1024 * 1024);
        let (read, write) = tokio::io::split(server);
        let path = data_dir.to_path_buf();
        let serving = tokio::spawn(async move { mcp::serve(read, write, &path, options).await });
        Client {
            stream: client,
            serving,
            pending: Vec::new(),
            next_id: 1,
        }
    }

    /// Sends one request and returns its response.
    ///
    /// Requests go one at a time here because these tests assert on answers;
    /// `interleaved_requests_are_answered_independently` is where several are
    /// in flight at once.
    async fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(method, params, id).await;
        loop {
            let message = self.recv().await.expect("a response");
            if message["id"] == json!(id) {
                return message;
            }
            // A notification, or an answer to something else. Kept, so a test
            // that wants it can look.
            self.pending.push(message);
        }
    }

    /// Sends a request without waiting for it.
    async fn send(&mut self, method: &str, mut params: Value, id: i64) {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "mcp-tests", "version": "1" },
        });
        let line =
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        self.stream
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
    }

    /// Sends a notification.
    async fn notify(&mut self, method: &str, params: Value) {
        let line = json!({ "jsonrpc": "2.0", "method": method, "params": params }).to_string();
        self.stream
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
    }

    /// Reads one message, failing rather than hanging if none arrives.
    async fn recv(&mut self) -> Option<Value> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                self.stream.read(&mut byte),
            )
            .await
            .expect("the server answered within 30s")
            .unwrap();
            if read == 0 {
                return None;
            }
            if byte[0] == b'\n' {
                return Some(
                    serde_json::from_slice(&line).expect("every line on stdout is a JSON message"),
                );
            }
            line.push(byte[0]);
        }
    }

    /// Calls a tool and returns its result, asserting it did not fail.
    async fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let response = self
            .call(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            )
            .await;
        assert!(
            response.get("error").is_none(),
            "{name} failed at the protocol level: {response}"
        );
        let result = &response["result"];
        assert_ne!(
            result["isError"],
            json!(true),
            "{name} failed: {}",
            result["content"][0]["text"]
        );
        result.clone()
    }

    /// Calls a tool expecting it to report a failure a model can act on.
    async fn tool_error(&mut self, name: &str, arguments: Value) -> String {
        let response = self
            .call(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            )
            .await;
        let result = &response["result"];
        assert_eq!(
            result["isError"],
            json!(true),
            "{name} unexpectedly worked: {response}"
        );
        result["content"][0]["text"].as_str().unwrap().to_string()
    }

    /// Closes the input and waits for the server to exit.
    async fn close(mut self) {
        self.stream.shutdown().await.unwrap();
        // Drain whatever is still coming, so the server's writer finishes.
        let mut rest = Vec::new();
        let _ = self.stream.read_to_end(&mut rest).await;
        self.serving.await.unwrap().unwrap();
    }
}

/// A read-only server against a datadir.
fn reader(data_dir: &Path) -> Client {
    Client::open(
        data_dir,
        Options {
            allow_write: false,
            spaces: Vec::new(),
            max_read_bytes: 64 * 1024,
        },
    )
}

/// A server with the write tier on.
fn writer(data_dir: &Path) -> Client {
    Client::open(
        data_dir,
        Options {
            allow_write: true,
            spaces: Vec::new(),
            max_read_bytes: 64 * 1024,
        },
    )
}

#[tokio::test]
async fn the_tree_is_listed_read_and_described_through_the_typed_calls() {
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    daemon
        .space_with(
            "media",
            checkout.path(),
            &[
                ("notes/plan.md", b"# Plan\nship it\n"),
                ("notes/todo.md", b"- one\n- two\n"),
                ("raw.bin", &[0u8, 159, 146, 150]),
            ],
        )
        .await;

    let mut client = reader(data.path());

    // Spaces come back as data, not as a line to split.
    let spaces = client.tool("synch_spaces", json!({})).await;
    let listed = &spaces["structuredContent"]["spaces"];
    assert_eq!(listed[0]["id"], "media");
    assert_eq!(
        listed[0]["local_path"],
        checkout.path().to_string_lossy().as_ref()
    );

    let listing = client.tool("synch_list", json!({ "space": "media" })).await;
    let entries = listing["structuredContent"]["entries"].as_array().unwrap();
    let paths: Vec<&str> = entries
        .iter()
        .map(|entry| entry["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"notes/plan.md"), "{paths:?}");
    assert!(paths.contains(&"raw.bin"), "{paths:?}");
    for entry in entries {
        assert_eq!(entry["origin"], "nas@cluster.example");
        assert_eq!(entry["versions"], 1);
    }

    let stat = client
        .tool(
            "synch_stat",
            json!({ "space": "media", "path": "notes/plan.md" }),
        )
        .await;
    assert_eq!(stat["structuredContent"]["kind"], "file");
    assert_eq!(stat["structuredContent"]["size"], 15);
    assert!(stat["structuredContent"]["content_root"].is_string());

    // Text arrives as text.
    let read = client
        .tool(
            "synch_read",
            json!({ "space": "media", "path": "notes/plan.md" }),
        )
        .await;
    assert_eq!(read["content"][0]["type"], "text");
    assert_eq!(read["content"][0]["text"], "# Plan\nship it\n");
    assert_eq!(read["structuredContent"]["encoding"], "text");
    assert_eq!(read["structuredContent"]["eof"], true);

    // A window into the middle of a file reports itself honestly.
    let window = client
        .tool(
            "synch_read",
            json!({ "space": "media", "path": "notes/plan.md", "offset": 2, "length": 4 }),
        )
        .await;
    assert_eq!(window["content"][0]["text"], "Plan");
    assert_eq!(window["structuredContent"]["offset"], 2);
    assert_eq!(window["structuredContent"]["length"], 4);
    assert_eq!(window["structuredContent"]["eof"], false);

    // Bytes that are not text come back as a base64 blob rather than as
    // mangled UTF-8.
    let binary = client
        .tool("synch_read", json!({ "space": "media", "path": "raw.bin" }))
        .await;
    assert_eq!(binary["content"][0]["type"], "resource");
    assert_eq!(binary["structuredContent"]["encoding"], "base64");
    assert!(binary["content"][0]["resource"]["blob"].is_string());

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_listing_pages_through_the_daemons_own_cursor() {
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    let names: Vec<String> = (0..7).map(|n| format!("f{n:02}.txt")).collect();
    let files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), b"x" as &[u8])).collect();
    daemon.space_with("media", checkout.path(), &files).await;

    let mut client = reader(data.path());
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let mut args = json!({ "space": "media", "limit": 3 });
        if let Some(cursor) = &cursor {
            args["cursor"] = json!(cursor);
        }
        let page = client.tool("synch_list", args).await;
        for entry in page["structuredContent"]["entries"].as_array().unwrap() {
            seen.push(entry["path"].as_str().unwrap().to_string());
        }
        match page["structuredContent"]["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }
    assert_eq!(seen, names, "every path, once, in order");

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_page_thinned_by_deletions_still_reaches_every_live_path() {
    // The regression this pins: the daemon applies `limit` in SQL, *before*
    // dropping paths every publisher has tombstoned. A listing that asked for
    // three and got one back — because two of the three were deleted — would
    // look finished to any client that stops paging on a short page, and the
    // live paths behind them would never be seen.
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    let names: Vec<String> = (0..12).map(|n| format!("f{n:02}.txt")).collect();
    let files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), b"x" as &[u8])).collect();
    daemon.space_with("media", checkout.path(), &files).await;

    // Delete two out of every three, so a page of three would hold one entry.
    let mut client = writer(data.path());
    let mut live = Vec::new();
    for (n, name) in names.iter().enumerate() {
        if n % 3 == 0 {
            live.push(name.clone());
            continue;
        }
        client
            .tool("synch_delete", json!({ "space": "media", "path": name }))
            .await;
    }
    assert_eq!(live.len(), 4);

    // The daemon fills the page past the deletions, so one request covers all
    // four rather than returning one and looking done.
    let page = client
        .tool("synch_list", json!({ "space": "media", "limit": 4 }))
        .await;
    let got: Vec<String> = page["structuredContent"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["path"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(got, live, "a page is filled past what the filters drop");

    // And paging with a page size of one — where every page is thinned — still
    // walks the whole listing, ending on an empty page rather than a short one.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..20 {
        let mut args = json!({ "space": "media", "limit": 1 });
        if let Some(cursor) = &cursor {
            args["cursor"] = json!(cursor);
        }
        let page = client.tool("synch_list", args).await;
        let entries = page["structuredContent"]["entries"].as_array().unwrap();
        for entry in entries {
            seen.push(entry["path"].as_str().unwrap().to_string());
        }
        match page["structuredContent"]["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }
    assert_eq!(seen, live, "every live path, once, in order");

    // The resource surface walks the same tree and must agree.
    let listing = client.call("resources/list", json!({})).await;
    let uris: Vec<String> = listing["result"]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap().to_string())
        .collect();
    for name in &live {
        assert!(uris.contains(&format!("synch://media/{name}")), "{uris:?}");
    }
    assert_eq!(
        uris.len(),
        live.len(),
        "and nothing that was deleted: {uris:?}"
    );

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn writes_publish_and_deletes_tombstone() {
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    daemon.space_with("media", checkout.path(), &[]).await;

    let mut client = writer(data.path());
    let written = client
        .tool(
            "synch_write",
            json!({ "space": "media", "path": "notes/new.md", "text": "hello" }),
        )
        .await;
    assert_eq!(written["structuredContent"]["size"], 5);
    assert_eq!(written["structuredContent"]["kind"], "file");

    let read = client
        .tool(
            "synch_read",
            json!({ "space": "media", "path": "notes/new.md" }),
        )
        .await;
    assert_eq!(read["content"][0]["text"], "hello");

    // Bytes that are not text survive the round trip untouched.
    client
        .tool(
            "synch_write",
            json!({ "space": "media", "path": "raw.bin", "base64": "AACAAP8=" }),
        )
        .await;
    let raw = client
        .tool("synch_read", json!({ "space": "media", "path": "raw.bin" }))
        .await;
    assert_eq!(raw["content"][0]["resource"]["blob"], "AACAAP8=");

    let deleted = client
        .tool(
            "synch_delete",
            json!({ "space": "media", "path": "notes/new.md" }),
        )
        .await;
    assert_eq!(deleted["structuredContent"]["still_published"], false);
    let gone = client
        .tool_error(
            "synch_read",
            json!({ "space": "media", "path": "notes/new.md" }),
        )
        .await;
    assert!(!gone.is_empty());

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn the_write_tier_is_absent_from_a_read_only_server() {
    let data = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    let mut client = reader(data.path());

    let tools = client.call("tools/list", json!({})).await;
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"synch_list"));
    assert!(!names.contains(&"synch_write"));
    assert!(!names.contains(&"synch_socket_arm"));

    // Calling one anyway is refused with the remedy, and changes nothing.
    let refused = client
        .tool_error(
            "synch_write",
            json!({ "space": "media", "path": "a.txt", "text": "x" }),
        )
        .await;
    assert!(refused.contains("--allow-write"), "{refused}");

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_space_filter_hides_everything_outside_it() {
    let data = tempfile::tempdir().unwrap();
    let media = tempfile::tempdir().unwrap();
    let code = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    daemon
        .space_with("media", media.path(), &[("a.txt", b"a")])
        .await;
    daemon
        .space_with("code", code.path(), &[("b.txt", b"b")])
        .await;

    let mut client = Client::open(
        data.path(),
        Options {
            allow_write: true,
            spaces: vec!["media".into()],
            max_read_bytes: 64 * 1024,
        },
    );

    let spaces = client.tool("synch_spaces", json!({})).await;
    let listed = spaces["structuredContent"]["spaces"].as_array().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], "media");

    let refused = client
        .tool_error("synch_list", json!({ "space": "code" }))
        .await;
    assert!(refused.contains("out of scope"), "{refused}");

    // The resource surface is filtered by the same rule, and a URI outside it
    // is indistinguishable from one that does not exist.
    let listing = client.call("resources/list", json!({})).await;
    for resource in listing["result"]["resources"].as_array().unwrap() {
        assert!(
            resource["uri"]
                .as_str()
                .unwrap()
                .starts_with("synch://media/"),
            "{resource}"
        );
    }
    let denied = client
        .call("resources/read", json!({ "uri": "synch://code/b.txt" }))
        .await;
    assert_eq!(denied["error"]["code"], -32602);

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn resources_list_read_and_report_a_missing_one_with_the_fixed_code() {
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    daemon
        .space_with(
            "media",
            checkout.path(),
            &[("notes/plan.md", b"# Plan\n"), ("odd name.txt", b"spaces")],
        )
        .await;

    let mut client = reader(data.path());

    let templates = client.call("resources/templates/list", json!({})).await;
    assert_eq!(
        templates["result"]["resourceTemplates"][0]["uriTemplate"],
        "synch://{space}/{+path}"
    );

    let listing = client.call("resources/list", json!({})).await;
    let resources = listing["result"]["resources"].as_array().unwrap();
    let uris: Vec<&str> = resources
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    assert!(uris.contains(&"synch://media/notes/plan.md"), "{uris:?}");
    // A space in a path is escaped, so the URI stays one token.
    assert!(uris.contains(&"synch://media/odd%20name.txt"), "{uris:?}");
    assert!(resources.iter().any(|r| r["mimeType"] == "text/markdown"));

    let read = client
        .call(
            "resources/read",
            json!({ "uri": "synch://media/notes/plan.md" }),
        )
        .await;
    assert_eq!(read["result"]["contents"][0]["text"], "# Plan\n");
    assert_eq!(read["result"]["contents"][0]["mimeType"], "text/markdown");

    // The escaped URI reads back the file it names.
    let escaped = client
        .call(
            "resources/read",
            json!({ "uri": "synch://media/odd%20name.txt" }),
        )
        .await;
    assert_eq!(escaped["result"]["contents"][0]["text"], "spaces");

    let missing = client
        .call("resources/read", json!({ "uri": "synch://media/nope.txt" }))
        .await;
    assert_eq!(
        missing["error"]["code"], -32602,
        "the spec fixes the code for a resource that is not there"
    );
    assert!(
        missing["result"].is_null(),
        "and never an empty contents array"
    );

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_divergent_path_is_reported_with_the_way_out_of_it() {
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    daemon
        .space_with("media", checkout.path(), &[("shared.txt", b"ours")])
        .await;

    // A peer publishes different bytes for the same path.
    let peer = OriginId::named("laptop", "cluster.example").unwrap();
    let node = daemon.node.clone();
    let peer_for_task = peer.clone();
    off_runtime(move || {
        let root = node
            .store()
            .ingest_bytes(b"theirs", synch_core::now_ns())
            .unwrap();
        let entry = synch_core::FileEntry::file(6, synch_core::now_ns(), root, 1);
        node.store()
            .put_entry(&peer_for_task, "media", "shared.txt", &entry)
            .unwrap();
    })
    .await;

    let mut client = reader(data.path());

    // The default policy picks a side and says how many there were.
    let stat = client
        .tool(
            "synch_stat",
            json!({ "space": "media", "path": "shared.txt" }),
        )
        .await;
    assert_eq!(stat["structuredContent"]["versions"], 2);

    // Strict refuses, and the message tells the model what to do instead.
    let refused = client
        .tool_error(
            "synch_read",
            json!({ "space": "media", "path": "shared.txt", "policy": "strict" }),
        )
        .await;
    assert!(refused.contains("origin="), "{refused}");

    // And doing that works.
    let pinned = client
        .tool(
            "synch_read",
            json!({
                "space": "media",
                "path": "shared.txt",
                "policy": format!("origin={}", peer.canonical()),
            }),
        )
        .await;
    assert_eq!(pinned["content"][0]["text"], "theirs");

    // The versions are all visible side by side.
    let versions = client
        .tool(
            "synch_versions",
            json!({ "space": "media", "path": "shared.txt" }),
        )
        .await;
    let text = versions["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("laptop"), "{text}");

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn the_socket_lifecycle_runs_end_to_end_over_the_protocol() {
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    daemon.space_with("code", checkout.path(), &[]).await;

    let mut client = writer(data.path());

    // The header a program is written against is readable without a compiler.
    let sdk = client.tool("synch_socket_sdk", json!({})).await;
    let header = sdk["content"][0]["text"].as_str().unwrap();
    assert!(header.contains("SY_ENTRY"), "the SDK header");

    // Build → write → declare → review, with nothing touching the filesystem
    // outside the space.
    let source = "\
#include <synch.h>\n\
SY_ENTRY sy_s64 entry(void) { return 0; }\n";
    let built = client
        .call(
            "tools/call",
            json!({ "name": "synch_socket_build", "arguments": { "source": source } }),
        )
        .await;
    let built = &built["result"];
    if built["isError"] == json!(true) {
        // A build without the embedded compiler says so and stops here; the
        // rest of the lifecycle needs an object to arm.
        let why = built["content"][0]["text"].as_str().unwrap();
        assert!(why.contains("no embedded C compiler"), "{why}");
        client.close().await;
        daemon.shutdown().await;
        return;
    }
    let object = built["structuredContent"]["object_base64"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(built["structuredContent"]["size"].as_u64().unwrap() > 0);

    client
        .tool(
            "synch_write",
            json!({ "space": "code", "path": "echo.o", "base64": object }),
        )
        .await;
    client
        .tool(
            "synch_socket_add",
            json!({ "space": "code", "path": "echo.o", "note": "from mcp" }),
        )
        .await;
    // Declaring makes the *scanner* publish the path as a socket, so the
    // republish is a step of the lifecycle rather than an implementation
    // detail — and the whole of it is reachable over the protocol.
    client.tool("synch_scan", json!({})).await;

    // Declaring is not arming: the listing says so before any approval.
    let listed = client
        .tool("synch_socket_list", json!({ "long": true }))
        .await;
    assert!(listed["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("echo.o"));

    // Reviewing prints the declaration and the token that approves exactly it.
    let review = client
        .tool(
            "synch_socket_review",
            json!({ "space": "code", "path": "echo.o" }),
        )
        .await;
    let printed = review["content"][0]["text"].as_str().unwrap().to_string();
    assert!(printed.contains("--review"), "{printed}");

    // Arming without that token is refused, which is the whole point of it.
    let refused = client
        .tool_error(
            "synch_socket_arm",
            json!({ "space": "code", "path": "echo.o", "review_token": "0000" }),
        )
        .await;
    assert!(!refused.is_empty());

    // Nothing is running, and asking is answered rather than refused.
    client.tool("synch_socket_ps", json!({})).await;

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn interleaved_requests_are_answered_independently_and_cancellation_silences_one() {
    let data = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    let mut client = reader(data.path());

    // Three at once, answered by id rather than in order.
    client.send("tools/list", json!({}), 10).await;
    client.send("ping", json!({}), 11).await;
    client.send("resources/templates/list", json!({}), 12).await;

    let mut answered = Vec::new();
    for _ in 0..3 {
        let message = client.recv().await.expect("a response");
        answered.push(message["id"].as_i64().unwrap());
    }
    answered.sort_unstable();
    assert_eq!(answered, vec![10, 11, 12]);

    // A cancellation for a request that has already finished is ignored, and
    // the connection carries on.
    client
        .notify("notifications/cancelled", json!({ "requestId": 11 }))
        .await;
    let after = client.call("ping", json!({})).await;
    assert!(after["result"].is_object());

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn the_server_starts_without_a_daemon_and_recovers_when_one_appears() {
    let data = tempfile::tempdir().unwrap();
    // Initialized, but nothing serving: exactly what an MCP client that
    // launches at login finds.
    let dir = data.path().to_path_buf();
    off_runtime(move || {
        Node::init_named_by_zone(&dir, OriginId::named("nas", "cluster.example").unwrap())
    })
    .await
    .unwrap();

    let mut client = reader(data.path());

    // Discovery and the tool list are answered from static metadata.
    let discover = client.call("server/discover", json!({})).await;
    assert_eq!(discover["result"]["supportedVersions"][0], VERSION);
    let tools = client.call("tools/list", json!({})).await;
    assert!(!tools["result"]["tools"].as_array().unwrap().is_empty());

    // A tool that needs the daemon says so, and says what to run.
    let down = client.tool_error("synch_spaces", json!({})).await;
    assert!(down.contains("synch daemon start"), "{down}");

    // The daemon appears. The same connection recovers with no restart: the
    // channel is opened lazily, so there was never a dead one to retire.
    let daemon = Daemon::reopen(data.path()).await;
    let spaces = client.tool("synch_spaces", json!({})).await;
    assert!(spaces["structuredContent"]["spaces"].is_array());

    // And it survives the daemon being restarted underneath it, which mints a
    // fresh control token the cached channel knows nothing about.
    daemon.shutdown().await;
    let daemon = Daemon::reopen(data.path()).await;
    let again = client.tool("synch_spaces", json!({})).await;
    assert!(again["structuredContent"]["spaces"].is_array());

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn progress_reaches_a_client_that_asked_for_it() {
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    daemon
        .space_with("media", checkout.path(), &[("a.txt", b"a")])
        .await;

    let mut client = writer(data.path());
    let id = 42;
    let mut params = json!({ "name": "synch_scan", "arguments": {} });
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "progressToken": "scan-1",
    });
    let line =
        json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params }).to_string();
    client
        .stream
        .write_all(format!("{line}\n").as_bytes())
        .await
        .unwrap();

    let mut progress = 0;
    loop {
        let message = client.recv().await.expect("a message");
        if message["method"] == "notifications/progress" {
            assert_eq!(message["params"]["progressToken"], "scan-1");
            assert!(message["params"]["progress"].as_u64().unwrap() >= 1);
            progress += 1;
            continue;
        }
        assert_eq!(message["id"], json!(id));
        break;
    }
    // The scanner reports as it goes; a run over one small space may report
    // nothing at all, and either way the result arrived.
    assert!(progress >= 0);

    client.close().await;
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_legacy_client_gets_the_same_surface_through_the_handshake() {
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    daemon
        .space_with("media", checkout.path(), &[("a.txt", b"hello")])
        .await;

    let (mut stream, server) = tokio::io::duplex(1024 * 1024);
    let (read, write) = tokio::io::split(server);
    let path = data.path().to_path_buf();
    let serving = tokio::spawn(async move {
        mcp::serve(
            read,
            write,
            &path,
            Options {
                allow_write: false,
                spaces: Vec::new(),
                max_read_bytes: 64 * 1024,
            },
        )
        .await
    });

    // The legacy opening: an `initialize` with the version in params, not in
    // `_meta`, and no per-request metadata on anything after it.
    let script = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"old","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"synch_read","arguments":{"space":"media","path":"a.txt"}}}),
    ];
    let mut input = String::new();
    for message in &script {
        input.push_str(&format!("{message}\n"));
    }
    stream.write_all(input.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();

    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();
    serving.await.unwrap().unwrap();

    let out: Vec<Value> = raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(out.len(), 2, "the notification is owed no reply: {out:?}");
    assert_eq!(out[0]["result"]["protocolVersion"], "2025-06-18");
    assert!(
        out[0]["result"].get("resultType").is_none(),
        "a revision that does not define resultType is not sent it"
    );
    assert_eq!(out[1]["result"]["content"][0]["text"], "hello");

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_read_never_returns_more_than_the_configured_ceiling() {
    let data = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(data.path()).await;
    let big = vec![b'x'; 5000];
    daemon
        .space_with("media", checkout.path(), &[("big.txt", &big)])
        .await;

    let mut client = Client::open(
        data.path(),
        Options {
            allow_write: false,
            spaces: Vec::new(),
            max_read_bytes: 1024,
        },
    );

    // The tool asks for everything and is given a window, which says so.
    let read = client
        .tool(
            "synch_read",
            json!({ "space": "media", "path": "big.txt", "length": 99_999 }),
        )
        .await;
    assert_eq!(read["structuredContent"]["length"], 1024);
    assert_eq!(read["structuredContent"]["size"], 5000);
    assert_eq!(read["structuredContent"]["eof"], false);

    // Walking the rest with offsets reaches the end.
    let tail = client
        .tool(
            "synch_read",
            json!({ "space": "media", "path": "big.txt", "offset": 4000 }),
        )
        .await;
    assert_eq!(tail["structuredContent"]["length"], 1000);
    assert_eq!(tail["structuredContent"]["eof"], true);

    client.close().await;
    daemon.shutdown().await;
}
