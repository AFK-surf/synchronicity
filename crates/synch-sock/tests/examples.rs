//! The programs in `examples/`, compiled and run.
//!
//! An example is documentation that claims to work, which makes it the kind of
//! documentation that quietly stops working. These compile every `.c` in that
//! directory — so a new one is covered the moment it lands — and then run each
//! of them against a real stream and check what came back, because "it
//! compiles" is not the claim an example makes.

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::{path::PathBuf, sync::Arc};

use harness::{compile_with_clang, converse, exchange, peer, sdk, Harness};
use synch_core::SockStatus;
use synch_sock::{DuplexStream, EffectivePolicy, Limits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn examples_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/examples"))
}

fn source(name: &str) -> String {
    let path = examples_dir().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn build(name: &str) -> Vec<u8> {
    build_with(name, &[])
}

fn build_with(name: &str, defines: &[(&str, &str)]) -> Vec<u8> {
    synch_cc::compile(&source(name), name, &sdk(), defines)
        .unwrap_or_else(|e| panic!("examples/{name} does not compile:\n{e}"))
}

/// Everything in `examples/`, so nothing can be added and left uncovered.
fn every_example() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(examples_dir())
        .expect("the examples directory is there")
        .filter_map(|entry| {
            let path = entry.expect("a readable entry").path();
            (path.extension()? == "c").then(|| path.file_name()?.to_str().map(str::to_string))?
        })
        .collect();
    names.sort();
    names
}

/// Every example loads, declares a name, and has a stream entrypoint.
///
/// The floor under the specific tests below: whatever else an example does, it
/// is a program the runtime will accept and an operator can read a declaration
/// out of at arm time.
#[test]
fn every_example_compiles_loads_and_declares_itself() {
    let names = every_example();
    assert!(
        names.len() >= 5,
        "the examples directory has thinned out: {names:?}"
    );
    for name in &names {
        let elf = build(name);
        let declared = synch_sock::declare(&elf, Arc::new(harness::FakeTree::default()))
            .unwrap_or_else(|e| panic!("examples/{name} does not load: {e}"));
        assert!(
            !declared.name.is_empty(),
            "examples/{name} declares no name, so `synch socket arm` has nothing to show"
        );
        assert!(
            declared.max_streams.is_some(),
            "examples/{name} declares no concurrency cap"
        );
    }
}

#[tokio::test]
async fn compact_frames_runs_with_the_layout_it_declares() {
    let elf = build("compact-frames.c");
    let harness = Harness::new();
    let declaration = synch_sock::declare(&elf, harness.tree.clone()).expect("the hook ran");
    assert_eq!(declaration.stack_frame_size, Some(512));
    assert_eq!(declaration.guarded_stack_frames, Some(false));

    let policy = EffectivePolicy::armed(&declaration, vec![], None, 64);
    let (status, out) = exchange(&harness, &elf, b"", policy, peer(None), vec![]).await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"compact frames\n");
}

#[tokio::test]
async fn echo_returns_what_it_was_sent_and_counts_it() {
    let elf = build("echo.c");
    let harness = Harness::new();
    let (status, out) = exchange(
        &harness,
        &elf,
        b"hello sockets",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(out, b"hello sockets");
    assert_eq!(status, SockStatus::Ok(13), "the exit status counts bytes");
}

/// The regression the pump's cursor exists for.
///
/// A payload larger than the far side's window forces short writes. A pump
/// that returned "wrote some of it" and read again would lose the remainder —
/// silently, and only under exactly this condition, which is why it survived
/// review. Here the whole payload has to come back, byte for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_reader_costs_throughput_and_not_bytes() {
    let elf = build("echo.c");
    // Small enough that the guest's writes go short long before the payload
    // has been sent.
    let harness = Harness::with_tree_and_limits(
        &[],
        Limits {
            ring_bytes: 4096,
            ..Limits::default()
        },
    );

    let payload: Vec<u8> = (0..96 * 1024).map(|i| (i % 251) as u8).collect();
    let (status, out) = converse(&harness, &elf, payload.clone(), 8192).await;
    assert_eq!(
        out.len(),
        payload.len(),
        "the pump dropped {} bytes under backpressure",
        payload.len() as i64 - out.len() as i64
    );
    assert_eq!(out, payload, "the bytes came back reordered or corrupted");
    assert_eq!(status, SockStatus::Ok(payload.len() as i64));
}

#[tokio::test]
async fn whoami_reports_the_handshake_and_labels_the_caller_s_own_claims() {
    let elf = build("whoami.c");
    let harness = Harness::new();

    let (status, out) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(None),
        vec![("tag".into(), "laptop".into())],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("peer-origin:  laptop@cluster.example"),
        "{text}"
    );
    assert!(text.contains("peer-kind:    member"), "{text}");
    assert!(text.contains("reads `code`: yes"), "{text}");
    assert!(text.contains("this-node:    nas@cluster.example"), "{text}");
    assert!(text.contains("this-socket:  code/test.sock"), "{text}");
    // The device key, hex-encoded: 64 characters and no `sy_peer_device_key`
    // shortcut through the caller's own text.
    assert!(
        text.contains(&hex::encode(synch_sock::policy::NOBODY)),
        "{text}"
    );
    assert!(text.contains("claimed tag:  laptop"), "{text}");

    // A delegate is told it is one, and a space it does not hold is a `no`
    // whatever it says in its metadata.
    let (_, out) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(Some(vec!["photos".into()])),
        vec![("spaces".into(), "code".into())],
    )
    .await;
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("peer-kind:    delegate"), "{text}");
    assert!(text.contains("reads `code`: no"), "{text}");
    // Nothing was sent under `tag`, so nothing is printed under it.
    assert!(!text.contains("claimed tag:"), "{text}");
}

#[tokio::test]
async fn tree_cat_serves_the_directory_it_chose_and_nothing_above_it() {
    let elf = build("tree-cat.c");
    let harness = Harness::with_tree(&[
        ("code/pub/readme", "the tree, read from inside"),
        ("code/private/keys", "not this one"),
    ]);

    let (status, out) = exchange(
        &harness,
        &elf,
        b"readme\n",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"the tree, read from inside");

    // The traversal the validation exists for. It never reaches `sy_open`.
    for attempt in ["../private/keys\n", "..\n", "sub/dir\n", "\n"] {
        let (status, out) = exchange(
            &harness,
            &elf,
            attempt.as_bytes(),
            EffectivePolicy::default(),
            peer(None),
            vec![],
        )
        .await;
        assert_eq!(
            status,
            SockStatus::Ok(2),
            "{attempt:?} was not refused as a name"
        );
        assert!(
            String::from_utf8_lossy(&out).starts_with("usage:"),
            "{attempt:?} produced {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    // A well-formed name for a file that is not there.
    let (status, out) = exchange(
        &harness,
        &elf,
        b"absent\n",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(3));
    assert_eq!(out, b"no such file\n");
}

#[tokio::test]
async fn http_status_answers_http_and_counts_across_invocations() {
    let elf = build("http-status.c");
    let harness = Harness::new();

    let request = b"GET / HTTP/1.1\r\nHost: nas\r\n\r\n";
    let (status, out) = exchange(
        &harness,
        &elf,
        request,
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));

    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    let (head, body) = text
        .split_once("\r\n\r\n")
        .expect("a blank line ends the head");
    let declared: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .expect("a Content-Length")
        .trim()
        .parse()
        .expect("a number");
    assert_eq!(
        declared,
        body.len(),
        "the declared length is not the body's: {body:?}"
    );
    assert!(body.contains("node      nas@cluster.example"), "{body}");
    assert!(
        body.contains("peer      laptop@cluster.example (member)"),
        "{body}"
    );
    assert!(body.contains("requests  1"), "{body}");

    // The map outlives the invocation that wrote it, which is the whole
    // difference between socket state and program state.
    let (_, out) = exchange(
        &harness,
        &elf,
        request,
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert!(
        String::from_utf8_lossy(&out).contains("requests  2"),
        "the counter did not survive the first invocation"
    );
}

#[tokio::test]
async fn token_gate_lets_the_right_secret_through_and_nothing_else() {
    let elf = build("token-gate.c");
    let harness = Harness::new();
    let configured = |token: &str| EffectivePolicy {
        config: vec![("token".into(), token.into())],
        ..EffectivePolicy::default()
    };

    let (status, out) = exchange(
        &harness,
        &elf,
        b"hunter2\n",
        configured("hunter2"),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"ok\n");

    let (status, out) = exchange(
        &harness,
        &elf,
        b"hunter3\n",
        configured("hunter2"),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(4));
    assert_eq!(out, b"denied\n");

    // A prefix of the secret is not the secret: the length is checked before
    // the constant-time compare, which needs one count of bytes.
    let (status, _) = exchange(
        &harness,
        &elf,
        b"hunter\n",
        configured("hunter2"),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(4));

    // No `token` in the config is a refusal, not an open door.
    let (status, out) = exchange(
        &harness,
        &elf,
        b"anything\n",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(1));
    assert_eq!(out, b"misconfigured\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_proxy_reaches_the_upstream_it_declared_and_only_that_caller() {
    // A real listener, and the port it landed on becomes the constant the
    // example declares — which is what `#ifndef` and `--define` are for.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().unwrap().port();
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("a connection");
        let mut seen = Vec::new();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        socket.read_to_end(&mut seen).await.expect("the request");
        socket
            .write_all(format!("upstream saw {}", seen.len()).as_bytes())
            .await
            .expect("the reply");
        socket.shutdown().await.expect("a clean close");
        seen
    });

    let elf = build_with(
        "tcp-proxy.c",
        &[
            ("UPSTREAM_HOST", "\"127.0.0.1\""),
            ("UPSTREAM_PORT", &port.to_string()),
        ],
    );

    let declared =
        synch_sock::declare(&elf, Arc::new(harness::FakeTree::default())).expect("the proxy loads");
    assert_eq!(
        declared.egress,
        vec![format!("127.0.0.1:{port}")],
        "the declaration is what the operator approves, so it has to say the target"
    );

    let harness = Harness::new();
    // Arming approves the program's declaration. A literal address is the one
    // way it may name something in a range a DNS name must never reach.
    let armed = EffectivePolicy::armed(&declared, vec![], None, 64);

    let (status, out) = exchange(
        &harness,
        &elf,
        b"GET /info/refs\n",
        armed.clone(),
        peer(Some(vec!["code".into()])),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"upstream saw 15");
    assert_eq!(upstream.await.unwrap(), b"GET /info/refs\n");

    // A caller without `code` never gets as far as the connect.
    let (status, out) = exchange(
        &harness,
        &elf,
        b"GET /info/refs\n",
        armed,
        peer(Some(vec!["photos".into()])),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(1));
    assert!(out.is_empty(), "a refused caller was told something");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_upstream_does_not_spin_a_backpressured_proxy() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().unwrap().port();

    // Two complete endpoint rings put one chunk in the blocked host writer
    // and leave the second ring full. The final byte then becomes a pump
    // remainder at the same moment the upstream reaches terminal HUP.
    let prefix: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let tail = vec![0xfe];
    let mut expected = prefix.clone();
    expected.extend(&tail);
    let upstream_prefix = prefix;
    let upstream_tail = tail;
    let (prefix_sent, prefix_seen) = tokio::sync::oneshot::channel();
    let (send_tail, tail_allowed) = tokio::sync::oneshot::channel();
    let (eof_sent, eof_seen) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("a connection");
        let mut request = Vec::new();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        socket.read_to_end(&mut request).await.expect("the request");
        socket
            .write_all(&upstream_prefix)
            .await
            .expect("the response prefix");
        let _ = prefix_sent.send(());
        let _ = tail_allowed.await;
        socket
            .write_all(&upstream_tail)
            .await
            .expect("the response tail");
        socket.shutdown().await.expect("the upstream EOF");
        let _ = eof_sent.send(());
        request
    });

    let elf = build_with(
        "tcp-proxy.c",
        &[
            ("UPSTREAM_HOST", "\"127.0.0.1\""),
            ("UPSTREAM_PORT", &port.to_string()),
        ],
    );
    let declared =
        synch_sock::declare(&elf, Arc::new(harness::FakeTree::default())).expect("the proxy loads");
    let policy = EffectivePolicy::armed(&declared, vec![], None, 64);
    let harness = Harness::with_limits(Limits {
        ring_bytes: 4096,
        ..Limits::default()
    });
    let registry = harness.pool.registry().clone();

    let (mine, theirs) = tokio::io::duplex(1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let mut invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        policy,
        peer(Some(vec!["code".into()])),
        vec![],
    );
    let id = invocation.id;
    let socket = invocation.socket.qualified();
    let peer_name = invocation.peer.origin.to_string();
    invocation.slot = registry.reserve(
        id,
        &socket,
        &peer_name,
        invocation.peer.device_key,
        invocation.program_root,
        1,
        std::time::Instant::now(),
    );
    assert!(invocation.slot.is_some(), "the proxy was not admitted");

    let (start_reading, reading_allowed) = tokio::sync::oneshot::channel();
    let driver = tokio::spawn(async move {
        let mut mine = mine;
        mine.write_all(b"request").await.unwrap();
        mine.shutdown().await.unwrap();
        let _ = reading_allowed.await;
        let mut out = Vec::new();
        mine.read_to_end(&mut out).await.unwrap();
        out
    });
    let pool = harness.pool.clone();
    let running = tokio::spawn(async move { pool.run(invocation).await.expect("the program ran") });

    tokio::time::timeout(std::time::Duration::from_secs(5), prefix_seen)
        .await
        .expect("the upstream did not send its prefix")
        .expect("the upstream stopped before its prefix");
    // A generous bound with a gentle poll: filling the path takes several
    // ring-to-writer handoffs across threads, and on a loaded CI runner a
    // hot yield loop under a tight clock has timed out spuriously.
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let seen = registry.snapshot(None, std::time::Instant::now());
            if seen.first().is_some_and(|info| info.bytes_out >= 8192) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("the response prefix never filled the caller-facing path");

    let _ = send_tail.send(());
    tokio::time::timeout(std::time::Duration::from_secs(5), eof_seen)
        .await
        .expect("the upstream did not send EOF")
        .expect("the upstream stopped before EOF");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let before = registry.snapshot(None, std::time::Instant::now())[0].polls;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let after = registry.snapshot(None, std::time::Instant::now())[0].polls;

    // Always release the reader before asserting, so a failure cannot leave
    // the invocation and its worker blocked behind the test's own gate.
    let _ = start_reading.send(());
    let outcome = running.await.unwrap();
    let out = driver.await.unwrap();
    let request = upstream.await.unwrap();

    assert_eq!(outcome.status, SockStatus::Ok(0));
    assert_eq!(request, b"request");
    assert_eq!(
        out, expected,
        "the terminal upstream truncated its response"
    );
    assert!(
        after.saturating_sub(before) <= 8,
        "an inactive upstream HUP caused {} polls in 50 ms",
        after.saturating_sub(before)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn splice_proxy_forwards_both_directions_without_a_buffer() {
    // A payload several rings deep in each direction: a spliced proxy moves
    // what fits and comes back for the rest, and bytes it could not place stay
    // in the ring they were in. Anything less than the whole of it arriving,
    // in order, would mean the host lost the part it did not move.
    let request: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let response: Vec<u8> = (0..40_000).map(|i| (i % 241) as u8).collect();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().unwrap().port();
    let sent = response.clone();
    let upstream = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("a connection");
        let (mut reader, mut writer) = tokio::io::split(socket);
        // Both halves at once, and the reply deliberately does not wait for the
        // request: an upstream that answers early can reach EOF downstream
        // while the proxy still has request bytes queued upstream, so the
        // invocation can end owing bytes in a direction it has stopped
        // watching. Can, not will — by then both directions have been shut and
        // polled, so the ring is usually empty and this is a forwarding test
        // that merely leans on the teardown drain. The regression guard for the
        // drain itself is `what_a_program_queued_upstream_survives_the_end_of_
        // the_invocation` in `invoke.rs`, which fills the path on purpose.
        let replying = tokio::spawn(async move {
            writer.write_all(&sent).await.expect("the reply");
            writer.shutdown().await.expect("a clean close");
        });
        let mut seen = Vec::new();
        reader.read_to_end(&mut seen).await.expect("the request");
        replying.await.unwrap();
        seen
    });

    let elf = build_with(
        "splice-proxy.c",
        &[
            ("UPSTREAM_HOST", "\"127.0.0.1\""),
            ("UPSTREAM_PORT", &port.to_string()),
        ],
    );
    let declared = synch_sock::declare(&elf, Arc::new(harness::FakeTree::default()))
        .expect("the spliced proxy loads");
    assert_eq!(declared.egress, vec![format!("127.0.0.1:{port}")]);

    let harness = Harness::with_limits(Limits {
        ring_bytes: 4096,
        ..Limits::default()
    });
    let (mine, theirs) = tokio::io::duplex(8192);
    let (their_r, their_w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::armed(&declared, vec![], None, 64),
        peer(Some(vec!["code".into()])),
        vec![],
    );

    let (mut reader, mut writer) = tokio::io::split(mine);
    let sending = {
        let request = request.clone();
        tokio::spawn(async move {
            writer.write_all(&request).await.expect("the request");
            writer.shutdown().await.expect("a clean half-close");
        })
    };
    let receiving = tokio::spawn(async move {
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        out
    });

    let outcome = harness.pool.run(invocation).await.expect("the program ran");
    sending.await.unwrap();
    let out = receiving.await.unwrap();

    assert_eq!(outcome.status, SockStatus::Ok(0));
    assert_eq!(upstream.await.unwrap(), request, "the request was mangled");
    assert_eq!(out, response, "the response was mangled");
    assert_eq!(
        (outcome.bytes_in, outcome.bytes_out),
        (request.len() as u64, response.len() as u64),
        "a spliced proxy is not counted for `synch socket ps`"
    );
}

/// A stock SSH client for the shell example: the transport is already
/// authenticated by the harness, so the host key is accepted as presented.
struct ShellClient;

/// Waits for the shell's startup output to settle — the prompt is drawn and
/// nothing more arrives for half a second — before the test types anything.
///
/// A real user types at the prompt, and old interactive shells depend on it:
/// bash 3.2 (macOS's `/bin/bash`) configures its terminal with flush-style
/// `tcsetattr` during startup, discarding keystrokes that arrived early,
/// where modern bash deliberately preserves that typeahead.
async fn settle_at_prompt(channel: &mut russh::Channel<russh::client::Msg>, output: &mut Vec<u8>) {
    use std::time::Duration;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        match tokio::time::timeout(Duration::from_millis(500), channel.wait()).await {
            Ok(Some(russh::ChannelMsg::Data { data })) => output.extend_from_slice(&data),
            Ok(Some(russh::ChannelMsg::ExtendedData { data, .. })) => {
                output.extend_from_slice(&data)
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                if !output.is_empty() {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the shell never drew its prompt"
                );
            }
        }
    }
}

impl russh::client::Handler for ShellClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// `ssh-shell.c` end to end: SSH `none` completes against the outer identity,
/// `pty-req` allocates a terminal without starting anything, `shell` starts
/// exactly the declared `/bin/bash`, the splice loop carries keystrokes and
/// output both ways, and the shell's own exit status arrives after its last
/// output rather than racing it away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_shell_serves_the_declared_bash_on_a_pty() {
    use std::time::Duration;

    let elf = build("ssh-shell.c");
    let harness = Harness::new();

    // The declaration is the whole approval surface: the exact executable and
    // argv, PTY permission, and nothing an SSH client could widen.
    let declaration = synch_sock::declare(&elf, harness.tree.clone()).expect("the hook ran");
    assert_eq!(
        declaration.processes.len(),
        1,
        "one exact process capability is what the operator approves"
    );
    let bash = &declaration.processes[0];
    // The declared path is resolved at arm time, so a merged-/usr host shows
    // the operator `/usr/bin/bash` for a program that named `/bin/bash`.
    assert!(
        bash.executable.ends_with("/bash"),
        "the resolved shell is still bash: {}",
        bash.executable
    );
    assert_eq!(bash.argv, vec!["bash".to_string()]);
    assert_eq!(bash.flags & 0x01, 0x01, "PTY permission is declared");

    let policy = EffectivePolicy::armed(&declaration, vec![], None, 64);
    let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_stream);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(server_reader, server_writer),
        policy,
        peer(None),
        vec![],
    );
    let run = tokio::spawn(async move { harness.pool.run(invocation).await.unwrap() });

    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        ShellClient,
    )
    .await
    .expect("SSH handshake completed");
    assert!(
        client
            .authenticate_none("operator")
            .await
            .expect("none authentication got a response")
            .success(),
        "the outer identity is the authentication factor here"
    );

    let mut channel = client
        .channel_open_session()
        .await
        .expect("a session channel");
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("the pty request was sent");
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(10), channel.wait())
                .await
                .expect("a pty-req answer"),
            Some(russh::ChannelMsg::Success)
        ),
        "allocating the terminal succeeds without starting a process"
    );
    channel
        .request_shell(true)
        .await
        .expect("the shell request was sent");
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(10), channel.wait())
                .await
                .expect("a shell answer"),
            Some(russh::ChannelMsg::Success)
        ),
        "the declared shell started"
    );

    // Type only once the prompt is drawn, as a person would.
    let mut output = Vec::new();
    settle_at_prompt(&mut channel, &mut output).await;

    // Typed at the terminal: bash expands the arithmetic, so seeing the
    // expansion in the output proves a real shell ran — the echoed input
    // still spells `$((6*7))`.
    channel
        .data(&b"echo interactive-$((6*7)); exit 3\n"[..])
        .await
        .expect("keystrokes reached the channel");

    // The server reports the shell's exit and half-closes; closing the
    // channel back is the client's move, exactly as OpenSSH would.
    let mut exit_status = None;
    let mut eof = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !(eof && exit_status.is_some()) {
        let message = tokio::time::timeout_at(deadline, channel.wait())
            .await
            .expect("the shell session concluded");
        match message {
            Some(russh::ChannelMsg::Data { data }) => output.extend_from_slice(&data),
            Some(russh::ChannelMsg::ExtendedData { data, .. }) => output.extend_from_slice(&data),
            Some(russh::ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
            Some(russh::ChannelMsg::Eof) => eof = true,
            Some(russh::ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
    }
    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("interactive-42"),
        "bash did not run the command: {text:?}"
    );
    assert_eq!(
        exit_status,
        Some(3),
        "the shell's own exit status reached the client: {text:?}"
    );

    // A second login on the same connection: the finished session freed its
    // slot, so a fresh shell starts with a fresh lifecycle (§7.3).
    let mut second = client
        .channel_open_session()
        .await
        .expect("a second session channel");
    second
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("the second pty request was sent");
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), second.wait())
            .await
            .expect("a second pty-req answer"),
        Some(russh::ChannelMsg::Success)
    ));
    second
        .request_shell(true)
        .await
        .expect("the second shell request was sent");
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), second.wait())
            .await
            .expect("a second shell answer"),
        Some(russh::ChannelMsg::Success)
    ));
    let mut second_output = Vec::new();
    settle_at_prompt(&mut second, &mut second_output).await;
    second
        .data(&b"exit 0\n"[..])
        .await
        .expect("keystrokes reached the second channel");
    let mut second_status = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while second_status.is_none() {
        match tokio::time::timeout_at(deadline, second.wait())
            .await
            .expect("the second shell concluded")
        {
            Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                second_status = Some(exit_status)
            }
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(
        second_status,
        Some(0),
        "the second session ran to completion"
    );

    client
        .disconnect(russh::Disconnect::ByApplication, "logout", "en")
        .await
        .expect("a clean disconnect");
    drop(client);
    let outcome = tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("the invocation ended with the connection")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}

/// The runtime loads an object somebody else's compiler wrote.
///
/// Every other test here builds with the compiler in the binary, which would
/// hide a disagreement between the two: the runtime takes ELF, not tinycc's
/// ELF. Skipped where clang cannot target BPF, because a machine without the
/// toolchain cannot answer this and a red test that means "no compiler"
/// teaches people to ignore red tests.
#[tokio::test]
async fn an_example_built_with_clang_runs_the_same_way() {
    let Some(elf) = compile_with_clang(&source("echo.c"), "echo.c") else {
        return;
    };
    let harness = Harness::new();
    let (status, out) = exchange(
        &harness,
        &elf,
        b"built elsewhere",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(out, b"built elsewhere");
    assert_eq!(status, SockStatus::Ok(15));
}
