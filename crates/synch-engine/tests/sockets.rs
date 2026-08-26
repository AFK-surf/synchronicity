//! Sockets, from the engine's side (`docs/SOCKETS.md`).
//!
//! The properties here are the ones the design turns on, and none of them needs
//! an eBPF runtime to check: what the scanner publishes, what an arming record
//! means, and what happens to a socket that arrives from somebody else. The
//! runtime's own end-to-end tests live in `synch-sock`.

mod common;

use std::path::Path;

use synch_core::{EntryKind, Hash};
use synch_engine::{Node, NodeConfig};
use synch_store::{ArmCandidate, SocketRow};

/// A node with one space, and the directory that space indexes.
async fn node_with_space() -> (tempfile::TempDir, tempfile::TempDir, Node) {
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    Node::init(data.path(), None).unwrap();
    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    node.add_space("code", space.path()).unwrap();
    (data, space, node)
}

fn write(space: &Path, name: &str, body: &[u8]) {
    if let Some(parent) = Path::new(name).parent() {
        std::fs::create_dir_all(space.join(parent)).unwrap();
    }
    std::fs::write(space.join(name), body).unwrap();
}

fn declaration(space: &str, path: &str) -> SocketRow {
    SocketRow::new(space, path, synch_core::now_ns())
}

#[tokio::test]
async fn a_declared_path_is_published_as_a_socket_and_an_undeclared_one_is_not() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "git.sock", b"\x7fELF not really");
    write(space.path(), "readme.md", b"hello");

    node.socket_add(&declaration("code", "git.sock")).unwrap();
    node.scan_and_publish().unwrap();

    let socket = node
        .store()
        .entry(node.origin(), "code", "git.sock")
        .unwrap()
        .unwrap();
    assert_eq!(socket.kind, EntryKind::Socket);
    assert!(socket.content.is_some(), "a socket carries its ELF's root");

    let plain = node
        .store()
        .entry(node.origin(), "code", "readme.md")
        .unwrap()
        .unwrap();
    assert_eq!(plain.kind, EntryKind::File);
}

#[tokio::test]
async fn declaring_an_unchanged_published_file_changes_its_kind() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "git.sock", b"\x7fELF unchanged");
    node.scan_and_publish().unwrap();
    assert_eq!(
        node.store()
            .entry(node.origin(), "code", "git.sock")
            .unwrap()
            .unwrap()
            .kind,
        EntryKind::File
    );

    node.socket_add(&declaration("code", "git.sock")).unwrap();
    node.scan_and_publish().unwrap();
    assert_eq!(
        node.store()
            .entry(node.origin(), "code", "git.sock")
            .unwrap()
            .unwrap()
            .kind,
        EntryKind::Socket,
        "the scanner's unchanged-file cache hid the new declaration"
    );
}

#[tokio::test]
async fn removing_the_declaration_republishes_it_as_an_ordinary_file() {
    // The kind is an assertion this origin makes about its own copy, so
    // withdrawing the assertion has to change what it publishes.
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "git.sock", b"\x7fELF");
    node.socket_add(&declaration("code", "git.sock")).unwrap();
    node.scan_and_publish().unwrap();
    assert_eq!(
        node.store()
            .entry(node.origin(), "code", "git.sock")
            .unwrap()
            .unwrap()
            .kind,
        EntryKind::Socket
    );

    assert!(node.socket_rm("code", "git.sock").unwrap());
    node.scan_and_publish().unwrap();

    assert_eq!(
        node.store()
            .entry(node.origin(), "code", "git.sock")
            .unwrap()
            .unwrap()
            .kind,
        EntryKind::File,
        "a path with no declaration must publish as a file"
    );
}

#[tokio::test]
async fn arming_pins_the_bytes_and_a_change_disarms_without_unpublishing() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "git.sock", b"\x7fELF v1");
    node.socket_add(&declaration("code", "git.sock")).unwrap();
    node.scan_and_publish().unwrap();

    let first = node.resolve_socket("code", "git.sock").unwrap().unwrap();
    // Armed by hand rather than through `socket_arm`, which runs the program's
    // declaration hook and so needs a real eBPF object.
    node.store()
        .arm_socket("code", "git.sock", &first.root, "", synch_core::now_ns())
        .unwrap();
    assert!(node
        .resolve_socket("code", "git.sock")
        .unwrap()
        .unwrap()
        .state
        .is_armed_for(&first.root));

    write(space.path(), "git.sock", b"\x7fELF v2, unapproved");
    node.scan_and_publish().unwrap();

    let second = node.resolve_socket("code", "git.sock").unwrap().unwrap();
    assert_ne!(second.root, first.root, "the bytes changed");
    assert!(
        !second.state.is_armed_for(&second.root),
        "changed bytes must not stay armed"
    );
    assert_eq!(
        node.store()
            .entry(node.origin(), "code", "git.sock")
            .unwrap()
            .unwrap()
            .kind,
        EntryKind::Socket,
        "a disarmed socket is still published; it just will not run"
    );
}

#[tokio::test]
async fn approval_is_compare_and_set_against_the_reviewed_state() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "git.sock", b"\x7fELF reviewed");
    node.socket_add(&declaration("code", "git.sock")).unwrap();
    node.scan_and_publish().unwrap();

    let resolved = node.resolve_socket("code", "git.sock").unwrap().unwrap();
    let reviewed = resolved.root;
    let wrong = Hash::new(b"different bytes");
    assert!(
        !node
            .store()
            .arm_socket_reviewed(
                node.origin(),
                "code",
                "git.sock",
                ArmCandidate {
                    generation: &resolved.state.generation,
                    root: &wrong,
                    declared: "",
                    armed_at: synch_core::now_ns(),
                },
            )
            .unwrap(),
        "approval accepted bytes other than the reviewed root"
    );
    assert!(node
        .resolve_socket("code", "git.sock")
        .unwrap()
        .unwrap()
        .state
        .arm
        .is_none());

    assert!(node
        .store()
        .arm_socket_reviewed(
            node.origin(),
            "code",
            "git.sock",
            ArmCandidate {
                generation: &resolved.state.generation,
                root: &reviewed,
                declared: "",
                armed_at: synch_core::now_ns(),
            },
        )
        .unwrap());
    assert!(node
        .resolve_socket("code", "git.sock")
        .unwrap()
        .unwrap()
        .state
        .is_armed_for(&reviewed));
}

#[tokio::test]
async fn adopting_someone_elses_socket_adopts_its_bytes_and_not_its_socket_ness() {
    // The property the whole design rests on: a node executes only what is in
    // its own tree, and taking a peer's socket does not put a socket in it.
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "theirs.sock", b"\x7fELF from a peer");
    node.scan_and_publish().unwrap();

    let entry = node
        .store()
        .entry(node.origin(), "code", "theirs.sock")
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.kind,
        EntryKind::File,
        "bytes that arrived from elsewhere are a file until this node says otherwise"
    );
    assert!(
        node.resolve_socket("code", "theirs.sock")
            .unwrap()
            .is_none(),
        "an undeclared path resolves to no socket at all"
    );
}

#[tokio::test]
async fn a_socket_cannot_be_declared_outside_a_space_this_node_indexes() {
    let (_data, _space, node) = node_with_space().await;
    assert!(node.socket_add(&declaration("nowhere", "x.sock")).is_err());
    assert!(
        node.socket_add(&declaration("code", "../escape.sock"))
            .is_err(),
        "a path that leaves the space must be refused at declaration"
    );
}

#[tokio::test]
async fn a_socket_cannot_be_declared_in_a_detached_space() {
    let data = tempfile::tempdir().unwrap();
    Node::init(data.path(), None).unwrap();
    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    node.add_detached_space("code").unwrap();
    let err = node.socket_add(&declaration("code", "git.sock"));
    assert!(err.is_err(), "a space with no scanner accepted a socket");
}

#[tokio::test]
async fn a_declared_path_with_nothing_published_resolves_to_nothing() {
    let (_data, _space, node) = node_with_space().await;
    node.socket_add(&declaration("code", "missing.sock"))
        .unwrap();
    assert!(node
        .resolve_socket("code", "missing.sock")
        .unwrap()
        .is_none());
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn a_node_can_connect_to_its_own_socket() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "local.sock", b"\x7fELF not armed");
    node.socket_add(&declaration("code", "local.sock")).unwrap();
    node.scan_and_publish().unwrap();

    let err = node
        .connect_socket(node.origin(), "code", "local.sock", Vec::new())
        .await
        .expect_err("an unarmed socket should be refused after the self-connection lands");
    assert!(
        err.to_string().contains("declared but never armed"),
        "self-connection did not reach socket admission: {err}"
    );
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn a_self_connection_runs_the_armed_program() {
    use synch_core::SockStatus;
    use synch_engine::sockets::SocketConnection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (_data, space, node) = node_with_space().await;
    let elf = synch_cc::compile(
        include_str!("../../synch-sock/examples/echo.c"),
        "echo.c",
        &[("synch.h", synch_sock::sdk::HEADER)],
        &[],
    )
    .unwrap();
    write(space.path(), "echo.sock", &elf);
    node.socket_add(&declaration("code", "echo.sock")).unwrap();
    node.scan_and_publish().unwrap();
    let inspected = node.socket_inspect("code", "echo.sock").await.unwrap();
    node.socket_approve("code", "echo.sock", &inspected.review)
        .await
        .unwrap();

    let connection = node
        .connect_socket(node.origin(), "code", "echo.sock", Vec::new())
        .await
        .unwrap();
    let SocketConnection::Local {
        mut stream,
        completion,
        ..
    } = connection
    else {
        panic!("a self-connection used the remote transport");
    };
    stream.write_all(b"hello local socket").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello local socket");
    assert_eq!(
        completion.await.unwrap(),
        SockStatus::Ok(echoed.len() as i64)
    );
    node.shutdown().await.unwrap();
}

/// The daemon uses a multi-thread Tokio runtime, whose workers must never open
/// the synchronous SQLite store. Keep the fixture setup outside that runtime,
/// then exercise the complete async arm/admit/run path inside it. A regression
/// here aborts in debug builds at `Store::conn`, exactly as a real daemon does.
#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn a_daemon_style_runtime_can_arm_and_run_a_self_socket() {
    use synch_core::SockStatus;
    use synch_engine::sockets::SocketConnection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    Node::init(data.path(), None).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = runtime
        .block_on(Node::open(NodeConfig::loopback(data.path())))
        .unwrap();

    // These are the daemon command handler's synchronous operations; that
    // handler already offloads them. Here setup happens outside any runtime.
    node.add_space("code", space.path()).unwrap();
    let elf = synch_cc::compile(
        include_str!("../../synch-sock/examples/echo.c"),
        "echo.c",
        &[("synch.h", synch_sock::sdk::HEADER)],
        &[],
    )
    .unwrap();
    write(space.path(), "echo.sock", &elf);
    node.socket_add(&declaration("code", "echo.sock")).unwrap();
    node.scan_and_publish().unwrap();

    runtime.block_on(async {
        let inspected = node.socket_inspect("code", "echo.sock").await.unwrap();
        node.socket_approve("code", "echo.sock", &inspected.review)
            .await
            .unwrap();
        let connection = node
            .connect_socket(node.origin(), "code", "echo.sock", Vec::new())
            .await
            .unwrap();
        let SocketConnection::Local {
            mut stream,
            completion,
            ..
        } = connection
        else {
            panic!("a self-connection used the remote transport");
        };
        stream.write_all(b"daemon runtime").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"daemon runtime");
        assert_eq!(
            completion.await.unwrap(),
            SockStatus::Ok(echoed.len() as i64)
        );
        node.shutdown().await.unwrap();
    });
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn a_discovery_only_peer_can_connect_to_a_socket() {
    use iroh::address_lookup::memory::MemoryLookup;
    use synch_core::SockStatus;
    use synch_engine::sockets::SocketConnection;
    use tokio::io::AsyncWriteExt;

    let (_server_data, server_space, server) = node_with_space().await;
    let (_client_data, _client_space, client) = node_with_space().await;
    let elf = synch_cc::compile(
        include_str!("../../synch-sock/examples/echo.c"),
        "echo.c",
        &[("synch.h", synch_sock::sdk::HEADER)],
        &[],
    )
    .unwrap();
    write(server_space.path(), "echo.sock", &elf);
    server
        .socket_add(&declaration("code", "echo.sock"))
        .unwrap();
    server.scan_and_publish().unwrap();
    let inspected = server.socket_inspect("code", "echo.sock").await.unwrap();
    server
        .socket_approve("code", "echo.sock", &inspected.review)
        .await
        .unwrap();

    // Trust is present in both directions, but neither node records the
    // other's address in `peers_seen`. The client's iroh resolver is the only
    // source of the server's transport address.
    client
        .store()
        .put_binding(&common::binding(server.origin(), &server.node_id()))
        .unwrap();
    server
        .store()
        .put_binding(&common::binding(client.origin(), &client.node_id()))
        .unwrap();
    assert!(client.peer_addr(&server.node_id()).unwrap().is_none());
    client
        .net()
        .endpoint()
        .address_lookup()
        .unwrap()
        .add(MemoryLookup::from_endpoint_info([server
            .net()
            .direct_addr()]));

    let connection = client
        .connect_socket(server.origin(), "code", "echo.sock", Vec::new())
        .await
        .unwrap();
    let SocketConnection::Remote {
        client: socket_client,
        mut control,
        stream,
    } = connection
    else {
        panic!("a peer connection used the local transport");
    };
    let synch_net::sock::SockStream {
        mut send, mut recv, ..
    } = stream;
    send.write_all(b"discovered").await.unwrap();
    send.shutdown().await.unwrap();
    let echoed = recv.read_to_end(1024).await.unwrap();
    let closed = socket_client.next_closed(&mut control).await.unwrap();

    assert_eq!(echoed, b"discovered");
    assert_eq!(closed.status, SockStatus::Ok(echoed.len() as i64));
    common::shutdown(&[&client, &server]).await;
}

#[tokio::test]
async fn auto_follows_the_file_and_the_default_does_not() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "manual.sock", b"\x7fELF a");
    write(space.path(), "auto.sock", b"\x7fELF a");
    node.socket_add(&declaration("code", "manual.sock"))
        .unwrap();
    node.socket_add(&SocketRow {
        auto: true,
        ..declaration("code", "auto.sock")
    })
    .unwrap();
    node.scan_and_publish().unwrap();

    // Neither is armed yet: a declaration is not an approval.
    for path in ["manual.sock", "auto.sock"] {
        let state = node.resolve_socket("code", path).unwrap().unwrap();
        assert!(state.state.arm.is_none(), "{path} armed itself");
    }

    // Auto-arming needs a program that loads, and these bytes are not one, so
    // what this checks is the half that does not depend on a runtime: the
    // manual socket is left alone and neither is armed to bytes nobody
    // approved.
    write(space.path(), "manual.sock", b"\x7fELF b");
    write(space.path(), "auto.sock", b"\x7fELF b");
    node.scan_and_publish().unwrap();

    for path in ["manual.sock", "auto.sock"] {
        let resolved = node.resolve_socket("code", path).unwrap().unwrap();
        assert!(
            !resolved.state.is_armed_for(&resolved.root),
            "{path} armed itself to a program that does not load"
        );
    }
}

#[tokio::test]
async fn a_dropped_node_is_actually_dropped() {
    // A regression test for a reference cycle, not a hypothetical. The node
    // owns its endpoint, the endpoint's router owns the socket protocol
    // handler, and the handler holds the dispatcher — so a strong reference
    // from the dispatcher back to the node keeps every node ever opened alive,
    // with its database open. Nothing surfaces that until something reopens the
    // same data directory, which is a long way from the cause.
    let data = tempfile::tempdir().unwrap();
    Node::init(data.path(), None).unwrap();
    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    node.shutdown().await.unwrap();
    drop(node);

    // Reopening the same directory is what a leaked node makes fail.
    let again = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    assert!(again.own_head().unwrap().is_none() || again.own_head().unwrap().is_some());
    again.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_socket_that_is_not_declared_here_never_resolves_however_it_is_named() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "a/b/c.sock", b"\x7fELF");
    node.socket_add(&declaration("code", "a/b/c.sock")).unwrap();
    node.scan_and_publish().unwrap();

    assert!(node.resolve_socket("code", "a/b/c.sock").unwrap().is_some());
    // A different space with the same path is a different socket, and this
    // node declares nothing there.
    assert!(node
        .resolve_socket("other", "a/b/c.sock")
        .unwrap()
        .is_none());
    assert!(node.resolve_socket("code", "a/b").unwrap().is_none());
}

#[tokio::test]
async fn the_arming_record_survives_a_restart_and_the_map_does_not() {
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    Node::init(data.path(), None).unwrap();
    let root = {
        let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
        node.add_space("code", space.path()).unwrap();
        write(space.path(), "git.sock", b"\x7fELF");
        node.socket_add(&declaration("code", "git.sock")).unwrap();
        node.scan_and_publish().unwrap();
        let resolved = node.resolve_socket("code", "git.sock").unwrap().unwrap();
        node.store()
            .arm_socket(
                "code",
                "git.sock",
                &resolved.root,
                "name test",
                synch_core::now_ns(),
            )
            .unwrap();
        node.shutdown().await.unwrap();
        resolved.root
    };

    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    let resolved = node.resolve_socket("code", "git.sock").unwrap().unwrap();
    assert_eq!(resolved.root, root);
    assert!(
        resolved.state.is_armed_for(&root),
        "an approval must survive a restart; it is operator state, not a cache"
    );
    assert_eq!(
        resolved.state.arm.unwrap().declared,
        "name test",
        "what was approved is kept, so `socket ls` can show it"
    );
}

#[tokio::test]
async fn resolving_ignores_what_other_origins_publish() {
    // Connecting to a socket names an origin, and resolution reads that
    // origin's trie only. `newest` would otherwise let any member's mtime
    // decide whose program a connection lands on.
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "git.sock", b"\x7fELF mine");
    node.socket_add(&declaration("code", "git.sock")).unwrap();
    node.scan_and_publish().unwrap();
    let mine = node.resolve_socket("code", "git.sock").unwrap().unwrap();

    // A peer publishes a different program at the same path, with a later
    // mtime — which is what would win a `newest` selection.
    let peer = synch_core::OriginId::named("nas", "cluster.example").unwrap();
    let theirs = Hash::new(b"\x7fELF theirs");
    node.store()
        .put_entry(
            &peer,
            "code",
            "git.sock",
            &synch_core::FileEntry::socket(11, i64::MAX, theirs, 1),
        )
        .unwrap();

    let after = node.resolve_socket("code", "git.sock").unwrap().unwrap();
    assert_eq!(
        after.root, mine.root,
        "resolution followed a peer's entry instead of this node's own"
    );
}
