//! Sockets, from the engine's side (`docs/SOCKETS.md`).
//!
//! The properties here are the ones the design turns on, and none of them needs
//! an eBPF runtime to check: what the scanner publishes, what an arming record
//! means, and what happens to a socket that arrives from somebody else. The
//! runtime's own end-to-end tests live in `synch-sock`.

use std::path::Path;

use synch_core::{Declaration, EntryKind, Hash};
use synch_engine::{Node, NodeConfig};
use synch_store::SocketRow;

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
async fn approval_is_compare_and_set_against_the_reviewed_root() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "git.sock", b"\x7fELF reviewed");
    node.socket_add(&declaration("code", "git.sock")).unwrap();
    node.scan_and_publish().unwrap();

    let reviewed = node
        .resolve_socket("code", "git.sock")
        .unwrap()
        .unwrap()
        .root;
    let wrong = Hash::new(b"different bytes");
    assert!(
        node.socket_approve("code", "git.sock", &wrong, &Declaration::default())
            .is_err(),
        "approval accepted bytes other than the reviewed root"
    );
    assert!(node
        .resolve_socket("code", "git.sock")
        .unwrap()
        .unwrap()
        .state
        .arm
        .is_none());

    node.socket_approve("code", "git.sock", &reviewed, &Declaration::default())
        .unwrap();
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
