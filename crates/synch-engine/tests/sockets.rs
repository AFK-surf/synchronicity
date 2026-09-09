//! Sockets, from the engine's side (`docs/SOCKETS.md`,
//! `docs/SOCKET-PROGRAMS.md`).
//!
//! The properties here are the ones the design turns on, and most of them need
//! no eBPF runtime to check: what the scanner publishes, what an activation
//! binds, who a scope admits, and what a deployment moves. The runtime's own
//! end-to-end tests live in `synch-sock`.

mod common;

use std::path::Path;

use synch_core::{EntryKind, Hash, RefuseCode};
use synch_engine::{Node, NodeConfig};
use synch_store::SocketActivation;

/// A node with one filesystem source and its directory.
async fn node_with_space() -> (tempfile::TempDir, tempfile::TempDir, Node) {
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    Node::init(data.path(), None).unwrap();
    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    node.add_filesystem_source("code", space.path()).unwrap();
    (data, space, node)
}

fn write(space: &Path, name: &str, body: &[u8]) {
    if let Some(parent) = Path::new(name).parent() {
        std::fs::create_dir_all(space.join(parent)).unwrap();
    }
    std::fs::write(space.join(name), body).unwrap();
}

/// An activation of `name` on the program at `code/<program>`.
fn activation(name: &str, program: &str) -> SocketActivation {
    SocketActivation::new(name, "code", program, synch_core::now_ns())
}

#[tokio::test]
async fn a_program_publishes_as_an_ordinary_file_and_the_socket_is_not_in_the_tree() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "bin/gateway.o", b"\x7fELF not really");
    node.socket_activate(&activation("git", "bin/gateway.o"))
        .unwrap();
    node.scan_and_publish().unwrap();

    let program = node
        .store()
        .entry(node.origin(), "code", "bin/gateway.o")
        .unwrap()
        .unwrap();
    assert_eq!(
        program.kind,
        EntryKind::File,
        "a program is a file; nothing socket-shaped enters the tree"
    );
    assert!(program.content.is_some(), "and it carries its ELF's root");

    // The socket itself is a name, in no space and at no path.
    assert!(node
        .store()
        .entry(node.origin(), "code", "git")
        .unwrap()
        .is_none());
    let resolved = node.resolve_socket("git").unwrap().unwrap();
    assert_eq!(resolved.root, program.content.unwrap());
    assert_eq!(resolved.activation.program(), "code/bin/gateway.o");
}

#[tokio::test]
async fn one_program_backs_three_sockets_with_their_own_terms() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "bin/gateway.o", b"\x7fELF one object");
    for (name, upstream, scope) in [
        ("git", "git.internal", vec![]),
        ("hg", "hg.internal", vec![]),
        ("docs/git", "docs.internal", vec!["docs".to_string()]),
    ] {
        node.socket_activate(&SocketActivation {
            config: vec![("upstream".into(), upstream.into())],
            scope,
            ..activation(name, "bin/gateway.o")
        })
        .unwrap();
    }
    node.scan_and_publish().unwrap();

    let root = node.resolve_socket("git").unwrap().unwrap().root;
    for (name, upstream) in [
        ("git", "git.internal"),
        ("hg", "hg.internal"),
        ("docs/git", "docs.internal"),
    ] {
        let resolved = node.resolve_socket(name).unwrap().unwrap();
        assert_eq!(resolved.root, root, "{name} runs another object");
        assert_eq!(resolved.activation.config_get("upstream"), Some(upstream));
    }

    // And the reverse lookup names all three, which is what `activate` prints
    // as a program's blast radius and what a deployment walks.
    let dependents = node.sockets_backed_by("code", "bin/gateway.o").unwrap();
    assert_eq!(
        dependents
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>(),
        ["docs/git", "git", "hg"]
    );
}

#[tokio::test]
async fn a_redeploy_moves_every_socket_the_program_backs() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "bin/gateway.o", b"\x7fELF v1");
    for name in ["git", "hg", "docs/git"] {
        node.socket_activate(&activation(name, "bin/gateway.o"))
            .unwrap();
    }
    node.scan_and_publish().unwrap();
    let first = node.resolve_socket("git").unwrap().unwrap().root;

    write(space.path(), "bin/gateway.o", b"\x7fELF v2, deployed");
    node.scan_and_publish().unwrap();

    let second = Hash::new(b"\x7fELF v2, deployed");
    assert_ne!(second, first, "the bytes changed");
    for name in ["git", "hg", "docs/git"] {
        let resolved = node.resolve_socket(name).unwrap().unwrap();
        assert_eq!(resolved.root, second, "{name} kept the old program");
        assert_eq!(
            resolved.activation.program(),
            "code/bin/gateway.o",
            "the activation stands untouched across a deployment"
        );
    }
}

#[tokio::test]
async fn deactivating_leaves_the_program_alone() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "bin/gateway.o", b"\x7fELF");
    node.socket_activate(&activation("git", "bin/gateway.o"))
        .unwrap();
    node.socket_activate(&activation("hg", "bin/gateway.o"))
        .unwrap();
    node.scan_and_publish().unwrap();

    assert!(node.socket_deactivate("git").unwrap());
    assert!(
        node.resolve_socket("git").unwrap().is_none(),
        "a deactivated name resolves to nothing"
    );
    assert!(
        node.resolve_socket("hg").unwrap().is_some(),
        "the other socket on the same program is untouched"
    );
    assert_eq!(
        node.store()
            .entry(node.origin(), "code", "bin/gateway.o")
            .unwrap()
            .unwrap()
            .kind,
        EntryKind::File,
        "the program file is not the socket and never changes with it"
    );
    assert!(
        !node.socket_deactivate("git").unwrap(),
        "deactivating twice reports there was nothing to remove"
    );
}

#[tokio::test]
async fn adopting_someone_elses_program_adopts_only_its_bytes() {
    // The property the whole design rests on: a node executes only what its
    // own activation table names, and taking a peer's object does not
    // activate anything.
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "theirs.o", b"\x7fELF from a peer");
    node.scan_and_publish().unwrap();

    assert_eq!(
        node.store()
            .entry(node.origin(), "code", "theirs.o")
            .unwrap()
            .unwrap()
            .kind,
        EntryKind::File
    );
    assert!(node
        .sockets_backed_by("code", "theirs.o")
        .unwrap()
        .is_empty());
    assert!(node.resolve_socket("theirs.o").unwrap().is_none());
}

#[tokio::test]
async fn a_program_must_be_a_source_of_this_node_and_a_name_must_be_a_name() {
    let (_data, _space, node) = node_with_space().await;
    assert!(
        node.socket_activate(&SocketActivation::new(
            "git",
            "nowhere",
            "gateway.o",
            synch_core::now_ns()
        ))
        .is_err(),
        "a space this node is not a source of can hold no program"
    );
    assert!(
        node.socket_activate(&activation("git", "../escape.o"))
            .is_err(),
        "a program path that leaves the space must be refused at activation"
    );
    for name in ["", "../git", "/git", "git\u{202e}"] {
        assert!(
            node.socket_activate(&activation(name, "gateway.o"))
                .is_err(),
            "activated an illegal socket name {name:?}"
        );
    }
    // A path-shaped name is legal, which is what makes every migrated socket
    // keep its spelling.
    node.socket_activate(&activation("code/git.sock", "gateway.o"))
        .unwrap();
}

#[tokio::test]
async fn a_socket_can_be_activated_on_an_api_source() {
    // Sockets no longer enter the tree, so a source with no scanner hosts a
    // program as well as one with: the write channel is `commit_api_file`.
    let data = tempfile::tempdir().unwrap();
    Node::init(data.path(), None).unwrap();
    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    node.add_api_source("code").unwrap();
    node.socket_activate(&activation("git", "bin/gateway.o"))
        .unwrap();
    assert_eq!(node.socket_ls().unwrap()[0].program(), "code/bin/gateway.o");
}

#[tokio::test]
async fn a_socket_whose_program_is_unpublished_resolves_to_nothing() {
    let (_data, _space, node) = node_with_space().await;
    node.socket_activate(&activation("git", "bin/missing.o"))
        .unwrap();
    assert!(node.resolve_socket("git").unwrap().is_none());
    let activation = node.socket_ls().unwrap().pop().unwrap();
    assert_eq!(
        node.resolve_socket_program(&activation).unwrap(),
        Err(RefuseCode::NoSuchPath),
        "an unpublished program is named as such, not confused with a bad name"
    );
}

#[tokio::test]
async fn removing_a_source_removes_the_sockets_its_programs_backed() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "bin/gateway.o", b"\x7fELF");
    node.socket_activate(&activation("git", "bin/gateway.o"))
        .unwrap();
    node.scan_and_publish().unwrap();

    assert!(node.store().remove_source("code").unwrap());
    assert!(
        node.socket_ls().unwrap().is_empty(),
        "a socket whose program has no source behind it can never serve"
    );
}

/// Scope is the whole of who may open a socket now that position says nothing
/// (`docs/SOCKET-PROGRAMS.md` §2.2). Checked against the activation directly,
/// because that is where admission asks the question.
#[tokio::test]
async fn scope_admits_members_always_and_delegates_by_named_space() {
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "bin/gateway.o", b"\x7fELF");
    node.socket_activate(&activation("members-only", "bin/gateway.o"))
        .unwrap();
    node.socket_activate(&SocketActivation {
        scope: vec!["docs".into()],
        ..activation("for-docs", "bin/gateway.o")
    })
    .unwrap();
    node.scan_and_publish().unwrap();

    let by_name = |name: &str| {
        node.socket_ls()
            .unwrap()
            .into_iter()
            .find(|a| a.name == name)
            .unwrap()
    };
    let docs_delegate = ["docs".to_string()];
    let code_delegate = ["code".to_string()];

    // A rooted member opens either.
    assert!(by_name("members-only").admits(None));
    assert!(by_name("for-docs").admits(None));
    // A delegate in scope opens the one that names its space...
    assert!(by_name("for-docs").admits(Some(&docs_delegate)));
    // ...and one out of scope opens neither, even though the program lives in
    // `code`, which it is delegated. Scope is the grant, not position.
    assert!(!by_name("for-docs").admits(Some(&code_delegate)));
    assert!(!by_name("members-only").admits(Some(&code_delegate)));

    // `List` shows exactly what its caller may open, and no more.
    let listed = |delegated: Option<&[String]>| {
        let mut names: Vec<String> = node
            .socket_list_for(delegated)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        names.sort();
        names
    };
    assert_eq!(listed(None), ["for-docs", "members-only"]);
    assert_eq!(listed(Some(&docs_delegate)), ["for-docs"]);
    assert!(listed(Some(&code_delegate)).is_empty());

    // And a listed socket carries the program's path and root, which is the
    // audit the tree entry used to give for free.
    let entry = node
        .socket_list_for(Some(&docs_delegate))
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(entry.program_path, "code/bin/gateway.o");
    assert_eq!(entry.program, Hash::new(b"\x7fELF"));
}

/// A program in a space no delegate holds still serves a delegate the socket's
/// scope admits — and the delegate never gets the program's bytes, because
/// scope is authorization only and the connecting side executes nothing.
#[tokio::test]
async fn a_program_in_an_undelegated_space_serves_a_delegate_in_scope() {
    let (_data, _space, node) = node_with_space().await;
    let tools = tempfile::tempdir().unwrap();
    node.add_filesystem_source("tools", tools.path()).unwrap();
    write(tools.path(), "gateway.o", b"\x7fELF in tools");
    node.socket_activate(&SocketActivation {
        scope: vec!["docs".into()],
        ..SocketActivation::new("docs/git", "tools", "gateway.o", synch_core::now_ns())
    })
    .unwrap();
    node.scan_and_publish().unwrap();

    let docs_delegate = ["docs".to_string()];
    let listed = node.socket_list_for(Some(&docs_delegate)).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].program_path, "tools/gateway.o");

    // The delegate may open it, and the socket's scope is the only grant that
    // says so: `tools` is not in the delegate's list, and putting a socket
    // over a program does not put the program's space in it.
    let activation = node.socket_ls().unwrap().pop().unwrap();
    assert!(activation.admits(Some(&docs_delegate)));
    assert!(
        !activation.scope.contains(&"tools".to_string()),
        "scope names who may open, never where the bytes are"
    );
    assert!(!docs_delegate.contains(&"tools".to_string()));
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn an_invalid_update_stays_activated_but_unavailable() {
    // The bytes at the program path are not a loadable program. The socket
    // stays activated — deploying a fixed object is the remedy — and every
    // connection is refused with a message naming the defect.
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "local.o", b"\x7fELF but not really");
    node.socket_activate(&activation("local", "local.o"))
        .unwrap();
    node.scan_and_publish().unwrap();

    let err = node
        .connect_socket(node.origin(), "local", Vec::new())
        .await
        .expect_err("an unloadable update should refuse after the self-connection lands");
    assert!(
        err.to_string().contains("program-invalid"),
        "self-connection did not reach the manifest gate: {err}"
    );
    assert!(node.resolve_socket("local").unwrap().is_some());
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn a_self_connection_runs_the_activated_program() {
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
    write(space.path(), "bin/echo.o", &elf);
    node.socket_activate(&activation("echo", "bin/echo.o"))
        .unwrap();
    node.scan_and_publish().unwrap();

    let connection = node
        .connect_socket(node.origin(), "echo", Vec::new())
        .await
        .unwrap();
    let SocketConnection::Local {
        mut stream,
        completion,
        program_path,
        ..
    } = connection
    else {
        panic!("a self-connection used the remote transport");
    };
    assert_eq!(
        program_path, "code/bin/echo.o",
        "the reply names where the program lives, not the socket"
    );
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

/// One object, three sockets, three answers: each invocation reads its own
/// activation's config and its own name, and their maps do not meet. This is
/// the case `sy_socket_path` was added for and could not reach until a socket
/// stopped being a path.
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn three_sockets_on_one_object_have_their_own_config_name_and_map() {
    use synch_engine::sockets::SocketConnection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Answers `<name> <upstream> <visits>`: the socket's own name, its own
    // config, and its own map counter.
    const GATEWAY: &str = r#"
#include <synch.h>
SY_MANIFEST("{\"manifest\":1,\"name\":\"gateway\",\"max_streams\":4}");
SY_ENTRY sy_s64 entry(void) {
  char out[192];
  sy_u64 n = 0;
  sy_s64 k = sy_socket_path(out, sizeof out);
  if (k < 0) return 1;
  n += (sy_u64)k;
  out[n++] = ' ';
  k = sy_config_get(SY_STR("upstream"), out + n, sizeof out - n);
  if (k < 0) return 2;
  n += (sy_u64)k;
  out[n++] = ' ';
  sy_s64 visits = sy_map_incr(SY_STR("visits"), 1, 60000);
  if (visits < 0) return 3;
  n += (sy_u64)sy_utoa((sy_u64)visits, out + n, sizeof out - n);
  sy_write_all(SY_SELF, out, n, 5000);
  sy_shutdown(SY_SELF);
  return 0;
}
"#;
    let elf = synch_cc::compile(
        GATEWAY,
        "gateway.c",
        &[("synch.h", synch_sock::sdk::HEADER)],
        &[],
    )
    .unwrap();

    let (_data, space, node) = node_with_space().await;
    write(space.path(), "bin/gateway.o", &elf);
    for (name, upstream) in [
        ("git", "git.internal"),
        ("hg", "hg.internal"),
        ("docs/git", "docs.internal"),
    ] {
        node.socket_activate(&SocketActivation {
            config: vec![("upstream".into(), upstream.into())],
            ..activation(name, "bin/gateway.o")
        })
        .unwrap();
    }
    node.scan_and_publish().unwrap();

    let say = |node: Node, name: &'static str| async move {
        let connection = node
            .connect_socket(node.origin(), name, Vec::new())
            .await
            .unwrap();
        let SocketConnection::Local {
            mut stream,
            completion,
            program,
            ..
        } = connection
        else {
            panic!("a self-connection used the remote transport");
        };
        stream.shutdown().await.unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        completion.await.unwrap();
        (String::from_utf8(out).unwrap(), program)
    };

    let root = node.resolve_socket("git").unwrap().unwrap().root;
    for (name, expected) in [
        ("git", "git git.internal 1"),
        ("hg", "hg hg.internal 1"),
        ("docs/git", "docs/git docs.internal 1"),
    ] {
        let (said, program) = say(node.clone(), name).await;
        assert_eq!(said, expected);
        assert_eq!(program, root, "{name} ran another object");
    }
    // The maps are per socket: `git` counts its own visits and nobody else's,
    // so after three of them `hg`'s second is still its second.
    assert_eq!(say(node.clone(), "git").await.0, "git git.internal 2");
    assert_eq!(say(node.clone(), "git").await.0, "git git.internal 3");
    assert_eq!(say(node.clone(), "hg").await.0, "hg hg.internal 2");

    // A redeploy moves every dependent socket and clears every dependent map.
    let mut changed = elf.clone();
    changed.extend_from_slice(&[0u8; 32]);
    write(space.path(), "bin/gateway.o", &changed);
    node.scan_and_publish().unwrap();
    let after = node.resolve_socket("git").unwrap().unwrap().root;
    assert_ne!(after, root);
    for (name, expected) in [
        ("git", "git git.internal 1"),
        ("hg", "hg hg.internal 1"),
        ("docs/git", "docs/git docs.internal 1"),
    ] {
        let (said, program) = say(node.clone(), name).await;
        assert_eq!(said, expected, "{name}'s map survived a deployment");
        assert_eq!(program, after, "{name} did not move to the new program");
    }
    node.shutdown().await.unwrap();
}

/// A re-activation is a new bargain, and admission serves it: re-activating
/// with a rotated config reaches the next invocation with no content change at
/// all. The property this guards is that the operator half of the policy —
/// config and the stream cap — is read from the live activation row rather
/// than carried on any cached socket state; the admission path computes it
/// from the row it resolves under the authorization lock (`sockets.rs`), so a
/// re-activation that lands mid-admission cannot hand a stale config through.
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn a_reactivation_config_reaches_the_next_invocation() {
    use synch_engine::sockets::SocketConnection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CONF: &str = r#"
#include <synch.h>
SY_MANIFEST("{\"manifest\":1,\"name\":\"conf\",\"max_streams\":4}");
SY_ENTRY sy_s64 entry(void) {
  char v[64];
  sy_s64 n = sy_config_get(SY_STR("token"), v, sizeof v);
  if (n < 0) sy_write_all(SY_SELF, SY_STR("none"), 5000);
  else       sy_write_all(SY_SELF, v, (sy_u64)n, 5000);
  sy_shutdown(SY_SELF);
  return 0;
}
"#;
    let elf =
        synch_cc::compile(CONF, "conf.c", &[("synch.h", synch_sock::sdk::HEADER)], &[]).unwrap();

    let read_token = |node: Node| async move {
        let connection = node
            .connect_socket(node.origin(), "conf", Vec::new())
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
        stream.shutdown().await.unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        completion.await.unwrap();
        String::from_utf8(out).unwrap()
    };

    let (_data, space, node) = node_with_space().await;
    write(space.path(), "bin/conf.o", &elf);
    node.socket_activate(&SocketActivation {
        config: vec![("token".into(), "one".into())],
        ..activation("conf", "bin/conf.o")
    })
    .unwrap();
    node.scan_and_publish().unwrap();
    assert_eq!(read_token(node.clone()).await, "one");

    // Re-activate with a rotated config. The content root does not change, so
    // this exercises the activation read alone, not a deployment.
    node.socket_activate(&SocketActivation {
        config: vec![("token".into(), "two".into())],
        ..activation("conf", "bin/conf.o")
    })
    .unwrap();
    assert_eq!(
        read_token(node.clone()).await,
        "two",
        "admission handed the guest a stale config after re-activation"
    );
    node.shutdown().await.unwrap();
}

/// The daemon uses a multi-thread Tokio runtime, whose workers must never open
/// the synchronous SQLite store. Keep the fixture setup outside that runtime,
/// then exercise the complete async admit/run path inside it. A regression
/// here aborts in debug builds at `Store::conn`, exactly as a real daemon does.
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn a_daemon_style_runtime_can_activate_and_run_a_self_socket() {
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
    node.add_filesystem_source("code", space.path()).unwrap();
    let elf = synch_cc::compile(
        include_str!("../../synch-sock/examples/echo.c"),
        "echo.c",
        &[("synch.h", synch_sock::sdk::HEADER)],
        &[],
    )
    .unwrap();
    write(space.path(), "bin/echo.o", &elf);
    node.socket_activate(&activation("echo", "bin/echo.o"))
        .unwrap();
    node.scan_and_publish().unwrap();

    runtime.block_on(async {
        let connection = node
            .connect_socket(node.origin(), "echo", Vec::new())
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
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn a_discovery_only_peer_can_connect_to_a_socket_and_list_them() {
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
    write(server_space.path(), "bin/echo.o", &elf);
    server
        .socket_activate(&SocketActivation {
            note: "the echo".into(),
            ..SocketActivation::new("echo", "code", "bin/echo.o", synch_core::now_ns())
        })
        .unwrap();
    server.scan_and_publish().unwrap();

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

    // Discovery over the wire: `List` is what `synch ls` used to give for free.
    let listed = client.list_sockets(server.origin()).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "echo");
    assert_eq!(listed[0].program_path, "code/bin/echo.o");
    assert_eq!(listed[0].note, "the echo");

    let connection = client
        .connect_socket(server.origin(), "echo", Vec::new())
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
    assert_eq!(stream.program_path, "code/bin/echo.o");
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
async fn the_activation_survives_a_restart() {
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    Node::init(data.path(), None).unwrap();
    let root = {
        let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
        node.add_filesystem_source("code", space.path()).unwrap();
        write(space.path(), "bin/gateway.o", b"\x7fELF");
        node.socket_activate(&SocketActivation {
            note: "kept across restarts".into(),
            scope: vec!["docs".into()],
            ..SocketActivation::new("git", "code", "bin/gateway.o", synch_core::now_ns())
        })
        .unwrap();
        node.scan_and_publish().unwrap();
        let resolved = node.resolve_socket("git").unwrap().unwrap();
        node.shutdown().await.unwrap();
        resolved.root
    };

    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    let resolved = node.resolve_socket("git").unwrap().unwrap();
    assert_eq!(resolved.root, root);
    assert_eq!(
        resolved.activation.note, "kept across restarts",
        "an activation must survive a restart; it is operator state, not a cache"
    );
    assert_eq!(
        resolved.activation.scope,
        vec!["docs".to_string()],
        "and so must the grant it carries"
    );
}

#[tokio::test]
async fn resolving_ignores_what_other_origins_publish() {
    // A socket resolves its program in this node's own trie only. `newest`
    // would otherwise let any member's mtime decide whose program a
    // connection lands on.
    let (_data, space, node) = node_with_space().await;
    write(space.path(), "bin/gateway.o", b"\x7fELF mine");
    node.socket_activate(&activation("git", "bin/gateway.o"))
        .unwrap();
    node.scan_and_publish().unwrap();
    let mine = node.resolve_socket("git").unwrap().unwrap();

    // A peer publishes a different program at the same path, with a later
    // mtime — which is what would win a `newest` selection.
    let peer = synch_core::OriginId::named("nas", "cluster.example").unwrap();
    node.store()
        .put_entry(
            &peer,
            "code",
            "bin/gateway.o",
            &synch_core::FileEntry::file(11, i64::MAX, Hash::new(b"\x7fELF theirs"), 1),
        )
        .unwrap();

    let after = node.resolve_socket("git").unwrap().unwrap();
    assert_eq!(
        after.root, mine.root,
        "resolution followed a peer's entry instead of this node's own"
    );
}
