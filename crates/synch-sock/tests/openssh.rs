//! OpenSSH interoperability (`docs/SSH-SOCKETS.md` §14.5).
//!
//! Every other SSH test speaks to the adapter through russh, which shares
//! vendored code with the server and so cannot notice a disagreement with the
//! world's actual client. Here the stock `ssh` binary logs into the
//! `ssh-shell.c` example over a local TCP bridge — the same byte stream
//! `synch connect --listen` would carry — and runs a command in the declared
//! bash. Skipped where no OpenSSH client is installed, because a machine
//! without one cannot answer the question and a red test that means "no ssh"
//! teaches people to ignore red tests.

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::{path::PathBuf, process::Stdio, time::Duration};

use harness::{peer, sdk, Harness};
use synch_core::SockStatus;
use synch_sock::{DuplexStream, EffectivePolicy};
use tokio::{io::AsyncWriteExt, net::TcpListener, process::Command};

fn build_example(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/examples")).join(name);
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    synch_cc::compile(&source, name, &sdk(), &[])
        .unwrap_or_else(|e| panic!("examples/{name} does not compile:\n{e}"))
}

fn openssh_client() -> Option<String> {
    let probe = std::process::Command::new("ssh").arg("-V").output().ok()?;
    // OpenSSH prints its version to stderr.
    Some(String::from_utf8_lossy(&probe.stderr).trim().to_string())
}

/// The client options every invocation here needs: no user or system config,
/// no known-hosts state, and a forced PTY so a piped stdin still exercises
/// `pty-req` and the interactive shell path.
fn ssh_args(port: u16) -> Vec<String> {
    [
        "-tt",
        "-F",
        "/dev/null",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "NumberOfPasswordPrompts=0",
        "-o",
        "LogLevel=ERROR",
        "-p",
    ]
    .into_iter()
    .map(str::to_string)
    .chain([port.to_string(), "operator@127.0.0.1".to_string()])
    .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_logs_into_the_ssh_shell_example() {
    let Some(version) = openssh_client() else {
        eprintln!("skipping the OpenSSH interop test: no ssh client on this machine");
        return;
    };
    eprintln!("interop against: {version}");

    let elf = build_example("ssh-shell.c");
    let harness = Harness::new();
    let declaration = synch_sock::declare(&elf, harness.tree.clone()).expect("the hook ran");
    let policy = EffectivePolicy::armed(&declaration, vec![], None, 64);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("the ssh client connected");
        let invocation = harness.invocation(
            &elf,
            DuplexStream::from_split(stream),
            policy,
            peer(None),
            vec![],
        );
        harness.pool.run(invocation).await.expect("the program ran")
    });

    let mut ssh = Command::new("ssh")
        .args(ssh_args(port))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ssh client started");
    // Typed at the terminal: bash expands the arithmetic, so seeing the
    // expansion proves a real shell behind a real PTY, and `exit 5` proves
    // the SSH exit-status path end to end.
    ssh.stdin
        .take()
        .expect("a piped stdin")
        .write_all(b"echo interop-$((6*7))\nexit 5\n")
        .await
        .expect("keystrokes reached ssh");
    let out = tokio::time::timeout(Duration::from_secs(30), ssh.wait_with_output())
        .await
        .expect("the ssh session concluded")
        .expect("ssh ran");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("interop-42"),
        "bash did not run the command.\nstdout: {stdout:?}\nstderr: {stderr:?}"
    );
    assert_eq!(
        out.status.code(),
        Some(5),
        "ssh reports the shell's own exit status.\nstdout: {stdout:?}\nstderr: {stderr:?}"
    );

    let outcome = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the invocation ended with the connection")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}

/// Serves `ssh-shell.c` on 127.0.0.1:2222 for two minutes, one invocation per
/// connection, for a person with a terminal:
///
/// ```sh
/// cargo test -p synch-sock --test openssh -- --ignored serve_the_ssh_shell &
/// ssh -p 2222 -o StrictHostKeyChecking=no operator@127.0.0.1
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual: serves 127.0.0.1:2222 for an interactive ssh login"]
async fn serve_the_ssh_shell_example_for_a_manual_login() {
    let elf = build_example("ssh-shell.c");
    let harness = Harness::new();
    let declaration = synch_sock::declare(&elf, harness.tree.clone()).expect("the hook ran");
    let policy = EffectivePolicy::armed(&declaration, vec![], None, 64);
    let listener = TcpListener::bind("127.0.0.1:2222")
        .await
        .expect("port 2222 is free");
    eprintln!("serving ssh-shell.c on 127.0.0.1:2222 for 120s");

    let done = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = tokio::time::sleep_until(done) => break,
        };
        let Ok((stream, from)) = accepted else { break };
        eprintln!("connection from {from}");
        let invocation = harness.invocation(
            &elf,
            DuplexStream::from_split(stream),
            policy.clone(),
            peer(None),
            vec![],
        );
        let pool = harness.pool.clone();
        tokio::spawn(async move {
            match pool.run(invocation).await {
                Ok(outcome) => eprintln!("invocation ended: {:?}", outcome.status),
                Err(error) => eprintln!("invocation failed: {error}"),
            }
        });
    }
}
