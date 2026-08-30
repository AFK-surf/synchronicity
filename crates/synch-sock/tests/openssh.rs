//! OpenSSH interoperability (`docs/SSH-SOCKETS.md` §14.5).
//!
//! Every other SSH test speaks to the adapter through russh, which shares
//! vendored code with the server and so cannot notice a disagreement with the
//! world's actual client. Here the stock `ssh` binary logs into the
//! `ssh-shell.c` example over a local TCP bridge — the same byte stream
//! `synch socket connect --listen` would carry — and runs a command in the declared
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
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
};

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
    let declaration = synch_sock::manifest::manifest_declaration(&elf).expect("the hook ran");
    let policy = EffectivePolicy::granted(&declaration, vec![], None, 64);
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
        // A client with no local terminal — CI, a script, ProxyCommand —
        // sends an empty terminal name in pty-req. Pin that case everywhere
        // rather than inheriting whatever TERM this machine happens to have.
        .env_remove("TERM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ssh client started");
    let mut stdin = ssh.stdin.take().expect("a piped stdin");
    let mut stdout_pipe = ssh.stdout.take().expect("a piped stdout");
    let mut stderr_pipe = ssh.stderr.take().expect("a piped stderr");
    // Drained concurrently so a chatty shell profile cannot fill the pipe.
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf).await;
        buf
    });

    // Type only once the shell's startup output settles at the prompt, as a
    // person would. Old interactive shells depend on it: bash 3.2 (macOS's
    // /bin/bash) configures its terminal with flush-style tcsetattr during
    // startup and discards keystrokes that arrived early, where modern bash
    // deliberately preserves that typeahead.
    let mut output = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        match tokio::time::timeout(Duration::from_millis(500), stdout_pipe.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                eprintln!(
                    "the session ended before anything was typed.\nstdout so far: {:?}",
                    String::from_utf8_lossy(&output)
                );
                break;
            }
            Ok(Err(error)) => {
                eprintln!("reading ssh stdout failed before the prompt: {error}");
                break;
            }
            Ok(Ok(n)) => output.extend_from_slice(&chunk[..n]),
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
    eprintln!(
        "typing at the prompt; startup output: {:?}",
        String::from_utf8_lossy(&output)
    );

    // Run and observe one command before typing exit separately. Sending both
    // in one write can leave a second CHANNEL_DATA packet queued behind the
    // shell's exit; that packet would accidentally wake a broken server in
    // exactly the same way as pressing another key after `exit`.
    stdin
        .write_all(b"echo interop-$((6*7))\n")
        .await
        .expect("keystrokes reached ssh");
    stdin.flush().await.expect("keystrokes flushed");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !String::from_utf8_lossy(&output).contains("interop-42") {
        let n = tokio::time::timeout_at(deadline, stdout_pipe.read(&mut chunk))
            .await
            .expect("bash answered the probe")
            .expect("ssh stdout remained readable");
        assert_ne!(n, 0, "the session ended before bash answered");
        output.extend_from_slice(&chunk[..n]);
    }

    // Keep stdin open after the lone exit command. The remote channel must
    // send CLOSE on its own; client EOF or another byte must not be required.
    stdin
        .write_all(b"exit 5\n")
        .await
        .expect("exit reached ssh");
    stdin.flush().await.expect("exit flushed");
    tokio::time::timeout(
        Duration::from_secs(10),
        stdout_pipe.read_to_end(&mut output),
    )
    .await
    .expect("the ssh session concluded")
    .expect("stdout drained");
    // The remote side has closed (stdout reached EOF); only now may stdin
    // go away, and it must — ssh lingers while its stdin stays readable.
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(10), ssh.wait())
        .await
        .expect("ssh exited after the remote close")
        .expect("ssh ran");
    let stderr_bytes = stderr_task.await.expect("stderr drained");

    let stdout = String::from_utf8_lossy(&output);
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    assert!(
        stdout.contains("interop-42"),
        "bash did not run the command.\nstdout: {stdout:?}\nstderr: {stderr:?}"
    );
    assert_eq!(
        status.code(),
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
    let declaration = synch_sock::manifest::manifest_declaration(&elf).expect("the hook ran");
    let policy = EffectivePolicy::granted(&declaration, vec![], None, 64);
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
