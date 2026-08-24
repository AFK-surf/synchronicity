//! `synch connect` — the caller's side of a socket (`docs/SOCKETS.md` §9.1).
//!
//! This is a byte pump and nothing more. It executes no eBPF, holds no policy,
//! and knows nothing about what it is talking to: it names a path, and
//! everything that decides what runs is state the far node already holds. That
//! is why this half of the design works on platforms where the runtime does not
//! exist at all.
//!
//! DESIGN.md §9.1 is categorical that the daemon owns the node and the CLI is
//! only a client of it — one endpoint, one lifecycle, no second iroh endpoint
//! sharing the device key. So this opens a bidirectional control-socket stream
//! and the daemon bridges it to a QUIC stream on the remote node.
//!
//! In `--listen` mode the **TCP listener lives here**, in the foreground
//! process, not in the daemon. Closing this command ends the exposure, and the
//! daemon never holds a listening socket it was not configured with. A
//! daemon-hosted persistent forward is a reasonable thing to want and is future
//! work, where it can be given a config file and a lifecycle of its own.

use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::control::{proto::pb, Client};

/// Splits `k=v`, refusing anything else: a metadata pair with no `=` is far
/// more likely a typo than an intention.
fn meta_pair(text: &str) -> Result<pb::MetaPair> {
    let (key, value) = text
        .split_once('=')
        .with_context(|| format!("`{text}` is not `k=v`"))?;
    Ok(pb::MetaPair {
        key: key.trim().to_string(),
        value: value.to_string(),
    })
}

/// Runs `synch connect`.
pub async fn run(
    data_dir: &Path,
    reference: &str,
    meta: &[String],
    listen: Option<&str>,
    once: bool,
) -> Result<()> {
    let meta: Vec<pb::MetaPair> = meta.iter().map(|m| meta_pair(m)).collect::<Result<_>>()?;

    match listen {
        None => {
            let code = pipe_stdio(data_dir, reference, &meta).await?;
            // The program's own return value reaches the shell, which is what
            // makes a socket usable from a script.
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Some(addr) => serve_listener(data_dir, reference, &meta, addr, once).await,
    }
}

/// Pipes this process's stdin and stdout through one invocation.
async fn pipe_stdio(data_dir: &Path, reference: &str, meta: &[pb::MetaPair]) -> Result<i32> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    pipe(data_dir, reference, meta, stdin, stdout).await
}

/// Accepts TCP connections and gives each one its own invocation.
async fn serve_listener(
    data_dir: &Path,
    reference: &str,
    meta: &[pb::MetaPair],
    addr: &str,
    once: bool,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("could not listen on {addr}"))?;
    let local = listener.local_addr()?;
    eprintln!("listening on {local}, forwarding to {reference}");

    loop {
        let (stream, from) = listener.accept().await.context("accept failed")?;
        let data_dir = data_dir.to_path_buf();
        let reference = reference.to_string();
        let meta = meta.to_vec();
        let task = async move {
            let (reader, writer) = tokio::io::split(stream);
            // One invocation per accepted connection, each with its own
            // control stream: they are separate conversations and a failure in
            // one is not a failure in another.
            if let Err(e) = pipe(&data_dir, &reference, &meta, reader, writer).await {
                eprintln!("{from}: {e:#}");
            }
        };
        if once {
            task.await;
            return Ok(());
        }
        tokio::spawn(task);
    }
}

/// Bridges a reader and a writer through one socket invocation.
async fn pipe(
    data_dir: &Path,
    reference: &str,
    meta: &[pb::MetaPair],
    mut reader: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    mut writer: impl tokio::io::AsyncWrite + Unpin,
) -> Result<i32> {
    let mut client = Client::connect(data_dir).await?;
    let (requests, request_rx) = tokio::sync::mpsc::channel::<pb::ConnectRequest>(16);

    requests
        .send(pb::ConnectRequest {
            kind: Some(pb::connect_request::Kind::Open(pb::ConnectOpen {
                reference: reference.to_string(),
                meta: meta.to_vec(),
            })),
        })
        .await
        .ok();

    // The uplink runs on its own task: a program that says everything before it
    // reads anything, and one that reads everything before it says anything,
    // are both ordinary, and a single-threaded pump would deadlock on the
    // second.
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let message = pb::ConnectRequest {
                        kind: Some(pb::connect_request::Kind::Data(buf[..n].to_vec())),
                    };
                    if requests.send(message).await.is_err() {
                        return;
                    }
                }
            }
        }
        // A clean EOF on our side is a half-close, not a hang-up: the program
        // may still have a reply to write, and a `git upload-pack` that was cut
        // off here would lose its whole response.
        let _ = requests
            .send(pb::ConnectRequest {
                kind: Some(pb::connect_request::Kind::Fin(pb::ConnectFin {})),
            })
            .await;
    });

    let mut responses = client
        .open_socket(tokio_stream::wrappers::ReceiverStream::new(request_rx))
        .await
        .context("the daemon refused the socket")?;

    let mut exit = 0;
    while let Some(message) = responses.message().await? {
        match message.kind {
            Some(pb::connect_response::Kind::Opened(opened)) => {
                tracing::debug!(
                    program = %synch_core::Hash::from_slice(&opened.program)
                        .map(|h| h.to_hex().to_string())
                        .unwrap_or_default(),
                    invocation = opened.invocation,
                    "socket opened"
                );
            }
            Some(pb::connect_response::Kind::Data(bytes)) => {
                writer.write_all(&bytes).await?;
                // Flushed per message rather than per buffer: an interactive
                // protocol is a sequence of small writes that each need to
                // arrive, and buffering them turns a prompt into a hang.
                writer.flush().await?;
            }
            Some(pb::connect_response::Kind::Closed(closed)) => {
                if !closed.status.is_empty() && closed.exit_code != 0 {
                    eprintln!("{reference}: {}", closed.status);
                }
                exit = closed.exit_code;
            }
            None => {}
        }
    }
    uplink.abort();
    writer.flush().await.ok();
    Ok(exit)
}
