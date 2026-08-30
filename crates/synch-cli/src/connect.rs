//! `synch socket connect` — the caller's side of a socket (`docs/SOCKETS.md` §9.1).
//!
//! This is a byte pump and nothing more. It executes no eBPF, holds no policy,
//! and knows nothing about what it is talking to: it names a path, and
//! everything that decides what runs is state the named node already holds. That
//! is why this half of the design works on platforms where the runtime does not
//! exist at all.
//!
//! DESIGN.md §9.1 is categorical that the daemon owns the node and the CLI is
//! only a client of it — one endpoint, one lifecycle, no second iroh endpoint
//! sharing the device key. So this opens a bidirectional control-socket stream
//! and the daemon bridges it to QUIC for a peer or an in-memory stream for
//! itself.
//!
//! In `--listen` mode the **TCP listener lives here**, in the foreground
//! process, not in the daemon. Closing this command ends the exposure, and the
//! daemon never holds a listening socket it was not configured with. A
//! daemon-hosted persistent forward is a reasonable thing to want and is future
//! work, where it can be given a config file and a lifecycle of its own.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use synch_sock::limits::{
    MAX_ACCEPTS_PER_IP_PER_SECOND, MAX_ACCEPTS_PER_SECOND, MAX_ACCEPT_CONCURRENT,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

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

/// Runs `synch socket connect`.
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

/// One acceptance window for `serve_listener`: who we recently admitted, and
/// when.
///
/// A sliding window over accepted connections, checked twice: the global
/// budget caps the total accept rate, and the per-IP budget stops one peer
/// from taking the whole window. A breach drops the connection immediately —
/// never queued, never retried.
struct AcceptRate {
    /// How long an admission stays in the window.
    window: Duration,
    /// Recent admissions, oldest first.
    recent: VecDeque<(Instant, IpAddr)>,
}

impl AcceptRate {
    fn new(window: Duration) -> Self {
        AcceptRate {
            window,
            recent: VecDeque::new(),
        }
    }

    /// Admits a connection from `ip` if both the global and the per-IP window
    /// budgets are not exhausted, recording the admission on success.
    fn admit(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        while let Some(&(at, _)) = self.recent.front() {
            if now.duration_since(at) >= self.window {
                self.recent.pop_front();
            } else {
                break;
            }
        }
        if self.recent.len() >= MAX_ACCEPTS_PER_SECOND {
            return false;
        }
        let from_ip = self.recent.iter().filter(|&&(_, seen)| seen == ip).count();
        if from_ip >= MAX_ACCEPTS_PER_IP_PER_SECOND {
            return false;
        }
        self.recent.push_back((now, ip));
        true
    }
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

    // The listener is a pre-auth front door, so it bounds itself: a semaphore
    // caps concurrent pre-auth connections, and a sliding window caps the
    // accept rate globally and per peer IP (limits.rs). A breach drops the
    // connection immediately — fail-closed, never queued. The permit is held
    // for the whole pipe() lifetime and dropped with the task, so a trickle
    // connection cannot hold a slot beyond the invocation's idle deadline.
    let concurrency = Arc::new(Semaphore::new(MAX_ACCEPT_CONCURRENT));
    let rate = Arc::new(Mutex::new(AcceptRate::new(Duration::from_secs(1))));

    loop {
        let (stream, from) = listener.accept().await.context("accept failed")?;
        if !rate.lock().unwrap().admit(from.ip()) {
            eprintln!("{from}: rate limited (accept window)");
            drop(stream);
            continue;
        }
        let Ok(permit) = concurrency.clone().try_acquire_owned() else {
            eprintln!("{from}: rate limited (concurrency)");
            drop(stream);
            continue;
        };
        let data_dir = data_dir.to_path_buf();
        let reference = reference.to_string();
        let meta = meta.to_vec();
        let task = async move {
            let _permit = permit;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_rate_enforces_per_ip_and_global_windows() {
        let mut rate = AcceptRate::new(Duration::from_secs(1));
        let a = "10.0.0.1".parse::<IpAddr>().unwrap();
        let b = "10.0.0.2".parse::<IpAddr>().unwrap();
        // Two peers together fill the window up to the per-IP cap each: 16
        // admits fit, the 17th from either peer is refused.
        for _ in 0..MAX_ACCEPTS_PER_IP_PER_SECOND {
            assert!(rate.admit(a));
            assert!(rate.admit(b));
        }
        assert!(!rate.admit(a));
        assert!(!rate.admit(b));
        // A third IP is still within the global budget.
        assert!(rate.admit("10.0.0.3".parse::<IpAddr>().unwrap()));

        // The global budget: MAX_ACCEPTS_PER_SECOND distinct peers fit, the
        // next one is refused.
        let mut rate = AcceptRate::new(Duration::from_secs(1));
        for i in 0..MAX_ACCEPTS_PER_SECOND {
            let ip = format!("10.1.0.{i}").parse::<IpAddr>().unwrap();
            assert!(rate.admit(ip), "admit {i} must succeed");
        }
        assert!(!rate.admit("10.2.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn accept_rate_evicts_entries_after_the_window() {
        // The window is a parameter so the test can shrink it and sleep
        // through it instead of waiting a full second.
        let window = Duration::from_millis(20);
        let mut rate = AcceptRate::new(window);
        let ip = "10.0.0.1".parse::<IpAddr>().unwrap();
        for _ in 0..MAX_ACCEPTS_PER_IP_PER_SECOND {
            assert!(rate.admit(ip));
        }
        assert!(!rate.admit(ip), "the window is full");
        std::thread::sleep(window * 5);
        for _ in 0..MAX_ACCEPTS_PER_IP_PER_SECOND {
            assert!(rate.admit(ip), "admission resumes once the window passes");
        }
    }
}
