//! `synch mcp` — the Model Context Protocol, served over stdio (§9.1).
//!
//! An MCP client launches this as a child process and speaks newline-delimited
//! JSON-RPC to it. Every request is answered from the local daemon's control
//! socket, so this is a client of the node exactly as `synch ls` is: it holds
//! no store handle, no iroh endpoint, and no signing key.
//!
//! # stdout carries protocol and nothing else
//!
//! The stdio binding is categorical about it, and the failure mode is silent
//! corruption rather than an error, so the rule is enforced structurally: this
//! module writes through one task fed by a channel, and nothing in it prints.
//! `clippy::print_stdout` is denied here — the workspace allows it, because
//! every other command in this binary exists to print — and tracing is already
//! stderr-only (`synch_net::process::init`).
//!
//! # Two eras
//!
//! MCP dropped the `initialize` handshake in revision `2026-07-28`: the
//! protocol is now stateless and every request declares its own version. Most
//! installed clients still handshake. This server answers both, selecting by
//! how the client opens; [`rpc`] holds the mechanics and the reasoning.
//!
//! # Concurrency
//!
//! The spec is explicit that a connection is not a conversation — a client may
//! interleave unrelated requests. Each one is handled on its own task over a
//! cloned control channel, which HTTP/2 multiplexes, and every response goes
//! back through the single writer, which is what keeps "one message per line"
//! true under concurrency.
#![deny(clippy::print_stdout)]

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{Context as _, Result};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, Mutex, Notify},
};

pub(crate) mod resources;
pub(crate) mod rpc;
pub(crate) mod session;
pub(crate) mod tools;

use rpc::{Era, Incoming, RequestId};
use session::Session;
use tools::{Context, ToolError};

/// What the process was told it may do.
///
/// Fixed at startup from the command line: an MCP client cannot widen it, and
/// the tool list reflects it, so a client is shown exactly the authority it
/// was given rather than discovering the boundary by being refused at it.
#[derive(Debug, Clone)]
pub struct Options {
    /// Whether the tools that change state are served.
    pub allow_write: bool,
    /// The spaces in scope, or empty for every space this node holds.
    pub spaces: Vec<String>,
    /// The largest payload one read returns.
    pub max_read_bytes: u64,
}

/// The longest line this server will read.
///
/// A tool result is bounded by `--max-read-bytes` and the caps in [`tools`], so
/// nothing legitimate comes close. This bounds what a stream that is not MCP —
/// a file redirected into stdin, a client writing framed messages — can make
/// this process allocate before it gives up.
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// How many responses may be queued for the writer before a handler waits.
///
/// Small on purpose: a client that has stopped reading should slow the
/// handlers down rather than have its unread output accumulate here.
const WRITE_AHEAD: usize = 32;

/// How long requests already accepted have to finish once the input closes.
///
/// Longer than any tool that answers from the daemon takes, and shorter than
/// the ceiling on `synch_connect`: a client that closes its end while a socket
/// invocation is still running gets a prompt exit rather than a five-minute
/// wait for an answer it is no longer reading.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// What the server tells a model about itself, once, up front.
const INSTRUCTIONS: &str = "\
synchronicity is a peer-to-peer file store. Files live in spaces; every node \
publishes its own version of a path, so a path can carry several versions at \
once and reads select between them with a policy.

Start with synch_spaces to see what this node holds, then synch_list to walk a \
space and synch_read to read a file. Reads are windowed — pass offset and \
length to walk a large object.

When a read reports a divergent path, several origins publish different bytes \
for it: call synch_versions to see them, then read again with \
policy=\"origin=<id>\" to pin one.

Paths are also addressable as resources at synch://<space>/<path>.";

/// Runs the server on this process's stdin and stdout.
pub async fn run(data_dir: &Path, options: Options) -> Result<()> {
    // Locked handles: nothing else in this process writes to either, and
    // taking them here makes that a property of the code rather than a
    // convention.
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    tracing::info!(
        data_dir = %data_dir.display(),
        allow_write = options.allow_write,
        spaces = ?options.spaces,
        "serving MCP over stdio"
    );
    serve(stdin, stdout, data_dir, options).await
}

/// Runs the server over any pair of streams.
///
/// Generic rather than bound to stdio because the binding says the framing is
/// defined over "any reliable bidirectional byte stream" and only the process
/// mechanics are stdio's — which is what lets `tests/mcp.rs` drive a real
/// server over an in-memory duplex against a real daemon.
pub async fn serve<R, W>(reader: R, writer: W, data_dir: &Path, options: Options) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let context = Arc::new(Context {
        session: Session::new(data_dir),
        options,
    });
    let (out, outbox) = mpsc::channel::<String>(WRITE_AHEAD);
    let pump = tokio::spawn(write_all(writer, outbox));
    let server = Server {
        context,
        out: out.clone(),
        inflight: Arc::new(Mutex::new(HashMap::new())),
        legacy: Arc::new(Mutex::new(None)),
    };

    let mut lines = Framed::new(reader);
    let mut handlers: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    loop {
        // Finished handlers are dropped as they are noticed rather than kept
        // for the shutdown that may be hours away: a long session would
        // otherwise accumulate one handle per request it ever answered.
        handlers.retain(|handler| !handler.is_finished());
        match lines.next().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                if let Some(handler) = server.accept(&line).await {
                    handlers.push(handler);
                }
            }
            // Stdin closed: the primary graceful-shutdown signal, and the only
            // portable one.
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "the input stream ended badly");
                break;
            }
        }
    }

    // Requests already accepted are answered before this exits. A client that
    // writes a batch and closes its end immediately — which is exactly how a
    // script drives this — would otherwise get silence for work the server had
    // already started. The grace is bounded because a handler can be waiting on
    // a daemon that is not answering, and a server that will not exit is worse
    // than one that abandons a late reply.
    let draining = async {
        for handler in &mut handlers {
            let _ = handler.await;
        }
    };
    if tokio::time::timeout(SHUTDOWN_GRACE, draining)
        .await
        .is_err()
    {
        tracing::warn!(
            "in-flight requests did not finish within {SHUTDOWN_GRACE:?} of the input closing"
        );
    }
    server.cancel_all().await;
    // Whatever the drain reached has already been awaited to completion, and a
    // completed `JoinHandle` panics if it is polled again — so only the ones
    // the grace ran out on are left here.
    handlers.retain(|handler| !handler.is_finished());
    for handler in &handlers {
        handler.abort();
    }
    // Awaited, not just aborted: an abort marks a task for cancellation but the
    // runtime drops it — and with it the sender it holds — some time later.
    // The writer below ends when the last sender is gone, so going straight to
    // it could wait on a task that has been told to stop and has not yet been
    // dropped. Each of these resolves once its task really is gone.
    for handler in handlers {
        let _ = handler.await;
    }
    // Dropping every remaining sender is what ends the writer; awaiting it is
    // what flushes whatever was already queued.
    drop(out);
    drop(server);
    pump.await
        .context("the MCP output task did not finish")?
        .context("writing to the MCP output stream")
}

/// The dispatcher, and everything one request needs from the ones around it.
struct Server {
    context: Arc<Context>,
    out: mpsc::Sender<String>,
    /// The requests currently running, so a cancellation can reach them.
    inflight: Arc<Mutex<HashMap<RequestId, Arc<Cancel>>>>,
    /// The version a legacy `initialize` settled on, if there was one.
    legacy: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").finish_non_exhaustive()
    }
}

impl Server {
    /// Reads one line and starts whatever it asks for.
    ///
    /// Returns the handle of a spawned handler, so the caller can abandon it
    /// at shutdown.
    async fn accept(&self, line: &str) -> Option<tokio::task::JoinHandle<()>> {
        let message = match rpc::parse(line) {
            Ok(message) => message,
            Err(e) => {
                // No id could be read, so the response carries none — which is
                // what JSON-RPC says to do and the only case where that is
                // allowed.
                self.send(rpc::error_response(None, &e)).await;
                return None;
            }
        };

        let request = match message {
            Incoming::Request(request) => request,
            Incoming::Notification { method, params } => {
                self.notified(&method, &params).await;
                return None;
            }
            Incoming::Stray => {
                tracing::debug!("ignoring a message that is not a request");
                return None;
            }
        };

        let era = match self.era(&request).await {
            Ok(era) => era,
            Err(e) => {
                self.send(rpc::error_response(Some(&request.id), &e)).await;
                return None;
            }
        };

        let cancel = Arc::new(Cancel::default());
        // Registered before the task exists, so a cancellation that arrives
        // while it is starting still reaches it, and so the task can remove
        // its own entry without racing the insert.
        self.inflight
            .lock()
            .await
            .insert(request.id.clone(), cancel.clone());

        let context = self.context.clone();
        let out = self.out.clone();
        let inflight = self.inflight.clone();
        let legacy = self.legacy.clone();
        Some(tokio::spawn(async move {
            let id = request.id.clone();
            let reporter = Reporter::new(out.clone(), request.meta.get("progressToken").cloned());
            let answer = tokio::select! {
                biased;
                // A cancelled request is owed no further messages at all, which
                // is why this returns rather than sending anything.
                _ = cancel.cancelled() => {
                    tracing::debug!("a request was cancelled");
                    None
                }
                answer = handle(&context, &legacy, &request, &reporter) => Some(answer),
            };
            inflight.lock().await.remove(&id);
            if let Some(answer) = answer {
                let message = match answer {
                    Ok(result) => rpc::response(&id, &era, result),
                    Err(e) => rpc::error_response(Some(&id), &e),
                };
                let _ = out.send(message.to_string()).await;
            }
        }))
    }

    /// Which era a request is served under.
    ///
    /// `initialize` is the one method that settles this rather than declaring
    /// it, so it is resolved as legacy here and negotiates inside [`handle`].
    async fn era(&self, request: &rpc::Request) -> Result<Era, rpc::Error> {
        // A modern method, answered in the modern era whatever the caller
        // declared: it is how a dual-era client finds out which era this is,
        // so answering it in the legacy era would defeat the probe.
        if request.method == "server/discover" && request.declared_version().is_none() {
            return Ok(Era::Modern {
                version: rpc::LATEST_VERSION.to_string(),
            });
        }

        if let Some(version) = request.declared_version() {
            if !rpc::SUPPORTED_VERSIONS.contains(&version) {
                return Err(rpc::Error::unsupported_version(version));
            }
            if version >= rpc::FIRST_MODERN_VERSION {
                // A modern request missing a required `_meta` field is
                // malformed, and the spec fixes the code.
                if !request.is_modern() {
                    return Err(rpc::Error::invalid_params(format!(
                        "a {version} request must carry {} in _meta",
                        rpc::META_CLIENT_CAPABILITIES
                    )));
                }
                return Ok(Era::Modern {
                    version: version.to_string(),
                });
            }
            return Ok(Era::Legacy {
                version: version.to_string(),
            });
        }

        // No declared version: a legacy client, either mid-session or one that
        // never handshook. Both are served, because refusing the second would
        // refuse clients that work everywhere else for a rule they cannot see.
        Ok(Era::Legacy {
            version: self
                .legacy
                .lock()
                .await
                .clone()
                .unwrap_or_else(|| newest_legacy().to_string()),
        })
    }

    /// Acts on a notification, which is owed no reply.
    async fn notified(&self, method: &str, params: &Value) {
        match method {
            "notifications/cancelled" => {
                let Some(id) = params.get("requestId") else {
                    tracing::debug!("a cancellation named no request");
                    return;
                };
                let Ok(id) = serde_json::from_value::<RequestId>(id.clone()) else {
                    tracing::debug!("a cancellation named a malformed request id");
                    return;
                };
                match self.inflight.lock().await.get(&id) {
                    Some(cancel) => cancel.cancel(),
                    // Already finished. The spec anticipates this race and
                    // says to ignore it.
                    None => tracing::debug!("a cancellation arrived after its request finished"),
                }
            }
            // The legacy handshake's third leg. Nothing to do: the version was
            // settled by the `initialize` it acknowledges.
            "notifications/initialized" => {}
            other => tracing::debug!(method = other, "ignoring an unhandled notification"),
        }
    }

    /// Cancels everything still running.
    async fn cancel_all(&self) {
        for (_, cancel) in self.inflight.lock().await.drain() {
            cancel.cancel();
        }
    }

    /// Queues one message for the writer.
    async fn send(&self, message: Value) {
        let _ = self.out.send(message.to_string()).await;
    }
}

/// Answers one request.
async fn handle(
    context: &Context,
    legacy: &Mutex<Option<String>>,
    request: &rpc::Request,
    reporter: &Reporter,
) -> Result<Value, rpc::Error> {
    match request.method.as_str() {
        "server/discover" => Ok(json!({
            "supportedVersions": rpc::SUPPORTED_VERSIONS,
            "capabilities": capabilities(),
            "instructions": INSTRUCTIONS,
        })),
        "initialize" => {
            let version = negotiate(request.param("protocolVersion").as_str());
            *legacy.lock().await = Some(version.to_string());
            Ok(json!({
                "protocolVersion": version,
                "capabilities": capabilities(),
                "serverInfo": rpc::server_info(),
                "instructions": INSTRUCTIONS,
            }))
        }
        // Defined by the legacy revisions as a liveness check, and harmless to
        // answer in either era.
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({
            "tools": context
                .catalog()
                .iter()
                .map(|tool| tool.to_json())
                .collect::<Vec<_>>(),
        })),
        "tools/call" => {
            let Some(name) = request.param("name").as_str() else {
                return Err(rpc::Error::invalid_params("tools/call needs a tool name"));
            };
            let args = tools::arguments(&request.params);
            match tools::call(context, name, &args, reporter).await {
                Ok(outcome) => {
                    let mut result = json!({ "content": outcome.content, "isError": false });
                    if let (Some(structured), Value::Object(map)) =
                        (outcome.structured, &mut result)
                    {
                        map.insert("structuredContent".into(), structured);
                    }
                    Ok(result)
                }
                // A protocol error is about the request's shape, so it travels
                // as one. Everything else is something a model can act on, and
                // travels as a result it can read.
                Err(ToolError::Protocol(e)) => Err(e),
                Err(ToolError::Execution { message, data }) => {
                    let mut result = json!({
                        "content": [{ "type": "text", "text": message }],
                        "isError": true,
                    });
                    if let (Some(data), Value::Object(map)) = (data, &mut result) {
                        map.insert("structuredContent".into(), data);
                    }
                    Ok(result)
                }
            }
        }
        "resources/list" => {
            let cursor = request.param("cursor").as_str().map(str::to_string);
            resources::list(context, cursor.as_deref())
                .await
                .map_err(into_rpc_error)
        }
        "resources/templates/list" => Ok(resources::templates()),
        "resources/read" => {
            let Some(uri) = request.param("uri").as_str() else {
                return Err(rpc::Error::invalid_params("resources/read needs a uri"));
            };
            resources::read(context, uri).await.map_err(into_rpc_error)
        }
        // Declared by neither capability, so a client should not be asking —
        // and the code says so rather than the request hanging.
        other => Err(rpc::Error::new(
            rpc::METHOD_NOT_FOUND,
            format!("this server does not implement {other}"),
        )),
    }
}

/// Turns a tool failure into a JSON-RPC error, for the surfaces that have no
/// `isError` to carry one.
///
/// `resources/read` and `resources/list` are both of them: their results are
/// contents and listings, with nowhere to put a failure, so the spec routes
/// them through the error channel and fixes the code for a missing resource.
fn into_rpc_error(e: ToolError) -> rpc::Error {
    match e {
        ToolError::Protocol(e) => e,
        ToolError::Execution { message, data } => {
            let error = rpc::Error::new(rpc::INTERNAL_ERROR, message);
            match data {
                Some(data) => error.with_data(data),
                None => error,
            }
        }
    }
}

/// What this server can do, as both eras spell it.
fn capabilities() -> Value {
    json!({
        // The catalogue is fixed at process start by the flags, so it never
        // changes and the notification is never owed.
        "tools": { "listChanged": false },
        // Neither `subscribe` nor `listChanged`: the control service has no
        // watch call to build them on, and claiming a subscription this
        // process cannot deliver is worse than not claiming one.
        "resources": {},
    })
}

/// The newest revision this server supports that still handshakes.
fn newest_legacy() -> &'static str {
    rpc::SUPPORTED_VERSIONS
        .iter()
        .find(|version| **version < rpc::FIRST_MODERN_VERSION)
        .copied()
        // Unreachable while the list holds one: pinned by a test in `rpc`.
        .unwrap_or(rpc::LATEST_VERSION)
}

/// Settles the version a legacy `initialize` gets back.
///
/// A supported legacy version is echoed. Anything else — a version this build
/// does not know, a modern one asked for through the wrong door, or nothing at
/// all — is answered with the newest legacy revision, which is what the
/// handshake defines: the server names a version, and the client disconnects
/// if it cannot speak it.
fn negotiate(requested: Option<&str>) -> &'static str {
    match requested {
        Some(version) => rpc::SUPPORTED_VERSIONS
            .iter()
            .find(|known| **known == version && **known < rpc::FIRST_MODERN_VERSION)
            .copied()
            .unwrap_or_else(newest_legacy),
        None => newest_legacy(),
    }
}

/// A request's progress channel, when the client opted into one.
///
/// The daemon already reports what a long command is doing — `scan`, `sync`
/// and `fill` all emit progress frames the CLI prints to stderr — so the only
/// thing missing was somewhere to put them. A client that sends a
/// `progressToken` gets them; one that does not sends nothing and costs
/// nothing.
#[derive(Debug, Clone)]
pub(crate) struct Reporter {
    out: mpsc::Sender<String>,
    token: Option<Value>,
    /// How many reports have gone out, which is the only monotonic number
    /// available: the frames say what is happening, never how much is left.
    sent: Arc<std::sync::atomic::AtomicU64>,
}

impl Reporter {
    /// Builds a reporter for one request.
    fn new(out: mpsc::Sender<String>, token: Option<Value>) -> Reporter {
        Reporter {
            out,
            token,
            sent: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// A reporter that discards everything, for callers with no client.
    #[cfg(test)]
    pub(crate) fn silent() -> Reporter {
        let (out, _) = mpsc::channel(1);
        Reporter::new(out, None)
    }

    /// Reports one step, if the client asked to hear about them.
    pub(crate) async fn report(&self, message: &str) {
        let Some(token) = &self.token else {
            return;
        };
        let progress = self.sent.fetch_add(1, Ordering::Relaxed) + 1;
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": token,
                "progress": progress,
                "message": message,
            },
        });
        let _ = self.out.send(notification.to_string()).await;
    }
}

/// A one-shot cancellation signal.
///
/// A flag as well as a notify: a cancellation that arrives before the handler
/// reaches its first await must still be seen, and `Notify` alone only wakes
/// waiters that are already waiting.
#[derive(Debug, Default)]
struct Cancel {
    flag: AtomicBool,
    notify: Notify,
}

impl Cancel {
    /// Signals the request to stop.
    fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Resolves once cancelled.
    async fn cancelled(&self) {
        loop {
            // The future is created before the flag is read, so a `cancel`
            // landing between the two still wakes this.
            let notified = self.notify.notified();
            if self.flag.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
            if self.flag.load(Ordering::SeqCst) {
                return;
            }
        }
    }
}

/// Writes queued messages, one per line, flushing each.
///
/// Flushed per message because a response the client cannot see yet is a
/// response that has not arrived: this is a request/response protocol over a
/// pipe, and buffering turns an answer into a hang.
async fn write_all<W>(mut writer: W, mut outbox: mpsc::Receiver<String>) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(message) = outbox.recv().await {
        debug_assert!(
            !message.contains('\n'),
            "a message with an embedded newline would be two messages on the wire"
        );
        writer.write_all(message.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
    Ok(())
}

/// Newline framing with a ceiling.
struct Framed<R> {
    reader: R,
    buffer: Vec<u8>,
    /// How far into the buffer a newline has already been looked for, so a
    /// long line is scanned once rather than once per read.
    scanned: usize,
}

impl<R: AsyncRead + Unpin> Framed<R> {
    /// Wraps a stream.
    fn new(reader: R) -> Framed<R> {
        Framed {
            reader,
            buffer: Vec::new(),
            scanned: 0,
        }
    }

    /// The next line, without its terminator, or `None` at end of stream.
    async fn next(&mut self) -> std::io::Result<Option<String>> {
        let mut chunk = [0u8; 8192];
        loop {
            if let Some(offset) = self.buffer[self.scanned..].iter().position(|b| *b == b'\n') {
                let end = self.scanned + offset;
                let line: Vec<u8> = self.buffer.drain(..=end).collect();
                self.scanned = 0;
                return Ok(Some(decode_line(&line[..end])?));
            }
            self.scanned = self.buffer.len();
            if self.buffer.len() > MAX_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("a line longer than {MAX_LINE_BYTES} bytes is not an MCP message"),
                ));
            }
            let read = self.reader.read(&mut chunk).await?;
            if read == 0 {
                // A final line with no terminator is still a message; the next
                // call returns None.
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                let last = std::mem::take(&mut self.buffer);
                self.scanned = 0;
                return Ok(Some(decode_line(&last)?));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// Reads one framed line as UTF-8, tolerating a CRLF terminator.
fn decode_line(bytes: &[u8]) -> std::io::Result<String> {
    let bytes = match bytes.last() {
        Some(b'\r') => &bytes[..bytes.len() - 1],
        _ => bytes,
    };
    String::from_utf8(bytes.to_vec()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("an MCP message must be UTF-8: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options {
            allow_write: false,
            spaces: Vec::new(),
            max_read_bytes: 64 * 1024,
        }
    }

    #[tokio::test]
    async fn framing_splits_on_newlines_and_tolerates_crlf_and_a_missing_last_one() {
        let input = "one\r\ntwo\n\nthree";
        let mut framed = Framed::new(input.as_bytes());
        assert_eq!(framed.next().await.unwrap().as_deref(), Some("one"));
        assert_eq!(framed.next().await.unwrap().as_deref(), Some("two"));
        assert_eq!(framed.next().await.unwrap().as_deref(), Some(""));
        assert_eq!(framed.next().await.unwrap().as_deref(), Some("three"));
        assert_eq!(framed.next().await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_line_without_end_is_refused_rather_than_buffered_forever() {
        let flood = vec![b'x'; MAX_LINE_BYTES + 1];
        let mut framed = Framed::new(&flood[..]);
        let error = framed.next().await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn non_utf8_input_is_refused() {
        let mut framed = Framed::new(&b"\xff\xfe\n"[..]);
        assert!(framed.next().await.is_err());
    }

    #[tokio::test]
    async fn cancellation_is_seen_even_when_it_lands_first() {
        let cancel = Cancel::default();
        cancel.cancel();
        // Would hang if the flag were not checked before waiting.
        tokio::time::timeout(std::time::Duration::from_secs(5), cancel.cancelled())
            .await
            .expect("an already-cancelled signal resolves immediately");
    }

    #[test]
    fn legacy_negotiation_answers_with_something_the_client_can_speak() {
        assert_eq!(negotiate(Some("2025-06-18")), "2025-06-18");
        assert_eq!(negotiate(Some("2025-11-25")), "2025-11-25");
        // A version this build does not know, and a modern one asked for
        // through the handshake, both land on the newest legacy revision.
        assert_eq!(negotiate(Some("1999-01-01")), newest_legacy());
        assert_eq!(negotiate(Some(rpc::LATEST_VERSION)), newest_legacy());
        assert_eq!(negotiate(None), newest_legacy());
        assert!(newest_legacy() < rpc::FIRST_MODERN_VERSION);
    }

    /// Drives a server over an in-memory duplex and collects what it wrote.
    ///
    /// The datadir has no daemon, which is the point for these: everything
    /// here is answered without one.
    /// A modern request, with the `_meta` every one of them must carry.
    fn modern(id: i64, method: &str, mut params: Value) -> String {
        params["_meta"] = json!({
            rpc::META_PROTOCOL_VERSION: rpc::LATEST_VERSION,
            rpc::META_CLIENT_CAPABILITIES: {},
            "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "1" },
        });
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
    }

    async fn exchange(lines: &[&str]) -> Vec<Value> {
        let data = tempfile::tempdir().unwrap();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let input: String = lines
            .iter()
            .inspect(|line| {
                assert!(
                    !line.contains('\n'),
                    "one message is one line; this test would send several broken ones"
                )
            })
            .map(|line| format!("{line}\n"))
            .collect();
        let (server_read, server_write) = tokio::io::split(server);
        let path = data.path().to_path_buf();
        let serving =
            tokio::spawn(async move { serve(server_read, server_write, &path, options()).await });
        client.write_all(input.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut raw = String::new();
        client.read_to_string(&mut raw).await.unwrap();
        serving.await.unwrap().unwrap();
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("every line is a JSON message"))
            .collect()
    }

    #[tokio::test]
    async fn discovery_answers_without_a_daemon_and_names_every_version() {
        let out = exchange(&[&modern(1, "server/discover", json!({}))]).await;
        assert_eq!(out.len(), 1);
        let result = &out[0]["result"];
        assert_eq!(result["resultType"], "complete");
        assert_eq!(result["supportedVersions"][0], rpc::LATEST_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(
            result["_meta"][rpc::META_SERVER_INFO]["name"],
            "synchronicity"
        );
    }

    #[tokio::test]
    async fn a_legacy_client_handshakes_and_then_lists_tools_with_no_metadata() {
        let out = exchange(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        ])
        .await;
        assert_eq!(out.len(), 2, "the notification is owed no reply");
        assert_eq!(out[0]["result"]["protocolVersion"], "2025-06-18");
        assert!(
            out[0]["result"].get("resultType").is_none(),
            "2025-06-18 does not define resultType"
        );
        let tools = out[1]["result"]["tools"].as_array().unwrap();
        assert!(tools.iter().any(|tool| tool["name"] == "synch_read"));
        assert!(
            !tools.iter().any(|tool| tool["name"] == "synch_write"),
            "the write tier is off by default"
        );
    }

    #[tokio::test]
    async fn an_unknown_version_is_refused_with_the_ones_we_have() {
        let out = exchange(&[&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "_meta": {
                rpc::META_PROTOCOL_VERSION: "1900-01-01",
                rpc::META_CLIENT_CAPABILITIES: {},
            }},
        })
        .to_string()])
        .await;
        assert_eq!(out[0]["error"]["code"], rpc::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(out[0]["error"]["data"]["requested"], "1900-01-01");
        assert_eq!(out[0]["error"]["data"]["supported"][0], rpc::LATEST_VERSION);
    }

    #[tokio::test]
    async fn a_modern_request_missing_its_capabilities_is_malformed() {
        let out = exchange(&[&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "_meta": { rpc::META_PROTOCOL_VERSION: rpc::LATEST_VERSION }},
        })
        .to_string()])
        .await;
        assert_eq!(out[0]["error"]["code"], rpc::INVALID_PARAMS);
        assert!(out[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("clientCapabilities"));
    }

    #[tokio::test]
    async fn malformed_input_is_answered_and_the_stream_survives_it() {
        let out = exchange(&["{not json", r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#]).await;
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["error"]["code"], rpc::PARSE_ERROR);
        assert!(out[0]["id"].is_null(), "an unreadable id travels as null");
        // The result is empty apart from the identity every result carries.
        assert_eq!(
            out[1]["result"]["_meta"][rpc::META_SERVER_INFO]["name"],
            "synchronicity"
        );
        assert!(out[1]["result"].get("error").is_none());
    }

    #[tokio::test]
    async fn an_unimplemented_method_says_so() {
        let out = exchange(&[r#"{"jsonrpc":"2.0","id":1,"method":"prompts/list"}"#]).await;
        assert_eq!(out[0]["error"]["code"], rpc::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn a_tool_that_needs_the_daemon_reports_it_as_something_to_fix() {
        let out = exchange(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"synch_peers","arguments":{}}}"#,
        ])
        .await;
        // A tool execution error, not a protocol error: the model is told what
        // to do about it rather than that it asked wrongly.
        assert!(out[0].get("error").is_none(), "{:?}", out[0]);
        assert_eq!(out[0]["result"]["isError"], true);
        let text = out[0]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("synch daemon start"), "{text}");
        assert_eq!(out[0]["result"]["structuredContent"]["code"], "unavailable");
    }

    #[tokio::test]
    async fn an_unknown_tool_is_a_protocol_error() {
        let out = exchange(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm_rf","arguments":{}}}"#,
        ])
        .await;
        assert_eq!(out[0]["error"]["code"], rpc::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn a_bad_resource_uri_is_refused_with_the_code_the_spec_fixes() {
        let out = exchange(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#,
        ])
        .await;
        assert_eq!(out[0]["error"]["code"], rpc::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn every_response_is_one_line_and_carries_its_id_back() {
        let out = exchange(&[
            r#"{"jsonrpc":"2.0","id":"a","method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
        ])
        .await;
        let ids: Vec<&Value> = out.iter().map(|message| &message["id"]).collect();
        assert!(ids.contains(&&json!("a")) && ids.contains(&&json!(7)));
        for message in &out {
            assert_eq!(message["jsonrpc"], "2.0");
        }
    }
}
