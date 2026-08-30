//! `synch daemon run`: the process that owns the node, and `synch daemon
//! start`: its background launcher (§9.1).
//!
//! The daemon holds the one endpoint, the one database writer, and the one
//! lifecycle. It serves the control socket concurrently with the engine's
//! standing work — the anti-entropy scheduler, the scanner, the filesystem
//! watcher, the batching publisher, the mirror loop, and the maintenance/GC
//! pass.

use std::{
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use anyhow::{Context, Result};
use synch_engine::{Node, NodeConfig};
use tokio::sync::broadcast;

use crate::{
    control::{proto::pb, Client, Command as ControlCommand, Server},
    render,
};

/// The background daemon's combined stdout and stderr log.
const LOG_FILE: &str = "daemon.log";

/// Private handoff from the background launcher to the `daemon run` child.
const READY_FILE_ENV: &str = "SYNCH_INTERNAL_READY_FILE";

/// How long `daemon start` waits for the child's control socket before giving
/// up on it.
///
/// Generous, because the wait covers real work: opening the store, running
/// startup recovery over whatever the last run left behind, and binding iroh.
/// A cold start on a large node behind a slow disk is entitled to take a while,
/// and a launcher that gave up on a daemon that was merely busy would be worse
/// than one that waited. What it may not do is wait *for ever* — that is not
/// patience, it is a hang with no diagnosis, and it is what this bounds.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

/// A pending server can become a named server in the same process. Only the
/// first one is this process's startup boundary.
static READY_SENT: AtomicBool = AtomicBool::new(false);

/// Starts this executable's `daemon run` form in the background and waits
/// until its control socket accepts connections.
///
/// All global arguments are preserved verbatim, including values supplied on
/// the command line; values supplied through the environment are inherited by
/// the child. The child gets its own process group and no terminal handles, so
/// the launcher can exit without either forwarding Ctrl-C or keeping a caller's
/// stdout/stderr pipes open.
pub async fn start(data_dir: &Path, args: impl IntoIterator<Item = OsString>) -> Result<()> {
    // Refuse a running daemon (or an offline migration) before spawning. The
    // child takes this same lock for its whole life; this acquisition is only
    // a preflight and is dropped immediately before the spawn.
    let lifecycle = crate::control::transport::LifecycleLock::acquire(data_dir)
        .context("another daemon or CAS migration owns this data directory")?;
    drop(lifecycle);

    let args = run_args(args)?;
    let log_path = data_dir.join(LOG_FILE);
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("could not open daemon log {}", log_path.display()))?;
    writeln!(
        log,
        "\n--- synch daemon start (launcher pid {}) ---",
        std::process::id()
    )?;
    log.flush()?;
    let log_start = log.stream_position()?;
    let stderr = log.try_clone()?;

    // The socket identifies a data directory, not a process. This marker ties
    // the later status round-trip to this exact child, so two simultaneous
    // launchers cannot both claim whichever daemon won the lifecycle lock.
    let ready = ReadyMarker::new(data_dir);

    let mut command = Command::new(std::env::current_exe().context("could not locate synch")?);
    command
        .args(args)
        .env(READY_FILE_ENV, ready.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    detach(&mut command);

    let mut child = command.spawn().context("could not start the daemon")?;
    let deadline = std::time::Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("could not inspect the daemon")? {
            return Err(startup_exit(status, &log_path, log_start));
        }

        // A child that neither comes up nor exits used to spin this loop for
        // ever, and `daemon start` with it. That is the worst shape a failure
        // can take: the launcher holds whatever invoked it — a shell, a service
        // manager, a test harness reading its output — with nothing on stdout
        // and nothing in the log to say what is wrong. It cost a CI run six
        // hours before anyone could see which test was stuck.
        //
        // Every other startup failure here reports with the log tail, so this
        // one does too. Killing the child first is the point of ordering: this
        // process is about to say the daemon did not come up, and leaving a
        // half-started one holding the lifecycle lock would make the next
        // `daemon start` fail for a reason that is this call's fault.
        if std::time::Instant::now() >= deadline {
            // Which of the two conditions was never met, before the child is
            // killed and the answer becomes unobtainable. They fail for
            // unrelated reasons and the difference decides where to look: a
            // marker that never appeared is a child that did not reach its
            // readiness signal, while a marker present and a socket that never
            // answered means the daemon is serving somewhere this launcher is
            // not looking — which is possible at all only because the endpoint
            // name is computed independently by each process.
            let marker = ready.belongs_to(child.id());
            let _ = child.kill();
            let _ = child.wait();
            return Err(startup_timeout(
                &log_path,
                log_start,
                marker,
                &crate::control::transport::endpoint_name(data_dir),
            ));
        }

        // Binding the listener is earlier than serving it: startup recovery
        // happens between those two events. A real authenticated round-trip is
        // the boundary callers need before their next command can succeed.
        if ready.belongs_to(child.id())
            && tokio::time::timeout(Duration::from_secs(1), control_is_ready(data_dir))
                .await
                .unwrap_or(false)
        {
            // Close the last small race between the status response and the
            // child losing its lifecycle. The marker is the primary identity
            // proof; this makes an exit at the boundary report as an exit.
            if let Some(status) = child.try_wait().context("could not inspect the daemon")? {
                return Err(startup_exit(status, &log_path, log_start));
            }
            println!("daemon started (pid {})", child.id());
            println!(
                "control socket: {}",
                crate::control::transport::endpoint_name(data_dir)
            );
            println!("log: {}", log_path.display());
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A unique, process-specific startup handshake file.
#[derive(Debug)]
struct ReadyMarker(std::path::PathBuf);

impl ReadyMarker {
    fn new(data_dir: &Path) -> Self {
        Self(data_dir.join(format!(
            ".daemon-start-{}-{}.ready",
            std::process::id(),
            synch_core::now_ns()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn belongs_to(&self, pid: u32) -> bool {
        std::fs::read_to_string(&self.0).is_ok_and(|value| value.trim() == pid.to_string())
    }
}

impl Drop for ReadyMarker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Signals that this exact `daemon run` process has started its control
/// server. The launcher still performs a status round-trip before returning.
fn signal_background_ready(data_dir: &Path) -> Result<()> {
    let Some(path) = std::env::var_os(READY_FILE_ENV).map(std::path::PathBuf::from) else {
        return Ok(());
    };
    if READY_SENT.load(Ordering::Acquire) {
        return Ok(());
    }
    let valid = path.parent() == Some(data_dir)
        && path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(".daemon-start-"));
    if !valid {
        anyhow::bail!(
            "refusing invalid background readiness path {}",
            path.display()
        );
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| {
            format!(
                "could not create background readiness marker {}",
                path.display()
            )
        })?;
    writeln!(file, "{}", std::process::id()).with_context(|| {
        format!(
            "could not write background readiness marker {}",
            path.display()
        )
    })?;
    READY_SENT.store(true, Ordering::Release);
    Ok(())
}

/// A successful status response proves the listener, token, gRPC service and
/// command handler are all ready. It works for both named nodes and the reduced
/// service used while a membership zone has not named the device yet.
async fn control_is_ready(data_dir: &Path) -> bool {
    let Ok(mut client) = Client::connect(data_dir).await else {
        return false;
    };
    let Ok(mut frames) = client
        .run(ControlCommand::DaemonStatus(pb::DaemonStatus {}))
        .await
    else {
        return false;
    };
    loop {
        match frames.next().await {
            Ok(Some(_)) => {}
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

/// Rewrites the launcher's subcommand while leaving every global option in
/// exactly the position and spelling the caller used.
fn run_args(args: impl IntoIterator<Item = OsString>) -> Result<Vec<OsString>> {
    let mut args: Vec<OsString> = args.into_iter().collect();
    let Some(start) = args
        .windows(2)
        .rposition(|pair| pair[0] == OsStr::new("daemon") && pair[1] == OsStr::new("start"))
    else {
        anyhow::bail!("could not reconstruct `synch daemon start` arguments");
    };
    args[start + 1] = OsString::from("run");
    Ok(args)
}

/// Reads a bounded tail so a failed background launch still reports the
/// daemon's actual startup error without loading an old, potentially large log.
fn log_tail(path: &Path, current_start: u64) -> std::io::Result<String> {
    const TAIL: u64 = 16 * 1024;
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(current_start.max(len.saturating_sub(TAIL))))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn startup_timeout(log_path: &Path, log_start: u64, marker: bool, endpoint: &str) -> anyhow::Error {
    let detail = log_tail(log_path, log_start).unwrap_or_default();
    let detail = detail.trim();
    let secs = STARTUP_TIMEOUT.as_secs();
    let reached = match marker {
        true => "it signalled readiness, so it is running but not answering at",
        false => "it never signalled readiness; this launcher was watching",
    };
    let detail = match detail.is_empty() {
        true => "it wrote nothing to the log".to_string(),
        false => format!("{} contains:\n{detail}", log_path.display()),
    };
    anyhow::anyhow!(
        "daemon did not come up within {secs}s and has been stopped; \
         {reached} {endpoint}; {detail}"
    )
}

fn startup_exit(
    status: std::process::ExitStatus,
    log_path: &Path,
    log_start: u64,
) -> anyhow::Error {
    let detail = log_tail(log_path, log_start).unwrap_or_default();
    let detail = detail.trim();
    if detail.is_empty() {
        anyhow::anyhow!(
            "daemon exited with {status} before its control socket was ready; see {}",
            log_path.display()
        )
    } else {
        anyhow::anyhow!(
            "daemon exited with {status} before its control socket was ready; {} contains:\n{detail}",
            log_path.display()
        )
    }
}

#[cfg(unix)]
fn detach(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
fn detach(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
    disinherit_std_handles();
    command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

/// Stops the daemon from inheriting *this* process's stdout and stderr.
///
/// The child's own three handles are redirected to the log a few lines above,
/// which is the part that looks like it settles the question. It does not.
/// `CreateProcess` is called with `bInheritHandles = TRUE` — Rust's `Command`
/// has no other way to hand a child its redirected stdio — and that flag is
/// not selective: the child receives *every* handle in this process that is
/// marked inheritable, not only the three that were redirected. When
/// `daemon start` was itself launched with piped output, its stdout and stderr
/// are the write ends of those pipes, they are inheritable, and so the daemon
/// holds them open for its entire life.
///
/// The reader on the other end is then waiting for a pipe that will not close
/// until the daemon exits, which is the opposite of what backgrounding it was
/// for. `std::process::Command::output()` waits for EOF and not for exit, so
/// anything reading this command that way — a script, a service manager, this
/// repo's own `cli.rs` tests — blocks indefinitely even though the launcher
/// exited long before. The launcher's own startup timeout cannot help: it
/// exits on time and the pipe stays open regardless, because another process
/// holds it.
///
/// Clearing the inherit flag first costs nothing. The child never reads or
/// writes these handles — it was given the log instead — so the only thing
/// lost is a handle it had no business holding.
///
/// Unix needs no equivalent: `exec` keeps only the descriptors explicitly
/// dup'd into place, and the rest are closed by `CLOEXEC`.
#[cfg(windows)]
fn disinherit_std_handles() {
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};

    for id in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: `GetStdHandle` returns a handle this process owns, or an
        // invalid one when there is no such stream. `SetHandleInformation`
        // only clears a flag on it and reports failure through its return,
        // which is ignored on purpose: a process without a console, or one
        // whose stream is already non-inheritable, has nothing to clear and
        // is not a reason to refuse to start a daemon.
        unsafe {
            let handle = GetStdHandle(id);
            if !handle.is_null() {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

/// Opens the node, binds the control socket, and runs until stopped.
///
/// Stopping happens on `Ctrl-C` or on a `synch daemon stop` request; both fire
/// the same broadcast, which every task shuts down on.
pub async fn run(config: NodeConfig) -> Result<()> {
    let data_dir = config.data_dir.clone();
    // Before Store open and before iroh bind: offline migration holds the same
    // lock, so the two can never overlap during initialization either.
    let _lifecycle = crate::control::transport::LifecycleLock::acquire(&config.data_dir)
        .context("another daemon or CAS migration owns this data directory")?;
    // No "(run `synch init` first?)" stapled onto every failure: the
    // uninitialized case already says exactly that itself, and the hint sent
    // an operator with a taken port off to re-init a healthy node.
    let (stop_tx, _) = broadcast::channel::<()>(1);
    let node = open_once_named(config, &stop_tx)
        .await
        .context("could not open the node")?;
    // Before anything is announced: a daemon that cannot resolve the membership
    // it is configured for has nothing to serve past the current grace window,
    // and finding that out at startup is the difference between a fixable
    // message and a cluster that partitions on a timer.
    let resolver = match build_resolver(&node).await {
        Ok(resolver) => resolver,
        Err(e) => {
            let _ = node.shutdown().await;
            return Err(e);
        }
    };
    // Subscribed before anything can ask us to stop, so a `daemon stop` that
    // arrives during the initial scan is not sent to nobody.
    let mut stopped = stop_tx.subscribe();

    // Bind before announcing: a client that sees the banner can connect.
    let server = match Server::bind(node.clone(), stop_tx.clone()).await {
        Ok(server) => server,
        Err(e) => {
            // The endpoint is already up; close it properly or iroh shouts
            // "Aborting ungracefully" over the error that actually matters —
            // usually "another daemon already owns this datadir".
            let origin = node.origin().clone();
            let _ = node.shutdown().await;
            return Err(anyhow::Error::new(e)
                .context(format!("could not bind the control socket for {origin}")));
        }
    };
    println!(
        "origin {} on {}",
        node.origin(),
        render::addr(&node.net().direct_addr())
    );
    println!("control socket: {}", server.endpoint_name());

    // A completion severed by a stop or a crash left its upload latched, and
    // nothing else ever clears the latch: without this, an upload whose parts
    // are all still staged would refuse every retry until it aged out (§9.4).
    // Off the runtime: it takes a store connection, which §10 keeps off the
    // worker threads.
    let reopening = node.clone();
    match synch_core::offload(move || reopening.reopen_interrupted_uploads()).await {
        Ok(0) => {}
        Ok(reopened) => tracing::info!(reopened, "reopened interrupted multipart uploads"),
        Err(e) => tracing::warn!(error = %e, "could not reopen interrupted uploads"),
    }

    // A restored SQLite replica may trail an acknowledged publish whose bytes
    // already reached the cloud CAS. Peers retain the signed head; recover it
    // before scanner or publisher tasks can mint a competing successor.
    match node.readopt_self_on_startup().await {
        Ok(true) => tracing::info!("re-adopted a newer own-origin head from a peer"),
        Ok(false) => {}
        Err(error) => {
            let _ = node.shutdown().await;
            return Err(anyhow::Error::new(error)
                .context("startup own-head/cloud durability recovery failed"));
        }
    }

    if let Err(error) = signal_background_ready(&data_dir) {
        crate::control::transport::remove_token(&data_dir);
        let _ = node.shutdown().await;
        return Err(error);
    }
    let control = tokio::spawn(server.run());
    let aae = spawn_loop(
        "anti-entropy",
        &node,
        &stop_tx,
        |node, shutdown| async move { node.run_anti_entropy(shutdown).await },
    );
    let scanner = spawn_loop("scanner", &node, &stop_tx, |node, shutdown| async move {
        node.run_scanner(shutdown).await
    });
    let watcher = spawn_loop("watcher", &node, &stop_tx, |node, shutdown| async move {
        node.run_watcher(shutdown).await
    });
    let maintenance = spawn_loop(
        "maintenance",
        &node,
        &stop_tx,
        |node, shutdown| async move { node.run_maintenance(shutdown).await },
    );
    // The standing checkout loop: projects replicas whenever the tree
    // changes, and once at startup (§7.2).
    let checkouts = spawn_loop("checkouts", &node, &stop_tx, |node, shutdown| async move {
        node.run_checkouts(shutdown).await
    });
    // The standing replication loop: reconciles what the replicated spaces
    // should hold against what they do, and fetches the difference
    // (`docs/REPLICATION.md` §3.4). A node replicating nothing sweeps an empty
    // list and sleeps.
    let replicas = spawn_loop("replicas", &node, &stop_tx, |node, shutdown| async move {
        node.run_replicas(shutdown).await
    });
    // Membership is only as live as its last validated lookup: without this
    // loop a DNSSEC cluster dissolves one TTL plus grace after the last manual
    // refresh, because `run_maintenance` expires bindings and nothing renews
    // them (§3.2). It also carries the §3.4 unknown-key trigger.
    let dns_resolver = resolver.clone();
    let dns = spawn_loop("dns", &node, &stop_tx, move |node, shutdown| async move {
        match dns_resolver {
            Some(resolver) => node.run_dns(resolver.as_ref(), shutdown).await,
            None => shutdown.await,
        }
    });
    // Multipart uploads leak by design — S3's own answer is a lifecycle rule —
    // so something has to collect the ones nobody finished, and the payloads a
    // crash or a re-uploaded part left unreferenced inside a live upload (§9.4).
    let uploads = spawn_loop("uploads", &node, &stop_tx, |node, shutdown| async move {
        run_upload_sweeper(&node, shutdown).await
    });
    // The outbound tunnel to the control plane the membership zone names — on
    // by default, and a settings read per interval once opted out.
    // It shares this process's node, database handle and resolver by
    // construction, because it *is* the daemon (§9.1).
    let cloud_resolver = resolver.clone();
    let cloud = spawn_loop("cloud", &node, &stop_tx, move |node, shutdown| async move {
        node.run_cloud(cloud_resolver, shutdown).await
    });
    // What turns the scanner's and the watcher's staged changes into heads: one
    // batch per quiet period or per 1000 entries, whichever comes first (§7.1).
    let publisher = spawn_loop("publisher", &node, &stop_tx, |node, shutdown| async move {
        node.run_publisher(shutdown).await
    });

    // An initial scan and push, so a fresh daemon converges immediately rather
    // than waiting a full interval — with the stop signal watched throughout
    // it. The scan reads every space and pushes the head it produces to every
    // peer, so it is the one piece of startup work that depends on the outside
    // world, and a daemon that cannot be stopped while it runs is a daemon an
    // operator has to kill.
    let mut stopping = false;
    tokio::select! {
        scanned = node.scan_publish_push() => {
            if let Err(e) = scanned {
                tracing::warn!(error = %e, "initial scan failed");
            }
        }
        stop = wait_for_stop(&stop_tx, &mut stopped) => {
            stop?;
            stopping = true;
        }
    }
    if !stopping {
        wait_for_stop(&stop_tx, &mut stopped).await?;
    }

    // A plain join: every loop either selects on the shutdown signal or is
    // bounded by the dial timeout and the per-request deadline the network
    // layer applies, so none of them can outlive the stop by more than one
    // request.
    //
    // The results are read, not discarded. A `JoinError` here means a loop
    // ended by panicking rather than by the stop signal — which happened at
    // some earlier and unknown moment, since nothing restarts one and nothing
    // else inspects the handle. The daemon went on serving without it: with no
    // publisher nothing is ever published again, with no anti-entropy the node
    // silently stops converging, and `daemon status` keeps answering. Ending
    // the process with a message naming the loop is the least this can do, and
    // the exit status is what a supervisor restarts on.
    let outcomes = tokio::join!(
        control,
        aae,
        scanner,
        watcher,
        maintenance,
        publisher,
        dns,
        checkouts,
        replicas,
        uploads,
        cloud
    );
    // One entry per joined task, in the order they are joined. The names and
    // the indices have to be read together — a list shorter than the join
    // silently reports one loop's outcome under another loop's name, which is
    // worse than not reporting it, since the message sends whoever reads it to
    // the wrong place.
    let named: [(&str, bool); 11] = [
        ("control", outcomes.0.is_err()),
        ("anti-entropy", outcomes.1.is_err()),
        ("scanner", outcomes.2.is_err()),
        ("watcher", outcomes.3.is_err()),
        ("maintenance", outcomes.4.is_err()),
        ("publisher", outcomes.5.is_err()),
        ("dns", outcomes.6.is_err()),
        ("checkouts", outcomes.7.is_err()),
        ("replicas", outcomes.8.is_err()),
        ("uploads", outcomes.9.is_err()),
        ("cloud", outcomes.10.is_err()),
    ];
    let lost: Vec<&str> = named
        .iter()
        .filter(|(_, failed)| *failed)
        .map(|(name, _)| *name)
        .collect();
    if !lost.is_empty() {
        node.shutdown().await?;
        anyhow::bail!(
            "the {} loop(s) ended abnormally and this daemon has been running without them; \
             restart it",
            lost.join(", ")
        );
    }
    node.shutdown().await?;
    Ok(())
}

/// Opens the node, serving the reduced control service until the membership
/// zone names it (§3.1).
///
/// A node with no name cannot sign, publish or scan, and no peer would accept
/// its connections either — the same absent record leaves them without a
/// binding for its key. But it must still answer the control socket, because
/// the command that lifts the state is `synch domain set`: without a socket a
/// data directory pointed at the wrong zone could never be corrected, and its
/// key, its published history and its content would be unreachable.
///
/// So the wait is served, not slept through. The pending server is torn down
/// before the real one binds, because they want the same socket.
async fn open_once_named(config: NodeConfig, stop: &broadcast::Sender<()>) -> Result<Node> {
    let mut serving: Option<(
        tokio::task::JoinHandle<std::io::Result<()>>,
        broadcast::Sender<()>,
    )> = None;
    let recheck = std::sync::Arc::new(tokio::sync::Notify::new());
    loop {
        match Node::open(config.clone()).await {
            Err(synch_engine::EngineError::Unidentified { domain, node_id }) => {
                if serving.is_none() {
                    println!("waiting for {domain} to name this node");
                    println!(
                        "  _synchronicity.{domain}. IN TXT \"v=sync1 id=<name> nk={} apex=<apex>\"",
                        node_id.to_z32()
                    );
                    let pending =
                        pending_state(&config, &domain, *node_id, recheck.clone()).await?;
                    // Its own stop channel: this server is torn down when the
                    // zone answers, which is not the daemon shutting down.
                    let (pending_stop, _) = broadcast::channel::<()>(1);
                    let server = Server::bind_pending(pending, pending_stop.clone())
                        .await
                        .with_context(|| {
                            format!(
                                "could not bind the control socket for {}",
                                config.data_dir.display()
                            )
                        })?;
                    println!("control socket: {}", server.endpoint_name());
                    if let Err(error) = signal_background_ready(&config.data_dir) {
                        crate::control::transport::remove_token(&config.data_dir);
                        return Err(error);
                    }
                    serving = Some((tokio::spawn(server.run()), pending_stop));
                }
                tokio::select! {
                    signal = termination_signal() => {
                        signal?;
                        stop_pending(serving.take()).await;
                        anyhow::bail!("stopped while waiting for {domain} to name this node");
                    }
                    // `synch daemon stop` reaches the pending server, which
                    // fires its own channel; leaving is the same as Ctrl-C.
                    stopped = wait_for_pending_stop(&serving) => {
                        stopped?;
                        stop_pending(serving.take()).await;
                        anyhow::bail!("stopped while waiting for {domain} to name this node");
                    }
                    // `synch domain refresh` rings this, so an operator who
                    // has just published the record — or pointed the node at
                    // another zone — does not wait out the tick.
                    _ = recheck.notified() => {}
                    _ = tokio::time::sleep(IDENTITY_POLL) => {}
                }
            }
            other => {
                // The socket is wanted by the real server next, so this one
                // has to be all the way down before returning.
                stop_pending(serving.take()).await;
                let _ = stop;
                return Ok(other?);
            }
        }
    }
}

/// Reads what the reduced service needs to know about a node with no name.
///
/// Opening the store is filesystem work, so it goes to the blocking pool like
/// every other store acquisition (§10).
async fn pending_state(
    config: &NodeConfig,
    domain: &str,
    node_id: synch_core::NodeId,
    recheck: std::sync::Arc<tokio::sync::Notify>,
) -> Result<crate::control::Pending> {
    let data_dir = config.data_dir.clone();
    let opened = data_dir.clone();
    let store = tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        synch_store::Store::open(&opened)
    })
    .await
    .context("the store-opening task did not complete")?
    .with_context(|| format!("could not open {}", data_dir.display()))?;
    Ok(crate::control::Pending {
        data_dir,
        store: std::sync::Arc::new(store),
        node_id,
        domain: domain.to_string(),
        recheck,
    })
}

/// Waits for a `synch daemon stop` that reached the pending server.
async fn wait_for_pending_stop(
    serving: &Option<(
        tokio::task::JoinHandle<std::io::Result<()>>,
        broadcast::Sender<()>,
    )>,
) -> Result<()> {
    match serving {
        Some((_, stop)) => {
            let mut rx = stop.subscribe();
            let _ = rx.recv().await;
            Ok(())
        }
        None => std::future::pending().await,
    }
}

/// Brings the pending server down and waits for the socket to go with it.
async fn stop_pending(
    serving: Option<(
        tokio::task::JoinHandle<std::io::Result<()>>,
        broadcast::Sender<()>,
    )>,
) {
    if let Some((task, stop)) = serving {
        let _ = stop.send(());
        let _ = task.await;
    }
}

/// How often a node with no name yet re-asks its zone (§3.1).
///
/// Tight enough that publishing the record and watching the node come up feels
/// immediate, loose enough not to flood a name that does not exist yet.
const IDENTITY_POLL: std::time::Duration = std::time::Duration::from_secs(30);

/// Waits for the daemon to be told to stop: SIGINT/SIGTERM, or a `synch daemon stop`
/// request landing on the control socket.
///
/// `Ctrl-C` fires the same broadcast a control request does, so both paths shut
/// every task down the one way.
async fn wait_for_stop(
    stop_tx: &broadcast::Sender<()>,
    stopped: &mut broadcast::Receiver<()>,
) -> Result<()> {
    tokio::select! {
        signal = termination_signal() => {
            signal?;
            println!("shutting down");
            let _ = stop_tx.send(());
        }
        _ = stopped.recv() => {}
    }
    Ok(())
}

/// Resolves the process-manager stop signals into one clean-shutdown path.
///
/// Containers and service managers send SIGTERM; terminals send SIGINT. Both
/// must reach `Node::shutdown` so SQLite checkpoints and a Litestream sidecar
/// can ship the WAL tail before the process exits.
async fn termination_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

/// Builds the one resolver this daemon refreshes membership through, and
/// installs it on the node so control requests use the same one (§3.2, §10.2).
///
/// One per process, not one per request. The resolver holds when it last walked
/// Sigstore's TUF repository, and that state is only persisted on a *successful*
/// walk — so a fresh resolver per control request re-attempts the whole walk at
/// 30 s per file whenever the repository is unreachable, which is exactly what
/// the pre-stamping in `dns.rs` exists to bound to one attempt a day.
///
/// A resolver that cannot be built — a mistyped `--dnssec-anchor` path, an empty
/// anchor file, a malformed DoH URL — means no membership refresh can happen at
/// all: bindings ossify and then lapse a grace window later. With membership
/// domains configured that is a refusal to start, because a daemon that cannot
/// refresh them is a cluster that will partition on a timer, and the one command
/// an operator would run afterwards would otherwise report a healthy node. With
/// none configured there is nothing to refresh, so the daemon runs on static
/// trust and the reason is recorded where `doctor`, `daemon status` and the next
/// `domain set` will say it.
async fn build_resolver(node: &Node) -> Result<Option<std::sync::Arc<synch_net::DnssecResolver>>> {
    let dns = node.config().dns.clone();
    let built = tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        synch_net::DnssecResolver::with_options(&dns)
    })
    .await
    .context("the DNS resolver construction task did not complete")?;
    match built {
        Ok(resolver) => {
            let resolver = std::sync::Arc::new(resolver);
            node.set_dns_resolver(Ok(resolver.clone()));
            Ok(Some(resolver))
        }
        Err(e) => {
            node.set_dns_resolver(Err(e.to_string()));
            let lookup = node.clone();
            let domain = tokio::task::spawn_blocking(move || {
                let _scope = synch_core::BlockingScope::enter();
                lookup.domain()
            })
            .await
            .context("the membership-domain lookup task did not complete")??;
            if let Some(domain) = domain {
                return Err(anyhow::Error::new(e).context(format!(
                    "no DNSSEC resolver could be built, so {domain} would never refresh: \
                     its bindings would lapse a grace window from now, and this node's own \
                     name comes out of it. Fix the resolver options, or `synch domain clear` \
                     to run key-identified on static trust"
                )));
            }
            tracing::warn!(
                error = %e,
                "no DNSSEC resolver available; running on static trust (see `synch doctor`)"
            );
            Ok(None)
        }
    }
}

/// How often the multipart sweeper looks for uploads and payloads to collect.
///
/// Nothing waits on it: everything it collects has already been abandoned for
/// longer than any writer's window, so the cadence only bounds how long the
/// bytes sit, not whether they go.
const UPLOAD_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(900);

/// Collects abandoned multipart uploads until the daemon stops (§9.4).
async fn run_upload_sweeper(node: &Node, shutdown: ShutdownSignal) {
    let shutdown = std::pin::pin!(shutdown);
    let mut shutdown = shutdown;
    loop {
        tokio::select! {
            _ = &mut shutdown => return,
            _ = tokio::time::sleep(UPLOAD_SWEEP_INTERVAL) => {
                let swept = node
                    .sweep_uploads_durable(synch_engine::DEFAULT_UPLOAD_TTL)
                    .await;
                match swept {
                    Ok(0) => {}
                    Ok(collected) => tracing::info!(collected, "swept multipart uploads"),
                    Err(e) => tracing::warn!(error = %e, "multipart upload sweep failed"),
                }
            }
        }
    }
}

/// Spawns one of the engine's standing loops, wired to the stop broadcast.
fn spawn_loop<F, Fut>(
    name: &'static str,
    node: &Node,
    stop: &broadcast::Sender<()>,
    body: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnOnce(Node, ShutdownSignal) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let node = node.clone();
    let mut rx = stop.subscribe();
    tokio::spawn(async move {
        body(
            node,
            Box::pin(async move {
                let _ = rx.recv().await;
            }),
        )
        .await;
        // Reached only on the stop signal: every body loops until told to
        // stop. Saying so at the moment it happens is what distinguishes an
        // orderly end from the panic the join below reports.
        tracing::debug!(loop_name = name, "standing loop stopped");
    })
}

/// The future the engine loops await to know they should stop.
type ShutdownSignal = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
