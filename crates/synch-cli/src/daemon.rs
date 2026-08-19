//! `synch daemon run`: the process that owns the node (§9.1).
//!
//! The daemon holds the one endpoint, the one database writer, and the one
//! lifecycle. It serves the control socket concurrently with the engine's
//! standing work — the anti-entropy scheduler, the scanner, the filesystem
//! watcher, the batching publisher, the mirror loop, and the maintenance/GC
//! pass.

use anyhow::{Context, Result};
use synch_engine::{Node, NodeConfig};
use tokio::sync::broadcast;

use crate::{control::Server, render};

/// Opens the node, binds the control socket, and runs until stopped.
///
/// Stopping happens on `Ctrl-C` or on a `synch daemon stop` request; both fire
/// the same broadcast, which every task shuts down on.
pub async fn run(config: NodeConfig) -> Result<()> {
    // No "(run `synch init` first?)" stapled onto every failure: the
    // uninitialized case already says exactly that itself, and the hint sent
    // an operator with a taken port off to re-init a healthy node.
    let node = Node::open(config)
        .await
        .context("could not open the node")?;
    // Before anything is announced: a daemon that cannot resolve the membership
    // it is configured for has nothing to serve past the current grace window,
    // and finding that out at startup is the difference between a fixable
    // message and a cluster that partitions on a timer.
    let resolver = match build_resolver(&node) {
        Ok(resolver) => resolver,
        Err(e) => {
            let _ = node.shutdown().await;
            return Err(e);
        }
    };
    let (stop_tx, _) = broadcast::channel::<()>(1);
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

    let control = tokio::spawn(server.run());
    let aae = spawn_loop(&node, &stop_tx, |node, shutdown| async move {
        node.run_anti_entropy(shutdown).await
    });
    let scanner = spawn_loop(&node, &stop_tx, |node, shutdown| async move {
        node.run_scanner(shutdown).await
    });
    let watcher = spawn_loop(&node, &stop_tx, |node, shutdown| async move {
        node.run_watcher(shutdown).await
    });
    let maintenance = spawn_loop(&node, &stop_tx, |node, shutdown| async move {
        node.run_maintenance(shutdown).await
    });
    // The standing mirror loop: materializes the unified tree whenever it
    // changes, and once at startup (§7.2).
    let mirrors = spawn_loop(&node, &stop_tx, |node, shutdown| async move {
        node.run_mirrors(shutdown).await
    });
    // Membership is only as live as its last validated lookup: without this
    // loop a DNSSEC cluster dissolves one TTL plus grace after the last manual
    // refresh, because `run_maintenance` expires bindings and nothing renews
    // them (§3.2). It also carries the §3.4 unknown-key trigger.
    let dns_resolver = resolver.clone();
    let dns = spawn_loop(&node, &stop_tx, move |node, shutdown| async move {
        match dns_resolver {
            Some(resolver) => node.run_dns(resolver.as_ref(), shutdown).await,
            None => shutdown.await,
        }
    });
    // The outbound tunnel to the control plane the membership zone names — on
    // by default, and a settings read per interval once opted out.
    // It shares this process's node, database handle and resolver by
    // construction, because it *is* the daemon (§9.1).
    let cloud_resolver = resolver.clone();
    let cloud = spawn_loop(&node, &stop_tx, move |node, shutdown| async move {
        node.run_cloud(cloud_resolver, shutdown).await
    });
    // What turns the scanner's and the watcher's staged changes into heads: one
    // batch per quiet period or per 1000 entries, whichever comes first (§7.1).
    let publisher = spawn_loop(&node, &stop_tx, |node, shutdown| async move {
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
    let _ = tokio::join!(
        control,
        aae,
        scanner,
        watcher,
        maintenance,
        publisher,
        dns,
        mirrors,
        cloud
    );
    node.shutdown().await?;
    Ok(())
}

/// Waits for the daemon to be told to stop: `Ctrl-C`, or a `synch daemon stop`
/// request landing on the control socket.
///
/// `Ctrl-C` fires the same broadcast a control request does, so both paths shut
/// every task down the one way.
async fn wait_for_stop(
    stop_tx: &broadcast::Sender<()>,
    stopped: &mut broadcast::Receiver<()>,
) -> Result<()> {
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal?;
            println!("shutting down");
            let _ = stop_tx.send(());
        }
        _ = stopped.recv() => {}
    }
    Ok(())
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
/// `domain add` will say it.
fn build_resolver(node: &Node) -> Result<Option<std::sync::Arc<synch_net::DnssecResolver>>> {
    match synch_net::DnssecResolver::with_options(&node.config().dns) {
        Ok(resolver) => {
            let resolver = std::sync::Arc::new(resolver);
            node.set_dns_resolver(Ok(resolver.clone()));
            Ok(Some(resolver))
        }
        Err(e) => {
            node.set_dns_resolver(Err(e.to_string()));
            let domains = node.domains()?;
            if !domains.is_empty() {
                return Err(anyhow::Error::new(e).context(format!(
                    "no DNSSEC resolver could be built, so the {} configured membership \
                     domain(s) ({}) would never refresh and their bindings would lapse a \
                     grace window from now. Fix the resolver options, or \
                     `synch domain rm` them to run on static trust",
                    domains.len(),
                    domains.join(", ")
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

/// Spawns one of the engine's standing loops, wired to the stop broadcast.
fn spawn_loop<F, Fut>(
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
        .await
    })
}

/// The future the engine loops await to know they should stop.
type ShutdownSignal = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
