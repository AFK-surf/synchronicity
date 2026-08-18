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
    let dns = spawn_loop(&node, &stop_tx, |node, shutdown| async move {
        match synch_net::DnssecResolver::with_options(&node.config().dns) {
            Ok(resolver) => node.run_dns(&resolver, shutdown).await,
            Err(e) => {
                tracing::warn!(error = %e, "no DNSSEC resolver available; membership will not refresh");
                shutdown.await
            }
        }
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
        mirrors
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
