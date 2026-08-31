//! `synch-dp` — the cloud data plane (`docs/CLOUD-DATAPLANE.md`).
//!
//! One process, one shard, many tenants. Configuration comes from the
//! environment, because that is what a pod is configured with, and nothing is
//! read from disk: the disk is ephemeral and a configuration that outlived a
//! reschedule would be a lie.

use std::sync::Arc;

use synch_dp::config::DpConfig;
use synch_dp::control::ControlPlane;
use synch_dp::metrics::Metrics;
use synch_dp::reconciler::Reconciler;
use synch_dp::store::ObjectStore;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SYNCH_DP_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Every TLS client in this workspace standardizes on one provider, chosen
    // in exactly one place per binary (`synch_net::tls`).
    synch_net::tls::install_crypto_provider();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        // Every store touch of every tenant crosses this pool, serialized per
        // tenant by that tenant's one connection (§7.1). Sized for the shard's
        // tenant capacity rather than left at the default.
        .max_blocking_threads(blocking_threads())
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "could not start the runtime");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "the data plane stopped");
            std::process::ExitCode::FAILURE
        }
    }
}

/// How many blocking threads the shared pool gets.
fn blocking_threads() -> usize {
    std::env::var("SYNCH_DP_BLOCKING_THREADS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(512)
}

async fn run() -> synch_dp::Result<()> {
    let config = DpConfig::from_env()?;
    tracing::info!(
        shard = config.shard,
        shards = config.shards,
        base_dir = %config.base_dir.display(),
        "cloud data plane starting"
    );
    // Before anything provisions: a backend that cannot carry database
    // streams is a shard that would lose every identity it creates (§5.3).
    config.check_db_replication()?;
    let objects = ObjectStore::new(config.objects.operator()?);
    let control = ControlPlane::new(&config.control_url, &config.token)?;
    let metrics = Arc::new(Metrics::default());

    // One resolver for the whole process: it holds the TUF/Rekor pin-walk
    // state, so a Sigstore outage costs one attempt a day rather than one per
    // tenant (§7.1). Tenants that cannot resolve simply do not identify, which
    // the supervisor already treats as "wait", so a failure here is a warning
    // rather than a refusal to start.
    let resolver = match build_resolver(config.dns.clone()).await {
        Ok(resolver) => Some(resolver),
        Err(error) => {
            tracing::error!(%error, "no DNSSEC resolver; tenants will not identify");
            None
        }
    };

    let (shutdown, _) = tokio::sync::broadcast::channel(1);
    if let Some(addr) = config.metrics_addr.clone() {
        serve_metrics(addr, metrics.clone(), shutdown.subscribe());
    }

    let reconciler = Reconciler::new(config, control, objects, resolver, metrics);
    let running = tokio::spawn(reconciler.run(shutdown.subscribe()));

    // SIGTERM is treated exactly as SIGINT, so a pod eviction gets the same
    // orderly drain a Ctrl-C does — which is what ships the last WAL tail
    // (§4.6).
    wait_for_signal().await;
    tracing::info!("draining tenants");
    let _ = shutdown.send(());
    if let Err(error) = running.await {
        tracing::error!(%error, "the reconciler did not stop cleanly");
    }
    Ok(())
}

/// Builds the shared DNSSEC resolver.
async fn build_resolver(
    options: synch_net::ResolverOptions,
) -> synch_dp::Result<Arc<synch_net::DnssecResolver>> {
    let built = tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        synch_net::DnssecResolver::with_options(&options)
    })
    .await
    .map_err(|error| synch_dp::DpError::Config(error.to_string()))?;
    built
        .map(Arc::new)
        .map_err(|error| synch_dp::DpError::Config(error.to_string()))
}

/// Serves the exposition on `addr` until shutdown.
fn serve_metrics(
    addr: String,
    metrics: Arc<Metrics>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/metrics",
            axum::routing::get(move || {
                let metrics = metrics.clone();
                async move { metrics.render() }
            }),
        );
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => listener,
            Err(error) => {
                tracing::error!(%addr, %error, "could not bind the metrics listener");
                return;
            }
        };
        tracing::info!(%addr, "serving metrics");
        let served = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown.recv().await;
        });
        if let Err(error) = served.await {
            tracing::warn!(%error, "the metrics server stopped");
        }
    });
}

/// Waits for SIGTERM or SIGINT.
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::error!(%error, "could not listen for SIGTERM");
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
