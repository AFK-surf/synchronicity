//! `synch` — the synchronicity daemon and the CLI that drives it (§9.1).
//!
//! A thin argument-parsing shell over [`synch_cli`]: parse, dispatch, render
//! the failure as an exit status.

use clap::Parser;
use synch_cli::{cli::Cli, commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Before anything builds a TLS client: reqwest, built without a baked-in
    // provider, refuses to construct a `Client` until one is installed.
    synch_net::tls::install_ring_provider();
    let args = Cli::parse();
    let default = if args.verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SYNCH_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default)),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = commands::run(args).await {
        // Rust starts processes with SIGPIPE ignored, so a reader that hung
        // up early (`synch ls | head`) surfaces as a broken-pipe write error.
        // That is the reader saying "enough", not a failure to report.
        let reader_hung_up = e.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
        });
        if reader_hung_up {
            std::process::exit(0);
        }
        eprintln!("synch: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}
