//! `synch` — the synchronicity daemon and the CLI that drives it (§9.1).
//!
//! A thin argument-parsing shell over [`synch_cli`]: parse, dispatch, render
//! the failure as an exit status.

use clap::Parser;
use synch_cli::{cli::Cli, commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        eprintln!("synch: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}
