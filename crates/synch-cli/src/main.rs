//! `synch` — the synchronicity CLI and daemon (§9.1).
//!
//! A thin argument-parsing shell over `synch-engine`: every command here is a
//! few lines of dispatch and formatting over the embeddable node API.
#![deny(missing_docs)]

mod cli;
mod commands;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Cli::parse();
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
