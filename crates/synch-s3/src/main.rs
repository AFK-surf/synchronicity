//! `synch-s3` — an S3-compatible gateway onto a synchronicity cluster (§9.4).
//!
//! A thin argument-parsing shell over the gateway library. Every subcommand,
//! `bucket add` and `key add` included, is a control-service call to a
//! running daemon: this process opens no database and binds no endpoint, so the
//! daemon remains the only writer and the only endpoint (§9.1).

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use synch_s3::{
    auth::{self, AccessKey, AuthMode},
    buckets,
    daemon::Daemon,
    is_loopback, Gateway,
};

/// An S3-compatible gateway onto a synchronicity cluster.
#[derive(Debug, Parser)]
#[command(name = "synch-s3", version, about, long_about = None)]
struct Cli {
    /// The node's data directory. Defaults to the platform data directory.
    #[arg(long, global = true, env = "SYNCH_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the S3 API.
    Serve {
        /// The address to bind.
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: SocketAddr,
        /// Skip client authentication entirely. Only legal on loopback.
        #[arg(long)]
        anonymous: bool,
    },
    /// Map buckets onto cluster views.
    Bucket {
        #[command(subcommand)]
        command: BucketCommand,
    },
    /// Manage static access keys.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum BucketCommand {
    /// Map a bucket onto a space of the unified tree.
    Add {
        /// The bucket name.
        bucket: String,
        /// The space, or `<origin>:<space>` as shorthand for an origin pin.
        reference: String,
        /// Which version of each key reads serve: `newest` (default),
        /// `origin=<id>`, or `strict`.
        #[arg(long)]
        policy: Option<String>,
    },
    /// Remove a bucket mapping.
    Rm {
        /// The bucket name.
        bucket: String,
    },
    /// List bucket mappings.
    Ls,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Add or replace a static access key.
    Add {
        /// The access key id.
        id: String,
        /// The secret access key.
        secret: String,
    },
    /// Remove an access key.
    Rm {
        /// The access key id.
        id: String,
    },
    /// List access key ids.
    Ls,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Before anything builds a TLS client: reqwest, built without a baked-in
    // provider, refuses to construct a `Client` until one is installed.
    synch_net::tls::install_ring_provider();
    let args = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SYNCH_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = run(args).await {
        // A reader that hung up early (`bucket ls | head`) surfaces as a
        // broken-pipe write error: the reader saying "enough", not a failure.
        let reader_hung_up = e.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
        });
        if reader_hung_up {
            std::process::exit(0);
        }
        eprintln!("synch-s3: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn run(args: Cli) -> Result<()> {
    let data_dir = match args.data_dir {
        Some(dir) => dir,
        None => synch_cli::default_data_dir()?,
    };
    // Nothing is opened here — only the control token is read, and only when
    // the first request is sent. With no daemon running, that request fails
    // with a message naming the socket and `synch daemon run` (§9.1).
    let daemon = Daemon::new(data_dir);
    dispatch(&daemon, args.command).await
}

async fn dispatch(daemon: &Daemon, command: Command) -> Result<()> {
    match command {
        Command::Bucket { command } => match command {
            BucketCommand::Add {
                bucket,
                reference,
                policy,
            } => {
                let bucket = buckets::add(daemon, &bucket, &reference, policy.as_deref()).await?;
                println!("{} -> {} ({})", bucket.name, bucket.space, bucket.policy);
                if let Some(warning) = bucket.foreign_pin_warning(&daemon.origin().await?) {
                    println!("warning: {warning}");
                }
                // Mapping a bucket before its space first syncs is legal;
                // mapping one onto a typo would otherwise look the same.
                if !daemon.space_known(&bucket.space).await? {
                    println!(
                        "warning: no origin publishes {} yet; the bucket serves nothing until one does",
                        bucket.space
                    );
                }
            }
            BucketCommand::Rm { bucket } => {
                if !buckets::remove(daemon, &bucket).await? {
                    bail!("no bucket named {bucket}");
                }
                println!("removed {bucket}");
            }
            BucketCommand::Ls => {
                let buckets = buckets::load(daemon).await?;
                if buckets.is_empty() {
                    eprintln!("(no buckets mapped; add one with `synch-s3 bucket add`)");
                }
                for bucket in buckets {
                    println!("{:<24} {:<20} {}", bucket.name, bucket.space, bucket.policy);
                }
            }
        },
        Command::Key { command } => match command {
            KeyCommand::Add { id, secret } => {
                auth::put_key(
                    daemon,
                    &AccessKey {
                        id: id.clone(),
                        secret,
                    },
                )
                .await?;
                println!("added access key {id}");
            }
            KeyCommand::Rm { id } => {
                if !auth::remove_key(daemon, &id).await? {
                    bail!("no access key {id}");
                }
                println!("removed {id}");
            }
            KeyCommand::Ls => {
                let keys = auth::load_keys(daemon).await?;
                if keys.is_empty() {
                    eprintln!("(no access keys; the gateway will refuse to serve without one)");
                }
                for key in keys {
                    println!("{}", key.id);
                }
            }
        },
        Command::Serve { listen, anonymous } => {
            let auth = if anonymous {
                // §9.4: `--anonymous` is for localhost-only development. Binding
                // it to a routable address would expose the whole cluster's
                // content to anyone who can reach the port.
                if !is_loopback(&listen) {
                    bail!(
                        "--anonymous requires a loopback listen address, got {listen}; \
                         configure access keys with `synch-s3 key add` instead"
                    );
                }
                AuthMode::Anonymous
            } else {
                // Read once, at startup: a gateway that re-read the key list per
                // request would put a socket round trip in front of every
                // signature check. Adding a key therefore takes a restart.
                let keys = auth::load_keys(daemon).await?;
                if keys.is_empty() {
                    bail!(
                        "no access keys configured; add one with `synch-s3 key add <id> <secret>` \
                         or use --anonymous on loopback"
                    );
                }
                AuthMode::SigV4(keys)
            };

            let gateway = Gateway::new(daemon.clone(), auth).await?;
            let listener = tokio::net::TcpListener::bind(listen).await?;
            let bound = listener.local_addr()?;
            println!("synch-s3 listening on http://{bound}");
            println!(
                "  serving {} through the daemon at {}",
                gateway.origin(),
                daemon.data_dir().display()
            );
            for bucket in buckets::load(daemon).await? {
                println!("  {} -> {} ({})", bucket.name, bucket.space, bucket.policy);
                if let Some(warning) = bucket.foreign_pin_warning(gateway.origin()) {
                    tracing::warn!("{warning}");
                    println!("  warning: {warning}");
                }
            }
            axum::serve(listener, gateway.router())
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
    }
    Ok(())
}
