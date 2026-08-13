//! `synch-s3` — an S3-compatible gateway onto a synchronicity cluster (§9.4).
//!
//! A thin argument-parsing shell over the gateway library and `synch-engine`.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use synch_engine::{Node, NodeConfig};
use synch_s3::{
    auth::{self, AccessKey, AuthMode},
    buckets, is_loopback, Gateway,
};

/// An S3-compatible gateway onto a synchronicity cluster.
#[derive(Debug, Parser)]
#[command(name = "synch-s3", version, about, long_about = None)]
struct Cli {
    /// The node's data directory. Defaults to the platform data directory.
    #[arg(long, global = true, env = "SYNCH_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Disable relays and address discovery on the embedded node.
    #[arg(long, global = true)]
    offline: bool,

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
    let args = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SYNCH_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = run(args).await {
        eprintln!("synch-s3: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn run(args: Cli) -> Result<()> {
    let data_dir = match args.data_dir {
        Some(dir) => dir,
        None => synch_engine::default_data_dir()?,
    };
    let mut config = NodeConfig::new(data_dir);
    config.net.offline = args.offline;
    if args.offline {
        config.net.bind_addr = Some("127.0.0.1:0".parse().expect("valid loopback address"));
    }
    let node = Node::open(config)
        .await
        .context("could not open the node (run `synch init` first?)")?;

    let result = dispatch(&node, args.command).await;
    node.shutdown().await?;
    result
}

async fn dispatch(node: &Node, command: Command) -> Result<()> {
    match command {
        Command::Bucket { command } => match command {
            BucketCommand::Add {
                bucket,
                reference,
                policy,
            } => {
                let bucket = buckets::add(node, &bucket, &reference, policy.as_deref())?;
                println!("{} -> {} ({})", bucket.name, bucket.space, bucket.policy);
                if let Some(warning) = bucket.foreign_pin_warning(node) {
                    println!("warning: {warning}");
                }
            }
            BucketCommand::Rm { bucket } => {
                if buckets::remove(node, &bucket)? {
                    println!("removed {bucket}");
                } else {
                    println!("no such bucket");
                }
            }
            BucketCommand::Ls => {
                for bucket in buckets::load(node)? {
                    println!("{:<24} {:<20} {}", bucket.name, bucket.space, bucket.policy);
                }
            }
        },
        Command::Key { command } => match command {
            KeyCommand::Add { id, secret } => {
                auth::put_key(
                    node,
                    AccessKey {
                        id: id.clone(),
                        secret,
                    },
                )?;
                println!("added access key {id}");
            }
            KeyCommand::Rm { id } => {
                if auth::remove_key(node, &id)? {
                    println!("removed {id}");
                } else {
                    println!("no such access key");
                }
            }
            KeyCommand::Ls => {
                for key in auth::load_keys(node)? {
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
                let keys = auth::load_keys(node)?;
                if keys.is_empty() {
                    bail!(
                        "no access keys configured; add one with `synch-s3 key add <id> <secret>` \
                         or use --anonymous on loopback"
                    );
                }
                AuthMode::SigV4(keys)
            };

            let gateway = Gateway::new(node.clone(), auth);
            let listener = tokio::net::TcpListener::bind(listen).await?;
            let bound = listener.local_addr()?;
            println!("synch-s3 listening on http://{bound}");
            for bucket in buckets::load(node)? {
                println!("  {} -> {} ({})", bucket.name, bucket.space, bucket.policy);
                if let Some(warning) = bucket.foreign_pin_warning(node) {
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
