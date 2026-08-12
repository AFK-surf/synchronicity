//! Command dispatch.
//!
//! Two commands touch the data directory directly: `synch init`, which creates
//! it before any daemon can exist, and `synch daemon run`, which *is* the
//! daemon. Every other command is a control-socket request to a running daemon
//! (§9.1) — there is no in-process fallback.

use std::{
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result};
use synch_core::OriginId;
use synch_engine::{EntryRef, Node, NodeConfig};

use crate::{
    cli::{
        Cli, Command, DaemonCommand, DomainCommand, KeyCommand, MirrorCommand, PinCommand,
        SpaceCommand, TrustCommand,
    },
    control::{proto::Response, transport, Client, Request},
    daemon,
};

/// Resolves the data directory from the CLI flags or the platform default.
pub fn data_dir(cli: &Cli) -> Result<PathBuf> {
    match &cli.data_dir {
        Some(dir) => Ok(dir.clone()),
        None => Ok(synch_engine::default_data_dir()?),
    }
}

/// Builds the node configuration from the CLI flags.
pub fn node_config(cli: &Cli) -> Result<NodeConfig> {
    let mut config = NodeConfig::new(data_dir(cli)?);
    config.net.offline = cli.offline;
    if let Some(bind) = &cli.bind {
        config.net.bind_addr = Some(bind.parse().context("--bind wants HOST:PORT")?);
    } else if cli.offline {
        config.net.bind_addr = Some("127.0.0.1:0".parse().expect("valid loopback address"));
    }
    Ok(config)
}

/// Runs one command.
pub async fn run(cli: Cli) -> Result<()> {
    let data_dir = data_dir(&cli)?;
    match &cli.command {
        Command::Init { id } => {
            let origin = match id {
                Some(id) => Some(OriginId::from_str(id).context("--id wants <name>@<domain>")?),
                None => None,
            };
            // The datadir holds a signing key and the control token: it is the
            // owner's alone from the moment it exists (§9.3).
            transport::harden_data_dir(&data_dir)?;
            let report = Node::init(&data_dir, origin)?;
            println!("origin:     {}", report.origin);
            println!("device key: {}", report.node_id.to_z32());
            println!("data dir:   {}", report.data_dir.display());
            println!("next:       synch daemon run");
            Ok(())
        }
        Command::Daemon {
            command: DaemonCommand::Run,
        } => daemon::run(node_config(&cli)?).await,
        _ => {
            let request = to_request(&cli)?;
            deliver(&data_dir, &cli, request).await
        }
    }
}

/// Translates a parsed command into its control-socket request.
fn to_request(cli: &Cli) -> Result<Request> {
    Ok(match &cli.command {
        Command::Init { .. } => unreachable!("handled before dispatch"),
        Command::Daemon {
            command: DaemonCommand::Run,
        } => unreachable!("handled before dispatch"),
        Command::Daemon {
            command: DaemonCommand::Status,
        } => Request::DaemonStatus,
        Command::Daemon {
            command: DaemonCommand::Stop,
        } => Request::DaemonStop,

        Command::Id => Request::Id,

        Command::Key { command } => match command {
            KeyCommand::Rotate => Request::KeyRotate,
            KeyCommand::Activate { key } => Request::KeyActivate { key: key.clone() },
            KeyCommand::Retire { key } => Request::KeyRetire { key: key.clone() },
            KeyCommand::Ls => Request::KeyLs,
        },

        Command::Trust { command } => match command {
            TrustCommand::Add {
                key,
                name,
                domain,
                note,
                addr,
            } => Request::TrustAdd {
                key: key.clone(),
                name: name.clone(),
                domain: domain.clone(),
                note: note.clone(),
                addr: addr.clone(),
            },
            TrustCommand::Rebind { origin, key } => Request::TrustRebind {
                origin: origin.clone(),
                key: key.clone(),
            },
            TrustCommand::Rm { origin } => Request::TrustRm {
                origin: origin.clone(),
            },
            TrustCommand::Ls => Request::TrustLs,
        },

        Command::Domain { command } => match command {
            DomainCommand::Add { domain } => Request::DomainAdd {
                domain: domain.clone(),
            },
            DomainCommand::Rm { domain } => Request::DomainRm {
                domain: domain.clone(),
            },
            DomainCommand::Ls => Request::DomainLs,
            DomainCommand::Refresh => Request::DomainRefresh,
        },

        Command::Peers => Request::Peers,

        Command::Space { command } => match command {
            // The daemon's working directory is its own; a relative path is
            // resolved against the caller's before it crosses the socket.
            SpaceCommand::Add { id, path } => Request::SpaceAdd {
                id: id.clone(),
                path: absolute(path)?,
            },
            SpaceCommand::Ls => Request::SpaceLs,
            SpaceCommand::Rm { id } => Request::SpaceRm { id: id.clone() },
        },

        Command::Mirror { command } => match command {
            MirrorCommand::Add { reference, path } => Request::MirrorAdd {
                reference: reference.clone(),
                path: absolute(path)?,
            },
            MirrorCommand::Rm { reference } => Request::MirrorRm {
                reference: reference.clone(),
            },
            MirrorCommand::Ls => Request::MirrorLs,
            MirrorCommand::Sync => Request::MirrorSync,
        },

        Command::Pin { command } => match command {
            PinCommand::Add { root } => Request::PinAdd { root: root.clone() },
            PinCommand::Rm { root } => Request::PinRm { root: root.clone() },
            PinCommand::Ls => Request::PinLs,
        },

        Command::Ls { reference, all } => Request::Ls {
            reference: reference.clone(),
            all: *all,
        },
        Command::Status { reference } => Request::Status {
            reference: reference.clone(),
        },
        Command::Cat { reference, range } => Request::Cat {
            reference: reference.clone(),
            range: range.clone(),
        },
        Command::Get { reference, .. } => Request::Get {
            reference: reference.clone(),
        },
        Command::Take { reference } => Request::Take {
            reference: reference.clone(),
        },
        Command::Log { reference } => Request::Log {
            reference: reference.clone(),
        },
        Command::Doctor { rebuild } => Request::Doctor { rebuild: *rebuild },
        Command::Scan => Request::Scan,
    })
}

/// Sends the request and renders the response stream.
async fn deliver(data_dir: &Path, cli: &Cli, request: Request) -> Result<()> {
    let mut client = Client::connect(data_dir).await?;
    client.send(&request).await?;

    // `get` is the one command whose payload lands in a file rather than on
    // stdout, so it needs the destination the caller named.
    if let Command::Get { reference, output } = &cli.command {
        let target = match output {
            Some(path) => path.clone(),
            None => {
                let reference: EntryRef = reference.parse()?;
                PathBuf::from(reference.path.rsplit('/').next().unwrap_or(&reference.path))
            }
        };
        let mut file = std::fs::File::create(&target)
            .with_context(|| format!("could not create {}", target.display()))?;
        let mut written = 0u64;
        while let Some(response) = client.next().await? {
            match response {
                Response::Chunk(bytes) => {
                    file.write_all(&bytes)?;
                    written += bytes.len() as u64;
                }
                Response::Line(text) => println!("{text}"),
                Response::Progress(text) => eprintln!("{text}"),
                Response::Ready | Response::End | Response::Error(_) => {}
            }
        }
        file.flush()?;
        println!("wrote {written} bytes to {}", target.display());
        return Ok(());
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    while let Some(response) = client.next().await? {
        match response {
            Response::Line(text) => {
                writeln!(out, "{text}")?;
            }
            Response::Chunk(bytes) => out.write_all(&bytes)?,
            // Progress is rendered and discarded: it is not the command's
            // output, just what it is doing while producing it.
            Response::Progress(text) => eprintln!("{text}"),
            Response::Ready | Response::End | Response::Error(_) => {}
        }
    }
    out.flush()?;
    Ok(())
}

/// Resolves a path against the caller's working directory.
fn absolute(path: &Path) -> Result<String> {
    let path = std::path::absolute(path)
        .with_context(|| format!("could not resolve {}", path.display()))?;
    Ok(path.to_string_lossy().into_owned())
}
