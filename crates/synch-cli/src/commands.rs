//! Command dispatch.
//!
//! Three commands touch the data directory directly: `synch init`, which creates
//! it before any daemon can exist; `synch id set`, which names a key-identified
//! node while the daemon is stopped; and `synch daemon run`, which *is* the
//! daemon. Every other command is a control-service call to a running daemon
//! (§9.1) — there is no in-process fallback.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use synch_engine::{EntryRef, Node, NodeConfig};

use crate::{
    cli::{
        Cli, CloudCommand, Command, DaemonCommand, DomainCommand, KeyCommand, MirrorCommand,
        PinCommand, SpaceCommand, TrustCommand,
    },
    control::{proto::pb, transport, Client, Command as Cmd, Frame},
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
    config.net.relay_urls = cli.relay.clone();
    config.net.discovery_url = cli.discovery.clone();
    config.net.dht = cli.dht;
    config.net.dht_bootstrap = cli.dht_bootstrap.clone();
    config.net.dht_publish_direct_addrs = cli.dht_publish_addrs;
    config.dns.doh_url = cli.doh.clone();
    config.dns.trust_anchor = cli.dnssec_anchor.clone();
    config.dns.rekor = cli.rekor.map(Into::into);
    config.dns.rekor_key = cli.rekor_key.clone();
    config.dns.tuf_url = cli.tuf.clone();
    config.dns.no_tuf = cli.no_tuf;
    // Where the TUF-verified transparency-log pin set lives
    // (docs/REKOR-ZONE-KEY.md §10.2). One file for the whole data directory,
    // never one per domain: monotonicity is what bounds a hostile mirror, and
    // it only bounds anything if every domain shares the same floor.
    config.dns.rekor_state = Some(config.data_dir.join(REKOR_PIN_STATE_FILE));
    Ok(config)
}

/// The pin-state file inside the data directory (§10.2).
pub const REKOR_PIN_STATE_FILE: &str = "rekor-pins.json";

/// Runs one command.
pub async fn run(cli: Cli) -> Result<()> {
    let data_dir = data_dir(&cli)?;
    match &cli.command {
        Command::Init { domain } => {
            let domain = domain.clone();
            // Refuse a data dir whose control socket could never be bound —
            // finding out one command later, from the kernel, in acronyms,
            // is how a newcomer gives up.
            transport::check_socket_path(&data_dir)?;
            // The datadir holds a signing key and the control token: it is the
            // owner's alone from the moment it exists (§9.3).
            transport::harden_data_dir(&data_dir)?;
            // Creating the store runs the migration chain and fsyncs a new
            // database, which is blocking work on the multi-thread runtime this
            // binary starts (§10).
            let dir = data_dir.clone();
            let report = tokio::task::spawn_blocking(move || {
                let _scope = synch_core::BlockingScope::enter();
                Node::init(&dir, domain.as_deref())
            })
            .await
            .context("the initializing task did not complete")??;
            println!("device key: {}", report.node_id.to_z32());
            println!("data dir:   {}", report.data_dir.display());
            match (&report.origin, &report.domain) {
                (Some(origin), _) => {
                    println!("origin:     {origin}");
                    println!("next:       synch daemon run");
                }
                (None, Some(domain)) => {
                    // The record is the next step, and printing it is the
                    // difference between one copy-paste and a trip to the docs.
                    println!("domain:     {domain}");
                    println!("next:       publish this record, then `synch daemon run`:");
                    println!(
                        "  _synchronicity.{domain}. IN TXT \"v=sync1 id=<name> nk={} apex=<apex>\"",
                        report.node_id.to_z32()
                    );
                }
                (None, None) => unreachable!("init settles a name or a domain"),
            }
            Ok(())
        }
        Command::Daemon {
            command: DaemonCommand::Run,
        } => daemon::run(node_config(&cli)?).await,
        _ => {
            let command = to_command(&cli)?;
            deliver(&data_dir, &cli, command).await
        }
    }
}

/// Translates a parsed command into the one the control service takes.
fn to_command(cli: &Cli) -> Result<Cmd> {
    Ok(match &cli.command {
        Command::Init { .. } => unreachable!("handled before dispatch"),
        Command::Daemon {
            command: DaemonCommand::Run,
        } => unreachable!("handled before dispatch"),
        Command::Daemon {
            command: DaemonCommand::Status,
        } => Cmd::DaemonStatus(pb::DaemonStatus {}),
        Command::Daemon {
            command: DaemonCommand::Stop,
        } => Cmd::DaemonStop(pb::DaemonStop {}),

        Command::Id => Cmd::Id(pb::Id {}),

        Command::Key { command } => match command {
            KeyCommand::Rotate => Cmd::KeyRotate(pb::KeyRotate {}),
            // The global --bind names the new endpoint's address; every other
            // command ignores it, and `daemon run` never reaches here.
            KeyCommand::Activate { key } => Cmd::KeyActivate(pb::KeyActivate {
                key: key.clone(),
                bind: cli.bind.clone(),
            }),
            KeyCommand::Retire { key } => Cmd::KeyRetire(pb::KeyRetire { key: key.clone() }),
            KeyCommand::Ls => Cmd::KeyLs(pb::KeyLs {}),
        },

        Command::Trust { command } => match command {
            TrustCommand::Add { key, note, addr } => Cmd::TrustAdd(pb::TrustAdd {
                key: key.clone(),
                note: note.clone(),
                addr: addr.clone(),
            }),
            TrustCommand::Rm { origin, key } => Cmd::TrustRm(pb::TrustRm {
                origin: origin.clone(),
                key: key.clone(),
            }),
            TrustCommand::Ls => Cmd::TrustLs(pb::TrustLs {}),
        },

        Command::Domain { command } => match command {
            DomainCommand::Set { domain } => Cmd::DomainSet(pb::DomainSet {
                domain: domain.clone(),
            }),
            DomainCommand::Clear => Cmd::DomainClear(pb::DomainClear {}),
            DomainCommand::Ls => Cmd::DomainLs(pb::DomainLs {}),
            DomainCommand::Refresh => Cmd::DomainRefresh(pb::DomainRefresh {}),
        },

        Command::Peers => Cmd::Peers(pb::Peers {}),
        Command::Sync => Cmd::SyncNow(pb::SyncNow {}),

        Command::Space { command } => match command {
            // The daemon's working directory is its own; a relative path is
            // resolved against the caller's before it crosses the socket.
            SpaceCommand::Add { id, path } => Cmd::SpaceAdd(pb::SpaceAdd {
                id: id.clone(),
                path: absolute(path)?,
            }),
            SpaceCommand::Ls => Cmd::SpaceLs(pb::SpaceLs {}),
            SpaceCommand::Rm { id } => Cmd::SpaceRm(pb::SpaceRm { id: id.clone() }),
        },

        Command::Mirror { command } => match command {
            MirrorCommand::Add {
                space,
                path,
                policy,
            } => Cmd::MirrorAdd(pb::MirrorAdd {
                space: space.clone(),
                path: absolute(path)?,
                policy: policy.clone(),
            }),
            MirrorCommand::Rm { path } => Cmd::MirrorRm(pb::MirrorRm {
                path: absolute(path)?,
            }),
            MirrorCommand::Ls => Cmd::MirrorLs(pb::MirrorLs {}),
            MirrorCommand::Sync => Cmd::MirrorSync(pb::MirrorSync {}),
        },

        Command::Pin { command } => match command {
            PinCommand::Add { target } => Cmd::PinAdd(pb::PinAdd {
                target: target.clone(),
            }),
            PinCommand::Rm { target } => Cmd::PinRm(pb::PinRm {
                target: target.clone(),
            }),
            PinCommand::Ls => Cmd::PinLs(pb::PinLs {}),
        },

        Command::Ls { reference, all } => Cmd::Ls(pb::Ls {
            reference: reference.clone(),
            all: *all,
        }),
        Command::Status { reference } => Cmd::Status(pb::Status {
            reference: reference.clone(),
        }),
        Command::Cat {
            reference,
            range,
            from,
            strict,
        } => Cmd::Cat(pb::Cat {
            reference: reference.clone(),
            range: range.clone(),
            from: from.clone(),
            strict: *strict,
        }),
        Command::Get {
            reference,
            from,
            strict,
            ..
        } => Cmd::Get(pb::Get {
            reference: reference.clone(),
            from: from.clone(),
            strict: *strict,
        }),
        Command::Take { reference } => Cmd::Take(pb::Take {
            reference: reference.clone(),
        }),
        Command::Log { reference } => Cmd::Log(pb::Log {
            reference: reference.clone(),
        }),
        Command::Compare {
            reference,
            to,
            from,
            json,
        } => Cmd::Compare(pb::Compare {
            reference: reference.clone(),
            from: from.clone(),
            to: to.clone(),
            json: *json,
        }),
        Command::Recover { wait, gap } => {
            // Parsed here as well as on the daemon, so a typo fails before a
            // connection is made rather than an hour into a quiesce.
            if let Some(wait) = wait {
                crate::cli::parse_duration(wait).context("--wait")?;
            }
            Cmd::Recover(pb::Recover {
                wait: wait.clone(),
                gap: *gap,
            })
        }
        Command::Doctor { rebuild } => Cmd::Doctor(pb::Doctor { rebuild: *rebuild }),
        Command::Scan => Cmd::Scan(pb::Scan {}),

        Command::Cloud { command } => match command {
            CloudCommand::Enable => Cmd::CloudEnable(pb::CloudEnable {}),
            CloudCommand::Disable => Cmd::CloudDisable(pb::CloudDisable {}),
            CloudCommand::Status => Cmd::CloudStatus(pb::CloudStatus {}),
        },
    })
}

/// Sends the command and renders its output.
async fn deliver(data_dir: &Path, cli: &Cli, command: Cmd) -> Result<()> {
    let mut client = Client::connect(data_dir).await?;
    let mut frames = client.run(command).await?;

    // `get` is the one command whose payload lands in a file rather than on
    // stdout, so it needs the destination the caller named.
    if let Command::Get {
        reference, output, ..
    } = &cli.command
    {
        let target = match output {
            Some(path) => path.clone(),
            None => {
                let reference: EntryRef = reference.parse()?;
                PathBuf::from(reference.path.rsplit('/').next().unwrap_or(&reference.path))
            }
        };
        // The destination is created when the first byte arrives, so a read
        // that fails — an unknown path, no provider — leaves whatever was
        // there alone instead of truncating it.
        let mut file: Option<std::fs::File> = None;
        let mut written = 0u64;
        while let Some(frame) = frames.next().await? {
            match frame {
                Frame::Chunk(bytes) => {
                    let file = match &mut file {
                        Some(file) => file,
                        None => file.insert(create(&target)?),
                    };
                    file.write_all(&bytes)?;
                    written += bytes.len() as u64;
                }
                Frame::Line(text) => println!("{text}"),
                Frame::Progress(text) => eprintln!("{text}"),
            }
        }
        // An empty entry is still an entry: it arrives as no chunks at all.
        let mut file = match file {
            Some(file) => file,
            None => create(&target)?,
        };
        file.flush()?;
        println!("wrote {written} bytes to {}", target.display());
        return Ok(());
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    while let Some(frame) = frames.next().await? {
        match frame {
            Frame::Line(text) => {
                writeln!(out, "{text}")?;
            }
            Frame::Chunk(bytes) => out.write_all(&bytes)?,
            // Progress is rendered and discarded: it is not the command's
            // output, just what it is doing while producing it.
            Frame::Progress(text) => eprintln!("{text}"),
        }
    }
    out.flush()?;
    Ok(())
}

/// Creates the destination file `synch get` writes to.
fn create(target: &Path) -> Result<std::fs::File> {
    std::fs::File::create(target).with_context(|| format!("could not create {}", target.display()))
}

/// Resolves a path against the caller's working directory.
fn absolute(path: &Path) -> Result<String> {
    let path = std::path::absolute(path)
        .with_context(|| format!("could not resolve {}", path.display()))?;
    Ok(path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn command_for(args: &[&str]) -> Result<Cmd> {
        to_command(&Cli::parse_from(args))
    }

    /// The key is the identity: there is no flag that names a peer, because a
    /// name belongs to the zone that issues it (§3.2).
    #[test]
    fn trust_add_takes_a_key_and_nothing_that_names_it() {
        let command =
            command_for(&["synch", "trust", "add", "abc", "--note", "zeynep's laptop"]).unwrap();
        assert_eq!(
            command,
            Cmd::TrustAdd(pb::TrustAdd {
                key: "abc".into(),
                note: Some("zeynep's laptop".into()),
                addr: None,
            })
        );
        // The flags that used to attach a name are not arguments at all now:
        // clap refuses them before anything reaches the daemon.
        assert!(Cli::try_parse_from(["synch", "trust", "add", "abc", "--as", "nas"]).is_err());
        assert!(Cli::try_parse_from(["synch", "trust", "rebind", "nas", "abc"]).is_err());
    }

    #[test]
    fn the_dht_flags_reach_the_endpoint() {
        let config = node_config(&Cli::parse_from([
            "synch",
            "--data-dir",
            "/tmp/synch-test",
            "--dht",
            "--dht-bootstrap",
            "boot.example:6881",
            "--dht-publish-addrs",
            "daemon",
            "run",
        ]))
        .unwrap();
        assert!(config.net.dht);
        assert_eq!(config.net.dht_bootstrap, ["boot.example:6881"]);
        assert!(config.net.dht_publish_direct_addrs);

        let config = node_config(&Cli::parse_from([
            "synch",
            "--data-dir",
            "/tmp/synch-test",
            "daemon",
            "run",
        ]))
        .unwrap();
        assert!(!config.net.dht);
    }
}
