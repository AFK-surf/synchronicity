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
    str::FromStr,
};

use anyhow::{Context, Result};
use synch_core::OriginId;
use synch_engine::{EntryRef, Node, NodeConfig};

use crate::{
    cli::{
        Cli, Command, DaemonCommand, DomainCommand, IdCommand, KeyCommand, MirrorCommand,
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
        Command::Init { id } => {
            let origin = match id {
                Some(id) => Some(OriginId::from_str(id).context("--id wants <name>@<domain>")?),
                None => None,
            };
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
                Node::init(&dir, origin)
            })
            .await
            .context("the initializing task did not complete")??;
            println!("origin:     {}", report.origin);
            println!("device key: {}", report.node_id.to_z32());
            println!("data dir:   {}", report.data_dir.display());
            println!("next:       synch daemon run");
            Ok(())
        }
        Command::Id {
            command: Some(IdCommand::Set { id }),
        } => {
            let origin = OriginId::from_str(id).context("id set wants <name>@<domain>")?;
            if Client::connect(&data_dir).await.is_ok() {
                anyhow::bail!(
                    "a daemon is running for {}; stop it first with `synch daemon stop`                      so it does not keep signing as the old origin",
                    data_dir.display()
                );
            }
            let dir = data_dir.clone();
            let report = tokio::task::spawn_blocking(move || {
                let _scope = synch_core::BlockingScope::enter();
                Node::adopt_named_origin(&dir, origin)
            })
            .await
            .context("the renaming task did not complete")??;
            println!("origin:     {}  (was {})", report.origin, report.previous);
            println!("device key: {}", report.node_id.to_z32());
            println!("next:       synch daemon run && synch scan");
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
        Command::Id {
            command: Some(IdCommand::Set { .. }),
        } => unreachable!("handled before dispatch"),
        Command::Daemon {
            command: DaemonCommand::Run,
        } => unreachable!("handled before dispatch"),
        Command::Daemon {
            command: DaemonCommand::Status,
        } => Cmd::DaemonStatus(pb::DaemonStatus {}),
        Command::Daemon {
            command: DaemonCommand::Stop,
        } => Cmd::DaemonStop(pb::DaemonStop {}),

        Command::Id { command: None } => Cmd::Id(pb::Id {}),

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
            TrustCommand::Add {
                key,
                name,
                domain,
                note,
                addr,
            } => {
                // Origins are spelled name@domain everywhere else, so
                // `--as nas@cluster.example` means what it says: the name and
                // the domain, in the one token the user already knows.
                let (name, domain) = match name.as_deref().and_then(|n| n.split_once('@')) {
                    Some((n, d)) => {
                        if domain.as_deref().is_some_and(|given| given != d) {
                            anyhow::bail!(
                                "--as names domain {d} but --domain says {}: drop one",
                                domain.as_deref().unwrap_or_default()
                            );
                        }
                        (Some(n.to_string()), Some(d.to_string()))
                    }
                    None => (name.clone(), domain.clone()),
                };
                Cmd::TrustAdd(pb::TrustAdd {
                    key: key.clone(),
                    name,
                    domain,
                    note: note.clone(),
                    addr: addr.clone(),
                })
            }
            TrustCommand::Rebind { origin, key } => Cmd::TrustRebind(pb::TrustRebind {
                origin: origin.clone(),
                key: key.clone(),
            }),
            TrustCommand::Rm { origin, key } => Cmd::TrustRm(pb::TrustRm {
                origin: origin.clone(),
                key: key.clone(),
            }),
            TrustCommand::Ls => Cmd::TrustLs(pb::TrustLs {}),
        },

        Command::Domain { command } => match command {
            DomainCommand::Add { domain } => Cmd::DomainAdd(pb::DomainAdd {
                domain: domain.clone(),
            }),
            DomainCommand::Rm { domain } => Cmd::DomainRm(pb::DomainRm {
                domain: domain.clone(),
            }),
            DomainCommand::Ls => Cmd::DomainLs(pb::DomainLs {}),
            DomainCommand::Refresh { domain } => Cmd::DomainRefresh(pb::DomainRefresh {
                domain: domain.clone(),
            }),
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

    /// Origins are spelled `name@domain` everywhere else, so `--as` takes
    /// that form too and splits it, rather than bouncing it off the
    /// member-label regex.
    #[test]
    fn trust_add_accepts_the_origin_form() {
        let command = command_for(&[
            "synch",
            "trust",
            "add",
            "abc",
            "--as",
            "nas@cluster.example.com",
        ])
        .unwrap();
        assert_eq!(
            command,
            Cmd::TrustAdd(pb::TrustAdd {
                key: "abc".into(),
                name: Some("nas".into()),
                domain: Some("cluster.example.com".into()),
                note: None,
                addr: None,
            })
        );

        // A bare label with a separate --domain is unchanged.
        let command = command_for(&[
            "synch",
            "trust",
            "add",
            "abc",
            "--as",
            "nas",
            "--domain",
            "x.example",
        ])
        .unwrap();
        assert_eq!(
            command,
            Cmd::TrustAdd(pb::TrustAdd {
                key: "abc".into(),
                name: Some("nas".into()),
                domain: Some("x.example".into()),
                note: None,
                addr: None,
            })
        );

        // Two domains that disagree are an error, not a silent pick.
        let err = command_for(&[
            "synch",
            "trust",
            "add",
            "abc",
            "--as",
            "nas@a.example",
            "--domain",
            "b.example",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("drop one"), "{err}");
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
