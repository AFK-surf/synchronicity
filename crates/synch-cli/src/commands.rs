//! Command dispatch.
//!
//! Two commands touch the data directory directly: `synch init`, which creates
//! it before any daemon can exist, and `synch daemon run`, which *is* the
//! daemon. Every other command is a control-service call to a running daemon
//! (§9.1) — there is no in-process fallback.

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use synch_engine::{EntryRef, Node, NodeConfig};

use crate::{
    cli::{
        CasBackendArg, CasCommand, Cli, CloudCommand, Command, DaemonCommand, DelegateCommand,
        DomainCommand, KeyCommand, MirrorCommand, PinCommand, SpaceCommand, TrustCommand,
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
    // The daemon installs its SQLite store as `rekor_config` during open, so
    // the monotonic pin state rides Litestream with every other durable fact.
    config.cloud = cloud_config_for(cli, cli.cas_backend, config.data_dir.join("cloud"))?;
    Ok(config)
}

fn cloud_config_for(
    cli: &Cli,
    backend: CasBackendArg,
    scratch_dir: PathBuf,
) -> Result<Option<synch_store::cloud::CloudConfig>> {
    cloud_config_with_fallback(
        cli,
        backend,
        scratch_dir,
        &std::collections::HashMap::new(),
        false,
    )
}

fn cloud_config_with_fallback(
    cli: &Cli,
    backend: CasBackendArg,
    scratch_dir: PathBuf,
    fallback: &std::collections::HashMap<String, String>,
    prefer_fallback: bool,
) -> Result<Option<synch_store::cloud::CloudConfig>> {
    let select = |explicit: Option<String>, name: &str| match prefer_fallback {
        true => fallback.get(name).cloned().or(explicit),
        false => explicit.or_else(|| fallback.get(name).cloned()),
    };
    let mut options = std::collections::HashMap::new();
    let explicit_root = (cli.cloud_root != "/").then(|| cli.cloud_root.clone());
    let root = select(explicit_root, "root").unwrap_or_else(|| "/".into());
    options.insert("root".to_string(), root);
    let service = match backend {
        CasBackendArg::Local => return Ok(None),
        CasBackendArg::S3 => {
            options.insert(
                "bucket".into(),
                select(cli.s3_bucket.clone(), "bucket")
                    .context("--cas-backend s3 requires --s3-bucket")?,
            );
            if let Some(region) = select(cli.s3_region.clone(), "region") {
                options.insert("region".into(), region);
            }
            if let Some(endpoint) = select(cli.s3_endpoint.clone(), "endpoint") {
                options.insert("endpoint".into(), endpoint);
            }
            synch_store::cloud::CloudService::S3
        }
        CasBackendArg::Gcs => {
            options.insert(
                "bucket".into(),
                select(cli.gcs_bucket.clone(), "bucket")
                    .context("--cas-backend gcs requires --gcs-bucket")?,
            );
            if let Some(endpoint) = select(cli.gcs_endpoint.clone(), "endpoint") {
                options.insert("endpoint".into(), endpoint);
            }
            if let Some(path) = &cli.gcs_credential_path {
                options.insert(
                    "credential_path".into(),
                    path.to_string_lossy().into_owned(),
                );
            }
            synch_store::cloud::CloudService::Gcs
        }
        CasBackendArg::Azblob => {
            options.insert(
                "container".into(),
                select(cli.azblob_container.clone(), "container")
                    .context("--cas-backend azblob requires --azblob-container")?,
            );
            if let Some(endpoint) = select(cli.azblob_endpoint.clone(), "endpoint") {
                options.insert("endpoint".into(), endpoint);
            }
            if let Some(account) = select(cli.azblob_account_name.clone(), "account_name") {
                options.insert("account_name".into(), account);
            }
            if let Some(key) = &cli.azblob_account_key {
                options.insert("account_key".into(), key.clone());
            }
            synch_store::cloud::CloudService::Azblob
        }
    };
    Ok(Some(synch_store::cloud::CloudConfig {
        service,
        options,
        scratch_dir,
        io_timeout: std::time::Duration::from_secs(60),
        upload_policy: cli.cloud_upload.into(),
        cache_bytes: cli.cloud_cache_bytes,
    }))
}

/// Runs one command.
pub async fn run(cli: Cli) -> Result<()> {
    let data_dir = data_dir(&cli)?;
    match &cli.command {
        Command::Init { domain } => {
            let domain = domain.clone();
            let backend = cli.cas_backend.as_str().to_string();
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
            let report = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let _scope = synch_core::BlockingScope::enter();
                let report = Node::init(&dir, domain.as_deref())?;
                synch_store::Store::open(&dir)?.set_config("cas.backend", &backend)?;
                Ok(report)
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
        Command::Cas {
            command: CasCommand::Migrate { to },
        } => migrate_cas(&cli, &data_dir, *to).await,
        _ => {
            let command = to_command(&cli)?;
            deliver(&data_dir, &cli, command).await
        }
    }
}

async fn migrate_cas(cli: &Cli, data_dir: &Path, target: CasBackendArg) -> Result<()> {
    match transport::connect(data_dir).await {
        Ok(_) => anyhow::bail!(
            "a daemon is running for {}; stop it before migrating the CAS backend",
            data_dir.display()
        ),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) => {}
        Err(error) => return Err(error).context("could not establish that the daemon is stopped"),
    }

    let directory = data_dir.to_path_buf();
    let (source_store, stored) = tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        let store = Arc::new(synch_store::Store::open(directory)?);
        let stored = store
            .config("cas.backend")?
            .unwrap_or_else(|| "local".to_string());
        Ok::<_, synch_store::StoreError>((store, stored))
    })
    .await
    .context("the source CAS opening task did not complete")??;
    let source = parse_backend(&stored)?;

    let fallback_store = source_store.clone();
    let (source_fallback, target_fallback) = tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        Ok::<_, synch_store::StoreError>((
            persisted_cloud_options(&fallback_store, source)?,
            persisted_cloud_options(&fallback_store, target)?,
        ))
    })
    .await
    .context("the stored cloud configuration task did not complete")??;
    let source_config = cloud_config_with_fallback(
        cli,
        source,
        data_dir.join("cas-migrate/source-scratch"),
        &source_fallback,
        true,
    )?;
    let target_config = cloud_config_with_fallback(
        cli,
        target,
        data_dir.join("cas-migrate/target-scratch"),
        &target_fallback,
        false,
    )?;
    if source == target
        && source_config.as_ref().map(|config| &config.options)
            == target_config.as_ref().map(|config| &config.options)
    {
        println!("CAS backend is already {}", target.as_str());
        return Ok(());
    }
    let directory = data_dir.to_path_buf();
    let target_store = tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        Ok::<_, synch_store::StoreError>(Arc::new(synch_store::Store::open(directory)?))
    })
    .await
    .context("the destination CAS opening task did not complete")??;
    let target_settings = target_config
        .as_ref()
        .map(persisted_settings)
        .unwrap_or_default();
    let source_backend = build_migration_backend(source_store.clone(), source_config)?;
    let target_backend = build_migration_backend(target_store.clone(), target_config)?;

    let migrated = copy_and_switch_backends(
        source_store,
        target_store,
        source_backend,
        target_backend,
        target.as_str(),
        target_settings,
        data_dir.join("cas-migrate/materialized"),
    )
    .await?;
    println!(
        "CAS backend switched to {} ({migrated} object(s))",
        target.as_str()
    );
    Ok(())
}

async fn copy_and_switch_backends(
    source_store: Arc<synch_store::Store>,
    target_store: Arc<synch_store::Store>,
    source_backend: Arc<dyn synch_store::backend::CasBackend>,
    target_backend: Arc<dyn synch_store::backend::CasBackend>,
    target_name: &str,
    target_settings: Vec<(String, Option<String>)>,
    staging: PathBuf,
) -> Result<usize> {
    let listed = source_store;
    let candidates = tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        Ok::<_, synch_store::StoreError>(
            listed
                .blob_candidates()?
                .into_iter()
                .filter(|blob| {
                    blob.size > synch_core::INLINE_BLOB_MAX && (blob.complete || blob.durable)
                })
                .collect::<Vec<_>>(),
        )
    })
    .await
    .context("the CAS inventory task did not complete")??;
    tokio::fs::create_dir_all(&staging).await?;
    for (index, blob) in candidates.iter().enumerate() {
        let materialized = staging.join(format!(
            "{}-{}-{}.payload",
            std::process::id(),
            index,
            blob.root
        ));
        source_backend
            .materialize(blob.root, blob.size, materialized.clone())
            .await
            .with_context(|| format!("could not read source object {}", blob.root))?;
        let ingested = target_backend
            .ingest_file(materialized.clone(), synch_core::now_ns())
            .await
            .with_context(|| format!("could not write destination object {}", blob.root));
        let _ = tokio::fs::remove_file(&materialized).await;
        let ingested = ingested?;
        if (ingested.root, ingested.size) != (blob.root, blob.size) {
            anyhow::bail!(
                "destination verification changed {} ({} bytes) into {} ({} bytes)",
                blob.root,
                blob.size,
                ingested.root,
                ingested.size
            );
        }
        tracing::info!(
            completed = index + 1,
            total = candidates.len(),
            root = %blob.root,
            "migrated CAS object"
        );
    }

    let switched = target_store;
    let target_name = target_name.to_string();
    tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        switched.transaction(|txn| {
            txn.set_config("cas.backend", &target_name)?;
            for (key, value) in target_settings {
                match value {
                    Some(value) => txn.set_config(&key, &value)?,
                    None => txn.clear_config(&key)?,
                }
            }
            Ok::<_, synch_store::StoreError>(())
        })
    })
    .await
    .context("the CAS switch task did not complete")??;
    let _ = tokio::fs::remove_dir(&staging).await;
    Ok(candidates.len())
}

fn cloud_option_names(backend: CasBackendArg) -> &'static [&'static str] {
    match backend {
        CasBackendArg::Local => &[],
        CasBackendArg::S3 => &[
            "root",
            "bucket",
            "region",
            "endpoint",
            "enable_virtual_host_style",
        ],
        CasBackendArg::Gcs => &["root", "bucket", "endpoint"],
        CasBackendArg::Azblob => &["root", "container", "endpoint", "account_name"],
    }
}

fn persisted_cloud_options(
    store: &synch_store::Store,
    backend: CasBackendArg,
) -> std::result::Result<std::collections::HashMap<String, String>, synch_store::StoreError> {
    let mut options = std::collections::HashMap::new();
    for name in cloud_option_names(backend) {
        let key = format!("cas.cloud.{}.{name}", backend.as_str());
        if let Some(value) = store.config(&key)? {
            options.insert((*name).to_string(), value);
        }
    }
    Ok(options)
}

fn persisted_settings(cloud: &synch_store::cloud::CloudConfig) -> Vec<(String, Option<String>)> {
    let backend = match cloud.service {
        synch_store::cloud::CloudService::S3 => CasBackendArg::S3,
        synch_store::cloud::CloudService::Gcs => CasBackendArg::Gcs,
        synch_store::cloud::CloudService::Azblob => CasBackendArg::Azblob,
        synch_store::cloud::CloudService::Memory => return Vec::new(),
    };
    let prefix = format!("cas.cloud.{}", backend.as_str());
    let mut settings: Vec<(String, Option<String>)> = cloud_option_names(backend)
        .iter()
        .map(|name| {
            (
                format!("{prefix}.{name}"),
                cloud.options.get(*name).cloned(),
            )
        })
        .collect();
    settings.push((
        format!("{prefix}.cache_bytes"),
        cloud.cache_bytes.map(|bytes| bytes.to_string()),
    ));
    settings.push((
        format!("{prefix}.upload"),
        Some(cloud.upload_policy.as_str().to_string()),
    ));
    settings
}

fn parse_backend(value: &str) -> Result<CasBackendArg> {
    match value {
        "local" => Ok(CasBackendArg::Local),
        "s3" => Ok(CasBackendArg::S3),
        "gcs" => Ok(CasBackendArg::Gcs),
        "azblob" => Ok(CasBackendArg::Azblob),
        other => anyhow::bail!("unsupported stored CAS backend {other}"),
    }
}

fn build_migration_backend(
    store: Arc<synch_store::Store>,
    cloud: Option<synch_store::cloud::CloudConfig>,
) -> Result<Arc<dyn synch_store::backend::CasBackend>> {
    Ok(match cloud {
        None => Arc::new(synch_store::backend::LocalFs::new(store)),
        Some(config) => {
            let objects = synch_store::cloud::CloudStore::open(&config)?;
            Arc::new(synch_store::backend::Cloud::new(
                store,
                objects,
                config.upload_policy,
                config.cache_bytes,
            ))
        }
    })
}

/// Translates a parsed command into the one the control service takes.
fn to_command(cli: &Cli) -> Result<Cmd> {
    Ok(match &cli.command {
        Command::Init { .. } => unreachable!("handled before dispatch"),
        Command::Daemon {
            command: DaemonCommand::Run,
        } => unreachable!("handled before dispatch"),
        Command::Cas { .. } => unreachable!("handled before dispatch"),
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

        Command::Delegate { command } => match command {
            DelegateCommand::Add {
                key,
                spaces,
                until,
                note,
            } => Cmd::DelegateAdd(pb::DelegateAdd {
                key: key.clone(),
                spaces: spaces.clone(),
                until: until.clone(),
                note: note.clone(),
            }),
            DelegateCommand::Rm { key } => Cmd::DelegateRm(pb::DelegateRm { key: key.clone() }),
            DelegateCommand::Ls => Cmd::DelegateLs(pb::DelegateLs {}),
        },

        Command::Domain { command } => match command {
            DomainCommand::Set { domain, delegate } => Cmd::DomainSet(pb::DomainSet {
                domain: domain.clone(),
                delegate: *delegate,
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
            SpaceCommand::Add { id, path, detached } => Cmd::SpaceAdd(pb::SpaceAdd {
                id: id.clone(),
                path: path
                    .as_deref()
                    .map(absolute)
                    .transpose()?
                    .unwrap_or_default(),
                detached: *detached,
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

    #[test]
    fn cloud_backend_flags_build_provider_neutral_opendal_config() {
        let cli = Cli::parse_from([
            "synch",
            "--cas-backend",
            "s3",
            "--s3-bucket",
            "durable-cas",
            "--s3-region",
            "us-west-2",
            "--cloud-root",
            "nodes/a",
            "daemon",
            "run",
        ]);
        let cloud = node_config(&cli).unwrap().cloud.unwrap();
        assert_eq!(cloud.service, synch_store::cloud::CloudService::S3);
        assert_eq!(cloud.options["bucket"], "durable-cas");
        assert_eq!(cloud.options["region"], "us-west-2");
        assert_eq!(cloud.options["root"], "nodes/a");

        let missing = Cli::parse_from(["synch", "--cas-backend", "gcs", "daemon", "run"]);
        assert!(node_config(&missing)
            .unwrap_err()
            .to_string()
            .contains("--gcs-bucket"));
    }

    #[tokio::test]
    async fn cas_migration_switches_only_after_every_object_verifies() {
        let _blocking = synch_core::BlockingScope::enter();
        let data = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let source_store = Arc::new(synch_store::Store::open(data.path()).unwrap());
        source_store.set_config("cas.backend", "local").unwrap();
        let source: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::LocalFs::new(source_store.clone()));
        let payload: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
        let root = source
            .ingest_bytes(payload.clone(), synch_core::now_ns())
            .await
            .unwrap()
            .root;

        let target_store = Arc::new(synch_store::Store::open(data.path()).unwrap());
        let objects = synch_store::cloud::CloudStore::open(&synch_store::cloud::CloudConfig {
            service: synch_store::cloud::CloudService::Memory,
            options: std::collections::HashMap::new(),
            scratch_dir: scratch.path().to_path_buf(),
            io_timeout: std::time::Duration::from_secs(5),
            upload_policy: synch_store::cloud::CloudUploadPolicy::OwnPinned,
            cache_bytes: None,
        })
        .unwrap();
        let target: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::Cloud::new(
                target_store.clone(),
                objects.clone(),
                synch_store::cloud::CloudUploadPolicy::OwnPinned,
                None,
            ));
        let count = copy_and_switch_backends(
            source_store.clone(),
            target_store,
            source,
            target,
            "s3",
            Vec::new(),
            data.path().join("migration-test"),
        )
        .await
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            source_store.config("cas.backend").unwrap().as_deref(),
            Some("s3")
        );
        assert_eq!(
            objects
                .read_range(&root, 17..90_017)
                .await
                .unwrap()
                .as_ref(),
            &payload[17..90_017]
        );

        // The same verified walk covers cloud-to-cloud and cloud-to-local;
        // force each source cache cold so the test cannot pass by reusing the
        // local payload left by the first leg.
        source_store
            .reconcile_scratch_generation("cloud-to-cloud-cold")
            .unwrap();
        let cloud_source_store = Arc::new(synch_store::Store::open(data.path()).unwrap());
        let cloud_source: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::Cloud::new(
                cloud_source_store.clone(),
                objects,
                synch_store::cloud::CloudUploadPolicy::OwnPinned,
                None,
            ));
        let second_scratch = tempfile::tempdir().unwrap();
        let second_objects =
            synch_store::cloud::CloudStore::open(&synch_store::cloud::CloudConfig {
                service: synch_store::cloud::CloudService::Memory,
                options: std::collections::HashMap::new(),
                scratch_dir: second_scratch.path().to_path_buf(),
                io_timeout: std::time::Duration::from_secs(5),
                upload_policy: synch_store::cloud::CloudUploadPolicy::OwnPinned,
                cache_bytes: None,
            })
            .unwrap();
        let second_store = Arc::new(synch_store::Store::open(data.path()).unwrap());
        let second_cloud: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::Cloud::new(
                second_store.clone(),
                second_objects.clone(),
                synch_store::cloud::CloudUploadPolicy::OwnPinned,
                None,
            ));
        copy_and_switch_backends(
            cloud_source_store,
            second_store,
            cloud_source,
            second_cloud,
            "gcs",
            Vec::new(),
            data.path().join("migration-cloud-to-cloud"),
        )
        .await
        .unwrap();
        assert_eq!(
            second_objects
                .read_range(&root, 17..90_017)
                .await
                .unwrap()
                .as_ref(),
            &payload[17..90_017]
        );

        let reverse_source_store = Arc::new(synch_store::Store::open(data.path()).unwrap());
        reverse_source_store
            .reconcile_scratch_generation("cloud-to-local-cold")
            .unwrap();
        let reverse_source: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::Cloud::new(
                reverse_source_store.clone(),
                second_objects,
                synch_store::cloud::CloudUploadPolicy::OwnPinned,
                None,
            ));
        let local_store = Arc::new(synch_store::Store::open(data.path()).unwrap());
        let local: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::LocalFs::new(local_store.clone()));
        copy_and_switch_backends(
            reverse_source_store,
            local_store.clone(),
            reverse_source,
            local,
            "local",
            Vec::new(),
            data.path().join("migration-cloud-to-local"),
        )
        .await
        .unwrap();
        assert_eq!(
            local_store.config("cas.backend").unwrap().as_deref(),
            Some("local")
        );
        assert_eq!(local_store.read_all(&root).unwrap(), payload);

        // A source verification/read failure returns before the final config
        // transaction, leaving the stored backend untouched for a retry.
        let broken_data = tempfile::tempdir().unwrap();
        let broken_source = Arc::new(synch_store::Store::open(broken_data.path()).unwrap());
        broken_source.set_config("cas.backend", "local").unwrap();
        let broken_backend: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::LocalFs::new(broken_source.clone()));
        let _broken = broken_backend
            .ingest_bytes(payload, synch_core::now_ns())
            .await
            .unwrap();
        let destination_store = Arc::new(synch_store::Store::open(broken_data.path()).unwrap());
        let destination: Arc<dyn synch_store::backend::CasBackend> = Arc::new(
            synch_store::backend::LocalFs::new(destination_store.clone()),
        );
        let broken_staging = broken_data.path().join("migration-test");
        std::fs::write(&broken_staging, b"not a directory").unwrap();
        assert!(copy_and_switch_backends(
            broken_source.clone(),
            destination_store,
            broken_backend,
            destination,
            "s3",
            Vec::new(),
            broken_staging,
        )
        .await
        .is_err());
        assert_eq!(
            broken_source.config("cas.backend").unwrap().as_deref(),
            Some("local")
        );
    }

    /// A device key or a zone, told apart by shape rather than by a flag.
    ///
    /// A name belongs to the zone that issues it (§3.2), so nothing infers one
    /// from a key: a plain `trust add <key>` binds the key and only the key. A
    /// member publishing under a name is reached by trusting its *zone*, which
    /// is what `trust add <domain>` does — the route that used to require
    /// `--as` and a static binding that never expired.
    #[test]
    fn trust_add_takes_a_key_or_a_zone() {
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
        // A domain travels in the same field; the daemon tells them apart,
        // because a device key is fixed-length z-base-32 and a domain is not.
        let zone = command_for(&["synch", "trust", "add", "cluster.example"]).unwrap();
        assert_eq!(
            zone,
            Cmd::TrustAdd(pb::TrustAdd {
                key: "cluster.example".into(),
                note: None,
                addr: None,
            })
        );
        // `--as` is gone: a name is the zone's to issue.
        assert!(Cli::try_parse_from([
            "synch",
            "trust",
            "add",
            "abc",
            "--as",
            "nas@cluster.example"
        ])
        .is_err());
        // `trust rebind` stays gone: re-pointing a name is the zone's job.
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
    }
}
