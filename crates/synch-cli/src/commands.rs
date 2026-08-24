//! Command dispatch.
//!
//! `synch init` creates the data directory before a daemon can exist; `synch
//! daemon run` is the daemon, and `synch daemon start` launches that command in
//! the background. Every other command is a control-service call to a running
//! daemon (§9.1) — there is no in-process fallback.

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
        DomainCommand, KeyCommand, MirrorCommand, PinCommand, SocketCommand, SpaceCommand,
        TrustCommand,
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
    let explicit_root = (cli.cas_root != "/").then(|| cli.cas_root.clone());
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
            if cli.gcs_skip_signature {
                options.insert("skip_signature".into(), "true".into());
            }
            if cli.gcs_disable_vm_metadata {
                options.insert("disable_vm_metadata".into(), "true".into());
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
        upload_policy: cli.cas_upload.into(),
        cache_bytes: cli.cas_cache_bytes,
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
                    println!("next:       synch daemon start");
                }
                (None, Some(domain)) => {
                    // The record is the next step, and printing it is the
                    // difference between one copy-paste and a trip to the docs.
                    println!("domain:     {domain}");
                    println!("next:       publish this record, then `synch daemon start`:");
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
        Command::Daemon {
            command: DaemonCommand::Start,
        } => daemon::start(&data_dir, std::env::args_os().skip(1)).await,
        Command::Cas {
            command: CasCommand::Migrate { to },
        } => migrate_cas(&cli, &data_dir, *to).await,
        // Not a `Run` command: it is a bidirectional byte pipe, and rendering
        // it as lines of text would be rendering somebody else's protocol.
        Command::Connect {
            reference,
            meta,
            listen,
            once,
        } => crate::connect::run(&data_dir, reference, meta, listen.as_deref(), *once).await,
        // Also not a `Run` command, and for a plainer reason: compiling a C
        // file needs no node, no daemon and no data directory. Sending it to
        // the daemon would mean a compiler in the daemon and a source file
        // over a socket, for a job this process can do itself.
        Command::Socket {
            command:
                SocketCommand::Build {
                    source,
                    output,
                    clang,
                    define,
                },
        } => build_socket(source, output.as_deref(), *clang, define),
        _ => {
            let command = to_command(&cli)?;
            deliver(&data_dir, &cli, command).await
        }
    }
}

/// `synch socket build` — C in, eBPF object out, nothing installed.
fn build_socket(
    source: &Path,
    output: Option<&Path>,
    clang: bool,
    defines: &[String],
) -> Result<()> {
    if !clang && !synch_cc::SUPPORTED {
        anyhow::bail!(
            "this build has no embedded C compiler; rerun with `--clang` and compatible \
             `clang` and `llc` executables on PATH"
        );
    }

    // Match GCC and Clang: `-DNAME` is shorthand for `-DNAME=1`.
    let defines: Vec<(&str, &str)> = defines
        .iter()
        .map(|text| match text.split_once('=') {
            Some((name, value)) => (name, value),
            None => (text.as_str(), "1"),
        })
        .collect();

    let headers = [("synch.h", synch_sock::sdk::HEADER)];
    let object = if clang {
        synch_cc::compile_file_with_clang(source, &headers, &defines)
    } else {
        synch_cc::compile_file(source, &headers, &defines)
    }
    .map_err(|e| anyhow::anyhow!("{e}"))
    .with_context(|| format!("compiling {}", source.display()))?;

    let output = match output {
        Some(path) => path.to_path_buf(),
        None => source.with_extension("o"),
    };
    std::fs::write(&output, &object).with_context(|| format!("writing {}", output.display()))?;
    println!("{} ({} bytes)", output.display(), object.len());
    Ok(())
}

async fn migrate_cas(cli: &Cli, data_dir: &Path, target: CasBackendArg) -> Result<()> {
    // Own the same process lock the daemon takes before Store/endpoint open,
    // for the whole migration. A connect-only preflight is a TOCTOU check.
    let _lifecycle = transport::LifecycleLock::acquire(data_dir)
        .with_context(|| {
            format!(
                "could not exclusively lock {} for CAS migration; stop its daemon and any other migration",
                data_dir.display()
            )
        })?;

    let target_index = data_dir.join(format!(
        "cas-migrate/target-index-{}-{}",
        std::process::id(),
        synch_core::now_ns()
    ));
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
    if target != CasBackendArg::Local {
        let checked = source_store.clone();
        let path_spaces = tokio::task::spawn_blocking(move || {
            let _scope = synch_core::BlockingScope::enter();
            path_backed_space_ids(&checked)
        })
        .await
        .context("the space inventory task did not complete")??;
        if !path_spaces.is_empty() {
            anyhow::bail!(
                "cloud CAS migration requires detached spaces; path-backed space(s): {}",
                path_spaces.join(", ")
            );
        }
    }

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
    let directory = target_index.clone();
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

    let migration = copy_and_switch_backends(
        source_store,
        source_backend,
        target_backend,
        target.as_str(),
        target_settings,
        data_dir.join("cas-migrate/materialized"),
    )
    .await;
    let _ = tokio::fs::remove_dir_all(target_index).await;
    let migrated = migration?;
    println!(
        "CAS backend switched to {} ({migrated} object(s))",
        target.as_str()
    );
    Ok(())
}

fn path_backed_space_ids(
    store: &synch_store::Store,
) -> std::result::Result<Vec<String>, synch_store::StoreError> {
    Ok(store
        .spaces()?
        .into_iter()
        .filter(|space| space.local_path.is_some())
        .map(|space| space.id)
        .collect())
}

async fn copy_and_switch_backends(
    source_store: Arc<synch_store::Store>,
    source_backend: Arc<dyn synch_store::backend::CasBackend>,
    target_backend: Arc<dyn synch_store::backend::CasBackend>,
    target_name: &str,
    target_settings: Vec<(String, Option<String>)>,
    staging: PathBuf,
) -> Result<usize> {
    let source_is_cloud = source_backend.remote_upload_parts();
    if source_is_cloud {
        let advertised_store = source_store.clone();
        let advertised = tokio::task::spawn_blocking(move || {
            let _scope = synch_core::BlockingScope::enter();
            let mut probes: std::collections::HashMap<synch_core::Hash, (u64, bool)> =
                std::collections::HashMap::new();
            if let Some(ours) = advertised_store.self_origin()? {
                for root in advertised_store.provider_roots_for_origin(&ours)? {
                    let row = advertised_store.blob(&root)?;
                    if row.as_ref().is_none_or(|row| !row.durable) {
                        if let Some((_, ad)) = advertised_store
                            .providers(&root)?
                            .into_iter()
                            .find(|(origin, ad)| origin == &ours && ad.is_complete())
                        {
                            probes.insert(root, (ad.size, true));
                        }
                    }
                }
            }
            for (root, size) in advertised_store.referenced_content_sizes()? {
                if advertised_store.blob(&root)?.is_some_and(|row| row.durable) {
                    continue;
                }
                match probes.get(&root) {
                    Some((known, _)) if *known != size => {
                        return Err(synch_store::StoreError::invalid(format!(
                            "recovered metadata for {root} gives both {known} and {size} bytes"
                        )));
                    }
                    Some(_) => {}
                    None => {
                        probes.insert(root, (size, false));
                    }
                }
            }
            Ok::<_, synch_store::StoreError>(
                probes
                    .into_iter()
                    .map(|(root, (size, required))| (root, size, required))
                    .collect::<Vec<_>>(),
            )
        })
        .await
        .context("the source cloud advertisement inventory task did not complete")??;
        for (root, size, required) in advertised {
            source_backend
                .ensure_ranges(root, size, synch_core::ChunkRanges::empty())
                .await
                .with_context(|| format!("could not locate advertised source object {root}"))?;
            let checked = source_store.clone();
            let (durable, complete_cache) = tokio::task::spawn_blocking(move || {
                let _scope = synch_core::BlockingScope::enter();
                let row = checked.blob(&root)?;
                Ok::<_, synch_store::StoreError>(match row {
                    Some(row) => (
                        row.durable && row.size == size,
                        row.size == size
                            && row.complete
                            && (row.inline.is_some()
                                || checked.cached_blob_files_present(&root, size)),
                    ),
                    None => (false, false),
                })
            })
            .await
            .context("the source cloud durability check did not complete")??;
            if required && !durable && !complete_cache {
                anyhow::bail!(
                    "source advertises cloud object {root} ({size} bytes), but its final pair is unavailable"
                );
            }
        }
    }
    let listed = source_store.clone();
    let candidates = tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        let mut candidates = Vec::new();
        for blob in listed.blob_candidates()? {
            if blob.durable || (!source_is_cloud && blob.complete) {
                candidates.push(blob);
                continue;
            }
            if source_is_cloud && blob.complete {
                let row = listed.blob(&blob.root)?.expect("candidate row exists");
                if row.inline.is_some() || listed.cached_blob_files_present(&blob.root, blob.size) {
                    candidates.push(blob);
                }
            }
        }
        Ok::<_, synch_store::StoreError>(candidates)
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
        let copied: Result<()> = async {
            target_backend
                .ingest_file(materialized.clone(), synch_core::now_ns())
                .await
                .with_context(|| format!("could not write destination object {}", blob.root))?;
            if target_name == "local" {
                // Install through the real future-local Store, not merely the
                // isolated target index. This rebuilds and fsyncs both the
                // payload and outboard before the backend flip.
                let installed = source_store.clone();
                let path = materialized.clone();
                tokio::task::spawn_blocking(move || {
                    let _scope = synch_core::BlockingScope::enter();
                    installed.ingest_file(&path, synch_core::now_ns())
                })
                .await
                .context("the local CAS install task did not complete")??;
            }
            Ok(())
        }
        .await;
        let _ = tokio::fs::remove_file(&materialized).await;
        copied?;
        tracing::info!(
            completed = index + 1,
            total = candidates.len(),
            root = %blob.root,
            "migrated CAS object"
        );
    }

    if target_name == "local" {
        let checked = source_store.clone();
        let expected: Vec<(synch_core::Hash, u64)> = candidates
            .iter()
            .map(|blob| (blob.root, blob.size))
            .collect();
        tokio::task::spawn_blocking(move || {
            let _scope = synch_core::BlockingScope::enter();
            for (root, size) in expected {
                let row = checked
                    .blob(&root)?
                    .ok_or(synch_store::StoreError::MissingBlob(root))?;
                if row.inline.is_none() && !checked.cached_blob_files_present(&root, size) {
                    return Err(synch_store::StoreError::MissingBlob(root));
                }
            }
            Ok::<_, synch_store::StoreError>(())
        })
        .await
        .context("the local destination CAS presence check did not complete")??;
    }

    let switched = source_store;
    let target_name = target_name.to_string();
    let migrated_roots: Vec<synch_core::Hash> = candidates.iter().map(|blob| blob.root).collect();
    tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        switched
            .commit_cas_migration(
                &target_name,
                &target_settings,
                &migrated_roots,
                source_is_cloud,
            )
            .map(|_| ())
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
        CasBackendArg::Gcs => &[
            "root",
            "bucket",
            "endpoint",
            "skip_signature",
            "disable_vm_metadata",
        ],
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
        Command::Connect { .. } => unreachable!("handled before dispatch"),
        Command::Daemon {
            command: DaemonCommand::Run,
        } => unreachable!("handled before dispatch"),
        Command::Daemon {
            command: DaemonCommand::Start,
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
            SpaceCommand::Add {
                id,
                path,
                detached,
                replicate,
                grace,
                budget,
            } => Cmd::SpaceAdd(pb::SpaceAdd {
                id: id.clone(),
                path: path
                    .as_deref()
                    .map(absolute)
                    .transpose()?
                    .unwrap_or_default(),
                detached: *detached,
                replicate: replicate.clone(),
                grace: grace.map(|d| d.as_secs() as i64),
                budget: *budget,
            }),
            SpaceCommand::Set {
                id,
                replicate,
                no_replicate,
                release,
                grace,
                budget,
            } => Cmd::SpaceSet(pb::SpaceSet {
                id: id.clone(),
                replicate: replicate.clone(),
                no_replicate: *no_replicate,
                release: *release,
                grace: grace.map(|d| d.as_secs() as i64),
                budget: *budget,
            }),
            SpaceCommand::Ls { id } => Cmd::SpaceLs(pb::SpaceLs {
                id: id.clone().unwrap_or_default(),
            }),
            SpaceCommand::Sync { id } => Cmd::SpaceSync(pb::SpaceSync {
                id: id.clone().unwrap_or_default(),
            }),
            SpaceCommand::Rm { id, release } => Cmd::SpaceRm(pb::SpaceRm {
                id: id.clone(),
                release: *release,
            }),
        },

        Command::Fill {
            reference,
            from,
            strict,
            force,
            dry_run,
        } => Cmd::Fill(pb::Fill {
            reference: reference.clone(),
            from: from.clone(),
            strict: *strict,
            force: *force,
            dry_run: *dry_run,
        }),

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

        Command::Socket { command } => match command {
            SocketCommand::Add {
                target,
                config,
                max_streams,
                auto,
                note,
            } => Cmd::SocketAdd(pb::SocketAdd {
                target: target.clone(),
                config: config.clone(),
                max_streams: max_streams.unwrap_or(0),
                auto: *auto,
                note: note.clone().unwrap_or_default(),
            }),
            SocketCommand::Arm { target, review } => Cmd::SocketArm(pb::SocketArm {
                target: target.clone(),
                review: review.clone().unwrap_or_default(),
            }),
            SocketCommand::Disarm { target } => Cmd::SocketDisarm(pb::SocketDisarm {
                target: target.clone(),
            }),
            SocketCommand::Rm { target } => Cmd::SocketRm(pb::SocketRm {
                target: target.clone(),
            }),
            SocketCommand::Ls { space, long } => Cmd::SocketLs(pb::SocketLs {
                space: space.clone().unwrap_or_default(),
                long: *long,
            }),
            SocketCommand::Ps { target } => Cmd::SocketPs(pb::SocketPs {
                target: target.clone().unwrap_or_default(),
            }),
            SocketCommand::Kill { invocation } => Cmd::SocketKill(pb::SocketKill {
                invocation: *invocation,
            }),
            SocketCommand::Log { target } => Cmd::SocketLog(pb::SocketLog {
                target: target.clone(),
            }),
            SocketCommand::Sdk => Cmd::SocketSdk(pb::SocketSdk {}),
            // Compiling is local work with no node in it, so `run` handles it
            // before anything reaches here and there is no control command to
            // build. Spelled out rather than left to `_`, so adding a socket
            // command that *does* need the daemon is a compile error here
            // rather than a silent no-op.
            SocketCommand::Build { .. } => {
                anyhow::bail!("`synch socket build` runs in this process, not the daemon")
            }
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
            root,
        } => Cmd::Cat(pb::Cat {
            reference: reference.clone().unwrap_or_default(),
            range: range.clone(),
            from: from.clone(),
            strict: *strict,
            root: root.clone(),
        }),
        Command::Get {
            reference,
            from,
            strict,
            root,
            ..
        } => Cmd::Get(pb::Get {
            reference: reference.clone().unwrap_or_default(),
            from: from.clone(),
            strict: *strict,
            root: root.clone(),
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
        reference,
        output,
        root,
        ..
    } = &cli.command
    {
        let target = match (output, reference, root) {
            (Some(path), _, _) => path.clone(),
            (None, Some(reference), _) => {
                let reference: EntryRef = reference.parse()?;
                PathBuf::from(reference.path.rsplit('/').next().unwrap_or(&reference.path))
            }
            // A root names no file, so the root is the file name. Better than
            // guessing: whoever asked for a bare object knows what it is, and a
            // hex name is at least unambiguous about which one they got.
            (None, None, Some(root)) => PathBuf::from(root),
            (None, None, None) => {
                anyhow::bail!("get needs a <space>/<path> or a --root")
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
            "--cas-root",
            "nodes/a",
            "--cas-upload",
            "all",
            "--cas-cache-bytes",
            "1024",
            "daemon",
            "run",
        ]);
        let cloud = node_config(&cli).unwrap().cloud.unwrap();
        assert_eq!(cloud.service, synch_store::cloud::CloudService::S3);
        assert_eq!(cloud.options["bucket"], "durable-cas");
        assert_eq!(cloud.options["region"], "us-west-2");
        assert_eq!(cloud.options["root"], "nodes/a");
        assert_eq!(
            cloud.upload_policy,
            synch_store::cloud::CloudUploadPolicy::All
        );
        assert_eq!(cloud.cache_bytes, Some(1024));

        let missing = Cli::parse_from(["synch", "--cas-backend", "gcs", "daemon", "run"]);
        assert!(node_config(&missing)
            .unwrap_err()
            .to_string()
            .contains("--gcs-bucket"));

        let emulator = Cli::parse_from([
            "synch",
            "--cas-backend",
            "gcs",
            "--gcs-bucket",
            "test",
            "--gcs-endpoint",
            "http://127.0.0.1:4443",
            "--gcs-skip-signature",
            "--gcs-disable-vm-metadata",
            "daemon",
            "run",
        ]);
        let cloud = node_config(&emulator).unwrap().cloud.unwrap();
        assert_eq!(cloud.options["skip_signature"], "true");
        assert_eq!(cloud.options["disable_vm_metadata"], "true");
    }

    #[test]
    fn cloud_migration_preflight_names_path_backed_spaces() {
        let data = tempfile::tempdir().unwrap();
        let store = synch_store::Store::open(data.path()).unwrap();
        store.put_space("detached", None).unwrap();
        store.put_space("checkout", Some("/srv/checkout")).unwrap();
        assert_eq!(
            path_backed_space_ids(&store).unwrap(),
            vec!["checkout".to_string()]
        );
    }

    #[tokio::test]
    async fn cas_migration_switches_only_after_every_object_copies() {
        let _blocking = synch_core::BlockingScope::enter();
        let data = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let source_store = Arc::new(synch_store::Store::open(data.path()).unwrap());
        source_store
            .set_self_origin(&synch_core::OriginId::named("migration", "test.example").unwrap())
            .unwrap();
        source_store.set_config("cas.backend", "local").unwrap();
        let source: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::LocalFs::new(source_store.clone()));
        let payload: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
        let root = source
            .ingest_bytes(payload.clone(), synch_core::now_ns())
            .await
            .unwrap()
            .root;
        let inline_payload = b"inline migration must reach every backend".to_vec();
        let inline_root = source
            .ingest_bytes(inline_payload.clone(), synch_core::now_ns())
            .await
            .unwrap()
            .root;

        let target_index = tempfile::tempdir().unwrap();
        let target_store = Arc::new(synch_store::Store::open(target_index.path()).unwrap());
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
        // Resume shape: the destination object was acknowledged before a
        // previous process reached the final backend-config transaction.
        target
            .ingest_bytes(payload.clone(), synch_core::now_ns())
            .await
            .unwrap();
        target
            .ingest_bytes(inline_payload.clone(), synch_core::now_ns())
            .await
            .unwrap();
        let count = copy_and_switch_backends(
            source_store.clone(),
            source,
            target,
            "s3",
            Vec::new(),
            data.path().join("migration-test"),
        )
        .await
        .unwrap();
        assert_eq!(count, 2);
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
        assert_eq!(
            objects
                .read_range(&inline_root, 0..inline_payload.len() as u64)
                .await
                .unwrap()
                .as_ref(),
            inline_payload
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
                objects.clone(),
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
        let second_index = tempfile::tempdir().unwrap();
        let second_store = Arc::new(synch_store::Store::open(second_index.path()).unwrap());
        let second_cloud: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::Cloud::new(
                second_store.clone(),
                second_objects.clone(),
                synch_store::cloud::CloudUploadPolicy::OwnPinned,
                None,
            ));
        let stale = cloud_source_store
            .ingest_bytes(&vec![0x6d; 100_000], synch_core::now_ns())
            .unwrap();
        assert!(!cloud_source_store.blob(&stale).unwrap().unwrap().durable);
        let _ = std::fs::remove_file(
            cloud_source_store
                .data_dir()
                .join(synch_store::CAS_DIR)
                .join({
                    let hex = stale.to_hex();
                    format!("{}/{hex}", &hex[..2])
                }),
        );
        let ours = cloud_source_store.self_origin().unwrap().unwrap();
        let cached_payload = vec![0x72; 100_000];
        let cached = cloud_source_store
            .ingest_bytes(&cached_payload, synch_core::now_ns())
            .unwrap();
        let inline_cached_payload = b"complete inline peer cache".to_vec();
        let inline_cached = cloud_source_store
            .ingest_bytes(&inline_cached_payload, synch_core::now_ns())
            .unwrap();
        cloud_source_store
            .put_provider(
                &cached,
                &ours,
                &cloud_source_store.local_ad(&cached).unwrap().unwrap(),
            )
            .unwrap();
        cloud_source_store
            .put_provider(
                &inline_cached,
                &ours,
                &cloud_source_store
                    .local_ad(&inline_cached)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let masked_payload = vec![0x33; 100_000];
        let masked = cloud_source_store
            .ingest_bytes(&masked_payload, synch_core::now_ns())
            .unwrap();
        objects.ingest_bytes(&masked_payload).await.unwrap();
        let masked_hex = masked.to_hex();
        let _ = std::fs::remove_file(
            cloud_source_store
                .data_dir()
                .join(synch_store::CAS_DIR)
                .join(format!("{}/{masked_hex}", &masked_hex[..2])),
        );
        cloud_source_store
            .put_entry(
                &synch_core::OriginId::named("peer", "test.example").unwrap(),
                "shared",
                "masked.bin",
                &synch_core::FileEntry::file(masked_payload.len() as u64, 1, masked, 1),
            )
            .unwrap();
        let rowless_payload = b"self-readopted rowless cloud object".to_vec();
        let rowless = objects.ingest_bytes(&rowless_payload).await.unwrap();
        cloud_source_store
            .put_provider(
                &rowless.root,
                &ours,
                &synch_core::BlobAd::complete(rowless.size),
            )
            .unwrap();
        assert!(cloud_source_store.blob(&rowless.root).unwrap().is_none());
        let migrated = copy_and_switch_backends(
            cloud_source_store,
            cloud_source,
            second_cloud,
            "gcs",
            Vec::new(),
            data.path().join("migration-cloud-to-cloud"),
        )
        .await
        .unwrap();
        assert_eq!(migrated, 6);
        assert!(source_store.blob(&stale).unwrap().is_none());
        assert_eq!(
            second_objects
                .read_range(&root, 17..90_017)
                .await
                .unwrap()
                .as_ref(),
            &payload[17..90_017]
        );
        assert_eq!(
            second_objects
                .read_range(&inline_root, 0..inline_payload.len() as u64)
                .await
                .unwrap()
                .as_ref(),
            inline_payload
        );
        assert_eq!(
            second_objects
                .read_range(&rowless.root, 0..rowless.size)
                .await
                .unwrap()
                .as_ref(),
            rowless_payload
        );
        assert_eq!(
            second_objects
                .read_range(&cached, 0..cached_payload.len() as u64)
                .await
                .unwrap()
                .as_ref(),
            cached_payload
        );
        assert_eq!(
            second_objects
                .read_range(&inline_cached, 0..inline_cached_payload.len() as u64)
                .await
                .unwrap()
                .as_ref(),
            inline_cached_payload
        );
        assert_eq!(
            second_objects
                .read_range(&masked, 0..masked_payload.len() as u64)
                .await
                .unwrap()
                .as_ref(),
            masked_payload
        );

        let reverse_source_store = Arc::new(synch_store::Store::open(data.path()).unwrap());
        let root_hex = root.to_hex();
        let payload_path = reverse_source_store
            .data_dir()
            .join(synch_store::CAS_DIR)
            .join(format!("{}/{root_hex}", &root_hex[..2]));
        let mut outboard_path = payload_path.clone();
        outboard_path.set_extension("obao");
        let _ = std::fs::remove_file(payload_path);
        let _ = std::fs::remove_file(outboard_path);
        let reverse_source: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::Cloud::new(
                reverse_source_store.clone(),
                second_objects,
                synch_store::cloud::CloudUploadPolicy::OwnPinned,
                None,
            ));
        let local_store = Arc::new(synch_store::Store::open(data.path()).unwrap());
        let local_index = tempfile::tempdir().unwrap();
        let local_target_store = Arc::new(synch_store::Store::open(local_index.path()).unwrap());
        let local: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::LocalFs::new(local_target_store));
        copy_and_switch_backends(
            reverse_source_store,
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
        assert_eq!(local_store.read_all(&inline_root).unwrap(), inline_payload);
        assert_eq!(
            local_store.read_all(&rowless.root).unwrap(),
            rowless_payload
        );
        assert_eq!(local_store.read_all(&cached).unwrap(), cached_payload);
        assert_eq!(
            local_store.read_all(&inline_cached).unwrap(),
            inline_cached_payload
        );
        assert_eq!(local_store.read_all(&masked).unwrap(), masked_payload);
        let all_cached = synch_core::ChunkRanges::single(
            0,
            synch_core::group_count(cached_payload.len() as u64),
        );
        local_store.encode_slice(&cached, &all_cached).unwrap();

        // A complete own durability promise must not disappear merely because
        // an older staged row masks it. With neither source final pair nor
        // complete cache, migration fails before the backend flip.
        let unavailable_data = tempfile::tempdir().unwrap();
        let unavailable_scratch = tempfile::tempdir().unwrap();
        let unavailable_store =
            Arc::new(synch_store::Store::open(unavailable_data.path()).unwrap());
        let unavailable_origin =
            synch_core::OriginId::named("unavailable", "test.example").unwrap();
        unavailable_store
            .set_self_origin(&unavailable_origin)
            .unwrap();
        unavailable_store.set_config("cas.backend", "s3").unwrap();
        let unavailable_objects =
            synch_store::cloud::CloudStore::open(&synch_store::cloud::CloudConfig {
                service: synch_store::cloud::CloudService::Memory,
                options: Default::default(),
                scratch_dir: unavailable_scratch.path().to_path_buf(),
                io_timeout: std::time::Duration::from_secs(5),
                upload_policy: synch_store::cloud::CloudUploadPolicy::OwnPinned,
                cache_bytes: None,
            })
            .unwrap();
        let unavailable_source: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::Cloud::new(
                unavailable_store.clone(),
                unavailable_objects,
                synch_store::cloud::CloudUploadPolicy::OwnPinned,
                None,
            ));
        let unavailable_root = unavailable_store
            .ingest_bytes(&vec![0x28; 100_000], synch_core::now_ns())
            .unwrap();
        unavailable_store
            .put_provider(
                &unavailable_root,
                &unavailable_origin,
                &synch_core::BlobAd::complete(100_000),
            )
            .unwrap();
        let unavailable_hex = unavailable_root.to_hex();
        let _ = std::fs::remove_file(
            unavailable_store
                .data_dir()
                .join(synch_store::CAS_DIR)
                .join(format!("{}/{unavailable_hex}", &unavailable_hex[..2])),
        );
        let unavailable_target_index = tempfile::tempdir().unwrap();
        let unavailable_target_store =
            Arc::new(synch_store::Store::open(unavailable_target_index.path()).unwrap());
        let unavailable_target: Arc<dyn synch_store::backend::CasBackend> =
            Arc::new(synch_store::backend::Cloud::new(
                unavailable_target_store,
                synch_store::cloud::CloudStore::open(&synch_store::cloud::CloudConfig {
                    service: synch_store::cloud::CloudService::Memory,
                    options: Default::default(),
                    scratch_dir: unavailable_target_index.path().join("scratch"),
                    io_timeout: std::time::Duration::from_secs(5),
                    upload_policy: synch_store::cloud::CloudUploadPolicy::OwnPinned,
                    cache_bytes: None,
                })
                .unwrap(),
                synch_store::cloud::CloudUploadPolicy::OwnPinned,
                None,
            ));
        assert!(copy_and_switch_backends(
            unavailable_store.clone(),
            unavailable_source,
            unavailable_target,
            "gcs",
            Vec::new(),
            unavailable_data.path().join("migration"),
        )
        .await
        .is_err());
        assert_eq!(
            unavailable_store.config("cas.backend").unwrap().as_deref(),
            Some("s3")
        );

        // A source read failure returns before the final config
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
