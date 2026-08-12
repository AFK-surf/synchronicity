//! Command dispatch: a thin shell over `synch-engine`.

use std::{io::Write, path::PathBuf, str::FromStr};

use anyhow::{bail, Context, Result};
use iroh_base::SecretKey;
use synch_core::{now_ns, Hash, NodeId, OriginId};
use synch_engine::{EntryRef, Node, NodeConfig};
use synch_store::KeyState;

use crate::cli::{
    ByteRange, Cli, Command, DaemonCommand, DomainCommand, KeyCommand, MirrorCommand, PinCommand,
    SpaceCommand, TrustCommand,
};

/// Resolves the data directory from the CLI flags or the platform default.
pub(crate) fn data_dir(cli: &Cli) -> Result<PathBuf> {
    match &cli.data_dir {
        Some(dir) => Ok(dir.clone()),
        None => Ok(synch_engine::default_data_dir()?),
    }
}

/// Builds the node configuration from the CLI flags.
pub(crate) fn node_config(cli: &Cli) -> Result<NodeConfig> {
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
pub(crate) async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Init { id } => {
            let origin = match id {
                Some(id) => Some(OriginId::from_str(id).context("--id wants <name>@<domain>")?),
                None => None,
            };
            let report = Node::init(data_dir(&cli)?, origin)?;
            println!("origin:     {}", report.origin);
            println!("device key: {}", report.node_id.to_z32());
            println!("data dir:   {}", report.data_dir.display());
            return Ok(());
        }
        Command::Doctor { rebuild } => {
            let node = open(&cli).await?;
            if *rebuild {
                let n = node.rebuild_views()?;
                println!("rebuilt {n} derived rows from the trie");
            }
            print_doctor(&node)?;
            return node.shutdown().await.map_err(Into::into);
        }
        _ => {}
    }

    let node = open(&cli).await?;
    let result = dispatch(&cli, &node).await;
    node.shutdown().await?;
    result
}

// TODO(design §9.1): the design has the CLI reach a running daemon over a local
// control socket (Unix domain socket, named pipe on Windows) with a per-datadir
// token, falling back to in-process when no daemon is running. Only the
// in-process path exists today; the seam is here, where a socket client would
// be tried first and this would stay as the fallback.
//
// TODO(design §9.3): one-shot mode over the network — open an endpoint, `Hello`
// any reachable trusted peer, pull just the Merkle path for the requested key,
// resolve holders with `FindProviders`, fetch, exit. The proof machinery
// (`synch_mpt::Proof`) and both `FindProviders`/`Providers` wire handlers are
// implemented and tested; what is missing is the orchestration here.
async fn open(cli: &Cli) -> Result<Node> {
    Node::open(node_config(cli)?)
        .await
        .context("could not open the node (run `synch init` first?)")
}

async fn dispatch(cli: &Cli, node: &Node) -> Result<()> {
    match &cli.command {
        Command::Init { .. } | Command::Doctor { .. } => unreachable!("handled before open"),

        Command::Id => {
            println!("origin: {}", node.origin());
            for key in node.store().device_keys()? {
                println!("  {} ({})", key.node_id.to_z32(), key.state.as_str());
            }
            println!("address: {}", render_addr(&node.net().direct_addr()));
        }

        Command::Key { command } => key_command(node, command)?,
        Command::Trust { command } => trust_command(node, command)?,
        Command::Domain { command } => domain_command(node, command).await?,
        Command::Space { command } => space_command(node, command)?,
        Command::Mirror { command } => mirror_command(node, command).await?,
        Command::Pin { command } => pin_command(node, command)?,

        Command::Daemon { command } => match command {
            DaemonCommand::Run => run_daemon(node).await?,
            DaemonCommand::Status => print_doctor(node)?,
        },

        Command::Peers => {
            let now = now_ns();
            for peer in node.store().peers_seen()? {
                let origins = node.store().live_origins_for_key(&peer.node_id, now)?;
                let names: Vec<String> = origins.iter().map(|o| o.canonical()).collect();
                println!(
                    "{}  {}  last-seen {}  last-sync {}  rtt {}µs",
                    peer.node_id.to_z32(),
                    if names.is_empty() {
                        "(untrusted)".to_string()
                    } else {
                        names.join(",")
                    },
                    ago(peer.last_seen),
                    ago(peer.last_sync),
                    peer.latency_ewma_us,
                );
            }
        }

        Command::Scan => {
            let (report, head) = node.scan_and_publish()?;
            println!(
                "hashed {} · unchanged {} · deleted {} · ignored {}",
                report.hashed, report.unchanged, report.deleted, report.ignored
            );
            for (path, reason) in &report.skipped {
                eprintln!("skipped {path}: {reason}");
            }
            match head {
                Some(head) => println!("published seq {} root {}", head.seq, head.root),
                None => println!("nothing changed"),
            }
        }

        Command::Ls { reference, all } => {
            let reference: EntryRef = reference.parse()?;
            let rows = node.store().list_entries(
                reference.origin.as_ref(),
                &reference.space,
                &reference.dir_prefix(),
                None,
                None,
            )?;
            let mut seen: Vec<&str> = Vec::new();
            for row in &rows {
                if !*all {
                    if seen.contains(&row.path.as_str()) {
                        continue;
                    }
                    seen.push(&row.path);
                }
                println!(
                    "{:>12}  {:<8}  {}  {}",
                    row.size,
                    kind_name(row.kind),
                    row.path,
                    row.origin.short()
                );
            }
        }

        Command::Status { reference } => {
            let (space, path) = match reference {
                Some(text) => {
                    let reference: EntryRef = text.parse()?;
                    (Some(reference.space), reference.path)
                }
                None => (None, String::new()),
            };
            let spaces = match space {
                Some(space) => vec![space],
                None => node.store().known_spaces()?,
            };
            for space in spaces {
                let rows = node.store().list_entries(None, &space, &path, None, None)?;
                let mut paths: Vec<String> = rows.iter().map(|r| r.path.clone()).collect();
                paths.sort();
                paths.dedup();
                for path in paths {
                    let views = node.store().entries_for_path(&space, &path)?;
                    let roots: std::collections::BTreeSet<Option<Hash>> =
                        views.iter().map(|v| v.content).collect();
                    let agreement = if roots.len() <= 1 {
                        "agree"
                    } else {
                        "DIVERGED"
                    };
                    println!("{space}/{path}  [{agreement}]");
                    for view in views {
                        println!(
                            "    {:<28} seq {:<6} {:>12}  {}",
                            view.origin.short(),
                            view.seq,
                            view.size,
                            view.content
                                .map(|h| h.to_hex()[..16].to_string())
                                .unwrap_or_else(|| kind_name(view.kind).to_string()),
                        );
                    }
                }
            }
        }

        Command::Cat { reference, range } => {
            let reference: EntryRef = reference.parse()?;
            let origin = reference
                .origin
                .clone()
                .context("cat needs an explicit <origin>:<space>/<path>")?;
            let range = match range {
                Some(text) => ByteRange::parse(text)?,
                None => ByteRange {
                    start: 0,
                    end: None,
                },
            };
            let bytes = node
                .read_entry_range(
                    &origin,
                    &reference.space,
                    &reference.path,
                    range.start,
                    range.len(),
                )
                .await?;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(&bytes)?;
            lock.flush()?;
        }

        Command::Get { reference, output } => {
            let reference: EntryRef = reference.parse()?;
            let origin = reference
                .origin
                .clone()
                .context("get needs an explicit <origin>:<space>/<path>")?;
            let bytes = node
                .read_entry(&origin, &reference.space, &reference.path)
                .await?;
            let target = match output {
                Some(path) => path.clone(),
                None => PathBuf::from(reference.path.rsplit('/').next().unwrap_or(&reference.path)),
            };
            std::fs::write(&target, &bytes)?;
            println!("wrote {} bytes to {}", bytes.len(), target.display());
        }

        Command::Take { reference } => {
            let reference: EntryRef = reference.parse()?;
            let origin = reference
                .origin
                .clone()
                .context("take needs an explicit <origin>:<space>/<path>")?;
            if origin == *node.origin() {
                bail!("that is already this node's own entry");
            }
            let bytes = node
                .read_entry(&origin, &reference.space, &reference.path)
                .await?;
            let path = node.adopt(&reference.space, &reference.path, &bytes)?;
            println!("adopted into {}", path.display());
            let (_report, head) = node.scan_and_publish()?;
            if let Some(head) = head {
                node.push_head(&head).await?;
                println!("published seq {}", head.seq);
            }
        }

        Command::Log { reference } => {
            let reference: EntryRef = reference.parse()?;
            if reference.path.is_empty() {
                bail!("log needs a path, not just a space");
            }
            let origins = match &reference.origin {
                Some(origin) => vec![origin.clone()],
                None => node
                    .store()
                    .entries_for_path(&reference.space, &reference.path)?
                    .into_iter()
                    .map(|r| r.origin)
                    .collect(),
            };
            let key = synch_core::file_key(&reference.space, &reference.path)?;
            let trie = synch_mpt::Trie::new(node.store().as_ref());
            for origin in origins {
                println!("{origin}");
                let mut roots = Vec::new();
                if let Some(head) = node.store().complete_head(&origin)? {
                    roots.push((head.seq, head.root));
                }
                for head in node.store().head_history(&origin)? {
                    roots.push((head.seq, head.root));
                }
                roots.sort_by_key(|r| std::cmp::Reverse(r.0));
                roots.dedup();
                let mut last: Option<Option<Vec<u8>>> = None;
                for (seq, root) in roots {
                    // Old roots are retained for `root_retention`, so history
                    // is a storage policy rather than a protocol constant.
                    let value = trie.get(root, &key).ok().flatten();
                    if last.as_ref() == Some(&value) {
                        continue;
                    }
                    match &value {
                        Some(bytes) => {
                            let entry = synch_engine::scanner::decode_entry(bytes)?;
                            println!(
                                "  seq {:<6} {:<10} {:>12}  {}",
                                seq,
                                kind_name(entry.kind),
                                entry.size,
                                entry
                                    .content
                                    .map(|h| h.to_hex()[..16].to_string())
                                    .unwrap_or_else(|| "-".into())
                            );
                        }
                        None => println!("  seq {seq:<6} (absent)"),
                    }
                    last = Some(value);
                }
            }
        }
    }
    Ok(())
}

fn key_command(node: &Node, command: &KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Ls => {
            for key in node.store().device_keys()? {
                println!("{} {}", key.node_id.to_z32(), key.state.as_str());
            }
        }
        KeyCommand::Rotate => {
            // §3.4 step 1: generate the new key, keep the old one active, and
            // print the record to publish. The switch-over happens once the new
            // binding is observed, not here.
            let new = SecretKey::generate();
            node.store()
                .add_device_key(&new, KeyState::Retiring, now_ns())?;
            println!("generated device key {}", new.public().to_z32());
            match node.origin().domain() {
                Some(domain) => {
                    let id = node.origin().canonical();
                    let id = id.split('@').next().unwrap_or(&id);
                    println!("publish alongside the existing record:");
                    println!(
                        "_synchronicity.{domain}. 300 IN TXT \"v=sync1 id={id} nk={}\"",
                        new.public().to_z32()
                    );
                    println!("then run `synch key retire <old-key>` once it has propagated");
                }
                None => println!(
                    "this origin is key-identified and cannot rotate; \
                     re-init with --id or have peers `synch trust add --as <name>`"
                ),
            }
        }
        KeyCommand::Retire { key } => {
            let key = NodeId::from_z32(key).context("not a z-base-32 device key")?;
            node.store().remove_device_key(&key)?;
            println!("removed the secret for {}", key.to_z32());
        }
    }
    Ok(())
}

fn trust_command(node: &Node, command: &TrustCommand) -> Result<()> {
    match command {
        TrustCommand::Add {
            key,
            name,
            domain,
            note,
            addr,
        } => {
            let key = NodeId::from_z32(key).context("not a z-base-32 device key")?;
            let origin =
                node.trust_add(key, name.as_deref(), domain.as_deref(), note.as_deref())?;
            if let Some(addr) = addr {
                let socket = addr.parse().context("--addr wants HOST:PORT")?;
                node.remember_peer(&iroh::EndpointAddr::new(key).with_ip_addr(socket))?;
            }
            println!("trusted {} as {origin}", key.to_z32());
        }
        TrustCommand::Rebind { origin, key } => {
            let origin = OriginId::from_str(origin)?;
            let key = NodeId::from_z32(key).context("not a z-base-32 device key")?;
            node.trust_rebind(&origin, key)?;
            println!("{origin} now also accepts {}", key.to_z32());
        }
        TrustCommand::Rm { origin } => {
            let origin = OriginId::from_str(origin)?;
            let removed = node.store().remove_origin_bindings(&origin)?;
            println!("removed {removed} binding(s) for {origin}");
        }
        TrustCommand::Ls => {
            let now = now_ns();
            for binding in node.store().bindings()? {
                println!(
                    "{:<32} {} {:<7} {}{}",
                    binding.origin.canonical(),
                    binding.node_id.to_z32(),
                    binding.source.as_str(),
                    if binding.is_live(now) {
                        "live"
                    } else {
                        "lapsed"
                    },
                    binding
                        .note
                        .as_ref()
                        .map(|n| format!("  ({n})"))
                        .unwrap_or_default(),
                );
            }
        }
    }
    Ok(())
}

async fn domain_command(node: &Node, command: &DomainCommand) -> Result<()> {
    match command {
        DomainCommand::Add { domain } => {
            node.add_domain(domain)?;
            println!("added {domain}");
            refresh_domains(node).await;
        }
        DomainCommand::Rm { domain } => {
            node.remove_domain(domain)?;
            println!("removed {domain} and its bindings");
        }
        DomainCommand::Ls => {
            for domain in node.domains()? {
                println!("{domain}");
            }
        }
        DomainCommand::Refresh => refresh_domains(node).await,
    }
    Ok(())
}

async fn refresh_domains(node: &Node) {
    let resolver = match synch_net::DnssecResolver::from_system() {
        Ok(resolver) => resolver,
        Err(e) => {
            eprintln!("no DNSSEC resolver available: {e}");
            return;
        }
    };
    match node.refresh_domains(&resolver).await {
        Ok(refreshes) => {
            for refresh in refreshes {
                println!(
                    "{}: {} binding(s), {} rejected record(s), ttl {}s",
                    refresh.domain,
                    refresh.bindings,
                    refresh.rejected,
                    refresh.ttl.as_secs()
                );
                for key in &refresh.ambiguous {
                    eprintln!(
                        "  ambiguous: {} appears under more than one id; \
                         an explicit --id is required",
                        key.to_z32()
                    );
                }
            }
        }
        Err(e) => eprintln!("refresh failed: {e}"),
    }
}

fn space_command(node: &Node, command: &SpaceCommand) -> Result<()> {
    match command {
        SpaceCommand::Add { id, path } => {
            node.add_space(id, path)?;
            println!("indexing {} as {id}", path.display());
        }
        SpaceCommand::Ls => {
            for space in node.store().spaces()? {
                println!("{:<20} {}", space.id, space.local_path);
            }
        }
        SpaceCommand::Rm { id } => {
            let staged = node.remove_space(id)?;
            let removed = staged.len();
            node.publish(staged)?;
            println!("removed {id} and unpublished {removed} record(s)");
        }
    }
    Ok(())
}

async fn mirror_command(node: &Node, command: &MirrorCommand) -> Result<()> {
    match command {
        MirrorCommand::Add { reference, path } => {
            let reference: EntryRef = reference.parse()?;
            let origin = reference
                .origin
                .clone()
                .context("mirror add needs <origin>:<space>")?;
            node.add_mirror(&origin, &reference.space, path)?;
            println!(
                "mirroring {origin}:{} into {}",
                reference.space,
                path.display()
            );
        }
        MirrorCommand::Rm { reference } => {
            let reference: EntryRef = reference.parse()?;
            let origin = reference
                .origin
                .clone()
                .context("mirror rm needs <origin>:<space>")?;
            if node.remove_mirror(&origin, &reference.space)? {
                println!("removed");
            } else {
                println!("no such mirror");
            }
        }
        MirrorCommand::Ls => {
            for mirror in node.store().mirrors()? {
                println!(
                    "{}:{:<20} {}",
                    mirror.origin.canonical(),
                    mirror.space,
                    mirror.local_path
                );
            }
        }
        MirrorCommand::Sync => {
            for (origin, space, report) in node.sync_all_mirrors().await? {
                println!(
                    "{origin}:{space}  written {} · current {} · removed {}",
                    report.written, report.current, report.removed
                );
                for (path, reason) in &report.skipped {
                    eprintln!("  skipped {path}: {reason}");
                }
            }
        }
    }
    Ok(())
}

fn pin_command(node: &Node, command: &PinCommand) -> Result<()> {
    match command {
        PinCommand::Add { root } => {
            let root = Hash::from_str(root).context("not a 64-character hex object root")?;
            node.store().set_pinned(&root, true)?;
            println!("pinned {root}");
        }
        PinCommand::Rm { root } => {
            let root = Hash::from_str(root).context("not a 64-character hex object root")?;
            node.store().set_pinned(&root, false)?;
            println!("unpinned {root}");
        }
        PinCommand::Ls => {
            for root in node.store().pinned_blobs()? {
                println!("{root}");
            }
        }
    }
    Ok(())
}

async fn run_daemon(node: &Node) -> Result<()> {
    println!(
        "origin {} on {}",
        node.origin(),
        render_addr(&node.net().direct_addr())
    );
    let (stop_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    let aae = {
        let node = node.clone();
        let mut rx = stop_tx.subscribe();
        tokio::spawn(async move {
            node.run_anti_entropy(async move {
                let _ = rx.recv().await;
            })
            .await
        })
    };
    let scanner = {
        let node = node.clone();
        let mut rx = stop_tx.subscribe();
        tokio::spawn(async move {
            node.run_scanner(async move {
                let _ = rx.recv().await;
            })
            .await
        })
    };
    let watcher = {
        let node = node.clone();
        let mut rx = stop_tx.subscribe();
        tokio::spawn(async move {
            node.run_watcher(async move {
                let _ = rx.recv().await;
            })
            .await
        })
    };
    let maintenance = {
        let node = node.clone();
        let mut rx = stop_tx.subscribe();
        tokio::spawn(async move {
            node.run_maintenance(async move {
                let _ = rx.recv().await;
            })
            .await
        })
    };

    // An initial scan and push, so a fresh daemon converges immediately rather
    // than waiting a full interval.
    if let Err(e) = node.scan_publish_push().await {
        tracing::warn!(error = %e, "initial scan failed");
    }

    tokio::signal::ctrl_c().await?;
    println!("shutting down");
    let _ = stop_tx.send(());
    let _ = tokio::join!(aae, scanner, watcher, maintenance);
    Ok(())
}

fn print_doctor(node: &Node) -> Result<()> {
    let report = node.doctor()?;
    println!("origin: {}", report.origin);
    for (key, state) in &report.device_keys {
        println!("  key {} ({state})", key.to_z32());
    }
    println!("address: {}", render_addr(&node.net().direct_addr()));

    println!("\nmembership:");
    if report.domains.is_empty() {
        println!("  (no DNSSEC domains configured; static trust only)");
    } else {
        for domain in &report.domains {
            println!("  domain {domain}");
        }
    }
    let now = now_ns();
    for binding in &report.bindings {
        println!(
            "  {:<32} {} {:<7} {}",
            binding.origin.canonical(),
            binding.node_id.to_z32(),
            binding.source.as_str(),
            if binding.is_live(now) {
                "live"
            } else {
                "LAPSED"
            },
        );
    }

    println!("\nheads:");
    for head in &report.heads {
        println!(
            "  {:<32} seq {:<8} {:<12} {:<10} {} entries",
            head.origin.canonical(),
            head.complete_seq
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            match head.pending_seq {
                Some(seq) => format!("pending {seq}"),
                None => String::new(),
            },
            if head.servable { "servable" } else { "PARTIAL" },
            head.entries,
        );
        if !head.bound {
            println!(
                "    ! no live binding: this origin's data stays unavailable \
                 until it republishes under a bound key"
            );
        }
    }

    if !report.unbound_origins.is_empty() {
        println!("\nunbound origins (see §3.4):");
        for origin in &report.unbound_origins {
            println!("  {origin}");
        }
    }

    if report.equivocations.is_empty() {
        println!("\nequivocation: none detected");
    } else {
        println!("\nEQUIVOCATION DETECTED:");
        for e in &report.equivocations {
            println!(
                "  {} signed {} roots at seq {}",
                e.origin,
                e.heads.len(),
                e.seq
            );
            for head in &e.heads {
                println!(
                    "    root {} signed by {}",
                    head.root,
                    head.signed_by.to_z32()
                );
            }
            println!("    likely cause: duplicate id assignment, or a restored database backup");
        }
    }

    if !report.lapsed.is_empty() {
        println!("\nlapsed bindings: {}", report.lapsed.len());
    }

    println!(
        "\nstorage: {} trie nodes, {} trie values, {} objects ({} complete)",
        report.trie.nodes, report.trie.values, report.blobs.0, report.blobs.1
    );
    Ok(())
}

fn render_addr(addr: &iroh::EndpointAddr) -> String {
    let parts: Vec<String> = addr
        .ip_addrs()
        .map(|a| a.to_string())
        .chain(addr.relay_urls().map(|u| u.to_string()))
        .collect();
    if parts.is_empty() {
        addr.id.to_z32()
    } else {
        format!("{} via {}", addr.id.to_z32(), parts.join(", "))
    }
}

fn kind_name(kind: synch_core::EntryKind) -> &'static str {
    match kind {
        synch_core::EntryKind::File => "file",
        synch_core::EntryKind::Dir => "dir",
        synch_core::EntryKind::Symlink => "symlink",
        synch_core::EntryKind::Tombstone => "deleted",
    }
}

fn ago(timestamp: i64) -> String {
    if timestamp == 0 {
        return "never".into();
    }
    let seconds = (now_ns() - timestamp) / 1_000_000_000;
    match seconds {
        s if s < 0 => "just now".into(),
        s if s < 60 => format!("{s}s ago"),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}
