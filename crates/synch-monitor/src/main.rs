//! `synch-monitor` — read the log, classify what names your zones.
//!
//! One run: fetch the checkpoint, verify it under the pinned log keys, check
//! that it extends the tree this monitor saw last time, then walk every entry
//! bundle from the last-seen index, pull the certificate out of each leaf, and
//! classify the ones naming a watched apex (docs/REKOR-ZONE-KEY.md §5.5).
//!
//! Exit codes are the interface a cron job or an alerting rule reads:
//!
//! ```text
//!  0  nothing new for a watched apex
//! 10  new tier A entries only — routine rotations, already countersigned
//! 20  tier C present — unauthorized claims naming a watched apex, no alarm
//! 30  tier B present — a chain-valid key nobody countersigned: LOOK
//!  2  the run could not finish (transport, checkpoint, state)
//! ```
//!
//! Tier B outranks tier C in that ordering because a run that found both is a
//! run that found tier B.

use std::path::PathBuf;

use clap::Parser;
use hickory_resolver::proto::dnssec::TrustAnchors;
use synch_monitor::{
    classify::{classify, Tier},
    state::MonitorState,
    tiles::{HttpTiles, Tree},
    MonitorError,
};
use synch_net::rekor::{Checkpoint, HashedRekordBody, LogKeys};

/// Watch a Rekor v2 transparency log for zone-key entries.
#[derive(Debug, Parser)]
#[command(name = "synch-monitor", version, about)]
struct Args {
    /// The log's base URL.
    #[arg(
        long,
        env = "SYNCH_MONITOR_LOG",
        default_value = "https://log2025-1.rekor.sigstore.dev"
    )]
    log: String,

    /// Where to persist the last checkpoint, the last index and known keys.
    #[arg(long, env = "SYNCH_MONITOR_STATE")]
    state: PathBuf,

    /// A file of log verification keys, *replacing* the embedded Sigstore
    /// set — the same "an override is a different universe" semantics the
    /// client's `--rekor-key` has.
    #[arg(long)]
    rekor_key: Option<PathBuf>,

    /// A DNSSEC trust anchor file, replacing the ICANN root. Only for a
    /// deployment whose zones are anchored somewhere else; a chain that does
    /// not reach the anchor in force is tier C.
    #[arg(long)]
    dnssec_anchor: Option<PathBuf>,

    /// Start here instead of at the persisted index. A fresh monitor for a
    /// log with 10⁸ entries in it wants a starting point that is not zero.
    #[arg(long)]
    from_index: Option<u64>,

    /// Stop after this many entries, so a first run can be bounded.
    #[arg(long)]
    max_entries: Option<u64>,

    /// Write the findings as JSON lines instead of one human line each.
    #[arg(long)]
    json: bool,

    /// Classify but do not persist: the dry run an operator does first.
    #[arg(long)]
    no_save: bool,
}

fn main() {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("synch-monitor: {e}");
            std::process::exit(2);
        }
    }
}

fn run(args: &Args) -> Result<i32, MonitorError> {
    let logs = match &args.rekor_key {
        Some(path) => LogKeys::from_file(path)
            .map_err(|e| MonitorError::Checkpoint(format!("{}: {e}", path.display())))?,
        None => LogKeys::embedded(),
    };
    let anchors = match &args.dnssec_anchor {
        Some(path) => TrustAnchors::from_file(path)
            .map_err(|e| MonitorError::State(format!("trust anchor {}: {e}", path.display())))?,
        None => TrustAnchors::default(),
    };

    let mut state = MonitorState::load(&args.state)?;
    if state.known.keys.is_empty() {
        return Err(MonitorError::State(format!(
            "{} names no apex to watch — seed it with the zones and keys you \
             already know, e.g. {{\"known\":{{\"keys\":{{\"sync.example.dev\":[]}}}}}}",
            args.state.display()
        )));
    }

    let source = HttpTiles::new(&args.log)?;
    let checkpoint = Checkpoint::parse(&source.checkpoint()?)
        .map_err(|e| MonitorError::Checkpoint(e.to_string()))?;
    checkpoint
        .verify_under(&logs)
        .map_err(|e| MonitorError::Checkpoint(e.to_string()))?;

    let tree = Tree::new(&source, checkpoint.tree_size);
    if tree
        .root()
        .map_err(|e| MonitorError::Checkpoint(e.to_string()))?
        != checkpoint.root_hash
    {
        return Err(MonitorError::Checkpoint(
            "the tree the tiles describe does not hash to the checkpoint's root".into(),
        ));
    }

    // Consistency: the root this monitor persisted, recomputed from the *new*
    // tree's tiles. A log that cannot reproduce its own past has shown two
    // histories, and nothing below this line would be worth reading.
    if !state.is_fresh() {
        if state.origin != checkpoint.origin {
            return Err(MonitorError::Checkpoint(format!(
                "this state is for {}, the log now calls itself {}",
                state.origin, checkpoint.origin
            )));
        }
        if checkpoint.tree_size < state.tree_size {
            return Err(MonitorError::Checkpoint(format!(
                "the log shrank from {} to {} entries",
                state.tree_size, checkpoint.tree_size
            )));
        }
        let prefix = tree
            .subtree_hash(0, state.tree_size)
            .map_err(|e| MonitorError::Checkpoint(e.to_string()))?;
        if hex::encode(prefix) != state.root {
            return Err(MonitorError::Checkpoint(format!(
                "the tree of {} entries does not extend the {} this monitor saw: \
                 the log has equivocated",
                checkpoint.tree_size, state.tree_size
            )));
        }
    }

    let mut at = args.from_index.unwrap_or(state.next_index);
    let end = match args.max_entries {
        Some(max) => checkpoint.tree_size.min(at + max),
        None => checkpoint.tree_size,
    };
    let mut findings = Vec::new();
    while at < end {
        for (index, body) in tree.entry_bundle(at)? {
            if index < at || index >= end {
                continue;
            }
            let Ok(parsed) = HashedRekordBody::parse(&body) else {
                // Almost every entry in a public log is somebody else's, in
                // a shape this design says nothing about. Not an event.
                continue;
            };
            let Some(name) = parsed.certificate.single_dns_name().ok() else {
                continue;
            };
            if !state
                .known
                .apexes()
                .any(|apex| synch_net::x509::same_dns_name(apex, name))
            {
                continue;
            }
            // A watched apex: prove the leaf really is this entry before
            // reading anything out of it, then classify.
            if !tree.leaf_matches(index, &body)? {
                return Err(MonitorError::Tile(format!(
                    "entry {index} does not hash to the leaf the log stored"
                )));
            }
            let path = tree.inclusion_path(index)?;
            synch_net::rekor::verify_inclusion(
                index,
                checkpoint.tree_size,
                synch_net::rekor::leaf_hash(&body),
                &path,
                checkpoint.root_hash,
            )
            .map_err(|e| MonitorError::Tile(e.to_string()))?;
            if let Some(finding) = classify(&parsed, index, &state.known, &anchors) {
                findings.push((finding, parsed.certificate.spki.clone()));
            }
        }
        at = ((at / 256) + 1) * 256;
    }

    for (finding, _) in &findings {
        match args.json {
            true => println!(
                "{}",
                serde_json::to_string(finding).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
            ),
            false => println!("{}", finding.line()),
        }
    }

    // Only a tier A key becomes a trusted predecessor. Promoting tier B would
    // hand an attacker a foothold: their first substituted key would become
    // the known predecessor that makes their second one look routine.
    for (finding, spki) in &findings {
        if finding.tier == Tier::A {
            state.known.insert(&finding.apex, spki);
        }
    }
    state.origin = checkpoint.origin.clone();
    state.tree_size = checkpoint.tree_size;
    state.root = hex::encode(checkpoint.root_hash);
    state.next_index = end;
    if !args.no_save {
        state.save(&args.state)?;
    }

    let worst = findings.iter().map(|(f, _)| f.tier).max();
    eprintln!(
        "synch-monitor: {} entries read to index {end}, {} finding(s)",
        end.saturating_sub(args.from_index.unwrap_or(0)),
        findings.len()
    );
    Ok(match worst {
        None => 0,
        Some(Tier::A) => 10,
        Some(Tier::C) => 20,
        Some(Tier::B) => 30,
    })
}
