//! `synch-monitor` — read the log, classify what names your zones.
//!
//! One run: fetch the checkpoint, verify it under the pinned log keys, check
//! that it extends the tree this monitor saw last time, then walk every entry
//! bundle from the last-seen index, pull the certificate out of each leaf, and
//! classify the ones naming a watched apex (docs/REKOR-ZONE-KEY.md §5.5).
//!
//! **The product is the list of newly authorized keys.** A tier A entry whose
//! key this monitor has not recorded for that apex is a new authorization: it
//! goes to stdout, and is then recorded so the next run does not repeat it. A
//! tier A entry for a key already recorded has been reported before and is
//! not reported again. Tier B — an unauthorized claim no client would have
//! accepted — goes to stderr as a note and is never recorded, because
//! recording it would suppress the report if the same key later showed up
//! with a chain that does verify.
//!
//! stdout is therefore the report and nothing else; stderr is the running
//! commentary. A cron job that mails stdout mails exactly the events that
//! need a human.
//!
//! Exit codes are the interface a cron job or an alerting rule reads:
//!
//! ```text
//!  0  nothing new for a watched apex
//! 10  unauthorized claims only — tier B naming a watched apex, no alarm
//! 20  new authorizations seen — a key was authorized for a watched apex
//!     that this monitor had not recorded: check it against what you published
//!  2  the run could not finish (transport, checkpoint, state)
//! ```
//!
//! They are ordered by severity, so a rule testing `>=` reads correctly.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use futures_util::stream::StreamExt;
use hickory_resolver::proto::dnssec::TrustAnchors;
use synch_monitor::{
    classify::{classify, Finding, Tier},
    discover::{self, HttpRepo},
    state::MonitorState,
    tiles::{HttpTiles, Tree},
    MonitorError,
};
use synch_net::rekor::{Checkpoint, HashedRekordBody, LogKeys};

/// Seconds since the epoch — what TUF's expiry and validity windows are read
/// against.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A duration for a progress line, rounded to what fits in a few characters.
fn rough_eta(secs: u64) -> String {
    match secs {
        0..=89 => format!("{secs}s"),
        90..=3599 => format!("{}m{:02}s", secs / 60, secs % 60),
        _ => format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60),
    }
}

/// Watch a Rekor v2 transparency log for zone-key entries.
///
/// Reports every newly authorized zone key for a watched apex: an entry whose
/// DNSSEC chain verifies and covers its own key authorizes that key, and the
/// first time this monitor sees one it says so. It cannot tell a rotation you
/// performed from a substitution by somebody who took your registrar — an
/// attacker with the DS builds the same chain — so it reports the
/// authorization and leaves the judgement to your own record of what you
/// published.
///
/// New authorizations go to stdout, one line each; everything else to stderr.
#[derive(Debug, Parser)]
#[command(
    name = "synch-monitor",
    version,
    about,
    after_long_help = "EXIT CODES:
   0  nothing new for a watched apex
  10  unauthorized claims only — entries naming a watched apex whose chain
      does not verify. No client would have accepted one; recorded, no alarm.
  20  new authorizations seen — a key was authorized for a watched apex that
      this monitor had not recorded. Check it against what you published.
   2  the run could not finish (transport, checkpoint, state)"
)]
struct Args {
    /// The log's base URL. Discovered from Sigstore's TUF repository when
    /// not given, which is how a monitor survives a shard rotation.
    #[arg(long, env = "SYNCH_MONITOR_LOG")]
    log: Option<String>,

    /// Where to persist the last checkpoint, the last index, the apexes to
    /// watch and the keys already reported for each.
    #[arg(long, env = "SYNCH_MONITOR_STATE")]
    state: PathBuf,

    /// The TUF repository to discover the log and its keys from.
    #[arg(long, env = "SYNCH_MONITOR_TUF", default_value = synch_net::tuf::SIGSTORE_TUF_URL)]
    tuf: String,

    /// Do not contact the TUF repository: run on the pins already persisted,
    /// or on the embedded bootstrap trusted root if there are none.
    #[arg(long)]
    no_tuf: bool,

    /// Where to persist the TUF pin state. Defaults to `rekor-pins.json`
    /// beside the state file, the name the client uses too.
    #[arg(long)]
    rekor_pins: Option<PathBuf>,

    /// A file of log verification keys, *replacing* the discovered set —
    /// the same "an override is a different universe" semantics the
    /// client's `--rekor-key` has.
    #[arg(long)]
    rekor_key: Option<PathBuf>,

    /// A DNSSEC trust anchor file, replacing the ICANN root. Only for a
    /// deployment whose zones are anchored somewhere else; a chain that does
    /// not reach the anchor in force is tier B.
    #[arg(long)]
    dnssec_anchor: Option<PathBuf>,

    /// Start here instead of at the persisted index. A fresh monitor for a
    /// log with 10⁸ entries in it wants a starting point that is not zero.
    #[arg(long)]
    from_index: Option<u64>,

    /// Stop after this many entries, so a first run can be bounded.
    #[arg(long)]
    max_entries: Option<u64>,

    /// How many tile fetches may be in flight at once. A full-history
    /// catch-up on a big log is hundreds of thousands of bundles, which at
    /// one request per round-trip is most of a day; the default keeps that
    /// in minutes while staying polite to a free, community-run log.
    #[arg(
        long,
        env = "SYNCH_MONITOR_CONCURRENCY",
        default_value_t = std::num::NonZeroUsize::new(8).unwrap()
    )]
    concurrency: std::num::NonZeroUsize,

    /// Write the findings as JSON lines instead of one human line each.
    #[arg(long)]
    json: bool,

    /// Classify but do not record: the dry run an operator does first.
    ///
    /// Nothing is written to the state file, so the same new authorizations
    /// are reported again on the next run — which is what makes it a dry run
    /// rather than a run that silently consumed the news.
    #[arg(long)]
    no_save: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    match run(&args).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("synch-monitor: {e}");
            std::process::exit(2);
        }
    }
}

async fn run(args: &Args) -> Result<i32, MonitorError> {
    let keys_override = match &args.rekor_key {
        Some(path) => Some(
            LogKeys::from_file(path)
                .map_err(|e| MonitorError::Checkpoint(format!("{}: {e}", path.display())))?,
        ),
        None => None,
    };
    let anchors = match &args.dnssec_anchor {
        Some(path) => TrustAnchors::from_file(path)
            .map_err(|e| MonitorError::State(format!("trust anchor {}: {e}", path.display())))?,
        None => TrustAnchors::default(),
    };

    // Everything local before anything remote: an unseeded state file is the
    // first-run mistake, and finding out about it after a TUF walk and a
    // checkpoint fetch would be a slower way to learn the same thing.
    let mut state = MonitorState::load(&args.state)?;
    if state.known.keys.is_empty() {
        return Err(MonitorError::State(format!(
            "{} names no apex to watch — seed it with the zones you want \
             reported on, and (optionally) the keys you have already accounted \
             for, e.g. {{\"known\":{{\"keys\":{{\"sync.example\":[]}}}}}}",
            args.state.display()
        )));
    }

    // Discovery decides both which log this run reads and which keys its
    // checkpoint must verify under, and the two come from one trusted root —
    // a pin set from one artifact and an endpoint from another is how a
    // rotation ends up looking like an equivocation.
    //
    // It runs on a blocking thread: `synch_net::tuf::Repo` is a synchronous
    // trait and HttpRepo a blocking client, which suits a handful of
    // sequential fetches made once per run — but a blocking reqwest call
    // panics on a runtime thread, so it cannot run in place.
    let pins = match &args.rekor_pins {
        Some(path) => path.clone(),
        None => discover::pins_beside(&args.state),
    };
    let (tuf, no_tuf, log, now) = (
        args.tuf.clone(),
        args.no_tuf,
        args.log.clone(),
        now_unix(),
    );
    let found = tokio::task::spawn_blocking(move || {
        let repo = match no_tuf {
            true => None,
            false => Some(HttpRepo::new(&tuf)?),
        };
        discover::discover(
            repo.as_ref().map(|repo| repo as &dyn synch_net::tuf::Repo),
            &pins,
            log.as_deref(),
            keys_override,
            now,
            &mut |warning| eprintln!("synch-monitor: {warning}"),
        )
    })
    .await
    .map_err(|e| MonitorError::Transport(format!("discovery: {e}")))??;
    eprintln!(
        "synch-monitor: reading {} (via {})",
        found.base_url, found.source
    );
    let logs = found.keys;

    let source = HttpTiles::new(&found.base_url)?;
    let checkpoint = Checkpoint::parse(&source.checkpoint().await?)
        .map_err(|e| MonitorError::Checkpoint(e.to_string()))?;
    checkpoint
        .verify_under(&logs)
        .map_err(|e| MonitorError::Checkpoint(e.to_string()))?;

    let tree = Tree::new(&source, checkpoint.tree_size, args.concurrency.get());
    if tree
        .root()
        .await
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
            .await
            .map_err(|e| MonitorError::Checkpoint(e.to_string()))?;
        if hex::encode(prefix) != state.root {
            return Err(MonitorError::Checkpoint(format!(
                "the tree of {} entries does not extend the {} this monitor saw: \
                 the log has equivocated",
                checkpoint.tree_size, state.tree_size
            )));
        }
    }

    // A from-index *ahead* of where this monitor stopped leaves a range that
    // will never be classified: the run writes `next_index = end` back, so
    // the gap is skipped permanently and silently. Bounded first runs want
    // this; a resuming monitor almost never does, so say so out loud.
    if let Some(from) = args.from_index {
        if from > state.next_index {
            eprintln!(
                "synch-monitor: starting at {from}, past the recorded {}: \
                 entries {}..{from} will never be classified",
                state.next_index, state.next_index
            );
        }
    }
    let started_at = args.from_index.unwrap_or(state.next_index);
    let end = match args.max_entries {
        // Saturating: `--from-index` and `--max-entries` are both operator
        // input, and their sum is not bounded by anything but the CLI.
        Some(max) => checkpoint.tree_size.min(started_at.saturating_add(max)),
        None => checkpoint.tree_size,
    };
    let total = end.saturating_sub(started_at);
    if total > 0 {
        eprintln!(
            "synch-monitor: reading entries {started_at}..{end} ({total} to classify), \
             {} fetch(es) in flight",
            args.concurrency
        );
    }
    let scan_started = Instant::now();
    let mut last_progress = scan_started;
    let mut findings = Vec::new();
    // Bundles arrive strictly in index order, however far fetching has run
    // ahead — the findings and the bookkeeping are exactly as a serial scan
    // would produce them.
    let mut bundles = tree.bundle_stream(started_at, end);
    while let Some(bundle) = bundles.next().await {
        let entries = bundle?;
        for (index, body) in &entries {
            let index = *index;
            if index < started_at || index >= end {
                continue;
            }
            let Ok(parsed) = HashedRekordBody::parse(body) else {
                // Almost every entry in a public log is somebody else's, in
                // a shape this design says nothing about. Not an event.
                continue;
            };
            // Parsed, never trimmed. The watch filter and the chain walk
            // have to agree on what a name is, or an entry can be recognised
            // as belonging to a watched zone and then classified against a
            // different one (see `synch_net::chain::authorize`).
            let Ok(name) = parsed.certificate.single_dns_name() else {
                continue;
            };
            if !state.known.watches(&name) {
                continue;
            }
            // A watched apex: prove the leaf really is this entry before
            // reading anything out of it, then classify.
            if !tree.leaf_matches(index, body).await? {
                return Err(MonitorError::Tile(format!(
                    "entry {index} does not hash to the leaf the log stored"
                )));
            }
            let path = tree.inclusion_path(index).await?;
            synch_net::rekor::verify_inclusion(
                index,
                checkpoint.tree_size,
                synch_net::rekor::leaf_hash(body),
                &path,
                checkpoint.root_hash,
            )
            .map_err(|e| MonitorError::Tile(e.to_string()))?;
            if let Some(finding) = classify(&parsed, index, &anchors) {
                findings.push(finding);
            }
        }
        let covered = entries
            .last()
            .map(|(last, _)| last + 1)
            .unwrap_or(started_at)
            .min(end);
        let read = covered.saturating_sub(started_at);
        if last_progress.elapsed() >= Duration::from_secs(10) {
            let rate = read as f64 / scan_started.elapsed().as_secs_f64();
            let eta = match rate > 0.0 {
                true => rough_eta(((total - read) as f64 / rate) as u64),
                false => "unknown".to_string(),
            };
            eprintln!("synch-monitor: {read}/{total} entries ({rate:.0}/s, eta {eta})");
            last_progress = Instant::now();
        }
    }

    // Sort the classified entries into the three things a run can have found.
    //
    // The "already reported" test runs against the state as it was *loaded*,
    // and recording happens after the whole batch is decided — so two entries
    // in one run that authorize the same key report once, and an entry does
    // not suppress itself.
    let mut new_authorizations = Vec::new();
    let mut already_known = 0usize;
    let mut claims = Vec::new();
    for finding in &findings {
        match finding.tier {
            Tier::A => {
                let apex = synch_net::chain::parse_name(&finding.apex);
                // An entry is news when *any* key its chain proves has not
                // been reported yet — a rotation that pre-publishes one new
                // key beside a known one is exactly the event to hear about.
                // A tier A finding always came from a parsed SAN, so parsing
                // cannot fail; treating an unparseable one as *new* rather
                // than as known is the safe direction anyway — it reports.
                let all_known = apex.is_ok_and(|apex| {
                    finding
                        .keys
                        .iter()
                        .all(|key| state.known.contains_digest(&apex, &key.sha256))
                });
                match all_known {
                    true => already_known += 1,
                    false => new_authorizations.push(finding),
                }
            }
            Tier::B => claims.push(finding),
        }
    }

    // stdout is the report: newly authorized keys, and nothing else.
    for finding in &new_authorizations {
        println!("{}", render(finding, args.json));
    }
    // Tier B on stderr. It is not an alarm — no client would have taken these
    // — but an operator who sees the exit code needs to be able to see *what*
    // was claimed without re-running with different flags.
    for finding in &claims {
        eprintln!("{}", render(finding, args.json));
    }

    // Record what was reported, so the next run stays quiet about it. Tier B
    // is deliberately never recorded: the same key arriving later with a
    // chain that *does* verify is a genuine new authorization, and a tier B
    // sighting must not have quietly consumed it.
    for finding in &new_authorizations {
        if let Ok(apex) = synch_net::chain::parse_name(&finding.apex) {
            for key in &finding.keys {
                state.known.insert_digest(&apex, &key.sha256);
            }
        }
    }
    state.origin = checkpoint.origin.clone();
    state.tree_size = checkpoint.tree_size;
    state.root = hex::encode(checkpoint.root_hash);
    state.next_index = end;
    if !args.no_save {
        state.save(&args.state)?;
    }

    eprintln!(
        "synch-monitor: {} entries read to index {end} in {:.0}s; {} new authorization(s), \
         {already_known} already recorded, {} unauthorized claim(s)",
        end.saturating_sub(started_at),
        scan_started.elapsed().as_secs_f64(),
        new_authorizations.len(),
        claims.len()
    );
    Ok(match (new_authorizations.is_empty(), claims.is_empty()) {
        (false, _) => 20,
        (true, false) => 10,
        (true, true) => 0,
    })
}

/// One finding, as a line — JSON when asked, human otherwise.
fn render(finding: &Finding, json: bool) -> String {
    match json {
        true => serde_json::to_string(finding).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
        false => finding.line(),
    }
}
