//! `synch-monitor` — read the log, classify what names your zones.
//!
//! Two subcommands. `run` is the watcher: fetch the checkpoint, verify it
//! under the pinned log keys, check that it extends the tree this monitor
//! saw last time, then walk every entry bundle from the last-seen index,
//! pull the certificate out of each leaf, and classify the ones naming a
//! watched apex (docs/REKOR-ZONE-KEY.md §5.5). Every finding's full entry
//! body goes into the state file with it, and `entry` is the evidence
//! drawer: print one of those bodies by index, a local read rather than a
//! re-fetch from the log under watch.
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
//! 30  the run could not finish (transport, checkpoint, state)
//! ```
//!
//! They are ordered by severity, so a rule testing `>=` reads correctly —
//! and **that ordering is why a failed run is 30 and not 2.** A monitor that
//! cannot finish is not a monitor with nothing to say: it is the state an
//! attacker most wants it in, because a wedged run and a quiet run look
//! identical from the outside. With failure sorted below the success codes,
//! the `>= 10` rule these docs invite ignored every failed run, which is
//! exactly backwards.
//!
//! A run that fails partway still prints and records everything it
//! classified before the failure, so an alarming entry found at index N is
//! not lost to a transport error at index N+1.

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
#[derive(Debug, Parser)]
#[command(name = "synch-monitor", version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Watch a Rekor v2 transparency log for zone-key entries.
    ///
    /// Reports every newly authorized zone key for a watched apex: an entry
    /// whose DNSSEC chain verifies and covers its own key authorizes that
    /// key, and the first time this monitor sees one it says so. It cannot
    /// tell a rotation you performed from a substitution by somebody who
    /// took your registrar — an attacker with the DS builds the same chain —
    /// so it reports the authorization and leaves the judgement to your own
    /// record of what you published.
    ///
    /// New authorizations go to stdout, one line each; everything else to
    /// stderr.
    #[command(after_long_help = "EXIT CODES:
   0  nothing new for a watched apex
  10  unauthorized claims only — entries naming a watched apex whose chain
      does not verify. No client would have accepted one; recorded, no alarm.
  20  new authorizations seen — a key was authorized for a watched apex that
      this monitor had not recorded. Check it against what you published.
  30  the run could not finish (transport, checkpoint, state). Sorts above
      the others on purpose: a wedged monitor is not a quiet one. Anything
      classified before the failure is still reported.")]
    Run(RunArgs),
    /// Print the full body of a log entry the state file holds: the evidence
    /// behind a finding, by its log index — with --log naming the shard when
    /// more than one holds that index. stdout is the raw entry bytes — the
    /// canonicalized Rekor body, nothing added — so it pipes into jq or a
    /// file byte-exactly.
    Entry(EntryArgs),
}

/// `run`'s flags.
#[derive(Debug, clap::Args)]
struct RunArgs {
    /// The log's base URL. Discovered from Sigstore's TUF repository when
    /// not given, which is how a monitor survives a shard rotation.
    #[arg(long, env = "SYNCH_MONITOR_LOG")]
    log: Option<String>,

    /// Where to persist the last checkpoint, the last index, the apexes to
    /// watch, the keys already reported for each, and the entry bodies
    /// behind the reports.
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

/// A run that could not finish. **Above** the success codes, not below
/// them: the codes are documented as severity-ordered so that `>= 10` reads
/// correctly, and a monitor that cannot complete is not a monitor with
/// nothing to report — it is the state an attacker most wants it in. At the
/// old value of 2 it sorted below "nothing new", so the alerting rule the
/// docs invite ignored precisely the runs that needed a human.
const EXIT_INCOMPLETE: i32 = 30;

/// `entry`'s arguments.
#[derive(Debug, clap::Args)]
struct EntryArgs {
    /// The log index to print.
    index: u64,

    /// Where the monitor's state — and its stored entry bodies — live.
    #[arg(long, env = "SYNCH_MONITOR_STATE")]
    state: PathBuf,

    /// The log the index belongs to, by origin line (e.g.
    /// "log2025-1.rekor.sigstore.dev"). Needed only when the state holds
    /// that index under more than one log — the error says so when it does.
    #[arg(long)]
    log: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let result = match Args::parse().command {
        Command::Run(args) => run(&args).await,
        Command::Entry(args) => dump_entry(&args),
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("synch-monitor: {e}");
            std::process::exit(EXIT_INCOMPLETE);
        }
    }
}

/// `entry`: the evidence half of the state file, back out. stdout gets the
/// raw body and nothing else, so it pipes byte-exactly.
fn dump_entry(args: &EntryArgs) -> Result<i32, MonitorError> {
    use std::io::Write;
    let state = MonitorState::load(&args.state)?;
    // An index names an entry only with its log: two shards both have an
    // entry 68,295,246, and they are not the same entry. With --log the
    // question is direct; without it, an index exactly one log holds is
    // unambiguous.
    let origin = match &args.log {
        Some(origin) => origin.clone(),
        None => match state.origins_holding(args.index).as_slice() {
            [only] => only.to_string(),
            [] => {
                let held = match state.entries.is_empty() {
                    true => "it holds none".to_string(),
                    false => format!(
                        "it holds bodies under: {}",
                        state.entries.keys().cloned().collect::<Vec<_>>().join(", ")
                    ),
                };
                return Err(MonitorError::State(format!(
                    "no entry {} in {} — {held}",
                    args.index,
                    args.state.display()
                )));
            }
            several => {
                return Err(MonitorError::State(format!(
                    "entry {} is held under several logs ({}) — name one with --log",
                    args.index,
                    several.join(", ")
                )));
            }
        },
    };
    let body = state.entry(&origin, args.index)?.ok_or_else(|| {
        MonitorError::State(format!(
            "no entry {} from {origin} in {}",
            args.index,
            args.state.display()
        ))
    })?;
    std::io::stdout()
        .write_all(&body)
        .map_err(|e| MonitorError::State(format!("writing stdout: {e}")))?;
    Ok(0)
}

async fn run(args: &RunArgs) -> Result<i32, MonitorError> {
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
    let (tuf, no_tuf, log, now) = (args.tuf.clone(), args.no_tuf, args.log.clone(), now_unix());
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
        "synch-monitor: reading {} log(s) (via {}): {}",
        found.base_urls.len(),
        found.source,
        found.base_urls.join(", ")
    );
    let logs = found.keys;

    // The "already reported" test runs against the state as it was *loaded*,
    // so two entries in one run that authorize the same key report once, an
    // entry does not suppress itself, and — now that a run reads several
    // logs — the same key turning up in two shards reports once rather than
    // once per shard.
    let known_at_start = state.known.clone();

    // Every log the trusted root names, not just the one in service.
    let mut findings = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for base_url in &found.base_urls {
        match walk_log(base_url, &logs, &anchors, &known_at_start, &mut state, args).await {
            Ok(found_here) => findings.extend(found_here),
            Err(e) => {
                // One unreadable shard must not cost the report from the
                // others: a retired log whose tiles have been taken down is
                // an ordinary thing to meet, and the busy shard is where the
                // news usually is. The run still ends incomplete.
                eprintln!("synch-monitor: {base_url}: {e}");
                failures.push(base_url.clone());
            }
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
                        .all(|key| known_at_start.contains_digest(&apex, &key.sha256))
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
    if !args.no_save {
        // A save failure must not swallow the report either: it is printed
        // by now, so say so and carry on to the exit code.
        if let Err(e) = state.save(&args.state) {
            eprintln!("synch-monitor: could not write the state file: {e}");
            return Ok(EXIT_INCOMPLETE);
        }
    }
    if !failures.is_empty() {
        eprintln!(
            "synch-monitor: {} of {} log(s) could not be read ({}); \
             {} finding(s) above came from the rest",
            failures.len(),
            found.base_urls.len(),
            failures.join(", "),
            findings.len()
        );
        return Ok(EXIT_INCOMPLETE);
    }

    eprintln!(
        "synch-monitor: {} log(s) read; {} new authorization(s), \
         {already_known} already recorded, {} unauthorized claim(s)",
        found.base_urls.len(),
        new_authorizations.len(),
        claims.len()
    );
    if !findings.is_empty() && !args.no_save {
        eprintln!(
            "synch-monitor: the full body of every finding is in the state file — \
             `synch-monitor entry <INDEX>` prints one"
        );
    }
    Ok(match (new_authorizations.is_empty(), claims.is_empty()) {
        (false, _) => 20,
        (true, false) => 10,
        (true, true) => 0,
    })
}

/// Reads one log end to end: checkpoint, consistency, then every entry from
/// where this monitor last stopped.
///
/// Returns what it classified. A failure partway is an error, but whatever
/// was classified before it is *not* lost — the caller keeps the findings
/// and the position it wrote, and only the exit code records that the
/// run was incomplete.
/// One log, walked end to end.
///
/// Extracted per log because a run reads *every* log the trusted root names
/// (§10): the position, the consistency proof and the resume index are all
/// per-log, keyed on the checkpoint's origin line.
async fn walk_log(
    base_url: &str,
    logs: &LogKeys,
    anchors: &TrustAnchors,
    known: &synch_monitor::classify::KnownKeys,
    state: &mut MonitorState,
    args: &RunArgs,
) -> Result<Vec<Finding>, MonitorError> {
    let source = HttpTiles::new(base_url)?;
    let checkpoint = Checkpoint::parse(&source.checkpoint().await?)
        .map_err(|e| MonitorError::Checkpoint(e.to_string()))?;
    // Under *any* pinned key: which log signed it is settled by the origin
    // line the position is then keyed on, and a checkpoint no pinned key
    // signed is not one this client would have believed either.
    checkpoint
        .verify_under(logs)
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

    let position = state.position(&checkpoint.origin).clone();

    // Consistency: the root this monitor persisted for *this* log,
    // recomputed from the new tree's tiles. A log that cannot reproduce its
    // own past has shown two histories, and nothing below is worth reading.
    if !position.is_fresh() {
        if checkpoint.tree_size < position.tree_size {
            return Err(MonitorError::Checkpoint(format!(
                "the log shrank from {} to {} entries",
                position.tree_size, checkpoint.tree_size
            )));
        }
        let prefix = tree
            .subtree_hash(0, position.tree_size)
            .await
            .map_err(|e| MonitorError::Checkpoint(e.to_string()))?;
        if hex::encode(prefix) != position.root {
            return Err(MonitorError::Checkpoint(format!(
                "the tree of {} entries does not extend the {} this monitor saw: \
                 the log has equivocated",
                checkpoint.tree_size, position.tree_size
            )));
        }
    }

    // A from-index *ahead* of where this monitor stopped leaves a range that
    // will never be classified. Bounded first runs want this; a resuming
    // monitor almost never does, so say so out loud.
    if let Some(from) = args.from_index {
        if from > position.next_index {
            eprintln!(
                "synch-monitor: {base_url}: starting at {from}, past the recorded {}: \
                 entries {}..{from} will never be classified",
                position.next_index, position.next_index
            );
        }
    }
    let started_at = args.from_index.unwrap_or(position.next_index);
    let end = match args.max_entries {
        // Saturating: `--from-index` and `--max-entries` are both operator
        // input, and their sum is not bounded by anything but the CLI.
        Some(max) => checkpoint.tree_size.min(started_at.saturating_add(max)),
        None => checkpoint.tree_size,
    };
    // How far the walk actually got, and the resume point when it fails
    // partway: saving `end` would step over entries the run never
    // classified, saving `started_at` would re-read work already reported.
    let mut at = started_at;

    let total = end.saturating_sub(started_at);
    if total > 0 {
        eprintln!(
            "synch-monitor: {base_url}: reading entries {started_at}..{end} \
             ({total} to classify), {} fetch(es) in flight",
            args.concurrency
        );
    }
    let scan_started = Instant::now();
    let mut last_progress = scan_started;
    // The walk runs inside an async block so that a failure partway through
    // does not take the findings with it. A monitor that read an alarming
    // entry at index N and then hit a 503 at N+1 used to print nothing at
    // all and exit as a failure — the one outcome that must never be silent
    // was the easiest to silence. Everything classified before the error is
    // returned and recorded; the error decides the exit code, not whether
    // the news gets out.
    let mut findings = Vec::new();
    let outcome: Result<(), MonitorError> = async {
        // Bundles arrive strictly in index order, however far fetching has
        // run ahead — the findings and the bookkeeping are exactly as a
        // serial scan would produce them.
        let mut bundles = tree.bundle_stream(started_at, end);
        while let Some(bundle) = bundles.next().await {
            let entries = bundle?;
            for (index, body) in &entries {
                let index = *index;
                if index < started_at || index >= end {
                    continue;
                }
                // **Before anything is read out of it, and before any
                // decision to skip it.** The hash tiles are checked against
                // the signed checkpoint; the entry bundles are a separate
                // resource served by the same party this monitor exists to
                // audit, and nothing else binds them to the tree.
                //
                // Deciding to *skip* on unauthenticated bytes is the whole
                // attack: a log that replaces one body with something that
                // fails to parse, or that names an unwatched zone, hides the
                // entry while its hash tiles stay honest — so every root and
                // consistency check still passes, and the victim's client,
                // whose proof carries a real path to the real leaf, still
                // accepts it. Silent monitor, working forgery. Costs one
                // level-0 hash tile per 256 entries, cached.
                if !tree.leaf_matches(index, body).await? {
                    return Err(MonitorError::Tile(format!(
                        "entry {index} does not hash to the leaf the log stored"
                    )));
                }
                let Ok(parsed) = HashedRekordBody::parse(body) else {
                    // Almost every entry in a public log is somebody else's,
                    // in a shape this design says nothing about. Not an event.
                    continue;
                };
                // Parsed, never trimmed. The watch filter and the chain walk
                // have to agree on what a name is, or an entry can be
                // recognised as belonging to a watched zone and then
                // classified against a different one (see
                // `synch_net::chain::authorize`).
                let Ok(name) = parsed.certificate.single_dns_name() else {
                    continue;
                };
                if !known.watches(&name) {
                    continue;
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
                if let Some(finding) = classify(&parsed, index, anchors) {
                    findings.push(finding);
                    // The evidence goes into the state with the finding:
                    // the full entry body under this log's origin, so "what
                    // exactly does the log hold for this report" stays a
                    // local lookup, never a re-fetch from the log under
                    // watch. A body here is not the recording tier B is
                    // denied — that rule is about the known-keys memory,
                    // and evidence suppresses nothing.
                    state.record_entry(&checkpoint.origin, index, body);
                }
            }
            let covered = entries
                .last()
                .map(|(last, _)| last + 1)
                .unwrap_or(started_at)
                .min(end);
            // Only once the whole bundle is through: a failure mid-bundle
            // leaves `at` at the previous boundary, so the next run re-reads
            // that bundle rather than stepping over the entries it never
            // classified. Re-reading is free of double-reports, because
            // anything already reported is recorded as known.
            at = covered;
            let read = covered.saturating_sub(started_at);
            if last_progress.elapsed() >= Duration::from_secs(10) {
                let rate = read as f64 / scan_started.elapsed().as_secs_f64();
                let eta = match rate > 0.0 {
                    true => rough_eta(((total - read) as f64 / rate) as u64),
                    false => "unknown".to_string(),
                };
                eprintln!(
                    "synch-monitor: {base_url}: {read}/{total} entries ({rate:.0}/s, eta {eta})"
                );
                last_progress = Instant::now();
            }
        }
        Ok(())
    }
    .await;

    // The position is written whether or not the walk finished, so a run
    // that dies partway resumes where it stopped instead of re-reading from
    // the last complete run.
    let reached = match outcome {
        Ok(()) => end,
        Err(_) => at.min(end),
    };
    let position = state.position(&checkpoint.origin);
    position.tree_size = checkpoint.tree_size;
    position.root = hex::encode(checkpoint.root_hash);
    position.next_index = reached;
    eprintln!(
        "synch-monitor: {base_url}: {} entries read to index {reached}",
        reached.saturating_sub(started_at)
    );

    outcome.map(|()| findings)
}

/// One finding, as a line — JSON when asked, human otherwise.
fn render(finding: &Finding, json: bool) -> String {
    match json {
        true => serde_json::to_string(finding).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
        false => finding.line(),
    }
}
