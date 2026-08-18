//! `synch-monitor` — read the log, classify what names your zones.
//!
//! Two subcommands. `run` is the watcher: fetch the checkpoint, verify it
//! under the pinned log keys, check that it extends the tree this monitor
//! saw last time, then walk every entry bundle from the last-seen index,
//! pull the certificate out of each leaf, and classify the ones naming a
//! watched apex (docs/REKOR-ZONE-KEY.md §5.5). Every report's full entry
//! body goes into the state file with it, and `entry` is the evidence
//! drawer: print one of those bodies by index, a local read rather than a
//! re-fetch from the log under watch.
//!
//! **The product is the list of newly authorized keys.** A tier A entry whose
//! key this monitor has not recorded for that apex is a new authorization: it
//! goes to stdout, and is then recorded so the next run does not repeat it. A
//! tier A entry for a key already recorded has been reported before and is
//! not reported again. Tier B — an unauthorized claim **no client holding
//! this monitor's anchor set would have accepted** — goes to stderr as a note
//! and is never recorded, because recording it would suppress the report if
//! the same key later showed up with a chain that does verify.
//!
//! stdout is therefore the report and nothing else; stderr is the running
//! commentary. A cron job that mails stdout mails exactly the events that
//! need a human.
//!
//! # Which client population a run covers
//!
//! **The trust surface**: the DNSSEC anchor set and the log key set the
//! verdicts are computed under, printed at the start of every run.
//! `--dnssec-anchor` and `--rekor-key` *replace* the ICANN root and the pinned
//! logs rather than unioning with them, so one process covers one population:
//! tier B means "no client holding *these* would have accepted it", and the
//! same bytes can be tier B here and client-accepted under a different anchor
//! set. The surface is recorded in the state file and a run that changes it is
//! refused rather than quietly filing verdicts about a different population
//! into the same memory.
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
//! and that ordering is why a failed run sorts **above** the success codes. A monitor that
//! cannot finish is not a monitor with nothing to say: it is the state an
//! attacker most wants it in, because a wedged run and a quiet run look
//! identical from the outside.
//!
//! A run that fails partway prints and records everything it classified
//! before the failure: the findings leave the walk whatever its outcome, and
//! the resume position is only ever moved over entries whose findings are in
//! that returned batch. An alarming entry found at index N is not lost to a
//! transport error at index N+1, and no future run steps over it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use futures_util::stream::StreamExt;
use hickory_resolver::proto::dnssec::TrustAnchors;
use synch_monitor::{
    classify::{classify, Finding, KnownKeys, Tier},
    discover::{self, HttpRepo},
    state::{MonitorState, TrustSurface},
    tiles::{HttpTiles, TileSource, Tree},
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
    /// Reports every newly authorized zone key for a watched name: an entry
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
  10  unauthorized claims only — entries naming a watched name whose chain
      does not verify. No client holding this run's anchor set would have
      accepted one; no alarm.
  20  new authorizations seen — a key was authorized for a watched name that
      this monitor had not recorded. Check it against what you published.
  30  the run could not finish (transport, checkpoint, state). Sorts above
      the others on purpose: a wedged monitor is not a quiet one. Anything
      classified before the failure is still reported.")]
    Run(RunArgs),
    /// Print the full body of a log entry the state file holds: the evidence
    /// behind a report, by its log index — with --log naming the shard when
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
    ///
    /// It narrows only *which shard is read*, never the key set: the pins
    /// stay whatever the trusted root in force names, so this run still
    /// believes checkpoints from shards it is not reading, and an entry in one
    /// of those is client-valid and unseen until a run without --log reads it.
    /// Each run says so, naming the shards it skipped. A log the trusted root
    /// does not pin at all therefore needs --rekor-key beside this, which
    /// replaces the key set outright.
    #[arg(long, env = "SYNCH_MONITOR_LOG")]
    log: Option<String>,

    /// Where to persist the last checkpoint, the last index, the apexes to
    /// watch, the keys already reported for each, and the entry bodies behind
    /// the reports.
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
    ///
    /// It replaces rather than adds, so a run under it covers only clients
    /// under the same anchors — which is why the state file remembers which
    /// anchor set its verdicts were made under.
    #[arg(long)]
    dnssec_anchor: Option<PathBuf>,

    /// Start here instead of at the persisted index. A fresh monitor for a
    /// log with 10⁸ entries in it wants a starting point that is not zero.
    #[arg(long)]
    from_index: Option<u64>,

    /// Accept a --from-index that leaves a range permanently unclassified.
    #[arg(long)]
    allow_gap: bool,

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
/// nothing to report — it is the state an attacker most wants it in.
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

/// The DNSSEC anchors this run judges chains against.
///
/// An anchor file that parses but holds no DNSKEY is refused, for the reason
/// the client gives in the same situation: an empty anchor set validates
/// nothing, forever, quietly. Every chain would fail to reach an anchor,
/// every entry naming a watched name would be tier B — "no client would have
/// accepted one" — and a completely blind monitor would exit 10 and report no
/// alarm. That is the one failure mode a monitor must never present as a
/// clean result.
fn anchors_in_force(path: Option<&PathBuf>) -> Result<TrustAnchors, MonitorError> {
    let Some(path) = path else {
        return Ok(TrustAnchors::default());
    };
    let anchors = TrustAnchors::from_file(path)
        .map_err(|e| MonitorError::State(format!("trust anchor {}: {e}", path.display())))?;
    if anchors.is_empty() {
        return Err(MonitorError::State(format!(
            "trust anchor {}: no DNSKEY records in the file — an empty anchor set \
             validates nothing, so every entry would be filed as an unauthorized \
             claim and the run would report no alarm",
            path.display()
        )));
    }
    Ok(anchors)
}

/// The trust surface this run's verdicts belong to: which anchors, which log
/// keys.
///
/// Labels, not material — they exist to be compared with the surface the state
/// file records. A digest identifies an override file without the state having
/// to carry its contents.
/// Whether this run contacts Sigstore's TUF repository at all.
///
/// `--no-tuf` says so outright. `--rekor-key` says it too, and that is the
/// half that was missing: on the client a named key file turns pin refresh off
/// entirely (`ResolverOptions`, crates/synch-net/src/dns.rs — "a static
/// universe is static in both directions"), and a monitor that kept walking
/// under one would follow Sigstore's pin set behind the operator's back while
/// reporting a surface of their key file. It also had a run reach a CDN to
/// fetch keys it had already been told to replace.
///
/// The log *endpoint* still comes from the trusted root in force — the pins on
/// disk, else the embedded bootstrap — because replacing the keys says nothing
/// about where the log is. `--log` is the flag for that.
fn tuf_walk_disabled(args: &RunArgs) -> bool {
    args.no_tuf || args.rekor_key.is_some()
}

fn trust_surface(args: &RunArgs) -> Result<TrustSurface, MonitorError> {
    let digest = |path: &PathBuf| -> Result<String, MonitorError> {
        let bytes = std::fs::read(path)
            .map_err(|e| MonitorError::State(format!("{}: {e}", path.display())))?;
        Ok(format!(
            "sha256:{}",
            hex::encode(synch_net::rekor::sha256(&bytes))
        ))
    };
    Ok(TrustSurface {
        anchors: match &args.dnssec_anchor {
            None => "icann-root".to_string(),
            Some(path) => digest(path)?,
        },
        log_keys: match &args.rekor_key {
            None => "tuf".to_string(),
            Some(path) => digest(path)?,
        },
    })
}

/// Refuses a watch list that watches nothing.
///
/// Two ways to hold one, and they close the same hole: a watch list is the
/// only thing that decides whether an entry is looked at, so a list that
/// matches nothing produces exit 0 forever. Empty is the first-run mistake.
/// An entry that is not a DNS name is the quieter one — it cannot match a
/// certificate's SAN, which is parsed too, so it watches nothing however long
/// it sits in the file, and checking the list for non-emptiness alone lets a
/// typo be indistinguishable from good news.
fn check_watch_list(known: &KnownKeys, state_path: &Path) -> Result<(), MonitorError> {
    if known.keys.is_empty() {
        return Err(MonitorError::State(format!(
            "{} names no apex to watch — seed it with the zones you want \
             reported on, and (optionally) the keys you have already accounted \
             for, e.g. {{\"known\":{{\"keys\":{{\"sync.example\":[]}}}}}}",
            state_path.display()
        )));
    }
    let unwatchable = known.unwatchable();
    if !unwatchable.is_empty() {
        return Err(MonitorError::State(format!(
            "{} watches {} entr{} that are not domain names ({}) — an entry that \
             does not parse can never match a certificate, so it watches nothing \
             and this monitor would report no alarm whatever the log held",
            state_path.display(),
            unwatchable.len(),
            match unwatchable.len() {
                1 => "y",
                _ => "ies",
            },
            unwatchable.join(", ")
        )));
    }
    Ok(())
}

async fn run(args: &RunArgs) -> Result<i32, MonitorError> {
    let keys_override = match &args.rekor_key {
        Some(path) => Some(
            LogKeys::from_file(path)
                .map_err(|e| MonitorError::Checkpoint(format!("{}: {e}", path.display())))?,
        ),
        None => None,
    };
    let anchors = anchors_in_force(args.dnssec_anchor.as_ref())?;
    let surface = trust_surface(args)?;

    // `--rekor-key` replaces the keys and nothing else. The *endpoints* still
    // come from the trusted root in force — the persisted pins, else the
    // embedded Sigstore bootstrap — so a run given a self-hosted log's key and
    // no `--log` fetches Sigstore's shards and checks their checkpoints under
    // a key that did not sign them. Every shard fails, every one lands in
    // `failures`, and the run exits 30. Every time, forever.
    //
    // That is the documented private-deployment path (§6: "a self-hosted log
    // plus `--rekor-key`/`CP_REKOR_KEY`"), so the population it describes
    // would have had clients that verify and a monitor that never completes a
    // run — which §5.5 calls the worst outcome there is, since a required log
    // with no watcher is a formality. Refused at startup, naming the flag,
    // rather than discovered from an exit code after a walk.
    if args.rekor_key.is_some() && args.log.is_none() {
        return Err(MonitorError::State(
            "--rekor-key replaces the log keys but not the log endpoints, which              still come from the trusted root in force — so this run would read              Sigstore's shards and check them under your key, and fail on every              one. Name the log with --log <url>."
                .to_string(),
        ));
    }

    // Everything local before anything remote: an unseeded watch list is the
    // first-run mistake, and finding out about it after a TUF walk and a
    // checkpoint fetch would be a slower way to learn the same thing.
    let mut state = MonitorState::load(&args.state)?;
    check_watch_list(&state.known, &args.state)?;

    // A change of trust surface is refused, not merged. The recorded keys and
    // the recorded verdicts are statements about a client population, and
    // anchors replace rather than union — so one state file covers one
    // population, and two populations want two of them.
    if let Some(recorded) = &state.surface {
        if *recorded != surface {
            return Err(MonitorError::State(format!(
                "{} holds verdicts made under anchors {} and log keys {}, and this run \
                 uses anchors {} and log keys {} — tier B means \"no client holding \
                 these would have accepted it\", so the two are statements about \
                 different client populations. Use a separate state file for each",
                args.state.display(),
                recorded.anchors,
                recorded.log_keys,
                surface.anchors,
                surface.log_keys
            )));
        }
    }
    state.surface = Some(surface.clone());
    eprintln!(
        "synch-monitor: watching {} apex(es) ({}) under anchors {} and log keys {}",
        state.known.keys.len(),
        state
            .known
            .keys
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        surface.anchors,
        surface.log_keys
    );

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
        tuf_walk_disabled(args),
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

    // Every log the trusted root names, and a walk that fails partway still
    // hands back what it classified.
    let mut classified = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for base_url in &found.base_urls {
        let source = match HttpTiles::new(base_url) {
            Ok(source) => source,
            Err(e) => {
                eprintln!("synch-monitor: {base_url}: {e}");
                failures.push(base_url.clone());
                continue;
            }
        };
        let walked = walk_log(
            &source,
            base_url,
            &logs,
            &anchors,
            &known_at_start,
            &mut state,
            args,
        )
        .await;
        // The findings come back whatever the outcome, and the position the
        // walk recorded never moved past an entry whose finding is not in
        // this batch. One unreadable shard must not cost the report from the
        // others either: a retired log whose tiles have been taken down is an
        // ordinary thing to meet, and the busy shard is where the news
        // usually is. The run still ends incomplete.
        classified.extend(walked.classified);
        if let Some(e) = walked.failure {
            eprintln!("synch-monitor: {base_url}: {e}");
            failures.push(base_url.clone());
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
    for entry in &classified {
        match entry.finding.tier {
            Tier::A => {
                let apex = synch_net::chain::parse_name(&entry.finding.apex);
                // An entry is news when *any* key its chain proves has not
                // been reported yet — a rotation that pre-publishes one new
                // key beside a known one is exactly the event to hear about.
                // A tier A finding always came from a parsed SAN, so parsing
                // cannot fail; treating an unparseable one as *new* rather
                // than as known is the safe direction anyway — it reports.
                let all_known = apex.is_ok_and(|apex| {
                    entry
                        .finding
                        .keys
                        .iter()
                        .all(|key| known_at_start.contains_digest(&apex, &key.sha256))
                });
                match all_known {
                    true => already_known += 1,
                    false => new_authorizations.push(entry),
                }
            }
            Tier::B => claims.push(entry),
        }
    }

    // stdout is the report: newly authorized keys, and nothing else.
    for entry in &new_authorizations {
        println!("{}", render(&entry.finding, args.json));
    }
    // Tier B on stderr. It is not an alarm — no client under this run's
    // anchor set would have taken these — but an operator who sees the exit
    // code needs to be able to see *what* was claimed without re-running with
    // different flags.
    for entry in &claims {
        eprintln!("{}", render(&entry.finding, args.json));
    }
    // Record what was reported, so the next run stays quiet about it — and
    // the evidence for exactly those reports. Tier B is deliberately never
    // recorded: the same key arriving later with a chain that *does* verify is
    // a genuine new authorization, and a tier B sighting must not have quietly
    // consumed it. Its body is not kept either, because an unauthorized claim
    // naming a watched apex costs an attacker one self-signed certificate,
    // and a body per claim is a state file that grows at their choosing.
    for entry in &new_authorizations {
        if let Ok(apex) = synch_net::chain::parse_name(&entry.finding.apex) {
            for key in &entry.finding.keys {
                state.known.insert_digest(&apex, &key.sha256);
            }
        }
        let dropped = state.record_entry(&entry.origin, entry.finding.log_index, &entry.body);
        for index in dropped {
            eprintln!(
                "synch-monitor: the evidence drawer for {} is full — the body of entry \
                 {index} is no longer held locally",
                entry.origin
            );
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
            classified.len()
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
    if !new_authorizations.is_empty() && !args.no_save {
        eprintln!(
            "synch-monitor: the full body of every report is in the state file — \
             `synch-monitor entry <INDEX>` prints one"
        );
    }
    Ok(match (new_authorizations.is_empty(), claims.is_empty()) {
        (false, _) => 20,
        (true, false) => 10,
        (true, true) => 0,
    })
}

/// One classified leaf, with the bytes it was classified from.
///
/// The body travels with the finding so that recording evidence is a decision
/// the reporting code makes, once it knows which findings became reports —
/// rather than one the scan makes about every entry it sees.
#[derive(Debug)]
struct Classified {
    /// The log's origin line: the label the evidence is filed under.
    origin: String,
    /// The canonicalized entry body, verified against the signed checkpoint —
    /// **only for tier A**, and empty for tier B.
    ///
    /// Evidence is kept for findings that become reports. A tier B finding
    /// never does: it is noted to stderr and deliberately not recorded, so
    /// that the same key arriving later with a chain that *does* verify is
    /// still news. Keeping its body would hand the size of this run's memory
    /// to whoever is publishing tier B entries — and that is anybody, for the
    /// price of one self-signed certificate naming a name on the watched
    /// zone's delegation path, which is public. The state file has excluded
    /// these bodies from the start for exactly this reason; the same
    /// arithmetic applies before the run ends.
    body: Vec<u8>,
    /// The verdict.
    finding: Finding,
}

/// What one shard's walk produced.
///
/// **The findings are not inside the `Result`.** A walk that fails partway has
/// still classified everything below the failure, and that is the half a
/// monitor exists to deliver: dropping it on the way out is how a tier A entry
/// at index N becomes invisible because index N+1 answered 503 — deterministic
/// for whoever serves the tiles, and silent, because the position advances
/// over the bundle that produced it either way.
#[derive(Debug, Default)]
struct Walked {
    /// Everything classified before the walk ended, however it ended.
    classified: Vec<Classified>,
    /// Why the walk stopped early, if it did.
    failure: Option<MonitorError>,
}

/// The checkpoint a run reads `base_url` under, and the range of entries to
/// walk: everything that decides whether the tiles are worth reading at all.
///
/// A failure here touches no position — nothing was read, so there is nothing
/// to resume from.
async fn prepare<S: TileSource>(
    source: &S,
    base_url: &str,
    logs: &LogKeys,
    state: &mut MonitorState,
    args: &RunArgs,
) -> Result<(Checkpoint, u64, u64), MonitorError> {
    let body = source
        .fetch("api/v2/checkpoint")
        .await?
        .ok_or_else(|| MonitorError::Transport("the log serves no checkpoint".into()))?;
    let checkpoint =
        Checkpoint::parse(&body).map_err(|e| MonitorError::Checkpoint(e.to_string()))?;
    // Under *any* pinned key: which log signed it is settled by the origin
    // line the position is then keyed on, and a checkpoint no pinned key
    // signed is not one this client would have believed either.
    checkpoint
        .verify_under(logs)
        .map_err(|e| MonitorError::Checkpoint(e.to_string()))?;

    let position = state.position(&checkpoint.origin).clone();
    let tree = Tree::new(source, checkpoint.tree_size, args.concurrency.get());
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

    // Consistency: the root this monitor persisted for *this* log, recomputed
    // from the new tree's tiles. A log that cannot reproduce its own past has
    // shown two histories, and nothing below is worth reading.
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
    // nothing will ever classify. Bounded first runs want exactly that; a
    // resuming monitor almost never does. stderr is the commentary channel and
    // that is not the right weight for "these entries are permanently unread",
    // so this is refused unless the operator says in the same breath that they
    // mean it.
    if let Some(from) = args.from_index {
        if from > position.next_index {
            let gap = format!(
                "starting at {from} skips {}..{from}, which no run will ever classify",
                position.next_index
            );
            if !args.allow_gap {
                return Err(MonitorError::State(format!(
                    "{base_url}: {gap} — pass --allow-gap to accept that, or drop \
                     --from-index to resume from {}",
                    position.next_index
                )));
            }
            eprintln!("synch-monitor: {base_url}: {gap} (--allow-gap)");
        }
    }
    let started_at = args.from_index.unwrap_or(position.next_index);
    let end = match args.max_entries {
        // Saturating: `--from-index` and `--max-entries` are both operator
        // input, and their sum is not bounded by anything but the CLI.
        Some(max) => checkpoint.tree_size.min(started_at.saturating_add(max)),
        None => checkpoint.tree_size,
    };
    Ok((checkpoint, started_at, end))
}

/// Reads one log end to end: checkpoint, consistency, then every entry from
/// where this monitor last stopped.
///
/// Extracted per log because a run reads *every* log the trusted root names
/// (§10): the position, the consistency proof and the resume index are all
/// per-log, keyed on the checkpoint's origin line.
async fn walk_log<S: TileSource>(
    source: &S,
    base_url: &str,
    logs: &LogKeys,
    anchors: &TrustAnchors,
    known: &KnownKeys,
    state: &mut MonitorState,
    args: &RunArgs,
) -> Walked {
    let mut walked = Walked::default();
    let (checkpoint, started_at, end) = match prepare(source, base_url, logs, state, args).await {
        Ok(prepared) => prepared,
        Err(e) => {
            walked.failure = Some(e);
            return walked;
        }
    };
    let tree = Tree::new(source, checkpoint.tree_size, args.concurrency.get());

    // How far the walk actually got, and the resume point when it fails
    // partway: saving `end` would step over entries the run never classified,
    // saving `started_at` would re-read work already reported.
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
    // The scan runs inside an async block so that a failure partway through
    // does not take the findings with it: `walked` is filled as the walk goes
    // and is returned whatever the block's outcome. The error decides the exit
    // code, not whether the news gets out.
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
                // decision to skip it**, the body is bound to the signed
                // checkpoint.
                //
                // Deciding to *skip* on unauthenticated bytes is the whole
                // attack. A log that replaces one body with something that
                // fails to parse, or that names an unwatched zone, hides the
                // entry — while the victim's client, whose proof carries a
                // real path to the real leaf, still accepts it. Silent
                // monitor, working forgery.
                //
                // And "bound" has to mean bound to the *checkpoint*. A
                // comparison against the level-0 hash tile is a comparison
                // against another file this same party serves, and the root
                // recomputation never reads that file — so the tile is folded
                // up to a node the root did commit to first, one fold per 256
                // entries (see `Tree::verify_leaf`).
                tree.verify_leaf(index, body, checkpoint.root_hash).await?;
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
                if let Some(finding) = classify(&parsed, index, anchors) {
                    // Tier B is noted, never recorded — so its body is never
                    // needed, and never held. See `Classified::body`.
                    let body = match finding.tier {
                        Tier::A => body.clone(),
                        Tier::B => Vec::new(),
                    };
                    walked.classified.push(Classified {
                        origin: checkpoint.origin.clone(),
                        body,
                        finding,
                    });
                }
            }
            let covered = entries
                .last()
                .map(|(last, _)| last + 1)
                .unwrap_or(started_at)
                .min(end);
            // Only once the whole bundle is through, and only because every
            // finding it produced is already in `walked`: the position may
            // never pass an entry whose finding did not leave this function.
            // A failure mid-bundle leaves `at` at the previous boundary, so
            // the next run re-reads that bundle rather than stepping over
            // entries it never classified. Re-reading is free of
            // double-reports, because anything already reported is recorded as
            // known.
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

    // The position is written whether or not the walk finished, so a run that
    // dies partway resumes where it stopped instead of re-reading from the
    // last complete run. That is only sound because the findings go back to
    // the caller in the same breath — see `Walked`.
    let reached = match outcome {
        Ok(()) => end,
        Err(e) => {
            walked.failure = Some(e);
            at.min(end)
        }
    };
    let position = state.position(&checkpoint.origin);
    position.tree_size = checkpoint.tree_size;
    position.root = hex::encode(checkpoint.root_hash);
    position.next_index = reached;
    eprintln!(
        "synch-monitor: {base_url}: {} entries read to index {reached}",
        reached.saturating_sub(started_at)
    );

    walked
}

/// One finding, as a line — JSON when asked, human otherwise.
fn render(finding: &Finding, json: bool) -> String {
    match json {
        true => serde_json::to_string(finding).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
        false => finding.line(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_net::sim::{SimLog, SimZone};

    /// A log served through the tile layout, from a `SimLog`'s leaves, with a
    /// bundle that can be made to fail.
    struct Fixture {
        log: SimLog,
        leaves: Vec<Vec<u8>>,
        /// Fetches for the bundle at this first index answer a 503.
        fail_bundle_at: Option<u64>,
    }

    impl TileSource for Fixture {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
            if path == "api/v2/checkpoint" {
                return Ok(Some(self.log.checkpoint()));
            }
            let rest = path.strip_prefix("api/v2/tile/").expect("a tile path");
            let (level, rest) = rest.split_once('/').expect("a level");
            let (digits, width) = match rest.split_once(".p/") {
                Some((digits, width)) => (digits, width.parse::<u64>().unwrap()),
                None => (rest, 256),
            };
            let index: u64 = digits.split('/').fold(0u64, |acc, group| {
                acc * 1000 + group.trim_start_matches('x').parse::<u64>().unwrap()
            });
            let tile_level: u32 = match level {
                "entries" => 0,
                level => level.parse().unwrap(),
            };
            let current = ((self.leaves.len() as u64) >> (8 * tile_level))
                .saturating_sub(index * 256)
                .min(256);
            if width != current {
                return Ok(None);
            }
            if level == "entries" {
                if self.fail_bundle_at == Some(index * 256) {
                    return Err(MonitorError::Transport(format!(
                        "{path}: the log answered 503"
                    )));
                }
                let mut out = Vec::new();
                for i in 0..width {
                    let body = &self.leaves[(index * 256 + i) as usize];
                    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                    out.extend_from_slice(body);
                }
                return Ok(Some(out));
            }
            let span = 1u64 << (8 * tile_level);
            let mut out = Vec::new();
            for i in 0..width {
                let start = (index * 256 + i) * span;
                out.extend_from_slice(&subtree(&self.leaves, start, start + span));
            }
            Ok(Some(out))
        }

        async fn checkpoint_size(&self) -> Result<Option<u64>, MonitorError> {
            Ok(Some(self.leaves.len() as u64))
        }
    }

    /// RFC 6962 §2.1, so the fixture's tiles are right independently of the
    /// code that reads them.
    fn subtree(leaves: &[Vec<u8>], lo: u64, hi: u64) -> [u8; 32] {
        if lo + 1 == hi {
            return synch_net::rekor::leaf_hash(&leaves[lo as usize]);
        }
        let mut span = 1u64;
        while span * 2 < hi - lo {
            span *= 2;
        }
        synch_net::rekor::node_hash(
            &subtree(leaves, lo, lo + span),
            &subtree(leaves, lo + span, hi),
        )
    }

    fn anchors_for(zone: &SimZone) -> TrustAnchors {
        let file = tempfile::NamedTempFile::new().expect("a temp file");
        std::fs::write(file.path(), zone.anchor_record()).expect("write the anchor");
        TrustAnchors::from_file(file.path()).expect("the anchor parses")
    }

    /// A watch list holding one apex and no keys — how an operator seeds one.
    fn watching(apex: &str) -> KnownKeys {
        let mut known = KnownKeys::default();
        known.keys.insert(
            synch_net::chain::parse_name(apex)
                .expect("a test apex")
                .to_string(),
            Vec::new(),
        );
        known
    }

    fn run_args(state: &Path) -> RunArgs {
        RunArgs {
            log: None,
            state: state.to_path_buf(),
            tuf: String::new(),
            no_tuf: true,
            rekor_pins: None,
            rekor_key: None,
            dnssec_anchor: None,
            from_index: None,
            allow_gap: false,
            max_entries: None,
            concurrency: std::num::NonZeroUsize::new(4).unwrap(),
            json: false,
            no_save: false,
        }
    }

    /// A log holding one zone-key entry at `index`, padded to `size` leaves.
    fn log_with_entry(index: u64, size: u64) -> (Fixture, SimZone) {
        let zone = SimZone::new(
            "cluster.example",
            vec!["v=sync1 id=nas nk=aaaa".to_string()],
        );
        let mut log = SimLog::new("log2025-1.rekor.example");
        for i in 0..index {
            log.append(format!("somebody else's entry {i}").as_bytes());
        }
        let proof = log.publish(&zone, "create");
        assert_eq!(proof.log_index, index);
        for i in index + 1..size {
            log.append(format!("somebody else's entry {i}").as_bytes());
        }
        let leaves = (0..size)
            .map(|i| match i == index {
                true => proof.canonicalized_body.clone(),
                false => format!("somebody else's entry {i}").into_bytes(),
            })
            .collect();
        (
            Fixture {
                log,
                leaves,
                fail_bundle_at: None,
            },
            zone,
        )
    }

    /// **C3.** A walk that dies after the bundle holding a tier A entry still
    /// returns that finding, and the position it records does not step over
    /// it.
    ///
    /// The audited party triggers this deliberately: fail one tile request
    /// once the monitor has crossed the bundle boundary, and a findings vector
    /// dropped on the error takes the alarm with it while the cursor advances
    /// past the entry that raised it — never printed, never recorded, never
    /// re-read.
    #[tokio::test]
    async fn a_walk_that_fails_partway_still_returns_what_it_classified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitor.json");
        // The entry is in the first bundle; the second bundle 503s.
        let (mut fixture, zone) = log_with_entry(100, 400);
        fixture.fail_bundle_at = Some(256);
        let keys = LogKeys::parse(&fixture.log.key_pem()).unwrap();
        let anchors = anchors_for(&zone);

        let mut state = MonitorState::default();
        let known = watching("cluster.example");
        let args = run_args(&path);
        let walked = walk_log(
            &fixture,
            "https://log.example",
            &keys,
            &anchors,
            &known,
            &mut state,
            &args,
        )
        .await;

        assert!(walked.failure.is_some(), "the second bundle must fail");
        let [found] = walked.classified.as_slice() else {
            panic!(
                "the finding must survive the failure: {:?}",
                walked.classified
            );
        };
        assert_eq!(found.finding.log_index, 100);
        assert_eq!(found.finding.tier, Tier::A);
        assert_eq!(found.origin, "log2025-1.rekor.example");
        assert!(!found.body.is_empty(), "the evidence comes back with it");

        // And the cursor stopped at the boundary of the bundle that
        // completed, so nothing above it was skipped.
        assert_eq!(state.position("log2025-1.rekor.example").next_index, 256);
    }

    /// **M2.** An anchor file with no DNSKEY in it is refused.
    #[test]
    fn an_empty_anchor_set_is_refused_rather_than_making_every_entry_tier_b() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("anchor.key");
        // Parses as a trust anchor file, holds no key.
        std::fs::write(&path, b"; nothing but a comment\n").unwrap();
        let Err(err) = anchors_in_force(Some(&path)) else {
            panic!("an anchor file with no DNSKEY in it must be refused");
        };
        let err = err.to_string();
        assert!(err.contains("validates nothing"), "{err}");
        // And the ICANN root is still the default.
        let Ok(default) = anchors_in_force(None) else {
            panic!("the ICANN root is the default");
        };
        assert!(!default.is_empty());
    }

    /// **D7.** A watch list that watches nothing is refused, whether it is
    /// empty or unparseable.
    ///
    /// Non-emptiness was the only test, so a mistyped apex — the state file is
    /// hand-edited — watched nothing forever and every run said "no alarm".
    #[test]
    fn a_watch_list_that_watches_nothing_is_refused() {
        let path = Path::new("/nonexistent/monitor.json");
        let empty = KnownKeys::default();
        let Err(err) = check_watch_list(&empty, path) else {
            panic!("an empty watch list must be refused");
        };
        assert!(err.to_string().contains("no apex to watch"), "{err}");

        // An entry that is not a name never matches a parsed SAN, so it
        // watches nothing however long it sits there.
        let mut hand_edited = KnownKeys::default();
        hand_edited
            .keys
            .insert("cluster.example..".into(), Vec::new());
        let Err(err) = check_watch_list(&hand_edited, path) else {
            panic!("an unparseable watch entry must be refused");
        };
        let err = err.to_string();
        assert!(err.contains("cluster.example.."), "{err}");
        assert!(err.contains("watches nothing"), "{err}");

        // A list of names is accepted.
        check_watch_list(&watching("cluster.example.com"), path)
            .expect("a domain name is a watchable apex");
    }

    /// **D7.** A `--from-index` that leaves a permanent hole is refused, not
    /// mentioned on the commentary channel.
    #[tokio::test]
    async fn a_from_index_that_skips_a_range_forever_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitor.json");
        let (fixture, zone) = log_with_entry(10, 300);
        let keys = LogKeys::parse(&fixture.log.key_pem()).unwrap();
        let anchors = anchors_for(&zone);
        let known = watching("cluster.example");

        let mut args = run_args(&path);
        args.from_index = Some(100);
        let mut state = MonitorState::default();
        let walked = walk_log(
            &fixture,
            "https://log.example",
            &keys,
            &anchors,
            &known,
            &mut state,
            &args,
        )
        .await;
        let failure = walked.failure.expect("a permanent gap must be refused");
        assert!(failure.to_string().contains("--allow-gap"), "{failure}");
        // Nothing was read, so no position moved: the entries 0..100 are still
        // there to be classified by a run without the flag.
        assert_eq!(state.position("log2025-1.rekor.example").next_index, 0);

        // Said out loud in the same breath, it proceeds — and the entry above
        // the gap is still classified.
        args.allow_gap = true;
        let walked = walk_log(
            &fixture,
            "https://log.example",
            &keys,
            &anchors,
            &known,
            &mut state,
            &args,
        )
        .await;
        assert!(walked.failure.is_none(), "{:?}", walked.failure);
        assert_eq!(
            state.position("log2025-1.rekor.example").next_index,
            300,
            "the run read to the end of the tree"
        );
    }

    /// **D6.** One state file, one client population.
    #[test]
    fn a_run_that_changes_the_trust_surface_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = dir.path().join("anchor.key");
        std::fs::write(&anchor, b"example. IN DNSKEY 257 3 13 aaaa\n").unwrap();
        let mut args = run_args(&dir.path().join("monitor.json"));
        let default = trust_surface(&args).unwrap();
        assert_eq!(default.anchors, "icann-root");
        assert_eq!(default.log_keys, "tuf");

        args.dnssec_anchor = Some(anchor);
        let overridden = trust_surface(&args).unwrap();
        assert!(overridden.anchors.starts_with("sha256:"), "{overridden:?}");
        assert_ne!(default, overridden);
    }

    /// `--rekor-key` is a static universe in both directions, here as on the
    /// client: it replaces the pin set *and* stops the walk that would keep
    /// following Sigstore's.
    #[test]
    fn a_named_key_file_turns_the_tuf_walk_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = run_args(&dir.path().join("monitor.json"));

        // `run_args` sets `no_tuf` so the suite never reaches a CDN; the
        // stock shape is the one where neither flag is given.
        args.no_tuf = false;
        assert!(!tuf_walk_disabled(&args), "a stock run follows Sigstore");

        args.no_tuf = true;
        assert!(tuf_walk_disabled(&args));

        args.no_tuf = false;
        args.rekor_key = Some(dir.path().join("log.pub"));
        assert!(
            tuf_walk_disabled(&args),
            "a run under a named key file must not go on refreshing pins from \
             Sigstore behind the operator's back"
        );

        args.no_tuf = true;
        assert!(tuf_walk_disabled(&args), "and both together is still off");
    }
}
