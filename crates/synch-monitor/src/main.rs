//! `synch-monitor` — read the log, classify what names your zones.
//!
//! One run: fetch the checkpoint, verify it under the pinned log keys, check
//! that it extends the tree this monitor saw last time, then walk every entry
//! bundle from the last-seen index, pull the certificate out of each leaf, and
//! classify the ones naming a zone the watch list covers
//! (docs/REKOR-ZONE-KEY.md §5.5).
//!
//! **Covers, not names.** A watch on `cp.example.com` also covers the zones
//! above and below it, because a DNS cut can be created or removed at any
//! label boundary and clients follow whichever one exists: `example.com` can
//! withdraw the delegation and sign `cp.example.com`'s names itself, and
//! `org.cp.example.com` can be delegated away and sign the names inside it.
//! Both authorize a key clients accept for the watched operator's names.
//! See [`synch_monitor::KnownKeys::watches`].
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
//!  0  nothing new for a watched zone
//! 10  unauthorized claims only — tier B naming a watched zone, no alarm
//! 20  new authorizations seen — a key was authorized for a watched zone, or
//!     for one above or below it: check it against what you published
//!  2  the run could not finish (transport, checkpoint, state)
//! ```
//!
//! They are ordered by severity, so a rule testing `>=` reads correctly.

use std::path::PathBuf;

use clap::Parser;
use hickory_resolver::proto::dnssec::TrustAnchors;
use hickory_resolver::proto::rr::Name;
use synch_monitor::{
    classify::{classify, Finding, Tier, Watched},
    state::MonitorState,
    tiles::{HttpTiles, Tree},
    MonitorError,
};
use synch_net::rekor::{Checkpoint, HashedRekordBody, LogKeys};

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
    after_long_help = "WHAT A WATCH LIST COVERS:
  Listing an apex also watches the zones above and below it. A DNS cut can be
  created or removed at any label boundary, and a client validates against
  whichever zone ends up signing the name: example.com can withdraw the
  delegation and sign cp.example.com's names itself, and org.cp.example.com
  can be delegated away and sign the names inside it. Either key would be
  accepted by clients, so either entry is reported — labelled with the
  relation, so a key that is not yours does not read as a rotation you forgot.

EXIT CODES:
   0  nothing new for a watched zone
  10  unauthorized claims only — entries naming a watched zone whose chain
      does not verify. No client would have accepted one; recorded, no alarm.
  20  new authorizations seen — a key was authorized for a watched zone, or
      for one above or below it, and this monitor had not recorded it.
      Check it against what you published.
   2  the run could not finish (transport, checkpoint, state)"
)]
struct Args {
    /// The log's base URL.
    #[arg(
        long,
        env = "SYNCH_MONITOR_LOG",
        default_value = "https://log2025-1.rekor.sigstore.dev"
    )]
    log: String,

    /// Where to persist the last checkpoint, the last index, the apexes to
    /// watch and the keys already reported for each.
    #[arg(long, env = "SYNCH_MONITOR_STATE")]
    state: PathBuf,

    /// A file of log verification keys, *replacing* the embedded Sigstore
    /// set — the same "an override is a different universe" semantics the
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
            "{} names no apex to watch — seed it with the zones you want \
             reported on, and (optionally) the keys you have already accounted \
             for, e.g. {{\"known\":{{\"keys\":{{\"sync.example\":[]}}}}}}. \
             List the zones you operate; the zones above and below each one are \
             covered without being named",
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
    let mut at = args.from_index.unwrap_or(state.next_index);
    // `at` advances as the scan runs; the summary needs where it began.
    let started_at = at;
    let end = match args.max_entries {
        // Saturating: `--from-index` and `--max-entries` are both operator
        // input, and their sum is not bounded by anything but the CLI.
        Some(max) => checkpoint.tree_size.min(at.saturating_add(max)),
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
            // Parsed, never trimmed. The watch filter and the chain walk
            // have to agree on what a name is, or an entry can be recognised
            // as belonging to a watched zone and then classified against a
            // different one (see `synch_net::chain::authorize`).
            let Ok(name) = parsed.certificate.single_dns_name() else {
                continue;
            };
            // Comparable with a watched zone, not equal to one: a zone above a
            // watched apex can serve its names by withdrawing the delegation,
            // and a zone below it takes names out of it by existing. Both
            // authorize a key that clients accept for a watched operator's
            // names (see `KnownKeys::watches`).
            let Some(watched) = state.known.watches(&name) else {
                continue;
            };
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
            if let Some(finding) = classify(&parsed, index, &anchors) {
                findings.push((finding, parsed.certificate.spki.clone(), watched));
            }
        }
        at = ((at / 256) + 1) * 256;
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
    for (finding, spki, watched) in &findings {
        match finding.tier {
            Tier::A => {
                let apex = synch_net::chain::parse_name(&finding.apex);
                // A tier A finding always came from a parsed SAN, so this
                // cannot fail; treating an unparseable one as *new* rather
                // than as known is the safe direction anyway — it reports.
                match apex.map(|apex| state.known.contains(&apex, spki)) {
                    Ok(true) => already_known += 1,
                    _ => new_authorizations.push((finding, spki, watched)),
                }
            }
            Tier::B => claims.push((finding, watched)),
        }
    }

    // stdout is the report: newly authorized keys, and nothing else.
    for (finding, _, watched) in &new_authorizations {
        println!("{}", render(finding, watched, args.json));
    }
    // Tier B on stderr. It is not an alarm — no client would have taken these
    // — but an operator who sees the exit code needs to be able to see *what*
    // was claimed without re-running with different flags.
    for (finding, watched) in &claims {
        eprintln!("{}", render(finding, watched, args.json));
    }

    // Record what was reported, so the next run stays quiet about it. Tier B
    // is deliberately never recorded: the same key arriving later with a
    // chain that *does* verify is a genuine new authorization, and a tier B
    // sighting must not have quietly consumed it.
    //
    // Recording is under the entry's *own* apex, not under the watched zone it
    // was matched through: the key belongs to that zone, and a neighbour's key
    // must never be filed as one the operator's zone has authorized. It also
    // means an ancestor or descendant zone joins the watch list once reported,
    // which widens nothing — everything comparable with it was already
    // comparable with the watched zone that surfaced it.
    for (finding, spki, _) in &new_authorizations {
        if let Ok(apex) = synch_net::chain::parse_name(&finding.apex) {
            state.known.insert(&apex, spki);
        }
    }
    state.origin = checkpoint.origin.clone();
    state.tree_size = checkpoint.tree_size;
    state.root = hex::encode(checkpoint.root_hash);
    state.next_index = end;
    if !args.no_save {
        state.save(&args.state)?;
    }

    // A neighbouring zone in the report is worth calling out in the summary:
    // it is the case an operator has not thought about, and reading it as
    // "my zone rotated a key" would be exactly the wrong conclusion.
    let neighbours = new_authorizations
        .iter()
        .filter(|(_, _, watched)| watched.zone().is_some())
        .count();
    eprintln!(
        "synch-monitor: {} entries read to index {end}; {} new authorization(s){}, \
         {already_known} already recorded, {} unauthorized claim(s)",
        end.saturating_sub(started_at),
        new_authorizations.len(),
        match neighbours {
            0 => String::new(),
            n => format!(" ({n} in a zone above or below a watched one)"),
        },
        claims.len()
    );
    Ok(match (new_authorizations.is_empty(), claims.is_empty()) {
        (false, _) => 20,
        (true, false) => 10,
        (true, true) => 0,
    })
}

/// One finding, as a line — JSON when asked, human otherwise.
///
/// The watch relation rides along rather than living in the [`Finding`],
/// deliberately: what an entry *is* comes from the certificate and the trust
/// anchors alone, and *why it is being shown to you* is a fact about this
/// operator's watch list. Keeping the second out of `classify` is what stops
/// the monitor's own configuration from steering its verdicts.
fn render(finding: &Finding, watched: &Watched, json: bool) -> String {
    match json {
        true => serde_json::to_string(&Report {
            finding,
            relation: watched.relation(),
            watched: watched.zone().map(Name::to_string),
        })
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
        false => match watched.note() {
            None => finding.line(),
            Some(note) => format!("{} [{note}]", finding.line()),
        },
    }
}

/// A finding as reported: the verdict, plus why this operator is seeing it.
#[derive(Debug, serde::Serialize)]
struct Report<'a> {
    #[serde(flatten)]
    finding: &'a Finding,
    /// `direct`, `ancestor` or `descendant` — always present, so a filter can
    /// select on it without testing for a missing field.
    relation: &'static str,
    /// The watched zone this entry concerns; absent when the entry names a
    /// watched apex itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    watched: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_monitor::classify::Tier;

    fn finding() -> Finding {
        Finding {
            log_index: 68_018_370,
            apex: "example.com.".into(),
            key_tag: 34918,
            spki_sha256: "ab".repeat(32),
            ds: "34918 13 2 beef".into(),
            tier: Tier::A,
            reasons: vec!["DNSSEC chain valid to .".into()],
        }
    }

    /// A key that is not yours must not read as a rotation you forgot.
    ///
    /// The relation is the whole difference between "your zone authorized a
    /// key" and "the zone above yours did, and it can serve your names" — an
    /// operator comparing the report against their own records has to be able
    /// to see which of the two they are looking at.
    #[test]
    fn a_neighbouring_zone_says_so_in_the_line() {
        let watched = synch_net::chain::parse_name("cp.example.com").unwrap();
        let direct = render(&finding(), &Watched::Directly, false);
        let above = render(&finding(), &Watched::Ancestor(watched), false);

        assert!(direct.starts_with("[A] index 68018370 apex example.com."));
        assert!(!direct.contains("watched"));
        assert!(above.starts_with(&direct));
        assert!(above.contains("above watched cp.example.com."));
    }

    /// The JSON line is the finding's own fields plus the relation, flat.
    ///
    /// Flattening is load-bearing for anyone already filtering these lines:
    /// the finding's keys stay where they were, and `relation` is always
    /// present so a filter can select on it without testing for absence.
    #[test]
    fn the_json_line_carries_the_relation_alongside_the_finding() {
        let watched = synch_net::chain::parse_name("cp.example.com").unwrap();
        let below: serde_json::Value =
            serde_json::from_str(&render(&finding(), &Watched::Descendant(watched), true)).unwrap();
        assert_eq!(below["apex"], "example.com.");
        assert_eq!(below["log_index"], 68_018_370);
        assert_eq!(below["relation"], "descendant");
        assert_eq!(below["watched"], "cp.example.com.");

        let direct: serde_json::Value =
            serde_json::from_str(&render(&finding(), &Watched::Directly, true)).unwrap();
        assert_eq!(direct["relation"], "direct");
        assert!(direct.get("watched").is_none());
    }
}
