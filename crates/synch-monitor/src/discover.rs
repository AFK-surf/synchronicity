//! Finding the log: which shard to read, and which keys verify what it says.
//!
//! A monitor that hardcodes a hostname is a monitor that goes quiet the day
//! Sigstore opens the next shard — silently, because an empty log reads
//! exactly like a log with nothing new in it. So the endpoint is discovered
//! the same way the keys already were: from Sigstore's TUF repository, whose
//! `trusted_root.json` names every transparency log, where each is served,
//! and the window each was in service for (docs/REKOR-ZONE-KEY.md §10).
//!
//! The walk and the verification are the client's, not a second copy of
//! them: [`synch_net::tuf`] against the same embedded root, persisting the
//! same `rekor-pins.json`. Nothing is trusted because it was fetched.
//!
//! §10.2's posture carries over intact: **TUF trouble is never worse than not
//! having asked.** A repository that is unreachable, stale, or serving
//! material that does not verify leaves the pins already in force standing,
//! and the run continues on them. The persisted state is the client's own
//! [`PinState`], so a monitor gets rollback and freeze bounds for free — a
//! mirror cannot walk it backwards to a retired shard.

use std::path::{Path, PathBuf};

use synch_net::{
    rekor::LogKeys,
    tuf::{self, HttpRepo, PinState, Repo, TufMetadata},
};

use crate::MonitorError;

/// Where the pin state lives, beside the monitor's own state file — the same
/// file name the client uses under its data directory.
pub fn pins_beside(state: &Path) -> PathBuf {
    match state.parent() {
        Some(dir) => dir.join("rekor-pins.json"),
        None => PathBuf::from("rekor-pins.json"),
    }
}

/// The shared [`HttpRepo`] at `base` (e.g. [`tuf::SIGSTORE_TUF_URL`]), with
/// its requests identified as the monitor's. The transport — and its byte
/// cap, which guards against the party this program audits — is
/// [`synch_net::tuf`]'s, not a second copy of it.
pub fn http_repo(base: &str) -> Result<HttpRepo, MonitorError> {
    HttpRepo::new(base, Some("synch-monitor")).map_err(MonitorError::Transport)
}

/// The logs a run should read, and the keys their checkpoints must verify
/// under.
///
/// **Every log the trusted root names, retired shards included**, and their
/// keys. A client accepts a proof from any shard whose key is pinned, and
/// `tlog_keys` pins every shard the trusted root lists, because a proof from a
/// retired shard is still a proof — an archival entry does not stop being
/// logged when its shard closes. The two halves therefore have to come out of
/// that one artifact through one filter: an entry in a pinned-but-unread shard
/// is client-valid and invisible, which is the "accepted by every client,
/// reported by no monitor" case the tiering exists to prevent, and it opens at
/// the first shard rotation.
#[derive(Debug, Clone)]
pub struct Discovered {
    /// Every log a checkpoint would be believed from, no trailing slashes.
    pub base_urls: Vec<String>,
    /// The keys of those logs. A checkpoint has to verify under the key of
    /// whichever shard signed it.
    pub keys: LogKeys,
    /// How `base_urls` was arrived at, for the line the run prints.
    pub source: &'static str,
}

/// Refreshes the pin state from `repo` when asked, then resolves the log to
/// read and the keys to verify it under.
///
/// `log_override` and `keys_override` are the operator's word and are taken
/// as given — the same "an override is a different universe" semantics as
/// `--dnssec-anchor`. Everything else comes from the trusted root in force.
///
/// A refresh that fails is reported to `warn` and otherwise ignored.
pub fn discover(
    repo: Option<&dyn Repo>,
    pins_path: &Path,
    log_override: Option<&str>,
    skipped: &[String],
    keys_override: Option<LogKeys>,
    now: u64,
    warn: &mut dyn FnMut(String),
) -> Result<Discovered, MonitorError> {
    let mut pins = PinState::load(pins_path).unwrap_or_else(PinState::embedded);
    let mut source = match pins.trusted_root.is_empty() {
        true => "embedded trusted root",
        false => "persisted TUF pins",
    };

    if let Some(repo) = repo {
        match refresh(repo, &pins, now) {
            Err(why) => warn(format!("TUF refresh failed, keeping current pins: {why}")),
            Ok(update) => {
                if update.changed {
                    if let Err(e) = update.state.save(pins_path) {
                        // Not fatal: the pins are good for this run, they
                        // just will not survive it.
                        warn(format!(
                            "could not persist pins to {}: {e}",
                            pins_path.display()
                        ));
                    }
                }
                pins = update.state;
                source = "TUF";
            }
        }
    }

    let keys = match keys_override {
        Some(keys) => keys,
        None => tuf::tlog_keys(pins.trusted_root_in_force())
            .map_err(|e| MonitorError::Checkpoint(format!("trusted root: {e}")))?,
    };

    // Every shard the trusted root names, newest first so the busy one is
    // walked before a long tail of retired ones. Ordering is presentation
    // only: a run reads all of them.
    let mut pinned = pins
        .tlogs()
        .map_err(|e| MonitorError::Checkpoint(format!("trusted root: {e}")))?;
    pinned.sort_by_key(|log| std::cmp::Reverse(log.valid_from));

    let base_urls = match log_override {
        Some(url) => {
            source = "--log";
            let url = url.trim_end_matches('/').to_string();
            // The operator's word, taken as given. It is still worth one line:
            // the pin set is unchanged, so this run believes checkpoints from
            // shards it is not reading, and an entry in one of those is
            // client-valid and unseen until a run without --log reads it.
            let unread: Vec<&str> = pinned
                .iter()
                .map(|log| log.base_url.as_str())
                .filter(|pinned| *pinned != url)
                .collect();
            if !unread.is_empty() {
                warn(format!(
                    "--log reads {url} only; {} other pinned shard(s) are not read this \
                     run ({}), and an entry in one of those is client-valid and unseen",
                    unread.len(),
                    unread.join(", ")
                ));
            }
            vec![url]
        }
        None => {
            if pinned.is_empty() {
                return Err(MonitorError::Checkpoint(
                    "the trusted root in force names no transparency log at all — \
                     pass --log to name one"
                        .into(),
                ));
            }
            // Shards the operator has said this monitor cannot read. Their
            // keys stay pinned, so this run still *believes* checkpoints from
            // them; what it stops doing is failing the whole run over a shard
            // it was never going to be able to walk. The trusted root pins one
            // such shard today — `rekor.sigstore.dev` is Rekor v1, a Trillian
            // API with no tiles — and every stock run filed it as a failure and
            // exited 30, permanently, which is the same as having no exit-code
            // signal at all.
            //
            // Named by the operator and never inferred from a response: a 404
            // is the audited party's own answer, and reading one as "not a
            // tiles log" would let a hostile or broken front end drop the live
            // shard from coverage and exit 0.
            let skipped: Vec<&String> = pinned
                .iter()
                .map(|log| &log.base_url)
                .filter(|url| skipped.iter().any(|s| s.trim_end_matches('/') == **url))
                .collect();
            if !skipped.is_empty() {
                warn(format!(
                    "--skip-log: {} pinned shard(s) are not read this run ({}); \
                     an entry in one of those is client-valid and unclassified",
                    skipped.len(),
                    skipped
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            let read: Vec<String> = pinned
                .iter()
                .map(|log| log.base_url.clone())
                .filter(|url| !skipped.contains(&url))
                .collect();
            if read.is_empty() {
                return Err(MonitorError::Checkpoint(
                    "every pinned shard is skipped, so this run would classify \
                     nothing at all"
                        .into(),
                ));
            }
            read
        }
    };

    Ok(Discovered {
        base_urls,
        keys,
        source,
    })
}

/// Walks the repository and verifies what it served.
fn refresh(repo: &dyn Repo, pins: &PinState, now: u64) -> Result<tuf::TufUpdate, String> {
    let bundle: TufMetadata =
        tuf::fetch_metadata(repo, pins.root_version).map_err(|e| e.to_string())?;
    tuf::update(&bundle, pins, now).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed instant inside the embedded trusted root's service windows.
    const NOW: u64 = 1_786_854_774;

    /// A repository that has nothing — how unreachable and empty mirrors both look.
    struct Empty;

    impl Repo for Empty {
        fn get(&self, _path: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
    }

    /// One discovery against a fresh pin file, returning its warnings.
    fn discover_with(
        repo: Option<&dyn Repo>,
        log: Option<&str>,
        skip: &[String],
    ) -> Result<(Discovered, Vec<String>), MonitorError> {
        let dir = tempfile::tempdir().unwrap();
        let mut warnings = Vec::new();
        let found = discover(
            repo,
            &pins_beside(&dir.path().join("monitor.json")),
            log,
            skip,
            None,
            NOW,
            &mut |w| warnings.push(w),
        )?;
        Ok((found, warnings))
    }

    #[test]
    fn with_no_repository_the_embedded_trusted_root_names_the_log() {
        let (found, warnings) = discover_with(None, None, &[]).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(found.source, "embedded trusted root");
        assert!(found.base_urls.iter().all(|u| u.starts_with("https://")));
        assert!(!found.keys.is_empty());
        // **Every pinned shard is read and every shard read is pinned**, retired ones included.
        let pinned = tuf::tlogs(tuf::EMBEDDED_TRUSTED_ROOT.as_bytes()).unwrap();
        assert_eq!(found.base_urls.len(), pinned.len());
        for log in &pinned {
            let unread = found.base_urls.contains(&log.base_url);
            assert!(unread, "pinned but unread: {}", log.base_url);
            let unpinned = found.keys.find(&log.log_id).is_some();
            assert!(unpinned, "read but unpinned: {}", log.base_url);
        }
    }

    /// The documented posture: TUF trouble is never worse than not asking —
    /// a failed refresh warns, keeps the pins, and runs on the embedded root.
    #[test]
    fn a_repository_that_serves_nothing_is_a_warning_and_not_a_failure() {
        let (found, warnings) = discover_with(Some(&Empty), None, &[]).unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("keeping current pins"), "{warnings:?}");
        assert_eq!(found.source, "embedded trusted root");
        assert!(!found.keys.is_empty());
    }

    /// `--log` is the operator's word, taken as given — one line says what the run is not reading.
    #[test]
    fn naming_one_log_says_which_pinned_shards_go_unread() {
        let (found, warnings) = discover_with(None, Some("https://log.example/"), &[]).unwrap();
        assert_eq!(found.base_urls, vec!["https://log.example".to_string()]);
        assert_eq!(found.source, "--log");
        // The keys are still the full pinned set, and the run says so.
        assert!(!found.keys.is_empty());
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("not read this run"), "{warnings:?}");
    }

    /// A shard the operator named unreadable is skipped, loudly; the rest proceed.
    #[test]
    fn a_skipped_shard_is_named_and_the_rest_are_still_read() {
        let pinned = tuf::tlogs(tuf::EMBEDDED_TRUSTED_ROOT.as_bytes()).unwrap();
        assert!(pinned.len() > 1, "needs more than one pinned shard");
        let skip = pinned[0].base_url.clone();
        let (found, warnings) = discover_with(None, None, std::slice::from_ref(&skip)).unwrap();
        assert!(!found.base_urls.contains(&skip));
        assert_eq!(found.base_urls.len(), pinned.len() - 1);
        // The pin set is untouched — this run still believes the skipped shard — hence the loss of coverage is worth saying.
        assert_eq!(found.keys.keys().len(), pinned.len());
        let named = warnings.iter().any(|w| w.contains(&skip));
        assert!(named, "the skipped shard must be named");
        let said = warnings.iter().any(|w| w.contains("unclassified"));
        assert!(said, "the loss of coverage must be said");
    }

    /// Skipping every shard would classify nothing, and says so rather than exiting 0 over an empty walk.
    #[test]
    fn skipping_every_shard_is_refused() {
        let logs = tuf::tlogs(tuf::EMBEDDED_TRUSTED_ROOT.as_bytes()).unwrap();
        let all: Vec<String> = logs.into_iter().map(|log| log.base_url).collect();
        discover_with(None, None, &all).expect_err("skipping every shard classifies nothing");
    }
}
