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
    tuf::{self, PinState, Repo, TufMetadata},
};

use crate::MonitorError;

/// The most a single TUF file may be.
///
/// Sigstore's `targets.json` is the big one at a few hundred KiB. The cap is
/// here for the same reason [`crate::tiles`] has one: these bytes come from a
/// party the monitor is auditing, and a response with no bound is a reader
/// that can be exhausted rather than a file that can be parsed.
const MAX_TUF_BYTES: usize = 8 * 1024 * 1024;

/// Where the pin state lives, beside the monitor's own state file — the same
/// file name the client uses under its data directory.
pub fn pins_beside(state: &Path) -> PathBuf {
    match state.parent() {
        Some(dir) => dir.join("rekor-pins.json"),
        None => PathBuf::from("rekor-pins.json"),
    }
}

/// A TUF repository read over HTTPS.
#[derive(Debug)]
pub struct HttpRepo {
    base: String,
    client: reqwest::blocking::Client,
}

impl HttpRepo {
    /// A repository at `base` (e.g. [`tuf::SIGSTORE_TUF_URL`]).
    pub fn new(base: &str) -> Result<HttpRepo, MonitorError> {
        Ok(HttpRepo {
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::blocking::Client::builder()
                .user_agent("synch-monitor")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| MonitorError::Transport(e.to_string()))?,
        })
    }
}

impl Repo for HttpRepo {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let url = format!("{}/{path}", self.base);
        let response = self
            .client
            .get(&url)
            .send()
            .map_err(|e| format!("{url}: {e}"))?;
        match response.status().as_u16() {
            200 => {
                // Read through a `take`, never `bytes()`. A cap applied to the
                // result of `bytes()` is a bound on nothing, because the
                // allocation has already happened — an endless body from a
                // hostile mirror exhausts the reader before the comparison
                // runs. One byte past the cap is read so that "exactly at the
                // cap" and "over it" are distinguishable.
                use std::io::Read;
                let mut body = Vec::new();
                response
                    .take(MAX_TUF_BYTES as u64 + 1)
                    .read_to_end(&mut body)
                    .map_err(|e| format!("{url}: {e}"))?;
                if body.len() > MAX_TUF_BYTES {
                    return Err(format!("{url}: over the {MAX_TUF_BYTES}-byte cap"));
                }
                Ok(Some(body))
            }
            // The end of the root chain is a 404, and Sigstore's CDN answers
            // 403 for an object that is not there.
            403 | 404 => Ok(None),
            status => Err(format!("{url}: the repository answered {status}")),
        }
    }
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
            pinned
                .iter()
                .map(|log| log.base_url.clone())
                .collect::<Vec<_>>()
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
    use std::collections::HashMap;

    /// A fixed instant inside the embedded trusted root's service windows.
    const NOW: u64 = 1_786_854_774;

    /// A repository that has nothing, which is how an unreachable mirror and
    /// an empty one both end up looking from here.
    struct Empty;

    impl Repo for Empty {
        fn get(&self, _path: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
    }

    /// A repository serving exactly the files it was handed.
    struct Fixed(HashMap<String, Vec<u8>>);

    impl Repo for Fixed {
        fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.get(path).cloned())
        }
    }

    #[test]
    fn with_no_repository_the_embedded_trusted_root_names_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let mut warnings = Vec::new();
        let found = discover(
            None,
            &pins_beside(&dir.path().join("monitor.json")),
            None,
            None,
            NOW,
            &mut |w| warnings.push(w),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(found.source, "embedded trusted root");
        assert!(found.base_urls.iter().all(|u| u.starts_with("https://")));
        assert!(!found.keys.is_empty());
        // **Every pinned shard is read, and every shard read is pinned.**
        // Retired ones included: the client accepts a proof from any shard
        // whose key is pinned, so a monitor that skipped the closed shards
        // would leave a client-valid entry permanently unseen. Asserted as a
        // set, and as a shape rather than as hostnames, because the hostnames
        // are what this must not fix.
        let pinned = tuf::tlogs(tuf::EMBEDDED_TRUSTED_ROOT.as_bytes()).unwrap();
        assert_eq!(found.base_urls.len(), pinned.len());
        for log in &pinned {
            assert!(
                found.base_urls.contains(&log.base_url),
                "{} is pinned but would not be read",
                log.base_url
            );
            assert!(
                found.keys.find(&log.log_id).is_some(),
                "{} would be read but its key is not pinned",
                log.base_url
            );
        }
    }

    #[test]
    fn a_repository_that_serves_nothing_is_a_warning_and_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mut warnings = Vec::new();
        let found = discover(
            Some(&Empty),
            &pins_beside(&dir.path().join("monitor.json")),
            None,
            None,
            NOW,
            &mut |w| warnings.push(w),
        )
        .unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("keeping current pins"), "{warnings:?}");
        assert_eq!(found.source, "embedded trusted root");
        assert!(!found.keys.is_empty());
    }

    #[test]
    fn a_repository_serving_tampered_metadata_leaves_the_pins_alone() {
        let dir = tempfile::tempdir().unwrap();
        // A root chain that starts where the embedded root does but carries
        // a file nobody signed: the walk collects it, `update` refuses it.
        let pins = PinState::embedded();
        let mut files = HashMap::new();
        files.insert(
            format!("{}.root.json", pins.root_version),
            br#"{"signed":{"_type":"root","version":99,"expires":"2099-01-01T00:00:00Z"},"signatures":[]}"#.to_vec(),
        );
        let mut warnings = Vec::new();
        let found = discover(
            Some(&Fixed(files)),
            &pins_beside(&dir.path().join("monitor.json")),
            None,
            None,
            NOW,
            &mut |w| warnings.push(w),
        )
        .unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(found.source, "embedded trusted root");
    }

    /// `--log` is the operator's word and is taken as given — with one line
    /// saying what the run is therefore not reading.
    ///
    /// The pin set is unchanged by it, so this run would believe a checkpoint
    /// from a shard it never asks for, and an entry there stays unseen until a
    /// run without the flag reads it. That is a coverage fact worth stating,
    /// not a reason to refuse an override.
    #[test]
    fn naming_one_log_says_which_pinned_shards_go_unread() {
        let dir = tempfile::tempdir().unwrap();
        let pins = pins_beside(&dir.path().join("monitor.json"));
        let mut warnings = Vec::new();
        let found = discover(
            None,
            &pins,
            Some("https://log.example/"),
            None,
            NOW,
            &mut |w| warnings.push(w),
        )
        .unwrap();
        assert_eq!(found.base_urls, vec!["https://log.example".to_string()]);
        assert_eq!(found.source, "--log");
        // The keys are still the full pinned set, and the run says so.
        assert!(!found.keys.is_empty());
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("not read this run"), "{warnings:?}");

        // Naming the one shard a single-log trusted root pins leaves nothing
        // unread, and says nothing.
        let pinned = tuf::tlogs(tuf::EMBEDDED_TRUSTED_ROOT.as_bytes()).unwrap();
        if let [only] = pinned.as_slice() {
            let mut quiet = Vec::new();
            discover(None, &pins, Some(&only.base_url), None, NOW, &mut |w| {
                quiet.push(w)
            })
            .unwrap();
            assert!(quiet.is_empty(), "{quiet:?}");
        }
    }
}
