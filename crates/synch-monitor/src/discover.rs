//! Finding the log: which shard to read, and which keys verify what it says.
//!
//! A monitor that hardcodes a hostname is a monitor that goes quiet the day
//! Sigstore opens the next shard — silently, because an empty log reads
//! exactly like a log with nothing new in it. So the endpoint is discovered
//! the same way the keys already were: from Sigstore's TUF repository, whose
//! `trusted_root.json` names every transparency log, where each is served,
//! and the window each was in service for (docs/REKOR-ZONE-KEY.md §10).
//!
//! The client learns this from a bundle a zone relays, because a client
//! resolves DNS and should not be made to depend on a CDN. A monitor has no
//! such constraint — it is already an HTTP client of a log it does not trust
//! — so it walks the repository itself and verifies what it gets with the
//! same [`synch_net::tuf`] code the client runs, against the same embedded
//! root. Nothing is trusted because it was fetched.
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
    tuf::{self, PinState, Repo, TufBundle},
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
                let body = response.bytes().map_err(|e| format!("{url}: {e}"))?;
                if body.len() > MAX_TUF_BYTES {
                    return Err(format!(
                        "{url}: {} bytes, over the {MAX_TUF_BYTES}-byte cap",
                        body.len()
                    ));
                }
                Ok(Some(body.to_vec()))
            }
            // The end of the root chain is a 404, and Sigstore's CDN answers
            // 403 for an object that is not there.
            403 | 404 => Ok(None),
            status => Err(format!("{url}: the repository answered {status}")),
        }
    }
}

/// The log a run should read, and the keys its checkpoints must verify under.
#[derive(Debug, Clone)]
pub struct Discovered {
    /// The log's base URL, no trailing slash.
    pub base_url: String,
    /// Every log the trusted root names, retired shards included: a proof
    /// from a closed shard is still a proof, and a checkpoint has to verify
    /// under the key of whichever shard signed it.
    pub keys: LogKeys,
    /// How `base_url` was arrived at, for the line the run prints.
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

    let base_url = match log_override {
        Some(url) => {
            source = "--log";
            url.trim_end_matches('/').to_string()
        }
        None => {
            let logs = pins
                .tlogs()
                .map_err(|e| MonitorError::Checkpoint(format!("trusted root: {e}")))?;
            tuf::current_tlog(&logs, now)
                .ok_or_else(|| {
                    MonitorError::Checkpoint(
                        "the trusted root in force names no transparency log in service \
                         right now — pass --log to name one"
                            .into(),
                    )
                })?
                .base_url
                .clone()
        }
    };

    Ok(Discovered {
        base_url,
        keys,
        source,
    })
}

/// Walks the repository and verifies what it served.
fn refresh(repo: &dyn Repo, pins: &PinState, now: u64) -> Result<tuf::TufUpdate, String> {
    let bundle: TufBundle =
        tuf::fetch_bundle(repo, pins.root_version).map_err(|e| e.to_string())?;
    tuf::update(&bundle, pins, now).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
            1_786_854_774,
            &mut |w| warnings.push(w),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(found.source, "embedded trusted root");
        assert!(found.base_url.starts_with("https://"));
        assert!(!found.keys.is_empty());
        // The log in service is one of the logs the root names, and the URL
        // is whatever that artifact says — asserted as a shape, not as a
        // hostname, because the hostname is exactly what this must not fix.
        let logs = tuf::tlogs(tuf::EMBEDDED_TRUSTED_ROOT.as_bytes()).unwrap();
        assert!(logs.iter().any(|log| log.base_url == found.base_url));
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
            1_786_854_774,
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
            1_786_854_774,
            &mut |w| warnings.push(w),
        )
        .unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(found.source, "embedded trusted root");
    }

    #[test]
    fn an_override_is_taken_as_given() {
        let dir = tempfile::tempdir().unwrap();
        let found = discover(
            None,
            &pins_beside(&dir.path().join("monitor.json")),
            Some("https://log.example/"),
            None,
            1_786_854_774,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(found.base_url, "https://log.example");
        assert_eq!(found.source, "--log");
    }
}
