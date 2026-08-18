//! Node configuration and the tunables the design names (§5.3, §5.4, §6.3, §7.1).

use std::{path::PathBuf, time::Duration};

use synch_net::NetOptions;

use crate::error::{EngineError, Result};

/// Where a node's data directory lives by default (§10).
pub fn default_data_dir() -> Result<PathBuf> {
    directories::ProjectDirs::from("", "", "synchronicity")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .ok_or_else(|| EngineError::invalid("no platform data directory is available"))
}

/// How a node is configured.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// The data directory holding the database and the CAS.
    pub data_dir: PathBuf,
    /// How the endpoint is bound.
    pub net: NetOptions,
    /// The base anti-entropy round interval (§5.3, default 30 s with ±50 %
    /// jitter).
    pub aae_interval: Duration,
    /// The backstop interval between mirror passes (§7.2, default 60 s with
    /// ±50 % jitter). Passes normally run because the unified tree changed
    /// and rang the bell; the interval is only for drift nobody rang about —
    /// a `chmod` moves nothing a mirror record holds, and only a pass
    /// repairs it.
    pub mirror_interval: Duration,
    /// How long a scanner rescan waits after a watcher hint (§7.1).
    pub watch_debounce: Duration,
    /// Full rescan interval (§7.1).
    pub scan_interval: Duration,
    /// How long staging must go quiet before the publisher turns a batch into
    /// one new signed root (§7.1).
    pub publish_quiesce: Duration,
    /// How many staged entries force a batch out without waiting (§7.1).
    pub publish_batch_max: usize,
    /// Minimum interval between `BlobAd` republishes for one in-flight object
    /// (§6.3).
    pub ad_update_interval: Duration,
    /// How many providers a single range fetch is split across (§6.4).
    pub fetch_fanout: usize,
    /// The smallest object a fetch will run the delta descent for
    /// (`docs/DELTA-SYNC.md` §4, default 16 MiB — one ad span).
    ///
    /// Below it the proof round trips cost more than the bytes they could
    /// save, and inline blobs (§6.2) never delta at all. Setting it to
    /// [`u64::MAX`] turns the descent off for this node, which is the escape
    /// hatch for diagnosing a fetch that is behaving strangely — code-level,
    /// like [`NodeConfig::fetch_fanout`]: no shipped binary reads it from a
    /// file.
    pub delta_min_size: u64,
    /// How long a pending head may sit with an incomplete trie before the
    /// maintenance pass abandons it (§5.2).
    ///
    /// A head reaches the pending slot by reactive push (§5.3) long before its
    /// trie does, and `head_floor` is the best of both slots — so while it sits
    /// there the node refuses a peer's older but *servable* head for that
    /// origin, and materializes nothing for it. If the publisher goes offline
    /// between the push and the fetch, nobody can serve the pending trie and
    /// nothing else can be adopted in its place. Clearing it drops the floor
    /// and head selection re-runs.
    ///
    /// Thirty anti-entropy intervals at the defaults: long enough that every
    /// peer holding the trie has had many rounds to serve it, short enough that
    /// an origin is not stranded for an afternoon.
    pub pending_head_ttl: Duration,
    /// How long old roots are retained (§5.4).
    pub root_retention: Duration,
    /// How long this node's own tombstones are kept before a later root drops
    /// them (§4.2, default 90 days).
    pub tombstone_ttl: Duration,
    /// How long `synch recover` collects peer summaries before it lifts the
    /// publishing floor (§3.4).
    pub recovery_quiesce: Duration,
    /// How far above the highest seq peers advertised publishing resumes after
    /// recovery (§3.4).
    pub seq_gap: u64,
    /// The human-friendly node name published in `m:self`.
    pub name: String,
    /// How the DNSSEC resolver reaches the DNS: an optional DoH endpoint and
    /// an optional root-trust-anchor override (§3.2).
    pub dns: synch_net::ResolverOptions,
}

impl NodeConfig {
    /// Builds a configuration rooted at `data_dir` with the design defaults.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        NodeConfig {
            data_dir: data_dir.into(),
            net: NetOptions::default(),
            aae_interval: Duration::from_secs(30),
            mirror_interval: Duration::from_secs(60),
            watch_debounce: Duration::from_millis(500),
            scan_interval: Duration::from_secs(3600),
            publish_quiesce: crate::publisher::DEFAULT_PUBLISH_QUIESCE,
            publish_batch_max: crate::publisher::DEFAULT_PUBLISH_BATCH_MAX,
            ad_update_interval: Duration::from_secs(60),
            fetch_fanout: 3,
            delta_min_size: synch_core::AD_SPAN_GRANULARITY,
            pending_head_ttl: Duration::from_secs(900),
            root_retention: Duration::from_secs(7 * 24 * 3600),
            tombstone_ttl: Duration::from_secs(90 * 24 * 3600),
            recovery_quiesce: crate::recovery::DEFAULT_RECOVERY_QUIESCE,
            seq_gap: crate::recovery::DEFAULT_SEQ_GAP,
            name: hostname(),
            dns: synch_net::ResolverOptions::default(),
        }
    }

    /// Builds a configuration for a loopback-only, fully offline node.
    pub fn loopback(data_dir: impl Into<PathBuf>) -> Self {
        NodeConfig {
            net: NetOptions::loopback(),
            ..NodeConfig::new(data_dir)
        }
    }

    /// Uses the platform data directory.
    pub fn default_dir() -> Result<Self> {
        Ok(NodeConfig::new(default_data_dir()?))
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "synchronicity".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_design() {
        let config = NodeConfig::new("/tmp/x");
        assert_eq!(config.aae_interval, Duration::from_secs(30));
        assert_eq!(config.mirror_interval, Duration::from_secs(60));
        assert_eq!(config.watch_debounce, Duration::from_millis(500));
        assert_eq!(config.scan_interval, Duration::from_secs(3600));
        assert_eq!(config.publish_quiesce, Duration::from_secs(2));
        assert_eq!(config.publish_batch_max, 1_000);
        assert_eq!(config.ad_update_interval, Duration::from_secs(60));
        assert_eq!(config.fetch_fanout, 3);
        assert_eq!(config.delta_min_size, 16 * 1024 * 1024);
        assert_eq!(config.pending_head_ttl, Duration::from_secs(900));
        assert_eq!(config.root_retention, Duration::from_secs(7 * 24 * 3600));
        assert_eq!(config.tombstone_ttl, Duration::from_secs(90 * 24 * 3600));
        assert_eq!(config.recovery_quiesce, Duration::from_secs(3600));
        assert_eq!(config.seq_gap, 1_000);
    }

    #[test]
    fn loopback_is_offline() {
        assert!(NodeConfig::loopback("/tmp/x").net.offline);
    }
}
