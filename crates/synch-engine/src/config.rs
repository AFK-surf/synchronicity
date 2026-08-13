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
    /// How long a scanner rescan waits after a watcher hint (§7.1).
    pub watch_debounce: Duration,
    /// Full rescan interval (§7.1).
    pub scan_interval: Duration,
    /// Minimum interval between `BlobAd` republishes for one in-flight object
    /// (§6.3).
    pub ad_update_interval: Duration,
    /// How many providers a single range fetch is split across (§6.4).
    pub fetch_fanout: usize,
    /// How long old roots are retained (§5.4).
    pub root_retention: Duration,
    /// How long `synch recover` collects peer summaries before it lifts the
    /// publishing floor (§3.4).
    pub recovery_quiesce: Duration,
    /// How far above the highest seq peers advertised publishing resumes after
    /// recovery (§3.4).
    pub seq_gap: u64,
    /// The human-friendly node name published in `m:self`.
    pub name: String,
}

impl NodeConfig {
    /// Builds a configuration rooted at `data_dir` with the design defaults.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        NodeConfig {
            data_dir: data_dir.into(),
            net: NetOptions::default(),
            aae_interval: Duration::from_secs(30),
            watch_debounce: Duration::from_millis(500),
            scan_interval: Duration::from_secs(3600),
            ad_update_interval: Duration::from_secs(60),
            fetch_fanout: 3,
            root_retention: Duration::from_secs(7 * 24 * 3600),
            recovery_quiesce: crate::recovery::DEFAULT_RECOVERY_QUIESCE,
            seq_gap: crate::recovery::DEFAULT_SEQ_GAP,
            name: hostname(),
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
        assert_eq!(config.watch_debounce, Duration::from_millis(500));
        assert_eq!(config.scan_interval, Duration::from_secs(3600));
        assert_eq!(config.ad_update_interval, Duration::from_secs(60));
        assert_eq!(config.fetch_fanout, 3);
        assert_eq!(config.root_retention, Duration::from_secs(7 * 24 * 3600));
        assert_eq!(config.recovery_quiesce, Duration::from_secs(3600));
        assert_eq!(config.seq_gap, 1_000);
    }

    #[test]
    fn loopback_is_offline() {
        assert!(NodeConfig::loopback("/tmp/x").net.offline);
    }
}
