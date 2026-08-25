//! Shared test fixture: a whole Rekor v2 log held in memory, served through
//! the tlog-tiles layout, with the tests' attacks as knobs on [`MemoryLog`].

use crate::tiles::TileSource;
use crate::MonitorError;
use std::sync::Mutex;
use synch_net::rekor::{leaf_hash, node_hash};

/// The root of the subtree over `leaves[lo..hi]` — plain RFC 6962 §2.1, so
/// the tile arithmetic has something independent to be wrong against.
pub fn reference_root(leaves: &[Vec<u8>], lo: u64, hi: u64) -> [u8; 32] {
    if lo + 1 == hi {
        return leaf_hash(&leaves[lo as usize]);
    }
    let mut span = 1u64;
    while span * 2 < hi - lo {
        span *= 2;
    }
    node_hash(
        &reference_root(leaves, lo, lo + span),
        &reference_root(leaves, lo + span, hi),
    )
}

/// Parses a tlog-tiles path into (level, tile index, width); 256 is a full tile.
pub(crate) fn parse_tile_path(path: &str) -> Option<(&str, u64, u64)> {
    let rest = path.strip_prefix("api/v2/tile/")?;
    let (level, rest) = rest.split_once('/')?;
    let (digits, width) = match rest.split_once(".p/") {
        Some((digits, width)) => (digits, width.parse().ok()?),
        None => (rest, 256),
    };
    let mut index = 0u64;
    for group in digits.split('/') {
        index = index * 1000 + group.trim_start_matches('x').parse::<u64>().ok()?;
    }
    Some((level, index, width))
}

/// A whole log held in memory; [`MemoryLog::paths`] replays every fetch in order.
#[derive(Debug, Default)]
pub struct MemoryLog {
    /// The leaves, in index order.
    pub leaves: Vec<Vec<u8>>,
    /// Forge this leaf: bundles serve `forged_body` for it and its level-0
    /// hash-tile entry becomes `leaf_hash(forged_body)`; higher tiles stay honest.
    pub forge_at: Option<u64>,
    /// The body served in place of the leaf at `forge_at`.
    pub forged_body: Vec<u8>,
    /// Fetches of the entry bundle starting at this index fail with a 503.
    pub fail_bundle_at: Option<u64>,
    /// Truncate every level-0 hash tile to this many bytes: a mis-sized tile.
    pub truncate_level0: Option<usize>,
    /// What `api/v2/checkpoint` answers, when a test needs one.
    pub checkpoint: Option<Vec<u8>>,
    fetched: Mutex<Vec<String>>,
}

impl MemoryLog {
    /// A log of `size` leaves, the i-th holding `entry {i}`.
    pub fn new(size: u64) -> MemoryLog {
        let leaves = (0..size).map(|i| format!("entry {i}").into_bytes());
        MemoryLog::from_leaves(leaves.collect())
    }

    /// A log serving exactly `leaves`, every knob disarmed.
    pub fn from_leaves(leaves: Vec<Vec<u8>>) -> MemoryLog {
        MemoryLog {
            leaves,
            ..Default::default()
        }
    }

    /// Every path fetched so far, in the order it was asked for.
    pub fn paths(&self) -> Vec<String> {
        self.fetched.lock().unwrap().clone()
    }
}

impl TileSource for MemoryLog {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
        self.fetched.lock().unwrap().push(path.to_string());
        if path == "api/v2/checkpoint" {
            return Ok(self.checkpoint.clone());
        }
        let (level, index, width) = parse_tile_path(path).expect("a tile path");
        let tile_level: u32 = match level {
            "entries" => 0,
            level => level.parse().expect("a tile level"),
        };
        // A width the log's growth has superseded is collected, like the real log's.
        let available = (self.leaves.len() as u64) >> (8 * tile_level);
        if width != available.saturating_sub(index * 256).min(256) {
            return Ok(None);
        }
        if level == "entries" {
            if self.fail_bundle_at == Some(index * 256) {
                return Err(MonitorError::Transport(format!("{path}: 503")));
            }
            let mut out = Vec::new();
            for i in 0..width {
                let at = index * 256 + i;
                let body = match self.forge_at == Some(at) {
                    true => &self.forged_body,
                    false => &self.leaves[at as usize],
                };
                out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                out.extend_from_slice(body);
            }
            return Ok(Some(out));
        }
        let span = 1u64 << (8 * tile_level);
        let mut out = Vec::new();
        for i in 0..width {
            let start = (index * 256 + i) * span;
            let hash = match (tile_level == 0, self.forge_at) {
                (true, Some(at)) if at == start => leaf_hash(&self.forged_body),
                _ => reference_root(&self.leaves, start, start + span),
            };
            out.extend_from_slice(&hash);
        }
        if let (0, Some(keep)) = (tile_level, self.truncate_level0) {
            out.truncate(keep);
        }
        Ok(Some(out))
    }

    async fn checkpoint_size(&self) -> Result<Option<u64>, MonitorError> {
        Ok(Some(self.leaves.len() as u64))
    }
}
