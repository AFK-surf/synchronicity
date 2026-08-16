//! Reading a Rekor v2 log the way it is actually published: as static tiles.
//!
//! Rekor v2 has no "give me entry N" API — `GET /api/v2/log/entries/<n>` is a
//! 404 and querying by index is a 501. What it has is the C2SP tlog-tiles
//! layout: a signed checkpoint, hash tiles, and *entry bundles* holding the
//! canonicalized bodies themselves. A monitor therefore does what an auditor
//! does, which is read the whole log, and that is a feature — indexing every
//! leaf by the apex in its certificate is only possible because there is no
//! server-side query to be lied to (docs/REKOR-ZONE-KEY.md §5.5).
//!
//! # The layout, exactly
//!
//! - `GET /api/v2/checkpoint` — the signed note.
//! - `GET /api/v2/tile/<level>/<path>` — 256 hashes at tree level `level × 8`.
//! - `GET /api/v2/tile/entries/<path>` — 256 entry bodies, each framed with a
//!   **big-endian `uint16` length prefix**.
//!
//! `<path>` is the tile's index written in three-digit groups from the right,
//! every group but the last prefixed with `x`: bundle 264 349 is `x264/349`.
//! A tile that is not yet full carries a `.p/<width>` suffix, so the frontier
//! of a growing log is fetched by width and never cached as if it were whole.
//!
//! # Why every proof here is computed from stored hashes
//!
//! A tile gives random access to every *complete-subtree* hash the log has
//! ever committed to. With that, a monitor needs no proof endpoint and has to
//! trust no proof the server hands it: it recomputes the root itself. The
//! whole of the verification is three uses of one primitive —
//! [`Tree::subtree_hash`]:
//!
//! - the tree matches the checkpoint when `subtree_hash(0, size)` is its root;
//! - the log is **consistent** with what this monitor saw last time when
//!   `subtree_hash(0, old_size)` is the root it persisted — that is exactly
//!   what an RFC 6962 consistency proof establishes, obtained here directly
//!   instead of asked for;
//! - an entry is **included** when its body hashes to `stored_hash(0, index)`,
//!   and the audit path this module derives walks to the checkpoint's root
//!   under `synch_net`'s own RFC 6962 walk — the same code the client runs.

use std::cell::RefCell;
use std::collections::HashMap;

use synch_net::rekor::{leaf_hash, node_hash, sha256};

use crate::MonitorError;

/// Where tiles come from.
#[allow(missing_debug_implementations)]
pub trait TileSource {
    /// Fetches one tile path, relative to the log's base URL.
    ///
    /// `Ok(None)` means the log answered 404 — a tile that does not exist,
    /// which is a fact about the tree, not a failure.
    fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError>;
}

/// A Rekor v2 log read over HTTPS, with an in-process cache.
///
/// The cache is what makes reading a 10⁸-entry log tolerable: one walk of a
/// bundle touches the same handful of hash tiles for every entry in it.
/// Partial tiles are cached under their width, so a frontier tile that grows
/// is a different cache entry rather than a stale one.
#[derive(Debug)]
pub struct HttpTiles {
    base: String,
    client: reqwest::blocking::Client,
    cache: RefCell<HashMap<String, Option<Vec<u8>>>>,
}

impl HttpTiles {
    /// A source reading from `base` (e.g. `https://log2025-1.rekor.sigstore.dev`).
    pub fn new(base: &str) -> Result<HttpTiles, MonitorError> {
        Ok(HttpTiles {
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::blocking::Client::builder()
                .user_agent("synch-monitor")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| MonitorError::Transport(e.to_string()))?,
            cache: RefCell::new(HashMap::new()),
        })
    }

    /// The signed checkpoint, verbatim.
    pub fn checkpoint(&self) -> Result<Vec<u8>, MonitorError> {
        self.fetch("api/v2/checkpoint")?
            .ok_or_else(|| MonitorError::Transport("the log serves no checkpoint".into()))
    }
}

impl TileSource for HttpTiles {
    fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
        if let Some(hit) = self.cache.borrow().get(path) {
            return Ok(hit.clone());
        }
        let url = format!("{}/{path}", self.base);
        let response = self
            .client
            .get(&url)
            .send()
            .map_err(|e| MonitorError::Transport(format!("{url}: {e}")))?;
        let body = match response.status().as_u16() {
            200 => Some(
                response
                    .bytes()
                    .map_err(|e| MonitorError::Transport(format!("{url}: {e}")))?
                    .to_vec(),
            ),
            404 => None,
            status => {
                return Err(MonitorError::Transport(format!(
                    "{url}: the log answered {status}"
                )))
            }
        };
        self.cache
            .borrow_mut()
            .insert(path.to_string(), body.clone());
        Ok(body)
    }
}

/// One tree, at one size, read through a [`TileSource`].
#[allow(missing_debug_implementations)]
pub struct Tree<'a> {
    source: &'a dyn TileSource,
    size: u64,
}

impl<'a> Tree<'a> {
    /// The tree of `size` leaves a checkpoint commits to.
    pub fn new(source: &'a dyn TileSource, size: u64) -> Tree<'a> {
        Tree { source, size }
    }

    /// The number of leaves.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The path of a tile, in the tlog-tiles naming scheme.
    fn path(level: &str, index: u64, width: u64) -> String {
        let mut groups = vec![format!("{:03}", index % 1000)];
        let mut rest = index / 1000;
        while rest > 0 {
            groups.insert(0, format!("x{:03}", rest % 1000));
            rest /= 1000;
        }
        let suffix = match width {
            256 => String::new(),
            width => format!(".p/{width}"),
        };
        format!("api/v2/tile/{level}/{}{suffix}", groups.join("/"))
    }

    /// How many hashes tile `(tile_level, index)` holds at this tree size.
    fn width(&self, tile_level: u32, index: u64) -> u64 {
        let available = (self.size >> (8 * tile_level)).saturating_sub(index * 256);
        available.min(256)
    }

    /// The bytes of a hash tile.
    fn hash_tile(&self, tile_level: u32, index: u64) -> Result<Vec<u8>, MonitorError> {
        let width = self.width(tile_level, index);
        if width == 0 {
            return Err(MonitorError::Tile(format!(
                "tile {tile_level}/{index} holds nothing at tree size {}",
                self.size
            )));
        }
        let path = Tree::path(&tile_level.to_string(), index, width);
        self.source
            .fetch(&path)?
            .ok_or_else(|| MonitorError::Tile(format!("{path} is missing")))
    }

    /// The hash of the complete subtree at `(level, index)`.
    ///
    /// Levels that are not a multiple of eight are not stored directly: a
    /// tile holds its base level and every higher node inside it is the hash
    /// of a contiguous run of those, which is what `fold` reconstructs.
    fn stored_hash(&self, level: u32, index: u64) -> Result<[u8; 32], MonitorError> {
        let tile_level = level / 8;
        let within = level % 8;
        let tile_index = (index << within) >> 8;
        let offset = index - ((tile_index << 8) >> within);
        let data = self.hash_tile(tile_level, tile_index)?;
        let start = (offset << within) as usize * 32;
        let end = ((offset + 1) << within) as usize * 32;
        let slice = data.get(start..end).ok_or_else(|| {
            MonitorError::Tile(format!(
                "node ({level},{index}) is past the end of tile {tile_level}/{tile_index}"
            ))
        })?;
        Ok(fold(slice))
    }

    /// The Merkle tree hash over leaves `[lo, hi)`.
    ///
    /// A range that is not a complete subtree is decomposed into the maximal
    /// aligned complete subtrees the log has stored, then folded from the
    /// right — RFC 6962's own recursion, expressed over stored hashes so that
    /// nothing has to be recomputed from leaves.
    pub fn subtree_hash(&self, lo: u64, hi: u64) -> Result<[u8; 32], MonitorError> {
        if lo >= hi {
            return Err(MonitorError::Tile(format!("empty range [{lo},{hi})")));
        }
        let mut parts = Vec::new();
        let mut at = lo;
        while at < hi {
            let mut span = max_pow2_le(hi - at);
            while at & (span - 1) != 0 {
                span /= 2;
            }
            parts.push(self.stored_hash(span.trailing_zeros(), at / span)?);
            at += span;
        }
        let mut hash = *parts.last().expect("non-empty range");
        for part in parts.iter().rev().skip(1) {
            hash = node_hash(part, &hash);
        }
        Ok(hash)
    }

    /// The Merkle root of the whole tree, recomputed from tiles.
    pub fn root(&self) -> Result<[u8; 32], MonitorError> {
        match self.size {
            0 => Ok(sha256(&[])),
            size => self.subtree_hash(0, size),
        }
    }

    /// The RFC 6962 audit path from leaf `index` to this tree's root.
    pub fn inclusion_path(&self, index: u64) -> Result<Vec<[u8; 32]>, MonitorError> {
        if index >= self.size {
            return Err(MonitorError::Tile(format!(
                "entry {index} is outside a tree of {}",
                self.size
            )));
        }
        self.path_within(0, self.size, index)
    }

    fn path_within(&self, lo: u64, hi: u64, index: u64) -> Result<Vec<[u8; 32]>, MonitorError> {
        if lo + 1 == hi {
            return Ok(Vec::new());
        }
        let split = lo + max_pow2_lt(hi - lo);
        match index < split {
            true => {
                let mut path = self.path_within(lo, split, index)?;
                path.push(self.subtree_hash(split, hi)?);
                Ok(path)
            }
            false => {
                let mut path = self.path_within(split, hi, index)?;
                path.push(self.subtree_hash(lo, split)?);
                Ok(path)
            }
        }
    }

    /// The bodies in the entry bundle covering `index`, in order.
    ///
    /// The framing is a big-endian `uint16` length before each body, 256 to a
    /// full bundle. Returned as `(index, body)` so a caller can name an entry
    /// without recomputing the arithmetic.
    pub fn entry_bundle(&self, index: u64) -> Result<Vec<(u64, Vec<u8>)>, MonitorError> {
        if index >= self.size {
            return Err(MonitorError::Tile(format!(
                "entry {index} is outside a tree of {}",
                self.size
            )));
        }
        let bundle = index / 256;
        let width = self.size.saturating_sub(bundle * 256).min(256);
        let path = Tree::path("entries", bundle, width);
        let data = self
            .source
            .fetch(&path)?
            .ok_or_else(|| MonitorError::Tile(format!("{path} is missing")))?;
        let mut out = Vec::with_capacity(width as usize);
        let mut at = 0usize;
        while at < data.len() {
            let length = match data.get(at..at + 2) {
                Some(header) => usize::from(u16::from_be_bytes([header[0], header[1]])),
                None => return Err(MonitorError::Tile(format!("{path}: truncated length"))),
            };
            at += 2;
            let body = data
                .get(at..at + length)
                .ok_or_else(|| MonitorError::Tile(format!("{path}: truncated entry")))?;
            out.push((bundle * 256 + out.len() as u64, body.to_vec()));
            at += length;
        }
        if out.len() as u64 != width {
            return Err(MonitorError::Tile(format!(
                "{path}: {} entries, expected {width}",
                out.len()
            )));
        }
        Ok(out)
    }

    /// Whether the entry at `index` really is the leaf the tree stored there.
    ///
    /// Cheap and total: the log's own hash tile already commits to the leaf,
    /// so a bundle body that hashes differently is a bundle the log did not
    /// serialize, caught before anything is parsed out of it.
    pub fn leaf_matches(&self, index: u64, body: &[u8]) -> Result<bool, MonitorError> {
        Ok(self.stored_hash(0, index)? == leaf_hash(body))
    }
}

/// A tile's internal node: the hash of a contiguous run of its base hashes.
fn fold(data: &[u8]) -> [u8; 32] {
    if data.len() == 32 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(data);
        return hash;
    }
    let half = data.len() / 2;
    node_hash(&fold(&data[..half]), &fold(&data[half..]))
}

/// The largest power of two strictly less than `n` — RFC 6962's split.
fn max_pow2_lt(n: u64) -> u64 {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The largest power of two at most `n`.
fn max_pow2_le(n: u64) -> u64 {
    let mut k = 1;
    while k * 2 <= n {
        k *= 2;
    }
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A whole log held in memory, served through the tile layout.
    ///
    /// Small enough to check by hand and large enough to have partial tiles,
    /// several tile levels and non-power-of-two frontiers — which is where
    /// stored-hash arithmetic goes wrong.
    struct MemoryLog {
        leaves: Vec<Vec<u8>>,
    }

    impl TileSource for MemoryLog {
        fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
            let rest = path.strip_prefix("api/v2/tile/").expect("tile path");
            let (level, rest) = rest.split_once('/').expect("level");
            let (digits, width) = match rest.split_once(".p/") {
                Some((digits, width)) => (digits, width.parse::<u64>().unwrap()),
                None => (rest, 256),
            };
            let index: u64 = digits.split('/').fold(0u64, |acc, group| {
                acc * 1000 + group.trim_start_matches('x').parse::<u64>().unwrap()
            });
            if level == "entries" {
                let mut out = Vec::new();
                for i in 0..width {
                    let body = &self.leaves[(index * 256 + i) as usize];
                    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                    out.extend_from_slice(body);
                }
                return Ok(Some(out));
            }
            let tile_level: u32 = level.parse().unwrap();
            let span = 1u64 << (8 * tile_level);
            let mut out = Vec::new();
            for i in 0..width {
                let start = (index * 256 + i) * span;
                out.extend_from_slice(&reference_root(&self.leaves, start, start + span));
            }
            Ok(Some(out))
        }
    }

    /// RFC 6962 §2.1, written out plainly so the tile arithmetic has
    /// something independent to be wrong against.
    fn reference_root(leaves: &[Vec<u8>], lo: u64, hi: u64) -> [u8; 32] {
        if lo + 1 == hi {
            return leaf_hash(&leaves[lo as usize]);
        }
        let split = lo + max_pow2_lt(hi - lo);
        node_hash(
            &reference_root(leaves, lo, split),
            &reference_root(leaves, split, hi),
        )
    }

    fn log(size: u64) -> MemoryLog {
        MemoryLog {
            leaves: (0..size)
                .map(|i| format!("entry {i}").into_bytes())
                .collect(),
        }
    }

    #[test]
    fn tile_paths_are_three_digit_groups_from_the_right() {
        assert_eq!(
            Tree::path("entries", 264_349, 256),
            "api/v2/tile/entries/x264/349"
        );
        assert_eq!(Tree::path("0", 0, 256), "api/v2/tile/0/000");
        assert_eq!(Tree::path("1", 7, 13), "api/v2/tile/1/007.p/13");
        assert_eq!(
            Tree::path("0", 1_234_567, 256),
            "api/v2/tile/0/x001/x234/567"
        );
    }

    #[test]
    fn roots_recomputed_from_tiles_match_the_reference_tree() {
        // Sizes that straddle every awkward boundary: a single leaf, one
        // short of a tile, exactly a tile, one past it, and two tile levels.
        for size in [1u64, 2, 3, 255, 256, 257, 511, 1000, 65_536, 65_537] {
            let log = log(size);
            let tree = Tree::new(&log, size);
            assert_eq!(
                tree.root().unwrap(),
                reference_root(&log.leaves, 0, size),
                "size {size}"
            );
        }
    }

    #[test]
    fn audit_paths_from_tiles_verify_under_the_clients_own_walk() {
        let size = 1_000u64;
        let log = log(size);
        let tree = Tree::new(&log, size);
        let root = tree.root().unwrap();
        for index in [0u64, 1, 255, 256, 511, 512, 998, 999] {
            let path = tree.inclusion_path(index).unwrap();
            synch_net::rekor::verify_inclusion(
                index,
                size,
                leaf_hash(&log.leaves[index as usize]),
                &path,
                root,
            )
            .unwrap_or_else(|e| panic!("index {index}: {e}"));
            assert!(tree
                .leaf_matches(index, &log.leaves[index as usize])
                .unwrap());
            assert!(!tree.leaf_matches(index, b"something else").unwrap());
        }
    }

    #[test]
    fn consistency_is_the_old_root_recomputed_from_the_new_trees_tiles() {
        // A tree that grew: the prefix's root, recomputed from the *new*
        // tree's stored hashes, is the root the monitor persisted. That is
        // precisely what an RFC 6962 consistency proof asserts, so a monitor
        // that can read tiles never has to ask for one.
        let grown = log(1_000);
        let old_root = reference_root(&grown.leaves, 0, 700);
        let tree = Tree::new(&grown, 1_000);
        assert_eq!(tree.subtree_hash(0, 700).unwrap(), old_root);
        // A forked log — one leaf rewritten inside the prefix — no longer
        // reproduces it, which is the split view the check exists to catch.
        let mut forked = log(1_000);
        forked.leaves[42] = b"a different history".to_vec();
        assert_ne!(
            Tree::new(&forked, 1_000).subtree_hash(0, 700).unwrap(),
            old_root
        );
    }

    #[test]
    fn entry_bundles_decode_their_length_framing() {
        let log = log(600);
        let tree = Tree::new(&log, 600);
        let full = tree.entry_bundle(0).unwrap();
        assert_eq!(full.len(), 256);
        assert_eq!(full[0], (0, b"entry 0".to_vec()));
        assert_eq!(full[255].0, 255);
        let partial = tree.entry_bundle(512).unwrap();
        assert_eq!(partial.len(), 88);
        assert_eq!(partial[0].0, 512);
        assert_eq!(partial[87], (599, b"entry 599".to_vec()));
        assert!(tree.entry_bundle(600).is_err());
    }
}
