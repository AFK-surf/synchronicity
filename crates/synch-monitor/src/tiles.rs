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
//!
//! # Fetching posture
//!
//! A log of 10⁸ entries is ~400 000 bundles; fetched one round-trip at a
//! time that is most of a day, so reads run ahead of consumption with a
//! bounded, caller-chosen concurrency — [`Tree::bundle_stream`] for the scan
//! itself, and the part reads inside [`Tree::subtree_hash`]. The bound stays
//! small on purpose: the log is free community infrastructure, and the
//! answer to "slow" is a handful of requests in flight, not a flood.
//! Transient failures — a 429, a 5xx, a dropped connection — are retried
//! with backoff a few times before a run gives up, because a reader that
//! fetches ahead meets more of them than one that does not.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use futures_util::stream::{self, Stream, StreamExt, TryStreamExt};
use synch_net::rekor::{leaf_hash, node_hash, sha256};

use crate::MonitorError;

/// The largest tile this reader will accept, **derived from the format
/// rather than guessed at**.
///
/// A full hash tile is 256 × 32 = 8 KiB. A full entry bundle is 256 bodies,
/// each framed by a big-endian `u16` length, so the largest one the wire
/// format can express is `256 × (2 + 65535)` = 16,777,472 bytes. The
/// previous bound was a round 16 MiB — 16,777,216 — which sits *256 bytes
/// below* that, so a bundle an honest log may legitimately serve was
/// refused. Since a refusal here is a hard error with no skip and no
/// progress saved, a single such bundle wedged every monitor permanently,
/// and an attacker able to land 256 consecutive maximal entries could put
/// one there on purpose.
///
/// The point of the bound stands: the log is the party this monitor is
/// auditing, so it is precisely the party whose response size must not be
/// taken on trust. It just has to be the *format's* ceiling, not a round
/// number near it.
const MAX_TILE_BYTES: usize = 256 * (2 + u16::MAX as usize);

/// Where tiles come from.
///
/// The returned future is required to be `Send` so a caller may run several
/// fetches at once; no implementor in this crate holds unsynchronized state
/// across an await.
#[allow(missing_debug_implementations)]
pub trait TileSource {
    /// Fetches one tile path, relative to the log's base URL.
    ///
    /// `Ok(None)` means the log answered 404 — a tile that does not exist,
    /// which is a fact about the tree, not a failure.
    fn fetch(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, MonitorError>> + Send;
}

/// A Rekor v2 log read over HTTPS, with an in-process cache.
///
/// The cache is what makes reading a 10⁸-entry log tolerable: one walk of a
/// bundle touches the same handful of hash tiles for every entry in it.
/// Partial tiles are cached under their width, so a frontier tile that grows
/// is a different cache entry rather than a stale one. The cache sits behind
/// a mutex so that fetches running concurrently can share it; two fetches
/// racing the same path may both go to the network, which is benign — the
/// bytes are the same and the last write wins.
#[derive(Debug)]
pub struct HttpTiles {
    base: String,
    client: reqwest::Client,
    cache: Mutex<HashMap<String, Option<Vec<u8>>>>,
}

/// How many times a fetch is tried before the run gives up, and the delay
/// before the first retry (doubled each time, capped at 8 s).
///
/// Retried at all because a reader that fetches ahead meets more transient
/// failures than a serial one; bounded because a log that is down is a
/// transport failure the run should report, not something to wait out.
const MAX_ATTEMPTS: u32 = 4;
const FIRST_RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(8);

impl HttpTiles {
    /// A source reading from `base` — the log [`crate::discover`] resolved,
    /// or whatever `--log` named.
    pub fn new(base: &str) -> Result<HttpTiles, MonitorError> {
        Ok(HttpTiles {
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .user_agent("synch-monitor")
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| MonitorError::Transport(e.to_string()))?,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The signed checkpoint, verbatim.
    pub async fn checkpoint(&self) -> Result<Vec<u8>, MonitorError> {
        self.fetch("api/v2/checkpoint")
            .await?
            .ok_or_else(|| MonitorError::Transport("the log serves no checkpoint".into()))
    }
}

impl TileSource for HttpTiles {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
        let cached = self.cache.lock().expect("tile cache").get(path).cloned();
        if let Some(hit) = cached {
            return Ok(hit);
        }
        let url = format!("{}/{path}", self.base);
        let mut delay = FIRST_RETRY_DELAY;
        let mut attempt = 1;
        let body = loop {
            let retryable = match self.client.get(&url).send().await {
                Ok(response) => match response.status().as_u16() {
                    200 => match read_capped(response).await {
                        Ok(Some(body)) => break Some(body),
                        // Over the cap is the server misbehaving, not a
                        // transient fault: retrying would just ask it to
                        // flood us again.
                        Ok(None) => {
                            return Err(MonitorError::Transport(format!(
                                "{url}: over the {MAX_TILE_BYTES}-byte cap"
                            )));
                        }
                        Err(e) => format!("{url}: {e}"),
                    },
                    404 => break None,
                    status @ (429 | 500..=599) => format!("{url}: the log answered {status}"),
                    status => {
                        return Err(MonitorError::Transport(format!(
                            "{url}: the log answered {status}"
                        )));
                    }
                },
                Err(e) => format!("{url}: {e}"),
            };
            attempt += 1;
            if attempt > MAX_ATTEMPTS {
                return Err(MonitorError::Transport(retryable));
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(MAX_RETRY_DELAY);
        };
        self.cache
            .lock()
            .expect("tile cache")
            .insert(path.to_string(), body.clone());
        Ok(body)
    }
}

/// Reads a response body, refusing to allocate past the tile cap.
///
/// `Ok(None)` means the cap was crossed. Streaming rather than `bytes()`:
/// a monitor reads from a log it does not trust, and `bytes()` on an
/// endless body allocates without limit — a bound applied to its result is
/// a bound on nothing, because the allocation has already happened. An
/// 8 KiB hash tile and a 256-entry bundle are both bounded by the format,
/// so anything past the cap is a server trying to exhaust the reader
/// rather than a tile.
///
/// The length check runs *before* each chunk is appended, so the buffer
/// never exceeds the cap at all.
async fn read_capped(mut response: reqwest::Response) -> Result<Option<Vec<u8>>, reqwest::Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_TILE_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// One tree, at one size, read through a [`TileSource`].
///
/// `concurrency` bounds how many tile fetches may be in flight at once: the
/// part reads inside [`Tree::subtree_hash`] and the read-ahead of
/// [`Tree::bundle_stream`]. It is clamped to at least one, and the right
/// value is small — the log is shared infrastructure.
#[allow(missing_debug_implementations)]
pub struct Tree<'a, S: TileSource> {
    source: &'a S,
    size: u64,
    concurrency: usize,
}

impl<'a, S: TileSource> Tree<'a, S> {
    /// The tree of `size` leaves a checkpoint commits to.
    pub fn new(source: &'a S, size: u64, concurrency: usize) -> Tree<'a, S> {
        Tree {
            source,
            size,
            concurrency: concurrency.max(1),
        }
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
    async fn hash_tile(&self, tile_level: u32, index: u64) -> Result<Vec<u8>, MonitorError> {
        let width = self.width(tile_level, index);
        if width == 0 {
            return Err(MonitorError::Tile(format!(
                "tile {tile_level}/{index} holds nothing at tree size {}",
                self.size
            )));
        }
        let path = Self::path(&tile_level.to_string(), index, width);
        self.source
            .fetch(&path)
            .await?
            .ok_or_else(|| MonitorError::Tile(format!("{path} is missing")))
    }

    /// The hash of the complete subtree at `(level, index)`.
    ///
    /// Levels that are not a multiple of eight are not stored directly: a
    /// tile holds its base level and every higher node inside it is the hash
    /// of a contiguous run of those, which is what `fold` reconstructs.
    async fn stored_hash(&self, level: u32, index: u64) -> Result<[u8; 32], MonitorError> {
        let tile_level = level / 8;
        let within = level % 8;
        // `index << within` overflows for a level/index pair a hostile log
        // can name; refuse rather than wrap into a different node.
        let shifted = index.checked_shl(within).ok_or_else(|| {
            MonitorError::Tile(format!("node ({level},{index}) is not addressable"))
        })?;
        let tile_index = shifted >> 8;
        let offset = index - ((tile_index << 8) >> within);
        let data = self.hash_tile(tile_level, tile_index).await?;
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
    ///
    /// The parts are independent tile reads and are fetched together, up to
    /// the tree's concurrency; the fold itself runs strictly in order.
    pub async fn subtree_hash(&self, lo: u64, hi: u64) -> Result<[u8; 32], MonitorError> {
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
            parts.push((span.trailing_zeros(), at / span));
            at += span;
        }
        let hashes = stream::iter(parts)
            .map(|(level, index)| self.stored_hash(level, index))
            .buffered(self.concurrency)
            .try_collect::<Vec<_>>()
            .await?;
        let mut hash = *hashes.last().expect("non-empty range");
        for part in hashes.iter().rev().skip(1) {
            hash = node_hash(part, &hash);
        }
        Ok(hash)
    }

    /// The Merkle root of the whole tree, recomputed from tiles.
    pub async fn root(&self) -> Result<[u8; 32], MonitorError> {
        match self.size {
            0 => Ok(sha256(&[])),
            size => self.subtree_hash(0, size).await,
        }
    }

    /// The RFC 6962 audit path from leaf `index` to this tree's root.
    pub async fn inclusion_path(&self, index: u64) -> Result<Vec<[u8; 32]>, MonitorError> {
        if index >= self.size {
            return Err(MonitorError::Tile(format!(
                "entry {index} is outside a tree of {}",
                self.size
            )));
        }
        // Walk from the root down to the leaf, noting the sibling range at
        // each level, then hash the siblings leaf-first — the order the
        // recursive formulation of this same walk produces them in.
        let mut siblings = Vec::new();
        let (mut lo, mut hi) = (0u64, self.size);
        while lo + 1 < hi {
            let split = lo + max_pow2_lt(hi - lo);
            if index < split {
                siblings.push((split, hi));
                hi = split;
            } else {
                siblings.push((lo, split));
                lo = split;
            }
        }
        let mut path = Vec::with_capacity(siblings.len());
        for (lo, hi) in siblings.into_iter().rev() {
            path.push(self.subtree_hash(lo, hi).await?);
        }
        Ok(path)
    }

    /// What to fetch to read the entry bundle covering `index`.
    ///
    /// Fetching and decoding are separate steps ([`Tree::bundle_request`],
    /// [`Tree::bundle_decode`]) so a caller can run many fetches at once and
    /// still decode strictly in order — which [`Tree::bundle_stream`] does.
    pub fn bundle_request(&self, index: u64) -> Result<BundleRequest, MonitorError> {
        if index >= self.size {
            return Err(MonitorError::Tile(format!(
                "entry {index} is outside a tree of {}",
                self.size
            )));
        }
        let first_index = (index / 256) * 256;
        let count = self.size.saturating_sub(first_index).min(256);
        let path = Self::path("entries", index / 256, count);
        Ok(BundleRequest {
            first_index,
            count,
            path,
        })
    }

    /// Decodes the bundle fetched for `request`.
    ///
    /// The framing is a big-endian `uint16` length before each body, 256 to a
    /// full bundle. Returned as `(index, body)` so a caller can name an entry
    /// without recomputing the arithmetic.
    pub fn bundle_decode(
        &self,
        request: &BundleRequest,
        data: &[u8],
    ) -> Result<Vec<(u64, Vec<u8>)>, MonitorError> {
        let mut out = Vec::with_capacity(request.count as usize);
        let mut at = 0usize;
        while at < data.len() {
            let length = match data.get(at..at + 2) {
                Some(header) => usize::from(u16::from_be_bytes([header[0], header[1]])),
                None => {
                    return Err(MonitorError::Tile(format!(
                        "{}: truncated length",
                        request.path
                    )))
                }
            };
            at += 2;
            let body = data
                .get(at..at + length)
                .ok_or_else(|| MonitorError::Tile(format!("{}: truncated entry", request.path)))?;
            out.push((request.first_index + out.len() as u64, body.to_vec()));
            at += length;
        }
        if out.len() as u64 != request.count {
            return Err(MonitorError::Tile(format!(
                "{}: {} entries, expected {}",
                request.path,
                out.len(),
                request.count
            )));
        }
        Ok(out)
    }

    /// The bodies in the entry bundle covering `index`, in order.
    ///
    /// For reading one bundle. A scan wants [`Tree::bundle_stream`], which
    /// fetches ahead instead of one round-trip per bundle.
    pub async fn entry_bundle(&self, index: u64) -> Result<Vec<(u64, Vec<u8>)>, MonitorError> {
        let request = self.bundle_request(index)?;
        let data = self
            .source
            .fetch(&request.path)
            .await?
            .ok_or_else(|| MonitorError::Tile(format!("{} is missing", request.path)))?;
        self.bundle_decode(&request, &data)
    }

    /// Every entry bundle covering `[from, to)`, in index order, with up to
    /// the tree's concurrency of fetches in flight.
    ///
    /// `to` must not exceed the tree's size, and may sit mid-bundle — the
    /// bundle holding it is read whole and the caller skips past what it did
    /// not ask for, exactly as with [`Tree::entry_bundle`]. An empty range
    /// yields an empty stream.
    ///
    /// The order guarantee is the contract: fetching runs ahead of decoding,
    /// but bundles leave the stream strictly in index order, so a consumer's
    /// "how far have I read" bookkeeping stays deterministic.
    pub fn bundle_stream(
        &self,
        from: u64,
        to: u64,
    ) -> impl Stream<Item = Result<Vec<(u64, Vec<u8>)>, MonitorError>> + '_ {
        let firsts: Vec<u64> = match from < to {
            true => ((from / 256)..=((to - 1) / 256))
                .map(|bundle| bundle * 256)
                .collect(),
            false => Vec::new(),
        };
        stream::iter(firsts)
            .map(move |first| async move {
                let request = self.bundle_request(first)?;
                let data =
                    self.source.fetch(&request.path).await?.ok_or_else(|| {
                        MonitorError::Tile(format!("{} is missing", request.path))
                    })?;
                self.bundle_decode(&request, &data)
            })
            .buffered(self.concurrency)
    }

    /// Whether the entry at `index` really is the leaf the tree stored there.
    ///
    /// Cheap and total: the log's own hash tile already commits to the leaf,
    /// so a bundle body that hashes differently is a bundle the log did not
    /// serialize, caught before anything is parsed out of it.
    pub async fn leaf_matches(&self, index: u64, body: &[u8]) -> Result<bool, MonitorError> {
        Ok(self.stored_hash(0, index).await? == leaf_hash(body))
    }
}

/// One entry bundle to fetch, as [`Tree::bundle_request`] describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleRequest {
    /// The index of the bundle's first entry.
    pub first_index: u64,
    /// How many entries the bundle holds at this tree size.
    pub count: u64,
    /// The tile path to fetch.
    pub path: String,
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
///
/// Checked for the same reason as [`max_pow2_le`]: the bound comes from the
/// log.
fn max_pow2_lt(n: u64) -> u64 {
    let mut k = 1u64;
    while k.checked_mul(2).is_some_and(|next| next < n) {
        k *= 2;
    }
    k
}

/// The largest power of two at most `n`.
///
/// The doubling is checked: `n` reaches this function from a tree size the
/// *log* chose, and an unchecked `k * 2` overflows and panics (debug) or
/// wraps to zero and spins (release) for sizes near `u64::MAX`. A monitor
/// must not be crashable by the thing it is auditing.
fn max_pow2_le(n: u64) -> u64 {
    let mut k = 1u64;
    while k.checked_mul(2).is_some_and(|next| next <= n) {
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
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
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
            Tree::<MemoryLog>::path("entries", 264_349, 256),
            "api/v2/tile/entries/x264/349"
        );
        assert_eq!(Tree::<MemoryLog>::path("0", 0, 256), "api/v2/tile/0/000");
        assert_eq!(
            Tree::<MemoryLog>::path("1", 7, 13),
            "api/v2/tile/1/007.p/13"
        );
        assert_eq!(
            Tree::<MemoryLog>::path("0", 1_234_567, 256),
            "api/v2/tile/0/x001/x234/567"
        );
    }

    #[tokio::test]
    async fn roots_recomputed_from_tiles_match_the_reference_tree() {
        // Sizes that straddle every awkward boundary: a single leaf, one
        // short of a tile, exactly a tile, one past it, and two tile levels.
        for size in [1u64, 2, 3, 255, 256, 257, 511, 1000, 65_536, 65_537] {
            let log = log(size);
            let tree = Tree::new(&log, size, 8);
            assert_eq!(
                tree.root().await.unwrap(),
                reference_root(&log.leaves, 0, size),
                "size {size}"
            );
        }
    }

    #[tokio::test]
    async fn audit_paths_from_tiles_verify_under_the_clients_own_walk() {
        let size = 1_000u64;
        let log = log(size);
        // Concurrency 1: nothing here may depend on fetches overlapping.
        let tree = Tree::new(&log, size, 1);
        let root = tree.root().await.unwrap();
        for index in [0u64, 1, 255, 256, 511, 512, 998, 999] {
            let path = tree.inclusion_path(index).await.unwrap();
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
                .await
                .unwrap());
            assert!(!tree.leaf_matches(index, b"something else").await.unwrap());
        }
    }

    #[tokio::test]
    async fn consistency_is_the_old_root_recomputed_from_the_new_trees_tiles() {
        // A tree that grew: the prefix's root, recomputed from the *new*
        // tree's stored hashes, is the root the monitor persisted. That is
        // precisely what an RFC 6962 consistency proof asserts, so a monitor
        // that can read tiles never has to ask for one.
        let grown = log(1_000);
        let old_root = reference_root(&grown.leaves, 0, 700);
        let tree = Tree::new(&grown, 1_000, 4);
        assert_eq!(tree.subtree_hash(0, 700).await.unwrap(), old_root);
        // A forked log — one leaf rewritten inside the prefix — no longer
        // reproduces it, which is the split view the check exists to catch.
        let mut forked = log(1_000);
        forked.leaves[42] = b"a different history".to_vec();
        assert_ne!(
            Tree::new(&forked, 1_000, 4)
                .subtree_hash(0, 700)
                .await
                .unwrap(),
            old_root
        );
    }

    #[tokio::test]
    async fn entry_bundles_decode_their_length_framing() {
        let log = log(600);
        let tree = Tree::new(&log, 600, 4);
        let full = tree.entry_bundle(0).await.unwrap();
        assert_eq!(full.len(), 256);
        assert_eq!(full[0], (0, b"entry 0".to_vec()));
        assert_eq!(full[255].0, 255);
        let partial = tree.entry_bundle(512).await.unwrap();
        assert_eq!(partial.len(), 88);
        assert_eq!(partial[0].0, 512);
        assert_eq!(partial[87], (599, b"entry 599".to_vec()));
        assert!(tree.entry_bundle(600).await.is_err());
    }

    #[tokio::test]
    async fn bundle_streams_decode_every_bundle_strictly_in_order() {
        let log = log(1_000);
        // Deliberately below the bundle count, so read-ahead has work in
        // flight and the in-order contract is what is being exercised.
        let tree = Tree::new(&log, 1_000, 2);
        let bundles: Vec<Vec<(u64, Vec<u8>)>> =
            tree.bundle_stream(0, 1_000).try_collect().await.unwrap();
        assert_eq!(bundles.len(), 4);
        for (expected_first, bundle) in [0u64, 256, 512, 768].into_iter().zip(&bundles) {
            assert_eq!(bundle.first().unwrap().0, expected_first);
        }
        // The stream agrees with the one-bundle reader on content.
        assert_eq!(bundles[0], tree.entry_bundle(0).await.unwrap());
        assert_eq!(bundles[3].len(), 232);
        assert_eq!(bundles[3][231].0, 999);

        // A mid-bundle start still reads the whole bundle and leaves the
        // skipping to the caller; an empty range is an empty stream.
        let mid: Vec<Vec<(u64, Vec<u8>)>> =
            tree.bundle_stream(100, 300).try_collect().await.unwrap();
        assert_eq!(mid.len(), 2);
        assert_eq!(mid[0][0].0, 0);
        let empty: Vec<Vec<(u64, Vec<u8>)>> =
            tree.bundle_stream(500, 500).try_collect().await.unwrap();
        assert!(empty.is_empty());
    }

    /// A log whose hash tiles are honest and whose entry bundles are not.
    ///
    /// This is the shape of the attack `leaf_matches` exists to catch, and
    /// the reason the check has to run *before* the walk decides to skip an
    /// entry: the hash tiles still commit to the real leaves, so the
    /// checkpoint root, the consistency proof and every inclusion path
    /// continue to verify. Only the bundle lies. A monitor that parsed the
    /// bundle first and skipped on "does not parse" or "not a watched zone"
    /// would drop the substituted entry without ever hashing it — silent,
    /// while the victim's client still accepts the genuine proof.
    struct TamperedBundles {
        honest: MemoryLog,
        at: u64,
        instead: Vec<u8>,
    }

    impl TileSource for TamperedBundles {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
            let served = self.honest.fetch(path).await?;
            if !path.starts_with("api/v2/tile/entries/") {
                // Hash tiles pass through untouched: the tree stays valid.
                return Ok(served);
            }
            let mut leaves = self.honest.leaves.clone();
            leaves[self.at as usize] = self.instead.clone();
            let bundle = self.at / 256;
            let width = (leaves.len() as u64).saturating_sub(bundle * 256).min(256);
            let mut out = Vec::new();
            for i in 0..width {
                let body = &leaves[(bundle * 256 + i) as usize];
                out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                out.extend_from_slice(body);
            }
            Ok(Some(out))
        }
    }

    #[tokio::test]
    async fn a_substituted_entry_body_does_not_match_the_leaf_the_log_committed_to() {
        let honest = log(600);
        let tampered = TamperedBundles {
            honest: log(600),
            at: 300,
            // Something that would fail `HashedRekordBody::parse`, which is
            // the cheapest way for a log to make an entry "uninteresting".
            instead: b"not an entry at all".to_vec(),
        };

        // The tree is unchanged as far as every hash-based check can tell:
        // same size, same root, same inclusion paths.
        let honest_tree = Tree::new(&honest, 600, 1);
        let tampered_tree = Tree::new(&tampered, 600, 1);
        assert_eq!(
            tampered_tree.subtree_hash(0, 600).await.unwrap(),
            honest_tree.subtree_hash(0, 600).await.unwrap(),
            "the hash tiles are honest, which is what makes this attack work"
        );

        // The bundle really does serve the substitute...
        let bundle = tampered_tree.entry_bundle(300).await.unwrap();
        let served = &bundle
            .iter()
            .find(|(index, _)| *index == 300)
            .expect("entry 300")
            .1;
        assert_eq!(served, b"not an entry at all");

        // ...and this is the one check that notices.
        assert!(
            !tampered_tree.leaf_matches(300, served).await.unwrap(),
            "a body the log did not commit to must not match its leaf"
        );
        assert!(
            honest_tree.leaf_matches(300, b"entry 300").await.unwrap(),
            "and the honest body must still match"
        );
    }
}
