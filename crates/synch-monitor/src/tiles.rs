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
//! - an entry is **included** when its body hashes to the leaf the level-0
//!   hash tile stores for it *and that tile is authenticated against the
//!   checkpoint* ([`Tree::verify_leaf`]).
//!
//! The second half of the third one is load-bearing. A comparison against
//! `stored_hash(0, index)` on its own binds a body to nothing the log signed:
//! that node lives in a level-0 hash tile fetched as its own resource, and the
//! root recomputation over a production-sized tree reads **no level-0 tile at
//! all** — a tree of 10⁸ leaves folds its root from three tiles, at levels 1,
//! 2 and 3 — so essentially every interior level-0 tile is unverified. A log
//! can serve a forged body together with the one level-0 hash covering it,
//! leave every higher tile honest, and satisfy the comparison while the root
//! and the consistency prefix still check out.
//!
//! [`Tree::verify_leaf`] closes that by authenticating the *tile*: fold its
//! 256 hashes into the single node they are, compare that against the entry
//! the level-1 tile holds for it, and climb — each tile checked against its
//! parent — until a tile the checkpoint-root recomputation itself consumed.
//! One fold per tile, memoized, so 256 entries share it.
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
//!
//! A run pins one checkpoint and then reads for minutes while the log keeps
//! integrating, so the one failure retries cannot fix is a *superseded*
//! partial: the frontier tile the pinned size named is collected as the tree
//! grows past it, and a walk that reaches the frontier last meets a 404 at
//! the very end. That 404 is a stale width, not a broken log — [`Tree`]
//! re-resolves the size the log commits to now, reads the tile at the width
//! that size implies, and keeps only the pinned prefix. Tiles are
//! append-only, so the prefix is byte-for-byte what the pinned checkpoint
//! committed to, and every consumer verifies against that checkpoint exactly
//! as if the narrower tile had still been there.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use futures_util::stream::{self, Stream, StreamExt, TryStreamExt};
use synch_net::rekor::{leaf_hash, node_hash, sha256, Checkpoint};

use crate::MonitorError;

/// The largest entry bundle this reader will accept, **derived from the
/// format rather than guessed at**.
///
/// A full entry bundle is 256 bodies, each framed by a big-endian `u16`
/// length, so the largest one the wire format can express is
/// `256 × (2 + 65535)` = 16,777,472 bytes — 256 bytes *above* a round 16 MiB,
/// and a bundle an honest log may legitimately serve. Since a refusal here is
/// a hard error with no skip and no progress saved, a bound below the
/// format's ceiling wedges a monitor permanently on a bundle of 256 maximal
/// entries, which an attacker able to land 256 consecutive maximal entries
/// can arrange.
///
/// The point of the bound stands: the log is the party this monitor is
/// auditing, so it is precisely the party whose response size must not be
/// taken on trust. It just has to be the *format's* ceiling, not a round
/// number near it.
const MAX_BUNDLE_BYTES: usize = 256 * (2 + u16::MAX as usize);

/// The largest hash tile this reader will accept: 256 nodes of 32 bytes.
///
/// A hash tile is bounded by its format at 8 KiB, so it gets the 8 KiB bound
/// and not the entry bundle's. One cap for both resources would let a hostile
/// log answer a hash-tile fetch with 16 MiB — times the run's concurrency,
/// and a scan asks for hash tiles constantly — for bytes that cannot be a
/// tile at any tree size.
const MAX_HASH_TILE_BYTES: usize = 256 * 32;

/// The largest checkpoint this reader will accept.
///
/// A signed note is a handful of text lines plus one signature line per
/// signer, and a production Sigstore checkpoint carries the log's own plus
/// one per witness that cosigned the tree. The number of witnesses is not
/// bounded by the format, so unlike the two above this is a policy number:
/// ~600 signature lines, far past any real witness set, and nowhere near
/// enough to be a memory attack.
const MAX_CHECKPOINT_BYTES: usize = 64 * 1024;

/// The response cap that applies to `path`.
///
/// Three resources, three format ceilings: an entry bundle is megabytes, a
/// hash tile is 8 KiB, a checkpoint is a note.
fn cap_for(path: &str) -> usize {
    match path.starts_with("api/v2/tile/entries/") {
        true => MAX_BUNDLE_BYTES,
        false => match path.starts_with("api/v2/tile/") {
            true => MAX_HASH_TILE_BYTES,
            false => MAX_CHECKPOINT_BYTES,
        },
    }
}

/// How many times a vanished partial tile is re-resolved against the log's
/// current size before the run gives up. One pass almost always settles it —
/// the checkpoint read and the tile fetch are a round-trip apart — but a log
/// integrating faster than that can outgrow the fresh width as well, and the
/// bound keeps that chase from following the frontier forever.
const MAX_WIDTH_CHASES: u32 = 4;

/// Where tiles come from.
///
/// The returned future is required to be `Send` so a caller may run several
/// fetches at once; no implementor in this crate holds unsynchronized state
/// across an await.
#[allow(missing_debug_implementations)]
pub trait TileSource {
    /// Fetches one tile path, relative to the log's base URL.
    ///
    /// `Ok(None)` means the log answered 404. For a full tile that is a fact
    /// about the tree; for a partial one it may only mean the log has grown
    /// past the width asked for — [`Tree`] consults
    /// [`TileSource::checkpoint_size`] before believing it.
    fn fetch(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, MonitorError>> + Send;

    /// The tree size the log's *current* checkpoint commits to, asked of the
    /// log anew on every call.
    ///
    /// [`Tree`] wants this when a partial tile 404s: a partial names the
    /// frontier of the tree at one size, and a log that has grown since
    /// serves that tile wider — or whole. `Ok(None)` means this source
    /// cannot say — a fixture, a static mirror — and a missing partial then
    /// stays missing.
    ///
    /// The size only ever *widens* a fetch, and nothing here verifies it.
    /// That is safe because the bytes it leads to are cut back to the pinned
    /// width and verified against the pinned checkpoint like everything
    /// else: a log lying about its size can make a run fail, which a broken
    /// log can do anyway, but cannot make wrong bytes pass.
    fn checkpoint_size(&self) -> impl Future<Output = Result<Option<u64>, MonitorError>> + Send {
        async { Ok(None) }
    }
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

    /// One GET, with retries, never cached.
    ///
    /// [`TileSource::fetch`] adds the cache; [`TileSource::checkpoint_size`]
    /// takes this path directly, because the caller asks precisely when the
    /// size it pinned has gone stale, and a cached answer would be the stale
    /// one.
    async fn get(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
        let url = format!("{}/{path}", self.base);
        let cap = cap_for(path);
        let mut delay = FIRST_RETRY_DELAY;
        let mut attempt = 1;
        loop {
            let retryable = match self.client.get(&url).send().await {
                Ok(response) => match response.status().as_u16() {
                    200 => match read_capped(response, cap).await {
                        Ok(Some(body)) => return Ok(Some(body)),
                        // Over the cap is the server misbehaving, not a
                        // transient fault: retrying would just ask it to
                        // flood us again.
                        Ok(None) => {
                            return Err(MonitorError::Transport(format!(
                                "{url}: over the {cap}-byte cap"
                            )));
                        }
                        Err(e) => format!("{url}: {e}"),
                    },
                    404 => return Ok(None),
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
        }
    }
}

impl HttpTiles {
    /// The cache, through a poisoned lock as readily as a healthy one.
    ///
    /// A panic while the cache was held would poison the mutex, and a
    /// `.expect()` here would turn that into a second panic in the auditing
    /// party's hot path — a monitor that stops on the way through a log it is
    /// halfway across. The cache holds no invariant worth protecting: it is
    /// path → bytes, every value re-fetchable, so the recovery is to carry on
    /// with the map as it stands.
    fn cached(&self) -> std::sync::MutexGuard<'_, HashMap<String, Option<Vec<u8>>>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl TileSource for HttpTiles {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
        let cached = self.cached().get(path).cloned();
        if let Some(hit) = cached {
            return Ok(hit);
        }
        let body = self.get(path).await?;
        self.cached().insert(path.to_string(), body.clone());
        Ok(body)
    }

    async fn checkpoint_size(&self) -> Result<Option<u64>, MonitorError> {
        let body = self
            .get("api/v2/checkpoint")
            .await?
            .ok_or_else(|| MonitorError::Transport("the log serves no checkpoint".into()))?;
        let checkpoint = Checkpoint::parse(&body).map_err(|e| {
            MonitorError::Transport(format!("the log's current checkpoint does not parse: {e}"))
        })?;
        Ok(Some(checkpoint.tree_size))
    }
}

/// Reads a response body, refusing to allocate past `cap` — [`cap_for`]'s
/// answer for the resource being fetched.
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
async fn read_capped(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<Option<Vec<u8>>, reqwest::Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > cap {
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
    /// The hash tiles already folded up to the checkpoint's root, by
    /// `(tile level, index)` — see [`Tree::authenticate_tile`]. A tile holds
    /// 256 entries, so this is what turns a per-entry cost into a per-tile
    /// one. Per tree, because a tree is one checkpoint.
    authenticated: Mutex<std::collections::HashSet<(u32, u64)>>,
}

impl<'a, S: TileSource> Tree<'a, S> {
    /// The tree of `size` leaves a checkpoint commits to.
    pub fn new(source: &'a S, size: u64, concurrency: usize) -> Tree<'a, S> {
        Tree {
            source,
            size,
            concurrency: concurrency.max(1),
            authenticated: Mutex::new(std::collections::HashSet::new()),
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

    /// How many hashes tile `(tile_level, index)` holds in a tree of `size`.
    fn width_at(size: u64, tile_level: u32, index: u64) -> u64 {
        let available = (size >> (8 * tile_level)).saturating_sub(index * 256);
        available.min(256)
    }

    /// How many hashes tile `(tile_level, index)` holds at this tree size.
    fn width(&self, tile_level: u32, index: u64) -> u64 {
        Self::width_at(self.size, tile_level, index)
    }

    /// The bytes of tile `(level, index)` at the width the pinned size names,
    /// recovering when the log has grown past it.
    ///
    /// A partial tile names the frontier of the tree at one instant; by the
    /// time a long walk asks for it, a log still integrating may serve that
    /// tile wider — or whole — and have collected the width the pinned size
    /// named. A 404 on the pinned path is therefore not yet a broken log:
    /// re-resolve the current size, and if it widens this tile, fetch the
    /// wider tile and keep only the pinned prefix. Tiles are append-only, so
    /// that prefix is byte-for-byte what the pinned checkpoint committed to,
    /// and everything downstream verifies against that checkpoint regardless
    /// of where the bytes were found.
    ///
    /// `tile_level` drives the width arithmetic — 0 for entry bundles, which
    /// hold framed entries rather than 32-byte nodes but tile identically.
    async fn tile_bytes(
        &self,
        level: &str,
        tile_level: u32,
        index: u64,
        width: u64,
    ) -> Result<Vec<u8>, MonitorError> {
        let path = Self::path(level, index, width);
        if let Some(data) = self.source.fetch(&path).await? {
            return Ok(data);
        }
        let mut width_now = width;
        for _ in 0..MAX_WIDTH_CHASES {
            if width_now == 256 {
                break; // a full tile is permanent; missing means a broken log
            }
            let size = match self.source.checkpoint_size().await? {
                Some(size) => size,
                None => break, // this source cannot say whether the log grew
            };
            let widened = Self::width_at(size, tile_level, index);
            if widened <= width_now {
                break; // the log has not grown into this tile: genuinely missing
            }
            width_now = widened;
            let wider_path = Self::path(level, index, width_now);
            match self.source.fetch(&wider_path).await? {
                Some(data) => return Self::cut(level, &wider_path, data, width),
                None => continue, // outgrown again within a round-trip: re-resolve
            }
        }
        Err(MonitorError::Tile(format!("{path} is missing")))
    }

    /// `data` — a tile fetched wider than the pinned `width` — cut back to
    /// exactly that width. Entry bundles are length-framed and walked; hash
    /// tiles are a flat 32 bytes per node. A wider tile that cannot even
    /// yield the pinned prefix is not the tile the checkpoint committed to.
    fn cut(
        level: &str,
        path: &str,
        mut data: Vec<u8>,
        width: u64,
    ) -> Result<Vec<u8>, MonitorError> {
        let end = match level {
            "entries" => {
                let mut at = 0usize;
                for _ in 0..width {
                    let header = data
                        .get(at..at + 2)
                        .ok_or_else(|| MonitorError::Tile(format!("{path}: truncated length")))?;
                    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
                    at += 2;
                    if data.get(at..at + length).is_none() {
                        return Err(MonitorError::Tile(format!("{path}: truncated entry")));
                    }
                    at += length;
                }
                at
            }
            _ => {
                let end = width as usize * 32;
                if data.len() < end {
                    return Err(MonitorError::Tile(format!(
                        "{path}: {} bytes, short of the {end} the pinned width holds",
                        data.len()
                    )));
                }
                end
            }
        };
        data.truncate(end);
        Ok(data)
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
        self.tile_bytes(&tile_level.to_string(), tile_level, index, width)
            .await
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
            .tile_bytes("entries", 0, index / 256, request.count)
            .await?;
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
                let data = self
                    .tile_bytes("entries", 0, first / 256, request.count)
                    .await?;
                self.bundle_decode(&request, &data)
            })
            .buffered(self.concurrency)
    }

    /// Whether tile `(tile_level, index)` has already been authenticated
    /// against this tree's checkpoint.
    fn is_authenticated(&self, tile_level: u32, index: u64) -> bool {
        self.authenticated
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&(tile_level, index))
    }

    /// Records that it has.
    fn mark_authenticated(&self, tile_level: u32, index: u64) {
        self.authenticated
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((tile_level, index));
    }

    /// Authenticates hash tile `(tile_level, index)` against `root`.
    ///
    /// A full tile is 256 complete-subtree hashes, and folding them is the
    /// single node at the base level of the tile above — so the tile is
    /// checked by comparing that fold against the entry its parent tile holds
    /// for it, and the parent is checked the same way, up to a tile the root
    /// recomputation itself consumed.
    ///
    /// A **frontier** tile is where the climb stops, because it needs no
    /// parent. Every hash a partial tile stores is a maximal complete subtree
    /// of the frontier, so the decomposition `subtree_hash(0, size)` walks
    /// exactly those hashes — recomputing the root from the tiles *is* the
    /// check on them. Nor can any of them be covered from somewhere else: a
    /// decomposition part spanning a whole 256-node run would require the tile
    /// to be full.
    ///
    /// Memoized per tree, which is what keeps the cost per *tile* rather than
    /// per entry.
    async fn authenticate_tile(
        &self,
        tile_level: u32,
        index: u64,
        root: [u8; 32],
    ) -> Result<(), MonitorError> {
        // Climb to the first tile that is already authenticated, or to the
        // frontier tile, collecting what has to be checked on the way.
        let mut chain = Vec::new();
        let (mut level, mut at) = (tile_level, index);
        while !self.is_authenticated(level, at) {
            chain.push((level, at));
            if self.width(level, at) != 256 {
                break; // the frontier: pinned by the root recomputation
            }
            // A full tile always has a parent: its 256 nodes exist, so the
            // tree reaches at least `(at + 1) << 8(level + 1)` leaves.
            (level, at) = (level + 1, at / 256);
        }
        // Then check from the top down, so every tile is verified against a
        // parent that has itself been verified.
        for &(level, at) in chain.iter().rev() {
            match self.width(level, at) {
                256 => {
                    let data = self.hash_tile(level, at).await?;
                    let parent = self.stored_hash(8 * (level + 1), at).await?;
                    if fold(&data) != parent {
                        return Err(MonitorError::Tile(format!(
                            "hash tile {level}/{at} does not fold to the node its parent \
                             tile stores for it: the log is serving tiles that do not \
                             belong to the tree it signed"
                        )));
                    }
                }
                _ => {
                    if self.root().await? != root {
                        return Err(MonitorError::Tile(format!(
                            "the frontier hash tile {level}/{at} does not recompute the \
                             checkpoint's root"
                        )));
                    }
                }
            }
            self.mark_authenticated(level, at);
        }
        Ok(())
    }

    /// Binds `body` to `root` — the root of a **signed checkpoint** — as the
    /// leaf at `index`, or fails.
    ///
    /// This is what makes a bundle body evidence rather than a suggestion.
    /// Comparing the body's leaf hash against `stored_hash(0, index)` looks
    /// equivalent and is not: that node comes out of a level-0 hash tile
    /// served as its own resource, and the root recomputation over a
    /// production tree reads no level-0 tile at all. So the comparison is made
    /// against a tile that has first been folded up to a node the checkpoint
    /// committed to (`Tree::authenticate_tile`).
    ///
    /// **Cost.** The fetch budget is the same as the unauthenticated
    /// comparison's: one level-0 hash tile per 256 entries, cached, plus one
    /// level-1 tile per 65,536 entries and one level-2 tile per 16.7 M — tiles
    /// the root recomputation is largely reading anyway. What is added is one
    /// 255-node fold per tile, *memoized*, so the 256 entries inside a tile
    /// share it: about one SHA-256 compression per entry, against the ~26 an
    /// audit path per entry would have cost.
    pub async fn verify_leaf(
        &self,
        index: u64,
        body: &[u8],
        root: [u8; 32],
    ) -> Result<(), MonitorError> {
        if index >= self.size {
            return Err(MonitorError::Tile(format!(
                "entry {index} is outside a tree of {}",
                self.size
            )));
        }
        self.authenticate_tile(0, index / 256, root).await?;
        match self.stored_hash(0, index).await? == leaf_hash(body) {
            true => Ok(()),
            false => Err(MonitorError::Tile(format!(
                "entry {index} does not hash to the leaf the signed checkpoint \
                 committed to"
            ))),
        }
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
            // Serve exactly what a log of this size serves: a width growth
            // has superseded is collected, the way the real log drops it.
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
                out.extend_from_slice(&reference_root(&self.leaves, start, start + span));
            }
            Ok(Some(out))
        }

        async fn checkpoint_size(&self) -> Result<Option<u64>, MonitorError> {
            Ok(Some(self.leaves.len() as u64))
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

    /// A hash tile gets the hash tile's cap, not the entry bundle's.
    ///
    /// One cap for both let a hostile log answer a hash-tile fetch — which a
    /// scan makes constantly, several in flight — with 16 MiB of bytes that
    /// cannot be a tile at any tree size.
    #[test]
    fn each_resource_is_capped_at_its_own_format_ceiling() {
        assert_eq!(cap_for("api/v2/tile/0/001"), MAX_HASH_TILE_BYTES);
        assert_eq!(cap_for("api/v2/tile/2/x001/234.p/17"), MAX_HASH_TILE_BYTES);
        assert_eq!(MAX_HASH_TILE_BYTES, 8 * 1024);
        assert_eq!(cap_for("api/v2/tile/entries/001"), MAX_BUNDLE_BYTES);
        assert_eq!(cap_for("api/v2/checkpoint"), MAX_CHECKPOINT_BYTES);
        // The bundle cap is the format's ceiling, not a round number near it:
        // 256 bodies, each framed by a big-endian u16.
        assert_eq!(MAX_BUNDLE_BYTES, 256 * (2 + 65_535));
        // Above a round 16 MiB by exactly 256 bytes, which is the margin a
        // bundle of 256 maximal entries needs and a round bound denies it.
        assert_eq!(MAX_BUNDLE_BYTES - 16 * 1024 * 1024, 256);
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
            tree.verify_leaf(index, &log.leaves[index as usize], root)
                .await
                .unwrap_or_else(|e| panic!("index {index}: {e}"));
            assert!(tree
                .verify_leaf(index, b"something else", root)
                .await
                .is_err());
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

    /// A log that substitutes one entry body **and** the level-0 hash tile
    /// entry covering it, leaving every higher hash tile alone.
    ///
    /// The harness grants the adversary nothing it would not have. Rewriting
    /// a level-0 hash tile costs exactly what rewriting an entry bundle costs
    /// — both are static files this same party serves — so a harness that
    /// passed hash tiles through untouched would be testing a weaker attacker
    /// than the one in the threat model, and would pass a check that only
    /// compares a body against a level-0 tile.
    ///
    /// Everything above level 8 stays honest, which is what keeps the
    /// checkpoint root and the consistency prefix intact: the forgery is
    /// invisible to every check except a walk to the signed root.
    struct TamperedBundles {
        honest: MemoryLog,
        at: u64,
        instead: Vec<u8>,
    }

    impl TileSource for TamperedBundles {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
            let served = self.honest.fetch(path).await?;
            if path.starts_with("api/v2/tile/entries/") {
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
                return Ok(Some(out));
            }
            // The level-0 hash tile holding the forged leaf's own hash, so a
            // body-against-tile comparison agrees with the bundle.
            let Some(mut data) = served else {
                return Ok(None);
            };
            if let Some(rest) = path.strip_prefix("api/v2/tile/0/") {
                let digits = rest.split(".p/").next().unwrap_or(rest);
                let index = digits.split('/').fold(0u64, |acc, group| {
                    acc * 1000 + group.trim_start_matches('x').parse::<u64>().unwrap()
                });
                if (index * 256..index * 256 + 256).contains(&self.at) {
                    let offset = (self.at - index * 256) as usize * 32;
                    data[offset..offset + 32].copy_from_slice(&leaf_hash(&self.instead));
                }
            }
            Ok(Some(data))
        }
    }

    #[tokio::test]
    async fn a_substituted_entry_body_is_refused_against_the_signed_root() {
        let honest = log(600);
        let tampered = TamperedBundles {
            honest: log(600),
            at: 300,
            // Something that would fail `HashedRekordBody::parse`, which is
            // the cheapest way for a log to make an entry "uninteresting".
            instead: b"not an entry at all".to_vec(),
        };

        // The forgery is invisible to the root check. Leaf 300 sits inside
        // the aligned 512-leaf subtree, whose hash the walk takes from a
        // *level-1* tile — so the rewritten level-0 hash is never folded into
        // the root at all, and the consistency prefix is the same story.
        let honest_tree = Tree::new(&honest, 600, 1);
        let tampered_tree = Tree::new(&tampered, 600, 1);
        let root = honest_tree.root().await.unwrap();
        assert_eq!(
            tampered_tree.root().await.unwrap(),
            root,
            "the root check cannot see this substitution, which is the point"
        );
        assert_eq!(
            tampered_tree.subtree_hash(0, 512).await.unwrap(),
            honest_tree.subtree_hash(0, 512).await.unwrap(),
            "nor can a consistency prefix over the subtree holding it"
        );

        // The bundle really does serve the substitute...
        let bundle = tampered_tree.entry_bundle(300).await.unwrap();
        let served = &bundle
            .iter()
            .find(|(index, _)| *index == 300)
            .expect("entry 300")
            .1;
        assert_eq!(served, b"not an entry at all");

        // ...and the body must not be accepted as the leaf the *checkpoint*
        // committed to, however the log rewrote the tile beneath it.
        assert!(
            tampered_tree.verify_leaf(300, served, root).await.is_err(),
            "a body the signed root does not commit to must be refused"
        );
        honest_tree
            .verify_leaf(300, b"entry 300", root)
            .await
            .expect("and the honest body must still verify");
    }

    #[tokio::test]
    async fn a_substituted_entry_in_the_frontier_tile_is_refused_too() {
        // Leaf 550 sits in the *partial* level-0 tile, which has no parent
        // tile to be folded into — the check there is that the tiles still
        // recompute the checkpoint's root, and a rewritten frontier hash
        // breaks exactly that.
        let honest = log(600);
        let tampered = TamperedBundles {
            honest: log(600),
            at: 550,
            instead: b"not an entry at all".to_vec(),
        };
        let root = Tree::new(&honest, 600, 1).root().await.unwrap();
        let tampered_tree = Tree::new(&tampered, 600, 1);
        assert_ne!(
            tampered_tree.root().await.unwrap(),
            root,
            "a frontier hash does reach the root"
        );
        let served = b"not an entry at all";
        assert!(tampered_tree.verify_leaf(550, served, root).await.is_err());
        Tree::new(&honest, 600, 1)
            .verify_leaf(550, b"entry 550", root)
            .await
            .expect("the honest frontier leaf verifies");
    }

    #[tokio::test]
    async fn a_frontier_tile_completed_since_the_pin_is_read_from_the_full_tile() {
        // Pinned at 1_000, the walk asks for entries tile 3 as `.p/232`; the
        // log, now at 1_300, completed that tile long ago and serves it
        // whole. Level-1 hash tile 0 is still partial — wider than the pin
        // named — so the root check exercises the wider-partial recovery at
        // the same time.
        let log = log(1_300);
        let tree = Tree::new(&log, 1_000, 4);
        assert_eq!(
            tree.root().await.unwrap(),
            reference_root(&log.leaves, 0, 1_000)
        );
        let bundles: Vec<Vec<(u64, Vec<u8>)>> =
            tree.bundle_stream(0, 1_000).try_collect().await.unwrap();
        assert_eq!(bundles.len(), 4);
        assert_eq!(bundles[3].len(), 232);
        assert_eq!(bundles[3][231], (999, b"entry 999".to_vec()));
    }

    #[tokio::test]
    async fn a_frontier_tile_widened_since_the_pin_is_read_from_the_wider_partial() {
        // The same race, but the log grew only within the tile: the pinned
        // `.p/232` is gone and the tile is now `.p/252` — still partial,
        // still the same prefix.
        let log = log(1_020);
        let tree = Tree::new(&log, 1_000, 4);
        let bundle = tree.entry_bundle(768).await.unwrap();
        assert_eq!(bundle.len(), 232);
        assert_eq!(bundle[0], (768, b"entry 768".to_vec()));
        assert_eq!(bundle[231], (999, b"entry 999".to_vec()));
        assert_eq!(
            tree.root().await.unwrap(),
            reference_root(&log.leaves, 0, 1_000)
        );
    }

    #[tokio::test]
    async fn a_partial_the_log_never_grew_into_stays_missing() {
        // Pinned past what the log serves: re-resolving the size says tile 3
        // holds nothing, and no wider tile can stand in for the pinned one.
        let log = log(768);
        let tree = Tree::new(&log, 1_000, 4);
        let err = tree.entry_bundle(768).await.unwrap_err();
        assert!(matches!(err, MonitorError::Tile(_)), "{err}");
    }
}
