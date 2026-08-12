# synchronicity — Design Document

**An omnipresent peer-to-peer file store, written in Rust.**

Status: draft v0.1 · 2026-08-12

---

## 1. Goals and non-goals

### Goals

- **Omnipresent**: every trusted node eventually knows the full metadata state of the
  cluster (what exists, who has it), and can fetch any content from any node that holds
  it. Metadata is replicated everywhere; content moves on demand or by policy.
- **Cross-platform**: Linux, macOS, Windows, and BSDs. No platform-specific kernel
  features (no FUSE, no kernel drivers, no admin privileges). The default distribution is
  a single static, dependency-free CLI binary.
- **Hierarchy-agnostic networking**: every node is a peer. There are no servers,
  coordinators, leaders, or super-nodes. Any node can sync with, relay for, and serve
  any other node. Built on [iroh](https://github.com/n0-computer/iroh).
- **Convergent metadata sync** (`mptsync`): filesystem structure and metadata are
  reconciled with active anti-entropy over Merkle-Patricia Tries, so two nodes can
  detect and repair divergence in `O(diff × log n)` regardless of how long they were
  partitioned.
- **Verifiable content**: content-addressed storage with a hash tree per object, so
  random reads are verifiable without downloading whole files, and any holder of any
  subtree can serve it.
- **Honest version control**: no invented "global" tree state, no automatic conflict
  resolution. Each node publishes *its own* view; divergence is a first-class,
  observable condition that users resolve explicitly.

### Non-goals

- POSIX filesystem semantics, mounting, or transparent virtual filesystems (v1).
- Automatic conflict merging (CRDT-style) — deliberately out of scope.
- Untrusted / open-world swarms. Membership is a closed, mutually-trusting set.
- Byzantine fault tolerance beyond authentication and content verification.
- Internet-scale DHTs. Target deployment is personal/team scale: 2–~100 nodes.

---

## 2. System overview

```
┌────────────────────────────── node ───────────────────────────────┐
│                                                                    │
│  ┌──────────┐   ┌──────────────────────────────────────────────┐   │
│  │   CLI    │──▶│                 engine (daemon)              │   │
│  └──────────┘   │                                              │   │
│   local RPC     │  ┌─────────┐ ┌─────────┐ ┌────────────────┐  │   │
│                 │  │ scanner │ │ mptsync │ │  blob fetcher  │  │   │
│                 │  │ watcher │ │ anti-   │ │  (bao verified │  │   │
│                 │  │         │ │ entropy │ │   range reads) │  │   │
│                 │  └────┬────┘ └────┬────┘ └───────┬────────┘  │   │
│                 └───────┼───────────┼──────────────┼───────────┘   │
│                         ▼           ▼              ▼               │
│                 ┌──────────────────────────┐ ┌──────────────┐      │
│                 │   SQLite (all metadata)  │ │  CAS blob    │      │
│                 │ tries · heads · bindings │ │  store (fs)  │      │
│                 │  entries · scanner state │ │              │      │
│                 └──────────────────────────┘ └──────────────┘      │
│                              │                                     │
│                 ┌────────────┴────────────┐                        │
│                 │      iroh endpoint      │                        │
│                 │  ALPN sync/mpt/1        │                        │
│                 │  ALPN sync/blob/1       │                        │
│                 └────────────┬────────────┘                        │
└──────────────────────────────┼─────────────────────────────────────┘
                               ▼
                     other trusted peers
```

The core mental model:

1. Every node owns exactly one **origin trie**: a signed Merkle-Patricia Trie containing
   that node's published records — its file metadata and its blob inventory.
2. Every node **replicates the origin tries of all trusted peers** via anti-entropy
   (`mptsync`). The cluster-wide view is the *union* of per-origin tries; it is never
   merged into a single tree.
3. File content lives in a local **content-addressed store**, addressed by BLAKE3 hash
   tree roots. Who-has-what is discoverable from the synced tries, so any node can fetch
   any range of any object from any holder, with per-read cryptographic verification.

Because origin tries are **single-writer** (only the origin ever mutates its own trie),
metadata sync is conflict-free by construction: replicating a peer's trie is just
"catch up to their latest signed root". All the hard conflict questions are pushed to
the *interpretation* layer (§8), where they belong.

---

## 3. Identity, trust, and membership

### 3.1 Node identity: origins vs. device keys

Two deliberately separate notions, so that keys can rotate without identity changing:

- **Device key** — an Ed25519 keypair, the same keypair used as the iroh `NodeId`. It
  authenticates *connections* (mutually authenticated QUIC: after the handshake both
  sides have cryptographic proof of the remote `NodeId`) and *signs heads*. Device
  keys are rotatable (§3.4).
- **`OriginId`** — the stable identity that owns a trie and keys all replicated state:
  heads, `f:`/`b:` records, provider views. It never changes for the lifetime of a
  node, across any number of key rotations.

```rust
enum OriginId {
    Key(NodeId),                          // no name: the device key is the identity
    Named { domain: String, id: String }, // dns membership: rendered "<id>@<domain>"
}
```

For DNS-discovered members, the `OriginId` comes from the `id=` field of the TXT
record (§3.2), scoped by the membership domain: `nas@cluster.example.com`. For
statically trusted peers without a name, the OriginId degenerates to the device key
itself — self-certifying, but not rotatable. Static trust may also bind a name
(`sync trust add --as nas <node-id>`), which makes rotation available without DNS.

A **binding** is the association `OriginId → device key`, with a source (static or
dns) and a validity window. An origin may have several simultaneously bound device
keys (the rotation window, §3.4). Every trust check and every head verification goes
through the bindings table — nothing in the durable data model references a bare
device key as an identity.

Device secret keys are generated on `sync init` (and on `sync key rotate`) and stored
in the SQLite database (created `0600` inside the data directory). Display/interchange
encoding for keys is z-base-32 (iroh's native encoding).

### 3.2 Trust sources

A remote node is **trusted** iff at least one of the following holds:

1. **Static trust** — its public key was explicitly added:

   ```
   sync trust add <node-id> [--note "zeynep's laptop"]
   ```

   Static trust is unilateral per node and never expires (until removed). For two nodes
   to sync, *each* must trust the other; there is no transitive trust. With `--as
   <name>` the binding is to a named OriginId (rotatable via `sync trust rebind`);
   without it, the key is the identity.

2. **DNSSEC-based discovery** — the node's key appears in a TXT record of a configured
   membership domain:

   ```
   sync domain add cluster.example.com
   ```

   The resolver queries `_synchronicity.<domain> TXT` and accepts records of the form:

   ```
   _synchronicity.cluster.example.com.  300  IN  TXT  "v=sync1 id=nas    nk=<z-base32 device key>"
   _synchronicity.cluster.example.com.  300  IN  TXT  "v=sync1 id=laptop nk=<z-base32 device key>"
   _synchronicity.cluster.example.com.  300  IN  TXT  "v=sync1 id=laptop nk=<z-base32 device key>"  ; rotation window
   ```

   Each record binds one device key to the origin named by `id=`. The `id` field is
   the member's stable identifier — an opaque label matching `[a-z0-9-]{1,63}`,
   case-insensitive, unique per member within the domain — and is what the data model
   keys the node by (`OriginId::Named`). The `nk` field is the *current* device key.
   **Multiple records with the same `id` and different `nk` are valid** and mean all
   listed device keys are simultaneously bound — this is the key-rotation window
   (§3.4). A record without an `id=` field is accepted for backward simplicity and
   binds `OriginId::Key(nk)` (non-rotatable, as if statically trusted).

   The lookup MUST be DNSSEC-validated end to end. We use
   `hickory-resolver` with in-process DNSSEC validation (we do not trust an upstream
   resolver's AD bit). If the chain of trust does not validate — missing signatures,
   expired RRSIGs, broken chain — the response is **discarded entirely** and the
   previously cached member set is retained until its own expiry. Fail closed.

   Records are re-resolved on the TTL (clamped to `[60s, 24h]`). A binding that
   disappears from DNS expires after `dns_trust_grace` (default: 1 TTL + 10 minutes)
   to absorb propagation glitches. Adding a machine to the cluster becomes: generate
   identity, publish one TXT record. A node learns its *own* OriginId either
   explicitly (`sync init --id nas@cluster.example.com`) or by auto-detection —
   finding its device key in the validated record set; explicit config wins on
   conflict.

Both sources feed a single `bindings` table (§10). Enforcement is at connection accept
time and on every incoming message: connections from device keys with no live binding
are closed immediately after the QUIC handshake; trie heads whose signing key is not
bound to the claimed origin are ignored even if relayed by a trusted peer.

Trust admits a node to the cluster in full: it may read all metadata and all content,
and its published trie is replicated by everyone. (Finer-grained ACLs are future work,
§13.)

### 3.3 Peer discovery (addresses, not membership)

Membership (who is allowed) is separate from address discovery (where they are).
For dialing, we use iroh's standard discovery stack — pkarr/DNS node discovery and
relay servers — so nodes behind NATs work out of the box. Optionally, the TXT record
may carry a hint: `relay=https://...` or `addr=host:port`, which is fed into iroh as
dialing hints. Self-hosted deployments can run their own iroh relay; nothing in
synchronicity assumes n0's infrastructure. To reach a named origin, a node dials
whichever device key(s) are currently bound to it.

### 3.4 Key rotation

Because every piece of durable state — tries, heads, entries, provider views, content
— is keyed by `OriginId`, rotating a device key changes *nothing* about replicated
data. It only changes which key may sign for the origin and which `NodeId` peers dial.
No trie rewrite, no re-hashing, no history loss.

**Planned rotation** (origin `nas@cluster.example.com`, `K_old → K_new`):

1. `sync key rotate` generates `K_new` locally, keeps `K_old` active, and prints the
   TXT record to publish. The node continues operating (transport + signing) on
   `K_old`.
2. The operator publishes the second record: `v=sync1 id=nas nk=<K_new>`, alongside
   the existing one. Both keys are now bound; peers pick this up on their next
   validated refresh.
3. The node polls its own domain until it observes the validated `K_new` binding, then
   switches over: it publishes a **rotation statement** into its trie at `m:rotation` —
   `RotationStmt { old: K_old, new: K_new, at_seq, sig_old }`, where `sig_old` is
   `K_old`'s signature over `("sync-rotate/1" || origin || old || new || at_seq)` —
   re-signs its current root as a new head (`seq+1`, `signed_by = K_new`), and restarts
   its iroh endpoint as `K_new`.
4. Peers verify the cross-signature and mark the rebinding as **verified continuity**.
   The operator removes the `K_old` record; its binding expires after TTL + grace, and
   the node deletes the `K_old` secret after that.

**Key-loss recovery** (no cross-signature possible): the operator simply replaces the
TXT record with a fresh `K_new`. DNS is authoritative, so peers accept the rebinding —
but an *uncross-signed* rotation is logged loudly and flagged by `sync doctor` on
every node until acknowledged, since it is indistinguishable from a domain-level
takeover (§12). The recovering node (fresh DB, same `id=` name) first pulls its own
origin's current head from peers, then resumes publishing at `seq+1` — peers enforce
per-origin seq monotonicity regardless of which bound key signs, so a lost key never
resets an origin's history or enables rollback.

**During the window**, both keys could in principle sign competing heads; the
deterministic `(seq, root)` ordering (§4.4) still converges everyone, and competing
same-seq heads are flagged as equivocation exactly as in the single-key case. A
well-behaved node signs with exactly one key at any moment.

Static-trust named origins rotate the same way, minus DNS: `sync trust rebind nas
<new-node-id>` on each peer (with the same cross-signed `m:rotation` statement
providing verified continuity).

---

## 4. Data model

### 4.1 Origin tries and the record keyspace

Each origin trie maps byte-string keys to record values. Keys are namespaced by a
single prefix byte:

| Prefix | Key                                  | Value          | Meaning                          |
|--------|--------------------------------------|----------------|----------------------------------|
| `f:`   | `f:<space-id>/<utf8 relative path>`  | `FileEntry`    | this origin's copy of a file     |
| `b:`   | `b:<32-byte tree-node hash>`         | `BlobAd`       | "I hold this hash-tree node"     |
| `m:`   | `m:self`                             | `NodeManifest` | node info: name, spaces, version |
| `m:`   | `m:rotation`                         | `RotationStmt` | cross-signed key rotation (§3.4) |

Paths are UTF-8, NFC-normalized, `/`-separated, no leading slash, no `.`/`..`
components. Because the MPT compresses shared prefixes, the `f:` namespace naturally
mirrors directory structure, and a directory listing is a range scan over
`f:<space>/<dir>/`.

A **space** is a named sync root (like a Syncthing folder): a user configures
`sync space add photos ~/Pictures`, and that subtree is indexed under `f:photos/...`.
Spaces are the unit of sharing policy and of local materialization.

### 4.2 Records

All records are `postcard`-encoded, versioned structs (first field is a `u8` schema
version).

```rust
struct FileEntry {
    v: u8,                    // schema version
    kind: EntryKind,          // File | Dir | Symlink | Tombstone
    size: u64,                // content length (0 for dirs)
    mtime_ns: i64,            // origin's observed mtime
    unix_mode: Option<u32>,   // advisory; best-effort cross-platform
    content: Option<Hash>,    // BLAKE3 hash-tree root (None for Dir/Tombstone)
    chunking: ChunkParams,    // { format: Bao, group_log2: u4 } — fixed per object
    seq: u64,                 // origin trie seq at which this version was published
    prev: Option<Hash>,       // previous content root (1-step lineage, see §8)
    symlink_target: Option<String>,
}

struct BlobAd {
    v: u8,
    object_root: Hash,        // root of the object this tree node belongs to
    byte_range: (u64, u64),   // span of the object covered by this subtree
    level: u8,                // 0 = leaf group, root = tree height
    complete: bool,           // whole subtree present locally (vs. announced-partial)
}

struct NodeManifest {
    v: u8,
    name: String,             // human-friendly node name
    spaces: Vec<SpaceInfo>,   // advertised spaces: id, description, entry count
    software: String,         // "synchronicity/0.1.0"
}
```

Notes:

- **Tombstones**: deletion publishes `kind: Tombstone` (with `content: None`). Tombstones
  are retained in the trie for `tombstone_ttl` (default 90 days), then dropped in a
  later root. Peers that were partitioned longer than the TTL may resurrect metadata —
  documented limitation, standard for AAE systems.
- **`BlobAd` granularity**: an ad is published for the object **root and every interior
  node and leaf group** of the hash tree (per the availability requirement, §6.3), so a
  read on any tree node can be served by any holder. The leaf unit is a **chunk group**
  (default 16 KiB, `group_log2 = 4` in blake3 chunks), which bounds ad count at
  ~2 × size/16 KiB per object. A per-space `publish_level` knob can raise the minimum
  advertised level for very large cold archives; the default publishes everything.

### 4.3 The Merkle-Patricia Trie

We implement our own small MPT (crate `sync-mpt`, no consensus-chain baggage):

- **Radix-16** (nibble) trie with three node kinds, à la Ethereum, but simplified:

  ```rust
  enum TrieNode {
      Leaf   { key_rest: Nibbles, value: ValueRef },
      Ext    { prefix: Nibbles, child: Hash },
      Branch { children: [Option<Hash>; 16], value: Option<ValueRef> },
  }
  enum ValueRef {
      Inline(Vec<u8>),   // ≤ 128 bytes, embedded in the node
      Hash(Hash),        // larger values stored out-of-line, content-addressed
  }
  ```

- **Hashing**: `node_hash = BLAKE3(domain_sep || canonical postcard encoding)`, with a
  domain-separation tag per node kind. No RLP, no keccak.
- **Content-addressed node store**: every trie node is stored by hash in SQLite
  (`trie_nodes`). Successive roots share unchanged subtrees structurally — publishing a
  new root after touching one file allocates only the path from that leaf to the root
  (≤ ~key-length/2 nodes). This same property makes diffing cheap and makes *any* node
  able to serve *any* trie node to *any* peer.
- **Proofs**: a key's value is provable against a root with the node path (Merkle
  proof); used by the light one-shot CLI mode (§9.3) and available for future partial
  replication.

### 4.4 Signed heads

The mutable pointer per origin is a **head**:

```rust
struct SignedHead {
    origin: OriginId,
    seq: u64,          // strictly monotonic per origin, across key rotations
    root: Hash,        // MPT root hash ("empty" sentinel for the empty trie)
    created_at: i64,   // unix nanos, informational only
    signed_by: NodeId, // the device key that produced sig
    sig: Signature,    // ed25519 over ("sync-head/1" || origin || seq || root || created_at || signed_by)
}
```

- A head is **valid** iff `sig` verifies under `signed_by` *and* `signed_by` is
  currently bound to `origin` (§3.1). Accepted heads record the binding check in
  `heads.verified_at`, so history signed by since-retired keys stays valid — a
  rotation never invalidates already-replicated state.
- Heads are **relayable**: any peer can hand you a newer signed head for any origin;
  the signature makes provenance independent of the carrier.
- Ordering is `(seq, root)` lexicographic. `created_at` is never used for ordering
  (clocks lie); it is display metadata.
- **Equivocation** (an origin signing two different roots at the same seq) is detected
  and logged loudly (`sync doctor` reports it); the deterministic `(seq, root)` max
  still converges everyone to the same head. Equivocation only harms the equivocator's
  own published view.

---

## 5. mptsync — active anti-entropy on Merkle-Patricia Tries

ALPN: `sync/mpt/1`. All messages are length-framed `postcard` on QUIC streams.

### 5.1 Protocol messages

```rust
// bidirectional stream 0 on connect: head gossip (push-pull)
Hello      { proto: u16, heads: Vec<HeadSummary> }      // HeadSummary = (origin: OriginId, seq, root)
HeadsWant  { origins: Vec<OriginId> }                   // "yours is newer, send full signed head"
Heads      { heads: Vec<SignedHead> }
HeadPush   { head: SignedHead }                         // reactive: sent on any head change

// one bidirectional stream per fetch batch:
GetNodes   { hashes: Vec<Hash> }                        // ≤ 256 per batch
Nodes      { nodes: Vec<(Hash, Bytes)>, missing: Vec<Hash> }
GetValues  { hashes: Vec<Hash> }                        // out-of-line ValueRef payloads
Values     { values: Vec<(Hash, Bytes)>, missing: Vec<Hash> }
```

### 5.2 Reconciliation algorithm

For each trusted origin `O`, a node tracks `local_head(O)` and a fully materialized
copy of that trie in `trie_nodes`. On learning a newer head `H` for `O` (via `Hello`
exchange or `HeadPush`):

```
verify sig(H) under H.signed_by; check H.signed_by is bound to O (else ignore)
check H.seq > local_head(O).seq (else ignore)
frontier ← { H.root }
while frontier ≠ ∅:
    want ← { h ∈ frontier : h ∉ trie_nodes }          // structural sharing: skip known subtrees
    if want = ∅: break
    nodes ← GetNodes(want) from this peer (or any peer advertising ≥ H.seq)
    verify each node hashes to its requested hash      // reject & disconnect on mismatch
    store nodes; frontier ← their children ∪ out-of-line value hashes
atomically: set local_head(O) ← H                      // single SQLite transaction
re-materialize changed leaves into `entries` / `blob_providers` (computed from the
node-level diff between old and new root — only touched subtrees are visited)
```

Properties:

- **Idempotent and resumable**: everything fetched is content-addressed; a crash
  mid-sync loses nothing. The head pointer flips only when the trie is complete under
  the new root.
- **Bandwidth ∝ change**: unchanged subtrees are pruned at the first shared hash.
  Fully-in-sync check is a single root-hash comparison in `Hello`.
- **Verified piecewise**: every trie node is checked against the hash it was requested
  by; a malicious or corrupt peer cannot inject data, only fail to help.
- **Peer-agnostic**: because trie nodes are content-addressed, missing nodes may be
  fetched from *any* peer whose advertised head for `O` is ≥ `H.seq` — including nodes
  that are neither `O` nor the peer that told us about `H`. Hierarchy-agnostic in
  practice: a laptop that heard about a NAS's update from a VPS can pull the trie
  nodes from either.

### 5.3 Anti-entropy scheduling

- **Reactive**: local publishes (§7) and received newer heads are pushed (`HeadPush`)
  to all currently connected peers immediately. This gives sub-second propagation on
  connected clusters and epidemic spread (each infected node pushes onward).
- **Periodic**: every `aae_interval` (default 30s with ±50% jitter), pick one random
  trusted peer, connect if needed, run a full `Hello` push-pull exchange. This repairs
  anything the reactive path missed (dropped connections, simultaneous partitions) and
  is the mechanism that guarantees convergence.
- **On-connect**: any new connection (inbound or outbound, whatever its purpose) begins
  with a `Hello` exchange. Blob fetches double as sync opportunities.

Expected staleness with push + pull-gossip is `O(log N)` rounds after any partition
heals; at N ≤ 100 and 30 s rounds this is well under 5 minutes worst-case, typically
sub-second via push.

### 5.4 Trie garbage collection

Old roots are kept for `root_retention` (default 7 days) to serve laggard peers cheap
diffs and to power `sync log` history (§8). GC is mark-and-sweep in SQLite: mark from
all retained heads (each origin's latest + retained history roots), sweep unmarked
`trie_nodes`/`trie_values`. Runs incrementally in the maintenance loop.

---

## 6. Content storage and transfer

### 6.1 Hash trees (bao / BLAKE3)

Every object (file content) is hashed with **BLAKE3**, whose native Merkle-tree
structure we expose rather than hide:

- Leaf unit: **chunk group** of 16 KiB (16 blake3 chunks), the same convention as
  `iroh-blobs`/`bao-tree`. Interior nodes are standard blake3 parent nodes.
- The **object address is the blake3 root hash** — identical to the plain `blake3(file)`
  digest, so addresses are checkable with any blake3 tool.
- Each stored object keeps an **outboard** encoding (the interior tree, ~1/512 of the
  content size at 16 KiB groups) alongside the raw bytes, enabling verified slice
  serving without recomputation.

**Verified random reads**: a read of any byte range is served as a *bao slice* — the
chunk groups covering the range plus the sibling hashes on the paths to the root. The
client verifies the slice incrementally against the root hash alone; a flipped bit
anywhere fails verification at the exact 16 KiB group it occurs in. Cost is
`O(range + log(size))`.

We build this on the `bao-tree` crate (the engine inside iroh-blobs) rather than
reimplementing.

### 6.2 Local store (CAS)

- Blob payloads live as flat files in the data dir: `store/<hex[0..2]>/<hex>` plus
  `store/<hex>.obao` for the outboard. Small blobs (≤ 16 KiB) are inlined in SQLite.
- All *index* metadata — sizes, completeness bitmaps (which chunk groups of a partially
  fetched object are present and verified), refcounts, pin state — is in SQLite (§10).
- Partial objects are first-class: the completeness bitmap tracks verified groups;
  `BlobAd`s are published for exactly the complete subtrees (with `complete: true` at
  covered interior nodes), so even a node holding the first half of a video usefully
  serves it.

### 6.3 Availability publishing

Whenever the local store gains or loses a verified subtree of some object, the engine
updates the `b:` records in the origin trie (batched, then republished as one new
head). Published per object: the **root** and **all interior nodes and leaf groups**
of the hash tree that are locally complete. Consequences:

- "Who can serve byte range R of object X?" is answered *locally*, by scanning the
  synced `blob_providers` view for ads whose `(object_root = X)` and `byte_range ∩ R ≠ ∅`,
  across all origins. No query round-trip, no DHT.
- Any holder of any subtree is discoverable and can serve it — swarm behavior (fetch
  different ranges from different peers in parallel) falls out naturally.

### 6.4 Blob transfer protocol

ALPN: `sync/blob/1`.

```rust
GetSlice   { root: Hash, ranges: ChunkRanges }   // ChunkRanges in 16 KiB group units
// response: bao slice stream, verified incrementally by the requester
SliceEnd   { served: ChunkRanges }               // what the provider actually had
```

The fetcher:

1. Resolves providers from `blob_providers`, ranks them (recent latency EWMA, then
   random tiebreak), and splits the wanted range across up to `fetch_fanout` (default 3)
   providers.
2. Streams and verifies groups as they arrive; verified groups are committed to the
   CAS and the completeness bitmap immediately (progress survives restarts).
3. Re-plans on provider failure or on ads changing. Wants are a persistent queue
   (`want` table) with priorities: explicit `sync get` > policy mirror > prefetch.

This is intentionally the same shape as iroh-blobs' protocol; we keep our own ALPN and
message frame so the availability semantics (partial serving, `SliceEnd`) stay under
our control, but the heavy machinery (bao verification) is shared code.

---

## 7. Local filesystem integration (no FUSE)

synchronicity is a **sync-directory** tool, not a mounted filesystem. Cross-platform
behavior with zero kernel dependencies:

### 7.1 Indexing pipeline (own spaces)

- **Watcher**: the `notify` crate (inotify / FSEvents / ReadDirectoryChangesW, with
  polling fallback) provides change hints per space. Hints are debounced (default
  500 ms) and only ever *schedule rescans* — correctness never depends on watcher
  completeness.
- **Scanner**: a periodic (default 1 h) and on-demand full walk. A file is considered
  unchanged if `(size, mtime_ns, file_id)` matches the `local_files` table — only then
  is hashing skipped. Changed files are re-hashed (streaming blake3, outboard emitted
  as a by-product), the CAS is updated, and a new `FileEntry` is staged.
- **Publisher**: staged changes are batched (default: quiesce 2 s or 1000 entries) into
  a single new trie root: bump `seq`, sign, store, `HeadPush` to connected peers. One
  save in an editor costs one head; a 100k-file initial index costs a handful.

Ignore rules: `.syncignore` per space root (gitignore syntax), plus sensible built-in
defaults (`.DS_Store`, `Thumbs.db`, temp/lock patterns).

### 7.2 Materialization (peers' spaces)

Since there is no unified tree, materialization is **per (origin, space)**:

- `sync get <origin>:<space>/<path> [-o dest]` — one-shot fetch into a local file.
- `sync mirror add <origin>:<space> <local-dir>` — continuous read-only mirror: the
  engine tracks that origin's `f:` records for the space and keeps the directory in
  sync (fetching content via §6.4). Mirrored trees are never indexed back into the
  local origin trie (no echo).
- `sync cat <origin>:<space>/<path> [--range a..b]` — stream to stdout with verified
  random access; this is where hash-tree reads shine (e.g. seeking in a large video).

Two-way "shared folder" workflows are composed from primitives: both nodes index their
own copy of a space (same space id), and divergence between them is surfaced by
`sync status` (§8) for explicit adoption with `sync take`.

---

## 8. Version control model

Principles: **every origin publishes only its own copy; the system never merges.**

- Each `(origin, space, path)` triple is an independent assertion: "this is my current
  copy". The cluster-wide state of a path is the *set* of such assertions.
- **Divergence is data, not an error.** `sync status <space>/<path>` shows all origins'
  entries side by side (size, mtime, content root, seq). Two origins whose content
  roots match are "in agreement" — a purely observational notion.
- **Adoption is explicit**: `sync take <origin>:<space>/<path>` fetches that origin's
  content, writes it into the local space, and thereby (via the indexing pipeline)
  publishes it as the local node's own new entry. `prev` is set to the replaced local
  content root, recording 1-step lineage so UIs can distinguish "adopted theirs on top
  of X" from "changed independently".
- **History**: retained old roots (§5.4) give each origin a time machine over its own
  publishes: `sync log <space>/<path>` walks historical roots' leaves for the key;
  `sync cat --at <seq>` reads an old version if its content is still in someone's CAS
  (content GC is pin/retention-driven, so history depth is a storage policy, not a
  protocol constant).
- No branches, no merge commits, no vector clocks in v1. `prev` plus per-origin `seq`
  is deliberately the entire causality story; experience (Syncthing, Unison) says
  users resolve file conflicts by *looking at the file*, not the DAG.

---

## 9. CLI and process model

### 9.1 One binary, no dependencies

A single `sync` binary (name negotiable; `sy` alias) built with:

- `rusqlite` with the `bundled` feature (SQLite compiled in — no system SQLite),
- `rustls` everywhere (no OpenSSL),
- musl static builds for Linux releases; standard static-ish builds for macOS/Windows.

`sync` is both the CLI and the daemon (`sync daemon run`). The CLI talks to a running
daemon over a local control socket (Unix domain socket; named pipe on Windows) with a
random per-datadir token; if no daemon is running, commands that can run one-shot do so
in-process against the same SQLite DB.

### 9.2 Command surface (v1)

```
sync init [--id <name>@<domain>]            create identity + database
sync id                                     print OriginId + current device key(s)
sync key rotate|ls|retire                   device-key rotation (§3.4)
sync daemon run|status|stop

sync trust add [--as <name>]|rebind|rm|ls   static membership (named or key-identified)
sync domain add|rm|ls <domain>              DNSSEC membership
sync peers                                  live peers, addresses, last sync, lag

sync space add <id> <path>                  index a local directory as a space
sync space ls|rm

sync ls   [<origin>:]<space>/[<dir>]        list entries (default: all origins, merged view)
sync status [<space>[/<path>]]              agreement/divergence across origins
sync cat  <origin>:<space>/<path> [--range] verified streaming read
sync get  <origin>:<space>/<path> [-o …]    fetch to file
sync take <origin>:<space>/<path>           adopt a peer's version as my own
sync log  [<origin>:]<space>/<path>         per-origin publish history
sync mirror add|rm|ls                       continuous read-only materialization

sync pin add|rm|ls <root|path>              keep content in CAS regardless of policy
sync doctor                                 connectivity, DNSSEC, equivocation, GC stats
```

### 9.3 One-shot mode

`sync cat/get/ls` work without a daemon: open endpoint, `Hello` with any reachable
trusted peer, pull the relevant origin's head + the trie path for the requested key
(Merkle-proof-verified — no full trie replication needed for a single read), fetch the
blob slice, exit. This keeps the "dependency-free CLI" promise meaningful even on
machines that never run the daemon.

---

## 10. SQLite schema

One database per node, `synchronicity.db` in the platform data dir
(`~/.local/share/synchronicity`, `~/Library/Application Support/…`, `%APPDATA%\…`).
WAL mode, `synchronous=NORMAL`, single writer task (all writes funneled through one
tokio task; reads from a pool). All multi-step state changes (head flips, publish
batches) are single transactions.

```sql
-- node & config
CREATE TABLE config        (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                                         -- includes 'self_origin_id'
CREATE TABLE device_keys (                -- own keys; >1 row only during rotation
  node_id     BLOB PRIMARY KEY,
  secret_key  BLOB NOT NULL,
  state       TEXT NOT NULL,             -- 'active' | 'retiring'
  created_at  INTEGER NOT NULL
);

-- membership: OriginId → device-key bindings.
-- origin_id is the canonical rendering: '<id>@<domain>' or 'key:<z-base32>'.
CREATE TABLE bindings (
  origin_id    TEXT NOT NULL,
  node_id      BLOB NOT NULL,            -- bound device key (32 bytes)
  source       TEXT NOT NULL,            -- 'static' | 'dns'
  domain       TEXT,                     -- for dns source
  note         TEXT,
  cross_signed INTEGER NOT NULL DEFAULT 0, -- verified continuity via m:rotation (§3.4)
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,                  -- NULL for static
  PRIMARY KEY (origin_id, node_id, source)
);
CREATE INDEX bindings_by_key ON bindings (node_id);   -- connection-accept lookup

-- mptsync
CREATE TABLE heads (
  origin_id   TEXT PRIMARY KEY,
  seq         INTEGER NOT NULL,
  root        BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  signed_by   BLOB NOT NULL,             -- device key that signed this head
  sig         BLOB NOT NULL,
  received_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,          -- when the signed_by↔origin binding was checked
  synced      INTEGER NOT NULL DEFAULT 0 -- trie fully materialized under this root
);
CREATE TABLE head_history  (origin_id TEXT, seq INTEGER, root BLOB, created_at INTEGER,
                            signed_by BLOB,
                            PRIMARY KEY (origin_id, seq));    -- for §8 history, pruned by retention
CREATE TABLE trie_nodes    (hash BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE trie_values   (hash BLOB PRIMARY KEY, data BLOB NOT NULL);

-- materialized views of trie leaves (rebuilt incrementally from diffs)
CREATE TABLE entries (
  origin_id   TEXT NOT NULL,
  space       TEXT NOT NULL,
  path        TEXT NOT NULL,
  kind        INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  mtime_ns    INTEGER NOT NULL,
  content     BLOB,                      -- object root hash
  seq         INTEGER NOT NULL,
  prev        BLOB,
  PRIMARY KEY (origin_id, space, path)
);
CREATE INDEX entries_by_path    ON entries (space, path);
CREATE INDEX entries_by_content ON entries (content);

CREATE TABLE blob_providers (
  hash        BLOB NOT NULL,             -- tree-node hash
  origin_id   TEXT NOT NULL,
  object_root BLOB NOT NULL,
  range_start INTEGER NOT NULL,
  range_end   INTEGER NOT NULL,
  level       INTEGER NOT NULL,
  PRIMARY KEY (hash, origin_id)
);
CREATE INDEX providers_by_object ON blob_providers (object_root, range_start);

-- local content store index
CREATE TABLE blobs (
  root        BLOB PRIMARY KEY,
  size        INTEGER NOT NULL,
  complete    INTEGER NOT NULL,
  bitmap      BLOB,                      -- verified 16 KiB-group bitmap when partial
  inline      BLOB,                      -- payload for small blobs, else NULL (fs store)
  pinned      INTEGER NOT NULL DEFAULT 0,
  last_access INTEGER NOT NULL
);

-- indexing / engine state
CREATE TABLE spaces        (id TEXT PRIMARY KEY, local_path TEXT NOT NULL, publish_level INTEGER DEFAULT 0);
CREATE TABLE local_files   (space TEXT, relpath TEXT, size INTEGER, mtime_ns INTEGER,
                            file_id BLOB, content BLOB, scanned_at INTEGER,
                            PRIMARY KEY (space, relpath));
CREATE TABLE mirrors       (origin_id TEXT, space TEXT, local_path TEXT NOT NULL,
                            PRIMARY KEY (origin_id, space));
CREATE TABLE want          (root BLOB, ranges BLOB, priority INTEGER, reason TEXT,
                            created_at INTEGER, PRIMARY KEY (root, ranges));
CREATE TABLE peers_seen    (node_id BLOB PRIMARY KEY, last_addr BLOB, last_seen INTEGER,
                            last_sync INTEGER, latency_ewma_us INTEGER);
```

The trie is authoritative; `entries` and `blob_providers` are derived caches and can
always be rebuilt from `trie_nodes` (`sync doctor --rebuild`).

---

## 11. Crate layout

Cargo workspace:

```
synchronicity/
├── crates/
│   ├── sync-core      # types: NodeId, Hash, records, keys, signed heads; postcard schemas
│   ├── sync-mpt       # the Merkle-Patricia Trie: nodes, hashing, diff, proofs, cursors
│   ├── sync-store     # SQLite layer + CAS (bao-tree outboards, bitmaps, GC)
│   ├── sync-net       # iroh endpoint, ALPN handlers: mptsync + blob protocols, DNSSEC resolver
│   ├── sync-engine    # scanner/watcher/publisher, anti-entropy scheduler, fetcher, mirrors
│   └── sync-cli       # the `sync` binary: clap CLI, daemon, control socket
└── docs/
```

Key dependencies: `iroh`, `bao-tree`, `blake3`, `ed25519-dalek` (via iroh),
`rusqlite` (bundled), `notify`, `hickory-resolver` (dnssec), `tokio`, `postcard`,
`serde`, `clap`, `tracing`, `directories`.

Testing strategy:

- `sync-mpt`: property tests (proptest) — insert/delete/iterate vs. a BTreeMap model;
  root-hash determinism; diff completeness (diff(a,b) applied to a yields b).
- `mptsync`: in-memory duplex-transport simulation of N nodes with random partitions,
  message loss, and interleaved publishes; assert convergence of all heads and tries.
- `sync-engine`: temp-dir integration tests across 2–3 real endpoints on localhost.
- Cross-platform CI matrix (linux-musl, macos, windows) from day one.

---

## 12. Security considerations

- **Transport**: iroh QUIC — encrypted, mutually authenticated by NodeId. No plaintext
  path exists.
- **Authorization**: binary, membership-based (§3.2). Enforced on accept and per-origin
  on every head/record. A trusted peer relaying data for an untrusted origin is ignored.
- **Data integrity**: three independent hash-verification layers — trie nodes verified
  against requested hashes, heads verified against origin signatures, content verified
  against object roots per 16 KiB group. A compromised peer can withhold, but never
  corrupt.
- **DNSSEC blast radius**: whoever controls the membership domain (or its DNSSEC keys)
  controls membership — adding a hostile node grants full read access and publish
  rights. With named origins the exposure is strictly larger: the domain controller
  can *rebind an existing origin's `id=` to an attacker key*, hijacking that namespace
  for future publishes (it cannot rewrite history or roll back — per-origin seq
  monotonicity and retained signed heads prevent that, and already-replicated content
  is hash-verified). Mitigations: legitimate rotations carry a cross-signed
  `m:rotation` statement (§3.4) and are silent, while any *uncross-signed* rebinding
  is loudly logged and flagged by `sync doctor` on every node until acknowledged; a
  `rotation_policy = cross-signed-only` config refuses uncross-signed rebindings
  outright (trading away DNS-only key-loss recovery). Plus the base mitigations:
  validated in-process resolution (no resolver trust), TTL-bounded caching, and
  `sync doctor` surfacing the full live member set, bindings, and their provenance.
  Deployments that can't accept domain-controller power use static trust only.
- **Equivocation & rollback**: signed monotonic seq prevents third-party replay of old
  heads; same-seq forks are detected and reported (§4.4). A malicious *origin* can
  publish garbage about its own files — that only pollutes its own namespace, which the
  version model already treats as "their claim, not truth".
- **Denial of service**: per-peer rate limits on `GetNodes`/`GetSlice`; batch-size caps;
  trie-depth caps on ingest (key length is bounded to 4 KiB, so depth ≤ ~8 K nibbles);
  publish-size quota per origin (configurable, default 10 M trie leaves) so one member
  can't OOM the cluster's metadata.
- **Privacy**: metadata (paths, sizes, mtimes) is visible to *all* members — inherent
  to omnipresence. Content is fetched on demand, so bytes only land where requested or
  mirrored. At-rest encryption of the CAS and DB is delegated to OS disk encryption in
  v1 (noted in §13).

---

## 13. Future work (explicit non-v1)

- Read-only membership tier and per-space ACLs.
- Encrypted spaces (per-space content keys; metadata padding).
- Partial trie replication for very large clusters (the proof machinery in §4.3
  already permits it).
- Smarter placement policies ("keep ≥ 2 replicas of every object cluster-wide"),
  built on the same `BlobAd` availability data.
- A local read-only HTTP gateway (`sync serve`) for browser access; optional
  platform-specific mounts (FUSE/WinFsp/NFSv3-loopback) as *plugins*, never as core.
- Bandwidth scheduling / QoS between anti-entropy and bulk fetches.

---

## 14. End-to-end walkthrough

Three nodes: `laptop`, `nas`, `vps`, all in `_synchronicity.cluster.example.com`.

1. `nas` runs `sync space add media /srv/media`. The scanner hashes 40 k files,
   the publisher signs head `(seq=1, root=r1)` containing 40 k `f:` records and the
   `b:` ads for every object's tree nodes.
2. `laptop` connects (dns-discovered membership, iroh-dialed), `Hello` exchanges heads,
   sees `nas@1 > nas@0`, pulls the trie breadth-first with `GetNodes` — a few MB of
   trie nodes for 40 k entries. It now knows every path, size, mtime, and object root
   on the NAS, holding zero content bytes.
3. `laptop` runs `sync cat nas:media/talks/keynote.mp4 --range 0..`. Providers for the
   root resolve to `{nas}`; the fetcher streams bao-verified slices; the player seeks —
   each seek is a new verified range read. Fetched groups land in laptop's CAS, and its
   next published head advertises the subtrees it now holds.
4. `vps` (which mirrors `nas:media`) later fetches the same file — provider resolution
   now returns `{nas, laptop}` and it pulls from both in parallel.
5. `nas` edits a file. Watcher → rescan → head `(seq=2, r2)` → `HeadPush` to both peers;
   each pulls exactly the changed path's trie nodes. `laptop`'s stale copy of the old
   content remains valid (content-addressed), and `sync status media/…` on any node
   shows `nas` at the new root and `laptop` still advertising (and pinning, if it
   chose) the old object — divergence visible, nothing auto-resolved, adoption one
   `sync take` away.
6. `nas`'s operator rotates its key: `sync key rotate`, publish the second
   `id=nas nk=<K_new>` TXT record, wait for validated visibility. `nas` publishes the
   cross-signed `m:rotation` statement, re-signs its head as `K_new` at `seq=3`, and
   restarts its endpoint. Peers verify continuity silently; `laptop` and `vps` now
   dial `K_new`. Every trie node, entry, and blob ad is untouched — `nas@cluster…`
   is the same origin it always was. The old TXT record is removed and `K_old`
   expires out of everyone's bindings a TTL later.

---

*This document is the v0.1 design baseline. Sections are numbered for reference in
issues and PRs; substantive changes should update this file in the same PR.*
