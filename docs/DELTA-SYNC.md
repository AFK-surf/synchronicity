# Delta sync for large files (proposal)

Status: **proposal** — nothing in this document is implemented.

## 1. Problem

A mirror pass treats content as all-or-nothing per object. `plan_pass`
(`crates/synch-engine/src/mirror.rs`) decides "current or wanted" by comparing
the on-disk file's whole-content hash against the selected entry's root; when
they differ, phase 2 runs `fetch_all` for the *new* root and
`write_blob_to_blocking` rewrites the whole file through a staging rename.

The fetch already skips groups verified locally — but only groups verified
**under the same root** (`fetch_groups` subtracts `local_groups(root)`). A
changed file has a new root, so its local-groups set starts empty even when
99% of its bytes are identical to the previous version sitting in the CAS and
on disk. The result, for the workloads mirrors exist for (§14: VM images,
databases, media libraries, append-heavy logs):

- **Network**: a 100 GB image with 50 MB changed in place costs a 100 GB fetch.
- **Disk**: the staging copy rewrites 100 GB even though the mirror already
  holds a file that is 99.95% correct.
- **Swarm**: until the fetch completes past an ad milestone, this node
  advertises nothing of the new root, so other mirrors cannot lean on it.

## 2. What makes delta cheap here

Two properties we already rely on elsewhere make verified delta transfer fall
out of the existing design rather than fight it:

1. **Fixed-offset chunk groups** (§6.1). Objects are chunked at fixed 16 KiB
   boundaries (`CHUNK_GROUP_LOG2`, `ChunkParams` fixed per object). A group's
   position in the tree is a pure function of its byte offset.

2. **Offset-indexed BLAKE3 chaining values.** A BLAKE3 chunk CV depends on the
   chunk's bytes and its absolute chunk counter — not on the rest of the file
   and not on the file's total length. So:

   - Two objects that carry the same bytes at the same offset have the **same
     leaf-group CV** at that offset, whatever else differs.
   - The same holds one level up, for any *complete, aligned* subtree (a
     power-of-two run of groups fully inside both objects): its CV is
     position-dependent but size-independent. An appended-to file keeps the
     CVs of every complete subtree of its old prefix.

   Only the final partial group, and subtrees that straddle either object's
   tail, escape this equivalence.

So "which parts of the new version do I already have?" reduces to comparing
subtree CVs of the new object's bao tree against CVs this node can compute
locally — and every reused byte can still be *verified against the new root*
before it is committed, keeping the §5.1 rule that no byte is trusted because
of who supplied it.

The one thing the node is missing is the new object's tree. That is the only
new thing the protocol has to move.

## 3. Design overview

Delta sync is a fetch-side optimization plus a write-side optimization, joined
by one new wire exchange. No schema migration, no trie or record changes, no
new subsystem: the partial-object machinery (bitmaps, sparse payload and
outboard files, `write_slice`, milestone ads) already does the bookkeeping.

```
        ┌───────────────────────────── new root R', size S' ──┐
        │                                                     │
  1. GetProof(R', spans)      hash-only bao traversal         │  provider
  2. compare span CVs         against donor outboards         │  (any holder
  3. GetProof(R', leaves)     only inside differing spans     │   of R')
  4. promote equal groups     donor bytes → CAS, re-verified  │
  5. GetSlice(R', changed)    existing fetch path, fanout     │
        │                                                     │
        └── mirror write: reflink old file, patch changed groups, rename
```

### 3.1 Wire: `GetProof` on `sync/blob/2`

```rust
GetProof  { root: Hash, ranges: ChunkRanges, level: u8 }
// response: pre-order interior hash pairs for `ranges`, down to `level`
ProofEnd  { served: ChunkRanges }
```

- **Semantics**: the parent-node pairs (64 bytes each) on the paths from the
  root to the requested ranges, descending no deeper than `level` (in group
  units: `level = n` stops at subtrees of `2^n` groups; `level = 0` yields
  leaf-group CVs). It is exactly a bao slice with the payload left out — the
  provider reads it positionally from the `.obao` file the same way
  `encode_slice_inner` does, and the requester verifies it top-down by
  recomputation from the root it already trusts. A flipped bit fails at the
  node it occurs in, as with slices.
- **Bounds**: served window clamped like slices (`MAX_SLICE_GROUPS`-shaped:
  a fixed cap on nodes per response, one frame, encode-in-memory), so a proof
  request can never name an object-sized allocation. `ProofEnd` reports how
  far the provider got; the requester walks on from there (§6.4 shape).
- **Who can serve**: any holder of the verified groups in question — a bao
  slice already carries its root-path hashes, so a partial holder's outboard
  has every node the proof for *its* groups needs. Provider selection reuses
  `providers_for` and its claims.
- **Compatibility**: new ALPN `sync/blob/2`, identical to `/1` plus the two
  messages. Nodes offer both; a dial that lands on `/1` (older peer) simply
  disables delta for that provider and the fetch degrades to today's full
  fetch. No flag day, no manifest change.

### 3.2 Donors: where local bytes come from

A *donor* is any local source of candidate bytes for the new object. In
priority order:

1. **The new root itself** — groups already in the bitmap (today's behavior,
   unchanged; a resumed fetch stays free).
2. **The entry's `prev` root** (§4.2, §8: 1-step lineage) when the CAS holds
   it, complete or partially. This is the common mirror case: the pass that
   materialized the old version fetched it into the CAS.
3. **Other versions of the same path** in its `VersionSet` — divergent
   origins' roots, and the losing versions under `newest`. Same mechanics as
   `prev`, just more candidates for the span comparison.
4. **The mirror's on-disk file.** `already_current` already streams the whole
   file through BLAKE3 every pass; its output *is* the file's content root.
   Returning that root from the phase-1 check (instead of a bare bool) tells
   the plan exactly which object is on disk for free. If it equals `prev` or
   any known version root that the CAS has dropped, the disk file itself is
   the donor: CAS-less, bytes-only.

CAS donors contribute both bytes and an outboard (so span-level CVs are read,
not recomputed). A disk-file donor contributes bytes only; its group CVs are
computed at promotion time, 16 KiB at a time, with the right chunk counter.

Donors are hints, never authority: every promoted group is re-verified against
the new root (§3.4). A malicious or stale donor costs CPU, not correctness.

### 3.3 The descent: two proof rounds, not a full outboard

Fetching the whole new outboard would be simple but is 1/256 of the object —
390 MB for a 100 GB file — most of it describing spans that did not change.
Instead the fetcher descends, the same way `mptsync` walks trie diffs (§5):

- **Round 1 — span level.** One `GetProof` at the level whose subtrees cover
  `AD_SPAN_GRANULARITY` (16 MiB, 1024 groups — deliberately the ad-span unit,
  §6.3). Cost: 32 bytes per 16 MiB plus path overhead — ~200 KB for 100 GB.
  Compare each complete aligned subtree CV against the donor's CV at the same
  position (read straight out of the donor's outboard). Equal ⇒ the whole
  span is byte-identical; promote it wholesale. Unequal or incomparable (tail
  spans, spans past either object's end) ⇒ descend.
- **Round 2 — leaf level.** `GetProof(level = 0)` restricted to the differing
  spans. Cost: 64 bytes per 16 KiB *of changed region only*. Compare leaf CVs
  group by group; equal groups are promoted, unequal groups are the delta.

Whatever remains after round 2 goes to the ordinary `fetch_groups` machinery
untouched: fanout split, `SliceEnd` re-planning, per-group verification,
bitmap commits. `FetchReport` grows a `promoted: ChunkRanges` field so
callers (and `synch mirror sync` progress lines over the control socket's
`Progress` frames) can say "reused 98.9 GB, fetched 1.1 GB".

If round 1 shows nothing in common — an encrypted container re-keyed, a
compressed archive rebuilt — the entire delta attempt has cost one ~200 KB
exchange, and the fetch proceeds exactly as today. That failure mode is cheap
enough that no similarity heuristic is needed in front of it.

### 3.4 Promotion: local bytes into the new object, verified

For each group whose new-tree leaf CV is proven (chained to `R'` by a proof
round) and equal to a donor CV:

1. Read the donor's 16 KiB at that offset (CAS payload via `read_range`-style
   positional read, or the disk file; `copy_file_range` where the donor is a
   CAS payload on the same filesystem).
2. Recompute the group CV with the offset's chunk counter and compare with the
   proven CV. This closes the gap between "the donor's outboard said so" and
   "the bytes on disk still say so" — a donor whose payload rotted under a
   correct outboard fails here and the group falls through to the network
   fetch.
3. Write into the new object's sparse payload, set the bitmap bit — the same
   commit discipline as `write_slice`, so progress survives restarts and a
   torn pass resumes instead of restarting.

Interior tree nodes come along too: nodes delivered by proof rounds are
written into the new object's sparse `.obao` at their positions, and the
interior nodes *beneath* a span-level CV proven equal are copied verbatim from
the donor's outboard (identical subtree ⇒ identical interior nodes). That
matters for the swarm: it is what lets this node serve slices of the promoted
spans, not merely hold them. Promoted groups flow through
`on_content_progress` like fetched ones, so the node advertises partial
possession of `R'` within one milestone interval — mirrors of the same space
then delta from *each other*, and the origin uploads the changed bytes
roughly once (§6.3's O(N) swarm property, now for updates too).

### 3.5 Mirror write path: patch, don't rewrite

Today phase 2 copies the whole object out of the CAS into a staging file and
renames (`write_blob_to_blocking`) — the atomicity invariant being that a
reader of the target sees old bytes or new bytes, never a truncation. Delta
keeps the invariant and drops the cost:

- When the plan knows the on-disk file's root equals the donor root (§3.2.4 —
  known for free from the phase-1 hash), the staging file starts as a
  **reflink clone** of the on-disk file (`FICLONE` on btrfs/XFS/bcachefs,
  `clonefile` on APFS): O(1) and no data copy. The differing groups — exactly
  the promoted-unequal plus network-fetched set — are then `pwrite`n into the
  staging clone from the CAS, fsync, rename. Old-or-new is preserved; write
  cost is proportional to the change.
- Where reflink is unsupported (ext4, NTFS, cross-device), fall back to
  `copy_file_range` (kernel-side copy, no user-space bounce) and then patch;
  the network savings are untouched and the write cost matches today's worst
  case. `copy_file_range` degrades to the existing read/write loop where the
  syscall itself is unavailable.
- In-place patching of the live target (no staging at all) is **rejected**: a
  crash mid-patch leaves a franken-file wearing a complete file's name, which
  is exactly what the staging rename exists to prevent (§7.2's conservatism).
  The next pass would catch it — `already_current` hashes content — but
  readers in between would not.

The s3 gateway (§9.4) and `synch take`/`get` inherit the fetch-side savings
automatically, since they ride the same fetch path; the reflink trick is
mirror-only, because only a mirror knows a same-lineage old file is sitting at
the destination.

## 4. Policy and configuration

- `delta_min_size` (default **16 MiB**): objects smaller than one ad span skip
  proof rounds entirely — the round-trips cost more than the bytes. Inline
  blobs (≤ 16 KiB) never delta.
- `mirror_delta_write`: `reflink` (default: reflink, then copy_file_range,
  then plain copy) | `copy` | `off`. `off` reproduces today's full staging
  write for operators who want bit-identical write behavior.
- Delta fetch itself needs no switch beyond the protocol version: with no
  donor, no `/2` provider, or no matching span, it *is* today's fetch plus at
  most one small exchange. A `--no-delta` escape hatch on `synch mirror sync`
  is cheap insurance for diagnosis and is worth carrying.

## 5. What this deliberately does not do

- **No content-defined chunking.** CDC would survive insertions and deletions
  that shift the tail of the file, which fixed-offset groups do not — one byte
  inserted at offset 0 defeats reuse entirely (the proof rounds report "all
  spans differ" and the fetch degrades gracefully to full, plus ~200 KB).
  But CDC chunk boundaries would have to become part of the object's identity,
  and the object address is *plain* `blake3(file)` — checkable by any BLAKE3
  tool, servable by bao, deduplicated across peers (§6.1). Changing the
  address scheme for one workload class is not worth breaking that; and the
  workloads mirrors carry at scale (images, databases, media, logs) mutate in
  place or append, which fixed offsets serve well. An rsync-style rolling-hash
  recovery layer over the existing addresses is possible future work; it fits
  *behind* `GetProof` (the receiver may match donor groups at shifted offsets
  it discovers itself — promotion in §3.4 never assumed offsets matched, only
  CVs) without any further wire change.
- **No per-chunk availability records.** Ads stay one coarse record per
  (object, holder) — §4.2 already litigated this; delta discovers exactness
  from `ProofEnd`/`SliceEnd`, the same way fetch discovers it today.
- **No persistent delta state.** No stored diffs, no generation chains beyond
  the existing 1-step `prev`. Every pass rediscovers reuse from hashes it can
  verify; nothing new can go stale or lie.

## 6. Failure modes

| Failure | Outcome |
| --- | --- |
| No provider speaks `/2` | Full fetch, as today. |
| Proof verification fails | Provider dropped for the exchange (as with a bad slice); next candidate tried; delta abandoned for this object if none remain. |
| Donor bytes fail re-verification | Group falls through to network fetch; donor kept for other groups (rot is per-extent). |
| Crash mid-promotion | Bitmap has only verified groups; next pass resumes. |
| Crash mid-patch | Staging file abandoned; target untouched (rename never happened). |
| Sizes equal, roots differ, content unrelated | Round 1 finds no equal spans; cost ≈ 200 KB per 100 GB, then full fetch. |

## 7. Cost model (worked example)

100 GB VM image, 1 GB modified in place across 64 spans, previous version on
disk and in the CAS:

| | today | with delta |
| --- | --- | --- |
| proof rounds | — | ~200 KB + 64 spans × 32 KB ≈ 2.2 MB |
| network payload | 100 GB | ~1 GB (+ slice path hashes) |
| CAS write | 100 GB payload + 400 MB outboard | ~1 GB + copied/received tree nodes |
| mirror write | 100 GB staging copy | reflink + ~1 GB patch |
| time to first ad of `R'` | after ≥ first milestone of a 100 GB fetch | one milestone after promotion — seconds |

Append-only case (log grows 100 MB on 50 GB): round 1 proves every old
complete span equal; only tail spans reach round 2; network cost ≈ the
appended bytes.

## 8. Implementation sketch

Ordered so each step lands testable on its own:

1. `synch-core`: `GetProof`/`ProofEnd` messages, `sync/blob/2` ALPN constant,
   proof-window bound; group-CV helper (16 KiB hash with explicit chunk
   counter) in `hash.rs`.
2. `synch-store`: `encode_proof` (positional outboard reads, mirror of
   `encode_slice_inner`), `write_proof_nodes` (sparse `.obao` commits), and
   `promote_groups(root, size, donor, groups)` with the §3.4 verification.
3. `synch-net`: serve `GetProof`; client `fetch_proof_into`; `/2` alongside
   `/1`.
4. `synch-engine`: donor resolution (`prev`, version set, disk-file root
   surfaced from `already_current`); the two-round descent in front of
   `fetch_groups`; `FetchReport::promoted`.
5. `synch-engine/mirror.rs`: thread the disk root through `plan_pass`;
   reflink/patch staging in phase 2 behind `mirror_delta_write`.
6. Tests: store-level round trips (equal spans across unequal sizes, tail
   groups, tampered proofs, rotted donors); a two-node
   `tests/two_nodes.rs`-style case asserting fetched-byte counts for a 1%
   edit; a mirror pass asserting reuse and the atomicity invariant;
   `examples/bench.rs` delta scenario.

Steps 1–4 deliver the network win for every fetch path; step 5 is the
mirror-specific write win and is independently shippable.
