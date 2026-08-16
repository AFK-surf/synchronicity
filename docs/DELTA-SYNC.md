# Delta sync for large files

Status: **implemented**. `synch-core` carries the messages and the chaining-value
helpers, `synch-store::proof` the proof walk and donor promotion, `synch-net` the
exchange, `synch-engine` the descent and the mirror's patching write. Section 8
is the order it landed in; where the built thing differs from what was proposed,
this document has been corrected to describe the built thing.

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

### 3.1 Wire: `GetProof` on `sync/blob/1`

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
- **Bounds**: served window clamped like slices, but counted in *nodes* rather
  than groups (`MAX_PROOF_NODES`, 8192 — 512 KiB in one frame,
  encode-in-memory), so a proof request can never name an object-sized
  allocation. Counting groups instead would defeat the point: a 512-group window
  would turn the span-level round of a 100 GB object into twelve thousand round
  trips. `ProofEnd` reports how far the provider got; the requester walks on
  from there (§6.4 shape). When the budget cuts a walk short the provider
  re-walks the ranges that fit and sends exactly those, so both sides agree on
  the answer node for node rather than the requester having to guess which
  prefix it received.
- **Who can serve**: any holder of the verified groups in question — a bao
  slice already carries its root-path hashes, so a partial holder's outboard
  has every node the proof for *its* groups needs. Provider selection reuses
  `providers_for` and its claims.
- **Compatibility**: none needed. The two messages extend `sync/blob/1` in
  place — appended to `BlobMessage`, which postcard numbers by position, so the
  existing `GetSlice`/`SliceEnd` encoding is untouched. Nobody is running this
  protocol yet, so a second ALPN would have bought version negotiation and a
  fallback path for a population of zero. No flag day, no manifest change.

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
4. **The mirror's on-disk file.** The phase-1 currency check already streams
   the whole file through BLAKE3 whenever its size matches the wanted version;
   its output *is* the file's content root, so returning that (instead of a
   bare bool) tells the plan exactly which object is on the disk for free. The
   file is offered as a donor whatever its size, though — an append is the case
   delta serves best, and there the old file is by definition the wrong length
   — and it is offered last, because it is the only donor whose every span has
   to be hashed to be compared at all. If the CAS has dropped every version,
   the disk file is the whole of the descent: CAS-less, bytes-only.

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
bitmap commits. `FetchReport` grows a `promoted: ChunkRanges` field, and a
`reused: Vec<(Donor, ChunkRanges)>` breakdown of which donor supplied what, so
callers (and `synch mirror sync` progress lines over the control socket's
`Progress` frames) can say "reused 98.9 GB, fetched 1.1 GB" — and so the mirror
write in §3.5 knows which groups of the file at its destination are already
right.

If round 1 shows nothing in common — an encrypted container re-keyed, a
compressed archive rebuilt — the entire delta attempt has cost one ~200 KB
exchange, and the fetch proceeds exactly as today. That failure mode is cheap
enough that no similarity heuristic is needed in front of it.

### 3.4 Promotion: local bytes into the new object, verified

For each group whose new-tree leaf CV is proven (chained to `R'` by a proof
round) and equal to a donor CV:

1. Read the donor's 16 KiB at that offset — a positional read of the CAS
   payload, or of the disk file. (Not `copy_file_range`: step 2 has to see the
   bytes, so a kernel-side copy that never brings them into user space would
   only mean reading them twice.)
2. Recompute the group CV with the offset's chunk counter and compare with the
   proven CV. This closes the gap between "the donor's outboard said so" and
   "the bytes on disk still say so" — a donor whose payload rotted under a
   correct outboard fails here and the group falls through to the network
   fetch.
3. Write into the new object's sparse payload, set the bitmap bit — the same
   commit discipline as `write_slice`, so progress survives restarts and a
   torn pass resumes instead of restarting.

Interior tree nodes come along too: nodes delivered by proof rounds are
written into the new object's sparse `.obao` at their positions, and the nodes
*beneath* a span-level CV fall out of the re-hash in step 2 for free — hashing a
span group by group produces every interior CV under it on the way up, so they
are recorded as the span is verified rather than copied out of the donor's
outboard. (Recomputing is also the stricter of the two: the nodes written are
the ones the bytes on this disk imply, not the ones the donor's tree claimed.)
That matters for the swarm: it is what lets this node serve slices of the
promoted spans, not merely hold them. Promoted groups flow through
`on_content_progress` like fetched ones, so the node advertises partial
possession of `R'` within one milestone interval — mirrors of the same space
then delta from *each other*, and the origin uploads the changed bytes
roughly once (§6.3's O(N) swarm property, now for updates too).

### 3.5 Mirror write path: patch, don't rewrite

Today phase 2 copies the whole object out of the CAS into a staging file and
renames (`write_blob_to_blocking`) — the atomicity invariant being that a
reader of the target sees old bytes or new bytes, never a truncation. Delta
keeps the invariant and drops the cost:

- When the plan knows the on-disk file's root equals a donor root (§3.2.4 —
  known for free from the phase-1 hash whenever the sizes match, and computed
  deliberately when they do not and the file is at least `delta_min_size`), the
  staging file starts as a
  **reflink clone** of the on-disk file (`FICLONE` on btrfs/XFS/bcachefs,
  `clonefile` on APFS): O(1) and no data copy. The differing groups — exactly
  the promoted-unequal plus network-fetched set — are then `pwrite`n into the
  staging clone from the CAS, fsync, rename. Old-or-new is preserved; write
  cost is proportional to the change.
- Where reflink is unsupported (ext4, NTFS, cross-device), fall back to
  `std::fs::copy` — which is itself a kernel-side `copy_file_range` on Linux,
  with no user-space bounce — and then patch; the network savings are untouched
  and the write cost matches today's worst case.

  Which groups are "the differing ones" is read off `FetchReport::reused`, which
  records what each donor supplied. Bytes promoted from the file at the target
  are trivially bytes that file has right; so are bytes promoted from the CAS
  object the file *is* a copy of, which is the case that carries the ordinary
  mirror update — the previous version is usually in both places, and the CAS is
  the cheaper of the two to compare against, so it wins the donor race every
  time. Everything else is written out of the CAS.
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
- `mirror_delta_write`: `reflink` (default: reflink, then copy) | `copy` |
  `off`. `off` reproduces the pre-delta full staging write for operators who
  want bit-identical write behavior.
- Delta fetch itself needs no switch: with no donor, no provider that answers,
  or no matching span, it *is* the old fetch plus at most one small exchange.
  The escape hatch for diagnosis is `delta_min_size`, which set to `u64::MAX`
  turns the descent off for a node without touching anything else.

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
| No provider answers a proof request | Full fetch, as before. |
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

1. `synch-core`: `GetProof`/`ProofEnd` messages on the existing `sync/blob/1`
   `BlobMessage`, proof-window bound; chaining-value helpers (`group_cv`,
   `join_cvs`, `join_root`) in `hash.rs`.
2. `synch-store`: `encode_proof` (positional outboard reads, mirror of
   `encode_slice_inner`), `write_proof` (verify, then sparse `.obao` commits),
   `subtree_cvs` (the donor-side comparison), and
   `promote(root, size, donor, proven)` with the §3.4 verification.
3. `synch-net`: serve `GetProof`; client `get_proof` and `fetch_proof_into`.
4. `synch-engine`: donor resolution (`prev`, version set, the disk file, whose
   root is surfaced from what used to be `already_current`); the two-round
   descent in front of `fetch_groups`; `FetchReport::promoted` and
   `FetchReport::reused`.
5. `synch-engine/mirror.rs`: thread the disk root through `plan_pass`;
   reflink/patch staging in phase 2 behind `mirror_delta_write`.
6. Tests: store-level round trips (equal spans across unequal sizes, tail
   groups, tampered proofs, rotted donors), and the tree arithmetic checked
   node for node against the outboard bao itself writes — everything else
   stands on that being right; a two-node `tests/two_nodes.rs` case asserting
   what a one-group edit to a 64-group object costs on the wire; mirror passes
   asserting reuse, patching, an appended file, and the atomicity invariant
   under a torn patch.

Steps 1–4 deliver the network win for every fetch path; step 5 is the
mirror-specific write win and is independently shippable.
