# Delta sync for large files

This document covers delta transfer during replica acquisition and the
optional newest-view checkout that may materialize the acquired content. See
[REPLICATION.md](REPLICATION.md) for the role model.

Status: **implemented**. `synch-core` carries the messages and the chaining-value
helpers, `synch-store::proof` the proof walk and donor promotion, `synch-net` the
exchange, `synch-engine` the descent and checkout materialization. Section 8 is the
order it landed in; where the built thing differs from what was proposed, this
document has been corrected to describe the built thing.

## 1. Problem

Without delta transfer, replica acquisition treats content as all-or-nothing
per object. A changed entry names a *new* root even when nearly all of its
bytes match an object already held in the CAS.

The fetch already skips groups verified locally — but only groups verified
**under the same root** (`fetch_groups` subtracts `local_groups(root)`). A
changed file has a new root, so its local-groups set starts empty even when
99% of its bytes are identical to the previous version sitting in the CAS. The
result, for replica workloads such as VM images, databases, media
libraries, append-heavy logs):

- **Network**: a 100 GB image with 50 MB changed in place costs a 100 GB fetch.
- **Disk**: the CAS writes 100 GB of payload it already holds a near-copy of,
  and an enabled checkout may then write 100 GB more.
- **Swarm**: until the fetch completes past an ad milestone, this node
  advertises nothing of the new root, so other replicas cannot lean on it.

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
subtree CVs of the new object's bao tree against CVs this node can read out of
the trees it already holds — and every CV the comparison is made against was
*proved against the new root*, keeping the §5.1 rule that nothing is believed
because of who supplied it.

The one thing the node is missing is the new object's tree. That is the only
new thing the protocol has to move.

## 2.1 Where verification happens

Delta sync does not change the verification posture; it is worth stating it
plainly, because the shape of the code follows from it.

**Verify at the boundary. Trust the filesystem at rest.** Bytes are checked when
they *enter* the CAS — a slice decoded off the network, a proof recomputed to
the root, a file being ingested — and a chaining value proved against a root is
checked before any byte it vouches for is written. Bytes already committed under
a verified bitmap are then trusted as they sit, exactly as the rest of the design
trusts the filesystem it runs on (§6.2, §10).

The alternative was tried and removed. Re-reading a donor's payload to re-hash
what was hashed when it was written, or scrubbing a whole payload before
materializing it, makes **every update cost the size of the object** — which is
precisely the cost delta sync exists to remove, paid locally instead of over the
network. It also duplicates, badly and partially, what a checksumming filesystem
does properly and continuously.

What still verifies, and always will:

| Boundary | Check |
| --- | --- |
| Slice off the network | bao decode against the root, per 16 KiB group |
| Proof off the network | every pair recomputed up to the root the entry named |
| Promotion | donor CV (from its tree) equals a CV proved against the new root, **before** any byte is written |
| A promoted subtree's interior nodes | recombined on the way up to the proved CV, so a rotted donor *tree* cannot poison a tree this node will serve |
| Re-ingest of a checkout file | `ingest_file` hashes by construction |
| A range read | `read_range` is a bao decode against the root |
| Serving a slice | `encode_ranges_validated` |
| The checkout's currency check | the target file is user-mutable, so a path no record vouches for is re-hashed; a file reconciliation wrote or hashed itself is believed by its stat — drift detection, not CAS scrubbing |

## 3. Design overview

Delta sync builds the **new CAS blob** out of the old CAS blob plus the groups
that changed. It is a fetch-side optimization joined by one new wire exchange;
the write side is downstream of it and has no delta logic of its own.

```
        ┌───────────────────────────── new root R', size S' ──┐
        │                                                     │
  1. GetProof(R', spans)      hash-only bao traversal         │  provider
  2. compare span CVs         against donor outboards         │  (any holder
  3. GetProof(R', leaves)     only inside differing spans     │   of R')
  4. promote equal runs       old CAS blob → new CAS blob     │
  5. GetSlice(R', changed)    existing fetch path, fanout     │
        │                                                     │
        └── checkout write: clone the finished CAS blob, rename
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
  from there (§6.4 shape). The requester sizes each window from
  `proof_nodes_upper_bound` so that a provider holding everything it asked for
  still fits the budget — and since a provider walks `requested ∩ what it
  holds`, a subset can never cost more. An over-budget request is therefore not
  a conforming requester's, and the provider refuses it rather than serving a
  prefix both sides would then have to agree about. The *number* of windows one exchange may take is capped
  too: a provider serving one group per window is not barren — it is making
  progress, an RTT at a time — and without a ceiling it could hold a descent
  open for one round trip per group of the object.
- **Who can serve**: any holder of the verified groups in question — a bao
  slice already carries its root-path hashes, so a partial holder's outboard
  has every node the proof for *its* groups needs. Provider selection reuses
  `providers_for` and its claims.
- **Compatibility**: none needed. The two messages extend `sync/blob/1` in
  place — appended to `BlobMessage`, which postcard numbers by position, so the
  existing `GetSlice`/`SliceEnd` encoding is untouched. Nobody is running this
  protocol yet, so a second ALPN would have bought version negotiation and a
  fallback path for a population of zero. No flag day, no manifest change.
- **A proof carries its root and its size.** `write_proof` returns a
  `Proven { root, size, subtrees }`, not a bare list. Two objects of the same
  size have the same tree *shape*, so every positional check a promotion makes
  would pass for the wrong object's proof just as readily as the right one's —
  and what would come out is an object filled with a stranger's bytes and marked
  complete. The size closes the same hole for the object's *length*: "whole" is
  the property that makes a subtree comparable across objects at all (§2), and
  it is a fact about where the object ends, so a proof spent under a shorter
  size hands out whole-looking subtrees the object does not end after — promote
  them and the row is complete at a fraction of its length, unreadable and
  refusing every honest writer of the rest. Both therefore travel *inside*
  `Proven` rather than alongside it: `promote` reads the object and its length
  off the proof, so spending one on another object is not something a caller can
  express.

### 3.2 Donors: CAS objects, and only CAS objects

A *donor* is another object in this node's CAS that may carry bytes of the new
one. In priority order:

1. **The new root itself** — groups already in the bitmap (today's behavior,
   unchanged; a resumed fetch stays free).
2. **The entry's `prev` root** (§4.2, §8: 1-step lineage) when the CAS holds
   it, complete or partially. This is the common checkout case: reconciliation
   materialized the old version fetched it into the CAS.
3. **Other versions of the same path** in its `VersionSet` — divergent
   origins' roots, and the losing versions under `newest`. Same mechanics as
   `prev`, just more candidates for the span comparison.

There is deliberately no fourth kind. An earlier shape had the checkout's
on-disk file as a donor of its own, which meant promotion had to cope with a
donor that has no tree, no bitmap and no row — every comparison it could not
make cheaply falling back to hashing bytes — and it meant the checkout had to
reason about which promoted groups were "the file's own" to decide what its
write could keep. Both are gone.

The one capability that donor bought is kept, and paid for where it belongs.
When the lineage names versions this node holds **none** of — the collector took
the old object — and the file at the checkout's own destination turns out to *be*
one of those versions, reconciliation `ingest_file`s it and the ordinary CAS-to-CAS
delta proceeds. It runs only above `delta_min_size`, only when no CAS donor
exists, and only when the file really is a named version.

What it costs is worth separating into the two currencies, because they do not
move together. **On the network** it buys an update that costs the change rather
than the object, which is the whole point. **Locally** it costs a full read of
the file to identify it (the currency check's hash, when the file happens to be
the length of the version being written, and a second read otherwise), plus
`ingest_file`: another full read and a **full-size write into the CAS**. So
recovering a 100 GB donor is two passes over 100 GB and 100 GB of new payload,
to save 100 GB of transfer and end with the delta. Worth it on any link slower
than the disk, and not free.

Donors are hints, never authority: nothing is promoted except where the donor's
own tree gives the run the chaining value a proof chained to the new root
(§3.4). A stale donor matches nothing.

### 3.3 The descent: two proof rounds, not a full outboard

Fetching the whole new outboard would be simple but is 1/256 of the object —
390 MB for a 100 GB file — most of it describing spans that did not change.
Instead the fetcher descends, the same way `mptsync` walks trie diffs (§5):

- **Round 1 — span level.** One `GetProof` at the level whose subtrees cover
  `AD_SPAN_GRANULARITY` (16 MiB, 1024 groups — deliberately the ad-span unit,
  §6.3). What travels is the *interior* of the tree above the spans: a 64-byte
  node **pair** each, one node per span less one, not a bare 32-byte CV per
  span. A 100 GB object is 5961 spans, so 5960 pairs — **~381 KB**.
  Compare each complete aligned subtree CV against the donor's CV at the same
  position (read straight out of the donor's outboard). Equal ⇒ the whole
  span is byte-identical; promote it wholesale.
- **Round 2 — leaf level.** `GetProof(level = 0)` restricted to the spans round
  one found **comparable and unequal**: a donor had a chaining value at that
  position and it differed, which is a span whose bytes moved and whose groups
  are worth comparing one at a time. Cost is the interior below one span: 1023
  pairs, ~65 KB per 16 MiB span. A span *no* donor can speak to — past the
  end of every one of them, held by none — has nothing to be compared against,
  and descending into it would buy a leaf proof of the whole object to learn
  what round one already said. It goes straight to the fetch. The object's right
  edge is the exception and is bounded to one span: a subtree cut short by the
  end of the object is not comparable as a subtree at all, so the absence of a
  donor value there means nothing, and its groups descend.
- **The zero-match early exit.** If round one finds **no** span in common with
  any donor, round two is skipped entirely and everything goes to the fetch. A
  same-size donor with unrelated content — a container re-keyed, an archive
  rebuilt — passes every cheap test the descent has and then matches nothing,
  and the leaf round over 100 GB is ~391 MB of tree in ~746 round trips. What
  that spend could still find is agreement *inside* spans whose span-level CVs
  all differed, which for fixed-offset groups means a run that happens to align
  on a group boundary within an otherwise-changed span. Real, and far too rare
  to be worth 391 MB every time it is absent. One span in common is enough to
  say the donor is a relative of this object and the leaf round is worth
  running; zero says it is not.

Round two runs one exchange's worth at a time, cut by the same `proof_window`
the transfer side sizes its windows with, so the list of proven subtrees stays a
few hundred kilobytes however much of the object turns out to have changed — and
the requester's idea of how much fits in a round is the provider's.

The level of round one is clamped: `span_level = min(AD_SPAN_LEVEL, top - 1)`
where `top = log2(next_power_of_two(group_count))` is the height of the object's
tree. An object that *is* one span has no subtree below its root to compare —
the root carries BLAKE3's root flag and equals no chaining value anywhere (§2) —
so one level below the top is the deepest cut that still says something. The
clamp only ever bites for objects of two spans or fewer: a 1024-group object has
`top = 10` and is compared at level 9, in half-span units of 512 groups; a
2048-group object is compared at level 10, which is the span level itself. Only
an object of **two groups or fewer** has round one land on the leaf level, and
one of a single group has no interior tree to prove at all.

**What "the changed region and nothing else" is worth, stated carefully.** For
the workloads this exists for — a VM image written in place, a database file, an
appended log — round one settles almost everything and round two looks only
inside the spans that moved, so the leaf proof is proportional to the edit. Two
cases are not that. A donor of the *same size* whose content is unrelated
matches no span at all, and the early exit above is what keeps that from costing
a full leaf proof. And a byte inserted at offset 0 shifts every subsequent group,
so every span is comparable-and-unequal and round two runs over the whole object:
~391 MB of tree for a 100 GB file, after which the fetch is full anyway. Fixed
offsets buy their cheapness by being exactly this brittle to shifts (§5).

Whatever remains after round 2 goes to the ordinary `fetch_groups` machinery
untouched: fanout split, `SliceEnd` re-planning, per-group verification,
bitmap commits. `FetchReport` carries `promoted: ChunkRanges` and a
`reused: Vec<(Donor, ChunkRanges)>` breakdown of which donor supplied what, so
callers (and `synch replica sync` progress reports over the control service)
can say "reused 98.9 GB, fetched 1.1 GB".

If round 1 shows nothing in common — an encrypted container re-keyed, a
compressed archive rebuilt — the entire delta attempt has cost one ~381 KB
exchange, because the zero-match exit above stops there and the fetch proceeds
exactly as today. That failure mode is cheap enough that no similarity heuristic
is needed in front of it.

**Ranged reads.** `prepare_range` descends for whole-object reads always, and
for a partial range only when the range is at least one span. Promotion works a
span at a time and the proof rounds come before the first byte, so a one-byte
cold `synch cat --range` would otherwise pay two round trips and promote 16 MiB
to answer with one byte.

### 3.4 Promotion: old CAS blob into new CAS blob

For each proven subtree, in the new object's tree:

1. Read the chaining value the **donor's own outboard** holds at the same
   position (`cv_at`, the machinery behind `subtree_cvs`). `None` means the
   donor cannot speak to it — its tree is shaped differently there, or the run
   is the whole of it. Two positional reads for a 16 MiB span.
2. Compare with the chaining value the proof chained to the new root. Unequal
   ⇒ the bytes differ; nothing is written.
3. Only then, copy the byte run from the old payload into the new object's
   sparse payload with `copy_file_range`. Both files are in the CAS directory
   and therefore on one filesystem, which is the condition under which Linux
   routes the call through the filesystem's own remap: on btrfs, XFS and
   bcachefs an aligned run becomes a **reflink**, so the bytes are shared rather
   than moved and the new object costs no space where it agrees with the old
   one. A run of whole 16 KiB groups at 16 KiB offsets satisfies any block size
   a filesystem is likely to have; the short tail group does not, and the kernel
   copies that instead of sharing it. Where the syscall is unavailable or
   refuses, positional reads and writes finish the job.
4. Copy the interior tree nodes under the run out of the donor's outboard,
   recombining each pair on the way up and checking that it arrives at the
   proved chaining value. The new object needs those nodes or the groups it
   just gained could be held and not *served* — and the recombination is what
   keeps the copy honest, at one 64-byte hash per group rather than a pass over
   the bytes.
5. Set the bitmap bits, after payload and tree are fsynced — the same commit
   discipline as `write_slice`, so a torn pass resumes instead of restarting.

**Compare strictly before writing.** An earlier shape of this absorbed the
donor's bytes into the new payload and judged the chaining value afterwards. A
concurrent `write_slice` on the same root could commit a group's bitmap bit and
then have promotion's not-yet-judged bytes land on top of it: a bit that lies,
a group advertised and unreadable, and no path back. Every write below step 2
is a write of bytes already known to belong there, which also makes two racing
writers of one root idempotent rather than merely lucky.

Two shapes of subtree are promotable, and between them they cover everything the
descent produces: a **whole** subtree, whose chaining value is comparable across
objects at all (§2), and a **single group**, comparable whenever both objects run
the same distance past its start. A multi-group subtree cut short by the end of
the object is neither, and the leaf round settles it.

"The same distance past its start" is checked rather than assumed: a run is
copied only where its extent under the size being filled equals its extent under
the donor's own size. A chaining value attests the whole of the run it covers,
and the size a fetch is filling is a claim off an entry — one a few bytes short
leaves the tree the same shape, so the proof verifies, the final group's value
matches, and the run copied would stop before the bytes that value speaks for.
Committing that marks the group verified and the row complete at a length the
disk does not reach. One reuse is given up by
comparing trees rather than hashing bytes: a new object whose tail group is
*shorter* than the donor's group at that index — a truncation — cannot match,
because the donor's tree has no value for "the first k bytes of that group". It
is one group, and it goes to the network.

Promoted groups flow through `on_content_progress` like fetched ones, so the
node advertises partial possession of `R'` within one milestone interval —
replicas of the same space then delta from *each other*, and the origin uploads
the changed bytes roughly once (§6.3's O(N) swarm property, now for updates too).

### 3.5 Materialization: one path onto the filesystem

`materialize_blob` is the only way an object becomes a file. Checkout reconciliation
(§7.2), `synch adopt tree` of a space (§7.2), `synch adopt path`/`adopt_from` (§8) and the
gateway's fetch-to-file all go through it, and all get the same guarantees: the target is old-or-new and never
half, no staging residue is left on any path, and the object is never held in
memory.

The object must already be held whole and locally — materialization refuses
what it does not have rather than leaving a truncated file wearing a complete
file's name. Then:

- The CAS payload is **cloned** into a staging file beside the target with
  `FICLONE`. On btrfs, XFS or bcachefs that shares the payload's extents: O(1),
  no data moved, and no second copy of the object on the disk until one of the
  two is written to.
- Where the ioctl cannot apply — the checkout is on a different filesystem from
  the CAS, ext4, a platform without it — the fallback is `std::fs::copy`, itself
  a kernel-side `copy_file_range` on Linux with no bounce through user space.
- Objects small enough to live in the index (§6.2) have no payload file and are
  written straight out of it.
- The staging file is fsynced, renamed over the target, and the parent directory
  is fsynced too: "old file or new file" is a claim about crashes, and without
  the directory flush the contents can survive a power cut while the name they
  arrived under does not. Every failure path unlinks the staging file — the
  clone's, the copy fallback's, and the commit's own, which is the one that
  matters most because it runs after the handle has been given up to be flushed
  and renamed. The name a staging file uses is one the scanner's built-in ignore
  rules skip, so a stranded one would sit beside the target unnoticed forever,
  full-size, on a path reached exactly when the disk is already in trouble.

`CheckoutReport::reflinked` counts the files that cost no data movement.

**Currency: a stat, not a hash.** Checkout reconciliation decides "already current?"
the way the scanner decides "unchanged?" for filesystem sources: a file the
pass wrote or hashed itself is believed by its record — the content root,
length, stored mtime, and platform identity, believed past the scanner's racy
window — and only a path no record vouches for is hashed. A quiet pass costs
the tree's syscalls rather than its bytes, which is what makes "the engine
keeps the directory in sync" (§7.2) cheap enough to actually run. The anchor
is deliberately stronger than the scanner's: the published mtime is
peer-chosen data, so a file is never believed for *matching the entry* — only
for matching the record of what this process itself wrote or hashed.

The record is in memory, per process, and the price is paid on restart: the
first reconciliation of every checkout hashes the whole tree once, and that
pass doubles as the checkout's only scrub — whatever has drifted or rotted is found and
rewritten there. Between restarts, what a stat that never moved hides stays
hidden: a same-size rewrite that restores length, mtime, and identity, and
bytes that rot at rest beneath the record — including a CAS payload already
rotted before a pass wrote from it. Both are the filesystem-integrity domain
§2.1 delegates, and neither can send the pass into a rewrite loop: a written
file is recorded and a recorded file is believed, so the pass converges by
construction rather than by guard.

**The trade-off, stated plainly.** A checkout on a *different filesystem from
the CAS* keeps the whole network win — the delta happens in the CAS, before the
checkout is involved at all — but pays a full local copy of the object on every
update, because `FICLONE` cannot cross filesystems. An earlier design avoided
that by patching the checkout's existing file in a clone of *itself*, keeping the
groups a donor had proved it already held. That path is deliberately gone:

- **One path.** Two ways to write a file meant two sets of atomicity, residue
  and metadata behavior to keep correct, and the patching one was only ever
  exercised by one caller.
- **No TOCTOU keep-set.** Deciding what to keep meant deciding which promoted
  groups were "the file's own" — a fact about a user-mutable file, established
  before a network fetch and acted on after it. Nothing stopped the file
  changing in between, and the pass would have kept groups that were no longer
  there.
- **Extent sharing where it counts.** When the checkout *does* share a filesystem
  with the CAS — the ordinary single-disk deployment — the clone is O(1) and the
  checkout file and the CAS object are the same extents, which is strictly
  better than patching a private copy.

Put the checkout on the CAS's filesystem and the whole update, network and disk,
costs the size of the change.

## 4. Policy and configuration

- `delta_min_size` (default **16 MiB**): objects smaller than one ad span skip
  proof rounds entirely — the round-trips cost more than the bytes. Inline
  blobs (≤ 16 KiB) never delta. Setting it to `u64::MAX` turns the descent off
  for a node. Like `fetch_fanout`, this is **code-level configuration**: no
  shipped binary reads it from a file today, and this document does not promise
  a knob an operator can reach.
- Delta fetch itself needs no switch: with no donor, no provider that answers,
  or no matching span, it *is* the old fetch plus at most one small exchange.
- There is no write-side switch. Reflink is probed per materialization by
  attempting it, which costs one failing ioctl on a filesystem that cannot.

## 5. What this deliberately does not do

- **No content-defined chunking.** CDC would survive insertions and deletions
  that shift the tail of the file, which fixed-offset groups do not — one byte
  inserted at offset 0 defeats reuse entirely (the proof rounds report "all
  spans differ" and the fetch degrades gracefully to full, plus ~381 KB — or
  plus the leaf round over the object, ~391 MB, where a donor still matched a
  span somewhere and the early exit therefore did not fire).
  But CDC chunk boundaries would have to become part of the object's identity,
  and the object address is *plain* `blake3(file)` — checkable by any BLAKE3
  tool, servable by bao, deduplicated across peers (§6.1). Changing the
  address scheme for one workload class is not worth breaking that; and the
  workloads replicas carry at scale (images, databases, media, logs) mutate in
  place or append, which fixed offsets serve well. An rsync-style rolling-hash
  recovery layer over the existing addresses is possible future work; it fits
  *behind* `GetProof` without any further wire change.
- **No per-chunk availability records.** Ads stay one coarse record per
  (object, holder) — §4.2 already litigated this; delta discovers exactness
  from `ProofEnd`/`SliceEnd`, the same way fetch discovers it today.
- **No persistent delta state.** No stored diffs, no generation chains beyond
  the existing 1-step `prev`. Every pass rediscovers reuse from hashes it can
  verify; nothing new can go stale or lie.
- **No scrubbing.** See §2.1.

## 6. Failure modes

| Failure | Outcome |
| --- | --- |
| No provider answers a proof request | Full fetch, as before. |
| Proof verification fails | Provider dropped for the exchange (as with a bad slice); next candidate tried; delta abandoned for this object if none remain. |
| A proof offered for the wrong object, or at the wrong length | The root and the size travel with the proof (§3.1), so a proof only ever verifies against the object it was taken for and is spent at the length it was taken at. |
| An entry understates a root's size by less than a group | The tail group is not promoted: its extent under the claim is shorter than under the donor, so the run a chaining value attests is not the run that would be copied, and promotion refuses it. The groups before it promote normally, and the honest writer of the real length is not refused by what the claim left behind. |
| An entry overstates a root's size | The row records the claim, and the next writer with a different one replaces it — a size is only settled once the final group is held, because no earlier group's chaining value depends on it. A verifying proof or slice *can* be produced under a claim that changes the object's group count: bao splits at the largest power of two below the chunk count, so every size in one bracket shares a left subtree, and `join_root` takes no size at all — a 64-byte span-level proof of the real object verifies under a lie in the same bracket. So a cross-bracket claim replaces an unattested one and `settle_size` resets the bitmap with it, because bits verified under one tree shape say nothing under another. That costs a re-fetch of what was held, never a wrong byte, and is the accepted price of letting an unattested size yield to the next writer — the alternative is an overstated entry bricking an honest root for good. It is worth being plain about who can do it: any origin publishing a false `f:` size for a root a peer is fetching, repeatably, for the cost of one proof. `tests/size_bracket.rs` is the test. |
| An entry **under**states a root's size | Refused before anything is written. Nothing is resized on the strength of an unproved length — the payload and outboard only ever grow until a commit settles the size — so a claim short enough to contradict groups already in the bitmap is rejected, and the bytes, the bitmap and the row are exactly as they were. |
| A size claim racing a write that completes the object | The claim loses. Whether a claimed size may stand is decided inside the same transaction as the bitmap read-union-write, so the two writers serialize: the honest one either finds the claim and replaces it, or lands first and has the claim refused against the size its final group now attests to. Before that the decision was made on a snapshot taken before the work, and the second committer overwrote the first's size — leaving the row `complete` under a length no byte on the disk supported: unreadable, refusing every honest writer for good, and pinned against the collector by the entry that named it. |
| Donor's tree disagrees under a matched span | Span refused and left to the network; the spans around it are unaffected. |
| Donor's **payload** rotted, its outboard intact | Not detected, and by design. Promotion compares tree chaining values, never bytes — re-reading the donor is the scrubbing §2.1 refuses — so the rotted run is copied into the new object and its bitmap bit set. The new object then fails its own `read_range` there, and serving it fails at `encode_ranges_validated` rather than sending bad bytes, so the damage does not propagate to peers. It does propagate *locally*, into every derived object promotion touches. This is the accepted cost of trusting the filesystem at rest; the answer to it is a checksumming filesystem, and the checkout's non-convergence guard (§3.5) is what surfaces it to an operator. |
| Donor object collected mid-promotion | The payload and outboard handles are opened once and held for the run, so an unlinked inode stays readable to the end; a donor already gone before the open simply supplies nothing. |
| Crash mid-promotion | Bitmap has only committed groups; next pass resumes. |
| Two writers filling one root at once | Bitmap commits are read-union-write inside one transaction, so neither loses the other's groups; promoted bytes are correct by construction, so overlapping writes are idempotent. |
| Crash mid-materialization | Staging file abandoned and unlinked; target untouched (rename never happened). |
| Sizes equal, roots differ, content unrelated | Round 1 finds no equal spans and the leaf round is skipped entirely (§3.3); the fetch follows. Cost is the one span-level exchange, ~381 KB for 100 GB. |

## 7. Cost model (worked example)

100 GB VM image, 1 GB modified in place across 64 spans, previous version in the
CAS and checkout on the same filesystem:

| | today | with delta |
| --- | --- | --- |
| proof rounds | — | ~381 KB + 64 spans × ~65 KB ≈ 4.6 MB |
| network payload | 100 GB | ~1 GB (+ slice path hashes) |
| CAS write | 100 GB payload + 400 MB outboard | ~1 GB + 390 MB of tree; the other 99 GB is shared extents |
| checkout write | 100 GB staging copy | reflink of the finished object: O(1) |
| time to first ad of `R'` | after ≥ first milestone of a 100 GB fetch | one milestone after promotion — seconds |

On a filesystem without reflink the CAS write becomes ~100 GB of local copy and
the checkout write another 100 GB; the network column is unchanged.

Append-only case (log grows 100 MB on 50 GB): round 1 proves every old
complete span equal; only tail spans reach round 2; network cost ≈ the
appended bytes.

## 8. Implementation map

1. `synch-core`: `GetProof`/`ProofEnd` messages on the existing `sync/blob/1`
   `BlobMessage`, proof-window bound; chaining-value helpers (`group_cv`,
   `join_cvs`, `join_root`) in `hash.rs`.
2. `synch-store`: `encode_proof` (positional outboard reads, counterpart of
   `encode_slice_inner`), `write_proof` (verify, then sparse `.obao` commits)
   returning `Proven`, `subtree_cvs` (the donor-side comparison), and
   `promote(donor, proven)` with the §3.4 compare-then-clone;
   `commit_groups` for the transactional bitmap union.
3. `synch-net`: serve `GetProof`; client `get_proof` and `fetch_proof_into`.
4. `synch-engine`: donor resolution (`donor_roots`, `donors_for`); the
   two-round descent in front of `fetch_groups`, with round two restricted to
   comparable-and-unequal spans; `FetchReport::promoted` and `reused`.
5. `synch-engine`: `materialize_blob`, the one write path (§3.5), and the
   checkout re-ingest recovery (§3.2).
6. Tests: store-level round trips (equal spans across unequal sizes, tail
   groups, tampered proofs, rotted donor trees, a proof spent on the wrong
   object or at the wrong length, an overstated size, an understated one that
   must not truncate what is held, and a size claim racing a completing write),
   the tree arithmetic checked node for node against the outboard bao itself
   writes, a two-node `tests/two_nodes.rs` case asserting what a one-group edit
   to a 64-group object costs on the wire, the leaf round's restriction to spans
   a donor can speak to, the proof window ceiling's arithmetic, a staging file
   unlinked on a commit that cannot finish, and checkout reconciliations asserting reuse, an
   appended file, donor recovery by re-ingest, the atomicity invariant under a
   torn materialization, and non-convergence on a rotted payload being reported
   rather than rewritten.

Nothing in the reflink and extent-sharing paths is asserted *as* a reflink in
the tests: whether extents are shared depends on the filesystem the tests run
on, and the point of every fallback here is that the bytes, the reports and the
atomicity are the same either way.
