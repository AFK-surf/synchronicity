# Plan: whole Trie and CAS domains in Lean, with complete proofs

Status: proposal, 2026-09-06. This plan is not authorized by
[LEAN-CORE-ARCHITECTURE.md](LEAN-CORE-ARCHITECTURE.md), whose current rule
freezes new domain migrations. Accepting this plan lifts that freeze for the
Trie and CAS domains only; the "whole Lean operation or pure Rust" rule, the
proof conventions of [`specs/lean`](../specs/lean/README.md) and the CI gates
(warnings as errors, standalone kernel recheck, axiom audit) stay in force.
Authorization, Replication and Publication are out of scope except where this
plan names an explicit seam with them.

## 1. Goal

Every Trie and CAS decision runs as executable Lean compiled into `synch`,
with Rust reduced to raw host services (SQLite, files, provider objects, hash
primitives, the transport) and facades that bind capabilities and decode
terminals. "Complete proof" means, for every migrated operation:

1. a functional theorem against a denotational model (a trie is a finite
   map; a CAS object is bytes plus a coverage set plus claims);
2. effect-trace theorems: guards hold before each effect, flush precedes
   publication, commit precedes cleanup, a failed effect at any position
   leaves the stated cleanup trace and never advertises success;
3. concrete history proofs on the shared simulated host that compose the new
   operation with the existing ones;
4. an explicit list of host assumptions the theorems take, in
   [CAS-PROMISES.md](CAS-PROMISES.md) or its Trie counterpart.

What stays trusted, permanently: SQLite, the filesystem, the object provider,
BLAKE3 and the whole Bao tree (construction, slice encode and decode, proofs
and chaining-value comparison, implemented in Rust on `bao-tree` and never
reimplemented or verified in Lean), Ed25519, the native runner and
transport, the Lean compiler and runtime. Nothing in this plan disguises one
of those as a metadata invariant.

## 2. Inventory of what moves

### Trie (`crates/synch-mpt`)

| Rust today | Callers | Lean target |
|---|---|---|
| `Trie::insert`, `apply`, `remove` and the canonicalization helpers `insert_at`, `split_leaf`, `split_ext`, `wrap_in_ext`, `remove_at`, `merge_down`, `collapse` | `synch-engine/src/node.rs` publish path | `Trie/Mutate.lean` |
| `TrieNode::encode`, `hash_of_encoded`, `check_invariants`, `hashes_to` (ingress canonicality) | `synch-engine/src/reconcile.rs:1834` | `Trie/Codec.lean` gains an encoder; `Trie/Verify.lean` |
| `iter`, `scan` (with redaction check) | `node.rs`, `replica.rs`, S3 listing | `Trie/Walk.lean` (done; `Trie::scan`/`iter` are facades) |
| `diff`, `diff_each_scoped`, `for_each_resolved_change_scoped` | `synch-store/src/views.rs:1185` (materialization) | `Trie/Diff.lean` (done; the `Apply` algebra streams each change to the host) |
| `MissingWalk` (`next_batch`, `resume`, `is_exhausted`, faults, dedup, deferral) | `reconcile.rs:889-962` | `Trie/Missing.lean` |
| `is_complete_scoped_for` and the memo protocol | `reconcile.rs`, `aae.rs`, `membership.rs` | `Trie/Complete.lean` |
| `resolve_paths`, `Scope::admits_node` (serve-side admission) | `synch-net/src/mpt.rs:299-377` | `Trie/Serve.lean` (done; `Scope::admits_path`, `contains_subtree` and `admits_value` stay Rust on the requesting walk until T3) |
| `first_key_outside` | `reconcile.rs:735` | `Trie/Scope.lean` |
| `reachable`, `reach_into` and `Store::gc_trie` mark-and-sweep | `synch-store/src/gc.rs:53-110` | `Trie/Collect.lean` (done; `Trie::reachable` stays a Rust test oracle) |
| `Scope` (`admits_path`, `contains_subtree`, `admits_key_path`, `memo_key_for`) | everywhere above | `Trie/Scope.lean` |
| `prove`, `Proof::verify` (feature `proofs`, no production caller) | none | `Trie/Proof.lean`, last |

After the cutover, `NodeStore` shrinks to raw record access (`get/put_node`,
`get/put_value`, the `redacted_nodes` and `trie_node_origins` rows, the memo
generation) and `synch-mpt` becomes a facade crate: command encoders, terminal
decoders and the `ByteStorage`/`Storage` adapters. `MemStore` survives only as
a raw store for tests.

### CAS (`crates/synch-store`)

| Rust today | Callers | Lean target |
|---|---|---|
| `encode_slice` (serve a verified window) | `backend.rs`, `synch-net/src/blob.rs:325`, CLI | `Cas/Serve.lean` |
| `encode_proof`, `encode_complete_proof` (`proof.rs`) | `backend.rs:740` | `Cas/Serve.lean` |
| `write_slice` (verified peer write) | `backend.rs:503,685`, `blob.rs:598` | `Cas/Receive.lean` |
| `write_proof`, `promote`, `subtree_cvs`, the `Subtree` tree math (`proof.rs`) | `backend.rs` delta sync | `Cas/Delta.lean` |
| `trim_to_size` | after every partial commit | folded into `Cas/Receive.lean` |
| `cache_trusted_range` (cloud hydration write) | `backend.rs:365-410` | `Cas/Hydrate.lean` |
| `adopt_durable_blob`, `mark_blob_durable`, `heal_missing_durable_blob`, `reconcile_scratch_generation`, `clear_blob_cache` | `backend.rs` | `Cas/Durable.lean` |
| `Cloud::{row_or_adopt, hydrate_ranges, finalize, read paths, touch}` (`backend.rs:174-945`) | `CasBackend` trait | `Cas/Cloud.lean` composing the above |
| `touch_blob`, `durable_cache_entries`, `evict_durable_cache_to`, `enforce_cache_limit` | `backend.rs:340-363,947` | `Cas/Collect.lean` (done) |
| `gc_content`, `gc_orphans`, `gc_staging`, `blob_candidates` pre-filter | `gc.rs:131-285` | `Cas/Collect.lean` (done; `gc_staging` stays a Rust layout sweep) |
| `hold_source_blob`, `reconcile_source_holds`, `live_source_blob_size` (`Txn`) | `synch-engine/src/node.rs:1633-1668`, inside the publish transaction | `Cas/Holds.lean`, gated on Publication (§6) |
| `local_ad`, `blob_candidates`, `blobs`, `pins*` projections | engine, CLI | `Cas/Project.lean` (done; the advertisement rule stays with C6) |
| `commit_cas_migration` | CLI one-shot | stays Rust (operator migration tool), documented as such |

Not CAS, not in this plan: `uploads.rs` (staged S3 uploads; touches the CAS
only through `CasBackend` part hooks), `cloud.rs` (the OpenDAL provider; it
becomes the `Provider` host service), `compute_outboard` (test oracle).

## 3. Foundation work (before any domain slice)

### F1. Host algebras

New raw capabilities, declared in Lean and generated through `hostgen`. None
carries policy; each is a primitive the current Rust code already performs.

| Algebra | Effects | Serves |
|---|---|---|
| `ByteStorage` (extend) | `existsBytes space key` | `has_value` without materializing the payload |
| `Storage` (extend) | `deleteExcept tx relation keyColumn keys` (one statement over a host temp table) | set-wise GC sweep, never per-row callbacks (done, T7) |
| `Digest` (new; `Crypto` stays signature-only) | `blake3 bytes` | node hashing (done, T1) |
| `ByteWrites` (new) | `putBytes space key bytes` | content-addressed node and value writes (T2) |
| `FileIO` (extend) | `copyRange src dst offset len` (reflink or positional), `setLen handle len`, `blocks space key`, `list space`, `mtime space key` | promote, trim, eviction accounting, orphan sweep |
| `Bao` (new, a whole host service like `Construct`) | `decodeSlice stream payload outboard size ranges` (verifies a slice stream against the root, writes only verified groups and their outboard nodes, answers the verified spans), `encodeSlice payload outboard size ranges → output`, `encodeProof`, `verifyProof`, `promoteRun` (compare-then-copy of one donor run) | every Bao computation: slice receive and serve, delta-sync proofs and promotion. Implemented in Rust on `bao-tree`/`blake3`, tested against standard vectors, and a stated trust assumption; Lean directs which ranges are asked for and what a reply means, never the tree |
| `Provider` (new) | `head root`, `readRange root offset len into handle`, `readOutboard root into handle`, `putPair payload outboard`, `putPairBytes`, `scratchSweep`, with a raw failure kind `notFound | other` | cloud adoption, hydration, finalize; Lean applies the §6.4 rule, the host only classifies |
| `Memo` (new) | `forgetExcept keep` (done, T7), `isKnown key`, `generation`, `certify key generation` | the completeness cache; invalidation on mutation edges is a host resource guarantee like `Lease` |
| `Redaction` (new) | `isRedacted hash path` | the refusals a peer recorded, read by every structural walk at a position it finds nothing at (done, T6) |
| `Apply` (new) | `applyChange key kind new` | the streaming materialization: each change handed to the host as the walk finds it, so a promotion never collects the diff (done, T6) |
| `Peer` (new) | `fetchNodes wants : Reply (List (path × hash × bytes))`, `fetchValues` | the reconcile fetch loop (§4, T3) |

The tag table in `Hostgen.lean` grows accordingly. The simulated host gains
sparse files, a provider object map with a NotFound switch, a memo with a
generation counter, and a hash primitive parameterized as it already is for
construction.

### F2. Async resumption

Two operations span host waits: the missing-node walk (network round trips
between batches) and cloud hydration/finalization (provider I/O). Today the
runner is synchronous and thread-confined, and the architecture document
records that no async API exists yet. F2 adds one, with the contracts that
document demands:

- a suspended program is an owned continuation with a request identity; a
  reply must name the request it answers, and a stale or duplicate reply is a
  protocol failure;
- cancellation drops the continuation and runs host abandonment cleanup;
- no SQLite transaction or connection guard is open across a suspending
  effect. This is enforced twice: the runner refuses a `Peer`/`Provider`
  request while a transaction token is live, and each program carries a Lean
  theorem `no_open_transaction_across_suspension` proved by structural
  induction on the program.

Without F2 the walk would have to serialize its frontier, deferred set and
dedup set across every batch. Those sets reach the 8 M-position ceiling on
hostile input, so that fallback is rejected on cost, not only on shape.

### F3. Proof conventions for hashes

Trie canonicality and structural-sharing pruning rest on the hash being
injective on the nodes actually stored. That is not an axiom (the audit
would reject it) but a hypothesis: theorems quantify over a hash function
and take `Injective` on the finite reachable node set as a premise. The
promise documents state that premise once.

## 4. Trie slices, in order

Each slice follows the existing integration sequence: implement the whole
program; add its raw effects to the SQLite/NodeStore adapters; run the
existing regressions plus effect-failure injection; switch the production
entry point; delete the Rust algorithm; extend the proofs. No selectable
backend at any point.

**T1. Encoder, canonicality and node hashing** (`Trie/Codec.lean`,
`Trie/Verify.lean`). Done. Lean has `encode : Node → ByteArray` and
`admit : ByteArray → Except Refusal Node` (decode, re-encode, compare, the
nibble-run cap `maxKeyBytes * 2`, the structural invariants). `verify
expected bytes` requests `Digest.blake3 (tag ++ bytes)` and decides
origin-fault versus peer-fault exactly as `verify_node` did. Proofs
(`TrieCodecProofs`, `TrieVerifyProofs`): `decode (encode n) = ok n` for every
well-formed node; `admit bytes = ok n → encode n = bytes`, the key bound and
the invariants; acceptance and each fault follow from the host's digests
alone; the borrowed input is read whole first. Cutover: `reconcile.rs`
calls `TrieNode::verify_served`, which is the Lean command; `hash_of_encoded`
is the Lean `admit` command; the Rust `hashes_to` and `check_invariants`
are deleted. `TrieNode::encode` stays until T2 removes the Rust write path.
`Digest` is the first F1 algebra; the byte-only runner gained a digest-only
entry (`run_digest`) with no storage reachable.

**T2. Mutation** (`Trie/Mutate.lean`). Done, with the denotational half
still open. `insert` and `remove` run as the whole commands `trieInsert` and
`trieRemove` over raw node reads, `ByteWrites.putBytes` and `Digest.blake3`,
with the inline/out-of-line split at 128 bytes and the 32 KiB value bound;
`apply` is the caller's sequence of those commands. The descent keeps its
path as data and rebuilds from an explicit stack, as the Rust did, so a
host round trip is a constant-depth step (the nested-continuation first
draft was quadratic in depth). Proved (`TrieMutateProofs`): every node the
path stores is the canonical image its address covers, so a store whose
nodes the ingress boundary admits stays so through every insert and remove
(`insert_preserves`, `remove_preserves`); values are written before the
nodes that name them; bounds are refused before any input is borrowed; a
remove's merges push down at most one key of nibbles. Still open: the
denotation `⟦root⟧ : key ⇀ bytes` with `⟦insert root k v⟧ = ⟦root⟧[k ↦ v]`
and `⟦remove root k⟧ = ⟦root⟧ \ k`, root uniqueness under F3, and the
key-depth invariant of whole paths (which is why the run bound is a
hypothesis rather than a theorem). The `properties.rs` proptests remain
the evidence for those. Cutover: `node.rs` publish path; the Rust
`insert_at`, `split_leaf`, `split_ext`, `wrap_in_ext`, `remove_at`,
`merge_down`, `collapse` and the frame types are deleted. Measured:
`deep_write_path` (about a thousand keys branching at every fourth byte
of a 4 KiB key) 8.9 s in the Rust write path, 17.5 s through the Lean
commands in a debug test run with the core's C compiled at `-O2`.

**T3. Walk and fetch** (`Trie/Walk.lean`, requires F2). The reconcile fetch
loop becomes one suspended program: walk a batch (reads inside a transaction
the program opens and closes), suspend on `Peer.fetchNodes`, verify each
reply through T1, write nodes and provenance rows, resume. The walk's
frontier, deferred set, `seen`, `must_be_branch` and terminal fault live in
the continuation. Proofs, on a raw snapshot and then on the mutable
simulated host: soundness (every reported want is absent and admitted by the
scope at its position); the deferral rule (a node with an absent out-of-line
value is never marked visited); the commit-ordering rule (an interrupted read
leaves the position pending); and the theorem the architecture document
currently records as an accepted gap, exhaustion implies coverage: when the
walk is exhausted, every node and value reachable from the root through
scope-admitted positions is present or redacted at a non-contained position.
Cutover: `reconcile.rs:889-962` and `verify_node`; `MissingWalk` is deleted.

**T4. Completeness and its memo** (`Trie/Complete.lean`). `isComplete owner
root scope` reads `Memo.isKnown`, snapshots `Memo.generation`, runs the T3
walk for one batch, and certifies. Proof: the result equals exhaustion of
the T3 walk; a certificate is written only under the generation it was
computed at. The host contract (generation advances on both edges of every
destructive mutation) is stated, and the existing `db.rs:275-330` tests
remain its evidence. Cutover: the four `reconcile.rs` sites, `aae.rs`,
`membership.rs`.

**T5. Serve-side admission** (`Trie/Serve.lean`). Done. The `GetNodes` and
`GetValues` answers run as the whole commands `trieServeNodes` and
`trieServeValues`, and position resolution as `trieResolve`, over raw node
reads and two snapshots. Lean owns the scope predicates a served view is
cut along (`Scope.admitsPath`, `containsSubtree`, `admitsKeyPath`,
`admitsNode`, `admitsValue`), the merged descent that resolves a batch of
claimed positions by one trail-sharing walk, the vouching rule (the root's
origins from `head_history`, ownership from `trie_node_origins`, a confined
origin vouching only for what this store was served as its), admission (an
unscoped peer answered by hash, a scoped peer refused whole on a root no
origin other than its own signed, an out-of-scope position answered as
missing under the claimed hash, a node judged by what it reveals at every
position it is named at), value authorization by the holder's coverage, and
one answer's byte budget with its one-payload-always rule. The scope, the
peer's origins and the confined origins are Authorization-domain inputs
computed in Rust (`lean_trie_serve.rs`). Proved (`TrieServeProofs`): the
spine property (`admitsPath_of_append`), the boundary property
(`containsSubtree_append`), no redaction inside a grant
(`no_redaction_inside_grant`), a value goes out only from a node that could
travel whole (`admitsNode_of_admitsValue`); whatever a descent answers, the
stored graph places it at the position descended to (`descend_sound`); the
trail holds only positions the graph places their hashes at
(`descend_trail`), so a merged descent never answers for a position it did
not reach (`resolveSorted_sound`, `resolvePaths_sound`: a position cannot
be claimed into existence); an unscoped peer and an unvouched root are
decided before any node is read (`admit_full`, `admit_unvouched`); the
budget invariant of `Answer.push`; and on a five-node trie the served,
missing and redacted lists for a scoped, an unscoped and a confined view,
value serving by coverage, and a failure injected at every effect. Cutover:
the two `mpt.rs` arms delegate to `Store::serve_trie_nodes` and
`serve_trie_values`; the Rust `admit`, `Vouch`, `Answer`, `Distinct` and
`Scope::admits_node` are deleted, and `Trie::resolve_paths` is kept only as
the walk tests' in-memory oracle. `Scope::admits_path`, `contains_subtree`
and `admits_value` remain in Rust for the *requesting* walk (`MissingWalk`)
and move with T3.

**T6. Scan, iteration and diff** (`Trie/Walk.lean`, `Trie/Diff.lean`).
Done. One structural walk serves every reader: a cursor that moves one
nibble at a time through stored and compressed nodes alike, a position the
store lacks reading as empty when the peer recorded a refusal for it (the
new `Redaction.isRedacted`) and as a missing node otherwise, and one
explicit-stack descent (`descend`) holding the hostile-shape defences for
every walk: a depth past which no valid key can begin, an absolute ceiling
on positions visited, a candidate filter (`Cursor.nextChild`) so a
position costs one step rather than sixteen, and the loop itself written
as `Program.iterate`, a trampoline that continues a pure iteration without
nesting a native call, so a 50 000-deep extension chain or a compressed
node spelling thousands of nibbles costs heap, not stack. `scan root prefix
startAfter limit` (the commands `trieScan`; `Trie::iter` is the empty
prefix) descends the prefix, then collects in key order, pruning every
subtree that sorts before the cursor and stopping when the limit is full.
`diff old new` (`trieDiff`) walks both roots in lockstep, prunes a position
both sides address alike before reading either, compares a value as a
value (`sameValue`: inline bytes against the digest of the address, through
`Digest`, never the store), and answers the changes in key order.
`materialize scope old new` (`trieMaterialize`) is the same walk confined
to the scope the fetch was confined to, each change resolved on its new
side only and handed to the host through the new `Apply.applyChange` as it
is found, answering how many were handed over; the host's callback error
travels back through `Applier` unchanged. Proved (`TrieWalkProofs`): the
nibble packing a key goes through and back (`bytesOfNibbles_keyNibbles`,
`bytesOfNibbles_odd`, `prefix_of_keyNibbles`); the value comparison
(`sameValue_inline`, `sameValue_mixed`, `sameValue_absent`); over any step
and any effect algebra the descent keeps every frame under the walk's base,
never charges past the ceiling and keeps whatever the step keeps of the
accumulator (`descend_step`, `walk_sound`, via the loop's own
`iterate_sound`), and at the ceiling a real position is refused
(`descend_refuses_past_the_ceiling`, the theorem the fan-out bomb test
now stands on); every entry a scan lists starts with the prefix, sorts
strictly after the resume cursor, and the listing is within the limit
(`takeValue_sound`, `collect_sound`, `scan_sound`); and on a concrete trie
the listing under prefix, cursor and limit with the reads each costs, a
refused position reading as empty against the same absence unexplained, a
diff against the empty root, one value under two representations being no
change by one digest, a shared subtree pruned unread, the streamed
materialization in walk order whole and scoped, and a failure injected at
every effect of all three. Open: the denotational claims (a scan lists
*exactly* the denotation under the prefix; a diff is *the* symmetric
difference), which need F3's injectivity premise and a denotation of
stored graphs. Cutover: `Trie::scan`, `iter`, `diff`, `diff_resolved` and
`for_each_resolved_change_scoped` are facades over the Lean commands with
the store's refusals, BLAKE3 and the caller's callback as capabilities;
the Rust `Cursor`, `FanoutGuard`, `descend`, `collect`, `take_value`,
`subtree_is_below`, `diff_each_scoped`, `diff_walk`, `enter` and
`same_value` are deleted.

**T7. Trie collection** (`Trie/Collect.lean`). Done. `Store::gc_trie` is
the whole command `trieCollect`: one immediate transaction that reads the
head rows, marks from every retained root through `readBytes` into one
accumulating mark set (a node already marked is not read again, a node the
store does not hold is marked and skipped, so a partially fetched pending
head marks what it has), computes the certificates to keep, forgets the
rest through the new `Memo.forgetExcept`, and sweeps `trie_nodes`,
`trie_node_origins` and `trie_values` with one `Storage.deleteExcept` each
(one statement over a host temporary table). The walk is written over a
`MarkSet` interface: the command runs it over `Std.HashSet`, the proofs over
a list. The certificates kept are the roots marked from, their keys under
the local scope, and their keys as each origin's own under the local scope
and the whole keyspace; the key layout is Lean's (`Trie/Memo.lean`, over
`Digest`), and `Scope::memo_key`/`memo_key_for` now ask Lean for it
(`trieMemoKey`), so every reader and the sweep share one layout. The memo
itself stays a host resource: forgetting begins the same mutation the
store's own transactions begin, and the guard ends it after the storage
session's transaction edge, exactly as `Txn` did. A walk that outran its
budget (2^40 nodes) sweeps nothing. Proved (`TrieCollectProofs`): both set
instances satisfy the laws the walk relies on; over any lawful set the walk
leaves the store untouched, marks every frontier address, keeps the mark
closed under children once the frontier is drained and every marked node's
values marked, so every node reachable from a root it started from is
marked (`mark_complete`) and every out-of-line value a marked node names is
marked (`mark_values`); a set-wise sweep keeps exactly the rows whose key is
kept (`sweep_keeps_only_kept`); the memo keys' byte layout is pinned
(`scoped_layout`, `owned_layout`), the whole keyspace is keyed by the root
with no digest asked for, and an owned key is one digest; and on a concrete
store the pass keeps exactly the retained root's nodes, provenance and
value and sweeps the displaced root, its provenance and the orphan value
(`the_sweep_keeps_exactly_what_the_retained_root_reaches`), provenance
names a surviving node, a store with no head is swept whole, a scoped store
keeps the scoped certificate, and every injected failure rolls back. The
graph-level claim "marked = reachable" is proved as completeness
(`mark_complete`); soundness (nothing unreachable is marked) is not, and is
not needed for safety. Cutover: `gc.rs`'s mark loop, `sweep_unmarked` and
the memo-key layout in `synch-mpt` are deleted; `Trie::reachable` stays a
test oracle; `retained_roots_in` stays under `cfg(test)`.

**T8. Merkle proofs** (`Trie/Proof.lean`). `prove` is `get` with its node
trace; `verify` is `get` over the proof's nodes as a raw snapshot. Both
follow from `TrieProgramProofs`. Last, because nothing in production calls
them.

## 5. CAS slices, in order

**C1. Serving** (`Cas/Serve.lean`). Done. `encodeSlice root ranges` reads
the row through the read path's statement and decoder, computes
`requested ∩ held ∩ [0, groups)` clamped to `maxSliceGroups`, and asks the
new `Bao` host algebra (`Host/Bao.lean`: `encodeSlice`, `encodeProof`) for
exactly that window; `encodeProof` computes the same window, answers a
single-group object without asking, and turns the service's over-budget
answer into a refusal of the whole request. The service appends its
encoding to the run's private output sink, as a file transfer does, so a
served window is never a Lean value; the interpreter loop serves the two
effects by hand for that reason, and the trait's methods are written in the
generator. The Bao tree, both formats and the walk stay in Rust as the
service (`lean_serve.rs`), a stated trust assumption. Proved
(`CasServeProofs`): every group the program asks the service for was
requested, is held by the row's own record and lies within the object
(`window_sound`, `wanted_sound`); a slice window covers at most
`maxSliceGroups` groups; a missing row and an empty window are answered
before the service is asked anything; a proof past the budget is an error
with nothing published; on the simulated host the published bytes are
exactly the service's encoding of the window the answer names, and every
failed effect publishes nothing. Cutover: `Store::encode_slice` and
`Store::encode_proof` delegate; the Rust window computation and
`encode_slice_inner` are deleted. `encode_complete_proof` (the cloud path's
in-memory outboard) stays Rust until C4. The requester-facing terminal
carries the byte count and the served spans, so `SliceEnd`/`ProofEnd` are
unchanged.

**C2. Verified receive** (`Cas/Receive.lean`). Done. `writeSlice`,
`writeProof` and `promote` run as the whole commands `casWriteSlice`,
`casWriteProof` and `casPromote` over the metadata commit's algebra, the
`Lease` algebra and six more `Bao` effects (`decodeInline`, `decodeSlice`,
`flushObject`, `trimObject`, `writeProof`, `promoteRun`). Lean owns the
write lease bracket (taken before the row is read, released exactly once),
`admit`, the row read and its complete short-circuit, the window within the
object, the inline-buffer-versus-file split at 16 KiB, the flush before the
commit, `commitGroups` with exactly the window, the trim of a completed
object, the held-nothing row a proof with interior nodes records, and every
promotion eligibility rule (no overlap with a held group; a single group or
a whole subtree; the donor covers the run; equal extents in both objects;
a donor with verified out-of-line groups and more than one of them). The
service decodes a received encoding out of the run's byte input straight
into the object's files or inline buffer, verifies a proof and writes its
nodes as far as they reach, compares a chaining value and copies a run on
a match, and flushes and trims files: the Bao tree, both formats, the walk,
the chaining-value comparison and the reach stay Rust as a trust assumption
on `bao-tree`/`blake3`. Proved (`CasReceiveProofs`): on the simulated host
a slice into a fresh store commits exactly the window (the planner's row
for `none` and the window, as `committed` spells it) with the lease
bracketing the whole and the decode and flush strictly before the
transaction; the inline path likewise; a proof with nodes records the
held-nothing row after its flush and one without records nothing; an empty
window takes no lease; a claim the row cannot yield to is refused before
anything is decoded; a promotion asks the service only about eligible runs
(never a held group: `eligible_disjoint`, `eligible_covered`,
`eligible_whole`) and commits exactly the runs the donor's tree agreed
with; and a failure at every effect before the commit leaves no row and no
lease. Not proved: the "downloading more preserves what you have"
composition with `CasReadPromises`, which needs the read path's row
predicate stated over a bitmap row; `size_bracket.rs` and `proof.rs` tests
remain that evidence. Cutover: `Store::write_slice`, `write_proof`,
`promote` delegate; their orchestration, the eligibility checks and
`open_donor`'s policy are deleted; the decode, verify, copy, flush and trim
halves are the service (`lean_bao.rs`, `cas.rs`, `proof.rs`).
`cache_trusted_range` (cloud) still calls `commit_groups` and
`trim_to_size` directly until C4. No per-group round trips: one decode per
window, as before.

**C3. Durability transitions** (`Cas/Durable.lean`). Done. `markDurable`,
`adoptDurable`, `healMissing`, `reconcileScratch` and `clearCache` run as
the whole commands `casMarkDurable`, `casAdoptDurable`, `casHealMissing`,
`casReconcileScratch` and `casClearCache` over `Storage`, `Access` and
`Clock`, with `Resources` for the writer count and the post-commit file
removals of `clearCache`. `Selection` gained `notEquals` (rendered
`IS NOT ?`) so "durable ≠ 0" is a raw predicate rather than a Rust
statement, and the store's schema capability gained the `config` relation.
The simulated host now renders every literal predicate as SQL `IS`, as the
adapter does, so NULL selects NULL (`isCell`); conflicts and joins keep `=`.
Proved (`CasDurableProofs`), each as the exact database the executed
program leaves on the shared host: marking never inserts and returns every
other relation and every other root's row verbatim; healing withdraws a
claim only where one stands, and only then copies every `source:`/`replica:`
pin to a repair intent (existing intents keeping their record), removes
exactly the role pins, leaves every other pin (the operator's among them)
and every other root's row, and conserves the read-path obligation theorem
(`heal_preserves_responsibility` reuses `CasHealingPromises`); a generation
change drops exactly the staged rows, clears the cached groups of every
durable out-of-line row and records the marker, while a matching marker
changes nothing; concrete fixtures cover adoption (create, mark, refuse a
size mismatch untouched), the cold-row sweep, the writer refusal of
`clearCache`, the commit-before-unlink order with unlink failures tolerated,
and rollback at every failing effect of every transition. Cutover: the five
`Store` methods in `cas.rs` delegate to `lean_durable.rs`; their SQL bodies
are deleted, and `clear_blob_cache` keeps the Rust ordering guard around
the command. `backend.rs` call sites are unchanged.

**C4. Cloud composition** (`Cas/Cloud.lean`, `Cas/Hydrate.lean`, requires
F2). `hydrateRanges` holds the lease, fetches the outboard on first touch,
reads 8 MiB windows with `Provider.readRange` straight into the payload
handle, and commits each window through `commitGroups`; `finalize` puts the
pair and then `markDurable`; the read and serve entry points hydrate the
missing groups first, then run C1 or the existing local read, then `touch`.
Proofs: the durability order (`durable = 1` is written only after a
successful `putPair` reply); a hydrated group is committed only after the
provider reply covered it; `notFound` reaches `healMissing` and no other
failure kind does; no transaction is open across a provider effect (F2
theorem). Cutover: `Cloud` in `backend.rs`; `cloud.rs` remains as the
provider service.

**C5. Eviction and collection** (`Cas/Collect.lean`). Done. `touch`,
`evict`, `gcContent` and `gcOrphans` run as the whole commands `casTouch`,
`casEvict`, `casGcContent` and `casGcOrphans` over `Storage`, `Access`,
`Clock`, `Lease` and a new `Sweep` algebra (`Host/Sweep.lean`: the bytes a
keyed file occupies, when it was written, and the store's object roots one
host-chosen page at a time). Two effects were added to existing algebras:
`Access.snapshotExcluding` (a snapshot with the same correlated `NOT
EXISTS` exclusions a delete's blockers evaluate) and `Lease.order`, the
remover's critical section, which the Rust service implements as the
connection followed by the CAS ordering guard (the order every writer's
lease takes) and shares with the storage session, so every statement inside
the section runs on the connection it holds. Lean owns the 60 s coalescing
against the row's own stamp and the rule that the clock never moves
backwards; the selection of evictable rows (`durable`, no inline bytes: a
pinned row is eligible, a staged-only row never), their measure, their
order by least recent use (a structural insertion sort, so the proofs can
evaluate it), the target from the configured limit and the filesystem
shortfall the host reports, and the clear of each entry inside the section
through `Durable.clearCache`, which refuses an object a writer holds; the
collection pre-filter as one excluding snapshot filtered by the horizon,
and the deletion of each candidate inside the section through the existing
`Cas.delete`, which re-reads every fact in its own transaction; and the
orphan sweep, per file, inside the section: the file's age, then whether a
row accounts for the object, then the writer count, then the unlink. The
staging-directory sweep (`gc_staging`) stays Rust: it removes unregistered
temporaries by age and consults no row. Proved (`CasCollectProofs`): the
clock moves only past the interval and only forwards; eviction considers
only cached durable rows, stops once within the target, and a clear of a
held object is refused before any transaction; the pre-filter's exclusions
are exactly the pin and entry facts the deletion re-reads
(`excluded_iff_protected`), so a row it drops for protection or freshness
is one `delete` refuses on the same database (`dropped_protected_is_kept`,
`dropped_fresh_is_kept`, the first by the read path's existing promise); a
fresh file is left alone with only the section and one reading; a stale
file of an unaccounted, unheld object goes, with the reading, the row
check, the writer check and the unlink inside the one section in that
order; fixtures run eviction in LRU order with a pinned row eligible and a
staged row not, skip a held object, collect exactly the cold unprotected
object with the section around the whole deletion, sweep only the stale
unaccounted unheld files, and release the section at every injected
failure. Cutover: `Store::touch_blob`, `evict_durable_cache`, `gc_content`
and the object-file half of `gc_orphans` delegate (`lean_collect.rs`,
`lean_sweep.rs`); the Rust LRU loop, cache measurement, in-memory touch
coalescing, candidate pre-filter and per-file orphan decision are deleted,
and `enforce_cache_limit` keeps only the `statvfs` reading.

**C6. Source holds** (`Cas/Holds.lean`). `holdSourceBlob`,
`reconcileSourceHolds`, `liveSourceBlobSize` run inside the engine's publish
transaction, so they cannot become standalone commands without breaking
atomicity with the `entries` write. They migrate when Publication does, as
sub-operations composed under the same transaction token. Until then they
stay Rust and are listed as the one CAS remainder.

**C7. Projections** (`Cas/Project.lean`). Done. `blob`, `blobs`,
`blob_candidates`, `pins`, `pins_for` and `pinned_blobs` run as the whole
commands `casBlob`, `casBlobs`, `casBlobCandidates`, `casPins` and
`casPinnedBlobs`, each one read transaction over raw `readRows` and
`existsRows`. Lean owns the statements and their order (most recently
accessed first, ties by root; claims by object then holder; pinned roots by
root), the row validation the read path applies (column class by position
and name, then the root's width, a row of the wrong shape malformed), the
holder spelling (`PinHolder.parse`, structural over the characters, with an
unknown spelling kept as a holder rather than dropped), and the pin state:
one object's from `existsRows` in the same transaction, a listing's from one
inner join of the same relation in the same order, merged in one pass
(`markPinned`) rather than asked row by row. Proved (`CasProjectProofs`): a
well-typed row decodes to its cells and each refusal names its column; the
merge marks exactly the rows the join listed a root for
(`markPinned_marks_exactly`, under a primary key's distinct roots); dropping
adjacent duplicates keeps exactly the roots there were; the holder parser on
the spellings that matter; one object's row on the simulated host, absent or
present with its pin state; and the ordered listings on fixtures with a
failure injected at every effect. The simulated host's ordered `query` now
sorts with a structural insertion sort so such fixtures can be decided.
Cutover: the six `Store` methods delegate (`lean_project.rs`); their SQL,
the pin subquery and the pins reader are deleted. `Txn::blob` and
`BlobRow::to_ad`, the row read and the advertisement rule inside the publish
transaction, stay Rust with C6: they are composed under the `entries` write
and move with Publication. `local_ad` is that rule over the Lean row read.

## 6. Cross-domain seams

- CAS and Trie still do not import each other.
- The reconcile loop after T3 is a Replication-domain program that composes
  the Trie walk. Until Replication migrates, Rust calls the T3 command and
  owns head acceptance and pending-head promotion around it.
- Vouching (T5) and hold atomicity (C6) are the two places this plan
  touches Authorization and Publication. Both are documented inputs, not
  Rust-computed trie or CAS policy.

## 7. Gates per slice

- `lake build --wfail`, the standalone kernel recheck and the axiom audit.
- The slice's Rust regressions, unchanged: for Trie, `properties.rs`,
  `ingest_boundary.rs`, `hostile_structure.rs`, `fanout_bomb.rs`,
  `frontier_cost.rs`, `missing_values.rs`, `interrupted_walk.rs`,
  `deep_write_path.rs`; for CAS, the `cas.rs` settlement, lease/sweep and
  deletion-ordering suites, the `backend.rs` contract suite against both
  backends, `proof.rs` tampering and extent tests, `gc.rs` retention tests.
- Effect-failure injection at every raw effect of the new program, native
  and simulated.
- Cost gates measured, not asserted: `frontier_cost.rs` read counts; the
  fan-out ceiling; slice receive and serve throughput against the Rust
  baseline; the 4 MiB and 64 MiB memory probes.
- Cross-platform CI (Linux GNU, macOS, Windows gnullvm) before a slice is
  called complete. Local green is a checkpoint, not completion.
- The Rust algorithm and its tests-only hooks are deleted in the same change
  that switches the entry point.

## 8. Order and dependencies

```
F1 ──┬── T1 ── T2 ── T6 ── T7 ── T8
     │    └──── T5
     ├── C1 ── C3 ── C5 ── C7
     │    └── C2
F2 ──┴── T3 ── T4
     └── C4
Publication migration ── C6
```

F1 and C1/T1 can start together. T3 and C4 wait for F2. Relative size: F2
and T3 are the large items; T1, C3 and C7 are small; the rest are medium.
C2 shrank when the Bao tree was fixed on the Rust side.

## 9. What the end state claims, and what it does not

At the end, every Trie and CAS decision in `synch` is a theorem's subject
on the simulated host, and every Rust line in those domains is an adapter or
a primitive. The proofs do not claim: physical durability, eventual recovery,
concurrent or crash refinement of the simulated host, correctness of the
provider, or that the native interpreter refines the simulated one. Those
stay as tested host contracts, listed where they are assumed.
