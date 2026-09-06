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
the BLAKE3 compression function, Ed25519, the native runner and transport, the
Lean compiler and runtime. Nothing in this plan disguises one of those as a
metadata invariant.

## 2. Inventory of what moves

### Trie (`crates/synch-mpt`)

| Rust today | Callers | Lean target |
|---|---|---|
| `Trie::insert`, `apply`, `remove` and the canonicalization helpers `insert_at`, `split_leaf`, `split_ext`, `wrap_in_ext`, `remove_at`, `merge_down`, `collapse` | `synch-engine/src/node.rs` publish path | `Trie/Mutate.lean` |
| `TrieNode::encode`, `hash_of_encoded`, `check_invariants`, `hashes_to` (ingress canonicality) | `synch-engine/src/reconcile.rs:1834` | `Trie/Codec.lean` gains an encoder; `Trie/Verify.lean` |
| `iter`, `scan` (with redaction check) | `node.rs`, `replica.rs`, S3 listing | `Trie/Scan.lean` |
| `diff`, `diff_each_scoped`, `for_each_resolved_change_scoped` | `synch-store/src/views.rs:1185` (materialization) | `Trie/Diff.lean` |
| `MissingWalk` (`next_batch`, `resume`, `is_exhausted`, faults, dedup, deferral) | `reconcile.rs:889-962` | `Trie/Walk.lean` |
| `is_complete_scoped_for` and the memo protocol | `reconcile.rs`, `aae.rs`, `membership.rs` | `Trie/Complete.lean` |
| `resolve_paths`, `Scope::admits_node` (serve-side admission) | `synch-net/src/mpt.rs:299-377` | `Trie/Serve.lean` |
| `first_key_outside` | `reconcile.rs:735` | `Trie/Scope.lean` |
| `reachable`, `reach_into` and `Store::gc_trie` mark-and-sweep | `synch-store/src/gc.rs:53-110` | `Trie/Collect.lean` |
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
| `touch_blob`, `durable_cache_entries`, `evict_durable_cache_to`, `enforce_cache_limit` | `backend.rs:340-363,947` | `Cas/Evict.lean` |
| `gc_content`, `gc_orphans`, `gc_staging`, `blob_candidates` pre-filter | `gc.rs:131-285` | `Cas/Collect.lean` |
| `hold_source_blob`, `reconcile_source_holds`, `live_source_blob_size` (`Txn`) | `synch-engine/src/node.rs:1633-1668`, inside the publish transaction | `Cas/Holds.lean`, gated on Publication (§6) |
| `local_ad`, `blob_candidates`, `blobs`, `pins*` projections | engine, CLI | `Cas/Project.lean` |
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
| `ByteStorage` (extend) | `writeBytes space key bytes`, `existsBytes space key` | node/value writes, `has_value` |
| `Storage` (extend) | `deleteExcept tx relation keyColumn keys` (one statement over a host temp table) | set-wise GC sweep, never per-row callbacks |
| `Hash` (new; `Crypto` stays signature-only) | `blake3 bytes`, `chunkGroup handle offset len isRoot` (chaining value of one 16 KiB group read from a file or stream), `parent left right isRoot` | node hashing, Bao tree math |
| `FileIO` (extend) | `writeAt handle offset bytes` (64-byte outboard nodes only), `copyRange src dst offset len` (reflink or positional), `setLen handle len`, `blocks space key`, `list space`, `mtime space key` | receive, promote, trim, eviction accounting, orphan sweep |
| `Stream` (new) | `openSlice`, `readNode handle` (64 bytes), `groupToFile handle payload offset len` (copies one group from the wire into the payload and answers its chaining value), `close` | verified slice receive without a payload byte ever being a Lean value |
| `Provider` (new) | `head root`, `readRange root offset len into handle`, `readOutboard root into handle`, `putPair payload outboard`, `putPairBytes`, `scratchSweep`, with a raw failure kind `notFound | other` | cloud adoption, hydration, finalize; Lean applies the §6.4 rule, the host only classifies |
| `Memo` (new) | `isKnown key`, `generation`, `certify key generation` | the completeness cache; invalidation on mutation edges is a host resource guarantee like `Lease` |
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

**T2. Mutation** (`Trie/Mutate.lean`). `insert`, `remove`, `apply` over
`ByteStorage` reads/writes and `Hash.blake3`, with the inline/out-of-line
split at 128 bytes and the 32 KiB value bound. Proof: a denotation
`⟦root⟧ : key ⇀ bytes` read through the actual decoder;
`⟦insert root k v⟧ = ⟦root⟧[k ↦ v]`, `⟦remove root k⟧ = ⟦root⟧ \ k`; every
written node satisfies the canonical invariants; two operations that yield
the same denotation yield the same root under F3 (the `root_is_order_independent`
and `canonical_after_delete` proptests become theorems). Effect trace: values
are written before the nodes that reference them; a failed write leaves the
old root readable. Cutover: `node.rs` publish path.

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

**T5. Serve-side admission** (`Trie/Serve.lean`). `resolvePaths` and the
admission decision (`admits_node`, redaction) as one command. The set of
origins the requesting peer is vouched for is an Authorization-domain result
and enters as a command argument; provenance itself is read from the raw
`trie_node_origins` rows. Proof: a served node stands at the claimed position
in the served root; a redacted reply is issued only for a node the scope
does not cover. Cutover: `synch-net/src/mpt.rs:299-377`.

**T6. Scan, iteration and diff** (`Trie/Scan.lean`, `Trie/Diff.lean`).
`scan prefix startAfter limit` with the positional redaction check; `diff`
and the scoped, streaming, resolve-new-side-only variant materialization
uses, including the `same_value` inline-versus-hash comparison that must not
touch the store. Proofs: `scan` lists exactly the denotation restricted to
the prefix, in key order, up to the limit; `diff old new` is the symmetric
difference of the two denotations; pruning identical subtrees is sound under
F3. Cutover: `views.rs:1185`, `node.rs`, `replica.rs`.

**T7. Trie collection** (`Trie/Collect.lean`). Mark from the retained roots
through `readBytes`, compute the memo keys to keep, then one
`Storage.deleteExcept` per relation (`trie_nodes`, `trie_node_origins`,
`trie_values`) and one `Memo` invalidation, all inside the single immediate
transaction `gc.rs` insists on. Proof: the marked set equals the union of
reachable sets; a node reachable from a retained root is never deleted; a
provenance row never outlives its node. Cutover: `gc_trie`.

**T8. Merkle proofs** (`Trie/Proof.lean`). `prove` is `get` with its node
trace; `verify` is `get` over the proof's nodes as a raw snapshot. Both
follow from `TrieProgramProofs`. Last, because nothing in production calls
them.

## 5. CAS slices, in order

**C1. Serving** (`Cas/Serve.lean`). `encodeSlice root ranges` computes
`requested ∩ verified ∩ [0, groups)` clamped to `MAX_SLICE_GROUPS`, then
directs the host: positional `FileIO.transfer`s of outboard nodes and payload
groups into the output sink, in Bao pre-order, with no hashing on the serve
path.
`encodeProof` moves the `Subtree` tree math (`locate`, `is_whole`,
`byte_range`, the level cut, the `MAX_PROOF_NODES` refusal) into Lean.
Proofs: every served group is in the row's coverage; an over-budget proof is
refused, not truncated; the served byte count equals the window arithmetic.
Cutover: `backend.rs:494,654,740`, `blob.rs:325`, CLI.

**C2. Verified receive** (`Cas/Receive.lean`, `Cas/Delta.lean`). `writeSlice`
owns the lease, `admit`, the row read, the complete short-circuit, the inline
buffer versus never-pre-grown-never-shrunk file policy, and the Bao tree:
Lean reads each 64-byte parent with `Stream.readNode`, has the host copy
each group into the payload with `Stream.groupToFile`, compares chaining
values up to the requested root, writes accepted outboard nodes with
`FileIO.writeAt`, flushes payload then outboard then parents, and only then
runs `IngestCommit.commitGroups` with the verified spans and `trim`.
`writeProof` and `promote` are the same tree math over `Hash.parent`,
`FileIO.copyRange` and the outboard reach rule. Proofs: a group is written to
the payload only after its chaining value chained to the requested root
(compare strictly before writing, the delta-sync invariant); the committed
spans are exactly the verified groups; the outboard is never written beyond
`reach`; promotion copies a run only when the extent the chaining value
attests equals the extent copied; every effect failure leaves the row and the
files as they were, with the lease released. This slice also closes the
existing gap: `commitGroups` with arbitrary spans and `admit` get execution
theorems on the simulated host, composed with `CasReadPromises` so that
"downloading more preserves what you have" becomes a statement about the
executed receive, not only the planner. Cutover: `write_slice`, `write_proof`,
`promote`, `trim_to_size`. Throughput gate: the CI slice benchmark must stay
within 10 % of the Rust decoder for 16 MiB slices; if two round trips per
group exceed that, the fallback is one `Stream.decodeSlice` host service
with the tree comparison stated as a trust assumption, chosen by measurement
and recorded, not assumed in advance.

**C3. Durability transitions** (`Cas/Durable.lean`). `adopt`, `markDurable`,
`healMissing`, `reconcileScratchGeneration`, `clearCache` are relational
transactions already; they move as whole commands over `Storage`, `Access`
and `Upsert`. Proofs: `markDurable` never inserts; `healMissing` withdraws a
claim only on `notFound`, moves every `source:`/`replica:` pin to a want,
leaves the operator pin, and preserves every other row; a scratch-generation
change clears exactly the non-durable, out-of-line rows. Cutover: the
`backend.rs` call sites.

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

**C5. Eviction and collection** (`Cas/Evict.lean`, `Cas/Collect.lean`).
`touch` with its 60 s coalescing through `Clock`; LRU eviction over
`durable` rows using `FileIO.blocks`; `gcContent` as one program that reads
the candidate projection and runs the existing Lean `delete` decision per
object inside its own transaction; `gcOrphans` over `FileIO.list`/`mtime`
and `Lease`. Proofs: eviction never touches a non-durable row or a row with a
live lease; the candidate pre-filter is sound (every collected object would
also be collected without the pre-filter); an orphan is removed only when
older than the window and unleased. Cutover: `gc.rs:131-285`,
`backend.rs:922-947`.

**C6. Source holds** (`Cas/Holds.lean`). `holdSourceBlob`,
`reconcileSourceHolds`, `liveSourceBlobSize` run inside the engine's publish
transaction, so they cannot become standalone commands without breaking
atomicity with the `entries` write. They migrate when Publication does, as
sub-operations composed under the same transaction token. Until then they
stay Rust and are listed as the one CAS remainder.

**C7. Projections** (`Cas/Project.lean`). `local_ad`, `blob_candidates`,
`blobs`, `pins`: row decoding through the existing `ReadCodec`, so a
malformed row is reported the same way everywhere. Small, last.

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

F1 and C1/T1 can start together. T3 and C4 wait for F2. Relative size: F2,
T3 and C2 are the large items; T1, C3 and C7 are small; the rest are medium.

## 9. What the end state claims, and what it does not

At the end, every Trie and CAS decision in `synch` is a theorem's subject
on the simulated host, and every Rust line in those domains is an adapter or
a primitive. The proofs do not claim: physical durability, eventual recovery,
concurrent or crash refinement of the simulated host, correctness of the
provider, or that the native interpreter refines the simulated one. Those
stay as tested host contracts, listed where they are assumed.
