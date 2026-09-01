# CAS / mptsync / ingest Lean model

This package proves the transition systems behind the CAS safety claim. It is
intentionally not a formal semantics of Rust, SQLite, or a filesystem. Instead,
each transition corresponds to a named Rust linearization point, and
`check-anchors.sh` makes those review anchors bidirectional.

```sh
cd specs/lean
lake build --wfail
./check-anchors.sh
```

The proof boundary is explicit:

- one process owns the data directory through `LifecycleLock`; independently
  opened `Store` values in that process share one CAS writer/GC coordinator;
- SQLite immediate transactions are atomic;
- the shared CAS coordinator orders lease registration against every unlink;
- production deletion of durable content re-checks entry, pin, and writer
  protection; the only unconditional deletion helper is compiled for tests and
  lies outside the safety transition system;
- a *staged* row (`durable = 0`) may be dropped without consulting pins — by
  cache eviction, a scratch-generation reset, or a backend migration — and
  `SystemSafety.DropStaged` models that. It is safe because `Pin` and
  `TakePossession` require `Available`, which requires `durable`, and
  `Store::pin`/`take_possession` enforce exactly that predicate
  (`staged_row_drop_is_unpinned`);
- verified content hashes identify the bytes, and the configured durable
  backend satisfies its write contract. A backend that loses an object it
  acknowledged (an S3 `NoSuchKey` on a durable root) breaks that assumption;
  the `heal_missing_*` paths that respond to it lower `durable`, convert
  source and replica pins into repair wants, and leave operator pins in place.
  Those transitions, and the source-holder wants they create, are outside the
  model on purpose: they describe recovery from a broken assumption, not an
  execution the theorems cover.

There are three layers:

- `CasGc` and `MptGc` are the compact, single-root protocol explanation;
- `SystemSafety` indexes content by root and claims by holder, and treats the
  materialized leaves of active tries as `sourceLive`, `replicaLive`, or
  metadata-only `ordinaryLive` relations;
- `TrieGraph` states GC's graph obligation over every node reachable from every
  retained trie root.

The principal system theorems are
`SystemSafety.source_live_content_is_available` and
`SystemSafety.replica_live_content_is_pin_or_want`. They quantify over the
actual holder and content root, so a claim for one root cannot discharge a leaf
for another. The reachable transition closure includes writes and aborts,
cache eviction, staged-row removal, remote adoption, publication/promotion,
materialized-leaf and entry removal, pin/unpin/expiry, want
removal/take-possession, protected deletion, and both GC phases.
`TrieGraph.gc_preserves_complete_retained_root` supplies the analogous
node-graph property.

`MptGc` is deliberately looser than the code where the code's own ordering is
not what the invariant rests on: a fetch batch may commit after the pending
slot was cleared (`LearnBatch` is unguarded), a head that loses the ordering
comparison is retained without a slot (`Retain`), and the pending slot may be
cleared without a flip (`DropPending`). Each is a transition Rust performs, and
each preserves `active → retained ∧ complete ∧ materialized` trivially.

What remains trusted rather than proved is the refinement from Rust statements
to Lean transitions. Anchors make that obligation auditable but do not prove
SQL or lock semantics. Crash/power-loss recovery is also outside this model;
the theorems describe executions between successful durable commits.
