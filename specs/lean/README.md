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
- production deletion re-checks entry, pin, and writer protection; the only
  unconditional deletion helper is compiled for tests and lies outside the
  safety transition system;
- verified content hashes identify the bytes, and the configured durable
  backend satisfies its write contract.

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
cache eviction, publication/promotion, materialized-leaf and entry removal,
pin/unpin/expiry, want removal/take-possession, protected deletion, and both GC
phases. `TrieGraph.gc_preserves_complete_retained_root` supplies the analogous
node-graph property.

What remains trusted rather than proved is the refinement from Rust statements
to Lean transitions. Anchors make that obligation auditable but do not prove
SQL or lock semantics. Crash/power-loss recovery is also outside this model;
the theorems describe executions between successful durable commits.
