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
- verified content hashes identify the bytes, and — in `SystemSafety` — the
  configured durable backend satisfies its write contract. `FaultTolerant`
  drops that last assumption: it adds unguarded loss steps and the two
  `heal_missing_*` transitions, and proves the weaker invariant that survives
  them (below).

There are three layers:

- `CasGc` and `MptGc` are the compact, single-root protocol explanation;
- `SystemSafety` indexes content by root and claims by holder, and treats the
  materialized leaves of active tries as `sourceLive`, `replicaLive`, or
  metadata-only `ordinaryLive` relations;
- `TrieGraph` states GC's graph obligation over every node reachable from every
  retained trie root;
- `FaultTolerant` re-proves the system invariant with the backend allowed to
  lose what it acknowledged.

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

`FaultTolerant` is the same cell and the same twenty-two transitions with two
environment steps added — `LoseRemote` and `LoseBytes`, with no guard — and the
two heals Rust runs when a read discovers the loss. `HealRemote` and `HealLocal`
mirror `heal_missing_durable_blob` and `heal_missing_local_blob`: withdraw the
durable claim, turn every role holder's pin into a repair want, leave the
operator's pin alone. Live holders are roles (`IsRole`), which is why
`SourcePublish` and `ReplicaPromote` carry that guard. The invariant that
survives replaces `Available` with `Durable` (row present, backend claim
standing) and gives the operator no clause. Its theorems:
`role_pin_stands_on_durable_row`, or equivalently `role_pin_is_available_or_lost`
— a source's or replica's pin stands on content that is available or that the
backend has lost and the heal has not yet run; `no_role_pin_over_withdrawn_claim`;
`source_live_is_held_or_wanted` and `replica_live_is_held_or_wanted`;
`heal_converts_role_pins`; and, stated so it is not mistaken for a guarantee,
`heal_keeps_operator_pin`. `fault_free_is_reachable` embeds every `SystemSafety`
execution, so the strong theorems remain the fault-free specialization. Not
modelled: that a heal ever runs, that a want is ever satisfied, or that the
backend's `NotFound` is true — a spurious one triggers a heal that errs in the
safe direction, a pin becoming a want and a refetch.

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
