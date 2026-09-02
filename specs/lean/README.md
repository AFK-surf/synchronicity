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

There are four layers:

- `CasGc` and `MptGc` are the compact, single-root protocol explanation;
- `SystemSafety` indexes content by root and claims by holder, and treats the
  materialized leaves of active tries as `sourceLive`, `replicaLive`, or
  metadata-only `ordinaryLive` relations;
- `TrieGraph` states GC's graph obligation over every node reachable from every
  retained trie root;
- `FaultTolerant` re-proves the system invariant with the backend allowed to
  lose what it acknowledged;
- `Scope` and `ScopedSync` open the `complete` bit of `MptGc` for a node that
  reads under a delegation scope (§5.5): the scoped fetch walk over a partial
  trie, its pruning against a reference root, the responder's authorization by
  position, and what a delegate can end up holding (below);
- `Convergence` proves the three pieces convergence decomposes into: head
  selection is an order-independent join, the derived view is a function of
  root and scope, and a fetch terminates and is complete when it can take no
  further step (below);
- `Provenance` is the multi-party model that the single-store privacy theorem
  cannot state: whether a node is *legitimately* a reader's, across every trie
  it might be read through. Its theorem is `privacy` and `integrity` over every
  reachable system state, with the graft of issue #115 as the witness that the
  invariant is strong enough to exclude it (below).

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

## mptsync over partial tries

`Scope` is `scope.rs` restated over nibble paths: `AdmitsPath`,
`ContainsSubtree`, `AdmitsKey`, and the facts both sides of a scoped fetch rely
on — `admitsPath_of_append` (every ancestor of an admitted position is
admitted, the spine), `containsSubtree_append` (nothing below a granted prefix
leaves it), and `admitsPath_of_admitsKey`.

`ScopedSync` builds the trie and the protocol on top:

- `At c root path hash` is the verified trie under content addressing `c`,
  descending branch slots and extension prefixes as `resolve_paths` does.
  `At.unique` — a position names one hash — needs exactly the non-empty
  extension prefix `check_invariants` enforces (`Canonical`).
- `Reach` is the scoped `MissingWalk`: a child position is visited when its
  parent was visited, held, not a redaction `Boundary`, and the child's position
  is admitted. `Reach.admits` says an honest walk never asks for an out-of-scope
  position, `Reach.at` that every position it claims resolves to the hash it
  claims. `CompleteWithin` is the walk draining with nothing missing — the fact
  `is_complete_scoped` memoizes.
- `ReachRef` prunes against a reference root. `prune_sound` is the §5.5 claim
  that the pruned walk may write the completeness memo: pruning is sound when
  every pruned position is one the reference root's own scoped walk *reached*
  (`Reach R`), because then everything under it was that walk's business, and
  that walk found nothing missing. `Paired` is the pairing `paired_children`
  computes — the reference descended through *held* nodes along the same steps
  — and `paired_reaches` shows it satisfies the premise because a held node is
  never a `Boundary` (`held_not_boundary`): a refusal is remembered by hash
  and position (`redacted_nodes`), a node refused at one position may be held
  from another it shares by structure, and `next_batch` consults the memo only
  on a failed load. An earlier version consulted it before loading, and the
  model then needed an assumption Rust did not enforce; `trie.rs`'s
  `a_held_node_is_never_a_boundary` is the regression. `diff_never_misses` is
  the same fact for the promotion diff, whose `cursor_at` reads an absent hash
  refused at any position as empty and loads a held one.
- `Admit`, `ServeNode`, `ServeValue`, and `Redacts` are the responder. For a
  scoped peer the claimed hash is not consulted (`admit_ignores_claim`), the
  root must be a head root (`admit_requires_head`), what is served is what sits
  at the claimed position (`admit_resolves`, `admit_unique`), and a node
  travels only if what it reveals is in scope. `no_redaction_inside_grant` is
  why a position under a granted prefix is never refused, which is what lets
  the walk consult the redaction memo only above the grant.
- `Learn`/`Reachable` is a delegate's store growing only by what scoped
  responders hand it. `reachable_confined` is the invariant; `held_within_scope`
  is the privacy theorem — every node a delegate holds sits at an admitted
  position of a head root and spells no key material (`Reveals`) and carries no
  record (`RevealsRecord`) outside its scope — with `held_value_within_scope`
  and `redacted_is_boundary` for values and refusals. A branch's *out-of-line*
  value travels as a hash, like every redacted child, and `Reveals` says so;
  `SpellsKey`, used by `keys_below_grant_admitted` for `first_key_outside`,
  counts it as a key because the publish-scope question is about the origin's
  own trie.

The model is positional, and Rust is positional where a hash-keyed shortcut
would not be sound. `MissingWalk::seen` deduplicates expansions by hash inside
the grant — `children_inside_grant_admitted` is why expansion there does not
depend on position — and by hash *and position* above it, where a branch shared
between a spine position and an in-grant position leads into the grant along
one slot at the first and along all of them at the second
(`a_node_at_two_spine_positions_is_visited_at_both` is the regression; an
earlier version keyed by hash alone and could leave an in-grant child
unfetched while reporting nothing missing). Not modelled: batches, `resume`,
the unproductive-round abandonment, the depth ceiling, and the promotion
refusal memo — none of them bears on what the theorems say.

## Provenance

`ScopedSync.held_within_scope` is true and too weak: it says every node a
delegate holds sits at an admitted position of *some* head root, and the graft
of issue #115 satisfies it. A confined origin holds the hash of every subtree
withheld from it, publishes a trie placing that hash at an in-scope position,
and a member that already holds the nodes from the issuer's trie completes the
head and serves the subtree to every delegate under the grafting origin's root.
The positions are admitted; the content was never that origin's.

`Provenance` has several participants (`Sys`), each with the shared node store
and provenance rows (`Store.owned`, the `trie_node_origins` table), and asks
whether a node is **legitimately** a reader's for the scope it reads under.
`Legit` says yes when the reader is rooted, for a node under a rooted origin's
head at an admitted position, for a node an origin authored, and for a node
under a *confined* origin's head at an admitted position provided that origin
legitimately held it. `Sound` is the system invariant: every held node is
legitimate for its holder, and every provenance row for a confined origin names
a node legitimately that origin's.

- `step_sound`: the vouching rule preserves `Sound`. A responder vouches for a
  node under a root only if the root's origin is rooted, or the responder was
  served the node as that origin's, or the responder *is* that origin and
  holds the node (`Vouched`, `net/mpt.rs::Vouch::covers`, applied to every
  peer, scoped or not — a full member handed the node under the grafting root
  would otherwise record provenance for it and move the leak one hop). A member
  records what it was served as the origin's (`learn`, `note_owned`, in the
  batch transaction), and a walk over a confined origin's root reads presence
  through `view` (`MissingWalk::for_origin`, `Trie::load_owned_raw`,
  `is_complete_scoped_for`). `provenance_owner` decides which origins are
  judged this way: every origin that is not rooted, except the node's own.
- **The theorem**, over every state `Reachable` from participants holding
  nothing: `privacy` — a confined participant holds only nodes legitimately
  its; `integrity` — a member that finds a confined origin's root complete
  through `view`, which is the premise on which it promotes, materializes and
  advertises the head, has found only nodes legitimately that origin's.
- The negative forms make the theorem checkable against an attack. `Withheld`
  is content no rooted trie exposes to a scope and no origin of that scope
  authored; `withheld_not_legit` shows a `Legit` derivation can never reach it
  for a confined scope, so `privacy_withheld` (it never reaches a confined
  participant), `withheld_not_served` (nobody serves it under a confined
  origin's root), and `withheld_root_incomplete` (a confined root that reaches
  it never completes) follow for any world, whatever trie it is grafted into.
- `Graft` instantiates them on issue #115 in four nodes: an issuer root over a
  photos leaf and a finance leaf, and a grafter root that is an extension
  placing the finance leaf under the photos slot. `finance_withheld` is the
  only concrete work — the leaf sits under the one rooted head at the finance
  slot alone, and only the issuer authored it — and `finance_not_legit`,
  `new_rule_refuses` and `grafted_root_incomplete` are the general theorems
  applied. Rust's fetch asks the grafter for it, is told `missing`, and
  abandons the head;
  `a_delegate_cannot_launder_a_withheld_subtree_through_its_own_trie` runs the
  whole shape over real endpoints. The rule before vouching — serve any held
  node at an admitted position — is one step from `Graft.before` to a state
  `Sound` rejects; it is gone from Rust and not modelled.

This is the bug class the earlier model could not see: a property that holds
at every single store while content crosses a boundary between stores. What it
costs Rust is one row per node per confined origin, a re-fetch of nodes a
confined origin's trie shares with another's, and a third completeness memo key.
Values are not tracked: `GetValues` serves a value only with a vouched holder,
and a head whose nodes lack provenance never completes, so a value cannot be
laundered without the node that carries it.

## Convergence

`Convergence` proves what "every node ends up with the same head, and derives
the same view from it" decomposes into, and names what it assumes.

- **Head selection is a join.** `adopt` is `offer_head`'s `supersedes(floor)`
  under the lexicographic `(seq, root)` order, `select` the fold of it over the
  heads a node has heard. `select_max` says the result is a maximum,
  `select_eq_of_max` that a maximum is the result, and `select_eq_of_mem_iff`
  — the convergence theorem — that two nodes that have heard the same heads, in
  any order and any multiplicity, hold the same head (`select_perm` is the
  permutation special case; `select_mono` that the floor never moves down).
  `seq_only_diverges` is §5.2's note made concrete: the same fold on `seq`
  alone gives different answers for `[(1,0),(1,1)]` and `[(1,1),(1,0)]`.
- **The view is a function of root and scope.** `HasValue` is `Trie::get`;
  `view_deterministic` says a key has one value under a root, which needs
  `At.split` and the non-empty extension prefix `check_invariants` enforces.
  `ScopedView` — what `materialize_diff` derives under a read scope — is defined
  from the content, the root and the scope alone, so `scoped_view_deterministic`
  is the statement that every node promoting the same head under the same scope
  derives the same view. `admitted_key_readable` says such a node can read it:
  under a root complete within the scope, every admitted key's value-carrying
  node is held, or the key lies under a boundary the walk stopped at.
- **The fetch terminates, and a stuck fetch is complete.** `FetchStep` is one
  learned item — a node, a refusal, or a value — for a position the scoped walk
  is asking about, served by a peer holding the root; each is a `Learn` step.
  `Bounded` is a finite list naming every node and value under the root, and
  `fetch_terminates` says no infinite fetch exists over one: `remaining`, the
  bounded items not yet learned, strictly decreases. `stuck_complete` says a
  store with no fetch step left is `CompleteWithin`, and `stuck_fetch_promotes`
  that this is `MptGc.Promote`'s premise.

What is assumed, as hypotheses: that heads reach every node (the same
membership `select_eq_of_mem_iff` takes as given); that a peer holding the
root's head stays reachable and answers, so a `FetchStep` exists whenever the
responder would serve; that the origin's trie is whole (`Whole`) and finite
(`Bounded`); and, for out-of-line values only, that a held node is admitted at
the position the walk meets it (`hadm`) — a node held from a position where it
revealed less may sit at one where it reveals more, the responder will not
serve its value there, and Rust abandons that head after
`MAX_UNPRODUCTIVE_ROUNDS` and retries once the other fetch has landed the
value. Not proved: that the gossip schedule delivers heads, or how long any of
this takes.

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
