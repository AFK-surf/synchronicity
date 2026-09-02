# specs — model-checked corners of the design

TLA+ models and Lean proofs for mechanisms whose correctness rests on
interleavings rather than on any single code path. The Rust test suite samples
those interleavings; TLC explores bounded state spaces and Lean proves
inductive invariants. A spec here verifies the *algorithm* the design document
states, not the Rust compiler output; checked anchors keep the model and its
implementation linearization points reviewably aligned.

## Running

TLC needs a JRE (11+) and [tla2tools.jar](https://github.com/tlaplus/tlaplus/releases)
(CI pins v1.7.4 by checksum):

```sh
java -jar tla2tools.jar -config specs/RecoveryCI.cfg -workers auto -deadlock specs/Recovery.tla
```

`-deadlock` disables deadlock reporting: these models have terminal states
by design (all bounds exhausted), which are not errors.

## Recovery.tla — key-loss recovery (§3.4)

A node that loses its key and database keeps its origin name but nothing
durable. Peers still hold heads signed by the lost key. The spec models
the publish/replicate/observe/recover/crash loop and checks that the
publishing-floor mechanism keeps the recovered node's new heads from ever
colliding with history its peers hold.

| Property | Claim | Sampled by |
|---|---|---|
| `NoObservableFork` | No peer ever verifies two same-seq heads with different roots from this origin's keys | `equivocation_is_detected_with_both_proofs`, `same_seq_forks_are_both_retained_as_evidence` |
| `FloorMonotone` | The publishing floor never lowers within one database's lifetime | `the_publishing_floor_only_rises` |
| `SlotMonotone` | A peer's complete slot only advances in the §4.4 `(seq, root)` order | `older_heads_are_ignored`, `the_seq_root_rule_accepts_equal_seq_greater_root` |
| `HeadMonotone` | The node's own head only advances within an incarnation | `next_seq` contract in `node.rs` |

Three configurations:

- **`RecoveryCI.cfg`** — the connected cluster at CI bounds (`MAX_SEQ = 3`,
  2 peers, 2 roots, 2 crashes; ~2.5 M states, ~20 s). Everything must hold.
- **`Recovery.cfg`** — the same model one seq deeper (~55 M states, ~3 min).
  Run locally after touching the recovery logic.
- **`RecoveryPartitioned.cfg`** — drops the connected-cluster assumption:
  the quiesce may elapse without reaching the peer holding the newest
  pre-loss history, and a publish may precede any summary. Here
  `NoObservableFork` **must fail**, and TLC's 6-state counterexample is
  precisely the fork §3.4 documents and accepts ("recovery is not a global
  no-fork property"). CI runs this config expecting the violation, so the
  admitted limitation stays pinned exactly where the design says it is.

The connected-cluster assumption (`PARTITIONED = FALSE`) states as a guard
what continuous `Hello` exchanges deliver in the running system: every
live peer's summary reaches the node before a post-loss publish, and the
recovery quiesce reaches every peer. That assumption — not the gap, not
the timer — is what carries the guarantee; the partitioned config is the
proof.

## Lean — CAS / mptsync / ingest safety

[`lean/`](lean/) contains unbounded inductive proofs at five resolutions: the
small per-root protocol, a root/holder-indexed system model whose live relations
are the content leaves materialized from active tries, a graph model of trie
mark/sweep, a fault-tolerant re-proof of the system model with the durable
backend allowed to lose what it acknowledged, and a positional model of mptsync
over partial tries — the scoped fetch walk a delegate runs, its pruning against
a reference root, the responder's authorization by position, and the privacy
theorem that a delegate holds nothing that spells a key outside its scope
(`ScopedSync`), together with the three pieces convergence decomposes into —
head selection is an order-independent join, the derived view is a function of
root and scope, and a fetch terminates and is complete when it can take no
further step — under stated delivery and finiteness assumptions
(`Convergence`); and a multi-party model of provenance across the delegation
boundary, whose `privacy` and `integrity` theorems hold in every reachable
state, with the graft of #115 as the witness that they exclude it
(`Provenance`). The system theorem says every
live source leaf names available content and every live replica leaf names
either pinned available content or a want for that same holder and root. It
covers protection removal as well as acquisition, protected explicit deletion,
writer abort, cache eviction, the unprotected removal of staged (non-durable)
rows, and the two GC phases. Under backend loss, the surviving theorem is that
a role's pin stands on content that is available or that the backend lost and
the heal has not yet converted into a want. Rust and Lean carry matching checked
anchors at their linearization points; run `lean/check-anchors.sh` after
changing either side.

```sh
cd specs/lean
lake build --wfail
./check-anchors.sh
```

## What Recovery.tla deliberately does not model

Signatures (perfect by assumption; only the origin's key signs its
heads), trie contents and fetch (a head stands atomically for its trie —
pending-head promotion has interleavings of its own and belongs in a
separate spec), and wall-clock time (the adversarial schedule already
contains every early-timer interleaving). The Lean model now covers pending
promotion and GC at the root/content level, `TrieGraph` covers the retained
node reachability obligation, and `ScopedSync` covers the fetch walk itself —
which positions it asks for, when its "complete within scope" answer may be
believed after pruning, and what a scoped peer is served. SQLite, filesystem, and Rust operational
semantics remain trusted behind the named linearization points; the anchor
checker is traceability, not a compiler-to-Lean refinement proof.
