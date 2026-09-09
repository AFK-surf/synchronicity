# Lean architecture and system guarantees

This is the canonical architecture and proof-goal guide. Build prerequisites live
in the [verified crate README](../crates/synch-verified/README.md) and
[proof README](../specs/lean/README.md); precise assumptions belong beside the code.

**Design high-level theorems around real properties that matter to users and can
be explained in plain words.** Define observations independently of the algorithm:
“the walk finished” is not a complete file list, and an availability flag is not
readable content. Prove the actual executed operation establishes that meaning.
Not every helper needs a theorem; keep supporting lemmas when a selected guarantee
needs them. Migration, integration, tests and proof completion are distinct.
The mptsync convergence theorem is checked under the explicit stable-run contracts
below; broader P1–P8 coverage and the full authorization goal remain incomplete.

Proof organization must mirror the goal hierarchy in this document: user-facing
P1–P8 goals and their specialized M1–M8 goals, not just implementation modules.
Each goal has a named property and a corresponding top-level theorem expressing
that guarantee, with an explicit link from this document to its proof entry point.
Operation-level theorems and helpers support that entry point. Component proofs,
including a conjunction that merely bundles them, do not by themselves complete
a goal. Mark a goal complete only when its top-level theorem establishes the
stated property for the relevant production executions under explicit assumptions.
Use operation-independent domain invariants or transition relations, not lists of
command-specific violations; prove actual operations refine the common property.
Derive permissions from real reads or captured work, not an assumed safe outcome.
Keep shared domain models outside `Goals`; operation proofs must not depend on
goal modules. `Goals` contains the goal-level properties and top-level theorems.

## Architecture and ownership

Lean owns **whole domain operations**; Rust provides facades and raw services.
Proofs import the same Lean source Cargo compiles and links. A separate model with
similar names does not verify production code.

```text
CLI / RPC / scanner → Lean command and continuation
                              ↕ raw requests / typed replies
                     Rust storage, transport, clock, crypto, Bao, provider
```

Lean chooses reads, policy, writes, transactions and recovery. Do not repeatedly
call scalar Lean policy helpers from Rust orchestration. Inner commands borrow
publication transactions rather than commit independently. Raw indexed queries
preserve stored types and distinguish absence, NULL and empty data.

Delete displaced Rust algorithms across production, fallback and test callers.
Test actual native commands against independent observations, not policy oracles.
Unmigrated operations remain Rust within scope, as do provider SDKs, cryptography,
transport, platform adapters and historical data conversions.

Hostgen derives typed codecs and the storage-only CAS projection entry points
from Lean command and operation types. External Peer/Provider requests,
replies, owned-frame conversions and failure envelopes are generated from
their effect algebras; the runner owns waiting and continuation lifetimes.
Rust shares the command-error wrapper and container codecs. The native runner checks framing, buffer/continuation
ownership and original failures; there is no selectable Rust fallback. Peer/provider
waits hold no database transaction, connection guard or removal-ordering section.
Writer protection may span a wait. Cancellation drops the owned continuation,
aborts pending work and releases resources/private output; committed progress stays.

## User-facing proof goals

A version is a publisher's immutable snapshot; a shared view selects its entries
by permission. Compare fixed versions/grants or state how changes affect the result.

| Goal | Property users should be able to rely on |
| --- | --- |
| P1 | **You read the version you saved.** Whole or partial reads return exactly the corresponding content bytes. |
| P2 | **Changes appear exactly where intended.** Edits preserve unrelated entries; listings and differences faithfully describe the selected snapshots. |
| P3 | **A completed file list omits no shared entries.** Completed metadata sync exposes exactly the permitted view of the selected version. |
| P4 | **Sharing one space does not grant another.** Relays, invented locations and reused references cannot create permission to receive protected data. |
| P5 | **Cleanup respects what must be kept.** Retention needs keep their required backing; discovering loss preserves the responsibility to repair it. |
| P6 | **Interruptions do not become incomplete successes.** Failed reads do not return a prefix as success; retries preserve verified progress for the same content and established size. |
| P7 | **Recovery respects learned history.** Recovered publication follows learned versions, and ordinary acceptance does not move backwards. |
| P8 | **Devices eventually agree after changes settle.** Usable communication and storage lead to the permitted views of the same latest valid versions. |

P3 concerns published metadata, not automatic offline availability of file contents
or a publisher's still-changing live filesystem. P5 permits cache eviction when
retained backing satisfies the storage contract. P7 cannot promise knowledge of
history hidden by a partition. P8 is neither automatic conflict merging nor a
promise to install every intermediate version during ongoing edits.

### mptsync goals

| Goal | Status and proof entry point | User property |
| --- | --- | --- |
| [M1](../specs/lean/Synchronicity/Goals/Mptsync/M1.lean) | Checked: `EventuallyConverges`, `eventual_convergence` | Once versions and permissions settle, covered devices eventually expose and retain the exact permitted views. |
| [M2](../specs/lean/Synchronicity/Goals/Mptsync/M2.lean) | Checked: `OrderDuplicationInvariant`, `order_duplication_invariant` | Reordering or duplicating the same valid advertisements does not change selection or healthy acceptance. |
| [M3](../specs/lean/Synchronicity/Goals/Mptsync/M3.lean) | Checked: `Safety`, `safety` | Delayed replies and obsolete work cannot overwrite or clear newer targets or accepted versions. |
| [M4](../specs/lean/Synchronicity/Goals/Mptsync/M4.lean) | Checked safety and healthy progress: `Safety`/`safety`, `Progress`/`progress` | A file list changes only as one atomic, ready version/view/retention replacement. |
| M5 | **Open as a whole.** Narrow serving, acceptance, scope and admission results exist. | Relays cannot forge changes or widen sharing; every accepted or disclosed item follows legitimate authority. |
| [M6](../specs/lean/Synchronicity/Goals/Mptsync/M6.lean) | Checked for stable finite queues: `BoundedService`, `bounded_service`, `inputs_service` | Earlier failures and stalls do not starve later healthy peer/origin turns. |
| [M7](../specs/lean/Synchronicity/Goals/Mptsync/M7.lean) | Checked under sufficient scheduled responses: `EventuallyReusesCommittedEvidence`, `actual_retries_accumulate_and_reuse` | Cancellation/retry retains committed evidence and cannot manufacture completion. |
| [M8](../specs/lean/Synchronicity/Goals/Mptsync/M8.lean) | Checked invalidation/readiness: `ApplicableChangedPermissions`, `applicable_changed_permissions` | Changed permissions invalidate old conclusions and retain the best target for fresh work. |

**M1 composition.** The shared execution theorem is
[`MptsyncProductionConvergence.StableRun.converges`](../specs/lean/Synchronicity/MptsyncProductionConvergence.lean);
`M1.eventual_convergence` lifts a finite list of participant/origin runs to one
system stabilization point. `StableRun` contains raw scheduler/contact and Hello
acceptance observations, finite requirements, a retry execution, authorized
admissions and a later primitive promotion opportunity. All origins on one device
share one production timeline and stable reconciliation tail; acceptance, retry
and promotion endpoints are tied to that timeline. It assumes no Fetch, Complete
or promotion result, `Ready`, `CorrectView` or tail refinement.

The chain is: M6 selects the latest advertisement and pending origin;
[`MptsyncAdvertisementWindow`](../specs/lean/Synchronicity/MptsyncAdvertisementWindow.lean)
ties its payload to `Reconcile.accept`;
[`ScheduledFetchAdmission`](../specs/lean/Synchronicity/ScheduledFetchAdmission.lean)
ties useful responses to authority-checked `Fetch.admit` bytes and deficit decrease;
M7 preserves committed evidence across retries;
[`TrieCompleteConverse`](../specs/lean/Synchronicity/TrieCompleteConverse.lean)
uses semantic permitted completeness and bounded actual transaction-lifted reads
to prove walk exhaustion and then production completion; M4 installs the
aligned exact view; and
[`ReconciliationViewExecution.stable_tail`](../specs/lean/Synchronicity/ReconciliationViewExecution.lean)
proves later reconciliation preserves it. Scope reset and promotion history derive
the initial view rather than assuming it anew.

This conditional theorem requires stable versions/policies, finite supported
metadata and coverage, retained authorized sources, usable contact windows, and a
scheduled authorized admission while a deficit remains. The host must later supply
one bounded healthy promotion window: successful certification, authority,
materialization and commit. Hashing, signatures, Unicode, SQLite and transport are
contracts. Partition, infinite cancellation, source loss, permanent I/O failure,
continuing publication and external recovery are excluded. M1 neither proves these
availability premises nor completes M5.

**M2 and M3 selection safety.** M2 checks both the production exchange planner
and healthy acceptance chains: order and duplicates preserve the final typed/backed
maximum. M3 makes each finite reconciliation execution keep a head, strictly
advance it, or consume exactly captured pending work. Complete cannot regress or
disappear. Credentials come from actual captured work or fresh promotion reads;
failures and obsolete acceptance preserve heads and other rows. Backing history,
unique keys, typed reads and exclusive transactions are storage contracts. M3 has
no fairness assumption.

**M4 atomic publication.** Every primitive prefix of received-version promotion
exposes the old view or one ready replacement whose installed version, exact
permitted files and current/forever retention obligations agree. The progress
theorem derives the flipped report and `CorrectView` from preparation,
completeness, authority, writes, materialization and commit. Initial view/schema,
faithful finite snapshots, canonical keys, replica policy, Unicode and SQLite are
contracts; download completion and provider grace deadlines are not claimed.

**M6 scheduling.** Production Lean owns peer and weighted-origin planning; Rust
persists per-peer advertisement cursors and pending-origin cursors only after an
attempt. Complete and pending summaries for one origin stay in one bounded group.
With stable finite inputs and enough rounds, each healthy peer, later page and
pending target gets a bounded turn despite earlier failure or timeout. Actual
contact and wire observations are consumed; connectivity supplies neither
authority nor a promised response.

**M7 retry progress.** Actual admitted responses and cancellation/resumption or
fresh-restart checkpoints form the retry execution. Cancellation at a peer wait
holds no transaction and preserves committed evidence.
`ScheduledSufficientResponses` is the liveness seam: for every still-positive
deficit, a strictly later M6-linked attempt must carry an authorized,
target-aligned response whose `Fetch.admit` commits evidence. A retry-limit exit
can supply that attempt only through actual outer requeue and reselection. These
facts derive the abstract productive-admission condition. A later finite
completion opportunity reuses accumulated evidence. Infinite cancellation is
excluded.

**M8 permission changes.** The production `ScopeChange` command reads the actual
old scope and typed heads, atomically clears old complete and derived state, and
retains the greatest signed target as one refreshed pending row. Malformed data or
host/commit failure is atomic. Enlargement, narrowing, expiry and revocation cannot
reuse old completion/refusal credentials or suspended work. A stable opportunity
restores current-scope readiness; M7/M1 and M4 supply Fetch and materialization.
[`ScopeChangePromotionBaseline`](../specs/lean/Synchronicity/ScopeChangePromotionBaseline.lean)
derives an empty baseline from cleanup plus schema/snapshot/policy contracts.

**M5 remains open.** Checked components validate signatures and origin bindings,
read serving authority in production transactions, constrain scoped responses by
position/provenance, and require authority evidence for admission. No top theorem
yet covers every identity lifecycle, relay, disclosure, publication and recovery.

## Implementation and checked scope

“Production Lean” describes ownership, not complete proof coverage.

| Area | Implemented and checked | Still open |
| --- | --- | --- |
| Trie | Production Lean ingress, lookup/mutation, scan/diff, completeness, collection, Merkle proofs, normalization and scope check. Proofs cover scoped lookup, retention, routing, entries and exact diff streams. | General exact edits/listings, legitimate caller grants and exact completion. |
| Fetch/serving | Production Lean. Actual rejection/rollback/storage coherence and no transaction across waits; position/response checks; scheduled authorized admissions strictly reduce finite deficits; retry checkpoints retain evidence. | Availability of sufficient responses remains an M1/M7 premise; full end-to-end authority/disclosure is M5. Exhaustion alone does not prove completeness. |
| CAS | Production Lean content operations, coverage, retention/repair, durability, collection and projections. Scoped exact-read, transfer/replay, retention and advertisement results. | Broader size-change/host failures and cloud/publication/source-hold composition. |
| Cloud | Production Lean cache/range restoration, associated adoption, hydration and outboard caching; native content/recovery/cancellation tests. | Remaining discovery/upload/finalize/read/serve orchestration and composed proofs. |
| Identity/authority | Production Lean origin APIs and whole authority/scope reads, including scope-change invalidation, borrowed promotion transactions and materialized delegation updates. Native expiry, grant, corruption and index tests. | M5: the remaining identity lifecycle and grant-to-all-publication/serving/recovery composition. |
| Replication | Production Lean acceptance, history/fork retention, pending-fetch lifecycle, promotion, scope change and streamed views. M1–M4 and M6–M8 have the conditional top-level results described above; contact/origin planners have bounded-turn proofs. | M5 overall; availability premises, recovery/local-publication orchestration and unconditional progress. Bounded TLA+ recovery is separate from M1. |

Promotion reads authority, completeness, heads and policy in one transaction;
failed materialization rolls back. Rust retains storage, crypto/NFC, transport,
notifications, memos and scheduler execution/cursors; Lean owns decisions. Fetch
holds no storage session across peer waits. SQLite/concurrent refinement is a host
contract; orphan-pointer recovery is outside the stable-run contract.

Content histories require faithful metadata storage and a Bao decoder preserving
previously verified bytes even after a partial write fails. Fresh-store/inline
results have distinct initial-state contracts, not arbitrary corruption recovery.

Authorization rejects unknown binding sources and invalid expiry types, and
diagnostics distinguish issuers. These results still do not complete M5.

## Publication format and compatibility

Refusal is not authenticated absence. Missing or refused metadata stays outstanding
instead of certifying an empty shared view. Older compressed nodes can place
private data above shared descendants, preventing legitimate scoped completion.

New publications use routing nodes with addressed payloads and child commitments
above permission boundaries, retaining compression inside suitable subtrees. This
permits authenticated absence without revealing private values. Normalization
preserves entries; its routing/serving proof still requires compatible grants.
The stable-run theorem covers completion/promotion; legacy republishing and the
actual builder path remain outside it.

**Protocol version 4 requires communicating peers to upgrade together.** Hello
rejects older peers. Old signed roots remain readable and cannot be rewritten by
relays; restricted legacy views lacking absence evidence remain incomplete.
Publishers republish preserved entries under a later signature through the normal
publication/recovery path without requiring a file edit. Eventual consistency
must include that upgrade path.

Native Lean is mandatory, including public origin APIs: Linux GNU, macOS
x86-64/arm64 and Windows gnullvm use the pinned runtime and checked ABI. OpenBSD
and control-plane protocols are outside this migration. Generated Rust glue
belongs in Cargo's output directory.

## Trust boundary and limits

Proofs share raw database/file/resource semantics, including read-your-writes and
rollback. Do not substitute operation-specific policy answers or assume the desired
postcondition as an initial invariant.

SQLite isolation, filesystems, provider acknowledgements, BLAKE3, Ed25519, Unicode NFC, the
**whole Bao service**, Rust interpreters, native transport and Lean compiler/runtime
are trusted contracts. Hash-sensitive results assume collision-freedom on relevant
data, not global injectivity. Provider acknowledgements must represent real backing;
only authoritative absence justifies withdrawing its availability claim.

Native/concurrent refinement and power-loss durability remain tested host contracts,
not extra universal proof requirements. The model does not verify all SQLite or
filesystem behavior. Keep fault, compatibility, concurrency and resource tests.

Privacy retains [DESIGN.md](../DESIGN.md)'s intentional delegation/index disclosures.
It does not erase received information, hide all space existence/traffic patterns
or prevent authorized publishers from redistributing known data.

## Deferred proof path

1. Prove exact edits/listings and permitted-view completion beyond the stable-run
   path, including justified omission.
2. Complete M5 by connecting grants and identity lifecycle to every accepted,
   disclosed, published and recovered item.
3. Discharge more M1 availability/host contracts through real orchestration.
4. Extend content results through cloud and retention/publication paths.

Migrate only whole operations needed for those properties. Diagnostics, exact
traces, LRU behavior and cost can remain tests. Do not require universal proofs
of every helper, root uniqueness or removal of all garbage, or weaken a user
property to make its proof convenient.

## Validation and completion gates

Distinguish universal theorems, native regressions and bounded models. Recovery
checks require learned history before post-loss publication; the partitioned model
exposes a no-fork limitation, not mptsync convergence.

```sh
# From specs/lean
lake build --wfail

# From crates/synch-verified/lean
lake env lean --run Hostgen.lean --check

# From the repository root
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Recheck accepted proofs with the standalone kernel and audit axioms using the CI
procedure. Reject `sorryAx` and native-evaluation shortcuts. Run relevant adversarial,
cancellation, cloud/emulator and recovery checks, shipped feature configurations
and supported platform CI. Local success alone is not cross-platform readiness.
