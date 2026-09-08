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
The complete system promises, including mptsync eventual consistency, remain open.

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

These specialize the promises to the actual metadata-sync implementation. They
are targets, not completed theorems.

| Goal | Property to establish |
| --- | --- |
| M1 | Once versions and permissions settle, devices eventually expose and retain the correct permitted views. |
| M2 | Reordering or duplicating the same valid advertisements does not change the selected version. |
| M3 | Delayed replies and obsolete work cannot overwrite or clear newer targets or accepted versions. |
| M4 | A new file list replaces the old one only when ready; version, entries and retention obligations change atomically. |
| M5 | Relays cannot forge changes or widen sharing; received, stored and served data remains tied to legitimate authority. |
| M6 | Faulty or stalling peers/publishers do not permanently starve healthy syncing. |
| M7 | Cancellation and retry preserve valid progress without manufacturing completeness. |
| M8 | Subsequent views use applicable changed permissions; stale work or narrower cached completion cannot authorize a wider view. |

M1 must compose real selection, fetch, promotion and scheduling to obtain the
same latest valid version and its exact permitted entries. Equal grants
imply equal views; equal incomplete views do not suffice. State finite supported
metadata, stable versions/grants, authorized sources, retention, sufficient service
within deadlines and host/crypto contracts. Derive Fetch progress rather than
assuming it; connectivity alone does not imply authority to relay.

Bounded retries need later reannouncement/requeue and a sufficient usable
opportunity. Truncated advertisements can starve later origins. Fair contact
selection alone proves neither condition. Infinite cancellation, permanent
partitions, lost last copies and permanent I/O failure rule out unconditional
convergence.

## Implementation and checked scope

“Production Lean” describes ownership, not complete proof coverage.

| Area | Implemented and checked | Still open |
| --- | --- | --- |
| Trie | Production Lean ingress, lookup/mutation, scan/diff, completeness, collection, Merkle proofs, normalization and scope check. Scoped proofs cover lookup, retained nodes, preserved publication entries/routing and scope-checked entries. | General exact edits/listings/differences, legitimate caller grants, exact completion and atomic promotion. |
| Fetch/serving | Production Lean. Actual rejection/rollback/storage coherence and no transaction across waits; position/response checks and native privacy/cancellation tests. | Productive Fetch progress and end-to-end authority/disclosure. Exhaustion does not prove completeness. |
| CAS | Production Lean local content operations, coverage, retention/repair, durability, collection and projections. Scoped exact-read, unchanged-size transfer/replay, retention and saved-byte advertisement results. | Broader size-change/host failures and cloud/publication/source-hold composition. |
| Cloud | Production Lean cache/range restoration, associated adoption, hydration and outboard caching; native content/recovery/cancellation tests. | Remaining discovery/upload/finalize/read/serve orchestration and composed proofs. |
| Identity/authority | Production Lean origin APIs and whole authority/scope reads, including borrowed promotion transactions and materialized delegation updates. Native expiry, grant, corruption and index tests. | Remaining identity lifecycle policy and grant-to-publication/serving proofs. |
| Replication | Production Lean signed-head acceptance, history/fork retention, pending-fetch lifecycle, promotion and streamed file/provider/delegation views with replica retention. Signature rejection is proved to preserve storage; exchange/contact selection has checked order independence and bounded turns for fixed eligible inputs. Bounded TLA+ recovery checks. | Advertisement observation, recovery/publication orchestration and real scheduling remain Rust. Exact-view/atomic-promotion proofs and M1–M8 composition remain open. |

Reconciliation reads authority, completeness, slot pointers and derived-view policy
in the promotion transaction. Failed materialization rolls it back before retiring
only the judged version. Local metadata type failures remain retryable; structural
and published-record refusals report a process-local memo key. Rust retains raw
storage, cryptography, Unicode NFC checks, peer transport, notifications and memo
storage. The pending-fetch command releases storage sessions across peer waits;
native regressions cover cancellation, retained progress and retry. These are
implementation and integration guarantees, not a complete reconciliation theorem.

Checked reconciliation components include exact-target abandonment, timestamp
updates and post-rollback retirement on arbitrary current rows with successful
storage, and the executed promotion body's no-downgrade guard. When the full acceptance
command returns `pending`, it is proved to install its candidate in committed pending
rows, after history trimming and commit; a matching row exists, and every
matching row has that candidate's sequence and root. Success also requires reading
both complete/pending floors, beating every decoded floor and executing the slot
write. Both reads and the pre-write state retain the initial committed heads table
and the same transaction token: authorization, immutable history recording and slot
decoding cannot change those heads. Any normal refusal (`badSignature`, `unbound`,
or `notNewer`) leaves every committed heads row unchanged after the whole command,
although history retention may change. These acceptance results allow arbitrary
injected host failures, deriving successful writes and commit from command success.
History trimming preserves all staged heads and the transaction token even on failure.
The slot reader's inner join omits orphan pointers. For an initially backed slot
whose selected rows agree on sequence/root (as primary-key uniqueness guarantees),
successful acceptance must strictly exceed that initial complete or pending version.
The proof derives nonempty, pointer-correct reads from raw relational keys; authority
reads preserve the private database and recording signatures retains prior history.
Malformed records may cause failure, never successful absence of a backed floor.
An obsolete advertisement that returns normally preserves every committed heads row.
Composing all failure paths, promotion and suspended-work interleavings remains open
for full M3; corrupt/orphan-pointer recovery is not covered by this slot invariant.

For M4, every execution prefix of the actual materializer preserves the committed
database: its streamed file/provider/delegation and retention writes cannot commit
themselves. The executed promotion finish stage publishes all staged rows together,
or discards them on body failure; commit failure cannot become success, even if
rollback also fails. These cover isolation and the commit boundary, not the whole
promotion theorem. Deriving exact permitted-view readiness from completeness,
proving the diff/materialized view and retention obligations correct, and composing
the entire promotion remain open. Walk exhaustion is not an assumed exact view.

Content histories require faithful metadata storage and a Bao decoder preserving
previously verified bytes even after a partial write fails. Fresh-store/inline
results have distinct initial-state contracts, not arbitrary corruption recovery.

Authorization rejects unknown binding sources and invalid expiry types in narrow
projections, and diagnostics distinguish separate issuers. These tested corrections
are not a completed authorization theorem.

## Publication format and compatibility

Refusal is not authenticated absence. Missing or refused metadata stays outstanding
instead of certifying an empty shared view. Older compressed nodes can place
private data above shared descendants, preventing legitimate scoped completion.

New publications use routing nodes with addressed payloads and child commitments
above permission boundaries, retaining compression inside suitable subtrees. This
permits authenticated absence without revealing private values. Normalization
preserves entries; its routing/serving proof still requires compatible grants.
The actual builder and completion/promotion connection remains open.

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

1. Prove exact edits/listings and permitted-view completion, including justified
   omission and actual Fetch progress.
2. Connect grants/authority to accepted and disclosed data; compose atomic
   view/head/reference publication and permission changes.
3. Connect safe targets/retries and retention to real scheduling; derive mptsync
   consistency under explicit availability and fairness.
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
