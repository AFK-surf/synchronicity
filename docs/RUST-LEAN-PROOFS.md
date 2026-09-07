# Rust/Lean architecture and system proof goals

This is the canonical architecture, proof contract, evidence map and delivery
plan for PR #134, revised 2026-09-07. It supersedes the separate architecture,
simulated-host, Trie/CAS migration, CAS promises, system promises, mptsync goals
and proof-audit documents. Historical implementation checkpoints are not current
requirements. The build READMEs contain commands and point here for guarantees.

**Design high-level theorems around real system properties that matter to users
and can be explained to them in plain words.** Define what a user observes
independently of how the algorithm works, then connect the executed operations
to that meaning. A theorem about a finished walk, a selected maximum or an
availability flag is useful only when it helps establish the promised system
behavior. Not every helper, internal trace or migrated operation needs a theorem.

The tables below are targets and scoped evidence, not a claim that every promise
is proved. Migration, native integration and proof completion are separate
statuses. In particular, eventual consistency of the actual mptsync implementation
is required; a detached protocol model cannot discharge that goal.

- [User promises and theorem design](#the-promises-in-user-terms)
- [mptsync safety and eventual consistency](#mptsync-safety-and-eventual-consistency)
- [Architecture and ownership](#architecture-and-ownership)
- [Current migration status](#current-migration-status)
- [Path to all proof goals](#path-to-all-proof-goals)
- [Checked CAS promise scopes](#checked-cas-promise-scopes)
- [Shared host semantics and trust boundary](#shared-host-semantics-and-trust-boundary)
- [Repository-wide proof audit](#repository-wide-proof-audit)
- [Validation and completion gates](#validation-and-completion-gates)

## The promises, in user terms

| | Promise | What it means |
| --- | --- | --- |
| P1 | You read the version you saved. | A successful read returns exactly the requested content. Reading part of it returns that part of the same version. |
| P2 | Your changes appear exactly where intended. | Updating or removing an entry changes that entry and preserves unrelated entries. Listings and reported changes faithfully describe the selected version. |
| P3 | An up-to-date file list does not silently omit shared files. | For a particular publisher's version and your sharing permissions, a completed metadata sync contains every entry you are entitled to see, with the right contents. |
| P4 | Sharing one space does not grant access to another. | Asking through another peer, lying about a location, or reusing a reference to hidden content cannot create a new permission to receive it. |
| P5 | Automatic cleanup respects what you need to keep. | Cleanup preserves content needed by current files or retention settings. Discovering a lost copy preserves the outstanding responsibility to restore it. |
| P6 | Interrupted transfers do not become successful but incomplete results. | Failed reads do not return a prefix as a successful answer. Retrying or receiving duplicate data for the same version preserves previously verified progress. |
| P7 | Recovery continues after the history learned from peers. | A recovered device publishes after the versions it has learned about; peers do not silently move their accepted version backwards. |
| P8 | Devices eventually agree after changes settle. | With stable published versions and permissions, continuing retries and usable communication/storage, devices eventually expose the corresponding permitted views of the same latest valid versions. |

P3 concerns the file list and other shared metadata. It does **not** say all
file contents have been downloaded, are available offline, or match a
publisher's still-changing live filesystem. P5 permits discarding a disposable
cache copy when a retained backing copy satisfies the storage contract.
P6 permits useful progress to survive a failed operation; failure does not
promise that nothing changed. P7 does not promise knowledge of history hidden
behind a network partition.

## Design the theorem around the observation

Use a small vocabulary with meanings independent of the algorithms:

- A **version** identifies one publisher's immutable published snapshot.
- Its **entries** say which paths exist and what each path refers to.
- A **shared view** selects the entries permitted by the applicable grants.
- **Content** is an immutable byte sequence; **readable portions** are the
  portions a successful read can actually return.
- **Retention needs** describe which content must be kept, and **repair
  responsibilities** describe outstanding restoration work.

The proof package must relate these observations to the actual executed
commands and their resulting state. They cannot be arbitrary predicates
assumed to hold. In particular, do not define a complete shared view as
"the walk finished", readable content as "the availability flag is set", or
authorized disclosure as "the serving predicate returned true".

The proposed theorem statements are:

| Promise | Statement to establish across the relevant operations |
| --- | --- |
| P1 | For any supported content and valid starting state, successful storage establishes the content/version relation used by subsequent reads. A successful full or ranged read returns exactly the specified bytes. Extend the existing fresh-store result to existing content and the receive/cloud paths that users actually use. |
| P2 | The meaning of a successful update is the old snapshot with exactly that entry replaced; removal deletes exactly that entry. A listing is exactly the requested page of that snapshot, and a change listing is exactly its difference from the other snapshot. Apply the changes and obtain the new view. |
| P3 | A successful completeness result establishes that all entries in the independently defined shared view are readable. Promotion/materialization then exposes exactly that view. Missing data cannot be converted into authoritative absence. A cached result must preserve this statement after permitted intervening changes. |
| P4 | In any admitted sequence of requests, every newly disclosed protected record or content value is justified by the receiver's grants and the publisher's authority to provide it. Connect the bytes actually sent to that authorized content, including relaying and reuse of shared content. A claimed location alone is never evidence. |
| P5 | Across automatic collection, eviction and the relevant publication/retention transitions, protected content keeps the backing required by its retention needs. If an external loss is discovered, healing preserves the corresponding repair responsibility until it is fulfilled or explicitly withdrawn. |
| P6 | At the operation's publication boundary, an error cannot publish an incomplete or invalid result as success. Across verified receive, retry and read, readable portions of the same content with the same established size are preserved, and duplicates/order do not change the resulting readable content. |
| P7 | Recovery and subsequent publication respect all recovered observations; ordinary acceptance never replaces an accepted version with an earlier one. Keep the bounded connected/partitioned model checks and their explicit limitation. A general no-fork theorem is not claimed; mptsync convergence is the separate P8 obligation. |
| P8 | Prove eventual consistency of the actual mptsync implementation under explicit quiescence, availability, authority and fair-service assumptions. Establish eventual accepted-version and exact-view agreement, including real selection, fetch, promotion and scheduling. The detailed safety and liveness goals are in [this document](#mptsync-safety-and-eventual-consistency). |

These statements hide storage encodings, traversal stacks, SQL columns and
memo tickets from users. Such details may appear in supporting lemmas when
needed to connect the statement to the executable implementation.

For P2/P3, compare a fixed version and fixed grants, or state explicitly how
a change of either affects the observation. Two devices holding the same
accepted version under the same grants should expose the same shared view;
exact-view results establish agreement once those versions are installed.
P8 additionally requires a proof that the real protocol eventually gets
there. No automatic conflict-merging guarantee is implied.

## An important unresolved meaning of completion

The current `TrieCompleteProofs` establish the completion check's execution
and generation discipline. They do not establish P3. The earlier command
accepted a root refusal as a complete empty view without the root's bytes.
The requesting walk now keeps that node outstanding; scans fail on missing
referenced nodes even when refused. `a_refused_root_does_not_certify_an_empty_view`
and `refusals_cannot_satisfy_missing_positions`, plus a native regression with
an actually published shared entry, check this correction.

A refusal to provide something is not, by itself, evidence that no shared
entry lies behind it. Before proving P3, establish what authentic evidence
makes an omitted portion irrelevant to the shared view. If the protocol
cannot provide that evidence, change the behavior or the completion status.
Do not assume "all refusals are safe" merely to make the desired theorem
provable. Also examine whether valid metadata layouts can place private
data above shared descendants: privacy and complete disclosure must be
compatible for the snapshots the product accepts. This is a real schema issue:
valid keys such as `r:photos` and `r:photos-raw` can put a private inline branch
value above an authorized descendant. The current whole-node hash prevents
revealing only the safe part of that branch with an ordinary hash check.
Refusing false completion is an intermediate safety correction, not the final
scoped-sync behavior or closure of eventual consistency. Legitimate private
omissions still need authenticated proof or a representation/protocol change;
do not weaken the existing successful-sharing requirements to hide this gap.

### Routing publications and older signed versions

The new publication form uses explicit routing nodes above authorization
boundaries, retaining compression inside a shared subtree. A routing node
reveals one level of child commitments and has only an optional addressed
payload. Unary and terminal routing nodes are valid: a private exact key can
therefore prove that it has no granted descendants without revealing its value.
An absent child provides authenticated nonmembership; an unprovided child does
not. Small out-of-line payloads are valid for routing nodes. The requesting
walk checks held value sizes too, so storing a small routing payload under an
address cannot legitimize a malformed legacy reference to the same address.

`Trie.Normalize.publication` executes normalization with an explicit work stack.
Its boundary rule depends on the metadata schema, not currently installed
grants. It preserves compressed `d:` and `b:` subtrees and file subtrees below
`f:<space>/`; exact-key and otherwise unresolved spines remain routed. The Rust
publisher calls this command in its publication transaction before signing and
final materialization. Native tests cover exact entries, old-root preservation,
idempotence, route edits, empty roots and the deepest supported exact key. The
previously failing empty permitted-view integration fixture now passes with
routing publications and unchanged privacy/progress assertions. These tests do
not replace the required normalization, serving/completion and promotion proofs.
`TrieNormalizeProofs` now proves exact entry preservation for the actual
assembly, compressed leaf-edge and finishing steps. The remaining visit cases
and iteration composition are still required before claiming that the whole
normalization operation preserves a published snapshot.

Protocol version **4** requires peers to understand the new node form. Upgrade
communicating peers together; the Hello version check rejects an older peer
before unsupported node bytes could be misclassified as an invalid publisher.
Old signed roots and their bytes remain readable; relays cannot alter them.
A legacy restricted view that lacks authentic absence evidence stays incomplete.

The publisher upgrade path uses the ordinary publication transaction and
sequence/recovery checks to republish preserved entries under a later signature,
without waiting for a file edit. Anti-entropy retries a deferred upgrade while
continuing unrelated syncing. The convergence proof must include that actual
path; it may not silently assume away accepted older roots. Remaining acceptance
work is exact normalization semantics, routing coverage for every supported
scope, atomic retention/publication, the formal upgrade/recovery composition, and cost measurements on the existing large corpus.

A signed refusal alone does not prove consistency with the signed snapshot.
Plain hashes of space names are also insufficient to hide guessable private
names. Neither is a substitute for authenticated structural absence.

Likewise, `TrieServePrivacyProofs` checks the implemented per-position scope
rules across an answer. That is useful support for P4, but is not a complete
access-control theorem: grant validity, actual source/position linkage,
publisher authority and provenance through relays must still be connected.

## Explicit assumptions and limits

The core proofs may assume faithful storage primitives, transaction
isolation/abort, cryptographic verification and hashing, Bao verification,
provider acknowledgements, and the compiler/runtime/host boundary described
in the architecture. An acknowledged backing copy must correspond to actual
content under the provider contract; a database claim alone is insufficient.
Initial representation invariants must be established by earlier operations
or identified as import/recovery assumptions, not assumed as the desired
postcondition of the operation being proved.

External corruption, deletion of the last backing copy, permanent network
partitions and permanent I/O failure prevent unconditional availability or
eventual recovery. These are not excluded from discussion: state how the
system reports them and preserves obligations, and test the relevant failure
paths. Physical crash durability and native/concurrent refinement remain
tested host contracts, not additional proof requirements for this PR.

For P4, state the intentional disclosures from DESIGN.md §5.5, including
global delegation records and the limited structure revealed by the index.
Do not promise that every other space's existence is hidden, that a peer
forgets content it already received, or that an authorized publisher cannot
redistribute information it already knows. Timing and traffic-analysis
noninterference are not claimed.

## What deserves a proof, and what can remain a test

Keep a theorem when it establishes a selected promise, connects actual
operations to it, or supplies a necessary reusable argument. Small algebraic
lemmas can be essential; an unused theorem can also be an important final
result. Declaration use counts are evidence for review, not a deletion rule.

Use regression tests or bounded model checks for compatibility details,
diagnostic precedence, exact SQL/request sequences, allocation strategies,
LRU ordering and timing. Keep adversarial and fault-injection examples when
they catch real integrity, privacy, retention or resource-lifetime mistakes.
Their being written in Lean does not make them universal system theorems.
Prove ordering such as publication after verification when it is necessary
for a promise; avoid proving every incidental event before every other one.

Do not require proofs that collection removes *all* garbage, that every map
has a unique encoding/root, that every projection has a universal decoder
theorem, or that every migrated function has an exact trace theorem. Add one
only when a selected guarantee actually depends on it. Do not retain a
parallel policy implementation just to prove facts about that copy.

## mptsync safety and eventual consistency

mptsync synchronizes published metadata. Converging file lists does not mean
every device has downloaded all file contents, nor that a published snapshot
equals a publisher's live filesystem before its next scan.

### Protocol promises

| | Promise | What the theorem must establish |
| --- | --- | --- |
| M1 | Devices eventually agree after changes settle. | Once publishing and permissions stabilize and the required communication/storage opportunities persist, each participating device eventually exposes the permitted view of the same latest valid version for each healthy publisher, and keeps that view while those conditions remain stable. |
| M2 | Arrival order does not decide which version wins. | Devices considering the same valid published versions choose the same winner despite message reordering, duplicates or different peers. Different permissions produce the corresponding different views of that winner, not arbitrary disagreement. |
| M3 | Old sync work cannot undo a newer version. | Accepted versions do not move backwards during a database lifetime. A delayed reply, failed fetch or abandoned old target cannot overwrite or clear a newer target or replace a newer accepted view. Explicit restore/recovery and permission changes have separately stated semantics. |
| M4 | A new file list replaces the old one only when it is ready. | While a target is incomplete or invalid, the previous accepted view remains usable. A successful promotion changes the accepted version, its exact permitted entries and their retention obligations together; a failed promotion does not expose a mixed view. Recorded refusals require justified omission, not blind acceptance as absence. |
| M5 | A relay cannot forge a publisher's changes or widen sharing. | Accepted metadata belongs to a valid published version from an authorized publisher. Bytes received, actually stored, and later served are tied to that version and the receiver's permissions. Invented locations, roots, repeated entries and reuse of another publisher's hidden content create no authority. |
| M6 | A faulty publisher or peer does not permanently stall healthy syncing. | Refusing one publisher's invalid data preserves unrelated accepted views. A stalling or unproductive peer eventually releases its attempt, and eligible healthy publishers/providers continue to receive service. A transport failure may end one exchange; healthy progress must still be established across later exchanges. |
| M7 | Interrupting and retrying sync is safe. | Verified metadata already committed remains valid and reusable. Missing work remains outstanding; retries, duplicates and reordering cannot manufacture completeness, corrupt the accepted view or count unverified data as progress. A later successful opportunity can resume progress without depending on the cancelled attempt finishing. |
| M8 | Sharing changes apply to subsequent synchronized views. | After a permission change takes effect locally, later publication of a view uses the new permissions. A previous narrower completion result cannot satisfy a wider view, and stale work cannot publish an obsolete permission decision. Serving is authorized at its specified decision point. This does not promise erasure of information already received or instantaneous cluster-wide revocation. |

These are related rather than eight isolated proof projects. In particular,
M2–M5 and M7 supply safety properties needed for M1; M6 supplies progress in
the presence of unrelated faults. M8 explains how to restart the argument
when permissions change.

### Eventual-consistency theorem

State the principal theorem over executions of the actual protocol and the
user-visible metadata view, not just over a maximum function or a missing-node
walk. For each publisher, let the selected version be the greatest admissible
published version under the product's deterministic version order. The formal
order is currently `(seq, root)`, not wall-clock time. Define the permitted
view independently as that version's published entries filtered by grants.

The desired statement is:

> For every participating device and healthy publisher, after the system
> settles under the conditions below, there is a later point from which that
> device's accepted version is the selected version and its visible metadata
> is exactly the view permitted to it.

For a fixed finite group this also yields a common later point after which
all relevant devices agree. Equal grants imply equal views; different grants
imply the appropriate projections. Agreement on an empty or partial view
that omits shared entries does not satisfy the theorem.

Make the environmental conditions explicit:

1. After some point, the publishers being considered stop changing their
   versions, relevant grants and bindings stabilize, and participating
   devices stay running with their databases. Published metadata is finite,
   supported by this build and within its documented limits. Validity must
   be defined independently of "fetch succeeds".
2. At least one usable copy of each required piece of metadata remains
   available. Devices are connected by paths on which the protocol can
   actually advertise and serve it with the required authority. Mere network
   connectivity is insufficient when an intermediate peer may not serve an
   origin's metadata. Retention/GC must not repeatedly destroy the needed
   source or pending-target state.
3. Anti-entropy continues. Eligible peers and origins are not permanently
   starved, and required requests, batch commits and promotion attempts
   eventually receive enough service to finish within the applicable
   deadlines. Permanent I/O errors, infinite resets and permanently
   inadequate attempt budgets are excluded; there is no universal completion
   time bound.
4. The stated signature, hash, storage, transaction and host-execution
   contracts hold. Summaries, claimed locations and peer refusals are not
   trusted as proofs of content or of authorized absence.

Periodic contact selection now runs the whole Lean `Replication.Contact.plan`
operation. It orders distinct eligible peer identifiers and selects the next
bounded batch after the last completed cursor. The engine serializes periodic
rounds, attempts every selected peer even after progress, and advances the
in-memory cursor only when the batch finishes. Cancellation does not spend the
unattempted turns. Clock jitter controls the interval, not peer selection.

The required contact theorem is: once eligibility stabilizes, every eligible
peer gets an attempt within `ceil(peer count / batch size)` completed rounds,
independently of query ordering or other peers' failures. Native tests cover
that behavior; the formal bounded-turn theorem and its connection to actual
eligibility and completed attempts remain open. Continued completed rounds are
an explicit runtime condition; infinitely cancelled rounds or repeated process
restarts do not establish progress. This does not yet prove eventual consistency.

There is also an advertisement bound: `local_summaries` truncates sorted origins
at `MAX_HEADS_PER_MESSAGE`. Bounding active membership is insufficient if retained
advertised origins exceed that limit. Either state the bound on all relevant
retained origins and prove it is maintained, or add pagination/fair rotation so
later origins cannot be permanently omitted. Do not hide this starvation case
inside a premise that each target is eventually discovered.

Continuing publication is a separate extension. Do not claim that every
intermediate version is installed: superseding a pending target is legitimate.
Nor does quiescent convergence imply a bounded lag while publishers keep
changing faster than receivers can process them.

### Implementation connection

The relevant paths include:

- `synch-core` signed-head ordering and identity/record contracts;
- `synch-engine/src/reconcile.rs`: offers, summaries, scope adoption,
  `sync_with`, pending fetches, refusals, target-specific cleanup and promotion;
- `synch-engine/src/aae.rs`: periodic/reactive scheduling, contact rotation,
  attempt budgets, maintenance and retries;
- `synch-net` authentication and mpt request/reply handling;
- the executable Trie admission, requesting walk, completeness, serving,
  diff/materialization and collection operations;
- `synch-store` heads/history, provenance, permission invalidation, reference
  retention and the transaction that publishes a derived view.

The theorem must compose these actual decisions. Where protocol policy
remains Rust, migrate the relevant whole operations into the executable Lean
core or establish an adequate checked connection to those executions. A new
detached protocol model with matching-looking names, prose anchors, tests
alone, or an assumption that the real reconciliation/promotion already
converges does not prove M1 for the implementation. Raw transport, clocks,
raw scheduling inputs and storage remain explicit host contracts; this does not require
proving the networking stack or compiler.

A useful decomposition is:

1. **Select and retain:** actual acceptance/advertisement chooses the same
   eligible winner and retains enough target/source state for work to continue.
2. **Fetch justified information:** each accepted batch adds valid, necessary
   metadata or evidence that genuinely justifies omission. Under stable
   inputs, a finite measure of unresolved work decreases on productive steps;
   duplicate packets and unsupported refusals cannot fake that decrease.
3. **Promote faithfully:** completed work establishes the exact shared view,
   and the atomic promotion preserves M3/M4. This includes the completion
   and redaction gap identified in this document.
4. **Supply progress:** the real scheduling and timeout paths keep enabling
   those steps, despite unrelated faulty peers/origins. Derive eventual
   adoption and then stable equality of the views.

Do not assume a whole fetch eventually completes as a premise of the
convergence proof. Derive it from finite supported metadata, justified
progress, retention and the service/scheduling conditions above.

### Existing evidence and priorities

The current scope, lookup, ingress, generation, retry and history-retention
lemmas are useful ingredients. Native tests cover forged signatures,
unrequested/repeated payloads, retained same-sequence forks, failed
materialization, pending-head races, provenance grafting, timeouts and
anti-entropy behavior. The recovery TLA+ model is valuable for P7 but does
not model this complete mptsync pipeline or establish M1.

The first blocking semantic issue is M4/P3: authenticated omission. The
requesting walk now keeps refused nodes outstanding, and scans report missing
nodes instead of silently hiding them. This corrects false success but does
not yet allow legitimate private omissions to complete. Resolve what makes an
omission justified before proving convergence to the resulting view. Then
connect M2/M3/M5 to the executed offer/fetch/promote chain, and prove progress
through the real scheduler. Preserve the existing fault and concurrency
regressions while doing so.

Exact SQL statement order, exact retry counts, cache hit rates and precise
wall-clock latency need not each become universal theorems. They may remain
tests and measurements unless a selected safety or liveness argument depends
on them. The proof obligations above, including eventual consistency, remain
open until the implementation and the composed evidence establish them.

## Architecture and ownership

Lean implements complete domain operations; Rust provides raw host services and
public facades. Proofs import the same executable Lean sources that Cargo compiles
and links. The production rule is **whole Lean operation or pure Rust**. Do not
retain Rust orchestration that repeatedly calls fine-grained Lean policy helpers.
A separate model with a matching Rust comment or source anchor is not verification
of that implementation.

Delete displaced Rust implementations, including algorithms retained only as
test oracles. Preserve meaningful regression and cost coverage by exercising
the actual native Lean command with controlled raw storage, transport and
failure inputs. A second policy algorithm is not a host service. Cryptographic
and Bao primitives, provider SDKs, serialization schemas and historical data
migrations remain Rust where they implement the stated trust boundary rather
than duplicate a migrated domain operation.

```text
CLI / RPC / scanner event
          |
Lean domain command and Program continuation
          | host request / typed reply
Rust interpreter: database, files, network, clock, crypto, Bao, provider
```

| Domain | Lean owns when migrated | Raw host supplies |
| --- | --- | --- |
| CAS | Ingest/read/serve/receive; size and coverage; retention, repair, durability, eviction and collection | Raw records/files, leases, provider I/O, complete Bao service, hashing |
| Trie | Codec, canonicality, lookup/update/scan/diff/proofs; scope traversal, completeness, collection | Encoded records/values, raw provenance/refusals, memo resource, hashing |
| Authorization | The binding, scope, authority and provenance decisions needed by P4/M5/M8 | Raw grants/heads, authenticated identity, signature check, DNS/clock observations |
| Replication | Selected-head order, adoption, fetch/retry/progress and reconciliation needed by M1–M8 | Raw records, transport, time and entropy |
| Publication/materialization | Exact entry/view changes and their atomic head/reference/hold transitions | Raw transactions, files, provider I/O and signing |

CAS and Trie should not depend on each other's domain policy. Currently
`Trie.Serve` imports the shared raw field-decoding utilities housed in `Cas.Codec`;
this is an existing source dependency, not a completed no-import rule. Extract
those utilities to a shared module when needed to maintain the boundary.
Replication and publication compose their Lean interfaces without bouncing
through Rust policy callbacks. Control-plane/UI,
transport engines, provider SDKs and platform adapters remain host integrations;
unrelated domain migration is not implied. Relevant authorization, scheduling and
publication decisions cannot remain assumed application-level oracles in a proof
of mptsync. Move the necessary complete commands or establish a checked execution
connection for the remaining control flow.

### Effects, transactions and failures

`VerifiedCore.Host.Program E A` is an executable typed free monad: return a value,
or issue a typed effect with its continuation. `ExceptT` carries domain errors;
`EffectSum`, `Inject`, `raise`, `observe` and `within` compose capabilities and whole
sub-operations. Use structural bounds or explicit fuel for finite commands;
long-lived protocols are sequences of commands. Production algorithms must be
computable and total, without `sorry` or unsafe substitute implementations.

Lean opens the resource/transaction scope before the relevant reads and chooses
its subsequent queries, mutations, commit, rollback and recovery. `transactionOver`
and `transactionWith` preserve the primary error through rollback. Sub-operations
in one publication share the transaction token; an inner operation cannot commit
it independently. Rust supplies connection/lock lifetime and transaction semantics,
not a snapshot of precomputed policy facts. Every fallible effect has a typed
failure; errors must not publish incomplete or invalid results as success. Valid
committed progress may survive a later failure, including a lease-release failure.

Storage requests are declarative raw projections, selections, joins and mutations.
The Rust adapter validates relation/column names, binds values and preserves SQLite
classes (NULL, signed integer, REAL bits, raw text and blob). Lean decodes metadata,
unsigned sequence representations and bitmap records. Preserve absence versus NULL
versus empty data, UPSERT semantics, permissive local versus strict ingress decoding,
bulk/indexed access and existing database/wire encodings. Do not add host operations
such as `isComplete`, `settleSize` or `applyValidatedEntry` that hide domain policy.

The shared native runner binds raw capabilities. Missing capabilities and malformed
replies produce protocol failures. Hostgen generates boundary records from Lean;
domain types and intermediate proof state are not a public ABI. Keep bounded,
versioned frames, checked lengths, buffer ownership and opaque error-token identity.
Payloads use bounded buffers/handles; preserve batched processing and avoid copying
whole objects or large traversal frontiers across each suspension.

### Suspension and cancellation

The native `run_suspending`/`Step`/`Suspension` path retains the Lean continuation
on one owning thread. The engine can bridge raw peer requests to async transport
through channels. A reply must match the outstanding request; stale, duplicate or
terminal replies are rejected by continuation ownership and reply validation.
No database transaction or connection guard may remain open over a suspending
peer/provider effect. The runtime rejects such effects and the production programs
need the relevant `SuspensionProofs` discipline, rather than relying on a toy probe.

Dropping an invocation destroys its continuation and invokes host abandonment:
abort uncommitted transactions, close owned handles/temporaries, release leases and
discard private output. Committed rows and published files remain. Do not extend
Rust guard lifetimes unsafely across awaits or threads. Cancellation cannot later
resume that dropped invocation and publish a result.

### Trusted primitives and supported platforms

SQLite, the filesystem, provider correctness/acknowledgements, BLAKE3, Ed25519,
the **whole Bao service** (construction, encoding/decoding, proof verification,
chaining-value comparison and copy), the Rust runner/interpreters, native transport,
Lean compiler and runtime remain explicit trust boundaries. Bao stays implemented
in Rust on `bao-tree`; Lean chooses requested ranges and interprets its replies.
Do not disguise a whole application policy subsystem as a cryptographic primitive.
Hash-sensitive statements use an explicit collision-freedom/injectivity hypothesis
on relevant stored data, not an added axiom or global injectivity claim for a
finite-width hash.

Native/concurrent refinement and physical crash durability are tested host contracts,
not additional universal proof requirements. Provider claims must refer to actual
backing content; local cache eviction does not erase a retained provider copy.
Retain Linux GNU, macOS x86-64/arm64 and Windows gnullvm support, without a selectable
Rust fallback. Control-plane protocols and OpenBSD support are outside this migration.

## Current migration status

“Production Lean” describes ownership only. The open proof column prevents a
completed cutover from being mistaken for a completed user guarantee.

| Slice | Executed owner at this checkpoint | Evidence and remaining obligation |
| --- | --- | --- |
| Foundation F1/F2 | Lean carrier, raw capabilities, native runtime and peer suspension integrated | Shared host, wire, cleanup and suspension lemmas/tests exist. Provider suspension still needs C4 integration; verify discipline for each real suspending program. |
| Trie T1/T2: ingress and mutation | Production Lean (`Codec`, `Verify`, `Mutate`) | Canonical encoding/address preservation proved. Exact update/remove map meaning and whole-path depth remain open (P2). |
| Trie T3: requesting fetch | Production Lean `Fetch`, with a pinned Rust worker interpreting peer waits | Inspection, verified response admission, provenance writes, bounded retries and pending-target updates moved into the whole suspended operation. Six store unit tests and seven transfer integration tests cover verified progress, invalidation, atomic rejection, cancellation, released database access and transfer cost. The duplicate Rust requesting, resolution, reachability and admission test algorithms are deleted. Rust scope predicates and the publication scope-check traversal still require cutover; this is not yet a claim that all duplicates are gone. Prove the actual operation against faithful shared byte storage; exhaustion still does not establish P3. |
| Trie T4: completeness | Production Lean `Complete` and scope/owner memo key | Ticket/key discipline and native regressions checked. Justified omission and exact-view coverage are open, including the root-refusal issue above. |
| Trie T5: serving | Production Lean `Serve`; authorization inputs still composed in Rust | Actual-position resolution and whole-response scope predicates proved. Connect grants, publisher authority, provenance and transmitted bytes for P4/M5. |
| Trie T6: scan/diff | Production Lean `Walk`/`Diff`, streaming host application | Prefix/cursor/limit constraints and fixtures exist. Exact listings/differences and atomic faithful materialization remain open (P2/P3/M4). |
| Trie T7/T8: collection and optional Merkle proofs | Production Lean `Collect`/`Proof` | Reachable retained nodes/values survive collection; proof verification/lookup and construction round trip checked. Retention through actual pending/publication transitions remains a composition obligation. |
| CAS local ingest/read/heal/lifecycle | Production Lean | Named scoped P1/P5/P6 results below; extend fresh-store/intact-content assumptions to relevant histories. |
| CAS C1/C2: serve/verified receive/delta promotion | Production Lean with trusted Bao service | Fresh full receive-to-read and exact reads of backed verified ranges are checked; successful existing-row receive persists actual planner/decoder output over arbitrary raw databases. Connect repeated receives to the backing/coverage invariant, including decoder failures and partial physical writes. |
| CAS C3/C5/C7: durability, collection, projections | Production Lean | Repair responsibility, collection protection and projection support exist. Blob projections now compute verified groups and canonical advertised spans, including inside an existing publication transaction; the Rust bitmap decoder and advertisement policy are deleted. `CasAdvertisementProofs.stored_partial_advertisements_offer_saved_content` proves that every byte advertised by an actual partial, non-durable projection is backed by the saved content. Durable provider availability and cloud/publication retention composition remain open. Clock/LRU/diagnostics are regression details. |
| CAS C4: cloud composition | Rust `backend.rs` | Migrate complete provider adoption/hydration/finalize/read/serve commands, including trusted-range ingestion and complete-proof path. |
| CAS C6: source holds and publication advertisement | Rust inside publication transaction | Migrate with the entry/head/reference publication command, never as independently committing calls. |
| History pruning | Production Lean `Replication/History` | Retention/fork witness support proved. Adoption, reconciliation and scheduling still require implementation-connected M1–M8 proofs. |
| Peer contact selection | Production Lean `Replication/Contact`, called by serialized periodic rounds | Native bounded-turn and duplicate/order cases checked. Formal bounded service and composition with actual eligibility, failures and cancellation remain required for M1/M6. |
| Head exchange selection | Production Lean `Replication/Exchange`, called by engine reconciliation | Selects request origins and push indices from advertised/servable heads. Exact newer-version requests, duplicate/order invariance and push selection support M2. Signature/admission/availability inputs and subsequent adoption remain separate obligations. |
| Promotion authority snapshot | Rust `try_promote`, with permissions/authority read in its publication transaction | Snapshot-consistent permission checks and full own-view readiness have native regressions. This is a safety fix, not a Lean promotion theorem or closure of P3/M4/M8. |

The operator-only CAS migration tool, staging-directory layout sweep and provider
SDK remain Rust. They are not alternate implementations of migrated domain policy.
Historical performance evidence includes the 120,000-entry completeness corpus:
the Lean command and the now-deleted Rust walk each read 160,533 nodes; one local debug run measured 0.668 s Rust and 0.733 s Lean.
These are measurements, not a portability theorem or substitute for CI.

### Latest mptsync checkpoint

`ExchangeProofs.requests_exactly_newer_versions` states that an origin is requested
exactly when its greatest remote advertisement exceeds the greatest local one.
`advertisement_order_and_duplicates_do_not_hide_updates` proves the same result
for lists containing the same per-origin versions despite order and multiplicity.
`pushes_only_servable_updates` ties selected pushes to the supplied servable list,
and `selected_positions_refer_to_servable_heads` establishes actual list-index
membership under the native list-length bound. These are proofs about the planner
the engine executes; they do not authenticate those inputs or prove later adoption.

`ExchangeVersionProofs.version_order_is_sequence_then_root` connects the executable
planner's numeric key to unsigned sequence ordering followed by lexicographic
root-byte ordering for 32-byte roots. Thus the comparison used in the request and
push proofs agrees with the independently specified product order; it is not just
an arbitrary ordering function named “version”. Native admission enforces root width.

The promotion fix reads publication authority and permissions in the same
transaction snapshot as readiness checks and materialization. Promoting our own
version requires a complete whole view even if local read permissions are narrower.
Focused native validation passed the four promotion tests, including newly covered
revocation/accepted-view preservation and incomplete-own-view rejection; the store
library suite passed 284 tests with four ignored. These tests support the Rust
composition change, not a formal atomic-promotion or eventual-consistency claim.
The new exchange proofs passed their individual Lean checks; aggregate proof,
axiom, native and platform gates remain required for the final checkpoint.

The requesting fetch now executes in `VerifiedCore.Trie.Fetch`. Its continuation
retains traversal state across peer waits; admission verifies requested addresses
and commits each answer atomically. The host drops its database session before
calling the peer and resumes on the same worker. Pending refresh/deletion matches
the target origin, sequence and root, so a stale attempt does not target a newer
pending version. These are implementation facts and native regression coverage;
whole-operation transaction, interruption and convergence theorems remain open.

Routing validation passed the three native publication tests, the automatic
legacy-republication regression, and all eight delegation integration tests.
The empty permitted-view test and the private-ancestor-payload test retain their
behavioral assertions. A separate legacy compressed fixture still checks that
an admitted position cannot disclose an ungranted payload. The requesting and
representation proof modules passed focused warning-free builds; aggregate,
standalone kernel and broader platform checks remain required for this change.

### Newly checked snapshot and content composition

`TrieWriteSemantics.mutation_preserves_saved_read` connects actual mutation effects
to preservation of an existing successful read, assuming only compatibility of
encountered stored images at their addresses. `insert_into_empty_exact` gives the
exact single-entry meaning of inserting into the empty snapshot. General insertion,
present-key deletion, complete listings and exact differences remain required;
preserving an existing positive read alone does not exclude new entries appearing
in a previously incomplete old snapshot.

`CasReceivePromises.fully_received_content_reads_exactly` connects a successful
fresh full receive to actual subsequent reads. `CasContentProofs.verified_parts_read_as_content`
extends the read result to arbitrary available nonempty ranges: every returned
byte equals the corresponding intended content byte, although other groups may
be absent. `CasReceiveStateProofs.existing_receive_execution` establishes actual
row and decoder-output persistence without the previous single-row/empty-lease
restriction. It is a composition lemma, not yet the user theorem that any sequence
of valid partial receives preserves all readable content. In particular, the
trusted decoder must preserve previously verified bytes even if it writes part
of an answer and then fails; a successful-verification flag alone is insufficient.

`CasReceiveHistoryProofs.further_transfer_preserves_readable_content` now connects
all receive outcomes for unchanged-size file-backed content to exact subsequent
reads: productive receives, decoder interruptions, already-complete duplicates
and empty windows preserve previously available ranges. A successful receive
also establishes the next stored-content invariant from its actual rows and
file bytes. This uses the explicit primitive byte-preservation contract, not a
premise that the later read succeeds. Iterated-history equivalence, inline
content and other injected host-failure paths remain open.

## Path to all proof goals

Each stage must leave an integrated, reviewable command and a theorem stated in
terms of the promise it serves. Add supporting lemmas only as required by that
argument. The following dependency order also permits independent CAS work while
the metadata semantics and fetch path are developed.

| Stage | Implementation work | Proof result / acceptance criterion | Depends on |
| --- | --- | --- | --- |
| A. Give snapshots and content independent meanings | Define finite version entries, grant projection, content bytes/readable portions and retention obligations over raw state; establish representation invariants at ingestion/import | Observations do not define success as a program flag or assume the desired postcondition. Address private data on shared-path spines and legitimate omissions. | Existing codecs/lookup and product metadata schema |
| B. Make metadata completion honest | Resolve root refusal and other unsupported omissions; migrate the whole suspended fetch using `Missing`, `Peer`, ingress verification, provenance writes and generation resets; integrate the engine driver and remove Rust walk/fetch policy on cutover | P3/M7: completed work covers exactly the independently permitted view; missing/unverified information remains outstanding; cancellation preserves valid progress. Prove no transaction across waits and cache soundness through invalidation. | A; runtime suspension |
| C. Prove exact edits and views | Connect `Mutate`, `Walk`, `Diff` and materialization to version entries; migrate complete derived-entry application with its atomic head/reference/hold transition (C6) | P2/P3/M4: updates preserve unrelated entries; scans/diffs are exact; promotion atomically publishes the correct view and retention obligations, preserving the prior view on failure. | A; B for promotion readiness |
| D. Connect authority to disclosure and acceptance | Migrate necessary complete grant/scope/provenance and received-head/reply admission commands; compose actual serving, relay and ingestion paths | P4/M5/M8: accepted and newly disclosed data is justified by publisher authority and applicable grants; forged positions, grafts and obsolete scope work cannot widen access. State the authorization decision point. | A; C for scope-aware publication |
| E. Make version transitions and retries safe | Move whole head offer/selection, pending-target cleanup and promotion guards into executable Lean commands; preserve same-sequence fork evidence and target identity | P7/M2/M3/M7: deterministic winner, monotone accepted versions, stale work cannot overwrite/clear a newer target, retry/duplicate invariance. Recovery checks retain their explicit bounded scope. | C/D; existing history support |
| F. Prove actual mptsync convergence | Connect real AAE candidate selection, timeouts, productive batches, retries and retention to the commands above; migrate remaining policy necessary for that connection | P8/M1/M6: finite justified progress plus fair service yields eventual stable accepted-version/exact-view agreement; unrelated faulty peers/publishers cannot permanently starve healthy work. No premise that the whole fetch already completes. | B–E; explicit stable inputs, authorized availability and fairness |
| G. Extend content composition | Relate `Receive`/`commitGroups` persisted files and rows to `Read`, including existing content and unchanged-size partial coverage; preserve raw shared state between commands | P1/P6: successful full/range reads return the specified bytes; further verified receives preserve readability, duplicates/order agree, failure cannot publish a partial result as success. | Existing CAS promises and trusted Bao/file contracts |
| H. Complete cloud and retention composition | Add raw `Provider` capability and suspension; migrate whole adoption/hydration/finalize/read/serve C4; compose C6 publication holds with durability/repair/collection | P1/P5/P6: committed ranges have supplied backing, advertise durability after acknowledgement, only actual not-found invokes missing-copy healing, protected backing/repair responsibilities survive transitions. | G; suspension; C for publication holds |
| I. Close the system proof package | Compose the named user-property theorems, audit their hypotheses and implementation entry points, remove obsolete Rust policy and redundant proof copies | Every P1–P8 and M1–M8 target has its checked scope, actual implementation connection and explicit limits recorded here; relevant native/platform gates pass. | A–H |

Do not count staged Lean code as production migration. For each cutover, retain the
existing public facade and protocol behavior where compatible with the promised
semantics, delete the displaced Rust algorithm and obsolete low-level exports,
and run the affected trust-boundary, failure and cost tests. If a promise exposes a
real behavior defect, change and document that behavior with regression coverage;
do not weaken the observation or assume away the defective transition.

## Checked CAS promise scopes

### Content-store assumptions

Proofs must refer to executable functions in `VerifiedCore.Cas`, or to their raw
effects under stated host semantics. An independent policy model is insufficient.
Coverage equality means containing the same groups, regardless of interval layout.

Host assumptions include faithful SQLite projections and mutations, transaction
isolation and abort, writer/collection ordering, exact file transfers, and private
output publication. Hash construction and verified incoming groups must describe
the content actually stored. Reads do not rehash local bytes. Read comparisons
assume the same intact content remains available between operations.

Size correction is separate from adding parts at an unchanged size: correcting an
unattested size can reset coverage when the group count changes. Healing also
clears coverage. Neither transition is covered by coverage monotonicity.

Healing retains SQL LIKE semantics for `source:%` and `replica:%`, not a new
holder parser. Preserving repair obligations does not prove eventual recovery:
that also requires an available source, retries, and successful I/O.

An error need not leave the world unchanged. Ingest can commit then report a
lease-release error; file publication can precede a failed metadata commit.
Transaction abort, command success, and physical durability are distinct.

### Named theorem scopes

Each promise below has a named theorem in the default `Synchronicity` build,
but several theorems establish only a component or a restricted history.
Their scopes differ; this is not a claim that all eight promises are proved
across every production path. The table below is part of the contract.
Operation proofs execute on the [shared simulated host](#shared-host-semantics-and-trust-boundary).
Native interpreter refinement is still an explicit trust boundary.

| Promise | Checked theorem and scope |
| --- | --- |
| You get back what you stored. | [`CasStorePromises.you_get_back_what_you_stored`](../specs/lean/Synchronicity/CasStorePromises.lean): the whole immutable-byte input command followed by the whole read, from an initially empty database, for arbitrary bytes of representable length and either backend tier. Ingestion chooses inline or file-backed storage, and read consumes its actual final shared state. `you_get_back_what_you_stored_inline` additionally permits unrelated tables/files with an initially empty blobs table. |
| Reading a part agrees with reading the whole. | [`CasReadPromises.reading_a_part_agrees_with_reading_the_whole`](../specs/lean/Synchronicity/CasReadPromises.lean): arbitrary valid ranges of intact complete content, inline or file-backed. `reading_a_part_returns_that_part` also covers incomplete metadata with sufficient local coverage. Empty ranges and EOF clamping are included. |
| Downloading more preserves what you already have. | [`CasPromises.downloading_more_preserves_what_you_have`](../specs/lean/Synchronicity/CasPromises.lean): arbitrary in-bounds held groups and incoming groups at an unchanged size, through the Lean commit planner. |
| Duplicates and download order do not matter. | `CasPromises.duplicate_downloads_do_not_matter` and `download_order_does_not_matter`: equality of group coverage for arbitrary batches through the same planner. This does not assert equality of timestamps, interval encodings, or native partial-ingest executions. |
| Losing a copy does not erase the responsibility to keep it. | [`CasHealingPromises.losing_a_copy_preserves_responsibility`](../specs/lean/Synchronicity/CasHealingPromises.lean): the whole healing program, for an existing blob, arbitrary raw pin/request tables with canonical blob/text keys, size, and clock, under successful effects. The shared host evaluates the literal SQL LIKE selection. Every key has a pin or request afterward exactly when it did before. |
| Kept content is protected from collection. | `CasPromises.kept_content_is_protected_from_collection`: arbitrary valid access metadata in shared state, with no injected failures or existing transaction; actual pin/reference rows or a nonzero writer counter make deletion refuse collection and preserve both database and files. |
| A cancelled request stays cancelled. | `CasPromises.a_cancelled_request_stays_cancelled`: arbitrary root, holder, time and decoded durability in shared state, under successful effects; querying an absent request makes possession return false and preserves the database. |
| A failed read never returns a partial answer as success. | `CasReadPromises.failed_read_never_returns_partial_success` and `published_result_is_whole`: arbitrary errors, buffers and terminal results under the private-output publication contract. Native output disposal on cancellation remains a host obligation. |

Supporting general healing theorems preserve existing request records and
unselected pin records verbatim. `CasCompositionProofs` checks complete histories
involving storage, acquisition, collection, loss, repair, restoration, and reads.
It also checks repeated healing with a different clock, avoidance of repeated
missing-file I/O, and cancellation before a late fetch. These histories are
concrete regression proofs, not additional universal laws.

All operation families share raw relational mutations, transaction state, files,
resources, and output publication. The [host document](#shared-host-semantics-and-trust-boundary)
describes its supported semantics and limitations. Hashing remains a primitive;
no cryptographic assumption is disguised as a metadata invariant.

The coverage laws concern the Lean planner. The receive/read composition above
now connects selected successful executions to persistent bytes and rows, while
repeated partial-receive histories and failure preservation remain open. Cloud
orchestration remains Rust; planner laws alone do not establish its guarantees.

### Remaining content composition

Prioritize store/read composition over existing rows, receive persistence and
read composition, retention through cloud transitions, and failure behavior
that threatens those promises. Native interpreter refinement and physical
crash durability remain tested host assumptions rather than requirements
to prove every layer. Eventual content recovery is not promised without an
available source and successful retries; mptsync's metadata-convergence
obligation is separately specified in [its proof goals](#mptsync-safety-and-eventual-consistency).

## Shared host semantics and trust boundary

[SimulatedHost.lean](../specs/lean/Synchronicity/SimulatedHost.lean) interprets raw
host effects against one `State`. CAS ingestion, reading, healing, acquisition,
release, expiry, collection, and history retention use the same interpreter.
The former per-operation reply scripts and `Handlers.lean` are removed.

### State and execution

`State` contains committed database tables, an optional transaction-local copy,
files keyed by namespace and object key, open handles, temporaries, writer leases
and counters, the completeness certificates and their generation, a private
output buffer, the clock, and the effect trace.

`Interpreter` has one implementation per raw capability. Its `EffectSum` instance
composes capabilities without changing their behavior. `execute` interprets the
actual `Program` constructors; `run` starts an operation with a fresh private
output buffer. It returns the outcome and the complete updated state. For example:

```lean
let stored := SimulatedHost.run (Input.run (.bytes size) now .local) initial
let held := SimulatedHost.run (acquire root holder now false) stored.2
let read := SimulatedHost.run (Read.read root .all) held.2
```

There is no ingestion-to-reader conversion and no host callback that computes
coverage, size settlement, pin protection, or repair policy. Those decisions
remain in the imported production Lean operations. Fixtures construct raw rows
and files; they do not implement effects or provide successful replies.

`publish` exposes a buffer only after successful completion with a matching byte
count. `abandon` models invocation cleanup: abort pending database work, drop
private output, close owned handles/temporaries, and release owned leases while
preserving committed rows and published files. `execute` and `run` do not silently
invoke abandonment; tests can distinguish explicit program cleanup from the
host's abandonment contract.

### Raw semantics

[Database.lean](../specs/lean/Synchronicity/SimulatedHost/Database.lean) implements
projection, equality selection, LIKE selection, joins, ordering, correlated
exclusions, bounded deletion, updates, and upserts. It knows no CAS table names.
Affected-row counts come from mutations of actual tables.

A transaction reads its own writes. Snapshot observations use committed state;
commit publishes the transaction-local database, and rollback discards it.
The model runs sequentially and does not claim concurrent or crash refinement.

Files and resources have shared identity across commands. Opening a file retains
its bytes under a handle; replacing or removing its pathname does not change that
handle. Transfers check the requested bounds and append the actual slice. Missing
files and short reads arise from file state, not configured success/failure
replies. Temporaries are created, filled, flushed, replaced, and discarded through
raw capabilities. Lease acquisition/release changes the counter collection reads.

`Storage.deleteExcept` keeps exactly the rows whose key column names one of
the kept keys, with SQL `NOT IN` semantics for NULL (a NULL key is neither in
nor out of the set, so the row stays). It touches rows only: the payloads a
content-addressed relation serves through `readBytes` live in the file
namespace of the same name, which a fixture keeps consistent with the rows.
`Memo.forgetExcept` filters `certified` down to the kept keys and advances
`memoGeneration`. `Memo.isKnown` hides certificates while `memoBlocked`
is true; `Memo.generation` reads the ticket; `Memo.certify` compares that
ticket with the current generation and, for a writable memo, refuses both
an invalidating mutation and the terminal epoch. With `memoWritable = false`
it only validates the generation and never caches an answer, modeling a
transaction that can read its own uncommitted rows. Mutation-edge
observations are explicit fixture inputs here, not a concurrent refinement
proof; the native memo's invalidation, saturation and capacity behavior are
covered by its Rust tests.
`Digest.blake3` answers with the same `hash` parameter
construction hashes with. `Redaction.isRedacted` answers whether `redacted`
records the hash, at the given position or at any; `Apply.applyChange`
appends the change to `applied`, in the order it was handed over.
`Peer.fetchNodes` and `Peer.fetchValues` answer each want by its hash from
`peerNodes` and `peerValues` (the pair served, or the hash absent, in want
order), name the absent hashes in `peerRedacted` as refusals, and refuse the
whole request as the protocol failure while a transaction is pending, the
way the runner refuses to suspend inside one.

`faults` selects ordinary failures by effect index in the accumulated trace.
`scanFault` models a failure after the returned scan prefix. Failed ordinary
mutations do not apply; consuming cleanup operations still consume their resource.
The clock and directory-sync support are environmental inputs. Hashing, outboard
construction, and public-key validation are explicitly parameterized primitives.

### Checked scope and limitations

This is an executable semantics for the raw operations used by the proofs, not
an implementation or verification of SQLite, a filesystem, or cryptography.
Relational comparisons cover the typed CAS/history schemas. The model does not
implement SQLite affinity, arbitrary collations, numeric mixed-type ordering, or
its full malformed-text behavior. General repair key theorems require canonical
blob roots and text holders. LIKE supports ASCII case folding, `%`, and `_`.
The Bao service is a trust parameter like the hash: `State.slice` and
`State.proof` say what the host would encode for exactly the groups it is
asked for (and whether a proof walk fits the budget); the encoding is
appended to the private output, as a file transfer is, and never becomes a
program value. On the receiving side `State.decodeInline`,
`State.decodeSlice`, `State.proven` and `State.agrees` say what a received
encoding decodes to, whether it verifies, what a proof establishes and
whether a donor's tree agrees with a run; flushes are recorded in `synced`.
The sweeps read the store as files: a file costs its length, its time is
what `State.modified` records for it, and the object roots are the keys of
the payload and outboard files on one page. The remover's critical section
(`Lease.order`) is a counted token like a lease, keyed by its space alone,
so "inside the section" is the counter of `("cas", empty)` reading one;
its exclusion against writers is a host obligation the model states, not
one it simulates. An ordered query sorts with a structural, stable
insertion sort, so a fixture over several rows can be decided by the
kernel; the order it produces is the one `ordered` states.
Literal predicates (`equals`, `notEquals`, delete bounds) have SQL `IS`
semantics, as the store adapter renders them: NULL selects NULL and `IS NOT`
NULL excludes it. Conflict detection and join correlation keep SQL `=`, where
NULL equals nothing, matching unique indexes and joins.

Files opened here have stable bytes. Mutable-file capture, concurrent mutations,
crash persistence, and allocator exhaustion are separate obligations. Fixtures
start with valid, noncolliding handle/transaction counters. Flush/sync effects are
recorded, but a successful simulation does not prove power-loss durability.

Native interpreter refinement remains unproved: the Rust host must implement
these effect contracts. The shared state makes that one explicit boundary instead
of several operation-specific assumptions.

## Repository-wide proof audit

### Scope and method

The starting inventory contained 46 Lean proof/support modules under
`specs/lean/Synchronicity`, 944 named theorem declarations and 11 anonymous
examples. The audit also covered the executable Lean core, the recovery TLA+
model and all three configurations, Rust proof citations across the 12 crate
directories, control-plane/backend/frontend references, and CI proof gates.
Cryptographic proof data and verification code are product functionality,
not candidates for removal as redundant theorem text.

The inventory was checked against the default Lean imports. Declaration
dependencies were extracted from the elaborated environment, including both
types and proof bodies, rather than inferred from text matches alone. For
removal candidates, references in production code and documentation were
also searched. The cleanup checkpoint passed the full Lean build, standalone kernel recheck
and approved-axiom audit. Later migrations must repeat the applicable gates.

### Coverage and decisions

Every proof/support module is accounted for below. "Keep" includes useful
regression evidence; it does not mean the corresponding system promise is
already established end to end.

| Area and modules | User property and decision |
| --- | --- |
| `CasStorePromises`, `CasReadPromises` | P1/P6. Keep content and ranged-read composition and failed-output protection. Fresh-store/intact-content hypotheses are material limits; extend to existing rows and receive/cloud composition rather than claiming arbitrary save/read correctness. |
| `CasPromises`, `CasPlanProofs`, `IngestCommitProofs`, `CasReceiveProofs` | P1/P6. Keep coverage mathematics, verification/commit constraints and failure regressions. Planner coverage alone does not prove that persisted bytes remain readable after real receives. That bridge is higher priority than more planner cases. |
| `CasHealingPromises`, `CasReadHealingProofs`, `CasCompositionProofs`, `CasDurableProofs` | P5/P6. Keep preservation of repair responsibilities, existing requests, and composed loss/repair/read histories. Neither a remembered responsibility nor a durable database flag proves that an external copy still exists. |
| `CasProgramProofs`, `CasLifecycleProofs`, `CasReleaseProofs`, `CasExpiryProofs`, `CasCollectProofs` | P5/P6. Keep protection by current references, retention requests and active writers, actual-operation release/expiry tests, and unsafe-cleanup failure tests. Remove detached SQL-policy copies and their self-equalities; remove unconsumed clock/target implementation equalities where executed regressions already cover the behavior. |
| `IngestProgramProofs`, `IngestInputProofs`, `CasReadProgramProofs`, `CasReadCodecProofs` | P1/P6. Keep capture order/size, malformed-data rejection, publication and resource-lifetime arguments and adversarial examples. Exact diagnostic ordering is compatibility evidence, not a separate user promise or a reason to expand formal coverage. |
| `CasServeProofs` | P1/P6. Keep requested/held-range constraints and failure/publication checks. The Bao service is trusted; don't restate its implementation as a Lean proof goal. |
| `CasProjectProofs` | P2/P5. Keep correct association of retention state with the corresponding object and malformed-row regression coverage. Listing order, holder spellings and individual column diagnostics can remain tests; no universal theorem for every projection is required. |
| `TrieProgramProofs`, `TrieCodecProofs`, `TrieVerifyProofs`, `TrieProgramTests` | P1/P2/P4. Keep lookup meaning, canonical ingress and identity-binding support, including malformed-input tests. These are dependencies of a faithful snapshot, not substitutes for one. |
| `TrieMutateProofs`, `TrieWalkProofs` | P2/P3. Keep support used by actual update/read proofs. Canonical stored nodes and prefix/cursor/limit restrictions do not yet establish the exact map after an edit, complete listings, or exact differences. Prioritize those semantic results; root uniqueness is optional unless needed. |
| `TrieMissingProofs`, `TrieCompleteProofs` | P3/P6. Keep retry/deferral/scope and generation-discipline support. Remove unconsumed definitional restatements. The root-refusal case prevents treating walk exhaustion as proof of a complete shared view; investigate the protocol evidence first. |
| `TrieServeProofs`, `TrieServePrivacyProofs` | P4. Keep actual-position resolution and response-loop checks. Complete the link to independently authorized content and provenance across relays. The current existential witnesses/per-position predicate checks are not an end-to-end privacy theorem. |
| `TrieCollectProofs` | P3/P5. Keep protection of every reachable retained node/value and the sweep bridge. Proving that nothing unreachable is retained is not necessary for preservation; leaks and cost remain testable. |
| `TrieMerkleProofs` | P1/P4 for users of the optional proof API. Keep verification meaning and construction/verification round trip. Do not expand this into a new network-proof feature merely to add proofs. |
| `ExchangeProofs`, `ExchangeVersionProofs` | P8/M2 support added after the starting inventory. Actual head-exchange selection is exact and invariant under duplicate/reordered advertisements; selected pushes refer to supplied servable heads, and the numeric comparison agrees with sequence/root order. This establishes selection, not authentication, promotion, scheduler fairness or eventual consistency. |
| `HistoryProgramProofs`, `OriginProgramProofs` | P4/P7. Keep identity normalization/validation, current-version and fork-evidence protection. Remove an unused error-precedence theorem. The history retention proofs do not establish global convergence, publication atomicity or all authorization behavior. |
| `HostProgramProofs`, `HostResourceProofs`, `SuspensionProofs` | Supporting P1/P3/P5/P6. Keep reusable composition, cleanup and suspension discipline. A correct toy peer probe is evidence about the runner contract, not proof of an as-yet-unimplemented fetch. |
| `HostWireProofs`, `WireBufferProofs`, `WireWordProofs` | Supporting P1/P6. Keep typed-result preservation, malformed/truncated reply rejection and byte-order arguments. Concrete acknowledgements are compatibility regressions; native interpreter refinement remains an explicit boundary. |
| `SimulatedHost`, `SimulatedHost/Database`, `SimulatedHostProofs`, `CasFixtures`, `Decidable` | Infrastructure for all selected promises. Keep shared host semantics, their independent checks and genuinely shared fixtures. Audit assumptions such as raw file/row agreement; passing the model cannot establish that the native adapter implements it faithfully. |
| `Recovery.tla`, `Recovery.cfg`, `RecoveryCI.cfg`, `RecoveryPartitioned.cfg` | P7. Keep the bounded recovery checks and the expected partition counterexample. They explain a real user-visible limitation. They do not prove crash-safe file storage or mptsync convergence. The latter is a distinct required implementation theorem under [this document](#mptsync-safety-and-eventual-consistency). |
| Rust, control plane, frontend and CI | Retain native regression, interoperability, cryptographic verification, concurrency, fault and cost tests. Remove citations to absent formal models while preserving the security/protocol reasoning around them. Tests remain the evidence for unmigrated orchestration and host integration. |
| mptsync across `synch-core`, `synch-net`, `synch-engine`, `synch-store` and the executable Trie core | P3/P4/P6/P7/P8. Add the required eventual-consistency theorem and goals for order-independent selection, monotone versions, atomic/exact promotion, authenticated and authorized data, fault isolation, safe retries and permission changes. Existing local lemmas and the recovery model do not establish this pipeline. |

### Cleanup completed in the audit

- `CasReleaseProofs.mutation` and `CasExpiryProofs.mutation` were duplicate
  SQL-request definitions used only by their own identity theorems. They
  were not related to executions of `unpin` or `expire`. Both copies
  and their seven theorems were removed; real-operation regressions remain.
- Removed three isolated typed-holder spelling equalities from
  `CasReleaseProofs`, four unconsumed access-clock/eviction-target equalities
  from `CasCollectProofs`, and one error-precedence theorem from
  `OriginProgramProofs`. These add no necessary dependency to the selected
  guarantees. Actual-operation and corruption/identity tests remain.
- Removed five unused definition-expansion theorems from `TrieMissingProofs`;
  retained the stronger executed-step, resumption and whole-batch results.
  In total this removes 20 theorem declarations and two detached policy
  definitions. No exported promise theorem is removed.
- Replaced stale references to removed `ScopedSync`, `Provenance`,
  `Convergence`, `MptGc`, `Bridge`, `Publication`, `SystemSafety` and related
  historical models in Rust comments. In particular, remove claims that an
  absent theorem proves every admitted key readable or every fetch convergent.
  The intended invariants remain, with unresolved guarantees identified honestly.

This is not a target to minimize theorem count. Remaining small lemmas can
be essential proof dependencies, and remaining standalone examples can be
useful regressions. Future additions and removals should name the user
property or regression they serve. The old blanket requirement to prove
every migrated operation's exact internal behavior is superseded.

## Validation and completion gates

Heavy local validation runs sequentially with `CARGO_BUILD_JOBS=1` and test
threads set to 1. The Lean compiler is limited to one thread and 4 GiB; Cargo's
job count alone does not constrain Lean workers. Use one active build/test scope
with `MemoryMax=4G` and `MemorySwapMax=0`; subagents must not start competing
builds. Inspect surviving processes after interruptions. If the cap is reached,
inspect memory events and narrow the check instead of raising the limit. Check
individual changed proof targets before the aggregate build. A virtual-address
limit is not equivalent to a process-group memory cap for mapped proof artifacts.


Use three distinct kinds of evidence: universal Lean theorems about actual
commands under host contracts; concrete executable/fault-injection regressions;
and bounded TLA+ recovery model checks. Do not describe one as another.

The recovery model checks `FloorMonotone`, `SlotMonotone`, `HeadMonotone` and
connected-cluster `NoObservableFork`. The connected model explicitly requires
peers' summaries to reach recovery before post-loss publication; elapsed quiescence
time alone does not establish that premise. `RecoveryCI.cfg` uses the CI bounds;
`Recovery.cfg` increases the sequence bound. `RecoveryPartitioned.cfg` must expose
the documented no-fork violation when peers' history is not learned before
publication. These are P7 evidence under model assumptions, not mptsync liveness
or a general no-fork theorem. Its atomic head abstracts away trie fetch/promotion.

For a changed proof or migration slice:

1. Build the core and proofs with warnings rejected; run Hostgen `--check` after
   boundary changes. Recheck with the standalone kernel and audit axioms against
   the approved logical primitives. Do not introduce `sorryAx` or native-evaluation
   shortcuts into accepted proofs. Concrete execution fixtures may use
   `decide +kernel` or `cbv`, with resulting terms checked by the kernel.
2. Run focused real-storage, failure/cancellation and adversarial tests for the
   changed paths. Preserve transaction/lease behavior, wire/database compatibility
   and scope/provenance defenses. Do not add theorem-per-diagnostic obligations.
3. Measure relevant cost: deep paths, 8-million-position hostile limits, fanout,
   large completeness corpora, FFI calls and batching, receive/serve throughput,
   memory probes. Tests and measurements suffice for incidental cost behavior.
4. Before merge, run applicable workspace formatting/lint/test gates and the
   Linux GNU, macOS and Windows gnullvm CI matrix. Run cloud/emulator and recovery
   gates when their behavior changes. Local success is a checkpoint, not cross-platform
   completion.

```sh
# Proof package (imports the production Lean core)
cd specs/lean
lake build --wfail
# The prefix-wide checker starts modules concurrently. Check them serially
# inside the bounded scope to stay within the 4 GiB local memory budget.
rg --files Synchronicity -g '*.lean' | sort | while IFS= read -r source; do
    module=$(printf '%s' "${source%.lean}" | tr / .)
    lake env leanchecker "$module" || exit 1
done
```

```sh
# From the repository root
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Hostgen is run from `crates/synch-verified/lean` with
`lake env lean --run Hostgen.lean --check`; omit `--check` to regenerate after
an intentional algebra/command change. Rust glue is generated into Cargo's output
directory, never committed. See the crate README for build prerequisites and the
CI workflow for the exact axiom and platform gates.

Completion means the selected real guarantees are established with their stated
limits. It does not mean maximal theorem count, universal proof of every helper,
proof that all garbage is collected, unconditional network availability, physical
crash durability, native host refinement, or recovery after the last copy is lost.
