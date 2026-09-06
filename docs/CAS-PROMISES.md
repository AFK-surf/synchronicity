# The promises of the content store

These user-facing statements organize the CAS proofs. They depend on the storage
and concurrency contracts below, not on disks never failing.

| Promise | Meaning |
| --- | --- |
| You get back what you stored. | Successful storage followed by a successful read returns the stored bytes while the content remains available and intact. |
| Reading a part agrees with reading the whole. | A ranged read returns exactly the corresponding section of a full read. |
| Downloading more preserves what you already have. | Adding verified groups at an unchanged object size preserves existing coverage. |
| Duplicates and download order do not matter. | Repeated or reordered verified groups give the same coverage. Timestamps need not agree. |
| Losing a copy does not erase the responsibility to keep it. | Successful healing transfers selected standing pins to repair requests without losing obligations or replacing existing requests. |
| Kept content is protected from collection. | A pin, current reference, or active writer prevents collection from deleting the object or requesting file cleanup. |
| A cancelled request stays cancelled. | A late possession acquisition cannot recreate a pin when its request is absent. A new request can authorize acquisition. |
| A failed read never returns a partial answer as success. | Errors and abandonment do not publish a prefix. |

## Proof boundary

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

## Proof map

All eight promises have named, universally quantified theorems in the default
`Synchronicity` build. Their scopes differ; the table below is part of the contract.
These are executions under explicit proof hosts, not proofs of the native hosts.

| Promise | Checked theorem and scope |
| --- | --- |
| You get back what you stored. | [`CasStorePromises.you_get_back_what_you_stored`](../specs/lean/Synchronicity/CasStorePromises.lean): the whole immutable-byte input command followed by the whole read, for a fresh object, arbitrary bytes of representable length, and either backend tier. Separate inline and captured-source theorems cover the underlying ingestion operations. The read observes the fields and payload actually written by ingestion. |
| Reading a part agrees with reading the whole. | [`CasReadPromises.reading_a_part_agrees_with_reading_the_whole`](../specs/lean/Synchronicity/CasReadPromises.lean): arbitrary valid ranges of intact complete content, inline or file-backed. `reading_a_part_returns_that_part` also covers incomplete metadata with sufficient local coverage. Empty ranges and EOF clamping are included. |
| Downloading more preserves what you already have. | [`CasPromises.downloading_more_preserves_what_you_have`](../specs/lean/Synchronicity/CasPromises.lean): arbitrary in-bounds held groups and incoming groups at an unchanged size, through the Lean commit planner. |
| Duplicates and download order do not matter. | `CasPromises.duplicate_downloads_do_not_matter` and `download_order_does_not_matter`: equality of group coverage for arbitrary batches through the same planner. This does not assert equality of timestamps, interval encodings, or native partial-ingest executions. |
| Losing a copy does not erase the responsibility to keep it. | [`CasHealingPromises.losing_a_copy_preserves_responsibility`](../specs/lean/Synchronicity/CasHealingPromises.lean): the whole healing program, for an existing blob and arbitrary pin/request maps, size, clock, and SQL LIKE matcher. Every key has a pin or request afterward exactly when it did before. |
| Kept content is protected from collection. | `CasPromises.kept_content_is_protected_from_collection`: arbitrary valid access metadata and protection observations; the executed delete refuses collection and requests no metadata deletion or file removal. |
| A cancelled request stays cancelled. | `CasPromises.a_cancelled_request_stays_cancelled`: arbitrary root, holder, time and decoded durability; observing an absent request makes possession return false with no pin UPSERT. |
| A failed read never returns a partial answer as success. | `CasReadPromises.failed_read_never_returns_partial_success` and `published_result_is_whole`: arbitrary errors, buffers and terminal results under the private-output publication contract. Native output disposal on cancellation remains a host obligation. |

Supporting healing theorems establish that existing request records survive
unchanged, other objects retain their claims, availability is retracted, and
repeating healing changes no modeled state even with a different clock value.
The healing interpreter models pin presence and full request fields; it does not
model pin timestamps. Its intermediate state is transaction-private, and its
success theorem assumes successful transaction effects. Existing trace proofs
cover the failure paths separately. Blob fields in that interpreter belong to
the target object; pin/request maps range over all object/holder keys.

The read and store hosts check raw keys and projections. The store host models
fresh insertion, exact input/construction, successful publication, and successful
commit; resource ownership, outboard correctness, syncing, and transaction
isolation remain host contracts. Hashing associates the supplied root with the
supplied bytes; no cryptographic axiom is disguised as a metadata invariant.

The coverage theorems are about the Lean planner. As recorded in
[the architecture](LEAN-CORE-ARCHITECTURE.md), native partial/cloud orchestration
currently lives in Rust. These mathematical laws do not verify that Rust path.

## Further proof obligations

The broader promises motivate extensions beyond this checked scope: store/read
composition over existing rows and conflict updates; complete mutable-path input
capture; partial-ingest persistence and codec/read composition; arbitrary failing
host executions; and native interpreter refinement. Eventual recovery and crash
durability need additional environmental assumptions and are not claimed here.

## Checking

```sh
cd specs/lean
lake build --wfail
```

The default library imports all four promise modules. No production operation or
host ABI changes are needed for these proofs.
