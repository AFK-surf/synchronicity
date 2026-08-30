# Source, replica, and checkout refactoring plan

Status: **implemented as a breaking refactor**.

This plan replaces the current `space`/`mirror` command model with two local
roles — **source** and **replica** — and makes an optional filesystem checkout a
property of a replica. It also removes the command aliases and policy variants
that exist only because the current surface mixes publishing, retention, and
materialization.

The plan is intentionally subtractive. It does not preserve every combination
the current implementation can express. The product should make its common,
important jobs obvious:

1. publish this node's copy of a space;
2. keep a durable second copy of a space;
3. optionally expose that replica as ordinary files;
4. inspect, read, or adopt content without creating a standing role.

Everything else should be an action, a storage setting, or an explicit manual
pin — not another replication mode.

---

## 1. Why this refactor

The current `spaces` row and `synch space` command combine several independent
facts:

- whether this node scans and publishes a filesystem directory;
- whether this node accepts API/S3 writes without a checkout (`--detached`);
- whether this node retains every origin's content (`--replicate`);
- whether retained content follows the current tree or is kept forever;
- the replica's grace period and budget.

`synch space rm` consequently means several things at once: stop scanning,
publish a mass removal of this origin's entries, stop replica work, and perhaps
release replica pins. `space set --no-replicate` without `--release` creates a
further unnamed state: no active replica policy, but all old replica pins kept
indefinitely.

Mirrors add a second, overlapping content consumer. A mirror selects one
version per path, fetches it independently, writes it to a directory, owns its
own standing loop, and has independent `newest`, `origin=...`, and `strict`
policies. This flexibility is expensive in concepts and implementation:

- mirrors and replicas maintain separate scheduling and status paths;
- mirror selection cannot describe what a replica holds (a replica holds every
  version);
- a node can configure many projections of one space, although the important
  deployment is one readable checkout on a storage node;
- removing a mirror stops management but leaves files, while removing a space
  may also stop retention;
- the same version-selection syntax is repeated across mirrors, reads, fills,
  pins, and S3 buckets.

The refactor treats a **space** as what it is on the wire: a string in the
cluster namespace. It is discovered from metadata or named by a local role. It
is not a resource a node creates or deletes.

---

## 2. Product decisions

These decisions are the contract for the implementation. Later phases should
not reintroduce removed behavior under compatibility flags.

### 2.1 Local roles

A node may have zero, one, or both of these roles for a space:

- **Source** — publishes this node's view of the space. A source is either a
  filesystem directory or API-only. API-only replaces the current word
  `detached`.
- **Replica** — durably holds every version currently published by every origin
  in the space. A replica may keep content according to the current tree or
  forever, and may have one read-only checkout.

The roles compose but never imply each other. Adding or removing one cannot
change the other.

### 2.2 No standalone mirror

Remove the standalone mirror feature:

- remove `synch mirror add/rm/ls/sync`;
- remove mirror-only nodes;
- remove multiple materialized targets per space;
- remove `origin=...` and `strict` materialization policies;
- remove mirror-specific fetching, persistence, wakeups, and reporting.

A replica may instead have one optional **checkout**. The checkout always
materializes the deterministic `newest` version of every live path. It is a
readable projection of a complete replica, not another content placement
policy.

The uncommon need to inspect one origin remains served by foreground reads and
read-only S3 views:

```text
synch cat media/file --select origin=nas@cluster.example
synch get media/file --select origin=nas@cluster.example
synch-s3 bucket add nas-media media --read-only \
    --select origin=nas@cluster.example
```

`strict` remains a foreground read policy, where reporting a divergence to the
caller is useful. A standing checkout must make progress without an operator
present, so it uses `newest` and reports divergence separately in status.

### 2.3 Replica retention

There are two replica retention policies:

- **`current`** — hold every version named by an origin's current trie. Once no
  current entry names a root, keep it for the configured grace period and then
  release the replica hold.
- **`forever`** — never release a root observed while the replica role is
  active. Enabling it is not retrospective: roots that disappeared before this
  node observed them are not recreated from metadata history.

These replace the current names `tree` and `archive`. `current` and `forever`
state the retention decision directly.

### 2.4 One checkout per replica

A replica may have zero or one checkout path.

- It writes the current `newest` view.
- It never publishes or feeds the source scanner.
- Its root may not overlap a source root or another replica checkout.
- It uses content already acquired by the replica. It does not create a second
  fetch queue or a second retention holder.
- When replication is incomplete, the checkout writes only paths whose selected
  roots are complete and reports the rest as blocked.
- Selected checkout roots receive priority inside the replica want queue so a
  budget or a large divergence set does not leave the useful filesystem view
  behind arbitrary non-selected versions.
- Under `forever`, old versions remain in the CAS and are read by root; they are
  not expanded into a historical directory layout.

Removing a checkout stops managing it and leaves its files in place by default.
Deleting checkout files is a separate explicit option.

### 2.5 No unnamed retention state

Removing a replica releases its replica holders by default. This means “stop
promising to keep these bytes”; it need not synchronously erase the bytes.
Ordinary references, operator pins, and the retention horizon still apply.

An operator who wants to stop replica work but retain everything already held
must explicitly convert those holds to operator pins:

```text
synch replica rm media --pin-held
```

There is no equivalent of `--no-replicate` without `--release`.

### 2.6 A publisher must hold its content

For regular files and sockets in this node's own current trie, publication has
an enforced storage precondition:

> A live own-origin entry may enter a signed head only when the complete object
> is present in this node's configured durable CAS.

This is stronger than the current convention that supported ingest paths store
bytes before they call the generic publisher. It closes the gap where a caller
can stage an arbitrary `f:` value.

The corresponding availability record must describe a complete object. A
signed metadata head proves authorship; it must no longer be possible for the
ordinary publisher boundary to turn that into an unsupported possession claim.

### 2.7 Persistent intent heals; cache does not

Every source root, replica root, and operator pin is a persistent content
intent. When the store has evidence that such a root is missing, it enters the
common want queue and is fetched from peers until restored or reported
unreachable.

Read-through cache has no persistent intent. `cat`, `get`, S3 reads, and other
foreground consumers may fetch ranges, but those cached ranges are not
automatically repaired after loss.

---

## 3. Target CLI

### 3.1 Source commands

```text
synch source add <space> <path>
synch source add <space> --api
synch source rm  <space>
synch source ls  [<space>]
synch source scan [<space>]
```

Semantics:

- `source add <space> <path>` creates a filesystem source, performs the same
  root/overlap validation as today, and wakes the standing scanner. It returns
  after configuration is durable rather than holding a control request open
  while a multi-terabyte initial scan runs. `source scan <space>` is the
  synchronous “publish it now” operation. Watcher and periodic scan behavior
  remain.
- `source add <space> --api` creates an API-only source. It has no scanner or
  watcher. S3/adoption writes ingest into the durable CAS and publish this
  origin's entries directly.
- `source rm` stops the scanner/API writer and publishes removal of this
  origin's current entries before returning. It never changes a replica.
- `source scan` scans one filesystem source or all filesystem sources. It
  refuses an API-only source by name instead of silently doing nothing.
- A node may have at most one source role for a space. Changing source kind or
  path is deliberately not a generic `set`: it requires a purpose-built future
  relocation operation with its own safety contract, or removal and addition.

### 3.2 Replica commands

```text
synch replica add <space>
    [--retention current|forever]
    [--grace <duration>]
    [--budget <bytes>]
    [--checkout <path>]

synch replica set <space>
    [--retention current|forever]
    [--grace <duration>]
    [--budget <bytes>|--no-budget]
    [--checkout <path>|--no-checkout]

synch replica rm <space>
    [--pin-held]

synch replica ls [<space>]
synch replica sync [<space>]
```

Defaults:

- retention: `current`;
- grace: 30 days;
- budget: none;
- checkout: none.

Validation:

- `--grace` is accepted only with `current`;
- a checkout path must not overlap any source or other checkout;
- `replica add` refuses an existing role and points to `replica set`;
- `replica rm --pin-held` converts complete replica-held roots to operator pins
  transactionally before removing the replica holders;
- incomplete wants are not converted to pins, and the command reports their
  count;
- removal never modifies or unpublishes a source.

`replica sync` performs one metadata reconciliation, drains ready replica wants
within the configured concurrency/backoff rules, updates the checkout, and
prints one report for the whole operation.

### 3.3 Space discovery without a `space` command

Remove `synch space` entirely. A bare listing discovers the namespace:

```text
synch ls                         # known spaces and local roles
synch ls media                   # the root of one unified tree
synch ls media/photos            # a directory
synch ls nas@cluster:media       # one origin's assertion
```

The no-argument form lists the union of:

- spaces named by materialized entries;
- configured sources;
- configured replicas;
- spaces known only through manifests, if they have no entries yet.

Each row shows compact local-role state, for example:

```text
media    source /srv/media · replica current · checkout /srv/checkout/media
photos   replica forever · 880 GiB held
docs     remote only
uploads  source api
```

Detailed role-specific health stays under `source ls <space>` and
`replica ls <space>`.

### 3.4 Foreground selection

Use one spelling everywhere a caller selects a version:

```text
--select newest
--select origin=<origin-id>
--select strict
```

Apply it to `cat`, `get`, adoption, path-based pins, and read-only S3 buckets.
Origin-qualified references remain shorthand. Remove the duplicate `--from`,
`--strict`, and `--policy` flags after the command transition described in
§9.

### 3.5 Adoption

Replace `take` and `fill` with one noun and two explicit cardinalities:

```text
synch adopt path <space>/<path> [--select ...]
synch adopt tree <space>[/<dir>] [--select ...] [--replace] [--dry-run]
```

- `adopt path` replaces current `take`, including deliberate adoption of a
  tombstone.
- `adopt tree` replaces current `fill`: additive by default, never adopts
  deletions in bulk, and replaces differing local files only with `--replace`.
- `adopt path` works with either source kind. A filesystem source writes the
  file safely and updates its scanner record; an API source promotes the
  selected object and publishes a direct reference.
- `adopt tree` requires a filesystem source. Bulk publication into an API-only
  source is not added by this refactor.
- Both publish the successful changes, flush the batch, and return only after
  the own head exists. The current “fill now, publish on a later scan” timing is
  removed.

### 3.6 Other command cleanup in the same breaking release

The following are small, direct corrections exposed by the inventory. They
belong in the same help/protocol/UI rewrite:

| Current | Target | Reason |
|---|---|---|
| `peers` | `peer ls` | A resource noun leaves room for `peer sync`. |
| top-level `sync` | `peer sync` | Distinguishes metadata exchange from replica synchronization. |
| `scan` | `source scan` | Scanning is source behavior. |
| `doctor --rebuild` | `repair rebuild-views` | `doctor` remains read-only. |
| `connect` | `socket connect` | Socket operations stay under one noun. |
| `cloud ...` | `control-plane ...` | Avoids collision with cloud CAS configuration. |
| `socket add/rm` | `socket declare/undeclare` | Names what the operation does. |

Keep common data-plane commands (`ls`, `status`, `cat`, `get`, `log`, and
`compare`) top-level. Nesting frequent Unix-like reads under a taxonomy would
make the CLI tidier on paper and worse to use.

Keep `init`, `id`, `key`, `daemon`, `trust`, `delegate`, `domain`, `pin`,
`recover`, `doctor`, `cas`, and `mcp` otherwise unchanged.

---

## 4. S3 gateway contract

An S3 bucket currently combines a selected read view with writes that always
publish the local origin. A foreign-origin bucket therefore accepts a write
that subsequent reads cannot see. Replace the warning with an explicit access
contract.

```text
synch-s3 bucket add <bucket> <space> --read-only [--select ...]
synch-s3 bucket add <bucket> <space> --read-write
synch-s3 bucket rm <bucket>
synch-s3 bucket ls
```

Rules:

- Exactly one of `--read-only` or `--read-write` is required.
- A read-only bucket may name any discovered space and use `newest`, one origin,
  or `strict`.
- A read-write bucket requires a local source role for the space.
- A read-write bucket reads this node's own view (`origin=self`) to preserve
  read-after-write behavior. It has no selection flag.
- PUT, multipart completion, and DELETE continue to publish only this node's
  assertions.
- An API-only source is the normal target for a serverless bucket. A filesystem
  source remains writable through S3 when the existing safe-path checks pass.

Rename `synch-s3 key` to `synch-s3 access-key`. Do not accept the secret as a
positional argument. `access-key add <id>` prompts on a terminal or accepts
`--secret-file <path>` / `--secret-stdin`; it never prints the secret.

---

## 5. Persistent model

### 5.1 Sources and replicas are separate tables

Replace the configuration meaning of `spaces` with two tables. Space ids in
published entries remain unchanged.

Illustrative schema (exact migration version and SQL belong in the
implementation change):

```sql
CREATE TABLE sources (
    space       TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('filesystem', 'api')),
    local_path  TEXT,
    CHECK (
        (kind = 'filesystem' AND local_path IS NOT NULL) OR
        (kind = 'api'        AND local_path IS NULL)
    )
);

CREATE TABLE replicas (
    space          TEXT PRIMARY KEY,
    retention      TEXT NOT NULL CHECK (retention IN ('current', 'forever')),
    grace_seconds  INTEGER,
    budget_bytes   INTEGER,
    checkout_path  TEXT,
    CHECK (
        (retention = 'current' AND grace_seconds IS NOT NULL) OR
        (retention = 'forever' AND grace_seconds IS NULL)
    )
);
```

Do not retain a third table merely to say that a node “joined” a space. A
source, replica, entry, or manifest is sufficient evidence that the space is
known.

### 5.2 Generalize content holders and wants

The existing pin-holder model is close to the desired shape. Extend it so every
persistent promise uses the same machinery:

```text
operator
source:<space>
replica:<space>
```

Rename `replica_want` to `content_want` (or introduce the generalized table and
migrate) so source repair and replica acquisition share retry, backoff,
provider ranking, delta donors, and error reporting.

Each want records at least:

- root and authenticated size;
- holder;
- optional previous-root donor;
- first-wanted time;
- attempts, last attempt, and last error;
- priority class (`checkout-selected`, ordinary replica, or source repair).

Priority order:

1. source repair;
2. roots selected by a configured checkout;
3. remaining replica roots, rarest first within a space and fair between
   spaces as today.

Operator pins use the same fetch path but remain foreground operations: `pin
add` returns success only after complete durable content exists.

### 5.3 Source intent transaction

When an own-origin file entry is published, one transaction must:

1. validate that its blob row is complete and durable for the configured
   backend;
2. install or retain the `source:<space>` holder;
3. insert the `f:` entry and complete `b:` advertisement into the trie;
4. sign and store the new head;
5. materialize the own-origin entry view;
6. release the source holder for a superseded root only when no current own
   entry in that space names it.

Tombstones and raw key removals carry no new source holder. Removing a source
releases its holders only as its entries leave the own head.

The transaction protects metadata and holder state. Durable ingest/finalize
still precedes it. A short pre-publication write lease or staging holder keeps
GC from deleting a newly ingested, not-yet-referenced object between finalize
and head commit.

### 5.4 Actual holdings, advertisements, and failure evidence

Desired state must not be confused with actual availability:

- `content_intent`/holders say what this node promises to restore;
- the blob row and verified group state say what it currently holds;
- `b:` records are derived only from actual verified holdings;
- a complete ad is published only for a complete locally servable object.

On evidence of loss:

- cloud `NotFound` continues to withdraw `durable`;
- local payload/outboard `NotFound` or short read invalidates the affected
  complete/verified claim instead of leaving a complete row that fails forever;
- invalidation retires or reduces the `b:` ad;
- every persistent holder for the root stages a generalized want and wakes the
  reconciler;
- successful peer recovery restores durable storage before restoring a
  complete ad.

Maintenance should cheaply stat payload/outboard existence and expected sizes
for persistent local-CAS intents. Full byte scrubbing is a separate optional
integrity feature; it is not required for this refactor. Cloud stores remain
failure-driven rather than issuing a periodic HEAD for every root.

---

## 6. Engine organization

### 6.1 Source module

The scanner remains the implementation of filesystem sources, but its public
entry points and reports move behind source terminology:

- `add_space` -> `add_filesystem_source`;
- `add_detached_space` -> `add_api_source`;
- `remove_space` -> `remove_source`;
- `scan_all` -> scan all filesystem sources;
- watcher registration reads `sources WHERE kind = 'filesystem'`.

API-only publication paths (S3 PUT, multipart completion, and detached
adoption) validate an API source rather than `local_path IS NULL`.

### 6.2 Replica and checkout module

Keep one standing replica loop. It owns this sequence:

1. reconcile replica intents from the unified entry view;
2. process ready content wants;
3. finalize and pin completed roots;
4. publish material coverage claims;
5. reconcile configured checkouts from complete local roots;
6. report coverage and checkout health.

Metadata promotion, a local publish, replica configuration changes, and source
repair completion all wake this loop. `replica sync` invokes the same pass
explicitly. Remove the separate mirror loop, wake object, interval, lock, and
daemon task.

Move reusable safe-filesystem code from `mirror.rs` into neutral modules:

- path validation and name safety;
- symlink-escape prevention;
- atomic staging/rename;
- reflink/copy from the CAS;
- mtime and advisory mode application;
- currency checks and stale-path removal.

The policy/listing part of `mirror.rs` is deleted. The remaining checkout
implementation reads only `replicas.checkout_path` and always resolves
`VersionPolicy::Newest`.

`fill.rs` becomes the implementation of `adopt tree`; it may continue sharing
the neutral filesystem primitives with checkout.

### 6.3 Checkout reconciliation

Checkout correctness rules remain conservative:

- never follow a symlink out of the checkout root;
- never silently choose between names that collide under the target
  filesystem's folding rules;
- write through daemon-owned staging and atomic rename;
- remove a checkout path only when the current selected tree no longer contains
  it and the checkout still matches the last materialized version;
- report, rather than overwrite, an unexplained local edit;
- preserve published mtime and masked permission bits;
- never feed checkout files into a source scanner.

Unlike the old mirror, there is no per-target version policy and no second
checkout for the same space.

### 6.4 Cloud attachment and routing

Anything that currently treats a source root or mirror as evidence that this
node “holds a space” must use explicit roles:

- a source claims the space it publishes;
- a replica claims the space it durably holds;
- a checkout adds no claim beyond its replica;
- foreground cache reads add no durable space claim.

This removes mirror-only routing and prevents a leftover checkout directory
from advertising node capability.

---

## 7. Control protocol, MCP, and app

### 7.1 Control protocol

Add new protobuf commands rather than reusing the mixed `Space*` messages:

```text
SourceAdd, SourceRm, SourceLs, SourceScan
ReplicaAdd, ReplicaSet, ReplicaRm, ReplicaLs, ReplicaSync
RepairRebuildViews
```

Append new oneof field numbers. Never reuse the numeric tags of `SpaceAdd`,
`SpaceLs`, `SpaceRm`, `SpaceSet`, `SpaceSync`, or any `Mirror*` command. Once
removed, reserve their tags and message names in both copies of
`control.proto`.

The control server should expose structured source/replica records where the
GUI needs stable fields. Human CLI rendering may remain streamed text, but the
app must not infer roles by parsing a combined `space ls` sentence.

### 7.2 MCP

Keep `synch_spaces` as a read-only discovery tool, but change its result to list
known namespace spaces plus structured local roles. It no longer means
“configured rows in the old spaces table.”

Rename the write tool `synch_scan` to `synch_source_scan`. Add source/replica
management tools only if MCP role administration is intentionally in scope;
do not expose them merely because protobuf commands exist. The existing
`--allow-write` boundary remains mandatory.

Update MCP prompts and resources to say:

- source = this node publishes;
- replica = this node durably retains;
- checkout = readable projection of a replica;
- a remote-only space is still listable and readable.

### 7.3 Hecatia

Update the app in the same repository change series:

- split the combined `Space` model into namespace information plus optional
  `SourceRole` and `ReplicaRole`;
- rename “Folders”/sharing operations to source operations where appropriate;
- remove `MirrorsSection`, `MirrorSheet`, `MirrorSyncOutcome`, mirror operation
  definitions, previews, and parser compatibility code;
- add checkout path and checkout health to the replica UI;
- split “Stop Sharing” from “Stop Replicating” into separate actions and
  confirmations;
- replace `space add/set/sync/rm` command lines with source/replica commands;
- update operation dirty sets, status refreshes, transcript parsing, samples,
  and compatibility tests;
- synchronize the app's copy of `control.proto` and reserve removed tags.

The GUI must make the destructive boundary visible: removing a source
unpublishes this origin; removing a replica stops a storage promise; deleting a
checkout removes ordinary files. No sheet should combine those consequences.

---

## 8. Stored-state migration

### 8.1 Existing spaces rows

Migrate each current row as follows:

| Current row | New source | New replica |
|---|---|---|
| `local_path != NULL`, no replication | filesystem source | none |
| `local_path != NULL`, `tree` | filesystem source | `current` |
| `local_path != NULL`, `archive` | filesystem source | `forever` |
| `local_path == NULL`, no replication | API source | none |
| `local_path == NULL`, `tree` | API source | `current` |
| `local_path == NULL`, `archive` | API source | `forever` |

The old schema cannot distinguish `space add --detached --replicate` from a
replicate-only row created without spelling `--detached`: both store a null
path and a replica policy. Creating an API source for both is the safe migration
because it preserves existing write capability and does not publish anything
by itself. `doctor` should flag API sources with no own entries and no S3 bucket
as candidates for removal.

Map old policy/config values:

- `tree` -> `current`, preserving grace and budget;
- `archive` -> `forever`, dropping meaningless grace and preserving budget;
- current replica pins/wants -> the corresponding generalized holder/want;
- operator pins remain operator pins.

### 8.2 Existing mirrors

Legacy mirror configuration is dropped. It is deliberately not converted into
a replica: doing so could turn a selected one-version cache into an unbounded
durability promise. Existing materialized files are left untouched as an
unmanaged snapshot. An operator who still wants them managed creates a replica
with an explicit checkout path.

### 8.3 Checkout files on removal

Database migration and role removal never delete materialized files. Checkout
directories are ordinary user-visible trees and the CLI does not recursively
delete them; after removing or moving a checkout, the operator may inspect and
remove the now-unmanaged files with normal filesystem tools.

---

## 9. Command transition

The workspace is pre-1.0, and the CLI, daemon, control protocol, MCP surface,
and app ship together. Prefer one clean break over permanent aliases.

There are no aliases or tombstone parsers. Removed commands fail through the
ordinary unknown-command path. Scripts can feature-detect the new surface with
`synch source --help`; no compatibility mode is provided.

---

## 10. Implementation phases

Each phase should merge with its tests and leave the workspace buildable. Avoid
a long branch that changes schema, protocol, CLI, and app only at the end.

### Phase 0 — lock the contract

- Land this document.
- Update `DESIGN.md` terminology for the source/replica surface.
- Add CLI parse snapshots for the target source/replica grammar.
- Add schema migration fixtures representing every row in §8.1 and every mirror
  policy.

Exit criterion: target commands and migration decisions no longer depend on
implementation convenience.

### Phase 1 — separate persistence

- Add `sources` and `replicas` tables.
- Migrate existing `spaces` rows according to §8.1.
- Add store types and CRUD methods with no CLI exposure yet.
- Drop old mirror records during the role-schema migration.
- Generalize holder and want persistence.
- Rebuild derived views and coverage reports against the new role tables.

Exit criterion: engine tests can configure sources and replicas independently,
and removing either leaves the other unchanged.

### Phase 2 — enforce source possession and healing

- Route scanner and API ingest through source records.
- Install source holders in the publish transaction.
- Validate complete durable blobs and complete ads for own live file/socket
  entries at the publisher boundary.
- Generalize failure invalidation and the want loop for source repair.
- Add cheap local persistent-intent stat checks to maintenance.

Exit criterion: no supported or generic local publish can create an own live
file entry without complete durable content, and an evidenced loss queues
repair when another provider exists.

### Phase 3 — fold materialization into replicas

- Add replica checkout configuration and validation.
- Extract neutral filesystem materialization primitives from `mirror.rs`.
- Reconcile checkouts only from content already held by the owning replica.
- Remove the separate mirror daemon task, wakeup, interval, lock, reports, and
  cloud-routing claim.

Exit criterion: a replica checkout converges, restarts, handles tombstones and
local edits safely, and performs no network fetch outside replica wants.

### Phase 4 — control protocol and CLI

- Add Source*/Replica* protobuf commands and handlers.
- Add `source` and `replica` Clap enums and renderers.
- Remove `SpaceCommand`, `MirrorCommand`, and top-level `Scan` dispatch.
- Make bare `ls` discover spaces and render role summaries.
- Replace `take`/`fill` with adoption commands.
- Standardize `--select`.
- Apply the small command moves in §3.6.

Exit criterion: removed commands follow the ordinary unknown-command path and
help text contains no old model.

### Phase 5 — S3, MCP, and Hecatia

- Add S3 bucket access mode and safe access-key input.
- Update MCP tool names, descriptions, and structured space results.
- Update both protobuf copies.
- Replace the app's combined space/mirror UI with source and replica/checkout
  UI.
- Update previews, operation registry, protocol tests, and docs.

Exit criterion: all shipped clients expose the same role model and no client
constructs an old Space* or Mirror* request.

### Phase 6 — delete old code and documentation

- Drop legacy mirror schema and runtime code in the migration release.
- Reserve old protobuf fields and remove old handlers.
- Delete obsolete tests rather than translating tests for removed features.
- Rewrite `DESIGN.md` §7/§9 CLI summaries, `docs/REPLICATION.md`,
  `docs/SERVERLESS.md`, `docs/MCP.md`, and implementation notes.
- Update examples, READMEs, shell completions, and screenshots.

Exit criterion: repository-wide searches for old command spellings and mirror
types return only migration history and release notes.

---

## 11. Compatibility, rollout, and non-goals

### 11.1 Cluster wire compatibility

The refactor changes local configuration, storage intent, control RPCs, and
user interfaces. It does not change the cluster's fundamental wire data:

- `FileEntry`, `BlobAd`, trie keys, signed heads, and content roots are
  unchanged;
- the unified tree remains derived from per-origin assertions;
- metadata exchange, provider discovery, bao verification, delegation scope,
  and membership remain unchanged;
- old and new nodes may coexist in one cluster because peers do not negotiate
  local source/replica/checkout configuration.

If replica coverage records expose the strings `tree` or `archive`, update
their local renderer without changing the authenticated meaning on the wire,
or version that record explicitly. Do not make a cosmetic CLI rename split
coverage interpretation across versions.

The control protocol is local to a node and its clients, so the CLI, daemon,
MCP bridge, S3 gateway, and Hecatia must be upgraded together. New protobuf
tags permit a controlled error from an older client; they do not make old
Space*/Mirror* requests meaningful on the new daemon.

### 11.2 Database rollout and downgrade

- Back up the SQLite database before the role-schema migration.
- Take the daemon lock and refuse migration while a daemon owns the database.
- Record the new schema version only after source/replica rows, holders, wants,
  and legacy-mirror state commit together.
- Make every filesystem move or deletion resumable and idempotent; schema
  rollback cannot put deleted checkout files back.
- An older binary must refuse the new schema. Downgrade requires restoring the
  pre-migration database backup; no reverse migration is promised.
- Mixed application versions are unsupported against one data directory.

### 11.3 Explicit non-goals

This refactor does not add:

- cooperative or automatic cluster-wide *k*-replication;
- origin-specific, strict, historical, or multiple replica checkouts;
- a historical directory layout for `forever` replicas;
- automatic promotion of a replica to a publisher after source loss;
- source path relocation or live conversion between filesystem and API source
  kinds;
- bulk tree adoption into an API-only source;
- per-file replica policies or placement rules;
- a full periodic byte-integrity scrub;
- new ACL semantics or changes to delegated read scope;
- compatibility aliases that continue mutating state indefinitely.

These omissions are deliberate. A later feature should be justified against
the two-role model rather than added as another flag to recover removed mirror
combinations.

### 11.4 Main implementation touch points

The expected code surface includes at least:

- `synch-store`: schema migrations, source/replica views, generalized holders
  and wants, CAS failure invalidation, coverage queries;
- `synch-engine`: node construction, scanner/watcher, publisher validation,
  replica loop, checkout reconciliation, adoption, maintenance, cloud routing,
  recovery, path-overlap rules;
- `synch-cli`: Clap definitions, command mapping, daemon task set, control
  protocol and handlers, renderers, MCP tools/resources, integration tests;
- `synch-s3`: bucket persistence and validation, read/write authorization,
  safe access-key input, gateway tests;
- `apps/Hecatia`: protobuf, models, operations, stores, sheets, node/files
  panes, previews, parser and compatibility tests;
- repository documentation and examples: `DESIGN.md`, `REPLICATION.md`,
  `SERVERLESS.md`, `MCP.md`, implementation notes, socket/S3 examples, and
  every command transcript.

Delete `mirror.rs` only after its safe materialization primitives have neutral
homes and all valuable tests have moved. A file deletion is not the milestone;
removing mirror-specific state and behavior is.

---

## 12. Test plan

### 12.1 CLI and control

- Parse every target command and reject conflicting flags.
- Assert no-argument `ls` includes remote-only, source-only, replica-only, and
  source+replica spaces.
- Assert `source rm` never changes replica configuration or holders.
- Assert `replica rm` never changes own entries or source configuration.
- Assert removed commands are rejected by argument parsing.
- Round-trip every new protobuf message; reserve old numeric tags.

### 12.2 Schema migration

- Cover all six source/replica combinations in §8.1.
- Preserve grace, budget, pins, wants, and coverage claims.
- Verify null-path ambiguity becomes an API source and is reported by doctor.
- Verify legacy mirror configuration is dropped without deleting its files.
- Prove migration is idempotent across interruption/restart.

### 12.3 Source invariant

- Filesystem scan: durable blob and source holder exist before the head.
- API PUT and multipart: backend ack -> blob row -> source holder + `f:`/`b:` ->
  client ack.
- Generic staged `f:` with absent or partial content is refused.
- Source deletion/tombstone releases the old holder only after head commit.
- Shared roots remain held while another own path in the space names them.
- Source removal flushes its mass removal and leaves a colocated replica intact.

### 12.4 Healing

- Local payload missing behind a complete row invalidates the row/ad and queues
  source and replica intents.
- Cloud `NotFound` queues every applicable persistent holder.
- A peer restores the root; content is verified, made durable, and advertised
  complete again.
- No provider leaves a durable want with backoff and visible error.
- Read-cache-only loss does not create background work.
- Operator pins continue to fail closed until durable restoration completes.

### 12.5 Replica retention

- `current` fetches every origin's current version, not only `newest`.
- Grace starts when the last current reference leaves.
- A root returning during grace cancels release.
- `forever` never releases observed roots.
- Budgets stop new acquisition but never evict held roots.
- Removing a replica releases its holder by default.
- `--pin-held` converts only complete holdings transactionally.

### 12.6 Checkout

Port the valuable mirror tests, rewritten around one replica checkout:

- initial and incremental convergence;
- newest selection and divergence reporting;
- tombstone/removal behavior;
- symlinks and escape prevention;
- case-folding/reserved-name collisions;
- mtime and mode preservation;
- atomic replacement and interrupted writes;
- unexplained local edits are not clobbered;
- source/checkout overlap refusal;
- restart currency checks;
- selected roots outrank non-selected replica wants;
- incomplete/budget-limited replicas report blocked checkout paths;
- checkout does not publish or create a second holder/fetch path;
- replica removal leaves files unless deletion is explicit.

Delete tests for multiple mirrors, origin-pinned mirrors, strict mirrors, and
mirror-only routing; those features are intentionally gone.

### 12.7 S3 and adoption

- Read-only buckets reject every mutation before reading a body.
- Read-write buckets require a source and read back the local origin's write.
- API-only and filesystem sources both satisfy PUT/multipart durability order.
- Foreign-origin and strict selection are accepted only read-only.
- Access-key secrets never appear in argv-derived output or logs.
- `adopt path` and `adopt tree` publish before returning and respect source
  recovery/ignore/path-safety gates.

### 12.8 End to end

At minimum, run a three-node scenario:

1. node A is a filesystem source;
2. node B is an API source for the same space;
3. node C is a `current` replica with checkout;
4. A and B publish divergent versions;
5. C holds both and checks out the deterministic newest;
6. A loses its CAS object, detects the failure, and repairs from C;
7. C removes its replica while A remains a source; no own entries are changed;
8. a read-only S3 origin view remains readable and rejects writes.

---

## 13. Observability and operator output

`source ls <space>` should report:

- source kind and path, if any;
- own live entry and byte counts;
- last scan and last error;
- staged changes/publisher recovery state;
- missing source-intent roots and oldest repair error.

`replica ls <space>` should report:

- retention, grace, budget, and checkout;
- desired/complete/unreachable object and byte counts;
- oldest want and retry error;
- coverage by origin;
- checkout current/written/blocked/skipped counts and last error;
- whether budget is preventing completion.

`doctor` remains read-only and reports:

- source entries whose storage invariant is broken;
- persistent holders with missing actual content;
- API sources that look like migrated replica-only ambiguity;
- unresolved legacy mirrors;
- checkout overlaps or unmanaged local edits;
- under-replicated spaces and stale coverage claims.

`repair rebuild-views` performs the current mutating rebuild. Repairing missing
content is not a one-shot `doctor` option; persistent intents already own that
work and expose their backlog.

---

## 14. Documentation and naming checklist

Use these terms consistently:

- **space** — cluster namespace string;
- **source** — local publisher role;
- **filesystem source** — scanner/watcher-backed source;
- **API source** — source with no filesystem checkout;
- **replica** — durable all-current-version content role;
- **checkout** — optional newest filesystem projection of a replica;
- **operator pin** — explicit root retention;
- **cache** — non-persistent foreground content;
- **metadata sync** — peer trie/head exchange;
- **replica sync** — content-intent reconciliation and checkout.

Remove these product terms:

- path-backed/detached “space” as a local role;
- mirror and mirror policy;
- replication modes `tree` and `archive`;
- `space sync` for content work;
- “replicate into our tree” — replicas hold CAS objects and a checkout projects
  one view.

Documentation must continue to distinguish metadata replication/read scope
from content retention. Every trusted node may sync metadata without becoming a
content replica.

---

## 15. Completion criteria

The refactor is complete when all of the following hold:

- there is no `synch space` or `synch mirror` command in normal help;
- source and replica configuration are stored and mutated independently;
- one replica may have one newest checkout and no standalone checkout exists;
- removing either role cannot affect the other;
- there is no inactive replica policy with live replica holders;
- every own live file/socket publication is gated on complete durable content;
- evidenced loss of persistent content queues peer repair;
- foreground cache remains non-persistent;
- S3 buckets state read-only versus read-write behavior explicitly;
- the CLI, control protocol, MCP, Hecatia, docs, and examples use the same
  terminology;
- old mirror configuration is explicitly converted or detached, never silently
  expanded into a replica;
- repository-wide tests cover schema migration, teardown independence,
  publication durability, healing, replica retention, and checkout safety.
