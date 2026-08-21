# Replica mode

Status: **proposed**. Nothing below is built. Section 11 is the order it should
land in; each phase is useful on its own, and the first one is worth doing even
if the rest is never built.

## 1. Problem

A node holds bytes for one of three reasons, and none of them is durability.

- **It published them.** The scanner indexed a local file, so the CAS holds its
  content and `entries` names it. Delete the file and the entry becomes a
  tombstone; the object is then unreferenced and `gc_content` takes it.
- **Something read them.** `synch get`, `synch cat`, an S3 range read, a mirror
  pass. The object survives `root_retention` — seven days by default
  (`NodeConfig::root_retention`) — and then goes, because `last_access` is
  stamped on ingest and download milestones and deliberately *not* on reads
  (`Store::gc_content`). Streaming an object hourly does not keep it.
- **Somebody pinned it.** `synch pin add` marks one root, by hand, one at a
  time.

So the cluster's retention story is: every version currently named by some
origin's entries is held *by the origins that published it*, and everything else
is held by whoever happened to touch it recently. Remove the member that
published a path and the last copy can leave with it. Nothing in the design
holds a second copy of a live path on purpose, and nothing can be asked to.

That is a reasonable default for a laptop and a wrong one for the machine in the
rack whose job is to still have things. The mechanism such a machine needs
already exists — content GC is reference- and pin-driven, and `BlobAd` records
make availability cluster-visible (§6.3) — but there is no way to say *hold all
of this*, and no way to see whether anybody is.

The gap is named in DESIGN.md §13 as future work ("smarter placement policies,
built on the same `BlobAd` availability data"). This document proposes the node
role first and the placement policy last, because the role is the part that is
both useful alone and hard to get wrong later.

## 2. What replica mode is

**A replica is a node that holds a whole copy of every version the unified tree
currently names, for the spaces it replicates.** Every origin's version of every
path — not the one a policy would select — fetched as it appears, held whole,
served to anyone. It materializes nothing onto the filesystem and publishes no
spaces of its own.

| | selects | holds | releases when |
|---|---|---|---|
| **mirror** (§7.2) | one version per path, by policy | files on disk, plus the CAS objects behind them | the tree stops naming the path |
| **pin** (§9.2) | one object root, named by hand | that object | an operator says so |
| **replica** | every version of every path, all origins | every object under them | the tree stops naming it, plus a grace window |

A mirror is a *view* of the tree, one version deep, on the filesystem. A pin is
possession of one named thing. A replica is possession of everything the tree
points at — which is a set that shrinks as well as grows.

**The word, since the design already spends it twice.** §5.5's *scoped
replication* is about how much of a peer's **trie** a node is entitled to read;
this is about how much of the cluster's **content** a node chooses to hold. They
compose — a delegated replica replicates the spaces its scope admits and no
others — and neither implies the other: a node with an unrestricted scope holds
no more bytes for it, and a replica of one space needs no scope beyond that
space. Where both are in play, this document says *read scope* for the first and
*replica* for the second.

### 2.1 The tree decides, not the replica

The retention rule is the whole design and it is one sentence:

> **A replica holds exactly the content some origin's current trie references,
> plus a grace window after a root falls out.**

Content that no origin's current entry names is garbage in a replica for the
same reason it is garbage on a laptop. The alternative — hold every version ever
observed, release nothing — was the first draft of this document, and it is
wrong in three ways that matter:

- **It does not converge.** Holding every version forever costs the integral of
  the cluster's churn, not the size of its tree, and that integral has no limit.
  A replica under that rule is a machine that eventually stops, and the date it
  stops is a function of how much other people write. §9 has the arithmetic.
- **It confuses two jobs.** "Nothing is lost when a member dies" and "every
  version is recoverable forever" are different products with different costs.
  The first is what the cluster structurally lacks and what a second copy
  actually buys. The second is a backup policy, and one an operator should have
  to ask for by name.
- **It fights the existing machinery instead of using it.** `gc_content` already
  computes "referenced by any current entry" — `referenced_content()` is
  `SELECT DISTINCT content FROM entries`, over every origin's materialized
  leaves. A replica whose rule is the tree's rule inherits a GC pass that is
  already written, already transactional, and already correct against a
  concurrent fetch.

So replica mode is a **fetch** policy far more than it is a retention policy.
What it adds is: fetch everything referenced rather than only what someone reads,
hold it whole rather than in the ranges a read happened to want, and release it
on a schedule the operator sets rather than on the `root_retention` clock that
happens to govern a read cache.

Two policies, then, and the second is the opt-in:

- **`tree`** (default) — the rule above. Storage tracks the size of the tree.
- **`archive`** — release nothing, ever. The archive of record, for deployments
  that want one and have costed it. Everything in this document applies except
  the release path.

### 2.2 What a replica does and does not protect against

Worth stating plainly at the top. The name now says what the default does — a
replica of the tree, not a record of its past — but the question an operator
actually arrives with is "so this is our backup, right?", and the honest answer
has two halves.

**It protects against loss of a node.** A member's disk dies, a laptop is
stolen, a VM is deleted, a member is removed from the zone: every path it
published is still held whole by the replica, and the replica advertises it, so
the swarm keeps serving it. This is the failure the cluster currently has no
answer to, and it is the common one.

**It does not protect against deletion.** A member deleting a path publishes a
tombstone; the content stops being referenced; the replica releases it when the
grace window expires. Ransomware that rewrites a member's files in place is the
same event wearing a different hat. **The grace window is the entire recovery
story under the `tree` policy**, so it should be set to the longest "oh no"
interval the deployment believes in — thirty days is a defensible default,
seven is not — and a deployment that wants deletion-proof retention runs
`--policy archive` and pays for it.

Saying this in the documentation is not enough; `synch replicate add` should print
it, and `replicate status` should show the grace window beside the held size,
because the number that matters is the one an operator sees the day they need it.

## 3. Design

### 3.1 A replica's pins are leases

Content the replica is holding must be pinned. It cannot ride on
`referenced_content` alone even though the rule is the same, for two reasons:
the grace window means the replica holds roots the tree no longer references,
and the ordinary retention clock is measured from the wrong event —
`last_access` is stamped when an object is *written*, so an object fetched a
year ago and superseded today is already cold and would go on the next pass with
no grace at all.

So the replica pins what it holds, and the pin carries its own expiry:

```sql
-- schema v20
CREATE TABLE pins (
  root          BLOB NOT NULL,
  holder        TEXT NOT NULL,       -- 'operator' | 'replica:<space>'
  created_at    INTEGER NOT NULL,
  release_after INTEGER,             -- NULL = held; set = leaving at this instant
  PRIMARY KEY (root, holder)
);
CREATE INDEX pins_by_release ON pins (release_after) WHERE release_after IS NOT NULL;
```

A holder column rather than the current boolean, because the boolean cannot
answer the only question that matters on release — *may these bytes go now?* —
once more than one thing holds a root. Three cases make that concrete: an
operator pins a root by hand and a replica later covers it; two replicated spaces
name the same content, which deduplicates to one object (`entries_by_content` is
indexed for exactly this); and a release under the `tree` policy must drop one
claim without touching another's.

Pinnedness becomes derived rather than stored — a denormalized copy of it would
be a second source of truth for a question with one right answer. The predicate
inside `delete_blob_if_collectable` changes from `pinned = 0` to a `NOT EXISTS`
over live `pins` rows, keeping the property that makes it correct today: it is
re-read inside the immediate transaction that does the delete, so a pin landing
between the candidate snapshot and the delete decides the delete. The migration
backfills `('operator', NULL)` for every `pinned != 0` row and drops the column.

`synch pin rm` removes the `operator` holder only, and reports what remains:

```
$ synch pin rm media/talks/keynote.mp4
unpinned 9f86d081… (still held by replica:media until 2026-09-20)
```

**Want is intent; a pin is possession.** A replica that has decided it needs an
object it does not hold must not write a pin row for it — a pin whose bytes are
absent makes `pin ls` a list of claims rather than of contents. Intent lives in
its own table and becomes a pin in the transaction that retires it (§3.3).

### 3.2 Configuration: one row per replicated space

```sql
CREATE TABLE replicas (
  space    TEXT PRIMARY KEY,
  policy   TEXT NOT NULL,          -- 'tree' | 'archive'
  grace    INTEGER NOT NULL,       -- seconds a released root is still held
  budget   INTEGER,                -- optional byte ceiling, NULL for none
  added_at INTEGER NOT NULL
);
```

Per space, not per node, for the reason mirrors are per directory: "replicate
everything this node can see" is expressible by adding every space, while a
node-wide flag would silently enrol spaces admitted later. A delegated replica
can only add spaces its scope covers, which `materialization_scope` already
decides — there is no path around it and none is added.

### 3.3 The want queue, resurrected

Schema v3 dropped a `want(root, ranges, priority, reason)` table. Replica mode
needs it back, in a shape fitted to this job:

```sql
CREATE TABLE replica_want (
  root         BLOB NOT NULL,
  holder       TEXT NOT NULL,      -- 'replica:<space>', same shape as pins.holder
  size         INTEGER NOT NULL,
  prev         BLOB,               -- donor hint: the root this version replaced
  first_wanted INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_attempt INTEGER,
  last_error   TEXT,
  PRIMARY KEY (root, holder)
);
```

`size` and `prev` are carried because the fetch needs both and neither survives
the entry. `fetch_all_from` fetches *by* size — a bare root nobody holds even
partially has none, which is the case `pin_object` refuses outright — and `prev`
is the delta donor: `Node::donors_for` derives donors from the selected entry's
`prev` and from the other versions in the set, and by the time the fetch loop
reaches a want row those rows may be gone.

Three properties earn a table rather than an in-memory queue:

- **Durable intent.** A promotion diff naming four million roots is staged in
  one transaction and fetched over days. Losing that on restart means
  rediscovering it by full sweep every time.
- **A place for failure to accumulate.** `attempts`, `last_attempt` and
  `last_error` turn "the replica is behind" into "these 14 objects have had no
  provider for six days", which is the alarm the whole feature exists to raise
  (§8).
- **Backpressure.** Staging must be one insert per changed leaf and nothing
  else; fetching is a separate loop with its own concurrency.

**Want rows self-clean.** A root that leaves the tree before the fetch loop
reaches it is dropped from the queue rather than fetched and then released —
which is both the cheaper order and the one that stops a churning path from
generating permanent false entries in the `unreachable` count.

**Priority is rarest-first.** Order by the number of distinct origins
advertising a complete `BlobAd` for the root (`blob_providers`), ascending, then
by `first_wanted`. A replica exists to raise the floor on the number of copies,
so the object with one advertised holder is worth more than the object with
nine — and it is the one about to be lost when that holder leaves. Ties go to
the oldest want, so nothing starves.

### 3.4 Two sources of work, and only one may release

**Live: the promotion diff.** `Syncer::try_promote` flips a head to complete
inside one transaction that also calls `materialize_diff`, which streams every
resolved change under the origin's scope into `entries`. Replica mode adds one
step to `apply_change`'s `f:` arm, in that same transaction:

- A change carrying a content root in a replicated space **stages a want** — or,
  if the root is already pinned with a `release_after` set, clears it. Content
  that comes back is content that stays: the same root can reappear because
  another origin still published it, because a `take` adopted it, or because a
  file was restored from a copy.
- A change that *replaces or removes* a root **sets `release_after = now +
  grace`** on the replica's pin for the old root — but only after confirming no
  other current entry still names it. The check is one indexed lookup
  (`entries_by_content`) and it is what makes deduplication safe: two paths
  sharing content release when the second one goes, not the first.

In the same transaction as the head flip, deliberately. A want row that can be
lost while the entry row lands is a version that goes unfetched with nothing
recording that it was ever wanted, and a release that lands while the entry row
does not is bytes leaving on the strength of a change that did not happen. The
argument is the one `gc_trie` already makes about splitting its own pass: this
is not tidiness, it is where the data loss is.

**Reconciling: a periodic sweep.** A standing loop, in the mould of the mirror
loop (its own interval, rung early by the same promotion bell). It walks
`entries` for replicated spaces and stages a want for every content root with no
pin and no want row. It covers a space added after the fact, promotions that
happened while replica mode was off, a views rebuild, and whatever the live path
gets wrong.

The sweep may **stage**, and it may **release only under §3.6**. Staging from
absence is safe — the worst case is fetching something already held. Releasing
from absence is not, and that asymmetry is the next section.

### 3.5 The fetch loop

A third standing task, separate from both, because it is the only one that
touches the network and the only one that should be rate-limited:

1. Take up to `replica_concurrency` want rows in priority order, skipping rows
   inside a backoff derived from `attempts`.
2. `fetch_all_from(root, size, donors)` — the ordinary §6.4 path, so delta
   descent, provider fanout and resumption apply unchanged. This is the best
   case for the descent and a replica hits it constantly: it is fetching
   version *n+1* of a file whose version *n* it is guaranteed to hold.
3. On completion: delete the want row and insert the pin row, in one
   transaction.
4. On failure: increment `attempts`, record `last_error`, leave the row.

Between the fetch's last commit and the pin insert the object is complete,
possibly unreferenced, and unpinned. It survives the window for the reason
`pin_object` already relies on — the fetch stamped `last_access`, so the
retention test holds it — and that deserves a test that runs a GC pass inside
the window rather than a paragraph asserting it.

### 3.6 Eviction discipline: absence is not evidence

A replica's eviction is the ordinary `gc_content` pass. What replica mode adds
is a rule about **who is allowed to conclude that a root left the tree**, and it
is the one piece of this design that has to be right.

> A release is driven by an **observed change**. Absence of a reference is not,
> by itself, evidence that a reference was removed.

The live path (§3.4) always has positive evidence: a diff said this leaf
changed, and the lookup said nothing else names the old root. The sweep has only
absence — `entries` does not name this root *now* — and there are at least three
routine ways for `entries` to stop naming something that is not a deletion:

- **`Store::set_read_scope`.** A scope change throws away every foreign origin's
  `entries` and `blob_providers` rows by design and drops every foreign complete
  head back to pending, because derived state whose premise changed is
  discarded rather than reconciled. For a moment the replica's view of the tree
  is *empty*. An absence-driven release at that moment would evict the entire
  store.
- **`Store::rematerialize`** (`synch doctor --rebuild`). Deletes an origin's
  entries and rebuilds them from the trie. The comment on it already records
  that a mirror pass reading in that window unlinks the user's files; a GC pass
  reading in that window would do the same to the CAS.
- **A member removed, a binding lapsed, an origin not yet synced.** The rows are
  gone or were never there. The content is not garbage; this node's knowledge is
  incomplete.

So the sweep may release only from a **complete view**, and all three
preconditions are locally checkable:

1. Every origin with a live binding has a complete head materialized — none
   sitting pending, none stale beyond a threshold.
2. The read scope has not changed since the last successful anti-entropy round
   with each peer.
3. No rebuild is in flight.

If any fails, the sweep stages as usual and releases nothing, and says why in
`replicate status` and `synch doctor`. Holding too much for a day is a cost;
releasing the last copy of something is not recoverable, and the asymmetry
should be visible in the code as plainly as it is here.

Two further brakes, both strictly conservative:

- **Under-replication delays a release.** A replica that is about to let a root
  go may check how many distinct origins advertise a complete `BlobAd` for it
  and hold on if the answer is too few. This uses peers' claims only to *keep*
  bytes, never to drop them, which is the safe half of §4.2's invariant.
- **A release is never a delete.** Setting `release_after` schedules the pin's
  removal; the object then faces the ordinary GC rule like anything else. If a
  current entry still names it — because another origin published the same
  bytes — it stays, and nothing special had to notice.

### 3.7 History: roots without bytes

Under the `tree` policy a replica is not a time machine, and the documentation
should not let anyone believe otherwise. `synch log` will keep showing every
version's seq and content root for as long as the retained head history goes
back, and the *bytes* of superseded versions will be gone once grace expires.
Roots without bytes.

That is the correct trade for the default and it is worth being loud about,
because the failure is silent: the log looks complete, and the read fails.
`synch log` should mark which versions the local store can still serve.

Head history is still worth retaining longer on a replica than on a laptop —
it is what `synch log`, fork evidence (§4.4) and the whole provenance story rest
on, and trie nodes are small beside content. But it is now a separate decision
from content retention rather than the same one, and `root_retention` keeps its
current job.

Which leaves a gap in the CLI either way. There is no read-by-root: `synch log`
prints content roots, `synch pin add <root>` is the only command that takes one,
and DESIGN.md §8 says reading an old version back "is done by content root, not
by a time-travel flag" — but nothing implements the former. `synch cat --root
<hex>` and `synch get --root <hex>` are small (the fetch and verify paths are
root-keyed already), and without them a `--policy archive` replica is a machine
holding history nobody can read.

### 3.8 The budget, and what "full" does

`replicas.budget` is an optional ceiling on bytes held for a space. When it is
reached the fetch loop stops taking new work for that space, want rows stay —
they are the record of what is missing, and dropping them converts a storage
problem into a silent data-loss problem — and `replicate status` and `synch
doctor` report the shortfall in objects and bytes.

**Reaching the budget never accelerates a release.** Under `tree` the release
schedule is the tree's, not the disk's; a replica that shortened its grace
window because it was full would drop the recovery story exactly when the
operator was least likely to be watching. Full means "stopped taking new
things, loudly", and the remedy is more disk or a shorter configured grace, both
of which are decisions rather than side effects.

An object larger than the remaining budget is skipped, not dropped: it stays
wanted and is retried when the budget rises.

## 4. The network-wide half

Two questions get confused here and only one of them is answerable.

### 4.1 Coverage is publishable

A replica may declare what it replicates, in its own signed trie, under a new
key prefix:

```
r:<space>   ->   ReplicaClaim { v, since_ns, policy, grace, objects, bytes, complete }
```

A new prefix rather than a field on `SpaceInfo` (`m:space/<id>`), for
compatibility rather than taste. postcard is not self-describing and every
record carries a version stamp checked with `v <= RECORD_VERSION`, so appending
a field to `SpaceInfo` means bumping the stamp and having every 0.1.x node
*refuse* the record — a flag day for a feature that should be additive. An
unknown key prefix already falls through `apply_change` to `Ok(())`: existing
builds ignore `r:` records and keep materializing everything else in the trie.

For a delegate, `r:` must be added to `publish_prefixes` for its granted spaces
and to the read scope, or a delegated replica cannot claim what it replicates.
The argument is the one already made for `b:` — a delegate that holds content
must be able to say so, or the swarm loses a source.

With claims published, `replicate status` can answer the question an operator
actually asks — *is anything replicating `media`, with what grace, and how far
behind is it?* — across the cluster rather than on one box.

### 4.2 Enforcement is not

No node can make another node retain anything, and this design does not pretend
otherwise. A claim is an assertion by a member, in the sense §12 already accepts
for `mtime_ns` and for `BlobAd`: a member with a full disk, a bug, or bad intent
can claim coverage it does not have. Hence:

> **A peer's claim may order this node's work, and may cause it to keep bytes.
> It may never cause it to drop them.**

Rarest-first (§3.3) uses provider counts to decide what to fetch first;
under-replication (§3.6) uses them to *delay* a release. Neither direction lets
another node's statement shorten this node's holdings. A replica that trusted
claims for release decisions would hand any member the ability to talk the
cluster's last copy out of existence, through the same door that a plain bug in
somebody's disk-full handling opens.

### 4.3 Cooperative k-replication, deferred

The obvious next step — several replicas sharing a space, each holding a subset,
targeting *k* copies cluster-wide — is DESIGN.md §13's "keep ≥ 2 replicas of
every object cluster-wide", and it should wait until single-node replication has
run somewhere for a while.

The mechanism is available (`blob_providers` carries per-origin complete and
partial spans). The hazard is specific and worth writing down before anyone
implements it: *k* as a **floor on fetching** is safe, and *k* as a **licence to
release** is how a pool of replicas converges on zero copies — every member
observing that "the others have it" at the same moment the others observe the
same thing, and all of them wrong together during a partition. Deployments that
want a hard floor run replicas on every machine they are willing to pay for and
count them.

## 5. Configuration

| knob | default | what it is |
|---|---|---|
| `replicas.policy` | `tree` | per space: `tree` (release with the tree) or `archive` (never release) |
| `replicas.grace` | 30 d | how long a root outlives the last entry naming it |
| `replicas.budget` | none | per space byte ceiling; stops fetching, never evicts |
| `replica_interval` | 300 s | reconciling sweep backstop; the promotion bell rings it early |
| `replica_concurrency` | 4 | concurrent object fetches for replica work |
| `replica_backoff` | 60 s … 6 h | per-want retry schedule, exponential in `attempts` |
| `root_retention` | 7 d | unchanged; head history depth, now independent of content |

Replica fetches share the endpoint with anti-entropy and with foreground reads,
and nothing schedules between them today — DESIGN.md §13 lists bandwidth QoS as
future work. `replica_concurrency` is the crude lever in the meantime, and its
default is deliberately low: a replica that saturates the link it shares with
the cluster's actual users is a worse problem than one that converges overnight.

## 6. CLI surface

```
synch replicate add <space> [--policy tree|archive] [--grace <dur>] [--budget <size>]
synch replicate rm <space> [--release]
synch replicate ls
synch replicate status [<space>] [--json]
synch replicate sync                     run a reconciling sweep now
```

`replicate rm` keeps the pins by default and `--release` drops them, because
releasing terabytes should not follow from typing the opposite of `add`.

`replicate status` is the whole operator interface, and should read like an
answer:

```
media   policy tree   grace 30d   since 2026-03-04
  held          412,880 objects   6.02 TiB   (covers every version in the tree)
  releasing       1,204 objects  31.7 GiB   (oldest leaves in 3d)
  wanted            412 objects  10.4 GiB   (oldest 4m ago)
  unreachable        14 objects   2.1 GiB   ← no provider for 6d
  view          complete — releases are running
  claims        nas@cluster.example.com (complete), vps@… (99.4%, claimed)
```

Three of those lines exist to be read on a bad day. `unreachable` must never be
folded into `wanted`: fourteen objects with no provider for six days is not a
backlog, it is fourteen versions that are probably already gone. `releasing` is
what an operator checks before deleting something they may want back. And
`view` says whether §3.6's preconditions hold, because "releases are paused" is
the difference between a replica that is behaving and one that is broken.

## 7. What this deliberately does not do

- **No filesystem materialization.** A replica holds objects, not a directory
  tree. An operator who wants both runs a mirror beside it, and the mirror's
  reflink write means the tree costs no second copy of the bytes
  (`docs/DELTA-SYNC.md` §3.5).
- **No protection against deletion beyond the grace window**, under the default
  policy. §2.2.
- **No eviction to make room.** Storage pressure stops fetching; it never
  shortens a release (§3.8).
- **No release from absence of knowledge.** §3.6.
- **No erasure coding, no partial-object placement.** The unit is the object and
  the copy is whole.
- **No cross-cluster federation.** A replica replicates spaces of its own
  cluster under its own membership.
- **No retention override of the trust rules.** A delegated replica replicates
  its granted spaces, because `materialization_scope` decides what its `entries`
  ever contained.

## 8. Failure modes

- **Content nobody serves.** A want row failing with "no provider" past the
  alarm threshold means the last holder left before the replica reached it.
  Nothing can be done about it, so the value is entirely in saying so early —
  `replicate status`, `synch doctor`, a warning per retry. The realistic
  mitigations are operational: replicas that are up when members are, and more
  than one of them.
- **A partitioned or lagging replica.** Its view is incomplete, so §3.6 pauses
  releases. It keeps fetching and keeps holding; it just stops making
  irreversible decisions. This is the failure the discipline exists for and it
  should be exercised by a test that partitions a node mid-sweep.
- **A scope change or a rebuild.** Both empty `entries` transiently or by
  design. Releases pause (§3.6); staging continues and re-derives.
- **A member deletes everything.** The replica follows, after grace. This is
  intended under `tree` and is why `--grace` is not a small decision. A
  deployment that treats this as unacceptable runs `--policy archive`.
- **A member fills the replica.** Any member can publish content and every
  replica of that space fetches it. That is the membership trust model working
  as designed (§12: members are trusted to publish), but it argues for
  `--budget` on any replica facing a large membership, and for a per-origin byte
  breakdown in `replicate status` so the operator can see whose content grew.
- **Clock skew.** `release_after` is an instant, so a backwards clock delays
  releases and a forwards one advances them. It should be compared against
  `Store::read_instant` rather than the bare clock, for the reason mirror passes
  already do, and a release should never fire from a reading the trust floor
  rejects.
- **The replica is also a publisher.** Benign — its own content is referenced by
  its own entries. Worth a test, not a rule.

## 9. Cost model

The `tree` policy is what makes this arithmetic tractable, and the comparison
with the alternative is the argument for it.

Take a cluster with 8 TiB of current content across 40 members, 2% of paths
rewritten daily, average rewritten object 40 MiB — so roughly 160 GiB of new
roots a day.

| policy | steady state after a year |
|---|---|
| `tree`, grace 7 d | ≈ 8 TiB + 7 × 160 GiB ≈ 9.1 TiB, flat |
| `tree`, grace 30 d | ≈ 8 TiB + 30 × 160 GiB ≈ 12.7 TiB, flat |
| `archive` | 8 TiB + 365 × 160 GiB ≈ 65 TiB, still climbing |

`tree` converges: it costs the tree plus one grace window of churn, and adding
a year changes nothing. `archive` costs the integral of churn and has no steady
state at all — which is what "keep every version forever" means, and some
deployments genuinely want it, but it should be chosen with that table in front
of the operator. `replicate add --policy archive` should print the current tree
size and the last 30 days' observed churn before it agrees.

Note that the tree is larger than "the size of the data": every origin's version
of every divergent path is held, because all of them are current. A cluster with
substantial two-way sharing pays for both sides of every divergence until it is
resolved — which is correct, and is also the state `synch status` exists to make
visible.

Delta sync helps the network and not the disk. Fetching version *n+1* of a file
whose version *n* is held is the best case for the descent
(`docs/DELTA-SYNC.md` §3.3), so a replica's *bandwidth* tracks changed spans
while its *storage* tracks whole objects. Whether the promotion path could clone
shared extents into the new payload — turning storage into changed spans too, on
filesystems that support it — is the largest available improvement to this table
and is unexplored (§12).

## 10. Security

- **A replica is a concentrated target.** It holds a whole copy of every
  version of everything in its spaces. At-rest encryption remains delegated to
  OS disk encryption (§12) and per-space content keys remain future work; a
  replica is a strong argument for finishing them.
- **A deleted file survives the grace window.** Under `tree` that is bounded and
  stated; under `archive` a deletion never removes the bytes at all, which
  operators with deletion obligations must know before they choose it. This is
  the strongest argument for `tree` being the default: the surprising behaviour
  should be the one you opt into.
- **Claims are assertions.** §4.2. `replicate status` renders peer claims as
  claims ("nas says complete"), never as verified coverage.
- **Scope holds.** A delegated replica replicates what it may read, and replica
  mode adds no path around `materialization_scope`.
- **Eviction is the dangerous verb.** Every code path that can set
  `release_after` should be countable on one hand and each should be justified
  where it is written, in the manner of `delete_blob_if_collectable`. A bug in
  the fetch path costs bandwidth; a bug in the release path costs the data.

## 11. Implementation map

Phases in dependency order. Each lands on its own and leaves the tree working.

1. **Pin holders and leases.** `pins` table, migration v20, GC predicate becomes
   `NOT EXISTS`, `pin ls`/`pin rm` report holders and pending releases. No new
   behavior; everything after this depends on it.
2. **Read by root.** `synch cat --root`, `synch get --root`. Independent,
   useful immediately, and what makes a replica's contents reachable.
3. **The replica, sweep-driven, hold-only.** `replicas` table, `replica_want`,
   the reconciling sweep, the fetch loop, `replicate add|rm|ls|status|sync`.
   Policy `archive` semantics — nothing is released yet — so the risky half is
   absent while the fetching half is proven.
4. **The live path.** Staging and release-scheduling from `apply_change` inside
   the promotion transaction, plus the `entries_by_content` check that makes
   deduplication safe.
5. **Release, with the discipline.** `tree` policy, grace, the §3.6
   preconditions, `view` in `replicate status`, and the partition test. This is
   the phase to be slow about.
6. **Budget and reporting.** `--budget`, per-origin breakdown, doctor lines.
7. **Claims.** The `r:` prefix, `ReplicaClaim`, `publish_prefixes` for
   delegates, peer coverage in `replicate status`.
8. **Under-replication brake**, then **cooperative k-replication** (§4.3) — the
   two that should wait for operational experience.

## 12. Open questions

- **Extent sharing between versions.** A replica holds *n* and *n+1* of a large
  object whose difference is small, and the descent already knows which spans
  were promoted from the donor. Cloning those extents rather than copying them
  would change §9's storage column from whole objects to changed spans on
  filesystems that support it.
- **How stale is "stale" in §3.6?** The completeness precondition needs a
  threshold for how far behind an origin's head may be before releases pause. Too
  tight and a replica with one flaky peer never releases anything; too loose and
  the precondition stops meaning much.
- **Should replicas be preferred providers?** They hold everything, so ranking
  them first in `providers_for` makes cold reads fast and points every cold read
  in the cluster at one machine. Probably "prefer them last, as the backstop that
  always has it", but it needs measuring.
- **Claim granularity.** `ReplicaClaim` carries counts. A per-space digest that
  let two replicas compare coverage without enumerating objects would make §4.3
  much easier, and looks like it wants to be a trie of its own.
- **What `replicate add` should refuse.** A space whose current size already
  exceeds free disk is an error at `add` time, not a surprise at 3am. The check
  is easy; the policy for "it fits now and will not in a month" is not.
