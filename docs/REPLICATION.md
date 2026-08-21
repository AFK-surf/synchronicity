# Replication

Status: **implemented** through §11 phase 9, except cooperative
*k*-replication, which §4.3 deliberately defers until single-node replication
has run somewhere for a while — the hazard that makes it worth waiting for is
written down there. Everything else is built: pin holders and leases, read by
root, the `spaces` columns and their commands, the sweep, the fetch loop, the
live path, release with the discipline, budget and reporting, published
coverage claims, and the under-replication brake. Where the built thing differs
from what was proposed, this document has been corrected to describe the built
thing.

Checked against `09d89a3` (OpenDAL CAS backends, `docs/SERVERLESS.md`). That
work moved three things this design leaned on — `spaces.local_path` is already
nullable, `blobs` carries a `durable` column, and a cloud-backed CAS never
deletes its final objects — and each is marked below where it lands.

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
built on the same `BlobAd` availability data"). This document proposes the
per-space role first and the cluster-wide placement policy last, because the
role is the part that is both useful alone and hard to get wrong later.

## 2. What replication is

**A replica is a node that holds a whole copy of every version the unified tree
currently names, for the spaces it replicates.** Every origin's version of every
path — not the one a policy would select — fetched as it appears, held whole,
served to anyone. Replicating is not publishing and not materializing: a node
may replicate a space it also indexes a directory for, or one it has no
directory for at all (§3.2), and replication itself writes no files and
publishes no entries either way.

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
  stops is a function of how much other people write. §9 has the arithmetic —
  and §9.1 the one backend where releasing does not win the bill back.
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

So replication here is a **fetch** policy far more than it is a retention
policy.
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

Saying this in the documentation is not enough; `space add --replicate` should
print it, and `space ls` should show the grace window beside the held size,
because the number that matters is the one an operator sees the day they need
it.

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

**Possession now has two meanings, and a pin already picks the right one.**
Since `09d89a3` a node's CAS is either `LocalFs` or an OpenDAL cloud store, and
`blobs.durable` records the backend's stable-storage promise separately from
`complete`, which is only cache availability. `Node::pin_object` already
resolves this: it calls `finalize_cloud_object` before `set_pinned`, so a pin
returns only once `durable = 1` — "a pin is a durability promise, and on this
backend durability means the configured cloud service"
(`docs/SERVERLESS.md` §6.3). A replica's pins inherit that rule and its
ordering: **finalize, then pin**, never the reverse (§3.5).

One good consequence falls out and needs no new configuration. The cloud
upload policy `own+pinned` — the default — promotes locally ingested content
plus everything pinned here. A replica pins everything it holds, so a
cloud-backed replica is durably covering its spaces under the default policy
already. `cas.cloud.upload = all` stays what it is for: a node that wants
durable coverage *without* pinning.

### 3.2 Replication is a property of a space

Cardinality decides where this lives. A mirror is keyed by *directory* — many
mirrors of one space, each with its own root and its own version policy — so
`mirrors` is its own table and `synch mirror` is its own noun, correctly.
Replication is one per space, so its natural primary key is the space id, which
is already the primary key of `spaces`. A table whose primary key is another
table's primary key is a column on that table.

So there is no `replicas` table and no `synch replicate` command, and — since
`09d89a3` — no table rebuild either. The serverless work already made a
`spaces` row mean what this needs it to mean.

**What that work already settled.** `spaces.local_path` is nullable today
(`NULL = detached`, V20), `synch space add <id> --detached` exists, `SpaceRow`
carries `Option<String>`, and the scanner, the watcher and the overlap guards
already skip a row with no root. An earlier draft of this section proposed all
of that as new work and argued for it at length; it is built, for a different
reason — a serverless node publishing into a space it holds no checkout of —
and the reasoning transfers intact. A `spaces` row already means "this node's
participation in this space" rather than "a directory I walk".

So the change is three columns:

```sql
-- schema v21 (v20 is the serverless foundation)
ALTER TABLE spaces ADD COLUMN replicate TEXT;    -- NULL | 'tree' | 'archive'
ALTER TABLE spaces ADD COLUMN grace     INTEGER; -- seconds; NULL under 'archive'
ALTER TABLE spaces ADD COLUMN budget    INTEGER; -- optional byte ceiling
```

`--replicate` and `--detached` are orthogonal, and the four combinations are all
meaningful: a path with no replication is today's ordinary space; a path with
replication is the durable-disk node that publishes its own copy and holds
everyone else's; detached with replication is the dedicated replica; detached
without it is the serverless write target that already exists. In the CLI
`--replicate` joins `--detached` in `required_unless_present` for the path
argument, and a path-less replicated space *is* detached — there is no third
state to name.

Two corrections to what an earlier draft claimed here, both from reading the
merged code rather than the older tree:

- **The cloud attach's space list must not skip a path-less row.** `held_spaces`
  maps every `spaces()` row plus every mirror, and its comment says why: a node
  that only mirrors a space is routable for it rather than a bystander. A
  detached or replicate-only space is servable for the same reason and should
  count for the same reason. The earlier draft had this backwards.
- **`m:space/<id>` no longer publishes the local path.** `space_info_changes`
  now sends `description: String::new()` for every space — "local paths are
  host-private implementation details" — so half the argument for suppressing
  the record on a replicate-only space was gone before this was built, fixed
  upstream and more broadly. The other half is implemented: the record still
  carries this origin's `entry_count`, which is permanently zero where the row
  exists only to replicate, so a zero record would claim a space this node
  publishes nothing into. `publishes_into` — a checkout, or an entry of our own,
  which is how a detached write target qualifies without one — gates both the
  advertisement and its withdrawal, so what is advertised and what `space rm`
  takes back cannot drift apart. That shared predicate is not decoration: had
  only the tombstone scan been skipped, a replicate-only space would have
  advertised an `m:space` record that `space rm` then stranded in the trie.

One decision does survive intact, and it is the sharp one:

- **`Node::remove_space` is an unpublish, and must not be one here.** It stages
  a tombstone for every key under the space prefix, removes the `m:space/<id>`
  record, and calls `ensure_publishable()` first — unchanged by `09d89a3`. That
  is right for a detached *write target*, which does publish entries. On a space
  this node only replicates there is nothing of its own under that prefix, so
  the loop stages nothing and the outcome is correct *by accident*. That is not
  good enough for the one command in this design that can publish a mass
  deletion: it must branch on which halves are configured, and a space that was
  only ever replicated must not reach `ensure_publishable()` at all (§8).

A space can also now be added twice over, in either order — indexed first and
replicated later, or replicated first and a directory attached afterwards. Both
are ordinary `space set` calls, and the second must not disturb what the first
established.

### 3.3 The want queue, resurrected

Schema v3 dropped a `want(root, ranges, priority, reason)` table. Replication
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

**Priority is rarest-first *within a space*, and a turn each between them.**
Rarity orders by the number of *other* origins advertising a complete `BlobAd`
for the root (`blob_providers`), ascending, then by `first_wanted`. A replica
exists to raise the floor on the number of copies, so the object with one
advertised holder is worth more than the object with nine — and it is the one
about to be lost when that holder leaves. Ties go to the oldest want. The count
excludes this node's own advertisement: a node advertises its `b:` records like
any other origin, so counting itself answers "does anyone else have this?" with
"I do", and the §3.6 release floor would never engage.

Ranking the *pooled* candidates globally is what this section first specified,
and it starves. A space bootstrapping four million equally rare objects sorts
ahead of every newer want in every other space, so a space added afterwards
fetches nothing until the first one drains. Rarity is the right order within a
space; between spaces the only defensible order is a turn each. So each
replicated space contributes its own rarest-first window, the windows are
interleaved one row at a time, and — because the fetch loop admits only the
first `replica_concurrency` rows of that interleave, and spaces are listed by
id — which space leads advances by one per pass. Every space gets the lead
within one turn of the list.

Rarity is ranked over a bounded window rather than the queue: the oldest ready
rows per space, `RARITY_WINDOW` per concurrency slot. That is enough for a rare
object in a batch to win without a pass costing one provider count per queued
row, which on a four-million-row queue is the whole feature's cost model.

### 3.4 Two sources of work, and only one may release

**Live: the promotion diff.** `Syncer::try_promote` flips a head to complete
inside one transaction that also calls `materialize_diff`, which streams every
resolved change under the origin's scope into `entries`. Replication adds one
step to `apply_change`'s `f:` arm, in that same transaction:

- A change carrying a content root in a replicated space **stages a want** — or,
  if the root is already pinned with a `release_after` set, clears it. Content
  that comes back is content that stays: the same root can reappear because
  another origin still published it, because a `take` adopted it, or because a
  file was restored from a copy.
- A change that *replaces or removes* a root **sets `release_after = now +
  grace`** on the replica's pin for the old root — but only after confirming no
  other current entry still names it. `09d89a3` added exactly that primitive:
  `Store::content_is_referenced(root)`, one `EXISTS` over the
  `entries_by_content` index. It is what makes deduplication safe — two paths
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
happened while replication was off for the space, a views rebuild, and whatever
the live path
gets wrong.

The sweep may **stage**, and it may **release only under §3.6**. Staging from
absence is safe — the worst case is fetching something already held. Releasing
from absence is not, and that asymmetry is the next section.

### 3.5 The fetch loop

A third standing task, separate from both, because it is the only one that
touches the network and the only one that should be rate-limited:

1. Take up to `replica_concurrency` want rows in §3.3's order — rarest-first
   within each replicated space, interleaved between them, with the lead
   rotating one space per pass — skipping rows inside a backoff derived from
   `attempts`. The backoff is per row, not one threshold for the batch: the
   first retry waits `min_backoff` and each failure after it doubles the wait,
   up to `max_backoff`.
2. `fetch_all_from(root, size, donors)` — the ordinary §6.4 path, so delta
   descent, provider fanout and resumption apply unchanged. This is the best
   case for the descent and a replica hits it constantly: it is fetching
   version *n+1* of a file whose version *n* it is guaranteed to hold.
3. On completion: finalize to the backend's durable tier, then delete the want
   row and insert the pin row in one transaction. The order matters on a cloud
   backend and is the order `pin_object` already uses — a pin row written before
   `durable = 1` is a promise about bytes that live only in a scratch cache, and
   `docs/SERVERLESS.md` §6.3 makes cache-only content evictable by design.
4. On failure: increment `attempts`, record `last_error`, leave the row.

Between the fetch's last commit and the pin insert the object is complete,
possibly unreferenced, and unpinned. It survives the window for the reason
`pin_object` already relies on — the fetch stamped `last_access`, so the
retention test holds it — and that deserves a test that runs a GC pass inside
the window rather than a paragraph asserting it.

### 3.6 Release discipline: absence is not evidence

**"Eviction" is taken.** On a cloud backend it means the LRU that drops cache
files for objects the bucket still holds — `cas.cloud.cache_bytes`, keyed on
`last_access`, and explicitly applied to pinned blobs too, "since on this
backend the pin's promise is kept remotely, not by the cache". That is a
different verb from the one here. This document says **release** for giving up a
claim on content, and never "evict"; a released root loses a pin, and what
happens to its bytes afterwards is the backend's business (§9).

A replica's release runs through the ordinary `gc_content` pass. What
replication adds is a rule about **who is allowed to conclude that a root left
the tree**, and it is the one piece of this design that has to be right.

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
  is *empty*. An absence-driven release at that moment would let go of the
  entire store.
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
`space ls` and `synch doctor`. Holding too much for a day is a cost;
releasing the last copy of something is not recoverable, and the asymmetry
should be visible in the code as plainly as it is here.

Two further brakes, both strictly conservative:

- **Under-replication delays a release.** A replica that is about to let a root
  go may check how many *other* origins advertise a complete `BlobAd` for it
  and hold on if the answer is too few — other, because a count that includes
  this node's own advertisement always finds one holder left, itself, and the
  brake would never engage. This uses peers' claims only to *keep*
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

`spaces.budget` is an optional ceiling on bytes held for a space. When it is
reached the fetch loop stops taking new work for that space, want rows stay —
they are the record of what is missing, and dropping them converts a storage
problem into a silent data-loss problem — and `space ls` and `synch doctor`
report the shortfall in objects and bytes.

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

With claims published, `space ls` can answer the question an operator
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
same thing, and all of them wrong together during a partition.

Half of it is built, and it is the conservative half. `replica_release_floor`
holds a stale root while fewer than *k* **other** origins advertise a complete
copy: peers' assertions make this node keep bytes and never drop them, which is
the only direction §4.2 permits. What is not built is declining to *fetch*
because others have it — that is the direction with the hazard, and the brake
creates no pressure to add it.

Deployments that want a hard floor run replicas on every machine they are
willing to pay for and count them.

## 5. Configuration

| knob | default | what it is |
|---|---|---|
| `spaces.replicate` | unset | per space: unset, `tree` (release with the tree) or `archive` (never release) |
| `spaces.grace` | 30 d | how long a root outlives the last entry naming it |
| `spaces.budget` | none | per space byte ceiling; stops fetching, never releases |
| `replica_interval` | 300 s | reconciling sweep backstop; the promotion bell rings it early |
| `replica_concurrency` | 4 | concurrent object fetches for replica work |
| backoff | 60 s … 6 h | per-want retry schedule; the first retry waits the minimum and each failure after that doubles it, computed per row inside `wants_to_attempt` rather than applied as one threshold |
| `root_retention` | 7 d | unchanged; head history depth, now independent of content |
| `cas.cloud.upload` | `own+pinned` | not new and not changed: the default already covers a replica's holdings, since a replica pins what it holds (§3.1) |

Replica fetches share the endpoint with anti-entropy and with foreground reads,
and nothing schedules between them today — DESIGN.md §13 lists bandwidth QoS as
future work. `replica_concurrency` is the crude lever in the meantime, and its
default is deliberately low: a replica that saturates the link it shares with
the cluster's actual users is a worse problem than one that converges overnight.

## 6. CLI surface

No new noun. Replication is a flag on the command that already names spaces:

```
synch space add <id> <path>   [--replicate[=tree|archive]] [--grace <dur>] [--budget <size>]
synch space add <id> --detached [--replicate[=tree|archive]] [--grace <dur>] [--budget <size>]
synch space set <id> [--replicate[=tree|archive]] [--no-replicate [--release]]
                     [--grace <dur>] [--budget <size>]
synch space rm  <id> [--release]
synch space ls  [<id>]
synch space sync [<id>]                  run a reconciling sweep now
```

`--replicate` composes with the existing `--detached` rather than competing
with it (§3.2). `space add media /srv/media --replicate` is the common
deployment in one line — publish my copy of `media` *and* hold everyone else's
versions of it. `space add media --detached --replicate` is the dedicated
replica, which indexes nothing and publishes nothing. `--replicate` defaults to
`tree`; `--replicate=archive` is the opt-in that releases nothing (§2.1).

`--release` on `space rm` and on `--no-replicate` drops the held pins; without
it they are kept, because releasing terabytes should not follow from typing the
opposite of `add`. On a space with both halves, `space rm` unpublishes *and*
stops replicating; `--no-replicate` stops only the latter and leaves the
indexed directory alone.

`space ls` becomes the participation table, which is the question an operator
has when they ask what a node is for:

```
$ synch space ls
media    /srv/media   replicate tree · grace 30d · 6.02 TiB held
photos   —            replicate archive · 880 GiB held
docs     /srv/docs    —
```

and naming one space prints the detail, which is the whole operator interface
for this feature and should read like an answer:

```
$ synch space ls media
media   indexed /srv/media   replicate tree   grace 30d
  held            412,880 objects    6614661799936 B
  releasing         1,204 objects      34036482048 B   (soonest leaves in 3d)
  wanted              412 objects      11166914560 B   (oldest 4m ago)
  unreachable          14 objects       2254857830 B   <- no provider has answered for these
  held back            31 objects                      too few peers advertise these to let them go
  budget        8000000000000 B, 6614661799936 B of it used
  view          complete — releases are running
  from nas@cluster.example.com               6510000000000 B
  from vps@cluster.example.com                104661799936 B
  claim   nas@cluster.example.com says it holds 412880 objects (6614661799936 B, nothing outstanding, tree, grace 30d)
```

Four of those lines exist to be read on a bad day. `unreachable` must never be
folded into `wanted`: fourteen objects with no provider for six days is not a
backlog, it is fourteen versions that are probably already gone. `releasing` is
what an operator checks before deleting something they may want back. `view`
says whether §3.6's preconditions hold, because "releases are paused" is the
difference between a replica that is behaving and one that is broken — and it
is a different reason from `held back`, which is the §4.3 floor, so the two are
counted and printed separately rather than one being read as the other.

The `from` lines answer the question a budget raises and cannot: *whose* content
grew. Any member can publish, and every replica of the space fetches what they
publish — the membership trust model working as designed (§8), and a thing an
operator should be able to watch happening. The `claim` lines are other nodes'
assertions about their own disks, rendered as claims because that is what they
are (§4.2); nothing here has checked them, and nothing may act on them beyond
ordering its own work.

## 7. What this deliberately does not do

- **No filesystem materialization.** A replica holds objects, not a directory
  tree. An operator who wants both runs a mirror beside it — on `LocalFs` the
  mirror's reflink write means the tree costs no second copy of the bytes
  (`docs/DELTA-SYNC.md` §3.5); on a cloud backend `materialize` fills the cache
  and writes the file, so the checkout is a real second copy and a replica is
  the wrong machine to keep one on.
- **No protection against deletion beyond the grace window**, under the default
  policy. §2.2.
- **No releasing to make room.** Storage pressure stops fetching; it never
  shortens a release (§3.8). Cache eviction on a cloud backend is a different
  verb and is none of this design's business (§3.6).
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
  `space ls`, `synch doctor`, a warning per retry. The realistic
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
  breakdown in `space ls <id>` so the operator can see whose content grew.
- **A durable claim withdrawn under the node's feet.** `docs/SERVERLESS.md` §6.4
  gives a cloud node a heal rule: an OpenDAL `NotFound` on an object a row calls
  `durable` is authoritative, so the store takes the claim back — `durable → 0`,
  the row dropped if the cache holds nothing either, the `b:` ad retired. For an
  ordinary node that is a strict gain, and the design calls it the one genuine
  consistency gain of the port. For a replica it is also a **hole in the
  coverage it has promised**, arriving without any change in the tree. So the
  withdrawal must re-enter the want queue: whatever retires an ad must stage a
  want for the same root where a replicated space still references it, or the
  replica silently stops holding something and its own status output goes on
  saying it holds it. This is the one place where absence of bytes *is*
  evidence — the backend said so about a content address, which is not the same
  kind of statement as `entries` not naming a root (§3.6).
- **Clock skew.** `release_after` is an instant, so a backwards clock delays
  releases and a forwards one advances them. It should be compared against
  `Store::read_instant` rather than the bare clock, for the reason mirror passes
  already do, and a release should never fire from a reading the trust floor
  rejects.
- **The replica is also a publisher.** Benign — its own content is referenced by
  its own entries, and both halves of the `spaces` row are independent. Worth a
  test, not a rule.
- **`space rm` on a replicate-only space.** The one command here that can
  publish a mass deletion, pointed at a space where this node publishes
  nothing. It must stop the replication and unpublish nothing, rather than
  arriving at that outcome because the tombstone loop happened to find no keys
  (§3.2). The test is a node that replicates a space it does not index, running
  `space rm`, and no peer seeing a single tombstone.

### 8.1 Where these are visible

`space ls <id>` and `synch doctor` say all of it on the node itself, which is
where an operator with a shell looks. The failure this section opens with — a
replica that has been quietly unable to fetch for days — is the one nobody is
looking at a shell for, so it is also reported to the control plane and drawn
in the dashboard beside delegated trust.

**Asked over the tunnel, not pushed, and asked of every attached node.**
The daemon already opens a standing tunnel that the control plane asks
questions down (`control-plane/README.md`, "Cloud browse"), so this is one more
question on it: `Down::Replication` in, `Up::Replication` back, read-only like
every other frame. Nothing is stored control-plane side — a stored count is
stale the moment a fetch lands, and the tunnel is what makes storing it
unnecessary.

**A node too old for the question is not asked it, and does not lose its
tunnel.** The frames are tagged, so a daemon that has not learnt this one
cannot decode it, and a frame that does not decode ends the connection. That is
what the protocol version is for: the attach settles on the *daemon's* version
within a range the control plane serves, and each question records the version
it appeared in. An older node keeps everything its own version defines and is
simply never sent this — reported as "does not report replication" rather than
as a node replicating nothing. Taking an org's whole browse surface away to
fill in one panel would be a bad trade for the org and no safer for anyone.

The one structural difference from the delegations query is who may answer.
A delegation is a `d:` record every member holds, so any attached node speaks
for the cluster. **Replication is a per-node decision**: one node replicates
`media`, its neighbour does not, and both are correct. So every attached daemon
is asked and every answer carries the node that gave it — and a node that could
not be asked is shown as exactly that, never folded in as a node replicating
nothing. The two have identical counts and call for opposite actions.

What the dashboard adds to the per-node numbers is the count the numbers cannot
carry: **how many attached nodes replicate each space**. A space one node
replicates keeps every superseded version in exactly one place, and read node
by node it looks the same as a space three nodes hold. That is §4.3's floor
question asked about the fleet rather than about a root, and it is answered
from what was measured — a node that refused contributes nothing to the count,
because silence is not evidence that it holds nothing.

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
of the operator. `space add --replicate=archive` should print the current tree
size and the last 30 days' observed churn before it agrees.

### 9.1 On a cloud backend, releasing frees the claim and not the bucket

The table above is a `LocalFs` table, and the difference matters more than a
footnote. Content GC on the cloud backend "deletes only the SQLite claim and
reconstructible cache. Final payload/outboard keys under `cas/` are never
deleted by the daemon" (`docs/SERVERLESS.md` §6.5), because a content address
may be shared by every node using the bucket and no node can know the others
have released it without distributed reference counting the design deliberately
refuses.

So on a cloud-backed replica a release frees the pin, the row, and the cache —
and nothing in object storage. Bucket bytes grow monotonically whatever the
policy says, and the `tree` policy's convergence, which is the whole argument
for it being the default (§2.1), is a property of the local backend only. Under
`tree` a cloud replica converges in *claimed* bytes, in cache footprint, and in
what it advertises; its bill does not converge.

That does not sink `tree` on cloud — the claim, the cache and the ad are what
the cluster and the operator interact with, and the residue is reusable by
re-ingest and self-readoption at the same deterministic address. But an operator
choosing a policy for a cloud replica is choosing what the node *serves*, not
what the bucket *costs*, and `space add --replicate` should say so on that
backend rather than let the §9 table be read as a bill. Where the bill is the
point, the lever is a provider lifecycle rule over `cas/` — which §6.5 forbids
the daemon to rely on and does not forbid an operator to set, with the residue
rules in hand. §12 keeps the harder question.

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
- **Claims are assertions.** §4.2. `space ls <id>` renders peer claims as
  claims ("nas says complete"), never as verified coverage.
- **Scope holds.** A delegated replica replicates what it may read, and replica
  mode adds no path around `materialization_scope`.
- **Release is the dangerous verb.** Every code path that can set
  `release_after` should be countable on one hand and each should be justified
  where it is written, in the manner of `delete_blob_if_collectable`. A bug in
  the fetch path costs bandwidth; a bug in the release path costs the data.

## 11. Implementation map

Phases in dependency order. Each lands on its own and leaves the tree working.

1. **Pin holders and leases.** `pins` table, GC predicate becomes `NOT EXISTS`,
   `pin ls`/`pin rm` report holders and pending releases. No new behavior;
   everything after this depends on it. (Landed in v21 with phase 3, since the
   two are one migration.)
2. **Read by root.** `synch cat --root`, `synch get --root`. Independent,
   useful immediately, and what makes a replica's contents reachable.
3. **`spaces` gains three columns.** Migration v21, `FINAL_SCHEMA` follows.
   Much smaller than it was drafted: V20 already rebuilt the table with a
   nullable `local_path` and taught the scanner, watcher and overlap guards
   about a row with no root. `space add --replicate`, `space set`, `space ls`
   and the `space rm` branch land here, holding nothing yet — a config change
   with no fetcher behind it, which is the cheap half to get wrong.
4. **The replica, sweep-driven, hold-only.** `replica_want`, the reconciling
   sweep, the fetch loop, `space sync`. Policy `archive` semantics — nothing is
   released yet — so the risky half is absent while the fetching half is
   proven.
5. **The live path.** Staging and release-scheduling from `apply_change` inside
   the promotion transaction, plus the `entries_by_content` check that makes
   deduplication safe.
6. **Release, with the discipline.** `tree` policy, grace, the §3.6
   preconditions, `view` in `space ls <id>`, and the partition test. This is
   the phase to be slow about.
7. **Budget and reporting.** `--budget`, per-origin breakdown, doctor lines.
8. **Claims.** The `r:` prefix, `ReplicaClaim`, `publish_prefixes` for
   delegates, peer coverage in `space ls <id>`.
9. **Under-replication brake**, then **cooperative k-replication** (§4.3) — the
   two that should wait for operational experience.

Two things the build taught that the plan did not anticipate:

- **The advertisement and its withdrawal must share a predicate.** Skipping only
  the tombstone scan in `space rm`, as §3.2 originally proposed, would have left
  a replicate-only space advertising an `m:space` record that the removal then
  stranded in the trie. `publishes_into` gates both.
- **Tests that enter a `BlockingScope` cannot see a §10 violation.** The fetch
  loop read a donor's blob row on the runtime worker; every integration test
  passed, because the house pattern for engine tests is to enter the scope at
  the top and that suppresses the guard for the thread polling the future. A
  real daemon aborted on the first supersede. Anything new on an async path
  wants a run against a live daemon, not only a green suite.

## 12. Open questions

- **May a replica ever delete a `cas/` key?** §9.1 is the largest unanswered
  cost in this design. `docs/SERVERLESS.md` §6.5 refuses distributed reference
  counting and makes final keys append-only, which is right for a shared bucket
  and possibly wrong for a bucket one replica owns outright. A per-node root
  that no other node writes into would make release mean release; whether that
  is worth a configuration flag that is catastrophic when set wrongly is the
  question, and "no" is a defensible answer.
- **Extent sharing between versions.** A replica holds *n* and *n+1* of a large
  object whose difference is small, and the descent already knows which spans
  were promoted from the donor. Cloning those extents rather than copying them
  would change §9's storage column from whole objects to changed spans — on
  `LocalFs`, where `promote` already uses `copy_file_range` and could reflink
  instead. On a cloud backend the equivalent question is whether an object can
  be composed server-side from an existing key plus a delta, which is a
  different and much harder one.
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
- **What `space add --replicate` should refuse.** A space whose current size already
  exceeds free disk is an error at `add` time, not a surprise at 3am. The check
  is easy; the policy for "it fits now and will not in a month" is not.
