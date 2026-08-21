# Archive mode

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
is held by whoever happened to touch it recently. Supersede a file and the old
version's bytes survive only where a `pin` was placed on purpose. Remove the
member that published a path and the last copy can leave with it.

That is a reasonable default for a laptop and a wrong one for the machine in the
rack whose whole job is to still have things. The mechanism such a machine needs
already exists — `pin` makes retention unconditional, and `BlobAd` records make
availability cluster-visible (§6.3) — but there is no way to say *keep all of
this*, and no way at all to see whether anybody is.

The gap is named in DESIGN.md §13 as future work ("smarter placement policies,
built on the same `BlobAd` availability data"). This document proposes the node
role first and the placement policy last, because the role is the part that is
both useful alone and hard to get wrong later.

## 2. What archive mode is

**An archive is a node that holds every version of every path in the spaces it
archives, and never releases one on its own.** It publishes nothing of its own —
it may, but archiving is orthogonal to having spaces — and it materializes
nothing onto the filesystem. It accumulates objects in its CAS, pins them, and
serves them.

The distinction from the two existing surfaces is worth being exact about,
because all three are easy to confuse:

| | selects | holds | releases when |
|---|---|---|---|
| **mirror** (§7.2) | one version per path, by policy | files on disk, plus the CAS objects behind them | the tree stops naming the path |
| **pin** (§9.2) | one object root, named by hand | that object | an operator says so |
| **archive** | every version it ever observes | every object under them | its policy says so, or never |

A mirror is a *view*: it follows the unified tree, and what the tree drops it
drops. A pin is *possession* of one thing. An archive is possession of a
*set defined by a rule*, and the rule is a standing one — new content joins the
set as it appears, without an operator naming it.

### 2.1 What "everything" can honestly mean

Three readings, and only one of them is a promise this design can keep.

- **E1 — every version currently in the unified tree.** Computable from a
  listing at any instant. Insufficient: a path written twice between two passes
  loses its intermediate version, and that is precisely the version an archive
  exists to have.
- **E2 — every version this node observes.** Each promotion that flips a head to
  complete carries a diff of changed leaves (`Store::materialize_diff`). An
  archive that takes its work from that diff sees every version that passes
  through it, whether or not it survives to the next pass. **This is what
  archive mode promises.**
- **E3 — every version that ever existed anywhere.** Not achievable and should
  not be implied. Anti-entropy can carry an origin from seq 40 to seq 45 in one
  round without the intervening roots ever being fetched; a publisher's own
  history is pruned at its `root_retention`; a member that never met this node
  and then left took its versions with it. §4.4's fork evidence is the only
  thing that reaches backwards, and it reaches for heads, not content.

E2 is a guarantee about *this node's observations*, so it is only as good as the
node's uptime. An archive that was down for a day archives what it can still see
when it comes back, which is E1 for that day plus whatever history is still
reachable. §3.7 describes a bounded backfill that narrows the gap and does not
close it. The status output must state the guarantee in those terms rather than
in the words "everything", which an operator will otherwise read as E3.

## 3. Design

### 3.1 Pins gain a holder

Archive mode cannot be built on the pin column as it stands. `blobs.pinned` is a
boolean with no provenance, and the moment two things pin for two reasons the
boolean cannot answer the only question that matters on removal: *may these
bytes go now?*

Three cases make this concrete:

1. An operator pins `media/keynote.mp4`'s root by hand. The archive later covers
   `media` and pins the same root. Removing the space from the archive must not
   drop the operator's pin.
2. Two archived spaces name the same content. Deduplication is real here —
   objects are keyed by hash and `entries_by_content` is indexed for exactly
   this — so `archive rm photos` must not release bytes `documents` still
   covers.
3. An archive under a `window=` policy releases a superseded root. It may
   release only its own claim on it.

So: replace the column with a table.

```sql
-- schema v20
CREATE TABLE pins (
  root       BLOB NOT NULL,
  holder     TEXT NOT NULL,        -- 'operator' | 'archive:<space>'
  created_at INTEGER NOT NULL,
  PRIMARY KEY (root, holder)
);
CREATE INDEX pins_by_holder ON pins (holder);
```

and make pinnedness derived rather than stored, because a denormalized copy of
this is a second source of truth for a question with one right answer. The GC
predicate inside `delete_blob_if_collectable` changes from `pinned = 0` to a
`NOT EXISTS` over `pins`, keeping the property that makes it correct today: the
predicate is re-read inside the immediate transaction that does the delete, so a
pin landing between the candidate snapshot and the delete decides the delete.
`Store::pinned_blobs` becomes `SELECT DISTINCT root FROM pins`.

The migration backfills `('operator', now)` for every row with `pinned != 0` and
drops the column. Nothing an operator pinned before the upgrade changes meaning.

`synch pin rm` removes the `operator` holder only, and says what remains:

```
$ synch pin rm media/talks/keynote.mp4
unpinned 9f86d081… (still held by archive:media)
```

which is the honest report — the bytes are not going anywhere, and a command
that said "unpinned" flat would be lying about the outcome the operator cares
about.

**Want is intent; a pin is possession.** An archive that has decided it needs an
object it does not hold must not write a pin row for it: a pin whose bytes are
absent guards nothing and makes `pin ls` a list of claims rather than of
contents. The intent lives in its own table (§3.3) and becomes a pin in the same
transaction that retires the want, once the fetch has completed.

### 3.2 Configuration: one row per archived space

```sql
CREATE TABLE archives (
  space      TEXT PRIMARY KEY,
  policy     TEXT NOT NULL,        -- 'all' | 'current' | 'window=<secs>'
  budget     INTEGER,              -- optional byte ceiling, NULL for none
  added_at   INTEGER NOT NULL
);
```

Per space, not per node, for the same reason mirrors are per directory: "archive
everything this node can see" is a policy an operator can express by adding every
space, and a node-wide flag would silently enrol spaces admitted later.

The three policies are the deployable range between "keep one copy of now" and
"keep the integral of all churn":

- **`all`** — every version ever observed, released never. The literal reading of
  archive mode, and the one whose storage curve is unbounded (§9).
- **`current`** — every version *currently* named by some origin's entry, in
  every origin's view, including versions no policy would select. Superseded
  roots are released. This is not E1-with-gaps: the archive still fetches an
  intermediate version the instant it sees it, and releases it only when the
  promotion that supersedes it arrives. It differs from `all` in what it keeps,
  not in what it notices.
- **`window=<dur>`** — `current`, plus superseded roots for `dur` after they were
  superseded. The setting most deployments actually want: "you can get last
  month back".

A release under `current` or `window=` deletes one row from `pins`. The object
then survives or not on the ordinary rules — an entry may still name it, another
holder may hold it — which is the point of the holder model.

### 3.3 The want queue, resurrected

Schema v3 dropped a `want(root, ranges, priority, reason)` table. Archive mode
needs it back, in a shape fitted to this job:

```sql
CREATE TABLE archive_want (
  root         BLOB NOT NULL,
  holder       TEXT NOT NULL,      -- 'archive:<space>', same shape as pins.holder
  size         INTEGER NOT NULL,
  prev         BLOB,               -- donor hint: the root this version replaced
  first_wanted INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_attempt INTEGER,
  last_error   TEXT,
  PRIMARY KEY (root, holder)
);
CREATE INDEX archive_want_by_attempt ON archive_want (last_attempt);
```

Three properties earn the table, and none of them is served by an in-memory
queue:

- **Durable intent.** A version observed once and superseded before the next
  sweep is not in any listing any more. If the intent to fetch it does not
  survive a restart, E2 is not a guarantee, it is a hope about uptime.
- **A place for failure to accumulate.** `attempts`, `last_attempt` and
  `last_error` are what turn "the archive is behind" into "these 14 objects have
  had no provider for six days", which is the alarm this whole feature exists to
  raise (§8).
- **Backpressure.** A promotion diff can name millions of roots. The staging
  step must be one insert per changed leaf and nothing else; the fetching is a
  separate loop with its own concurrency.

`size` and `prev` are carried because the fetch needs both and neither survives
the entry. `fetch_all_from` fetches *by* size — a bare root nobody holds even
partially has none, which is the case `pin_object` refuses outright — and `prev`
is the delta donor. Both are in the `FileEntry` that stages the want and are
recorded there rather than looked up later, when the version may have been
superseded and its row replaced.

**Priority is rarest-first.** The fetch loop orders candidates by how many
distinct origins advertise a complete `BlobAd` for the root
(`blob_providers`), ascending, then by `first_wanted`. An archive's job is to
raise the floor on the number of copies, so the object with one advertised
holder is worth more than the object with nine — and the object with one
advertised holder is the one about to be lost when that holder leaves. Ties go
to the oldest want, so nothing starves.

### 3.4 Two sources of work

**Live: the promotion diff.** `Syncer::try_promote` flips a head to complete
inside one transaction that also calls `materialize_diff`, which streams every
resolved change under the origin's scope into `entries`. Archive mode adds one
step to `apply_change`'s `f:` arm: when the entry carries a content root and its
space is archived, insert an `archive_want` row.

In that same transaction, deliberately. A want row that can be lost while the
entry row lands is the one failure that costs a version permanently, and the
argument is the one `gc_trie` already makes about splitting its pass: this is
not tidiness, it is where the data loss is. The added cost is one insert per
changed leaf, against a transaction that is already writing that leaf.

Two things fall out for free, and both are consequences of pins being
content-addressed rather than path-addressed:

- **Deletion needs no handling.** A tombstone removes the entry; the pin on the
  content root the path used to name is untouched, because it was never about the
  path. The bytes of a deleted file survive in the archive with no special case
  anywhere.
- **`take`, adoption and divergence need no handling.** Every version any origin
  publishes is a change in some origin's trie, so all of them arrive through the
  same door. An archive holds both sides of a divergence without knowing what
  divergence is.

**Reconciling: a periodic sweep.** A standing loop, in the mould of the mirror
loop (`mirror_interval`, rung by the same promotion bell, with a backstop
interval). It walks `entries` for archived spaces and stages a want for every
content root that has no pin row and no want row.

The sweep is not redundant with the live path. It covers: a space added to the
archive after the fact, promotions that happened while archive mode was off or
the space was not yet archived, a views rebuild (`synch doctor --rebuild`), and
whatever the live path gets wrong. It is a scan of current entries — bounded by
the size of the tree, not by its history — and it is the reason an operator can
turn archive mode on for an existing cluster and have it converge without
anything special being done.

### 3.5 The fetch loop

A third standing task, separate from both, because it is the only one that
touches the network and the only one that should be rate-limited:

1. Take up to `archive_concurrency` want rows in priority order, skipping rows
   whose `last_attempt` is inside a backoff derived from `attempts`.
2. For each, `fetch_all_from(root, size, donors)` — the ordinary §6.4 path, so
   delta descent, provider fanout and resumption all apply unchanged. This is
   the best case for the descent and an archive hits it constantly: it is
   fetching version *n+1* of a file whose version *n* it is guaranteed to hold.
   The donor has to be recorded at staging time, though, not rediscovered here:
   `Node::donors_for` derives donors from the selected entry's `prev` and from
   the other versions in the set, and by the time the fetch loop reaches a want
   row those entries may be gone. Hence the `prev` column.
3. On completion: delete the want row and insert the pin row, in one
   transaction.
4. On failure: increment `attempts`, record `last_error`, leave the row.

Between the fetch's last commit and the pin insert there is a window in which the
object is complete, possibly unreferenced, and unpinned. It survives it for the
reason `pin_object` already relies on: the fetch stamped `last_access`, so the
retention test in `gc_content` holds it. Worth stating rather than discovering
later, and worth a test that runs a GC pass in that window.

### 3.6 History retention becomes a role property

An archive that prunes `head_history` at seven days holds bytes it can no longer
explain. `synch log` walks retained roots to show a path's versions; the trie
mark set is built from complete and pending heads plus retained history roots, so
pruning history is also what sweeps the historical trie nodes. The objects would
survive on their pins and nothing would be able to say what any of them was.

So an archive node sets `root_retention` to never prune. The knob is node-wide
today, and this design keeps it node-wide rather than inventing per-origin
retention: the thing being retained is trie nodes and head rows, which are small
beside content, and the complexity of a per-origin policy buys an archive
nothing it wants.

This is what makes an archive answer the interesting question. DESIGN.md §8 says
history depth is a storage policy rather than a protocol constant; an archive is
the node that sets that policy to *keep it*, and having done so it can answer
"what did this path look like in March" from its own store, for every origin, with
the signed roots to prove each answer.

Which surfaces a gap in the CLI: there is no read-by-root. `synch log` prints
content roots, `synch pin add <root>` is the only command that takes one, and
DESIGN.md §8 says reading an old version back "is done by content root, not by a
time-travel flag" — but nothing implements the former. Archive mode should ship
`synch cat --root <hex>` and `synch get --root <hex>`, or it is a machine that
holds history nobody can read. This is small (the fetch and verify paths are
root-keyed already) and it is not optional.

### 3.7 Backfill: narrowing E2 toward E3

Best-effort, bounded, and off by default.

When an archive adopts an origin whose `head_history` shows seq gaps — it
learned of seq 45 having last seen seq 40 — it may ask peers for the roots at
41…44 and walk their tries for content it lacks. The constraint is a rule
already enforced on the serving side: a peer answers `GetNodes`/`GetValues` only
for a root it holds a head for, so backfill reaches exactly as far as some peer's
own retained history, and no further.

This does not close the gap to E3 and must not be described as if it does. It
converts "the archive was down for six hours" from a permanent hole into a
recoverable one, provided some peer that was up still holds those roots. It
belongs in a later phase than the rest.

### 3.8 The budget, and what "full" does

`archives.budget` is an optional ceiling on bytes held on behalf of that space.
When it is reached:

- The fetch loop stops taking new work for that space.
- Want rows stay. They are the record of what is missing, and dropping them
  would convert a storage problem into a silent data-loss problem.
- `archive status` and `synch doctor` report the shortfall in bytes and objects.
- **Nothing is ever unpinned to make room.** An archive that evicts under
  pressure is a cache with a misleading name. The failure mode of a full archive
  must be "it stopped taking new things and said so", never "it quietly dropped
  the oldest thing".

An object larger than the remaining budget is skipped, not dropped: it stays
wanted and is retried when the budget rises.

## 4. The network-wide half

Two questions get confused here and only one of them is answerable.

### 4.1 Coverage is publishable

An archive may declare what it archives, in its own signed trie, under a new key
prefix:

```
a:<space>   ->   ArchiveClaim { v, since_ns, policy, objects, bytes, complete }
```

A new prefix rather than a field on `SpaceInfo` (`m:space/<id>`), and the reason
is compatibility, not taste. postcard is not self-describing and every record
carries a version stamp that older builds check with `v <= RECORD_VERSION`, so
appending a field to `SpaceInfo` means bumping `RECORD_VERSION` to 2 and having
every 0.1.x node *refuse* the record — a flag day for a feature that should be
additive. An unknown key prefix, by contrast, already falls through
`apply_change` to `Ok(())`: existing builds ignore `a:` records completely and
keep materializing everything else in the trie.

For a delegate, `a:` must be added to `publish_prefixes` for its granted spaces
and to the read scope, or a delegated archive cannot claim what it archives. The
argument is the one already made for `b:`: a delegate that holds content must be
able to say so, or the swarm loses a source.

With claims published, `synch archive status` can answer the question an operator
actually asks — *is anything archiving `media`, and how far behind is it?* —
across the cluster rather than on one box.

### 4.2 Enforcement is not

No node can make another node retain anything, and this design does not pretend
otherwise. A claim is an assertion by a member, in exactly the sense §12 already
accepts for `mtime_ns` and for `BlobAd`: a member with a full disk, a bug, or bad
intent can claim a coverage it does not have.

Which yields the invariant that keeps the feature safe:

> **A peer's claim may order this node's work. It may never release this node's
> bytes.**

Rarest-first (§3.3) uses provider counts to decide what to fetch *first*.
Nothing anywhere uses another node's claim, ad, or count to decide what to
unpin. An archive that trusted claims for release decisions would give any member
the ability to talk the cluster's last copy out of existence, and it would do so
through the same door that a plain bug in somebody's disk-full handling opens.

### 4.3 Cooperative k-replication, deferred

The obvious next step — several archives sharing a space, each holding a subset,
targeting *k* copies cluster-wide — is DESIGN.md §13's "keep ≥ 2 replicas of
every object cluster-wide", and it should be built after single-node archiving
has run somewhere for a while.

The mechanism is available (`blob_providers` carries per-origin complete/partial
spans). The hazard is specific and worth writing down before anyone implements
it: *k* as a **floor on fetching** is safe, and *k* as a **licence to release**
is how a pool of archives converges on zero copies — every member observing that
"the others have it" at the same moment as the others observe the same thing.
Against a partition, that observation is wrong for everybody simultaneously.

So the shape, when it is built: an archive may decline to *start* a fetch while
*k* distinct origins advertise complete ads, and may never release what it holds
on those grounds. Deployments that want a hard floor run archives on `all` and
count machines.

## 5. Configuration

| knob | default | what it is |
|---|---|---|
| `archives.policy` | `all` | per space: `all`, `current`, `window=<dur>` |
| `archives.budget` | none | per space byte ceiling; stops fetching, never evicts |
| `archive_interval` | 300 s | reconciling sweep backstop; the promotion bell rings it early |
| `archive_concurrency` | 4 | concurrent object fetches for archive work |
| `archive_backoff` | 60 s … 6 h | per-want retry schedule, exponential in `attempts` |
| `root_retention` | 7 d, **never** on an archive | §3.6 |

Archive fetches share the node's endpoint with anti-entropy and with foreground
reads, and nothing schedules between them today — DESIGN.md §13 lists bandwidth
QoS as future work. `archive_concurrency` is the crude lever in the meantime, and
its default is deliberately low: an archive that saturates the link it shares
with the cluster's actual users is a worse problem than an archive that converges
overnight.

## 6. CLI surface

```
synch archive add <space> [--policy all|current|window=<dur>] [--budget <size>]
synch archive rm <space> [--release]
synch archive ls
synch archive status [<space>] [--json]
synch archive sync                     run a reconciling sweep now
```

`archive rm` keeps the pins by default and `--release` drops them. Releasing
terabytes is not something a command should do because an operator typed the
opposite of `add`.

`archive status` is the whole operator interface and should read like an answer,
not a dump:

```
media   policy all   since 2026-03-04
  held        1,284,551 objects   8.11 TiB
  wanted            412 objects  10.4 GiB   (oldest 4m ago)
  unreachable        14 objects   2.1 GiB   ← no provider for 6d
  history     retained from seq 1 for 7 origins
  claims      nas@cluster.example.com (complete), vps@cluster.example.com (99.4%)
```

The `unreachable` line is the one that matters and it must never be folded into
`wanted`. Fourteen objects with no provider for six days is not a backlog, it is
fourteen versions that are probably already gone; §8 covers what to do about it.

## 7. What this deliberately does not do

- **No filesystem materialization.** An archive holds objects, not a directory
  tree. An operator who wants both runs a mirror beside it, and the mirror's
  reflink write means the tree costs no second copy of the bytes
  (`docs/DELTA-SYNC.md` §3.5).
- **No erasure coding, no sharding within a space.** The unit is the object and
  the copy is whole. Partial-object placement across archives is a different
  design and a much larger one.
- **No cross-cluster federation.** An archive archives spaces of its own
  cluster, under its own membership. Pulling from a cluster you are not a member
  of has no story here and should not acquire one by accident.
- **No retention override of the trust rules.** An archive of a space it may not
  read is not a thing: a delegate archives its granted spaces, and the
  materialization scope already enforces that (§5.5).
- **No eviction.** Ever, on any pressure, under any policy. Releases happen only
  where the configured policy says a version has aged out, and never because
  something ran out of room.

## 8. Failure modes

- **Content nobody serves.** A want row that has failed with "no provider" for
  longer than the alarm threshold means the last holder left before the archive
  reached it. There is nothing the archive can do, so the whole value is in
  saying so loudly and early: `archive status`, `synch doctor`, and a warning log
  on each retry. The realistic mitigations are operational — archive nodes that
  are up when members are, and more than one of them.
- **A member fills the archive.** Any member can publish content and every
  archive of that space will fetch it. This is the membership trust model working
  as designed (§12: members are trusted to publish), but it is worth a per-origin
  byte counter in `archive status` so the operator can see *whose* content grew,
  and it argues for `--budget` being set on any archive facing a large
  membership.
- **A views rebuild.** `doctor --rebuild` drops and re-materializes `entries`.
  Pins are content-addressed and live in their own table, so nothing is
  released; want rows re-derive from the next sweep. This is the case that
  justifies the sweep existing even after the live path works.
- **Clock skew.** Pins do not expire, so retention has no clock dependence.
  `window=` policies do — they compare a supersession time to a duration — and
  should use `Store::read_instant` rather than the bare clock, for the same
  reason mirror passes do.
- **The archive is also a publisher.** Nothing prevents it, and the interaction
  is benign: its own content is referenced by its own entries and pinned by the
  archive besides. Worth a test, not a rule.
- **Two archives, one machine.** Two daemons on one data directory is already
  refused; two archives of the same space in one daemon is one row in `archives`.
  No new case.

## 9. Cost model

The number an operator needs before turning this on, and it is not the size of
the tree.

Take a cluster with 8 TiB of current content across 40 members, where 2% of
paths are rewritten daily and the average rewritten object is 40 MiB. Daily churn
is then roughly 160 GiB of *new* roots, of which delta sync moves only the
changed spans — but the archive **stores** whole objects, because an object is
the unit of a pin.

| policy | steady state after a year |
|---|---|
| `current` | ≈ 8 TiB, flat, tracking the tree |
| `window=30d` | ≈ 8 TiB + 30 × 160 GiB ≈ 12.7 TiB, flat after 30 days |
| `all` | 8 TiB + 365 × 160 GiB ≈ 65 TiB, and still climbing |

So: `all` costs the *integral of churn*, not the size of the tree, and the
integral does not converge. That is not an argument against `all` — it is what
"keep every version forever" means, and some deployments genuinely want it — but
it must be on the first page of the operator documentation and in the output of
`archive add`, which should print the current tree size and the last 30 days'
observed churn before it agrees.

Delta sync helps the network and not the disk here. Fetching version *n+1* of a
file whose version *n* is pinned locally is the best case for the descent
(§3.5 of `docs/DELTA-SYNC.md`), so an archive's *bandwidth* tracks changed
spans. Its *storage* tracks whole objects. On btrfs/XFS/bcachefs the CAS write
does not reflink between distinct objects, so nothing recovers that on disk in
v1; whether the promotion path could clone shared extents into the new payload
is an open question (§12).

## 10. Security

- **An archive is a concentrated target.** It holds every version of everything
  in its spaces, including versions the origins have since deleted — which
  means an archive can serve content that every other node in the cluster has
  forgotten, and a deletion is no longer a way to make bytes go away
  cluster-wide. That is the intended behavior and it is also a data-handling
  fact an operator must consent to. `archive add` should say it. At-rest
  encryption remains delegated to OS disk encryption (§12), and per-space
  content keys remain future work — an archive is a strong argument for
  finishing them.
- **Claims are assertions.** §4.2. A claim never releases another node's bytes,
  and `archive status` should render peer claims as claims ("nas says
  complete"), never as verified coverage.
- **Backfill widens what this node asks for.** §3.7 walks historical roots, and
  the serving-side rule (a root must be one the responder holds a head for) is
  what keeps that from becoming an arbitrary-root oracle. The archive must not
  acquire a way to ask for roots outside that rule.
- **Scope holds.** A delegated archive archives its granted spaces only, because
  `materialization_scope` decides what its `entries` ever contained. Archive mode
  adds no path around that.

## 11. Implementation map

Phases, in dependency order. Each lands on its own and leaves the tree working.

1. **Pin holders.** `pins` table, migration v20, GC predicate becomes `NOT
   EXISTS`, `pin ls`/`pin rm` report holders. No new behavior; everything after
   this depends on it.
2. **Read by root.** `synch cat --root`, `synch get --root`. Independent of the
   rest, useful immediately, and the thing that makes an archive readable.
3. **The archive, sweep-driven.** `archives` table, `archive_want`, the
   reconciling sweep, the fetch loop, `archive add|rm|ls|status|sync`. Policy
   `all` only, no budget. At this point the feature works and its guarantee is
   E1-plus-whatever-the-sweep-catches.
4. **The live path.** Staging from `apply_change` inside the promotion
   transaction. This is what upgrades the guarantee to E2, and it is one insert
   plus a test that a doubly-rewritten path keeps both versions.
5. **Policies and budget.** `current`, `window=`, release on supersession,
   `--budget` and the full-archive reporting.
6. **History as a role property.** `root_retention` never on an archive, `synch
   log` over the retained depth, history figures in `archive status`.
7. **Claims.** The `a:` prefix, `ArchiveClaim`, `publish_prefixes` for delegates,
   peer coverage in `archive status`.
8. **Backfill** (§3.7), then **cooperative k-replication** (§4.3) — the two that
   should wait for operational experience.

## 12. Open questions

- **Per-origin retention.** §3.6 keeps `root_retention` node-wide. A node that
  archives one space of a fifty-space cluster retains every origin's whole
  history for all of them. The trie is small, but "small" is doing work in that
  sentence that nobody has measured.
- **Extent sharing between versions.** An archive holds *n* and *n+1* of a large
  object whose difference is small, and the delta descent already knows which
  spans were promoted from the donor. Whether the CAS write could clone those
  extents rather than copy them — turning the storage curve from whole objects
  into changed spans on filesystems that support it — is the single largest
  possible improvement to §9 and is unexplored.
- **Should archives be preferred providers?** They hold everything, so ranking
  them first in `providers_for` would make cold reads fast. It would also point
  every cold read in the cluster at one machine. Probably the answer is "prefer
  them last, as the backstop that always has it", but it needs measuring.
- **Claim granularity.** `ArchiveClaim` as proposed carries counts. A per-space
  digest that let two archives compare coverage without enumerating objects
  would make §4.3 much easier, and looks like it wants to be a trie of its own.
- **What `archive add` should refuse.** A space whose current size already
  exceeds the free disk is an error at `add` time, not a surprise at 3am. The
  check is easy; the policy for "it fits now and won't in a month" is not.
