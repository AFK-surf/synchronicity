# Implementation notes

Where this implementation differs from `DESIGN.md`, and why. Everything here is
a deliberate, recorded choice. Nothing in this list weakens signature
verification, hash verification of trie nodes or content, the `(seq, root)`
acceptance rule, or binding checks — those are implemented exactly as specified.

Sections refer to `DESIGN.md`.

## Deferred, with the module boundary in place

### §7.1 — ignore rules

`.syncignore` implements the common gitignore subset: `*`, `?`, `**`, a leading
`/` to anchor, a trailing `/` for directories only, and a leading `!` to
un-ignore, plus the built-in defaults. Character classes (`[a-z]`), escapes, and
nested per-directory ignore files are not implemented.

### §5.2 — abandonment across multiple advertisers

"Three full rounds **across all advertisers**" is implemented as three
unproductive rounds against the peer currently being fetched from. Since the
anti-entropy scheduler picks a random peer each round, a persistently unservable
head is still abandoned and re-selected; the difference is that the count is
per-session rather than global.

## Differences in detail

### §4.2 — when a tombstone's clock starts, and who runs it down

Tombstones are "retained for `tombstone_ttl` (default 90 days), then dropped in
a later root". The design does not say what the age of a tombstone is measured
from, and this implementation uses the tombstone's own `mtime_ns` — the field
§4.2 calls "origin's observed mtime", which for a tombstone the scanner sets to
the moment it noticed the path was gone. So the clock starts at the deletion,
not at the head that carried it, and re-publishing an unchanged tombstone does
not restart it.

Expiry stages the trie-key removals and lets the publisher (§7.1) turn them
into one root, so retiring a thousand tombstones costs one head rather than a
thousand. It runs in two places: the periodic maintenance pass, beside binding
expiry and GC, and every scan — including an explicit `synch scan`, which is
how an operator forces it, and which reports `expired N` when there was
anything to retire.

Only this node's own tombstones are ever considered. A replicated trie belongs
to its origin and is reproduced whole; dropping a key from it would be
publishing someone else's view, which §8 forbids, so the query is scoped to the
node's own origin rather than filtered afterwards.

### §7.1 — which callers wait for the batch, and which flush it

The publisher batches staged changes into one root on either trigger the design
names: `publish_quiesce` (2 s of quiet) or `publish_batch_max` (1000 entries).
What §7.1 does not say is which callers may return *before* their batch has
become a head, and this implementation splits them by whether a person is
waiting for an answer:

- The watcher and the periodic rescan **stage** and return. This is the case
  batching exists for: a burst of editor saves is one batch and one head.
- `synch scan`, `synch take`, and `synch space rm` **flush** before they answer.
  Each is already one batch by construction, so flushing costs no extra head,
  and it keeps their output (`published seq N`, `unpublished N record(s)`)
  describing something peers can already ask for. `synch-s3`'s `PutObject`
  keeps its own, stricter timing — see §9.4 below.

A flush publishes the *whole* buffer, not the flushing caller's share of it, so
a `synch scan` that lands while a watcher rescan is still buffered publishes
both. A publish that is refused (§3.4) puts its batch back rather than dropping
it; a *push* that fails does not fail the flush, because the head exists and
the next anti-entropy round carries it. A clean daemon stop flushes what is
left.

One visible consequence of batching: `FileEntry.seq` is the seq the scan
expected to publish at, and a batch that lands after some unrelated publish
(an ad milestone, a key activation) can carry a seq one below the head that
actually delivers it. The trie, the head, and `entries.seq`'s ordering are
unaffected; only that advisory field can lag, and re-scanning the file restates
it.

### §8 — where the version order's ties are broken

`newest` is "the greatest `(mtime_ns, content_root, origin)`", and §8 requires
it to be a total order so every node selects the same version from the same
assertions. Two things that phrase does not pin down:

- **A tombstone has no content root.** It sorts as `None`, which is below every
  `Some`, so at equal mtimes a deletion loses to content. The tombstone still
  wins on a *later* mtime, which is what makes "deleted after you last wrote"
  read as a deletion.
- **The `origin` component never decides which version wins** — two entries
  with the same content root *are* the same version — so it decides only which
  attestor is named as the source of the bytes. The maximum is taken over
  entries rather than versions, which yields both answers at once and is the
  same result either way.

The order is computed over `entries` alone: mtime, content root, and canonical
origin are all data every node holds identically, so no node needs to ask
another what it selected.

### §8, §9.2 — how divergence is marked in a listing

§14 shows a divergent path marked `⑂2`, and that is what `synch ls` prints: the
U+2442 mark followed by the number of versions. A *count*, not a flag, because
the count is the fact and it is what `synch status` will lay out. Agreement
prints no mark at all, so an ordinary tree looks ordinary. The mark is only
produced by the unified listing; the origin-prefixed form of `ls` shows one
origin's view and has nothing to mark.

`synch status` uses the same vocabulary: `<space>/<path>  N version(s)` and one
indented line per version — content root, kind, size, seq, attestors — newest
first, which is the order selection runs in.

### §8, §9.2 — an origin-pinned reference and `--from` are the same thing

§7.2 gives `cat`/`get` both an `<origin>:` prefix and a `--from <origin>` flag.
They express the same policy, so naming both is a contradiction rather than a
preference and is refused with a message saying so. `--strict` on an
origin-pinned reference is refused too: a pin already names one version, so
strict has nothing to refuse. `--from` and `--strict` together are refused by
the argument parser before a connection is made.

### §7.2 — when a path leaves a mirror

§7.2 says a mirror keeps a directory in sync with the policy-selected version
of every path. The removal side has two halves, and only one of them is
visible in a listing:

- **The selected version is a tombstone.** The mirror follows the assertion it
  selected, so the file goes. Under `newest` a deletion newer than the content
  removes it; under `origin=<id>` only that origin's deletion does.
- **The path has left the unified tree.** When every entry for a path is gone —
  every publisher's tombstone expired (§4.2), or an operator ran `synch doctor
  --rebuild` against a trie that no longer carries it — there is nothing left
  to select, and nothing in the listing to notice. So each pass ends by walking
  the mirror directory and removing files whose path the tree no longer carries
  at all. Directories are left in place.

  Untrusting an origin is *not* one of those cases. Removal cuts a node off
  from future participation — connections refused, new heads ignored — and
  nothing cascades a deletion through everyone's tries, because that would hand
  any removal a blast radius (§12). The untrusted origin's entries stay in the
  tree and age out with ordinary retention; what changes is that `synch doctor`
  lists the origin under "origins held without a live binding", with how many
  entries it still carries.

Two related choices: an `origin=` pin that selects nothing (that origin
publishes no version of the path) removes the file too, since the path is not
in the pinned view; and a path a `strict` mirror skipped is left exactly as it
is — skipping is a refusal to act, not a decision to delete.

### §7.1 — reconciling `local_files` on open

Batching introduces a failure the synchronous publisher did not have.
`scan_space` records `(size, mtime_ns, file_id)` in `local_files` as it indexes,
and that record is exactly what makes the *next* scan skip the file. If a
daemon dies with a batch still buffered, the files were hashed and recorded but
no root mentions them, and every later scan skips them: silent, permanent
drift.

So `Node::open` reconciles before it returns anything. Every `local_files` row
is compared against this node's own current trie, and a row whose content hash
the trie does not corroborate is dropped, so the next scan re-hashes that path
and stages it again. Both tables are local — one trie lookup per indexed file,
no filesystem I/O — which is why the check is unconditional rather than
guarded by a crash marker. It is a repair, not a rescan: a node whose root
agrees with its rows keeps every one of them and re-hashes nothing.

### §3.4 — which endpoint dials during the overlap window

The design says `synch key activate` "brings up a second iroh endpoint as
`K_new`" and that both endpoints stay live until the old binding has expired.
Both do. What the design does not say is which of them the node dials *out*
from, and this implementation makes the new key the primary: `K_new` signs, and
new outbound connections carry it, while `K_old`'s endpoint keeps accepting
until `synch key retire` drops it. That way the identity peers are being moved
to is the one they see on every fresh connection, and retiring the old key
becomes a pure teardown of a serving-only endpoint rather than a second
switch-over.

One consequence is visible with an explicit `--bind HOST:PORT`: two endpoints
cannot share a port, so the incoming key binds an ephemeral port on the same
interface, and the fixed port stays with the outgoing key until it is retired.

### §9.2 — what `synch recover --wait` accepts

The design writes `--wait <dur>` without saying what a duration looks like.
This implementation takes a plain number of seconds (`0`, `45`) or a sequence
of unit-suffixed numbers (`30s`, `90m`, `1h`, `2h30m`, `1d`) — parsed by hand
rather than by adding a dependency for the one duration on the command
surface. It is parsed twice: on the client, so a typo fails before a connection
is made, and on the daemon, where a bad value comes back as an ordinary
structured error.

The quiesce reports one `Progress` frame per collection round, so an hour-long
wait shows what it is reaching rather than looking hung, and the recovery runs
as a task the connection owns: a client that hangs up aborts it, and the floor
is set once, deliberately, or not at all.

### §9.3 — `Line` frames for textual output

The design describes `cat`, `get`, and a long `ls` streaming their payload "as a
sequence of `Chunk` frames terminated by `End`". Byte payloads (`cat`, `get`) do
exactly that. Textual output (`ls`, `status`, `log`, `doctor`, …) streams
`Line` frames instead — the same incremental delivery terminated by the same
`End`, but framed per line, so the CLI does not have to re-split a byte stream
it is only going to print line by line. `Progress` and the structured `Error`
are as specified.

### §3.4 — when a node counts as "in recovery"

The design defines the state as "holds no head of its own but finds peers
advertising heads for its own origin". This implementation compares the
advertised seq against the seq the node *would publish at*, not against zero:
a node is in recovery when it holds no head of its own and some peer has
advertised a head at or above its next seq. The two agree exactly on a fresh
database, where the next seq is 1 and any advertisement at all means recovery.
They differ afterwards, and deliberately: once `synch recover` has set a floor
of `max_observed + gap`, an observation *below* that floor is not a return to
recovery — publishing at the floor would still be accepted — while one above it
is, because it would not.

The heads behind those advertisements are never verified, never adopted, and
never counted as history. They are recorded in an `observed_heads` table keyed
by origin, holding the greatest `(seq, root)` any peer has claimed, and the node
only tracks its *own* origin that way: for every other origin the ordinary
acceptance rule is both sufficient and stricter.

The publishing floor is durable (a `config` row) and only ever rises, so a
recovered node stays above its peers' history across restarts, and `synch
recover` never lowers a seq. A gap of 0 is refused rather than honored: a floor
at the highest seq peers advertised is precisely the collision the gap exists to
make improbable.

Two consequences of "publishing is refused" are worth naming. The gate runs
*before* a scan, not only at the publish it feeds: a scan records what it hashed
in `local_files`, so a scan whose publish was refused would leave the node
believing it had published files it never did. And `synch key activate` takes
the same gate, because re-signing the current root as `seq + 1` is a publish
like any other.

### §3.4 — the state of a key between `rotate` and `activate`

`device_keys.state` is `active` or `retiring` (§10), so the key that
`synch key rotate` generates is stored as `retiring` until `synch key activate`
promotes it: "held, and not the signing key". Exactly one key is `active` at any
moment, which is the invariant that matters.

### §7.1, §8 — symlinks, their change signal, and their version identity

§7.1 tracks symlinks in `local_files` "carrying the link's own (lstat) mtime
and its target as the change signal", and §8 identifies a content-less kind by
`(kind, target)`. Three implementation choices follow:

- **The target's signal lives in `local_files.content`, as `blake3(target)`.**
  That column already means "the content this path reduced to" for a file, and
  a link's only content is where it points, so no migration and no new column.
  `Node::open`'s reconciliation reads a published entry the same way — target
  hash for a link, content root for a file — or every open would drop every
  link's row and re-stage it forever.
- **`entries` grew a `symlink_target` column** (migration v6), because the
  unified tree is computed from `entries` and version identity now depends on
  the target. The table is rebuilt rather than `ALTER ... ADD COLUMN`-ed so the
  stored DDL reads in declaration order instead of trailing the primary key.
- **The staged entry keeps the link's real lstat mtime**, and its `size` is the
  target's byte length. Stamping `now_ns()` — which is what the code did — made
  every scan restate every link, so an unchanged tree published a head on every
  pass, and a symlink beat every file on `newest` forever purely by being
  rescanned most recently.

The version order gains the target as a component: `(mtime_ns, content_root,
symlink target, origin)`. §8's three-part order was written for versions that
are identified by a content root, and two symlinks with different targets are
two versions that share `None` there; without the extra component the order
would break their tie on the *origin*, which §8 reserves for choosing which
attestor is named, never which version wins.

Mirrors materialize a symlink as a real symbolic link on unix. Windows has
symlinks but creating one needs Developer Mode or
`SeCreateSymbolicLinkPrivilege`, which a background daemon can neither assume
nor usefully acquire, so there the path is **skipped and reported** — the same
rule §7.2 already applies to names the platform refuses. Writing the target's
contents under the link's name would silently turn a link into a file and hand
the next scanner on that machine a change nobody made.

### §5.4, §8 — what retention actually retains, and what it measures against

§5.4 keeps old roots for `root_retention` and sweeps the rest; §8 makes content
GC pin- and retention-driven. The maintenance pass runs the three steps in the
order the mark set demands — prune `head_history`, sweep `trie_nodes` /
`trie_values`, sweep content — because the trie mark set is "complete and
pending heads plus *remaining* history roots", so marking from every root ever
recorded would sweep nothing at all, and an object leaves `referenced_content`
only once the trie sweep has taken the entries naming it.

Four judgements the design leaves open:

- **History ages on `created_at`**, which is the only time `head_history`
  carries. For this node's own publishes that is this node's clock. For a
  replicated origin it is the origin's, which is the same member-supplied
  metadata §8 and §12 already accept for `mtime_ns` — a skewed member can hold
  its own history in our retention longer or shorter than intended, and no
  more.
- **The current heads are never pruned.** `Node::publish` records the head it
  just minted in `head_history` as well as in the `complete` slot, so a plain
  age rule would eventually drop the row for the root the node is actually
  serving. Both slots are exempt by identity, not by age.
- **Same-seq fork evidence outlives ordinary retention.** Two roots at one seq
  are provable equivocation (§4.4) and the fork side of a recovery (§3.4),
  which `synch doctor` surfaces on every node — dropping them on a timer would
  silently retire the proof. They are kept until the origin has published past
  the forked seq *and* the head that did so is itself older than retention: at
  that point the cluster has visibly moved beyond the fork, and the evidence
  ages out like anything else.
- **Content ages on `last_access`, which is written on ingest and on download
  milestones, not on reads.** A streaming read would otherwise cost one row
  update per chunk, and an object no entry references is by construction not
  being read through the tree. The window's real job is to stop a just-fetched
  historical root — one nothing currently references — from being swept out
  from under the fetch that produced it.

### §3.2, §3.4 — when membership is re-resolved, and what triggers it

§3.2 says records are re-resolved on the TTL, clamped to `[60 s, 24 h]`, and
§3.4 adds that an inbound connection from an unknown key triggers an immediate
re-resolution. Both run in the daemon's DNS loop (`Node::run_dns`), beside the
maintenance loop that expires bindings — the two exist as a pair, because
expiry without renewal dissolves a DNSSEC cluster one TTL plus grace after the
last manual `synch domain refresh`.

Three things the design leaves open:

- **The schedule lives in memory, not in the database.** It is a property of a
  running daemon, and a restart re-resolving every configured domain once is
  the right behavior anyway. A domain that has never been resolved — one
  `synch domain add` just wrote — is due immediately.
- **The trigger is rate-limited per domain**, at 30 s. The bell is rung by an
  inbound refusal, which a peer that keeps retrying produces as fast as it can
  dial, so an unlimited trigger would be a query amplifier pointed at the
  cluster's own zone. Within a cooldown window the refusals are counted and
  ignored; the TTL schedule is unaffected.
- **A failed lookup moves the retry time, and nothing else.** Failing closed
  (§3.2) means the cached bindings keep their own expiry, so a resolver outage
  degrades the cluster on the schedule §3.2 describes rather than on the
  schedule the outage would otherwise dictate. The retry waits one clamped
  minimum TTL, so a resolver that is down is not polled in a tight loop.

The refresh resolves through a `MemberResolver` trait rather than a concrete
`DnssecResolver`, so the loop's scheduling can be asserted on without a live
signed zone. `DnssecResolver` is the only implementation a running node ever
uses, and it is unchanged: in-process validation, per-record `Proof::is_secure()`.

### §3.4, §5.1 — what `synch key ls` counts, and what it refuses to count

`GetBindings`/`BindingsFor` are appended to `MptMessage` *after* `Error`, which
is where a new variant has to go: postcard numbers variants by position, so
only the end is free.

`synch key ls` asks every trusted peer it can dial and reports, per local key,
"bound by N of M reachable peers" plus a line per peer. Two choices worth
naming:

- **The peer answers with live bindings only.** A lapsed binding is precisely
  what the asker wants to know is gone, so an expired row counts as absent.
- **An unreachable peer is reported, never counted.** "Three of four peers hold
  `K_new`, one is asleep" is a different fact from "three of four hold it and
  one does not", and the operator judgement §3.4 hands to a human depends on
  telling them apart. When nothing could be reached, the tallies say `0 of 0`
  and a line says so, rather than reading as a unanimous no.

The question is asked about *our* origin, and answered by peers who are already
authorized members (§3.2), so it carries nothing they could not already read
out of their own bindings table.

### §3.4 — rotating a key-identified origin

`synch key rotate` on an `OriginId::Key` origin now fails before it generates
anything. The device key *is* the identity there (§3.1), so there is no `id=`
to rebind and no record to publish; the old behavior stored a `retiring` key
that could never be activated and that nothing ever cleaned up. The message
names both ways out: re-init under a named origin, or have peers bind the key
with `synch trust add --as <name>`.

### §7.1 — spaces added while the daemon runs

The watcher registers every configured space root with `notify` and
re-registers on every debounced pass, plus immediately when `space add` or
`space rm` rings its bell. A watcher whose set was fixed at startup would leave
a newly added space covered only by the hourly rescan, and would keep waking
for a directory nobody indexes any more. Failing to watch a root stays
non-fatal, exactly as at startup: the periodic scan is the guarantee, and the
watcher is a latency optimization.

### §9.2 — `synch pin` and `synch domain refresh` argument forms

`synch pin add|rm` accepts a hex object root or a `[<origin>:]<space>/<path>`.
A path is resolved through the same selection every other read goes through
(§8), so pinning `media/notes.txt` and `synch cat media/notes.txt` always mean
the same bytes; an `<origin>:` prefix pins that origin's version. Text with no
`/` in it was meant to be a root and is reported as a bad root rather than as a
bad space.

`synch domain refresh` takes an optional domain and refreshes just that one. A
domain the node was never told about is a typo, so it is refused before a
resolver is even built.

## Adapted to the dependencies

### §9.3 — the control token's randomness

The 32 random bytes in `control.token` come from `SecretKey::generate()`, which
is the same OS CSPRNG that mints device keys, rather than from a separate `rand`
dependency at a version this workspace does not otherwise pin.

Filesystem permissions are enforced where the platform has them: on Unix the
data directory is `0700` and the token and socket are `0600`. The token file is
*created* `0600` rather than chmod-ed afterwards; the socket can only be
restricted once `bind` has made it, and the `0700` directory around it is what
covers that instant. Windows has no equivalent, which is the case §9.3 already
anticipates — there the token carries the whole check, and it is checked on
every request on both platforms.

### §10 — the migration chain, and what is *not* in it

§10 specifies the chain: `MIGRATIONS[v]` takes a database from version `v` to
`v + 1`, each step is one transaction that carries the `schema_version` stamp,
a fresh database replays the whole chain, and a newer-than-known database is
refused. That is implemented literally in `schema.rs` and `db.rs`, with the
chain indexed from zero — `MIGRATIONS[0]` takes an *empty* file to version 1,
the original schema — so "fresh database" and "database at version 0" are the
same case and there is one code path, not two. There is no `IF NOT EXISTS`
anywhere.

Three details §10 leaves open:

- **A step may be SQL or Rust** (`Migration::Sql` / `Migration::Rust`), and
  both run under the same transaction rule. The Rust form exists for what SQL
  in this schema cannot express — v5 rewrites the `synch-s3` bucket map, which
  lives as tab-separated text in a `config` row rather than as a table.
- **An unstamped database is refused**, not adopted. Every database this
  software has written stamps itself inside the transaction that shaped it, so
  a `config` table with no `schema_version` row is not a version the binary can
  reason about; guessing "it must be current" is exactly the drift the chain
  exists to prevent.
- **The §10 DDL is kept as a test-only constant** (`FINAL_SCHEMA`), and a test
  asserts that a database built from it and one built by replaying the chain
  have identical `sqlite_master` contents — every object, with its SQL
  normalized for comments and whitespace. It is `#[cfg(test)]` precisely so it
  cannot become a second bootstrap path.

The chain to date:

| Step | Takes | To | What |
| --- | --- | --- | --- |
| 0 | empty | 1 | the original schema, as it first shipped |
| 1 | 1 | 2 | `observed_heads`, for key-loss recovery (§3.4) |
| 2 | 2 | 3 | drop the dead `want` table |
| 3 | 3 | 4 | reshape `mirrors` for the unified tree (§7.2) |
| 4 | 4 | 5 | reshape the `synch-s3` bucket map (§9.4) |
| 5 | 5 | 6 | `entries.symlink_target`, for §8 version identity |

Steps 0–2 reproduce the history that shipped before the chain existed: a
database stamped 1, 2, or 3 by an older build lands on exactly the version the
chain says it is at, and upgrades from there.

The `want` table itself described a persistent download queue. §6.4 is
explicitly queue-less — fetching is on-demand and request-scoped, and progress
survives restarts through the CAS rather than through a queue — so the table
never had a producer or a consumer, and dropping it removes a shape the design
does not have.

### §10 — one connection, and the scope that makes "one transaction" a type

§10 asks for "all access through one mutex-guarded connection", and that is
literally what this is: one `rusqlite::Connection` behind a `Mutex`, WAL mode,
`synchronous=NORMAL`. §10 accepts the cost the arrangement carries: readers
serialize behind the same mutex instead of running concurrently.

The invariant the section actually cares about — every multi-step state change
is a single transaction, and no partial state is ever observable — is enforced
by `Store::transaction`, which hands the caller a `Txn` scope. A `Txn` is both
a `NodeStore`, so trie writes join the transaction, and the head, history, and
materialization surface a publish or a promotion needs. Since the scope is the
only way to reach those methods, "trie writes, head, history, and
materialization commit together or not at all" is a property of the type rather
than a convention someone has to remember.

Two details:

- **The scope carries the caller's error type.** `Store::transaction` is
  generic over any error that converts from `StoreError`, so `Node::publish`
  rolls back on an `EngineError` and `Syncer::try_promote` on a `NetError`
  without either of them adopting the store's. No `rusqlite` type crosses the
  crate boundary in either direction.
- **Reads that decide the write happen inside it.** `Node::publish` reads the
  head it is about to displace from within the transaction, so the root it
  builds on and the seq it builds past come from the same snapshot the flip is
  written against, rather than from a moment when the mutex was not held.

A non-obvious consequence: a mid-publish failure now takes the *trie writes*
back too. Content-addressed nodes are harmless garbage that GC would sweep
eventually, but rolling them back means a failed publish leaves the database
byte-for-byte where it started, which is what makes the crash-safety tests able
to assert equality rather than "close enough".

### §6.2 — outboard file naming

The design writes `store/<hex[0..2]>/<hex>` for payloads and `store/<hex>.obao`
for outboards. This implementation shards both the same way:
`store/<hex[0..2]>/<hex>` and `store/<hex[0..2]>/<hex>.obao`, so a large store
does not accumulate one flat directory of outboards.

### §6.1 — outboards in memory during ingest and slice decode

`bao-tree`'s sync API builds an outboard into a caller-provided buffer, so
ingest holds the whole outboard in memory: 64 bytes per 16 KiB group, about
1/256 of the object, so ~390 MB for a 100 GB file. Slice *encoding* also reads
the outboard file whole. Slice *decoding* streams into the on-disk outboard
through `positioned-io`, so the receive path is already incremental.

Objects at or below 16 KiB are inlined in SQLite and have an empty outboard by
construction.

### §6.4 — slice framing

The design describes the response as "a bao slice stream, verified incrementally
by the requester", terminated by `SliceEnd`. This implementation sends the slice
as one length-framed payload followed by the `SliceEnd` frame, because the
decoder needs to know which ranges the encoding covers before it can verify —
and that is precisely what `SliceEnd` reports. Verification is still per-16 KiB
group and still happens before any byte is committed to the CAS; what is
buffered is one request's worth of slice, which the requester bounds by choosing
the ranges it asks for.

### §5.1 — the `Hello` exchange shape

The design lists `Hello` / `HeadsWant` / `Heads` as push-pull. This
implementation runs them as a fixed five-message exchange on one stream:

```
C→S  Hello     (client summaries)
S→C  Hello     (server summaries)
C→S  Heads     (heads the client holds that the server lacks)   — the push
C→S  HeadsWant (origins where the server is ahead)
S→C  Heads     (the wanted signed heads)                        — the pull
```

Both directions of head propagation complete in one round trip, and every
message is one of the §5.1 schema types.

One behavior the design implies but does not spell out is implemented here: a
head delivered by reactive `HeadPush` lands in the pending slot and is therefore
*not* newer than what the receiver holds, so the next `Hello` exchange would
never ask for its trie. `sync_with` additionally fetches any pending head's trie
from a peer advertising a complete head for that origin at or above its seq,
which is exactly what §5.2's peer-agnostic clause permits.

### §4.2 — `EntryKind::Dir`

The scanner does not emit `Dir` records. Directory listings come from range
scans over the `f:` prefix, which is how §4.1 describes them, so explicit
directory records would be redundant metadata. The variant exists, round-trips
on the wire, and is honored on read, so an origin that does publish them is
handled correctly.

### §7.1 — `file_id`

The `(size, mtime_ns, file_id)` change-detection triple uses `(dev, ino)` on
Unix and **no file identity at all on Windows**. `std::os::windows::fs::
MetadataExt::file_index` is still unstable (rust-lang/rust#63010) and does not
compile on stable, and obtaining the index otherwise costs an open handle per
file during every scan. Identity is `Option` by design, so Windows falls back
to comparing size and mtime, and re-hashes on ambiguity — the safe direction.

The visible consequence is narrow: a Windows file replaced by a different file
with byte-identical size and mtime is not re-hashed until the next full scan.
Restoring identity would mean calling `GetFileInformationByHandle` through a
`windows-sys` dependency; deferred as not yet worth the dependency.

### §9.4 — `PutObject` publish timing

The design says `PutObject` "responds once durably staged, with the head publish
following the usual batching". This implementation runs the scan and publish
synchronously before responding — deliberately around the batching publisher
rather than through it — so the ETag returned is always backed by a published
entry. It is stricter than specified, not looser.

### §9.4 — the bucket map's shape, and what a strict bucket lists

The bucket map has never been a table: it is tab-separated text in the
`s3_buckets` `config` row, because it belongs to the gateway rather than to the
node. Reshaping it from `<bucket>\t<origin>\t<space>` to
`<bucket>\t<space>\t<policy>` is therefore a Rust step in the ordinary
migration chain (v5, §10) rather than a table rewrite, and an existing bucket
comes out as an `origin=` pin on the origin it used to name — serving exactly
what it served before. Both shapes have three fields, so a loader that tried to
sniff which one it had would eventually guess wrong; doing it once, in a
numbered step, means the reader only ever sees one shape.

§9.4 says a `strict` bucket answers a divergent key with `409 Conflict` naming
the versions, and `GetObject`/`HeadObject` do exactly that (code
`DivergentVersions`, the version list in the message). It does not say what
`ListObjectsV2` should do, and a listing has no way to say 409 about one key —
so a strict bucket **omits divergent keys from its listings** rather than
publishing one side's size and ETag under a name it refuses to resolve. A
direct `GET` of such a key then explains what is wrong. `newest` and `origin=`
buckets list every key the tree carries.

Writes need no such care: §9.4 makes every bucket writable because a write is a
publish of the *local* node's view. A bucket pinned to a foreign origin still
accepts the write — it simply will not read back through that bucket — and the
gateway logs the warning §9.4 asks for whenever such a bucket is configured,
served, or written to.

### §9.4 — SigV4 test vectors

SigV4 verification is tested by pinning the canonical-request and
string-to-sign layouts exactly, checking the four-step key derivation reacts to
every scope component, and round-tripping sign-then-verify through the real HTTP
gateway with negative cases for unsigned, unknown-key, and tampered requests.
It is *not* checked against an external AWS-published test vector, because doing
that offline would mean hard-coding a value that could not be verified here.

## Dependency versions

Pinned in the workspace `Cargo.toml`. The notable ones:

- `iroh` 1.0.3 — the 1.0 API renamed `NodeId`/`NodeAddr` to
  `EndpointId`/`EndpointAddr`. `synch-core` re-exports `iroh_base::PublicKey` as
  `NodeId` so the design's vocabulary survives in the data model.
- `bao-tree` 0.16 — used through its synchronous `io::sync` API.
- `rusqlite` 0.40 with `bundled`, so no system SQLite is needed.
- `hickory-resolver` 0.26 with `dnssec-ring`, configured with `validate = true`
  and an additional per-record `Proof::is_secure()` check, so an insecure or
  bogus answer is discarded rather than trusted.
- No `openssl` anywhere: `rustls` throughout, via `iroh`'s `tls-ring` feature
  and `reqwest`'s `rustls` feature in tests.
