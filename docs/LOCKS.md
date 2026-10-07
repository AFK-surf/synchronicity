# Cluster locks — best-effort mutual exclusion without consensus

Status: built (phases 1 and 2 of §16) · 2026-10-07

A cluster lock is a named lease that at most one node holds at a time **while the
nodes that want it can talk to each other promptly**. When they cannot, because of a
partition, a sleeping laptop, or a link slower than the claim window, each side may
grant the lock and the cluster has two holders. That is the trade this design makes on
purpose. It is an AP lock: a node that can reach nobody can still lock, nothing waits
for a majority, and split brain is detected and ended when the sides meet again.
Nothing about it is hidden.

The lock is for coordination that the system's version model already makes
recoverable. Two holders writing the same path do not lose data. They produce two
versions, which §8 of DESIGN.md treats as ordinary divergence that stays visible. What
the lock buys is that, in the normal case, they do not.

Users reach locks through three surfaces, which share one name space:

- `synch lock …`, a `flock(1)`-shaped CLI (§10).
- **S3 lock keys**, which are conditional writes on keys a bucket declares as locks.
  This is the protocol Terraform's S3 backend (`use_lockfile`) and similar tools
  already speak (§11).
- **Fenced writes**, a put that commits only while its lock is still held (§7).

The safety claim in §3.4 is model-checked by [`specs/Locks.tla`](../specs/Locks.tla)
(§15).

---

## 1. Goals and non-goals

### Goals

- **No coordinator, no quorum.** Every node is a peer (DESIGN.md §1). A lock is
  granted by an exchange among the nodes that might contend for it. No node is
  special and no majority is needed. A node alone on a plane can take a lock.
- **Exclusive under bounded latency.** If every pair of contending nodes exchanges a
  message within the claim window Δ, and clock rates drift by at most ρ, at most one
  node holds a lock at any instant. §2 states this exactly.
- **Split brain is visible and heals deterministically.** When the assumption fails,
  both holders find out once they can talk again. Every node then picks the same
  survivor from data they all hold (§6).
- **Lock handoff carries the previous holder's writes.** Acquiring a lock that was
  last released by another node waits until this node has that node's published
  head as of the release (§8). Read-modify-write under a lock then reads what the
  last holder wrote, and that is the main reason to take a lock in a file store.
- **Monotone fencing tokens** while the assumption holds (§7).
- **Cheap.** An uncontended acquire costs one round trip to every peer, run
  concurrently, and nothing durable anywhere but on the holder.

### Non-goals

- **Linearizability, or safety under partition.** Getting those needs a quorum and
  gives up availability on the minority side. Deployments that need a CP lock should
  use a CP service (etcd, a cloud lock table) and treat synchronicity as storage.
- **Byzantine members.** Membership is closed and mutually trusting (DESIGN.md §1). A
  member can deny any lock by claiming it forever. §13 covers what bounds that.
- **Locks that outlive their holder indefinitely.** Every hold is a lease (§5). A
  holder that crashes for longer than its lease loses the lock.
- **Recording lock history in the tree.** Lock state is soft state (§9.1).

---

## 2. The guarantee, stated

**Model.** Nodes communicate over authenticated iroh connections. Each node has a
monotonic clock whose rate is within ρ of real time. The **bounded-latency
assumption** for a lock is this: any two nodes that contend for it can each deliver
a message to the other, and receive the reply, within the claim window Δ.

**Exclusion.** Under the bounded-latency assumption, at most one node is in the
*held* state for a lock at any real instant. A client that stops using the lock at
the deadline its node reported is never inside the critical section at the same time
as another node's client (§5).

**Exclusion needs only the contenders.** Safety depends on each *pair of contenders*
reaching each other, not on reaching everyone. Two nodes on the same side of a
partition still exclude each other. Bystanders' answers add information (§3.3) but
never decide anything.

**What breaks it.** Anything that delays a contender-to-contender exchange past Δ:

- a partition;
- a peer that is up but whose replies are slower than Δ;
- a holder process stalled past its lease (a GC pause, a suspended VM);
- a clock rate outside ρ.

Each of these can produce two holders. The partitioned TLC configuration exists to
show that the model still produces two holders when messages can be lost (§15).

**After the assumption fails.** Two holders that can communicate again detect each
other within one renewal interval (ttl/3) of reconnecting. Every node then picks the
same survivor (§6), and the other holder is told it lost the lock.

**What the lock does not promise.** It makes no promise about how fast the lock
moves between nodes, how fair it is among waiters, or whether a *client* actually
stops when its lease ends. An S3 client that never checks cannot be stopped. Fenced
writes (§7) are the tool for the cases where that matters.

---

## 3. The claim exchange

### 3.1 Names and who may contend

A lock is named `<space>/<name>`. `name` is any UTF-8 string of at most 512 bytes and
need not be a path. It may also equal a path in the tree, and that is how S3 lock
keys share names with the CLI (§11.1). The space decides authorization and scope:

- **Claims** are accepted only from origins that may *write* the space: members, and
  delegates whose grant lists the space read-write (DESIGN.md §3.5). A node that
  could not publish to the space has nothing a lock would protect.
- **Claims are sent** to every trusted member and to every delegate with a read-write
  grant on the space. They are never sent to a peer whose scope excludes the space:
  a lock's name is metadata of its space and follows §5.5's redaction rule.

"Peers" below means that set, for that space.

### 3.2 State

Each node keeps a **lock table** in memory. It maps each lock to the claims the node
currently believes live, and it is bounded (§14). A claim is:

```rust
struct ClaimInfo {
    lock: LockName,          // (space, name)
    ticket: Ticket,          // (lamport: u64, origin: OriginId): the total order
    nonce: u64,              // with the ticket, the claim's identity
    ttl_ms: u32,             // the lease observers keep without a renewal
    owner: String,           // display only: "alice@laptop", an S3 access key; ≤ 128 B
    payload: Bytes,          // opaque, ≤ 16 KiB; an S3 lock key's body (§11)
    supersedes: Vec<ClaimId>,// expired claims this one took over from (§6)
}
```

The table also keeps an **ended memory**: the claim ids it knows were released,
withdrawn, broken or superseded, each with its reason (§4). An ended claim never
becomes live again on a node that remembers it, whatever arrives later.

Each node keeps a **Lamport clock** (`lock_clock`, §9.2). The clock rises past every
ticket the node hears of and is persisted before a claim carrying it is sent.

### 3.3 Acquiring

To acquire lock `L`, node `A` does the following.

1. **Claim.** Take `ticket = (lamport + 1, A)`, where `lamport` is the clock's value
   after folding in every ticket in `A`'s table for `L`. Persist the clock, record the
   claim in `A`'s own table as *contending*, and send `Claim` to every peer at once.
   Each send waits at most Δ, including the dial.
2. **Answer** (at each peer `P`). Unless the claim is in `P`'s ended memory, `P`
   records it, raises its clock past the ticket, and answers with every claim it
   holds live for `L`. If `P` holds `L` itself, it marks its own claim **held**. It
   also includes its ended memory for `L` and the handoff watermarks it knows (§8).
   Recording and answering happen in one step under `P`'s per-lock mutex.
3. **Decide**, once every peer has answered or its Δ has run out. `A` collects the
   claims it *knows of*: those in every answer, after dropping any id in `A`'s or an
   answer's ended memory, plus those in `A`'s own table at this moment. `A` holds
   `L` if and only if both of these are true:
   - its ticket is the least among those claims;
   - no other claim among them is marked held.

   Otherwise `A` withdraws: it sends `End(Withdrawn)` to every peer and drops the
   claim.

   When `A` holds, it lists in `supersedes` every claim it knew of only as
   *expired* (below). One more check comes before holding. If any answer shows a
   claim of `L` that was *held* and has ended — released, broken or superseded —
   with a ticket above `A`'s, `A` withdraws and re-claims above it. Withdrawing is
   always safe, and this keeps fencing tokens monotone after a restart that lost
   the clock's last increments (§7). Live claims, and rivals that merely withdrew,
   are left out on purpose: re-claiming above them would make the least ticket
   give way to its rivals, and simultaneous claimants could livelock.

A withdrawn claimant with `--wait` time left re-claims with a fresh, higher ticket.
It does this when an `End` for the blocking claim arrives, or after a jittered
back-off of up to ttl/3, whichever comes first. Re-claiming is a new claim, so a
waiter never reaches the critical section through an old one.

**Holding and expiry.** A node in the held state marks its claim held in every
answer it gives (step 2). An observer marks a claim held once it has received a
`Renew` for it.

An observer **expires** a claim when its lease runs out without a renewal (§5). An
expired claim is no longer live but is not ended either. It stays in the table as
*expired* until the ended-memory horizon, so that the claim that takes over from it
can name it in `supersedes` (§6). The holder's own `held` answer always outranks a
third party's report of expiry. If the holder is reachable and says it holds, it
holds.

### 3.4 Why it is exclusive

Take two nodes `A` and `B` that both decide to hold, and that each received the
other's answer (the bounded-latency assumption). Two independent arguments each rule
this out.

**Held marks and the decision-time table.** Consider when `B` processed `A`'s claim.

- If it was after `B` decided to hold, `B`'s answer marked `B` held, so `A` withdrew.
- So it was before `B` decided. Then `A`'s claim was in `B`'s table at `B`'s
  decision, and `B` held only because `B < A`.
- By symmetry `A < B`, a contradiction.

**Ticket order.** Consider whether each claimant's answer showed the other.

- If neither showed the other, then each node processed the other's claim before it
  began its own. Both cannot be true, because each processed the other's claim after
  the other began.
- If exactly one showed the other, say `A` saw `B` but `B` did not see `A`, then `A`
  processed `B`'s claim before `A` began. `A`'s clock then passed `B`'s ticket, so
  `A > B` and `A` did not hold.
- If both showed the other, both compared the same two tickets, and only the lesser
  held.

Either mechanism alone is enough. TLC confirms this by mutation (§15): removing
either one keeps `MutualExclusion`, and removing both breaks it. The design keeps
both because each also does a job of its own:

- Ticket order makes fencing tokens monotone (§7) and gives an un-held lock a winner
  among simultaneous claimants. The least ticket always holds, so there is no
  livelock.
- The held mark gives an incumbent priority over a newcomer whose ticket happens to be
  lower. After a split-brain heal (§6) the newcomer's ticket is not ordered after the
  incumbent's.

**Third parties never decide.** Bystander answers can only add claims to what `A`
knows of, so they can only make `A` withdraw. This matters in a partial partition:
if `A` cannot reach `B` but `C` can reach both, `C`'s answer carries `B`'s claim to
`A`, and `A` defers to it. Split brain in that topology is less likely than the
model's worst case, but this is not a guarantee.

### 3.5 Rejected: skipping peers known to be down

Every uncontended acquire waits up to Δ for a peer that is off, such as a laptop
asleep in a bag. The obvious optimization is to stop waiting for a peer whose last
dial failed. That is unsafe even when every message is eventually delivered.

Suppose `A` and `B` each hold a stale belief that the other is down. Both decide
without waiting, and both hold. TLC finds this at once in a variant of the model
whose timeouts fire without any message being lost.

The design therefore pays up to Δ, concurrently, per acquire whenever a peer is
unreachable. With the default Δ of 2 s that is the same budget a reactive head push
gets (DESIGN.md §5.3). `synch lock status` names the peers an acquire waited on, so
an operator can see why.

---

## 4. Ending a claim

| Reason | Sent by | When |
|---|---|---|
| `Released` | holder | the client released the lock; carries the handoff watermark (§8) |
| `Withdrawn` | claimant | lost the decision in §3.3 step 3 |
| `Superseded` | the yielding holder | lost a split-brain heal (§6) |
| `Broken` | any writer of the space | an operator or S3 client forced it (§10, §11) |

`End` goes to every peer, and every recipient adds the id to its ended memory. The
ended memory is what lets a late message never revive the claim: a `Claim` or
`Renew` that arrives after its `End` is answered with the end and not recorded.

Ended memory is kept for twice the longest lease in force, bounded by the limits in
§14. That is far past any message delay the bounded-latency assumption allows.

A lost `End` costs liveness, not safety. The claim stays live at that peer until its
lease expires, and claimants that hear of it from that peer defer to it. Every
answer carries the answerer's ended memory for the lock, so one peer's knowledge of
an end reaches every claimant that asks it.

**Breaking a claim from another node** is allowed for any writer of the space. That
matches S3, where any writer may delete a lock object, and it is how Terraform's
`force-unlock` works. The broken holder learns of it in the answer to its next
renewal (§5) and reports the lock lost. Breaking is an operator action and is logged
on every node that receives it.

---

## 5. Leases and time

No decision compares wall clocks across nodes. Created-at stamps are display
metadata here too (DESIGN.md §4.4). Every lease is a *duration*, measured on the
local monotonic clock of whoever measures it:

- **The holder** dates its lease from the instant `s` it *sent* the claim or the
  renewal, which is earlier than any observer's receipt. The holder considers the
  lock held until `s + ttl`. It reports a deadline to its client with Δ subtracted
  from that, so a client that obeys the deadline stops before the holder's lease
  ends, even after the response's own latency.
- **An observer** dates the lease from the instant `r` it *received* the claim or
  renewal, and keeps the claim until `r + ttl·(1 + 2ρ)`.

Because `r ≥ s` in real time and both clocks run within ρ of real time, the observer's
expiry is never earlier than the holder's. ρ defaults to 10⁻³, far beyond what any
working oscillator drifts. With that value the observer's margin on a 30 s lease is
60 ms.

**Renewal.** The holder sends `Renew` to every peer every ttl/3, and once right
after it wins, so peers that answered its claim before it held learn that it holds.
A renewal carries the whole claim, so a peer that restarted relearns it. The answers
have the same shape as claim answers, and a heal is detected at the first renewal
that crosses the healed link (§6). A renewal
answered with an end (`Broken`, or `Superseded` in §6) means the lock is lost. The
holder stops renewing and reports the loss to its client.

The holder extends its own deadline when it *sends* the renewal, not when the
renewal is acknowledged. A partitioned holder therefore keeps its lock. That is the
AP choice: under partition both sides may believe they hold, and §6 is what ends it.

**Hold modes.** These describe who renews, not anything on the wire:

| Mode | Renewed by | Ends when | Used by |
|---|---|---|---|
| `session` | the daemon, while the client's control stream is open | the stream closes, or release | `synch lock run`, `synch lock acquire --hold` |
| `lease` | the client, explicitly | `ttl` passes without a renewal, or release | `synch lock acquire`, S3 with a TTL (§11) |
| `sticky` | the daemon, indefinitely | release or break | S3 lock keys by default, `--sticky` |

A `lease`-mode hold whose client lets its deadline pass is ended by the holder as a
release, with a watermark, exactly as if the client had released it.

**Restart.** A holder persists its held claims in SQLite (§9.2). The other two
outcomes are not acceptable:

- A daemon restart that forgot a sticky S3 lock would release it behind a client
  that still believes it holds it.
- A daemon that restored the lock unconditionally could resurrect a lease that ran
  out while it was down.

So a restarted daemon restores each held claim as *unconfirmed*. It answers claims
for the lock as held, which is the conservative choice, and sends `Renew` at once.
If any answer reports the claim ended, or reports a held claim that supersedes it
(§6), the lock is lost. Otherwise it is confirmed. A `lease`-mode hold whose wall-clock deadline passed
while the daemon was down is dropped, not renewed. This is the one place a wall
clock is consulted, and only to give up a lock, never to keep one.

---

## 6. Split brain: detection and healing

Two holders of one lock find each other through renewals. Each renewal answer
carries every claim the answering peer holds live, held marks included. Holder `X`
sees another claim `Y` reported held, either by `Y`'s own node or by any observer
`Y` renewed through. Both `X` and `Y` are then in a **contested** state. Every node
that holds both claims ranks them by one rule, applied in order:

1. **Supersession.** If `Y.supersedes` names `X`, then `Y` took the lock after `X`'s
   lease expired as far as `Y`'s side could tell. `Y` keeps the lock. This is the
   case of a holder that was partitioned or crashed past its lease while the rest of
   the cluster moved on. That holder is the stale one, even though its ticket is
   lower.
2. **Ticket.** Otherwise the lesser ticket keeps the lock. Neither holder has a
   better claim than the other, and the ticket is data both have.

The loser sends `End(Superseded)`, stops renewing, and reports the lock lost.

- A `session` client gets a `lost` event. `synch lock run` signals its child
  (§10).
- A sticky S3 lock simply changes hands. A `GET` of the lock key now returns the
  survivor's body.
- The losing node logs the loss with both claims' tokens, and `synch lock status`
  shows a lock as contested while more than one claim on it is reported held.

Healing does not undo what both holders did meanwhile. Writes they made to the same
paths are two versions of each path. §8 of DESIGN.md shows them as divergent and
leaves the resolution to someone (`synch adopt`) until they are resolved. In this
system, split brain degrades into visible divergence and not into a lost update.
That property is the reason an AP lock is acceptable here.

---

## 7. Fencing

A claim's **token** is its ticket and nonce rendered as text:
`<lamport>-<origin hex>-<nonce hex>`. Clients treat it as opaque, and it orders by
ticket.

**Monotonicity.** Under the bounded-latency assumption, successive holders' tokens
increase. A holder waited for the next holder's node to answer its claim, which
raised that node's clock past the holder's ticket. A clock raised by an answer is
persisted write-behind, so a crash can lose its last increments. The re-claim rule
in §3.3 step 3 covers that loss for as long as some peer's ended memory still holds
the predecessor. Under partition monotonicity fails, as everything else does.

**Fenced writes** are commits that check the lock first. `synch put --lock
<space>/<name> --token <t>` and the S3 header `x-synch-lock` (§11.3) commit only if
this node holds that lock with that token, unexpired, at the instant the write
commits. The check runs under the tree-write commit lock (TREE-WRITES.md §5.3), so
a lease that ends mid-upload refuses the commit and not just the request. A stale
holder cannot commit after it lost the lock, and that includes a client that
outlived its lease, a lock that was broken, and a lock superseded in a heal.

Fencing guards *this node's* commits only. A write on another node is that node's
own version and could not overwrite this one anyway (DESIGN.md §8). What a fenced
write prevents is the stale holder adding a *new* version after its successor took
over. That is the classic fencing hazard, translated into a store where versions
never overwrite.

---

## 8. Handoff: acquiring sees the last holder's writes

A lock that protects a read-modify-write is useless if the next holder reads before
the last holder's write has reached it. In this system, publication is asynchronous
anti-entropy (DESIGN.md §5.3). So:

- **Release flushes first.** Before sending `End(Released)`, the holder waits for any
  staged publish to be signed (`flush_staged`). It then attaches a **watermark**: its
  origin and the seq of its newest head.
- **Peers remember watermarks** per lock, keeping the newest per origin for the last
  8 releasers, for as long as the ended memory lasts. Every answer carries them.
- **The next acquirer waits.** Before reporting the lock acquired to its client, the
  acquirer waits, up to the handoff window (default 10 s), until its *complete* head
  for each watermark's origin reaches that seq. It runs an anti-entropy exchange
  with the releaser's keys at once instead of waiting for the next round.
  Promotion in DESIGN.md §5.2 is what makes "complete" mean "readable".

If the window passes first, the acquire fails with the retryable code
`handoff-pending` and the claim is released. `--allow-behind` turns this into a
warning for callers that read nothing from the tree. This is a liveness cost under
partition, not a safety cost. If the previous holder's trie is unreachable, its
writes are unreachable too, and reading without them is exactly the lost update the
lock exists to prevent.

The handoff guarantees that the bytes are *on this node*. Whether a read *returns*
them depends on the read's version policy. `newest` picks by `mtime_ns`, which a
member with a skewed clock can win (DESIGN.md §8). Lock-protected workflows that
cannot tolerate that should read with `--select origin=<last holder>`. The lock
status names the last holder for exactly this purpose. They can also adopt
(`synch adopt path`) before modifying.

---

## 9. Where it lives

### 9.1 Not in the trie

Lock claims are not trie records and are never published in a signed head. Using
the trie was considered and rejected:

- **Latency is hostage to promotion.** A head push lands in the receiver's pending
  slot, and the data moves only after a trie fetch and promotion (DESIGN.md §5.3).
  That makes "every peer has seen my claim" unbounded in exactly the way the claim
  window must not be.
- **Churn.** Every acquire, renewal and release would be a head. Each head is pushed
  to the whole membership and retained for `root_retention` (7 days). A renewal
  every 10 s per held lock would dominate a quiet cluster's metadata.
- **The wrong durability.** A lock is a lease whose meaning ends with its holder's
  liveness. The trie is signed, replicated history. Persisting a lease cluster-wide
  is how a crashed holder's lock outlives it.

Lock traffic therefore runs on its own ALPN, and only the holder persists anything:
its own holds, for restarts (§5).

### 9.2 Components

- **`synch-net`**: ALPN `sync/lock/1`, with length-framed postcard over one
  bidirectional stream per request, the same framing as `sync/mpt/1`. Sessions are
  held open and reused per peer like the other ALPNs (DESIGN.md §5.3). A peer's
  origin is the one its device key is bound to (DESIGN.md §3.1). Claims are not
  signed separately, because the connection authenticates them and relayed claims
  come from trusted members (§13).

  ```rust
  Claim   { lock: LockName, claim: Claim }               → Answer
  Renew   { lock: LockName, claim: Claim }               → Answer
  End     { lock: LockName, id: ClaimId, reason: EndReason,
            watermark: Option<Watermark> }               → Ack
  Inspect { lock: LockName }                             → Answer   // diagnostics only
  Answer  { reports: Vec<Report { claim, state: Expired | Live | Held, remaining_ms }>,
            ended: Vec<(ClaimId, EndReason)>,
            watermarks: Vec<Watermark { origin, seq }> }
         | Refused { reason }  // not a writer of the space; over a limit (§14)
  ```

  A `Refused` answer from a peer that may not write the space counts as an answer:
  that peer cannot contend.
  The schemas live in `synch-core` (`lock.rs`), the protocol handler and client in
  `synch-net` (`lock.rs`), mounted when the engine supplies a `LockService`.
- **`synch-engine`**: `locks.rs` holds the `LockManager`. It owns the table, the
  clock, the node's own claims and the renewal loop. The pure parts are free
  functions at the bottom of that file, so they are the natural unit for a later
  Lean port (§15): the decision in §3.3 step 3 (`decide`), the heal order in §6
  (`heal`), and the observer's lease in §5 (`observer_lease`).
- **SQLite**: local tables, never replicated.

  ```sql
  CREATE TABLE lock_clock (id INTEGER PRIMARY KEY CHECK (id = 0),
                           lamport INTEGER NOT NULL);
  CREATE TABLE lock_holds (
    space TEXT NOT NULL, name TEXT NOT NULL,
    origin TEXT NOT NULL,           -- the ticket's origin; a changed identity drops it
    lamport INTEGER NOT NULL, nonce INTEGER NOT NULL,
    ttl_ms INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('lease', 'sticky')),
    owner TEXT NOT NULL, payload BLOB NOT NULL, supersedes BLOB NOT NULL,
    acquired_at INTEGER NOT NULL,   -- wall clock, display only
    lease_until INTEGER,            -- wall clock; lease mode's restart check (§5)
    PRIMARY KEY (space, name));
  ```

  A `session` hold is not persisted. Its client's stream died with the daemon, and
  so did the hold.
- **Local requesters.** A node has at most one claim per lock. Concurrent local
  attempts on the same lock are serialized in the `LockManager`. A request that
  finds the lock held by another local owner fails with `lock-held`, or waits like
  any other waiter within its `--wait`, and never shares the hold.

### 9.3 Control service

These are program RPCs beside `Read` and `Put`, because the gateway needs structured
answers (DESIGN.md §9.3):

```proto
rpc Lock(LockRequest) returns (stream LockEvent);  // acquire; `session` holds live on the stream
rpc LockRenew(LockRenewRequest) returns (LockHold);
rpc LockRelease(LockReleaseRequest) returns (LockReleased);  // release, or break with `force`
rpc LockStatus(LockStatusRequest) returns (LockStatusResponse);  // this node's view, or every peer's
```

`LockEvent` is `acquired { token, valid_for_ms, handoff, waited_on }` or
`lost { reason }`. Closing a `session` stream releases the lock. `PutHeader` and
`CompleteUploadRequest` gain `lock` and `lock_token` for fenced writes (§7), and the
control version is 7, because a v6 daemon would ignore a fence and commit
unconditionally. Four
new `x-synch-error-code` values are added: `lock-held`, `lock-contended` (lost a
simultaneous claim, retryable at once), `lock-lost` and `handoff-pending`.

---

## 10. CLI

```
synch lock run <space>/<name> [--ttl 30s] [--wait <dur>] [--owner <text>]
               [--on-lost term|kill|ignore] [--allow-behind] -- <cmd> [args…]
        hold the lock for the life of <cmd> (session mode). The child gets
        SYNCH_LOCK_NAME and SYNCH_LOCK_TOKEN; exit status is the child's, or 75
        (EX_TEMPFAIL) when the lock was not acquired within --wait. If the lock
        is lost (§6, a break) the child is sent SIGTERM (Windows: the job is
        terminated) unless --on-lost says otherwise.
synch lock acquire <space>/<name> [--ttl 30s] [--wait <dur>] [--owner <text>]
               [--sticky|--hold] [--allow-behind] [--json]
        take the lock and print its token. Default is lease mode: held for --ttl
        unless renewed. --sticky has the daemon renew until release; --hold stays
        attached and releases on exit (session mode).
synch lock renew <space>/<name> --token <t> [--ttl <dur>]
synch lock release <space>/<name> [--token <t>]
        release this node's hold; with --token, only that claim.
synch lock break <space>/<name> [--holder <origin>]
        end another node's claim (§4); logged everywhere it lands.
synch lock ls [<space>] [--json]
        this node's table: lock, holder, owner, mode, remaining, state
        (held / contending / contested / expired), last releaser.
synch lock status <space>/<name> [--json]
        Inspect every reachable peer and show each one's view side by side,
        with peers that did not answer named; flags disagreement.
synch put … --lock <space>/<name> --token <t>
        a fenced write (§7).
```

`--wait` defaults to 0, which means fail at once with `lock-held` like `flock -n`.
`lock-contended` is retried automatically within `--wait`. Durations accept the same
suffixes as `synch recover --wait`.

`synch lock run` is the form recommended in the documentation. It ties the lease to
a process lifetime, renews without help, and fails closed on loss. The detached
`acquire` exists for scripts that span several commands. They pass the token along
and must renew within ttl.

---

## 11. S3

### 11.1 Lock keys

A bucket declares which of its keys are locks:

```
synch-s3 bucket add tf infra --read-write --locks '*.tflock'
```

`--locks` takes a glob matched against the whole key — `*` is any run of characters,
`/` included, and `?` any one — and may be repeated. It needs `--read-write`, and is
stored as an option field of the bucket record after `no-cache` (`buckets.rs`). A key that matches
is a **lock key** for every operation. It names the lock `<space>/<key>`, so
`synch lock status infra/env/prod/terraform.tfstate.tflock` shows the same lock.
Lock keys are virtual. They are never written into the tree and never listed, and a
tree file whose path matches a pattern is hidden behind the lock through that bucket.

| Request | Meaning | Answers |
|---|---|---|
| `PUT` + `If-None-Match: *` | acquire, no wait; the body (≤ 16 KiB) becomes the claim's payload | `200`, ETag = token · `412 PreconditionFailed` if held · `409 ConditionalRequestConflict` if a simultaneous claim won · `503 SlowDown` on `handoff-pending` |
| `PUT` + `If-Match: "<token>"` | renew, replacing the payload | `200` · `412` if that claim is not the current hold |
| `PUT` with neither | refused | `400 InvalidRequest` |
| `GET` / `HEAD` | the current hold | `200`: body = payload, ETag = token, `x-amz-meta-synch-holder` / `-owner` / `-expires-in` · `404 NoSuchKey` if free |
| `DELETE` | release if this node holds it, otherwise break (§4) | `204` (idempotent) |
| `DELETE` + `If-Match: "<token>"` | release or break that claim only | `204` · `412` if not current |

A plain `PUT` is refused rather than treated as an unconditional take-over. Silently
succeeding would turn a client's bug into a break, and §9.4's rule is that a write
the gateway cannot make mean the right thing is refused.

**Hold mode.** S3 lock keys are `sticky` by default, renewed by the daemon until
`DELETE`, because S3 locking clients never renew: an S3 object does not expire.
`x-amz-meta-synch-lock-ttl: <seconds>` on the acquiring `PUT` selects `lease` mode,
for clients that renew with `If-Match`.

**Acquire latency.** The `PUT` returns after the claim window and the handoff, so it
can take up to Δ plus the handoff window. That is within every SDK's default
timeout.

### 11.2 Terraform and other conditional-write clients

Terraform's S3 backend with `use_lockfile = true` (Terraform 1.10 and later) locks
this way:

1. It writes `<state key>.tflock` with `If-None-Match: *` and a JSON lock-info body.
2. On `412` it reads the object back to report who holds the lock.
3. To unlock it reads the object, checks the lock ID, and deletes it.
4. `terraform force-unlock` deletes it.

Each step is a row of the table above, so `--locks '*.tflock'` is the whole setup.
Two applies through gateways on different nodes exclude each other under §2's
assumption, and that is what this design is for.

The state file itself is an ordinary key. Read-write buckets read this node's own
origin (`buckets.rs`). A different gateway's apply therefore reads *its own node's*
last state, not the one the previous lock holder wrote. Locks do not fix that, and
a cross-node Terraform setup needs a read view that follows other origins, which the
gateway does not offer today. The handoff in §8 is the guarantee such a view would
rely on. Until it exists, one gateway node per state file is the supported Terraform
setup, and the lock protects concurrent runs through it.

**This also closed an existing hole.** `put_object` used to ignore `If-None-Match`
and `If-Match`, so a Terraform client configured with `use_lockfile` against
synch-s3 believed it locked while excluding nothing. `PutObject`, `DeleteObject` and
`CompleteMultipartUpload` on a key that is not a lock key now refuse both headers
with `501 NotImplemented`, naming the header. Conditional writes on ordinary keys
come in Phase 3. A client
told "not implemented" fails loudly, and a client whose condition was ignored loses
data.

### 11.3 Fenced S3 writes

`x-synch-lock: <lock key>; token=<token>` on `PutObject` or
`CompleteMultipartUpload` makes the commit fenced (§7). If the hold is not current
at commit, the answer is `412 PreconditionFailed` and nothing is published. The
header is ignored by real S3, which is the right failure for a client pointed back
at AWS: it fails open there because there is nothing to fence.

---

## 12. Failure matrix

| Situation | Outcome |
|---|---|
| Uncontended acquire, all peers up | Granted after one concurrent round trip (≪ Δ) |
| Uncontended acquire, some peer off | Granted after Δ; `waited_on` names the peer |
| Simultaneous claims, peers connected | Least ticket holds; others `lock-contended`, retried within `--wait` |
| Holder crashes | Observers expire after ttl·(1+2ρ); next claim supersedes it (§6) |
| Holder daemon restarts within ttl | Restored unconfirmed, renewed, kept (§5) |
| Holder daemon restarts after expiry and supersession | Renewal answers carry the superseding claim; reports `lock-lost` |
| Network partition | Both sides may grant: split brain (§2) |
| Partition heals | Detected at the next renewal, within ttl/3; one survivor by §6; the other `lost` |
| Partial partition (A∤B, both reach C) | C relays claims; exclusion usually holds, not guaranteed |
| `End` lost | Claim lingers until lease expiry: a delay, never a double grant |
| Handoff head unreachable | `handoff-pending`, claim released; retry or `--allow-behind` |
| Client ignores its deadline | Not preventable; fenced writes refuse its commits (§7) |
| Clock rate outside ρ, stalled holder | Possible double hold; healed like a partition |

---

## 13. Security

- **Authentication** is the connection's. A claim's origin is the origin the peer's
  device key is bound to, and a claim naming another origin is refused. Delegates are
  confined to spaces they may write (§3.1), and claims never travel to a peer outside
  the space's scope (DESIGN.md §5.5).
- **Relayed claims are trusted**, as relayed heads' *pointers* are. Members are
  mutually trusting. A member can invent claims for others in its answers. That
  delays locks and corrupts nothing, which is no worse than a member claiming every
  lock itself.
- **Denial of service by a member.** A member can hold any lock indefinitely in
  sticky mode, or break any lock. A break is logged by the node that breaks and by
  the holder it breaks, with the claim's token and origin, and
  the remedy is the same as for any misbehaving member: remove it. Per-origin limits
  (§14) bound memory, not intent.
- **Payloads are opaque and bounded** (16 KiB). They are relayed to every peer of the
  space, so they are as visible as the space's metadata. Terraform's lock info names
  a user and host, which is the same exposure the S3 object has on AWS.
- **No new control-socket exposure.** The RPCs sit behind the existing token (DESIGN.md
  §9.3).

---

## 14. Limits and defaults

| Setting | Default | Bound |
|---|---|---|
| Claim window Δ (`NodeConfig::lock_claim_window`) | 2 s | — |
| Lease ttl | 30 s | 5 s – 1 h |
| Renewal interval | ttl/3 | — |
| Clock-rate tolerance ρ | 10⁻³ | — |
| Handoff window (`NodeConfig::lock_handoff_window`) | 10 s | — |
| Name / owner / payload | — | 512 B / 128 B / 16 KiB |
| Live claims per origin, per node table | — | 1,024 / 65,536 |
| Ended memory | 2 × longest ttl in force | 65,536 ids |

A claim over a limit is answered `Refused` and counts as an answer, which is the
conservative choice for a peer that would otherwise be waited on. The claimant
surfaces the refusal and does not hold on a table it could not fill.

---

## 15. Verification and testing

- **TLA+** (`specs/Locks.tla`, run in CI beside `Recovery.tla`). The model covers
  one lock, the claim exchange, answers, ends, retries and a timeout. The configs:
  - `Locks.cfg`: three nodes contend at once with every message delivered. It must
    keep `MutualExclusion`.
  - `LocksRetry.cfg`: two nodes retry, so late answers and ends interleave with new
    claims. It must keep `MutualExclusion`.
  - `LocksPartitioned.cfg`: messages may be lost and waits may time out. It **must**
    reach the split brain; if it ever passes, the model has stopped describing the
    protocol.

  During design these mutations were also checked:
  - Removing ticket ordering alone keeps exclusion.
  - Removing the held-mark rule alone keeps exclusion.
  - Removing both, or removing ticket ordering and the decision-time table, breaks it.
  - Letting a claimant stop waiting without any message being lost breaks it (§3.5).

  The model does not cover leases, healing, handoff or bystander relays.
- **Lean (later).** The pure decision, heal order and lease arithmetic (§9.2) are
  small enough to move into the executable Lean core. A user-facing goal would read
  "under bounded latency, one node holds a lock at a time". The executions it
  covers need the claim exchange, which is the TLA+ model's job today. Proof
  ownership does not change with this design, so `docs/LEAN.md` is not amended.
- **Native tests** over real loopback endpoints (`synch-engine/tests/locks.rs`):
  - simultaneous claims grant exactly one;
  - a partitioned pair both grant, and on heal exactly one survives by §6's order;
  - a crashed holder is superseded after its lease, and the new claim names it;
  - a sticky hold survives a daemon restart;
  - a late renewal after `End` is not revived;
  - a release hands the lock over with the releaser's head;
  - a fenced commit is refused after a break;
  - a node alone can lock.

  The pure rules have unit tests beside them (`decide`, `heal`, the observer's
  lease), and the control service has tests for a session hold's life and a
  lease's renewal (`synch-cli/tests/control.rs`).
- **Gateway tests** (`synch-s3/tests/gateway.rs`): the §11.1 table — acquire,
  refusal, read-back, renew, delete, re-acquire — fenced writes, and the refusal
  of conditional headers on ordinary keys.
- **Not yet covered:** an end-to-end run of Terraform itself with `use_lockfile`
  against a gateway. The request flow in §11.2 is what the gateway tests drive.

---

## 16. Phases

1. **Protocol and CLI** (built). The protocol is `sync/lock/1` and the
   `LockManager` (§3–§6, §8, §9). The CLI adds `synch lock`, `--lock` on `synch
   put`, and the TLA+ model in CI.
2. **S3** (built). This adds lock keys (§11.1), fenced S3 writes (§11.3), and
   refusing `If-None-Match`/`If-Match` on other keys.
3. **Conditional writes on ordinary keys** (not built). `If-None-Match: *` and `If-Match` on any
   key become an implicit short lock on `<space>/<key>`:
   1. acquire;
   2. wait for the handoff;
   3. evaluate the condition against the bucket's selected version;
   4. write;
   5. release with a watermark.

   This gives cluster-wide create-if-absent and compare-and-swap with the same
   guarantee as the lock, exact under bounded latency and split-brain under
   partition. It is what Delta Lake and Iceberg's S3 commit protocols need.

---

## 17. Alternatives rejected

- **Quorum leases (Redlock-style majority grants).** Safe under partition only
  for the majority side. The minority cannot lock at all, which is the CP choice this
  design was asked not to make. It still needs every bounded-latency assumption, for
  lease expiry, that this design needs.
- **Raft or Paxos per space.** A leader per space contradicts "no coordinators"
  (DESIGN.md §1). It also makes locks unavailable on a laptop away from its cluster.
- **Locks as trie records.** See §9.1.
- **CRDT ownership registers.** A register that converges after the fact is what §6
  already provides as the heal. Without the claim exchange it would grant two
  holders even when the nodes are connected.
- **Skipping unreachable peers.** See §3.5.

---

## 18. Changes to existing documents

- **DESIGN.md §9.2** gains the `synch lock` lines, and **§9.4** gains a pointer to
  §11 for lock keys and fenced writes. Its "Not in v1" list keeps conditional writes
  on ordinary keys until Phase 3.
- **specs/README.md** describes the lock model and its expected counterexample.
