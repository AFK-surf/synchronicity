# mptsync correctness audit

Date: 2026-09-02. Scope: the `sync/mpt/1` protocol and everything that decides
what a node holds, advertises, serves and promotes — `synch-mpt` (trie, walks,
diff, scope), `synch-net/src/mpt.rs` (the ALPN handler and client),
`synch-engine/src/reconcile.rs` and `aae.rs` (acceptance, fetch, promotion,
scheduling, the pending sweep), and the store side that backs them
(`heads.rs`, `bindings.rs`, `gc.rs`, the `NodeStore` impls in `db.rs`). Read
against DESIGN.md §4–§5 and the Lean models in `specs/lean`.

Method: a read of the code paths above end to end, with each finding that
could be exercised over the wire reproduced in
`crates/synch-engine/tests/audit_repro.rs`. Those tests assert the property
the design promises and are `#[ignore]`d because they fail today; run them
with `cargo test -p synch-engine --test audit_repro -- --ignored`.

## Findings

Ordered by severity. "Reproduced" means the ignored test fails on exactly the
assertion described.

### 1. A delegate can launder a withheld subtree through its own trie (high, reproduced)

**Where.** `Store::is_head_root` (`crates/synch-store/src/heads.rs:510`),
`admit` (`crates/synch-net/src/mpt.rs:571`), and the presence-as-vouching
walk that `Syncer::fetch_pending` and `Trie::is_complete_scoped` share
(`crates/synch-engine/src/reconcile.rs:750`, `crates/synch-mpt/src/trie.rs:308`).

**Mechanism.** §5.5 withholds a subtree from a delegate by declining to send
its nodes, and notes that the delegate legitimately holds the subtree's
*hash* (it is inside the branch the signed root recomputes through). Nothing
stops the delegate from publishing a trie of its own that places that hash at
an in-scope position: one hand-built `Ext` whose prefix is `f:<granted>/…`
and whose child is the withheld branch. The delegate never holds a node of the
subtree, yet:

- A full member fetching that head finds every node under the graft already
  present in `trie_nodes` (structural sharing with the issuer's trie), so the
  walk drains, `note_complete` is recorded, `first_key_outside` finds every
  key inside the delegate's spaces, and the head is promoted. The withheld
  file entries are materialized under the delegate's origin.
- Every other delegate then reads the subtree by ordinary scoped sync: the
  positions are under `f:<granted>/`, so `admits_path` and `admits_node`
  both admit them, and the member serves names, records and content roots.
- The direct route works too. `admit` authorizes a position against any root
  in `head_history` except the *asker's own* origins, and a delegate's roots
  land in `head_history` as soon as signature and binding verify. A second
  delegate identity (or a colluding delegate) can name the withheld hash at
  the graft position under the grafter's root and be handed the node.

The existing test `a_delegate_cannot_authorize_with_its_own_root_or_name`
covers only the asker's own root; the `except` list in `admit` is the asker's
origins and nothing else.

**Root cause.** Two assumptions in §5.5 do not hold for delegate-authored
tries: that "positions in a head_history root are real because someone else
laid them out" (a delegate lays out its own), and that a node present locally
is a node this origin was entitled to serve (structural sharing crosses the
delegation boundary in the member's shared `trie_nodes`).

**Direction.** A cheap partial fix closes the direct route: have
`is_head_root` count only roots signed by origins holding a live *rooted*
binding, not merely roots other than the asker's. It does not close the
promotion route, and it would stop delegates fetching each other's honest
tries through members, which the scoped read of `f:<space>/` across origins
appears to rely on. Closing the promotion route needs provenance: a member
must not vouch for a node in a *confined* origin's trie unless that origin
served it (or it sits under the origin's own previous complete root, by
induction). That is a per-origin `(origin, hash)` record consulted by the
fetch walk, by `is_complete_scoped` for confined origins, and by `admit` when
the root is delegate-authored. Restricting the fetch source to the origin
alone is not enough on its own: `try_promote` is also reached from
`HeadPush`/`offer_head` and the maintenance sweep, and both judge
completeness by local presence.

### 2. A non-canonical node aborts the whole exchange instead of failing its origin (medium, reproduced)

**Where.** `take_served`'s `hash_of` closure in `Syncer::fetch_pending`
(`crates/synch-engine/src/reconcile.rs:879`) and
`TrieNode::hash_of_encoded` (`crates/synch-mpt/src/node.rs:111`).

**Mechanism.** `hash_of_encoded` returns `Err` for three different things: a
payload that does not re-encode canonically, a key run past `MAX_KEY_LEN`,
and a `check_invariants` failure (empty extension prefix, oversized inline
value, under-occupied branch). The fetch collapses all of them to `None` and
reports `NetError::NodeHashMismatch`, which `is_origin_fault` classifies as a
*peer* fault. `sync_with` therefore returns `Err` from the middle of its
`received` loop: every origin sorting after the offender in that exchange is
skipped, the pending-heads pass never runs, and the offending head keeps the
pending slot because the abandonment logic below the batch is never reached.
The TTL sweep clears it after `pending_head_ttl`, the next exchange re-adopts
it, and the cycle repeats with every peer that serves that origin. §12's
"fails its own origin and no other" does not hold for a member that publishes
one malformed node, although `MissingWalk::next_batch` was written to make it
hold for the same shapes once the node is stored.

The hash check itself cannot be fooled: the node hash covers the raw bytes as
served, so bytes that hash correctly but break an invariant are the origin's
doing, not the relaying peer's.

**Direction.** Split the two checks. Compare `hash_encoded(node.tag(), bytes)`
against the requested hash for the peer-fault case, then run the canonical
re-encode and `check_invariants` inside `put` and *refuse* the node the way
`put` already refuses an inline-sized out-of-line value: return `Ok(false)`
with a warning, so the node is not stored, the walk asks again, `unproductive`
climbs, and the §5.2 rule abandons the head three rounds later while the
exchange goes on. Alternatively raise an `MptError` so it classifies as an
origin fault; that contains the exchange but still leaves the head pending
until the sweep.

### 3. Moving the read scope can overwrite a newer pending head with an older one (low)

**Where.** `Store::set_read_scope` (`crates/synch-store/src/bindings.rs:941`)
and `put_head_in`'s `ON CONFLICT … DO UPDATE` (`crates/synch-store/src/heads.rs:1026`).

**Mechanism.** The scope move demotes each foreign complete head by writing it
into the pending slot. `put_head` replaces whatever is in the slot
unconditionally, so an origin with complete = seq 5 and pending = seq 7 ends
the transaction with pending = 5; head 7 survives only in `head_history`.
`head_floor` drops to 5, the next exchange re-adopts 7, and the node pays a
fetch and a promotion for 5 it did not need. Nothing diverges, so this is
wasted work rather than wrong state, but it is the one place a `put_head`
into the pending slot lowers the floor.

**Direction.** Demote only when the pending slot is empty or holds a lesser
`(seq, root)`; otherwise leave the pending head and just clear the complete
slot.

### 4. A confined origin's refused head keeps the slot and the floor indefinitely (low)

**Where.** `Syncer::try_promote`, the `PublishScope::Confined` and
`PublishScope::Untrusted` arms (`crates/synch-engine/src/reconcile.rs:676-699`),
and `Node::sweep_pending_heads` (`crates/synch-engine/src/aae.rs:588`).

**Mechanism.** A delegated origin's head whose trie publishes outside its
spaces is answered `Promotion::Waiting`, not `Refused`, and the same for an
origin with no live binding. The trie is wholly present, so the TTL sweep's
staleness test (`received_at <= before && !is_complete_scoped`) never fires,
the head is never abandoned, and it holds `head_floor` above any lesser
servable head for that origin for as long as the origin does not publish past
it. §5.2's third rule says a head "whose promotion this node's own rules
refuse never keeps the slot it was written into". Each later exchange with a
peer advertising the head complete also re-runs `fetch_pending` (an empty
walk) and `first_key_outside` for it. The existing test
`a_delegate_publishing_outside_its_spaces_is_refused` asserts only that the
complete slot did not move.

**Direction.** Treat the `Confined` refusal like an origin fault: record the
verdict in the refusal memo and retire the head with `clear_head_at`. The
`Untrusted` arm can retire too; a head re-offered once the binding is back is
re-adopted and promoted normally.

### 5. Hash-keyed bookkeeping in the scoped walk is position-blind (low)

**Where.** `MissingWalk::next_batch` — `seen` and `deferred`
(`crates/synch-mpt/src/trie.rs:356,376`), the redaction check
(`crates/synch-mpt/src/trie.rs:371`, `redacted_nodes` in `db.rs`), and
`Answer::wants` on the responder (`crates/synch-net/src/mpt.rs:532`).

**Mechanism.** Under a full scope a node's hash determines its whole subtree,
so deduplicating by hash is sound. Under a confined scope, admission depends
on the *position*: a node on the spine has some children admitted and some
not. If the same node hash sits at two spine positions with different
admission, the first pop decides for both — the walk expands it once, filters
children by the first path, and the second position is skipped as `seen`
(or, if the first position was refused, the hash is durably `redacted` and
the second is treated as satisfied). In-scope children under the second
position are never queued, so `is_complete_scoped` can answer true for a
trie that is missing part of the grant, and promotion materializes it short.
The responder's per-hash dedup means one batch naming both positions gets one
answer, so a redaction at the first position suppresses the node at the
second within the same round.

This needs the same node at two distinct spine positions — a self-similar
shape an origin can publish deliberately but honest data does not produce —
so it is a soundness gap rather than a live bug. The comment at
`trie.rs:359-370` already notes that a bare hash cannot carry the distinction.

**Direction.** When the scope is not full, key `seen`/`deferred` by
`(hash, path)` and key `redacted_nodes` by `(hash, path)`; let the responder
answer per `(path, hash)` pair for scoped peers.

### 6. The pending sweep condemns a snapshot head on a fault raised before the slot was read (note)

**Where.** `Node::sweep_pending_heads` (`crates/synch-engine/src/aae.rs:629`).

`try_promote` can fail with a `Column`/`Decode` store error while reading
`local_trie_scope`, `publish_scope`, or the complete head, before it has read
the pending slot and set `judged`. The sweep then clears the head from its
`all_heads` snapshot. The comment at `aae.rs:604-611` shows this is
deliberate (a head the promotion never reached still needs an exit), but the
faults that reach it are about this node's own rows, not that origin's data,
so the condemned head may be a perfectly good one. It is recoverable — a peer
re-offers it — so this is a note, not a defect.

## Properties checked and found sound

- **Acceptance is order-independent.** `offer_head` records history, reads
  `head_floor`, and writes the pending slot inside one `BEGIN IMMEDIATE`
  transaction; `trim_forks` evicts by root order and never the row a slot
  names, so the retained set is the same on every peer up to the two slots.
- **The flip is atomic.** `try_promote` reads the pending slot, checks
  `supersedes` against the complete slot rather than trusting
  "pending > complete", checks completeness within the read scope, flips,
  clears pending and materializes the diff in one transaction; the `Txn`
  `NodeStore` deliberately never memoizes completeness.
- **Abandonment names its head.** Both abandonment paths and the progress
  stamp use `clear_head_at`/`touch_pending_at` with `(seq, root)`, so a
  `HeadPush` landing mid-fetch is never deleted or extended by a verdict about
  a different head.
- **Reference pruning is sound under scope.** A hash equal at the same
  position in a root held whole within the scope is a subtree held whole
  within the scope; the pairing is by position, and declines to pair where
  shapes differ.
- **The completeness memo cannot go stale.** Nodes are never rewritten under
  a hash, GC marks from every `head_history` root inside the sweeping
  transaction, and `retain_complete_roots` drops memo entries for anything
  the sweep did not mark from, under both the bare and the scoped key.
- **Ingest containment.** `take_served` refuses unrequested and repeated
  payloads, verifies each against the requested hash, and refuses
  inline-sized or oversized values without failing the batch; `bounded_vec`
  caps every sequence while decoding.
- **Position resolution.** `resolve_paths` rejects nibble values ≥ 16 from
  the wire, refuses paths that stop inside an extension or continue past a
  leaf, and its shared-prefix trail agrees with resolving each path alone.
- **The walk bounds.** `MissingWalk` bounds path depth and leaf-value depth
  at `MAX_DEPTH_NIBBLES`, checks the extension-above-branch invariant in both
  orders of arrival, and `descend` charges every real position against the
  8 M ceiling with the stack on the heap.
- **Own seq derivation.** `next_own_seq` reads both slots and the retained
  history, and `prune_history_before` exempts the highest retained seq, so a
  restored node cannot re-sign a seq it already used.
- **Trie GC** runs mark and sweep in one immediate transaction from every
  `head_history` root, pending heads included.

## Non-correctness observations

- `local_summaries` calls `is_complete` (unscoped) on every complete head per
  `Hello`. A negative answer is never memoized, so a delegate walks its
  in-scope part of every foreign trie on every exchange until the walk hits
  the first absent node.
- `GetNodes` computes `scope_for_key` twice per request (once in the handler,
  once in `admit`).
- `anti_entropy_round`'s "random sample" is a contiguous window of the sorted
  peer list rotated by a clock-seeded offset, so the three candidates are
  always adjacent in that order.
