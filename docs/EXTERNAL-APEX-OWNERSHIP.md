# Owning the apex outright — and closing the external-mode rotation gap

Status: **proposed.** Amends docs/EXTERNAL-DNS-PROVIDER.md (§4.2, §4.3, §4.4,
§4.6, §5.1, §5.2, §8) and docs/REKOR-ZONE-KEY.md (§3). No code is written yet.

This document takes one deployment decision — **the apex is a name this
deployment owns entirely** — and follows it through the reconciler, the
serving filter, the timing constants and the tests. The decision is what
makes the reconciler's scope simple; the rest of the document is the set of
fixes that decision unblocks, plus three it does not touch but which the
same rotation path depends on.

Contents:

1. [The two premises](#1-the-two-premises)
2. [The scope rule](#2-the-scope-rule)
3. [The marker, and why it gets a version](#3-the-marker-and-why-it-gets-a-version)
4. [What the zone serves](#4-what-the-zone-serves)
5. [The timing invariant](#5-the-timing-invariant)
6. [Reconciliation posture](#6-reconciliation-posture)
7. [Persistence and observability](#7-persistence-and-observability)
8. [Migration](#8-migration)
9. [Testing](#9-testing)
10. [Documentation deltas](#10-documentation-deltas)
11. [What this does not fix](#11-what-this-does-not-fix)
12. [Open questions](#12-open-questions)

## 1. The two premises

**The apex is dedicated.** `CP_BASE_DOMAIN` names a subdomain that exists for
this control plane and nothing else — `control.example.com`, not
`example.com`. The dashboard, the REST API and every other service live on
sibling names, so no record under the apex is anybody else's. This is a
deployment requirement, not an inference, and §8 says how it is enforced
rather than merely asked for.

That premise is what the current design does *not* have, and it is why
`provider/diff.gleam` scopes itself to an enumerated list of names and leans
on the `_synchronicity` prefix for disjointness. With the premise in hand the
scope can be structural instead: everything under the apex is ours, so
anything under the apex we did not render is drift, and drift can be removed.

**The rotation window is longer than §8 prices it.** External mode's
transparency claim follows the provider's keys on a timer, so a provider that
activates a key the watcher has not yet logged strands `Require` clients.
docs/EXTERNAL-DNS-PROVIDER.md §8 prices that window as "≤ watch cadence +
propagation". Two things make it longer, and one makes it permanent:

- the proof records are published with a **24 h TTL**
  (`zone/render_external.gleam`), and the client keeps no cache of its own —
  it runs a bare `DnssecDnsHandle` over DoH — so the recursive resolver a
  client asks can serve the pre-rotation proof set for a day after the
  control plane has published the new one;
- a client's DNS-sourced bindings live for the membership TTL plus
  `DEFAULT_TRUST_GRACE` — 300 s + 600 s — so **the fail-closed window can
  outlast the membership it was protecting**, and the maintenance pass
  deletes the bindings rather than merely letting them go stale;
- nothing ever stops serving an old proof. `rekor/store.servable` returns
  every non-retire row, a rotation adds two rows (the `{old,new}` overlap,
  then `{new}` alone), and every proof's part 1 lands at the *same* owner
  name. At roughly 2 028 wire bytes each, four fit inside Cloudflare's
  measured 8 192-byte per-name-and-type cap and the fifth is refused —
  reached at the end of the second rotation. The refused create currently
  aborts the whole apply, ahead of the membership records, and
  `applied_hash` never advances, so the provider zone stops receiving *any*
  update until somebody deletes rows by hand.

The scope change addresses none of that on its own. §4 through §6 are the
part that does.

## 2. The scope rule

Replace the enumerated managed-name list with one sentence:

> **Every TXT record strictly below the apex is this deployment's to
> reconcile.**

Three qualifications, each load-bearing.

**Strictly below.** The apex name itself is excluded. If the apex is a
delegated zone it holds SOA, NS, DNSKEY and whatever CAA the operator wants;
if it is not, it is still the name a registrar or provider asks for a
verification record at. Nothing this deployment publishes sits at the apex —
the marker, the declaration, the proof parts and the membership records are
all at labels beneath it — so excluding it costs nothing and removes the one
name most likely to carry somebody else's data even under a dedicated apex.

**TXT only.** Every record we publish is TXT, so a record of any other type
can never be something we would overwrite. Filtering the listing to TXT makes
the old "no cross-type deletes" rule structural rather than a check: an `A`
record beneath the apex is not a conflict to be reported and not a casualty
to be deleted, it is simply invisible. The `Rtype` enum stays a
single-constructor type for exactly the reason its comment gives, but the
diff no longer needs a rule about foreign types because it never sees one.

**Listed in one call.** `Provider.list` loses its `names` argument; the leg
knows the apex from `connect` and returns the TXT records below it. On the
Cloudflare leg that means paginating `dns_records?type=TXT` and filtering by
suffix instead of issuing one request per name — permitted by the same
zone-scoped `Zone:DNS:Edit` token, since listing was always zone-wide in
capability. Bunny already returns the whole zone in one call.

What this buys beyond simplicity is a bug fix. `render_external.managed_names`
derives proof-part names from the *currently rendered* proofs, so when a
proof's part count shrinks — a six-part ICANN-rooted proof replaced by a
five-part one — `_synchronicity-rekor-6.<apex>` is never listed again, never
read and never deleted. It is orphaned permanently, in direct contradiction of
the comment promising that records we stopped rendering still get found. Under
a structural scope the managed set maintains itself and the orphan cannot
happen.

## 3. The marker, and why it gets a version

The ownership marker currently reads `heritage=synchronicity-cp`, and
`diff.diff` permits deletes at managed names once it sees that value at a name
the desired set also names. Widening the scope without touching the marker
would therefore be **silently destructive on upgrade**: an existing external
deployment already has the marker, so the first sweep after the upgrade would
delete every TXT below the apex it did not render — including records an
operator put there before this document existed.

So the marker's value carries the scope it authorizes:

```
_synchronicity-owner.<apex>  TXT  "heritage=synchronicity-cp,scope=apex"
```

Apex-wide deletes require *that* value. A deployment holding the old marker
gets the old behaviour — deletes only at names the renderer produced — until
the marker is upgraded, and the marker is upgraded only by a sweep that found
nothing unexpected below the apex. An apex that still holds a stranger's TXT
record fails that test and reports the conflict instead, naming the record.

That turns "the apex is dedicated" from a premise we hope holds into a
precondition the reconciler verifies before it is allowed to act on it. The
first sync of a green-field deployment sees an empty apex, writes the scoped
marker, and proceeds; the first sweep of an upgraded deployment either
verifies the premise or refuses, loudly, having changed nothing.

## 4. What the zone serves

### 4.1 The intersection filter

A proof authorizes an answer when the key that signed the answer is a member
of the proof's key set. A proof whose key set contains **no key the zone
currently publishes** can therefore never authorize anything. It is history:
worth keeping as our own record of what we published — which §5.5 of
docs/REKOR-ZONE-KEY.md makes the operator's job to compare against monitor
reports — and not worth serving.

> **Serve a proof if and only if its key set intersects the DNSKEY set the
> zone currently publishes.**

The rule is mode-independent, and each mode already knows its own key set:

- **external**: `observed_zone_keys`, the watcher's record of the apex DNSKEY
  RRset. If the table is empty — a control plane that has booted but not yet
  observed — serve everything, so a first boot never blanks the proof records
  it does have;
- **serve**: `zone_meta.dnskey_public` plus `dnskey_incoming` when the staging
  slot is occupied, which is exactly the set `zone/build.gleam` already
  computes to emit the DNSKEY RRset.

Filtering happens at the serving boundary — `rekor/store.servable` and the
`zone/model.read_rekor_proofs` that feeds both renderers — never by deleting
rows. `rekor_records` stays the full history.

The bound this produces is small and worth stating exactly. Through a
pre-publication rotation the observed set moves `{A}` → `{A,B}` → `{B}` while
the stored claims are `{A}`, `{A,B}`, `{B}`. During the overlap all three
intersect, so three proofs are served; once `A` leaves the RRset the `{A}`
claim drops out and two remain. Three is the steady-state worst case, against
the four that fit.

It also removes a cost nobody was counting: a client tries every proof it can
reassemble, each one a full DNSSEC chain walk. Bounding the served set bounds
the work a refresh does.

### 4.2 The byte budget

The filter makes the cap unreachable in normal operation, which is a reason to
keep a guard rather than to skip one — an unreachable limit that is never
checked is how the current freeze arrived. Each provider declares the ceiling
it enforces (Cloudflare 8 192 bytes combined per name and type, measured;
Bunny the same until measured otherwise), and the renderer keeps its rendered
part-1 bytes under

```
budget = provider_name_cap − max_part_bytes
```

so there is always room for one part more than we plan to publish, and a
delegation that grows a level does not tip the zone over. Over budget, the
renderer **sheds the oldest proofs by `verified_at`** and writes an audit row
naming what it dropped — no silent caps. It never sheds a proof covering a
currently published key; if the live key set alone exceeds the budget, that is
a genuine refusal with the byte count in the message, not something to paper
over.

Shedding rather than refusing is deliberate. A renderer that refused would
block the membership records too, which is the failure this document exists to
remove.

## 5. The timing invariant

The client-visible window after an unannounced cut is

```
detection (watch cadence) + publish (log + reconcile + edge) + proof TTL
```

and the budget it has to fit inside is the lifetime of the membership a client
is already holding:

```
membership TTL + trust grace
```

> **Invariant:** `watch_cadence + publish_slack + proof_ttl <
> membership_ttl + trust_grace`

Today that reads `900 + 60 + 86 400` against `300 + 600` — off by two orders
of magnitude, which is the arithmetic behind the finding that a rotation can
cost membership. Three constants change:

| Constant | Now | Proposed | Why |
|---|---|---|---|
| `watch_interval_ms` (`jobs/zonekey_watch`) | 900 000 | 300 000 | Detection is the term we control most cheaply: 96 → 288 validated DoH lookups a day. |
| `ttl_proof` (new, `zone/render_external`) | — | 300 | The proof record's TTL is the resolver-cache tail of the window; matching the membership TTL makes the tail no worse than the data it guards. |
| `ttl_declaration` (split from `ttl_rekor`) | 86 400 | 86 400 | The declaration's content is fixed forever; there is no reason to shorten it, and splitting the constant is what lets the proof TTL move without dragging it along. |

Which gives `300 + 60 + 300 = 660 s` against `300 + 600 = 900 s` — four
minutes of margin. The client-side terms (`MIN_TTL`, `DEFAULT_TRUST_GRACE`)
are deliberately untouched: the grace window is a revocation-latency decision
belonging to the client, and widening it to buy margin here would be paying
for a rotation with slower revocation everywhere.

The relation is stated here because it spans two languages. Each side asserts
its own half in a unit test — the Gleam constants against the published TTLs,
the Rust constants against the grace — and this table is what says why the two
halves have to be read together.

## 6. Reconciliation posture

### 6.1 An apply that does not abort

`Provider.apply` reports per-change outcomes instead of stopping at the first
failure:

```gleam
pub type Failure {
  Failure(name: String, reason: String)
}

pub type Applied {
  Applied(ok: Int, failed: List(Failure))
}

pub type Provider {
  Provider(
    /// Every TXT record the provider holds strictly below the apex.
    list: fn() -> Result(List(Existing), String),
    /// Applies every change it can; reports the ones it could not.
    apply: fn(Changes) -> Result(Applied, String),
    describe: String,
  )
}
```

The outer `Result` keeps a transport or credential failure — which says
nothing about any individual record — distinct from records the provider
refused. `applied_hash` advances only when `failed` is empty, so the diff's
idempotence means the next pass retries exactly the failures and nothing else.

### 6.2 Order within a pass

Creates, then replaces, then deletes — unchanged, and now for a reason worth
recording: creates-before-deletes means a proof's old and new parts briefly
coexist, which a client handles (it tries each proof it can reassemble),
whereas deletes-first would expose a window where the zone serves an
incomplete proof set.

Within creates, the order is **marker, declaration, membership, proofs**. The
declaration is what makes every logged claim the zone's own statement, and
membership is the product; proofs go last so that anything expensive or
oversized about them can never delay either. With a non-aborting apply this is
belt and braces, which is the appropriate amount of care for the ordering that
produced the current freeze.

## 7. Persistence and observability

One migration, appended to the forward-only list in `store/migrate.gleam`:

```sql
-- Partial applies are now representable: a pass can succeed for most
-- records and be refused for a few. `last_failures` is a rendered summary
-- for the operator, not a work queue — the desired state is still derived
-- and the next sweep recomputes it.
ALTER TABLE provider_sync_state ADD COLUMN last_failures TEXT;
ALTER TABLE provider_sync_state ADD COLUMN last_partial_at INTEGER;
```

`/healthz` in external mode gains four fields, three of which are computed
rather than stored:

- `oldest_unlogged_age` — `now − min(first_seen)` over `observed_zone_keys`
  where `logged_at IS NULL`. §4.6 of the provider document has promised this
  since it was written and it was never implemented; it is the one number that
  says whether the watch loop is keeping up.
- `proofs_served` and `proof_bytes_at_base_name` — what the filter and the
  budget of §4 currently produce, so the cap is observable long before it is
  reached.
- `last_partial_at` / `last_failures` — a pass that mostly worked, which the
  old all-or-nothing state could not express.

## 8. Migration

For a green-field external deployment there is nothing to do: the first sync
finds an empty apex, writes the scoped marker and proceeds.

For an existing one, in order:

1. **Deploy.** The new build holds the old marker value, so its scope is
   unchanged and nothing is deleted. The intersection filter and the new TTLs
   take effect immediately, which is the part that closes the window.
2. **Read the first sweep.** It reports either "apex clean, marker upgraded"
   or a conflict naming a TXT record below the apex that this deployment did
   not render.
3. **Clear the apex** if the sweep found something: move the record to a
   sibling name — which is where the dedicated-apex premise says it belonged —
   or accept that this deployment will remove it.
4. **Confirm** `scope=apex` on the marker and `provider_in_sync=true`.

Rollback is symmetric and safe at every step: the marker value is the only
thing that authorizes apex-wide deletes, so reverting the build reverts the
scope.

The runbook's cutover section gains one line under **Prepare**: the apex must
be a name nothing else publishes under, and the dashboard's own hostname is a
sibling of it, not a child.

## 9. Testing

Pure and table-driven where it can be, in the `zone_test.gleam` style:

- **Scope.** TXT below the apex that we did not render is deleted with the
  scoped marker present; is a conflict with the marker absent or unscoped; a
  record *at* the apex is never touched; non-TXT below the apex never appears
  in a change set. The shrinking-part-count case explicitly: a six-part proof
  replaced by a five-part one leaves no `-6` behind.
- **The filter.** A proof whose key set misses the observed set is not served;
  one that intersects is; an empty `observed_zone_keys` serves everything; the
  three-proof rotation overlap is asserted as the worst case, so a change that
  widens it fails here rather than at a provider's API.
- **The budget.** Rendered part-1 bytes stay under `cap − max_part`; shedding
  takes the oldest first; a proof covering a live key is never shed; the
  live-set-over-budget case refuses with the byte count.
- **The invariant.** The Gleam constants satisfy §5's relation; the Rust side
  asserts its half against `MIN_TTL` and `DEFAULT_TRUST_GRACE`. Both fail
  locally if either side moves a number.
- **Apply resilience.** One refused change does not prevent the others;
  `applied_hash` does not advance; the next pass retries only what failed;
  membership records land even when a proof create is refused.
- **The watcher, which currently has no tests at all.** Nothing under
  `control-plane/test/` references `zonekey_watch`, `observed_keys` or
  `record_logged`, though §9 of the provider document claims "key-set change →
  new entry → rekor TXT poke" is asserted. A `run_once_with` ladder on the
  `resign.run_once_with` pattern, driven with in-memory fakes: unchanged set
  logs nothing; an added key logs and pokes; a removed key logs; a logging
  failure leaves `logged_at` unset and is retried on the next tick; an absent
  declaration waits quietly instead of failing loudly.

## 10. Documentation deltas

- **EXTERNAL-DNS-PROVIDER.md §3.3** states that a pre-published key "is
  covered by the *existing* entry before the new key signs anything." An
  entry's subject is the key set as observed when it was logged, so it cannot
  contain a key that did not exist yet; what covers the cut is a *new* entry
  logged during the overlap. The key-set subject's real contribution is that
  one entry spans both sides of the cut, so nothing has to land at the
  activation instant. The behaviour is correct and the stated reason is not,
  which matters, because that sentence is what makes the gap look impossible.
- **§5.2** is rewritten around §2's scope rule and §3's marker.
- **§4.6** describes the health fields as they will then exist.
- **§8** restates the window with §5's arithmetic instead of "≤ watch cadence
  + propagation", and adds the resolver-cache term.
- **REKOR-ZONE-KEY.md §3** gains the serving filter beside the existing
  "a client tries each proof and membership decides".

## 11. What this does not fix

- **The window does not close, it shrinks.** A provider that activates a key
  it never published still strands `Require` clients, now for something like
  ten minutes rather than up to a day. Fail-closed is the correct direction
  and this only makes the fall shorter.
- **A rotation and a registrar-compromised substitution remain
  indistinguishable**, in the log and in the zone. Nothing here changes the
  §5.5 bargain: the monitor reports, and the operator's own record of what
  they published is what decides.
- **Key custody is still the provider's.** A provider compromise is a zone
  compromise, detectable in the log and not preventable by us.
- **The client still caches nothing.** §4.2 of the transparency document is
  explicit that a `Require` refresh performs all three lookups every time; a
  shorter proof TTL neither helps nor hurts that, because the client's own
  re-resolution floor already dominates. A cache in front of the DoH handle is
  still unwritten.
- **Bunny's DNSSEC support is still unverified**, and external mode is
  meaningless without it.

## 12. Open questions

1. **Should the apex requirement be checked at boot?** A public-suffix
   heuristic that refuses a bare registrable domain would reject the operator
   who genuinely dedicates one, and would still miss `control.example.com`
   with a stray record under it. The first-sync conflict is the better
   enforcement point because it tests the real property rather than a proxy
   for it — but it fires later, and that is a trade worth confirming.
2. **Cloudflare's suffix filtering.** Listing by suffix server-side would keep
   the response small on a zone that holds the apex among many other names;
   paginating and filtering locally always works. Worth measuring on a real
   zone before choosing, since the reconciler runs this every sweep.
3. **Is 300 s the right proof TTL?** It satisfies §5's invariant with margin,
   but the term it is really trading against is edge traffic for ~6 KB of TXT
   per resolver per five minutes. If that proves material, the honest lever is
   the watch cadence, not the TTL.
4. **Shed order.** Oldest-by-`verified_at` is the obvious rule and it is not
   obviously the right one; a claim covering a key that only just left the
   RRset may be worth more than a newer claim covering nothing live.
