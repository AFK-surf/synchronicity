# External DNS providers — publishing the zone through Cloudflare or Bunny

Status: **implemented.** The claim lives in `crates/synch-net` /
`crates/synch-monitor` and `control-plane/src/rekor`; external mode is
`CP_DNS_MODE=external`, with the Cloudflare and Bunny legs under
`control-plane/src/provider`. This document is the rationale and the
operational guide.

This document designs a control-plane mode in which the membership zone is
hosted by an external managed DNS provider instead of being served by the
control plane's own authoritative listeners. It amends the zone-key
transparency protocol (docs/REKOR-ZONE-KEY.md) where the two designs meet,
and states plainly what the trade is.

Contents:

1. [Problem and motivation](#1-problem-and-motivation)
2. [What the client enforces](#2-what-the-client-enforces)
3. [The zone-key claim](#3-the-zone-key-claim)
4. [Control plane: `CP_DNS_MODE=external`](#4-control-plane-cp_dns_modeexternal)
5. [The provider abstraction](#5-the-provider-abstraction)
6. [Provider notes: Cloudflare, Bunny](#6-provider-notes-cloudflare-bunny)
7. [Cutover runbook](#7-cutover-runbook)
8. [Costs, stated plainly](#8-costs-stated-plainly)
9. [Testing](#9-testing)
10. [Phasing](#10-phasing)
11. [Open questions](#11-open-questions)

## 1. Problem and motivation

The control plane is today a from-scratch authoritative DNSSEC nameserver:
`zone/model.gleam` reads the product tables into a `ZoneInput`,
`zone/build.gleam` renders the full zone (SOA, NS, DNSKEY, glue, membership
TXT, the `_synchronicity-transparency` declaration, `_synchronicity-rekor`
TXT, and the NSEC chain), `zone/publish.gleam` signs every RRset with the zone CSK and writes
the result into `presigned_rrsets` — all inside the API transaction, so
commit is publication — and the UDP/TCP/DoH listeners answer straight out
of SQLite.

That design buys exactness: the wire is a pure function of the database,
negative proofs are precise NSEC, and the DNSSEC key ceremony is entirely
operator-owned. What it costs is that every deployment must run public
port-53 infrastructure — a primary plus replicas, anycast or not, with all
the operational surface authoritative DNS carries (reflection abuse, port
exhaustion, the replica replication pipeline in ops/RUNBOOK.md). Many
operators already run their organization's DNS through a managed provider
and would rather add records to a zone they already have than stand up
nameservers.

The goal: a mode where the control plane **publishes** the membership
records to a provider-hosted zone via the provider's API, the provider
serves and DNSSEC-signs them, and the control plane runs no DNS listeners
at all.

The interesting part is not record publishing — that is a small
reconciler. It is that a managed provider will not hand over its private
keys, so the client's verification model must hold for a zone key nobody
on our side can sign with. Section 2 lays out the model that makes that
possible; section 3 gives the claim's exact shape.

## 2. What the client enforces

A client answer is accepted only after two gates:

**DNSSEC validation.** `crates/synch-net/src/dns.rs` validates in-process
(hickory over DoH) against the ICANN root anchor (or a `--dnssec-anchor`
override). This gate is provider-neutral: a zone signed by Cloudflare's
keys with a correct DS in the parent validates exactly as a self-served
zone does.

**Zone-key transparency.** By default (`RekorPolicy::Require`), a
validated answer is discarded unless the key that signed it is covered by
a verified Rekor log record. The proof check
(`crates/synch-net/src/rekor.rs`) is four verifications:

1. **Log inclusion** — the checkpoint carries the pinned log key's
   signature; the entry's Merkle inclusion path hashes up to it.
2. **Apex binding** — the logged certificate's single `dNSName` SAN names
   the zone whose RRSIG signed the answer.
3. **Authorization** — the certificate's embedded DNSSEC chain
   (`zonecert.rs`, the `OID_DNSSEC_CHAIN` extension: raw signed RRsets
   from the zone's declaration up to the root) is cryptographically
   verified against the trust anchors by `chain::authorize`, and what it
   proves is the apex DNSKEY RRset — the **authorized key set**. The key
   that signed the answer must be a member. The client verifies this chain
   even though it just validated the live one, because an entry whose chain
   is absent or broken would be invisible to a monitor (rekor.rs's "why the
   client verifies a chain it does not need").
4. **The declaration** — the chain's bottom link is the apex's own
   `_synchronicity-transparency.<apex>` TXT RRset, signed by the keys the
   ladder above it proved. Publishing that record takes write access to the
   zone, so an entry can only be built about a zone that has declared itself a
   control plane. It bounds *which zones* an entry can be about, and says
   nothing about who assembled the entry (§2.1).
5. **Attribution** — the entry signature over the DSSE PAE verifies under
   the certificate's own key: the entry is what its signer made, whoever
   that is.

### 2.1 Why the zone key signs nothing, and what does the work instead

The entry signature deliberately does **not** have to come from a zone
key, and requiring that would add no security.

Walk the threat. An attacker who wants a client to accept a rogue zone key
must present a proof passing the checks above for *that* key.
Authorization is the hard one: the entry must embed a DNSSEC chain in
which the parent's signed DS covers a key that signs the rogue key into
the apex RRset — which requires the attacker to have compromised the
parent zone or the registrar. And an attacker who minted a rogue key holds
its private half, so a signature by that key would cost them nothing. It
could only ever add *attribution* — the entry was made by the key's holder,
not a bystander — never *authorization*.

What bounds the entry instead is the **declaration**, and the bound is worth
stating precisely. A delegation ladder is public, so anyone can collect a
zone's DNSKEY and DS records; requiring the ladder to bottom out at
`_synchronicity-transparency.<apex>` means an entry can only be built about a
zone that has published a record declaring itself a control plane. Publishing
that record takes write access to the zone, and it is an ordinary record
write — so a zone whose DNSSEC keys live inside a managed provider can do it.
That is the trick the provider-managed case rests on: the requirement is
*controlling the zone*, not *holding the key*.

**It does not attribute an entry to the zone's operator.** Once published, the
declaration RRset and its RRSIG are public DNS: anyone can fetch the identical
bytes with the DO bit set and embed them in a chain of their own. So the
property the declaration delivers is "this entry is about a zone that has
declared itself a control plane" — it narrows entry-minting to the set of
synchronicity control planes, and stops there. What a third party still cannot
do is make an entry say anything *false*: the statement's key set must equal
the set the chain proves out of the DS-covered, RRSIG-verified DNSKEY RRset, so
the worst a replayer can log is a true claim about the zone's real keys, timed
as they choose. Telling one's own publications apart from a stranger's true
restatements is done against the operator's own record of what they minted
(§5.5 of docs/REKOR-ZONE-KEY.md), which is also §8's first cost.

Transparency's protection is *detectability*, not prevention. A
rogue-but-chained key is accepted by clients and simultaneously exposed in
the public log, where the monitor (`crates/synch-monitor`) files it as
evidence — and, because the monitor watches the whole delegation path
rather than one name, a takeover mounted from an ancestor zone shows up
there too.

## 3. The zone-key claim

### 3.1 The statement

- **Subject**: the apex DNSKEY RRset the entry's chain proves — the
  **key set** (see §3.3), one in-toto subject per key, each named by the
  apex and identified by the SHA-256 of its DNSKEY rdata. The predicate
  (`https://synchronicity.sh/zone-key/v2`) repeats the set with each
  key's tag, algorithm and flags.
- **Signer**: an **ephemeral ECDSA P-256 key, minted per entry and
  immediately discarded**. The signature is attribution and nothing more —
  the entry is what its signer made — and authorization is carried
  entirely by the chain, so a signer that exists for one signature is the
  honest expression of the model: no key file to store, protect, or
  rotate, and no false suggestion that the signing identity means
  anything. It signs the DSSE envelope; the Rekor `hashedrekord` verifier
  certificate names it, and on a refresh the stored entry's own
  certificate is what the signature verifies against.
- **Rendering**: byte-exact, fixed field order, no whitespace, one
  canonical key order (ascending tag, ties by digest) — the DSSE
  signature and the Merkle leaf both commit to the bytes, and both the
  Gleam and Rust renderers produce them identically.

### 3.2 The certificate and the chain walk

The certificate is a key envelope, not a trust assertion: its SAN carries
the apex into the Merkle leaf where a monitor can index it, and its
`OID_DNSSEC_CHAIN` extension (`SEQUENCE OF { zone, rrs }`, apex-first)
carries the evidence. Every link — the apex included — holds its own
DNSKEY RRset with the RRSIGs the walk needs, plus the DS RRset its parent
signed.

`chain::authorize` runs the standard delegation walk: the top link's
DNSKEY RRset verifies under a trust-anchored key, each link below proves
its DNSKEY RRset with a DS its parent signed, and what the walk returns is
the **proven apex key set**. A split-key zone is the reason for the shape
— the DS covers the KSK (SEP bit set) while answers are signed by the
ZSK, and DS → KSK → RRset is how DNSSEC itself authorizes the signing
key. A CSK zone is simply the degenerate case where the covered key and
the signing key are the same record; one walk serves both.

### 3.3 Provider key rotation and the key-set subject

Providers rotate ZSKs on their own schedule and without notice. If each
entry named exactly one key, every rotation would strand clients — the wire
key changes, no entry covers it, `Require` fails closed — until the control
plane noticed and re-logged.

Two mitigations, both part of this design:

- **The control plane watches** (§4.4): it re-observes the apex DNSKEY RRset
  every five minutes and logs a fresh entry whenever the set changes,
  updating the served `_synchronicity-rekor` TXT alongside.
- **The subject is the observed signing-key set**, not one key: every
  DNSKEY in the apex RRset (in practice one or two during a provider's
  rotation overlap). The client accepts a proof whose subject set contains
  the answer's signing key.

Together those two make a pre-publishing provider's rotation a non-event.
When the provider stages its next ZSK, the observed set changes, so the
watcher logs a claim covering **both** keys — days before the new one signs
anything. The set-valued subject is what makes one entry able to span both
sides of the cut; the watcher is what gets that entry logged while the old key
is still signing. Neither does it alone: an entry cannot cover a key that did
not exist when it was logged.

The residual gap is a provider that activates a key it never published. Then
clients fail closed until the watcher notices, logs, and the new proof
reaches the resolver a client asks — bounded by the cadence, publication, and
the proof records' TTL, and held by §4.2's timing relation to less than the
grace a client's existing bindings carry. That is the correct failure
direction, and §8 prices it.

## 4. Control plane: `CP_DNS_MODE=external`

### 4.1 Mode and configuration

`config.gleam` carries a mode with `serve` as the default — a deployment
that configures nothing serves its own zone:

```
CP_DNS_MODE=serve|external            # default: serve
CP_DNS_PROVIDER=cloudflare|bunny|log-only   # required iff external

CP_CLOUDFLARE_API_TOKEN=...           # zone-scoped token
CP_CLOUDFLARE_ZONE_ID=...             # optional; discovered via GET /zones?name= if absent
CP_CLOUDFLARE_API_URL=...             # test/e2e override, like CP_REKOR_URL

CP_BUNNY_API_KEY=...
CP_BUNNY_ZONE_ID=...                  # optional; discovered if absent
```

**`CP_BASE_DOMAIN` names an apex this deployment owns outright.** In external
mode the reconciler manages every TXT record below it and removes the ones it
did not render (§5.2), so the apex is a name that exists for the control plane
and nothing else — `control.example.com`, not `example.com`. The dashboard and
the REST API live on a sibling name, and so does anything else the
organization publishes. This is not enforced at boot, because no boot-time
check can tell what an operator intends a name for; the first sync verifies it
against the zone itself and refuses rather than assuming (§5.2).

Boot refusals, in the house "silent dead config is a lie" posture:

- provider credentials present while `CP_DNS_MODE=serve`;
- `CP_KEY_FILE` set in external mode (there is no zone CSK to hold);
- `CP_DNS_MODE=external` with `CP_ROLE=replica` — the replica role is
  serve-mode vocabulary; in external mode the provider's anycast fleet is
  the redundancy and there is exactly one control-plane instance that
  writes;
- `CP_DNS_LISTEN` set in external mode.

In external mode `serve_primary` builds a smaller tree: API pool, HTTP
(dashboard + REST — DoH is not mounted), the provider reconciler (§4.3),
the key watcher (§4.4), and the TUF refresh job both primary modes share —
which log shard the watcher submits to is answered from stored material in
either mode. No DNS pool, no UDP/TCP listeners, no hourly
re-sign job — there are no RRSIGs of ours to expire. `keygen`, `ds`, and
`/api/zone/anchor` refuse in external mode with a message naming the
reason.

### 4.2 Record rendering

A pure renderer — `zone/render_external.gleam` — consumes the same
`ZoneInput` that `zone/build.gleam` does and emits only the records that
are ours to publish, all of them strictly below the apex:

- membership TXT at `_synchronicity.<network>.<org_slug>.<apex>`, one
  string per non-revoked device key, via the same `rdata.sync1_text`
  rendering, at `ttl_data`. Omitted when `CP_REKOR_REQUIRE=true` and no
  verified log record exists yet — device bindings must not go out
  before a key is logged. The declaration still renders so the watcher
  can collect a chain;
- `_synchronicity-transparency.<apex>` TXT — the declaration (§2.1),
  rendered unconditionally, because it is what makes the *next* publish
  possible: link 0 of a chain is a signed copy of this RRset captured at
  publish time, so entries already logged keep verifying from the copies
  they carry, and deleting the live record breaks only chains not yet
  collected. Rendering it always means the watcher can always collect one.
  At `ttl_declaration`, because its twenty bytes are the same forever;
- `_synchronicity-rekor.<apex>` TXT and its numbered parts — the v2 proof
  records, at `ttl_proof`;
- `_synchronicity-owner.<apex>` TXT — the ownership marker the scope rule
  turns on (§5.2).

**`ttl_proof` is short, and the reason is the rotation window.** A client
caches nothing itself, so the only thing that TTL governs is how long the
recursive resolver it asks keeps serving the proof set from before a provider
rotated its keys. That interval is the tail of the window in which a `Require`
client fails closed, and it has to fit inside the *grace* a client's bindings
carry, or an ordinary rotation costs member bindings rather than a few
refreshes:

```
watch cadence + publish + ttl_proof  ≤  client trust grace
300           + 60      + 300        ≤  900
```

Both sides live in `crates/synch-net/src/dns.rs`: the sum on the left is
`CONTROL_PLANE_REPUBLISH_WINDOW`, spelled there as a sum of its three terms, and
the right is `DEFAULT_TRUST_GRACE`, whose own reasoning states the relation and
is checked by a test beside it. Eleven minutes of window against fifteen minutes
of grace: four minutes of headroom.

`ttl_data` is deliberately not a term. It is tempting to add it — a client
re-resolves on the TTL, so the answer it holds looks a TTL long — but expiry is
anchored to the client's *last successful refresh* and the refresh cadence **is**
the TTL, so by the time a rotation starts, the age of that last refresh has
already consumed the TTL term: with `T` the last success and `R` the moment the
provider starts signing with the un-logged key, `T − R ∈ (−ttl, 0]`. Crediting
`ttl_data` claims up to a full TTL of margin a client does not have, which at the
floor is the difference between a rotation costing a few refreshes and one
dropping every DNS-sourced binding for the domain at once.

The Rust assertion is the one that pins this. `external_test.gleam` also states a
relation over `render_external.ttl_proof`, but it hard-codes the watch cadence and
the client grace as literals rather than referencing either side's constants, and
it credits `ttl_data` — so it holds the *Gleam* numbers still and says nothing
about the client's. Moving `DEFAULT_TRUST_GRACE` fails the Rust test and leaves
that one passing.

**Everything hangs off the apex**, which is also where the client looks: it
takes the apex from the `apex=` field of the membership answer it has already
validated, bounded by the signing zone the RRSIG names
(docs/REKOR-ZONE-KEY.md §3). The signing zone is the zone the provider
actually hosts, and it differs from the apex when a control plane at
`control.example.com` lives inside the `example.com` zone with no delegation
of its own (`CP_SIGNING_ZONE`); it decides where a chain's ladder starts, not
where any record goes.

SOA, NS, DNSKEY, NSEC/NSEC3, and every RRSIG are the provider's business.
The renderer re-runs the product-invariant validation `build.build`
performs (`AmbiguousNk`, `DuplicateLabelInZone`, `InvalidNk`,
`OwnerOutsideZone`) — those invariants protect clients, not the wire
format, and they hold in either mode. Output is a provider-neutral record
list (§5), deterministically sorted so that a content hash of it is stable.

### 4.2.1 Which proofs the zone serves

`rekor_records` is history — every key set this deployment ever logged, kept
because §5.5 of the transparency document makes comparing monitor reports
against what you published the operator's job. What the *zone* serves is
narrower:

> A proof is served if and only if its key set contains at least one key the
> zone currently publishes.

A proof authorizes an answer when the key that signed the answer is a member
of the proof's key set, so a claim covering no live key cannot authorize
anything. Serving it would cost every client a chain walk it can only reject
and cost the zone bytes at an owner name the provider caps.

`rekor/store.servable` applies it, and each mode supplies the live set from
what it already knows: `observed_zone_keys` in external mode, and in serve
mode the DNSKEY set `zone/build` publishes — the active key plus the incoming
one while a rollover stages it. An empty set means "not observed yet" and
serves everything, so a first boot never blanks the proofs it has.

The bound this produces is worth stating exactly, because it is what keeps the
zone inside the provider's per-name cap. Through a pre-publication rotation the
observed set moves `{A}` → `{A,B}` → `{B}` while the stored claims are `{A}`,
`{A,B}`, `{B}`. During the overlap all three intersect, so three proofs are
served; once `A` leaves the RRset the `{A}` claim drops out and two remain.

Behind that, a budget: every proof has a part 1 and they all land at
`_synchronicity-rekor.<apex>`, so that name is the one that fills up.
`model.proofs_within_budget` holds the rendered part-1 bytes under the tightest
cap among supported providers less one part's worth — room for one part more
than we plan to publish, so a chain that grows a delegation level does not tip
the zone over. Over budget it drops the oldest claims and says how many in the
`provider.sync` audit row and the boot log. A cap nobody is told about reads as
"everything is published" when it is not.

`zone/publish.gleam` still runs in external mode, minus signing and minus
`presigned_rrsets`: it bumps `soa_serial` (which remains the generation
counter the reconciler tracks), validates via the renderer, and writes the
audit row. Commit still marks "the database changed"; what it no longer
marks is "the wire changed" — see §4.5.

### 4.3 The reconciler

`jobs/provider_sync.gleam`, an OTP actor cloned from `jobs/resign.gleam`'s
shape: supervised worker, own short-lived writer connection (pools are for
request paths), self-scheduled sweep, "failure is a log line" posture. Two
additions to the resign template:

- **A registered name accepting `Poke`.** `api/common.gleam:zone_mutation`
  sends it *after* its transaction commits — never inside; provider APIs
  are slow, eventually consistent, and cannot hold a SQLite write
  transaction hostage. A poke coalesces naturally: the actor processes one
  sync at a time and a queued poke that finds `applied_hash` already
  current is a no-op.
- **An hourly sweep** as the repair path: transient provider failures,
  provider-side manual edits, and missed pokes all converge on the next
  tick.

One sync pass:

1. Read `ZoneInput` and `soa_serial` on a fresh read connection; render
   the desired record set; hash it (SHA-256 over the canonical sort).
2. If the hash equals `provider_sync_state.applied_hash`, stop — the
   common case for the sweep.
3. `provider.list()` — every TXT record the provider holds strictly below
   the apex (§5.2). The scope is structural, so it takes no argument.
4. Diff at RRset granularity (§5.1). A conflict — a record below the apex
   we did not render, with no ownership marker — is recorded in
   `last_error`, logged, and stops the pass. The reconciler never
   clobbers.
5. `provider.apply(changes)` — every change attempted, in creates, replaces,
   deletes order. A record the provider refuses is reported by name and does
   not stop the ones behind it.
6. On a clean apply, update `provider_sync_state` (hash,
   `last_synced_serial`, timestamps). On a partial one, record the refusals
   and *leave the hash alone*: the zone is not the set we rendered, so the
   next sweep recomputes the diff and retries what is still missing. Either
   way write an `audit_log` row (`action='provider.sync'`, detail:
   creates/replaces/deletes counts, proofs shed, records refused, and the
   serial), matching the `zone.publish` audit convention.

**Why an apply does not abort.** The records this zone publishes are not
equally urgent, and the big ones are not the important ones. Stopping at the
first refusal put every remaining record behind the refused one — and because
the desired set is name-sorted, the proof records come before the membership
records, so a transparency proof the provider would not take was enough to
stop a device revocation from landing. Creates now go out in dependency order
instead (marker, declaration, membership, proofs) and nothing aborts.

There is deliberately **no outbox**. An outbox earns its keep when desired
state is a function of history; here it is a pure function of the current
tables — the same property `zone/build.gleam` exploits — so
desired-state-plus-sweep is simpler, and unlike an outbox it self-heals
drift introduced behind our back in the provider's console.

Failure posture matches the codebase: a provider outage degrades to a
stale-but-serving zone (the provider keeps answering with the last
records), never to a failed control plane. Staleness is *reported* (§4.6),
not fatal — the same stance `healthz` takes on absent TUF material.

### 4.4 The key watcher

`jobs/zonekey_watch.gleam`, a second actor on the same template, closing
the §3.3 loop:

1. On a fixed five-minute cadence (`watch_interval_ms` — a constant, not a
   knob, and one term of the timing relation in §4.2; thirty seconds
   while the declaration is not on the wire yet, because the reconciler
   publishes it at boot),
   resolve and DNSSEC-validate the signing-zone DNSKEY RRset over DoH — the
   existing `rekor/chain.gleam` collection machinery, which already speaks
   validating DoH for chain assembly.
2. Compare the zone-signing key set against `observed_zone_keys`.
3. On change: collect the full chain, build the v2 statement over the new
   set, sign with a freshly minted ephemeral key, submit through the injected
   `rekor/client.Log`, verify inclusion, store the record
   (`rekor/store.gleam` conventions), stamp only the observed keys that
   record covers, and poke the reconciler so the `_synchronicity-rekor`
   TXT follows. Extra keys stay unlogged so the next tick retries them.
   Audit row `action='zonekey.logged'`.

`rekor-publish`/`rekor-retire` remain as manual ceremonies for serve mode,
taking a key file and reading the apex and signing zone from `CP_BASE_DOMAIN`
and `CP_SIGNING_ZONE` like every other command — the zone a deployment speaks
for is configuration, not an argument. External mode's logging is continuous by
construction because the subject key is not ours and moves without asking us.

### 4.5 Eventual consistency, stated honestly

In serve mode, commit is publication. In external mode it is not: a
mutation is visible on the wire after the reconciler's next pass plus the
provider's own propagation (typically seconds; Cloudflare and Bunny are
effectively immediate at the edge). API semantics are unchanged — `zone_mutation` returns success at
commit, as today — but the meaning narrows from "published" to "accepted
and will converge". The dashboard and `/healthz` carry the convergence
state; nothing pretends the window doesn't exist.

### 4.6 Persistence and observability

Two migrations, in the house style (append-only list in
`store/migrate.gleam`, CHECK constraints making invalid states
unrepresentable):

```sql
-- V4: external DNS provider mode. One row: one deployment, one apex, one
-- provider. Desired state is derived from the product tables, never
-- stored; this row records only what the reconciler last did.
CREATE TABLE provider_sync_state (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  provider           TEXT    NOT NULL CHECK (provider IN ('cloudflare','bunny','log-only')),
  provider_zone_id   TEXT    NOT NULL,
  applied_hash       BLOB    CHECK (applied_hash IS NULL OR length(applied_hash) = 32),
  last_synced_serial INTEGER,
  last_ok_at         INTEGER,
  last_attempt_at    INTEGER NOT NULL,
  last_error         TEXT,
  last_error_at      INTEGER,
  CHECK ((last_error IS NULL) = (last_error_at IS NULL))
);

-- The provider signing keys last observed on the wire, and when each was
-- covered by a logged entry. The watcher's memory, keyed by the SHA-256 of
-- the DNSKEY rdata — the digest every other part of this design names keys
-- by, and what the serving filter of §4.2.1 matches against.
CREATE TABLE observed_zone_keys (
  key_sha256   BLOB    NOT NULL CHECK (length(key_sha256) = 32),
  key_tag      INTEGER NOT NULL,
  dnskey_rdata BLOB    NOT NULL,
  first_seen   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  logged_at    INTEGER,
  PRIMARY KEY (key_sha256)
);

-- V7: an apply can partly succeed, so the state row needs somewhere to say
-- which records the provider refused. Neither column is a work queue —
-- desired state is still derived, and the next sweep recomputes the diff.
ALTER TABLE provider_sync_state ADD COLUMN last_failures TEXT;
ALTER TABLE provider_sync_state ADD COLUMN last_partial_at INTEGER;
```

`/healthz` in external mode reports: `provider`, `provider_zone_id`,
`provider_last_synced_serial` vs `soa_serial`, `provider_in_sync` (hash
comparison — no provider round-trip on the health path),
`provider_last_ok_at`, `provider_last_error`/`_at`,
`provider_last_failures`/`provider_last_partial_at`, and the watcher's
`keys_observed`, `keys_logged` and `oldest_unlogged_age`. That last one is
the number to alert on: it is how long the oldest key the watcher has seen
has gone without a logged claim, so a value past a couple of intervals is a
zone whose next answer may fail closed. The serve-mode fields (`sig_expiry`,
served serial) are absent rather than faked.

## 5. The provider abstraction

### 5.1 Interface

House record-of-functions style, exactly as `rekor/client.Log` and
`tuf/fetch.Repo` — a single-constructor type holding function fields, real
HTTP legs built at the edge, fakes supplied inline in tests:

```gleam
// src/provider/provider.gleam
pub type Rtype {
  Txt
  // Every record this deployment publishes is TXT, and a leg lists nothing
  // else — so a record of another type below the apex never reaches the
  // diff. The old "no cross-type deletes" rule is structural now rather
  // than checked.
}

/// One desired record, provider-neutral. `value` is the full TXT string
/// (unchunked — chunking is a per-provider wire concern, §6).
pub type Record {
  Record(name: String, rtype: Rtype, ttl: Int, value: String)
}

/// A record as the provider holds it. `id` is the provider's handle —
/// an opaque string, empty where a provider has no per-record ids.
pub type Existing {
  Existing(id: String, record: Record)
}

pub type Changes {
  Changes(
    create: List(Record),
    replace: List(#(Existing, Record)),
    delete: List(Existing),
  )
}

/// One change the provider refused, named so an operator can see which
/// record is stuck without reading the whole zone back.
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
    /// Applies every change it can and reports the ones it could not. The
    /// outer Error is for a failure that says nothing about any single
    /// record — a rejected credential, an unreachable API.
    apply: fn(Changes) -> Result(Applied, String),
    /// For the boot log, like mailer.describe.
    describe: String,
  )
}

pub fn log_only() -> Provider   // dry-run leg, mailer's LogOnly pattern
pub fn below(name: String, apex: String) -> Bool   // the scope, one rule
```

### 5.2 The scope rule, and the refusal that guards it

The apex belongs to this deployment outright (§4.1), which is what lets the
scope be a single structural sentence rather than a list of names:

> **Every TXT record strictly below the apex is this deployment's to
> reconcile.**

So a record down there that the renderer did not produce is drift, and drift is
removed. That is a real power, and two things keep it from ever pointing at a
zone this deployment does not own — both in the pure diff
(`provider/diff.gleam`), so they are table-testable:

- **Strictly below.** The apex name itself is excluded. Nothing we publish
  sits there, and it is where the zone's own SOA, NS and DNSKEY live along
  with whatever a registrar or provider asks for. `provider.below` is the one
  place that decides, and it folds case on both sides because DNS names are
  case-insensitive and providers hand them back lowercased.
- **TXT only.** A leg lists nothing else, so a record of another type below the
  apex never reaches the diff: it cannot be deleted and cannot be a conflict.
  Every record we publish is TXT, so nothing is lost by not looking.
- **The ownership marker carries its scope.** `_synchronicity-owner.<apex>`
  TXT, value `heritage=synchronicity-cp,scope=apex` — the external-dns
  registry idea, plus the reach it authorizes. Deletes require that exact
  value at that name; byte-equal records elsewhere are adopted silently, and
  anything else below the apex is a named conflict that stops the pass with
  nothing touched.

The marker is why the dedicated-apex requirement does not have to be taken on
faith. A first sync against an apex somebody else is using finds records it did
not render, has no marker to authorize removing them, and refuses — naming the
record. Only an apex that is genuinely this deployment's gets the marker
written, and only then do deletes become possible. A marker written by a
different control plane, or one that names a different scope, is its own
conflict (`MarkerMismatch`) with its own remedy: it is fixed by deleting the
record, not by moving it, and the reconciler says so rather than overwriting a
licence nobody granted it.

## 6. Provider notes: Cloudflare, Bunny

**Cloudflare** — phase 1, the reference leg (`provider/cloudflare.gleam`).
v4 REST, single `Authorization: Bearer` token, scopable to Zone:DNS:Edit
on one zone (the runbook says so; a global API key works but must not be
recommended). Zone id explicit or discovered once via
`GET /zones?name=` against the **signing zone** (`CP_SIGNING_ZONE`,
defaulting to the apex). Listing still keeps only TXT strictly below
the apex.
Per-record ids; `per_page=100` pagination on list. TXT content: Cloudflare
accepts the full string and chunks at 255 bytes server-side. `proxied` is
meaningless for TXT but the leg pins `proxied: false` on anything it ever
writes, as a matter of policy. DNSSEC: enabled per-zone in the dashboard
or via API (`/dnssec` endpoint — the runbook automates the check, not the
toggle); Cloudflare signs with per-zone ECDSA P-256 keys, effectively
static outside algorithm migrations, and pre-publishes on rotation — the
friendliest case for §3.3. `CP_CLOUDFLARE_API_URL` overrides the base URL
so the e2e stub can stand in, mirroring `CP_REKOR_URL`.

**Bunny** — phase 2, gated (`provider/bunny.gleam`). Simplest API of the
three: `AccessKey` header, JSON, records addressed by numeric id within
`GET/POST /dnszone/{id}`. The gate: **whether Bunny signs hosted zones
(DNSSEC) is unverified**, and external mode is meaningless without it —
an unsigned zone fails every client at the first gate, before Rekor is
even consulted. Phase 3 begins with that verification against a real
account; if Bunny cannot sign the zone, the leg is dropped rather than
shipped with a caveat that amounts to "disable client security". A
secondary caution either way: Bunny API keys are account-scoped, not
zone-scoped — the credential blast radius is every zone on the account,
and the docs must say so.

## 7. Cutover runbook

Migrating a live serve-mode deployment; a green-field external deployment
runs the same steps minus the decommissioning.

1. **Prepare.** Create/verify the provider zone for the apex; enable
   DNSSEC on it (the provider's own toggle and ceremony). Check that
   `CP_BASE_DOMAIN` is a name nothing else publishes under (§4.1) — the
   dashboard's own hostname is a sibling of the apex, not a child of it, and
   any TXT record already sitting below the apex has to move before the first
   sync will touch the zone.
2. **Dual-run.** Flip the control plane to `external` with the provider
   configured but the registrar still pointing at our NS. The reconciler
   populates the provider zone; the watcher observes the provider's keys
   and logs the claim (the provider zone answers its own DNSKEY even
   before delegation). Our listeners keep serving the live zone.
   Verify: provider zone contains exactly the rendered set plus the ownership
   marker; the entry verified in the log; `healthz` `provider_in_sync=true`
   with `oldest_unlogged_age` null.
3. **Cut.** At the registrar: replace NS with the provider's, replace the
   DS with the provider's KSK DS. The parent's TTL governs the window;
   during it both zones answer, both validly signed, both carrying proof
   records for their respective key sets, distributed in-band by
   whichever zone answers.
4. **Verify.** `delv @1.1.1.1 _synchronicity.<net>.<org>.<apex> TXT`
   fully validates via the provider; a client resolves and accepts the
   member set end-to-end; the monitor sees the entry.
5. **Decommission.** Retire the CSK (`rekor-retire` files the retirement
   breadcrumb), stop the old listeners, drop replicas. Rollback before
   this step is symmetric: restore NS+DS at the registrar — the serve-mode
   zone never stopped being correct.

## 8. Costs, stated plainly

- **Anyone can log a true entry about any declared control plane.** The
  declaration and its RRSIG are public DNS, so a third party can assemble the
  same chain and log the same statement about your key set at a time of their
  choosing; the client accepts chained third-party entries too. No signer
  identity separates operator entries from anyone else's — deliberately: the
  signature is per-entry ephemeral, and authorization rests entirely on the
  chain, which §2.1 argues is where it rests in any case. The entry cannot be
  made to say anything untrue about the key set, so the residual cost is noise
  aimed at the alarm: reports the operator has to check against their own
  record of what they minted.
- **The wire is eventually consistent.** Commit no longer equals
  publication; a reconciler pass and provider propagation sit between a
  mutation and the edge. Seconds in practice, unbounded during a provider
  outage — reported in `healthz`, never blocking the API.
- **Key custody moves to the provider.** The DNSSEC private keys sign
  whatever the provider's infrastructure signs; a provider compromise is
  a zone compromise, detectable in the log (the same detectability we
  offer against ourselves in serve mode) but not preventable by us.
- **Fail-closed rotation gap.** A provider cutting to a never-observed key
  strands `Require` clients for three intervals in series: the watch cadence
  before we notice, the log round trip and reconciler pass, and — the term
  that is easy to forget — the proof records' own TTL, because a client
  caches nothing itself and the recursive resolver it asks may still be
  serving the pre-rotation proof set. That is why `ttl_proof` is 300 s rather
  than a day, and why §4.2 states the whole sum — eleven minutes — as a relation
  against the *grace* a client's bindings carry rather than against the TTL plus
  that grace: the TTL is consumed by the age of the client's last successful
  refresh before the rotation even starts. Past the grace a client does not
  merely fail to refresh — the maintenance pass deletes its DNS-sourced
  bindings — so the margin is what separates a rotation costing a few refreshes
  from one costing members. Pre-publishing providers (all three, normally) make
  the case theoretical; the cost is priced anyway.
- **Proof history is not served forever.** Only claims covering a key the zone
  currently publishes go into the zone (§4.2.1). Older claims stay in
  `rekor_records` as the operator's own record, and a monitor reporting a key
  the zone no longer serves a proof for is expected rather than alarming.
- **Answer shape is the provider's.** Negative proofs become whatever the
  provider serves (Cloudflare's on-the-fly "black lies" NSEC). Standard
  validators — hickory included — accept all of them,
  but the exact-NSEC guarantees of serve mode are not preserved.
- **Egress and credentials on the primary.** The control plane now holds
  a DNS-write credential and calls provider APIs continuously —
  consistent with the existing `tuf/fetch` egress posture, but a bigger
  secret than any it holds today. Zone-scoped tokens where the provider
  offers them (Cloudflare yes, Bunny no).

## 9. Testing

- **Pure, table-driven** (the `zone_test.gleam` style): renderer output
  for representative `ZoneInput`s including invariant refusals and the TTL
  each record carries; the scope rule (`provider.below`: strictly below,
  case-folded, siblings excluded); diff tables — adoption, marker-missing
  conflict, marker-of-another-scope refusal, a proof part we stopped
  rendering deleted, create ordering, idempotence
  (`diff(desired, desired-as-existing)` is empty); the desired-set hash's
  stability under permutation; the proof budget's shed order.
- **The timing relation of §4.2**: the client's `DEFAULT_TRUST_GRACE` against
  `CONTROL_PLANE_REPUBLISH_WINDOW` in `crates/synch-net`, which is the relation
  that actually has to hold, and the Gleam constants (`ttl_proof`, `ttl_data`) in
  `external_test.gleam`. The two client-side numbers are literals on the Gleam
  side, so that test does not fail when they move — the Rust assertion is the one
  that pins them.
- **Provider legs at their pure edges**: Cloudflare's TXT presentation
  folding and Bunny's relative-name conversion as unit tests; no network
  in tests, house rule.
- **The reconciler**: `run_once_with` ladders exactly like
  `resign.run_once_with`, driven with in-memory fakes; asserted:
  convergence, second-run no-op, conflict refusal leaves the provider
  untouched, failure → stale state → recovery, and a refused record
  reported as partial while every other record still goes out and the
  applied hash does not advance.
- **The watcher**: the same ladder over a fake resolver and a fake log;
  asserted: an unchanged set logs nothing, an added key logs a claim
  covering both, a removed key logs again, and a log that cannot be reached
  leaves the key unlogged — visible as `oldest_unlogged_age` — and is
  retried on the next tick rather than mistaken for covered.
- **Claim cross-validation**: the Gleam statement/cert renderer's output
  verified by the Rust client's verifier in `e2e/tests/crossval.rs`;
  chain-walk cases (CSK degenerate, KSK/ZSK split, subject-not-in-RRset
  refusal) on both sides.
- **e2e**: a Cloudflare-shaped HTTP stub in `e2e/run.sh` (the harness
  already stands up servers and curls them); `CP_CLOUDFLARE_API_URL`
  points at it; assert the stub converges to exactly the rendered set
  plus the ownership marker, and that a poked mutation shows up without
  waiting for the sweep. Full wire-serving e2e against a real provider
  needs a real account — a manual pre-GA checklist item, not CI.

## 10. Remaining work

1. **Bunny** — DNSSEC verification against a real account gates GA.
2. **Polish** — dashboard sync-state surfacing, post-apply DoH
   verification probe (the reconciler confirming the edge actually
   serves what it pushed), runbook hardening from a real cutover.

## 11. Open questions

1. **Bunny DNSSEC** — can a Bunny-hosted zone be signed at all? Gates
   phase 4 entirely.
2. **Watch cadence vs. rotation reality** — five minutes is chosen to
   satisfy §4.2's relation, not from a measurement of any provider's
   overlap window. Confirm Cloudflare's pre-publication overlap from its
   documentation or observation; if it is generous, the cadence could be
   relaxed, and the honest lever then is the cadence rather than the proof
   TTL, because the TTL is what a client pays for.
3. **Cloudflare suffix filtering.** The leg lists TXT records page by page
   and applies the apex suffix locally. Filtering server-side would keep
   responses small on a zone that holds many other names; worth measuring
   on a real zone, since this runs every sweep.
4. **Shed order.** Oldest-by-`verified_at` is the obvious rule for a proof
   set over budget and not obviously the right one: a claim covering a key
   that only just left the RRset may be worth more than a newer claim
   covering nothing live. Unreachable in normal operation, so unmeasured.
5. **Chunking boundary** — the client concatenates TXT strings before
   parsing (`dns.rs`); confirm each provider's chunking preserves
   concatenation order for >255-byte member records, and add a crossval
   case.
6. **Signer identity is gone by construction** — entries are signed by
   per-entry ephemeral keys, so monitors cannot distinguish operator
   entries from third-party ones by signer. Resolved deliberately: the
   distinction was never security (§2.1), and the operator's own record
   of what they published is the judgement that matters.
7. **Rate limits under churn** — a large deployment's mutation burst maps
   to how many provider calls after coalescing? Needs numbers from the
   phase-2 e2e stub under load before defaults (debounce, batch size)
   are pinned.
8. **`_synchronicity-owner` name** — as designed the marker is a real
   published TXT (harmless, but visible). An alternative is provider-side
   comment/tag fields where they exist; not every provider has them, so
   the record is the portable choice.
