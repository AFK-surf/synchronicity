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
and `_synchronicity-tuf` TXT, and the NSEC chain), `zone/publish.gleam` signs every RRset with the zone CSK and writes
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
   ladder above it proved. Without it the entry would prove only public
   records, which anyone can read out of an open resolver.
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

But attribution is not worthless, and dropping it outright would leave a
real gap: a delegation ladder is public, so anyone could collect a zone's
DNSKEY and DS records and mint an entry about a zone that never heard of
them, leaving monitors unable to tell an operator's own publication from a
stranger's. The **declaration** closes that without reaching for the
private key. Publishing `_synchronicity-transparency.<apex>` requires write
access to the zone, which is exactly the authority the entry claims to
speak with — and it is an ordinary record write, so a zone whose DNSSEC
keys live inside a managed provider can do it. That is the whole trick: the
proof of authority moved from *holding the key* to *controlling the zone*,
and only the second is available to a provider-managed deployment.

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

- **The subject is the observed signing-key set**, not one key: every
  DNSKEY in the apex RRset (in practice one or two during a provider's
  rotation overlap). The client accepts a proof whose subject set contains
  the answer's signing key. A provider pre-publishing its next ZSK — the
  standard rotation dance — is therefore covered by the *existing* entry
  before the new key signs anything.
- **The control plane watches** (§4.4): it re-observes the apex DNSKEY
  RRset on a short cadence and logs a fresh entry whenever the set
  changes, updating the served `_synchronicity-rekor` TXT alongside.

The residual gap — a provider that cuts to a never-pre-published key
faster than the watch cadence — fails closed for the propagation window.
That is the correct failure direction, and §8 prices it.

## 4. Control plane: `CP_DNS_MODE=external`

### 4.1 Mode and configuration

`config.gleam` grows a mode with `serve` as the default — a deployment
that configures nothing gets today's behavior, bit for bit:

```
CP_DNS_MODE=serve|external            # default: serve
CP_DNS_PROVIDER=cloudflare|bunny|log-only   # required iff external

CP_CLOUDFLARE_API_TOKEN=...           # zone-scoped token
CP_CLOUDFLARE_ZONE_ID=...             # optional; discovered via GET /zones?name= if absent
CP_CLOUDFLARE_API_URL=...             # test/e2e override, like CP_REKOR_URL

CP_ROUTE53_ACCESS_KEY_ID + CP_ROUTE53_SECRET_ACCESS_KEY   # credential_pair
CP_ROUTE53_ZONE_ID=...                # required (no discovery; names are ambiguous)

CP_BUNNY_API_KEY=...
CP_BUNNY_ZONE_ID=...                  # optional; discovered if absent
```

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
and the key watcher (§4.4). No DNS pool, no UDP/TCP listeners, no hourly
re-sign job — there are no RRSIGs of ours to expire. `keygen`, `ds`, and
`/api/zone/anchor` refuse in external mode with a message naming the
reason.

### 4.2 Record rendering

A new pure renderer — `zone/render_external.gleam` — consumes the same
`ZoneInput` that `zone/build.gleam` does and emits only the records that
are ours to publish:

- membership TXT at `_synchronicity.<network>.<org_slug>.<apex>`, one
  string per non-revoked device key, via the same `rdata.sync1_text`
  rendering;
- `_synchronicity-transparency.<apex>` TXT — the declaration (§2.1),
  rendered unconditionally: a zone that stopped publishing it would have
  every entry it ever logged stop verifying;
- `_synchronicity-rekor.<signing zone>` TXT — the v2 proof records;
- `_synchronicity-tuf.<signing zone>` TXT — the relayed TUF bundle.

The last two sit at the **signing zone** rather than the apex. The apex is
the control plane's name; the signing zone is the zone the provider actually
hosts, and the two differ when a control plane at `sync.example.com` lives
inside the `example.com` zone with no delegation of its own
(`CP_SIGNING_ZONE`). A client can only compute the signing zone — it reads it
off the RRSIG signer of the answer it just validated — whereas the apex is a
name only the log entry knows, so that is where the records a client must
*find* have to live.

SOA, NS, DNSKEY, NSEC/NSEC3, and every RRSIG are the provider's business.
The renderer re-runs the product-invariant validation `build.build`
performs today (`AmbiguousNk`, `DuplicateLabelInZone`, `InvalidNk`,
`OwnerOutsideZone`) — those invariants protect clients, not the wire
format, and they hold in either mode. Output is a provider-neutral record
list (§5), deterministically sorted so that a content hash of it is stable.

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
3. `provider.list(managed_names)` — only names we manage are ever read.
4. Diff at RRset granularity (§5.1). A conflict — foreign data at a
   managed name without our ownership marker — is recorded in
   `last_error`, logged, and stops the pass. The reconciler never
   clobbers.
5. `provider.apply(changes)` — sequential per record on both legs; the
   diff is idempotent, so a partial apply is repaired by the next pass.
6. Update `provider_sync_state` (hash, `last_synced_serial`, timestamps)
   and write an `audit_log` row (`action='provider.sync'`, detail:
   creates/replaces/deletes counts and the serial), matching the
   `zone.publish` audit convention.

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

1. On a short cadence (default 15 minutes; `CP_ZONEKEY_WATCH_SECONDS`),
   resolve and DNSSEC-validate the apex DNSKEY RRset over DoH — the
   existing `rekor/chain.gleam` collection machinery, which already speaks
   validating DoH for chain assembly.
2. Compare the zone-signing key set against `observed_zone_keys`.
3. On change: collect the full chain, build the v2 statement over the new
   set, sign with a freshly minted ephemeral key, submit through the injected
   `rekor/client.Log`, verify inclusion, store the record
   (`rekor/store.gleam` conventions), update `observed_zone_keys`, and
   poke the reconciler so the `_synchronicity-rekor` TXT follows. Audit
   row `action='zonekey.logged'`.

`rekor-publish`/`rekor-retire` remain as manual ceremonies for serve mode;
external mode's logging is continuous by construction because the subject
key is not ours and moves without asking us.

### 4.5 Eventual consistency, stated honestly

In serve mode, commit is publication. In external mode it is not: a
mutation is visible on the wire after the reconciler's next pass plus the
provider's own propagation (typically seconds; Cloudflare and Bunny are
effectively immediate at the edge). API semantics are unchanged — `zone_mutation` returns success at
commit, as today — but the meaning narrows from "published" to "accepted
and will converge". The dashboard and `/healthz` carry the convergence
state; nothing pretends the window doesn't exist.

### 4.6 Persistence and observability

Migration v4, in the house style (append-only list in
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
-- covered by a logged entry. The watcher's memory.
CREATE TABLE observed_zone_keys (
  spki_sha256 BLOB    NOT NULL CHECK (length(spki_sha256) = 32),
  key_tag     INTEGER NOT NULL,
  dnskey_rdata BLOB   NOT NULL,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  logged_at   INTEGER,
  PRIMARY KEY (spki_sha256)
);
```

`/healthz` in external mode reports: `provider`, `provider_zone_id`,
`sync_serial` vs `soa_serial`, `in_sync` (hash comparison — no provider
round-trip on the health path), `last_ok_at`, `last_error`/`last_error_at`,
and the watcher's `keys_observed`/`keys_logged`/`oldest_unlogged_age`. The
serve-mode fields (`sig_expiry`, served serial) are absent rather than
faked.

## 5. The provider abstraction

### 5.1 Interface

House record-of-functions style, exactly as `rekor/client.Log` and
`tuf/fetch.Repo` — a single-constructor type holding function fields, real
HTTP legs built at the edge, fakes supplied inline in tests:

```gleam
// src/provider/provider.gleam
pub type Rtype {
  Txt
  // The enum exists so the diff can refuse foreign types at managed
  // names by name; external mode itself publishes only TXT.
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

pub type Provider {
  Provider(
    /// Every record the provider holds at exactly these names.
    list: fn(List(String)) -> Result(List(Existing), String),
    /// Applies a change set. Atomic where the provider allows it.
    apply: fn(Changes) -> Result(Nil, String),
    /// For the boot log, like mailer.describe.
    describe: String,
  )
}

pub fn log_only() -> Provider   // dry-run leg, mailer's LogOnly pattern
```

### 5.2 Ownership and the refusal rule

The reconciler must be incapable of eating a zone it doesn't own. Three
rules, enforced in the pure diff (`provider/diff.gleam`) so they are
table-testable:

- **Scope**: operations are emitted only for managed names — the
  `_synchronicity*` owners the renderer produced. The provider is never
  asked to list anything else, and the `_synchronicity.` prefix means the
  managed set is disjoint from any human-managed record by construction.
- **Ownership marker**: an `_synchronicity-owner.<apex>` TXT
  (`"heritage=synchronicity-cp"`, the external-dns registry idea) is
  created on first sync. At any managed name holding data we didn't
  render, the diff refuses with a named conflict unless the marker
  exists; byte-equal records are adopted silently.
- **No cross-type deletes**: at a managed name, only `Txt` records are
  ever replaced or deleted; a foreign A record squatting there is a
  conflict, not a casualty.

## 6. Provider notes: Cloudflare, Bunny

**Cloudflare** — phase 1, the reference leg (`provider/cloudflare.gleam`).
v4 REST, single `Authorization: Bearer` token, scopable to Zone:DNS:Edit
on one zone (the runbook says so; a global API key works but must not be
recommended). Zone id explicit or discovered once via `GET /zones?name=`.
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
   DNSSEC on it (the provider's own toggle and ceremony).
2. **Dual-run.** Flip the control plane to `external` with the provider
   configured but the registrar still pointing at our NS. The reconciler
   populates the provider zone; the watcher observes the provider's keys
   and logs the claim (the provider zone answers its own DNSKEY even
   before delegation). Our listeners keep serving the live zone.
   Verify: provider zone contains exactly the rendered set; the entry
   verified in the log; `healthz` `in_sync=true`.
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

- **Anyone can log an entry about any zone** (they always could log
  *something*; the client accepts chained third-party entries too). No
  signer identity
  distinguishes operator entries from anyone else's — deliberately: the
  signature is per-entry ephemeral, and
  authorization rests entirely on the chain — which §2.1 argues is where
  it always rested.
- **The wire is eventually consistent.** Commit no longer equals
  publication; a reconciler pass and provider propagation sit between a
  mutation and the edge. Seconds in practice, unbounded during a provider
  outage — reported in `healthz`, never blocking the API.
- **Key custody moves to the provider.** The DNSSEC private keys sign
  whatever the provider's infrastructure signs; a provider compromise is
  a zone compromise, detectable in the log (the same detectability we
  offer against ourselves in serve mode) but not preventable by us.
- **Fail-closed rotation gap.** A provider cutting to a never-observed
  key strands `Require` clients until the watcher re-logs (≤ watch cadence
  + propagation). Pre-publishing providers (all three, normally) make
  this theoretical; the cost is priced anyway.
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
  for representative `ZoneInput`s including invariant refusals; diff
  tables — adoption, marker-missing conflict, foreign-type immunity,
  scope discipline, idempotence (`diff(desired, desired-as-existing)` is
  empty); the desired-set hash's stability under permutation.
- **Provider legs at their pure edges**: Cloudflare's TXT presentation
  folding and Bunny's relative-name conversion as unit tests; no network
  in tests, house rule.
- **Reconciler and watcher**: `run_once_with(db_path, provider, now)` /
  `run_once_with(db_path, resolver, log, now)` ladders exactly like
  `resign.run_once_with`, driven with in-memory fakes; asserted:
  convergence, second-run no-op, conflict refusal leaves the provider
  untouched, failure → stale state → recovery, key-set change → new
  entry → rekor TXT poke.
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
2. **Watch cadence vs. rotation reality** — 15 minutes is a guess;
   confirm Cloudflare's pre-publication overlap window from its
   documentation or observation before pinning the default.
3. **Chunking boundary** — the client concatenates TXT strings before
   parsing (`dns.rs`); confirm each provider's chunking preserves
   concatenation order for >255-byte member records, and add a crossval
   case.
4. **Signer identity is gone by construction** — entries are signed by
   per-entry ephemeral keys, so monitors cannot distinguish operator
   entries from third-party ones by signer. Resolved deliberately: the
   distinction was never security (§2.1), and the operator's own record
   of what they published is the judgement that matters.
5. **Rate limits under churn** — a large deployment's mutation burst maps
   to how many provider calls after coalescing? Needs numbers from the
   phase-2 e2e stub under load before defaults (debounce, batch size)
   are pinned.
6. **`_synchronicity-owner` name** — as designed the marker is a real
   published TXT (harmless, but visible). An alternative is provider-side
   comment/tag fields where they exist; not every provider has them, so
   the record is the portable choice.
