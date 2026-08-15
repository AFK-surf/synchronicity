# Zone key transparency — requiring a Sigstore Rekor record for the DNSSEC zone key

Status: proposed (design only). Scope: the control plane's zone CSK and the
clients that validate zones signed by it. Device keys are out of scope — they
already ride inside the signed zone this design protects.

## 1. Problem and threat model

DNSSEC answers one question: *is this key authorized for this zone?* The
answer is delegated — the parent zone's DS record names the CSK, the parent's
parent names the parent's key, up to the ICANN root. Every link in that chain
is an institution that can be compromised or compelled: a registrar account
takeover, a hostile parent operator, or a coerced re-delegation can replace
the DS with one naming an attacker's key. From that moment the attacker signs
a perfectly valid zone, and a synchronicity client — which fails closed
against *broken* chains, not *substituted* ones — admits attacker devices
into the cluster with full read/write membership (§3.2 of DESIGN.md: trust
admits a node in full).

The attack is quiet. It can be served to one resolver path, one client, one
network. Nothing in DNSSEC makes it visible to the zone's real operator.

**Proposal**: a client accepts a zone CSK only if that exact key is recorded
in an append-only, publicly monitorable transparency log — Sigstore's Rekor —
and the answer carries an offline-verifiable inclusion proof. This is the
certificate-transparency move applied to the zone-key layer: it does not
prevent a DS substitution, it makes the substituted key *public*. An attacker
must either log their key (naming the apex, where the operator's monitor sees
it) or fail client validation. Covert targeted substitution stops being
covert.

**What this does not protect against** (stated so nobody leans on it):

- Theft of the legitimate CSK. The stolen key already has a valid log record;
  its signatures pass. Response to theft remains the existing runbook
  ceremony (new key, DS replacement at the parent).
- Revocation or freshness. The log is append-only history, not a live
  statement of validity; which key is *currently* authorized remains the DS's
  job. We deliberately attach no client-side checkpoint-freshness rule (§4.4).
- A log that equivocates (split view) toward a client that never gossips.
  Monitors verify consistency proofs over time; witness cosignatures are
  future hardening (§8).

## 2. What gets logged

One Rekor **DSSE** entry per zone-key lifecycle event, signed by the zone key
itself. Self-signing is deliberate: possession of the CSK is exactly the
authority being made transparent, the client already holds the public key
from the validated DNSKEY RRset, and it keeps Fulcio/OIDC out of a key
ceremony that is designed to run offline.

The DSSE payload is an in-toto v1 Statement:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{
    "name": "sync.example.dev.",
    "digest": { "sha256": "<hex sha256 of the DNSKEY rdata>" }
  }],
  "predicateType": "https://synchronicity.dev/zone-key/v1",
  "predicate": {
    "apex": "sync.example.dev.",
    "keyTag": 34918,
    "algorithm": 13,
    "flags": 257,
    "ds": "34918 13 2 <hex sha256 digest>",
    "action": "create",
    "replacesKeyTag": null
  }
}
```

- `subject.digest` binds the entry to exact key bytes (the DNSKEY rdata:
  flags, protocol, algorithm, public key).
- `predicate.apex` binds it to one zone, so a key logged for one apex cannot
  be presented for another, and so monitors can watch a name.
- `action` is `create`, `rollover` (with `replacesKeyTag`), or `retire`.
  `retire` entries are monitor breadcrumbs only — clients never enforce
  retirement from the log (that would be revocation-by-log, see non-goals).
- The DSSE signature is ECDSA P-256/SHA-256 with the zone key — the same
  algorithm 13 material, no second signing identity.

The design targets Rekor v2 (tile-backed) bundles: entry + Merkle inclusion
proof + signed checkpoint. No reliance on v1 Signed Entry Timestamps.

## 3. Proof distribution: in-band, in the zone

The proof travels **inside the zone itself**, as a TXT record at

```
_synchronicity-rekor.<apex>   86400  IN  TXT  ( "<b64url chunk>" "<b64url chunk>" ... )
```

one record per DNSKEY the zone currently publishes (two during a zone-key
rollover window), each carrying a compact binary `RekorProof`:

```
RekorProof v1
  u8       version        = 1
  u16      key_tag          selects the record during rollover
  u8[32]   log_id           SHA-256 of the log's public key; selects the pinned key
  u64      log_index
  u16+[]   dsse_payload     the Statement, byte-exact (hashing requires it)
  u16+[]   dsse_signature   ECDSA P-256 over DSSE PAE(payload)
  u16+[]   checkpoint       signed note: origin, tree size, root hash, log sig
  u8+[32]* inclusion_path   Merkle audit path, leaf to root
```

Roughly 2.3 KB for a log of 10⁸ entries (~27 path hashes); base64url ≈ 3.1 KB
across 13 TXT character-strings — comfortably inside the DoH/TCP message
limit, and clamped to the client's existing 24 h TTL ceiling.

Why in-band rather than an HTTPS side-channel or a live Rekor query:

- It preserves the §3.2 single-transport rule. Membership resolution has
  exactly one road — DoH — and one failure domain. A second endpoint on the
  hot path is a second outage that can strand refreshes.
- The proof needs no trusted channel: it verifies against the pinned log key
  and the validated DNSKEY, not against where it came from. (It is
  DNSSEC-signed anyway, like every RRset in the zone.)
- Clients never talk to Rekor. No availability coupling to Sigstore
  infrastructure, no query-privacy leak beyond what the DoH resolver already
  sees.

The record sits at the **apex** (one zone key, one proof set), not per
membership name — the client learns the apex from the RRSIG signer field it
already validates.

## 4. Data plane: consuming and verifying

### 4.1 Policy surface

`ResolverOptions` (crates/synch-net) grows two knobs, mirrored as daemon
flags/env:

| Knob | Flag / env | Meaning |
|---|---|---|
| `rekor` | `--rekor <require\|off>` / `SYNCH_REKOR` | Whether a validated answer additionally requires a verified log record for the signing zone key. |
| `rekor_key` | `--rekor-key <file>` / `SYNCH_REKOR_KEY` | File of log checkpoint-verification key(s), *replacing* the embedded Sigstore production key — the same "an override is a different universe" semantics as `--dnssec-anchor`. |

Defaults: `require` when validating against the ICANN root; `off` when
`--dnssec-anchor` is in force. A pinned anchor file is already a direct key
pin — there is no delegation chain left for a substitution attack to ride —
so the requirement is opt-in there (self-hosted log + `--rekor-key`).
The embedded default key is snapshotted from Sigstore's TUF root at build
time; a full in-client TUF workflow is explicitly out of v1 (§8).

### 4.2 Refresh pipeline

A membership refresh under `require` performs three validated lookups over
the one DoH transport, then verifies entirely offline:

1. `_synchronicity.<domain> TXT` — as today (hickory in-process validation,
   secure-proof-only, owner-name check).
2. `<apex> DNSKEY` — apex taken from the TXT answer's RRSIG signer field;
   select the DNSKEY whose key tag matches that RRSIG. This yields the exact
   CSK rdata bytes the chain used.
3. `_synchronicity-rekor.<apex> TXT` — the proof record matching that key
   tag.

Then, in process, no network:

- decode `RekorProof`; check `log_id` names a pinned log key;
- verify the DSSE signature over the payload with the DNSKEY public key
  (possession);
- check the Statement binds what was observed: `subject.digest` =
  SHA-256(DNSKEY rdata), `predicate.apex` = RRSIG signer, key tag, flags 257,
  algorithm 13 (binding);
- hash the DSSE entry to its Merkle leaf, walk `inclusion_path` to the
  checkpoint's root hash (inclusion);
- verify the checkpoint signature with the pinned log key (the log vouches).

Steps 2 and 3 are cacheable on their own TTLs (the proof record's TTL is
long; the zone key changes rarely) — the steady-state refresh cost stays one
TXT query.

### 4.3 Failure semantics

Identical posture to a bogus DNSSEC chain: the answer is **discarded
entirely and the previously cached member set is retained until its own
expiry**. Fail closed, degrade toward static-only trust. New `NetError`
variants distinguish: proof record absent, proof malformed, possession/
binding/inclusion/checkpoint failure, unknown log. `synch doctor` explains
each (an absent record on a not-yet-upgraded control plane reads differently
from a binding mismatch, which is an alarm).

### 4.4 No freshness requirement — deliberately

The client checks *inclusion*, never checkpoint age. Transparency requires
that the key be on the public record; it does not require the record be
recent. An age rule would couple every cluster's liveness to Rekor uptime and
to the control plane's republish cadence — violating the standing posture
that a control-plane outage degrades slowly (signatures stay valid for days).
Detection of after-the-fact misbehavior is the monitors' job, where it
belongs.

## 5. Control plane: publishing

### 5.1 Configuration

| Variable | Role | Meaning |
|---|---|---|
| `CP_REKOR_URL` | primary | Rekor write endpoint. Default `https://rekor.sigstore.dev`. |
| `CP_REKOR_KEY` | primary | Optional file pinning a self-hosted log's verification key; absent means the embedded Sigstore production key. |

Replicas need nothing: the proof is public data in the database and rides the
existing operator-owned replication.

### 5.2 Ceremony and publication

`controlplane keygen` is unchanged — it stays runnable on an offline host.
Publication is a separate, explicit, idempotent step:

```
controlplane rekor-publish <apex> <keyfile>
```

which builds the Statement, signs it with the CSK, submits the DSSE entry,
waits for integration, fetches checkpoint + inclusion proof, **verifies the
proof locally with the same rules as the client** (cross-validated against
the Rust verifier in e2e), and stores it in a new table:

```sql
CREATE TABLE rekor_records (
  key_tag         INTEGER NOT NULL,
  apex            TEXT    NOT NULL,
  action          TEXT    NOT NULL,      -- create | rollover | retire
  dsse_payload    BLOB    NOT NULL,
  dsse_signature  BLOB    NOT NULL,
  log_id          BLOB    NOT NULL,
  log_index       INTEGER NOT NULL,
  checkpoint      BLOB    NOT NULL,
  inclusion_path  BLOB    NOT NULL,
  integrated_at   INTEGER NOT NULL,
  verified_at     INTEGER NOT NULL,
  PRIMARY KEY (key_tag, action)
);
```

Re-running searches the log by entry hash first — it refreshes the stored
checkpoint/proof (the tree has grown) without minting duplicate entries.

### 5.3 Serving and enforcement

- `zone/build` emits the `_synchronicity-rekor.<apex>` TXT record(s) from
  `rekor_records` for every DNSKEY the zone publishes; they are signed like
  any RRset and re-signed on every publish.
- `publish_in_tx` gains a gate: if the active CSK (by key tag) has no
  verified `rekor_records` row, publish **refuses** with a new
  `PublishError::NoRekorRecord` — the same stance as the existing §3.2
  build-time checks: the service refuses to publish rather than emit a zone
  clients will reject. (Phase-gated; see §7.)
- The hourly resign job additionally refreshes stored proofs against a fresh
  checkpoint when the stored one is older than 7 days. This keeps the served
  view young for monitors; clients do not require it (§4.4).
- `/healthz` reports `rekor_verified_at` and the log index alongside
  `sig_expires_at`.
- Air-gapped/direct mode: `/api/zone/rekor` serves the proof next to the
  existing `/api/zone/anchor`.

### 5.4 Rollover and retirement (runbook deltas)

Zone-key rollover stays the rare, manual, two-DS dance — with one inserted
step: **log the new key before it signs anything**.

1. `keygen` new key → 2. `rekor-publish` (action `rollover`, names the old
tag) → 3. publish both DNSKEYs + both proof records → 4. add the second DS at
the parent → 5. switch signing → 6. retire: `rekor-publish` action `retire`,
drop old DNSKEY/DS/proof record. The dashboard refuses the DS-switch step
while the new key lacks a verified record. Key *loss* recovery follows the
same order: the new key's record is published during the parent-DS wait,
which the ceremony already budgets as a planned outage.

### 5.5 Monitoring — the half that makes transparency worth it

A required log without a watcher is a formality. The primary runs a daily
monitor job:

- query the log for entries whose predicate names this apex;
- diff against `rekor_records`; any unknown entry → persistent dashboard
  alert + `/healthz` degradation (`unexpected zone-key log entry for <apex>`);
- verify log consistency (the new checkpoint extends the last-seen one),
  storing the latest verified checkpoint.

Because entries name the apex, third parties (or a second, differently-homed
monitor the operator runs) can watch too — that independence is the point.

## 6. Costs, stated plainly

- **Public disclosure**: logging names the apex in a public log. For
  organizations that consider internal zone names sensitive, this is real;
  their path is a self-hosted log + `--rekor-key`/`CP_REKOR_KEY` (private
  universe), accepting that transparency then reaches only as far as who can
  read that log.
- **Ceremony gains a network step**: `rekor-publish` needs an egress to the
  log. It is separable from offline `keygen` and idempotent, but a fully
  air-gapped primary now needs a courier step before first publish.
- **~3 KB more zone, one more query** on first refresh per client; amortized
  to nothing by the long proof TTL.
- **A new pinned key** (the log's) ships in the client, with the same
  update-story obligations as the ICANN anchor.

## 7. Rollout

- **Phase 0 — publish**: control plane logs keys, serves proof records;
  enforcement gate off. Existing clients never query the new name; zero
  impact.
- **Phase 1 — verify, warn**: clients verify when the record is present;
  failures surface in `synch doctor` and logs but do not discard answers.
  Absence is only a note.
- **Phase 2 — require**: `--rekor require` becomes the default on the ICANN
  path; control-plane publish gate turns on. Escape hatch remains per-daemon
  `--rekor off`.

## 8. Alternatives considered and future work

Rejected:

- **Client queries Rekor online** — couples cluster liveness and query
  privacy to Sigstore infrastructure; a second transport on the hot path.
- **HTTPS side-channel for the proof** (control-plane API on the hot path) —
  same objection; kept only for the air-gapped direct mode that already
  bypasses DNS.
- **`hashedrekord` over raw key bytes** — no apex binding, no monitorable
  name, no rollover semantics.
- **Fulcio/OIDC signing identity** — drags an interactive identity provider
  into an offline ceremony; CSK possession is precisely the authority at
  stake.
- **Logging every zone publish** — high write volume, no trust gained: zone
  contents are already signed by the (logged) key.
- **Per-network proof records** — duplicates the proof once per network for a
  zone-scoped fact.

Future work: checkpoint witness cosignatures (split-view resistance beyond
monitors); an in-client TUF root for log-key rotation; logging device-key
membership *sets* (a much chattier, much larger design, only worth it with
witnessing in place); `retire`-entry enforcement as soft revocation signal.

## 9. Testing

- `synch-net::sim` grows a deterministic in-memory tile log with a fixed
  keypair: unit tests exercise every verification failure independently
  (possession, binding, inclusion, checkpoint, unknown log, absent record).
- The control-plane e2e extends its crossval: the Gleam publisher's stored
  proof and served TXT record must verify under the real Rust client
  verifier — same load-bearing pattern as the existing delv + resolver e2e.
- Rollover e2e: both keys, both records, both orders of retirement.
