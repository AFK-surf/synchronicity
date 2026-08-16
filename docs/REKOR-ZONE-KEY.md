# Zone key transparency — requiring a Sigstore Rekor record for the DNSSEC zone key

Status: implemented — the client, the control plane and the monitor all
ship. Scope: the control plane's zone CSK and the clients that validate zones
signed by it. Device keys are out of scope — they already ride inside the
signed zone this design protects.

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
  A monitor detects the version of this it can see — a log that shows *this
  monitor* two histories over time (§5.5) — but a client that only ever reads
  one zone cannot, and neither can a monitor detect a history shown to
  *somebody else*. Cross-witnessing would have covered that second case and
  this design does not implement it (§8.2).
- Theft of the *previous* key as well as the current one. Succession
  countersignatures are what separate a rotation from a substitution (§2.2);
  an attacker holding both key generations produces a tier A entry, and at
  that point transparency was never going to be the defence.

## 2. What gets logged

One Rekor entry per zone-key lifecycle event, over a DSSE statement signed
by the zone key itself. Self-signing is deliberate: possession of the CSK is
exactly the authority being made transparent, the client already holds the
public key from the validated DNSKEY RRset, and it keeps Fulcio/OIDC out of a
key ceremony that is designed to run offline.

### 2.1 Why the entry looks the way it does

Rekor v2 accepts **exactly one entry type**. `internal/server/service.go`
rejects everything else with "invalid type, must be hashedrekord"; the DSSE
type is deprecated and, even when it existed, stored only a `payloadHash` and
never the payload. So there is no entry type in Rekor v2 that can carry a
statement body, and a DSSE-signed Statement has to be logged as a
`hashedrekord` v0.0.2 over the DSSE **PAE** (Pre-Authentication Encoding):
`data.digest` is `SHA-256(PAE)` and `signature.content` is the ECDSA P-256
signature over that digest (DER, the encoding Rekor indexes — not the raw
`r‖s` of a DNSSEC signature). Because the digest *is* `SHA-256(PAE)`, a
prehash signature over it and an ECDSA-SHA256 signature over the PAE are the
same bytes, which is how the client verifies it.

That leaves the *verifier* field, and it is the whole of this design.

`Verifier` is a protobuf oneof: `public_key` **or** `x509_certificate`. With
a raw public key, a leaf holds a digest, a signature and 91 bytes of
SubjectPublicKeyInfo — and **nothing that names a zone**. Such an entry is
*apex-anonymous*: nobody can monitor a zone for newly published keys, because
no leaf says which zone any key is for. That makes the transparency
requirement hollow. It cannot be patched by publishing an index in DNS
either: the threat model has a compromised upstream DNS provider in it, so
DNS-served state can never be the monitoring channel.

The second arm fixes it, for a reason that is worth stating precisely because
it looks like a loophole: **Rekor performs no certificate validation at
all.** `pkg/verifier/certificate/certificate.go` calls `x509.ParseCertificate`,
takes `cert.PublicKey`, and stops — no chain building, no Fulcio root, no
expiry check, no CA policy. `ToLogEntry` then copies the whole `Signature`
message, certificate DER included, verbatim into the canonicalized body the
Merkle leaf commits to. So a **self-signed certificate carrying the apex as a
`dNSName` SAN writes the zone name, in the clear, inside the log's own leaf**,
where anyone walking the log's tiles can index it.

This is confirmed live, not inferred: such an entry was published to
`log2025-1.rekor.sigstore.dev` (HTTP 201 Created, `logIndex 67766084`, SAN
`DNS:zone-key-transparency.demo.invalid`), carrying both custom extensions
below in a 944-byte certificate. Its leaf was read back out of the static
tiles and the whole record — inclusion, checkpoint, possession, bindings,
chain — verifies offline through the real client verifier. It is checked in
as `crates/synch-net/tests/fixtures/rekor_v3`.

The certificate is therefore a **key envelope, not a trust assertion**.
Nothing anywhere — not Rekor, not the client, not the monitor — verifies its
signature, its issuer or its validity window. Its `notBefore` is the
statement's timestamp and its `notAfter` is a century out, and both are
semantically meaningless: X.509 has a mandatory field there and it is filled
in honestly rather than cleverly.

```
Certificate (self-signed, ECDSA P-256/SHA-256)
  subject = issuer   CN = synchronicity zone key
  SPKI               the zone CSK
  basicConstraints   CA:FALSE            critical
  keyUsage           digitalSignature    critical
  subjectAltName     dNSName = <apex>    non-critical
  2.25.1555716359    the DNSSEC chain
  2.25.1138370866    the succession countersignature
```

### 2.2 The two custom extensions

We hold no IANA Private Enterprise Number, and inventing an arc under
somebody else's is how OID collisions happen. `2.25` is the UUID arc, which
needs no registration. Both OIDs are hardcoded as named constants on both
sides (`crates/synch-net/src/zonecert.rs`,
`control-plane/src/rekor/cert.gleam`) and pinned by the crossval fixtures.

| OID | DER content bytes | Carries |
|---|---|---|
| `2.25.1555716359` | `69 85 e5 e9 b2 07` | the DNSSEC chain |
| `2.25.1138370866` | `69 84 9e e8 d2 32` | the succession countersignature |

**The arcs must stay inside 31 bits, and this is not a style preference.**
Rekor is Go, its certificate parser is `crypto/x509`, and Go's
`encoding/asn1` `parseBase128Int` rejects any OID component that overflows
`int32`. A wider arc therefore fails inside `x509.ParseCertificate` *before*
Rekor looks at the extension at all, and the submission comes back
`400 invalid hashedrekord request` naming no field.

This design originally used full 128-bit UUID arcs
(`2.25.293397732029928475482264626946701631422` and
`2.25.90191032005037091005377665797806520834`) and **they are unusable**. The
failure was found by live submission and could not have been found any other
way: OpenSSL and Erlang's `public_key` — the encoder that builds these
certificates and the tool that reads them back — both parse a 128-bit arc
happily, so every test on both sides of this repo passed against a
certificate the log would refuse. Bisected against
`log2025-1.rekor.sigstore.dev`, where a rejected submission is not logged and
so costs nothing:

| Certificate | Size | Result |
|---|---|---|
| bare (no custom extensions) | 410 B | `201` |
| chain extension only | 771 B | `400 invalid hashedrekord request` |
| succession extension only | 616 B | `400 invalid hashedrekord request` |
| both | 973 B | `400 invalid hashedrekord request` |

and then, with the extension *bytes held byte-identical* and only the OID
changed:

| OID | Result |
|---|---|
| `2.25.<128-bit uuid arc>` | `400 invalid hashedrekord request` |
| `1.3.6.1.4.1.99999.1` | `201` |

The extension structure was never the problem. The arcs in use now are the
first four bytes of the original UUIDs masked into 31 bits — `0xdcba5907` and
`0x43da2932` — so they stay inside `int32` while remaining syntactically
UUID-arc OIDs. Both sides assert the `int32` bound in a unit test, so
widening one fails locally instead of in production.

**These OIDs are provisional.** `2.25.<31-bit>` is a syntactically valid
UUID-arc OID but semantically a UUID with 97 leading zero bits, which carries
a small collision risk against anyone else doing the same trick. The right
long-term fix is an IANA Private Enterprise Number and OIDs under
`1.3.6.1.4.1.<PEN>` — recorded as follow-up in §8.3.

**Extension A — the DNSSEC chain.** Non-critical.

```asn1
DnssecChain ::= SEQUENCE OF Link
Link        ::= SEQUENCE { zone IA5String, rrs OCTET STRING }
```

`rrs` is a run of concatenated **uncompressed wire-format** resource records
— `NAME | TYPE | CLASS | TTL | RDLENGTH | RDATA`, names spelled out in full,
because a Merkle leaf has no DNS message for a compression pointer to point
into. Links are ordered **from the apex upward**, and each link holds the
records *owned by* `zone`:

- link 0 — the apex: its `DS` RRset and the `RRSIG` its parent made over it.
  Deliberately **no DNSKEY**: a reader derives the key it is asking about from
  the certificate's own SubjectPublicKeyInfo, so a copy of the DNSKEY here
  would be a copy of something nobody is willing to believe.
- links 1..n−1 — each ancestor: its `DNSKEY` RRset + `RRSIG` (self-signed) and
  its `DS` RRset + `RRSIG` (signed by *its* parent).
- link n — the root: its `DNSKEY` RRset + `RRSIG`, terminated by the IANA
  trust anchor every reader already holds.

The root link is **always included, and this is not configurable**. It was,
briefly: `CP_DNSSEC_CHAIN_ROOT_DNSKEY=false` omitted it to save ~1.1 KB, on
the reasoning that every monitor holds the IANA anchor already. The reasoning
was wrong. A reader anchors the chain by finding a key it trusts in the
**top link's DNSKEY RRset**, and a chain topped by a TLD's DNSKEY contains no
such key — so the flag's only effect was to emit entries that every client
and every monitor refuses, while `rekor-publish` reported success. A switch
whose sole outcome is unverifiable output is not a size trade-off, so it is
gone. `rekor/chain.check_shape` now walks the ladder before anything is
published, so a chain that stops short fails at the ceremony rather than at
every client afterwards.

A real chain to the root measures ~1.9 KB of DER (root DNSKEY 1.1 KB, `com`
DNSKEY+DS 0.6 KB, the leaf DS 0.2 KB); about 480 B per extra delegation level.

**Extension B — the succession countersignature.** Non-critical.

```asn1
Succession ::= SEQUENCE {
  predecessorKeyTag  INTEGER,          -- RFC 4034 key tag of the old key
  predecessorSpki    OCTET STRING,     -- its DER SubjectPublicKeyInfo
  signature          OCTET STRING }    -- ECDSA P-256/SHA-256, DER
```

The signature is made by the **previous zone key** over the DSSE PAE of a
canonical-JSON payload under payload type
`application/vnd.synchronicity.succession+json`:

```
DSSEv1 45 application/vnd.synchronicity.succession+json <len> {"apex":"<apex>","predecessorKeyTag":<int>,"successorSpkiSha256":"<hex>"}
```

Byte-exact, no whitespace, fixed field order. `apex` is written **without its
root dot** so the two implementations cannot disagree about a character
nobody can see. The successor is named by the SHA-256 of its DER
SubjectPublicKeyInfo rather than by its key tag, so the signature commits to
the exact key bytes and not to a 16-bit checksum of them. The predecessor is
named by its full SPKI as well as its tag, for the same reason.

The extension is **absent** for a zone's genesis key (there is no
predecessor) and for disaster-recovery rotations (the predecessor's private
key is exactly what was lost). Both land in a monitor's tier B, which is
expected — see §5.5.

### 2.3 The Statement

The DSSE payload is an in-toto v1 Statement, and it travels *alongside* the
entry in the proof record (§3) because the leaf commits only to its digest:

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
- `predicate.apex` binds it to one zone; the certificate's SAN says the same
  thing where a monitor can see it without the Statement.
- `action` is `create`, `rollover` (with `replacesKeyTag`), or `retire`.
  Clients accept **only** `create` and `rollover` as authorization: a retire
  is a monitor breadcrumb and may be published chainless (§5.4), so treating
  one as authorization would accept an entry carrying no proof of delegation
  at all.
- The DSSE signature is ECDSA P-256/SHA-256 with the zone key — the same
  algorithm 13 material, no second signing identity.

**Interop scope, stated exactly.** All three halves are the real Sigstore
article. The checkpoint and log-key halves verify a genuine
`log2025-1.rekor.sigstore.dev` checkpoint against the embedded pins. The
Merkle leaf is real: a proof carries the log's own `canonicalizedBody`
verbatim and the leaf is `SHA-256(0x00 ‖ canonicalizedBody)`. The published
entry above is checked in as a conformance fixture and verified offline
through the real client code (§9). The control plane's submission client is a
real `POST /api/v2/log/entries` call (§5.2). A self-hosted,
Rekor-v2-compatible log still works via `--rekor-key`/`CP_REKOR_KEY`.

## 3. Proof distribution: in-band, in the zone

The proof travels **inside the zone itself**, as a TXT record at

```
_synchronicity-rekor.<apex>   86400  IN  TXT  ( "<b64url chunk>" "<b64url chunk>" ... )
```

one record per DNSKEY the zone currently publishes (two during a zone-key
rollover window), each carrying a compact binary `RekorProof`. The layout is
unchanged from v2 — what changed is what the body must contain, and a v2
record is refused as a malformed version and nothing more:

```
RekorProof v3
  u8       version            = 3
  u16      key_tag              selects the record during rollover
  u8[32]   log_id               SHA-256 of the log's DER SPKI; selects the pinned key
  u64      log_index
  u16+[]   statement            the in-toto Statement, byte-exact (DSSE PAE preimage)
  u16+[]   canonicalized_body   the log's hashedrekord body, verbatim (leaf preimage)
  u16+[]   checkpoint           signed note: origin, tree size, root hash, log sig
  u8+[32]* inclusion_path       Merkle audit path, leaf to root
```

The leaf is `SHA-256(0x00 ‖ canonicalized_body)` and an interior node is
`SHA-256(0x01 ‖ left ‖ right)` (RFC 6962 §2.1). The `canonicalized_body` is
carried verbatim precisely because the log computed it — nothing on either
side re-canonicalizes JSON. The Statement rides alongside because the body
commits only to its DSSE PAE *digest*; the client re-derives that digest from
the Statement bytes (`data.digest == SHA-256(PAE)`), reads the entry signature
and verifier out of the body, and refuses any disagreement. Measured, from the real published record in
`tests/fixtures/rekor_v3`: **3050 bytes, 4067 base64url characters**. That is
a floor rather than a typical figure, for two reasons the fixture makes
explicit — its entry sits near the tree's frontier, so its audit path is 8
hashes rather than the ~26 a deep entry in a 10⁸-entry log carries (+576 B),
and its chain is self-anchored at the apex rather than climbing to the ICANN
root (a real root-terminated chain is ~1.9 KB of DER, which is ~2.6 KB more
once base64'd inside the body). A deep, ICANN-rooted proof is therefore about
**5.5 KB, ≈ 7.4 KB base64url** across TXT character-strings: inside the
DoH/TCP message limit, over the 4 KB EDNS0 UDP advertisement (so these
answers go over TCP or DoH, which is the only transport this design has
anyway), and clamped to the client's existing 24 h TTL ceiling. That growth
is a real cost, paid by clients on behalf of monitors — see §6.

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

Default: `require`, everywhere — behind `--dnssec-anchor` as much as on the
ICANN path. A pinned anchor closes the delegation chain to substitution,
but the requirement is about the key being *public*; an internal deployment
that wants neither the public log nor its own says `--rekor off` in so many
words rather than inheriting it from an unrelated flag. The embedded
default keys are the Sigstore production logs, snapshotted from Sigstore's
TUF `trusted_root.json` at build time (the snapshot's target hash is
checked against the signed TUF targets metadata, and rotating it is a new
build); a full in-client TUF workflow is explicitly out of v1 (§8).

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
- hash the log's `canonicalized_body` to its Merkle leaf, walk
  `inclusion_path` to the checkpoint's root hash (inclusion);
- verify the checkpoint signature with the pinned log key (the log vouches);
- parse the `hashedrekord` body; require `kind == "hashedrekord"`,
  `apiVersion == "0.0.2"`, `data.algorithm == "SHA2_256"` and
  `verifier.keyDetails == "PKIX_ECDSA_P256_SHA_256"`;
- require the verifier arm to be `x509Certificate` — a `publicKey` entry is
  refused outright, with no branch to reach — and parse the certificate;
- **apex binding**: the certificate has exactly one `dNSName` SAN and it
  equals the apex being resolved (ASCII case-insensitive, trailing dot
  optional on either side);
- **key binding**: the certificate's DER SubjectPublicKeyInfo equals this
  DNSKEY's;
- **possession**: `signature.content` verifies under that SPKI over the
  entry's digest as a prehash — equivalently, ECDSA-SHA256 over the DSSE PAE,
  which is how ring is asked (ASN.1/DER, not the raw `r‖s` of DNSSEC);
- `data.digest` = SHA-256 of the DSSE PAE of the carried Statement;
- **statement binding**: `subject.digest` = SHA-256(DNSKEY rdata),
  `predicate.apex` = RRSIG signer, key tag, flags 257, algorithm 13, and
  `action` ∈ {`create`, `rollover`};
- **the DNSSEC chain**: the chain extension is present and validates
  cryptographically — every RRSIG verifies, the links form an unbroken
  delegation ladder to the trust anchor *this resolver holds*, and the apex
  DS covers this key.

Steps 2 and 3 are cacheable on their own TTLs (the proof record's TTL is
long; the zone key changes rarely) — the steady-state refresh cost stays one
TXT query.

### 4.2.1 Why the client verifies a chain it does not need

The client already knows the delegation is real: it validated it natively,
to its own anchor, before reaching any of this. It verifies the carried chain
**on behalf of monitors**, and the reasoning generalizes:

> A client must enforce whatever property makes an entry *discoverable*, or
> an attacker simply omits it.

An entry with no chain, or a broken one, is tier C to a monitor — the bin a
monitor records and does **not** alert on (§5.5). If a client accepted such
an entry, an attacker would hold a key that works against victims *and* rings
no bell, which is strictly worse than not logging at all. So the invariant
both halves preserve is:

> **Anything a client accepts is classified at least tier B.** Never tier C.

There is exactly one chain validator in the tree
(`crates/synch-net/src/chain.rs`), run by both sides, so the two rules cannot
drift apart. It is built on hickory's own DNSSEC primitives — the same code
that validates live answers — rather than a second RRSIG verifier.

**RRSIG validity windows are deliberately not checked, on either side.** Two
independent reasons. First, there is no trustworthy clock in the input: a
Rekor leaf commits to `data` and `signature` and nothing else, so
`integratedTime` is attacker-supplied metadata outside the Merkle commitment
and can never be a security input. Second, RRSIGs expire in weeks while log
entries are read for years; a window check would reject legitimate archival
entries and force a republish on every zone re-sign. Nothing is lost: the
chain is bound to the key *by content*, so replaying somebody else's old
chain gains an attacker nothing (it does not cover their key), and the client
independently requires a live DS through native DNSSEC validation anyway.

The **succession countersignature is the mirror image, and is not checked by
the client.** Its absence *alarms* a monitor (tier B) rather than silencing
one, so omitting it makes an attacker louder, not quieter; forging it needs
the predecessor's private key, which is a compromise transparency was never
going to survive; and requiring it would break a zone's genesis key and every
disaster recovery. Chain absence silences, countersignature absence alarms —
which is exactly why one is enforced and the other is not.

Under an explicit `--dnssec-anchor` the chain is validated to *that* anchor,
not the ICANN root: an override is a different universe in both directions, or
a client anchored elsewhere would demand a chain to a root it does not trust.
A public monitor anchored at ICANN classifies such an entry tier C, which is
the honest answer — nothing outside that private universe can tell whether the
key was authorized.

### 4.3 Failure semantics

Identical posture to a bogus DNSSEC chain: the answer is **discarded
entirely and the previously cached member set is retained until its own
expiry**. Fail closed, degrade toward static-only trust. New `NetError`
variants distinguish: proof record absent, proof malformed, possession/
binding/inclusion/checkpoint/chain failure, unknown log. `synch doctor` explains
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
| `CP_REKOR_URL` | primary | Rekor v2 write endpoint (`POST /api/v2/log/entries`). Default `https://log2025-1.rekor.sigstore.dev`. |
| `CP_REKOR_KEY` | primary | Optional file pinning a self-hosted log's verification key; absent means the embedded Sigstore production key. |
| `CP_DNSSEC_CHAIN_RESOLVER` | primary | DoH endpoint the DNSSEC chain is collected from. Default `https://cloudflare-dns.com/dns-query`. Not a trust decision — every reader verifies the signatures itself — so point it at your own validating resolver if you would rather not tell a third party when you rotate keys. |

Replicas need nothing: the proof is public data in the database and rides the
existing operator-owned replication.

### 5.2 Ceremony and publication — the order is inverted

`controlplane keygen` is unchanged — it stays runnable on an offline host.
Publication is a separate, explicit, idempotent step:

```
controlplane rekor-publish <apex> <keyfile> [<previous-keyfile>]
controlplane rekor-retire  <apex> <keyfile>
```

**Run it after the DS is live in the parent.** This reverses the original
ceremony, and the reason is §2.2: a `create` or `rollover` entry carries a
DNSSEC chain, a chain starts at the apex's DS, and there is no DS to fetch
before the parent publishes it. So the sequence is: create the key → publish
the DNSKEY in the zone → get the DS into the parent → **then** log. The
existing two-key rollover window covers the gap; the old key keeps signing
until the new one is logged, which is exactly what that window is for.

Naming `<previous-keyfile>` adds the succession countersignature (§2.2) — the
one thing an attacker holding a substituted DS cannot produce. The command
says out loud when it did not:

```
zone key 34918 rollover: log index 67673584 (entry added), DNSSEC chain carried,
countersigned by key tag 12345 (monitors see tier A)
```

```
zone key 34918 create: log index 67673585 (entry added), DNSSEC chain carried,
NOT countersigned: monitors will alert (tier B)
```

The step builds the Statement, collects the chain over DoH, mints the
certificate, computes `digest = SHA-256(PAE)`, signs with the CSK as **DER
ECDSA**, POSTs a protojson `hashedRekordRequestV002` `CreateEntryRequest` to
`CP_REKOR_URL`, parses the returned `TransparencyLogEntry` (its
`canonicalizedBody`, inclusion proof and signed checkpoint), **verifies that
returned proof locally with the same rules as the client** — the body's
digest against the PAE, possession, the certificate's key and name bindings,
inclusion, and the checkpoint signature — and only then stores it:

```sql
CREATE TABLE rekor_records (
  spki_sha256        BLOB    NOT NULL,   -- the key's identity
  key_tag            INTEGER NOT NULL,   -- how a client selects, indexed
  apex               TEXT    NOT NULL,
  action             TEXT    NOT NULL,   -- create | rollover | retire
  statement          BLOB    NOT NULL,   -- the in-toto Statement (PAE preimage)
  canonicalized_body BLOB    NOT NULL,   -- the log's hashedrekord body (leaf preimage)
  log_id             BLOB    NOT NULL,
  log_index          INTEGER NOT NULL,
  checkpoint         BLOB    NOT NULL,
  inclusion_path     BLOB    NOT NULL,
  chainless          INTEGER NOT NULL,   -- only ever a retire
  integrated_at      INTEGER NOT NULL,
  verified_at        INTEGER NOT NULL,
  PRIMARY KEY (spki_sha256, action)
);
```

**A key is identified by its key, not by a checksum of it.** The primary key
was `(key_tag, action)` until migration v7. An RFC 4034 key tag is a 16-bit
checksum over the DNSKEY rdata, so two distinct keys collide with odds around
1/65536 per rollover — and a collision meant one key's row silently
*replaced* another's, taking its proof out of the served zone with no error
anywhere. Rare and silent is the bad combination: it surfaces as a cluster
that stopped resolving for reasons nobody can reconstruct. The tag remains as
an indexed column because that is what a client selects on — it reads the tag
from the RRSIG it just validated — but selection is not identity. A zone may
now serve two proof records under one tag, and the client tries each until
one verifies.

The one client rule this side cannot re-run is the cryptographic chain walk —
that lives in the Rust verifier, and the e2e crossval is what keeps this side
honest about it.

Re-running is a **refresh**: the entry signature *and the certificate* both
live inside the stored `canonicalized_body`, and both are reused verbatim
(ECDSA is randomized and a freshly collected chain carries fresh RRSIGs, so
rebuilding either would mint a second leaf for one claim). Rekor v2 is
content-addressed by leaf, so re-submitting byte-identical bytes returns the
same `logIndex` with a fresh checkpoint and proof.

**There is no chainless-create escape hatch.** With logging after the DS,
even a zone's genesis key has a chain; what it lacks is a countersignature,
which is fine and which monitors are supposed to notice. A publish that
cannot build a chain fails, with the error an operator actually needs: *no DS
RRset at `<apex>` — is the DS live in the parent yet?*

### 5.3 Serving and enforcement

- `zone/build` emits the `_synchronicity-rekor.<apex>` TXT record(s) from
  `rekor_records` for every DNSKEY the zone publishes; they are signed like
  any RRset and re-signed on every publish.
- `publish_in_tx` gains a gate: if the active CSK (by key tag) has no
  verified `rekor_records` row, publish **refuses** with a new
  `PublishError::NoRekorRecord` — the same stance as the existing §3.2
  build-time checks: the service refuses to publish rather than emit a zone
  clients will reject. (Phase-gated; see §7.)
**Three things this section used to claim, which do not exist.** They are
recorded as gaps rather than deleted quietly, because each was load-bearing
in somebody's mental model:

- *"The hourly resign job refreshes stored proofs older than 7 days."* It does
  not — `jobs/resign.gleam` re-signs RRsets and refetches TUF material, and
  never touches `rekor_records`. **The served checkpoint therefore ages
  indefinitely**: a zone publishes the checkpoint that was current when
  `rekor-publish` last ran, and nothing moves it afterwards. This costs
  clients nothing, because §4.4 is explicit that inclusion is checked and
  freshness is not, and the stored proof stays valid for as long as the tree
  it names is a prefix of the current one — which is forever, in an
  append-only log. It costs *monitors* a little: a stale checkpoint is a
  weaker cross-check than a fresh one when comparing what a zone serves
  against what the log holds. Re-running `rekor-publish` refreshes it, and is
  idempotent by design; automating that on a timer is the obvious fix and is
  not written.
- *"`/healthz` reports `rekor_verified_at` and the log index."* It does not.
  `/healthz` reports the SOA serial and the soonest RRSIG expiry. An operator
  checks transparency state with `rekor-publish` (which prints it) or by
  reading `rekor_records`.
- *"`/api/zone/rekor` serves the proof for air-gapped mode."* It does not;
  `/api/zone/anchor` is the only zone endpoint. The proof is served in the
  zone itself, which is the design's whole point, and the air-gapped path is
  the database courier the rest of §5 already describes.

### 5.4 Rollover and retirement (runbook deltas)

Zone-key rollover stays the rare, manual, two-DS dance — with the logging
step moved **after** the parent DS, for the reason in §5.2:

1. `keygen` the new key.
2. Publish both DNSKEYs in the zone.
3. Add the second DS at the parent, and wait for it to be live.
4. `rekor-publish <apex> <newkey> <oldkey>` — action `rollover`, naming the
   old tag, carrying the chain that the new DS makes buildable and the
   countersignature the old key still exists to make. **Name the old key
   file.** Skipping it produces a tier B alert in every monitor watching the
   zone, and a rotation that alarms is a rotation that trains people to
   ignore alarms.
5. Publish the new proof record (the command republishes the zone for you).
6. Switch signing to the new key.
7. Retire: `rekor-retire <apex> <oldkey>`, then drop the old DNSKEY, DS and
   proof record.

The dashboard refuses the signing-switch step while the new key lacks a
verified record. Key *loss* recovery follows the same order without step 4's
old key file: there is no old private key to countersign with, so the entry
is tier B and a human is meant to look — which is exactly right, because a
key loss is an event.

**Chainless retires.** A retire is published after the DS may already be gone,
so it is allowed to carry no chain, and the row records `chainless`. Nothing
depends on it: retire entries are never served to clients, and a client
refuses `action = retire` as authorization outright (§2.3). To a monitor an
unauthorized "retire" claim is a nuisance, not an escalation — it says
nothing that could admit a key.

### 5.5 Monitoring — the half that makes transparency worth it

A required log without a watcher is a formality. `synch-monitor`
(`crates/synch-monitor`) is the watcher, and it works the only way that is
sound against the threat model: it reads **the whole log**.

**Tile consumption.** Rekor v2 has no "give me entry N" API —
`GET /api/v2/log/entries/<n>` is a 404 and querying by index is a 501. What it
publishes is the C2SP tlog-tiles layout: a signed checkpoint, hash tiles, and
entry bundles holding the canonicalized bodies (`uint16` big-endian length
prefix per entry, 256 to a full bundle; paths are three-digit groups from the
right, `x264/349`, with `.p/<width>` on the frontier). Having no query
endpoint is a *feature*: there is no server-side index to be lied to.

**Every proof is recomputed, never requested.** A tile gives random access to
every complete-subtree hash the log has committed to, so one primitive —
`subtree_hash(lo, hi)` — does all three jobs: the tree matches its checkpoint
when `subtree_hash(0, size)` is its root; the log is **consistent** with the
last run when `subtree_hash(0, old_size)` is the root the monitor persisted
(which is exactly what an RFC 6962 consistency proof establishes, obtained
directly instead of asked for); an entry is **included** when its body hashes
to the leaf the tiles already commit to, confirmed again by an audit path run
through the client's own RFC 6962 walk.

**SAN indexing.** Every leaf that parses as a `hashedrekord` with a
certificate verifier is indexed by the single `dNSName` SAN inside it. For a
watched apex the monitor then derives, **from the certificate's
SubjectPublicKeyInfo alone**, the DNSKEY rdata (flags 257, protocol 3,
algorithm 13), the RFC 4034 key tag, and the DS the registrar would have to
show. No DNS query anywhere: the threat model has a compromised DNS provider
in it, so a monitor that asked DNS what the zone's key is would be asking the
attacker.

**Offline chain validation.** The carried chain is validated against the IANA
root trust anchor with `synch_net::chain` — the same validator the client
runs, deliberately the same code. Signature *windows* are not enforced
(§4.2.1), and the monitor has **no clock at all** to enforce them against: an
entry's `integratedTime` sits outside the Merkle commitment and is therefore
attacker-supplied, so the only signed time anywhere near a leaf was the
checkpoint's witness cosignatures, and this design no longer interprets those.
An entry whose RRSIGs expired years ago classifies exactly like one signed
this morning — asserted directly, reasons and all. What is lost is forensic
detail ("this chain had already expired when the world last saw this tree"),
not security: neither side ever consulted a clock to reach a verdict.

**Three tiers.**

| Tier | Condition | Response |
|---|---|---|
| **A** | valid chain **and** a valid countersignature from a key this monitor already knew | routine rotation; log it |
| **B** | valid chain, no valid countersignature | **alert loudly** |
| **C** | no valid chain | record; do not alert |

Tier B is the compromise signature, and it is loud on purpose. An attacker who
has taken the registrar can produce tier A's first half — they hold the DS, so
they can assemble a real chain naming their key. They cannot produce the
second: countersigning needs the **previous zone key's private half**, which a
DS substitution does not give them. If they had that key, transparency was
never the defence; the operator's problem is theft, and theft has a different
runbook.

Two legitimate events land in tier B and must be documented rather than tuned
away: a zone's **genesis** key has no predecessor, and **disaster recovery**
happens precisely because the predecessor's private key is gone. Tier B means
*a human looks*, not *an attack happened*.

Tier C is silent because anybody may write anything into a public log — but
that is only safe because **no client would have accepted a tier C entry
either**. The client enforces the chain for exactly this reason (§4.2.1), and
the invariant is asserted directly in the test suite over every shape the two
sides could disagree about.

Only **tier A** findings become trusted predecessors in the monitor's state.
Promoting tier B would hand an attacker a foothold: their first substituted
key would become the known predecessor that makes their second look routine.

**Split-view resistance, and its exact limit.** The monitor persists the last
checkpoint it accepted and requires every later tree to be **consistent** with
it: the old root is recomputed from the new tree's tiles, which is precisely
what an RFC 6962 consistency proof asserts, obtained directly instead of asked
for. That catches a log which shows *this monitor* two histories over time,
and it is the strongest thing a single monitor can do alone.

It does **not** catch a log that has shown a *different* monitor a different
history. Detecting that needs the views compared across parties —
cross-witnessing, which this design does not implement (§8.2) and which the
checkpoint's own witness cosignature lines would have been the raw material
for. The parser tolerates those lines because real checkpoints carry them;
nothing reads them.

What is left in their place is cheap and real: entries name the apex in
public, so anyone can run a monitor. An operator who wants independence runs a
second one, differently homed, and compares. That is a procedure rather than a
protocol, and it is stated as one.

Exit codes are the interface an alerting rule reads: `0` nothing new, `10`
tier A only, `20` tier C present, `30` tier B present, `2` the run could not
finish.

## 6. Costs, stated plainly

- **The apex is disclosed, and the log becomes enumerable.** This reverses
  what an earlier draft of this document claimed. Under v3 the zone name is
  written *in the clear* inside the Merkle leaf — that is the entire
  mechanism, not a side effect — so anyone who consumes the log can list
  every zone using synchronicity, and watch each one's key history. There is
  no version of this design that is both monitorable by third parties and
  private about which zones exist; those are the same property seen from two
  sides. An organization that cannot accept it has one path: a self-hosted
  log plus `--rekor-key`/`CP_REKOR_KEY`, accepting that transparency then
  reaches only as far as who can read that log.
- **Clients subsidize monitors, in bandwidth.** A proof record grows from
  ~3.1 KB to ~7.4 KB base64url for a deep, ICANN-rooted entry — most of it
  the ~1.9 KB DNSSEC chain and the certificate around it. (The measured
  record in the conformance fixture is 4067 characters; §3 explains why that
  is a floor.) The client downloads all of it and uses the chain
  only to enforce a property it already knows — see §4.2.1 for why it must
  anyway. Amortized by the 24 h TTL, but it is a real transfer of cost from
  the parties who benefit (monitors, and through them every operator) to the
  parties who pay (clients).
- **Ceremony gains a network step, and an ordering constraint**:
  `rekor-publish` needs egress to the log *and* to a DoH resolver, and it can
  only run once the parent DS is live (§5.2). A fully air-gapped primary now
  needs a courier step before first publish.
- **A new pinned key** (the log's) ships in the client, with the same
  update-story obligations as the ICANN anchor.
- **A monitor is now infrastructure.** Tier B alerts are the product; nobody
  running one is done at "it publishes".

## 7. Rollout

Clients ship with `require` as the default from the first release — the
strictness is the point, and a default that waits is a window in which a
substitution stays quiet. That puts an ordering obligation on operators,
stated plainly: **log the zone key and serve its proof record before the
cluster's clients upgrade.** An upgraded client refreshing against a zone
that serves no record fails closed (cached set retained, degrading toward
static-only trust) until the record appears or the daemon is told
`--rekor off`.

The control-plane side is still phased:

- **Phase 0 — publish**: `rekor-publish` at the ceremony, proof records
  served; the publish gate (`CP_REKOR_REQUIRE`) stays off so a zone whose
  key is not yet logged can still publish while its operator catches up.
- **Phase 1 — gate**: `CP_REKOR_REQUIRE=true` — the primary refuses to
  publish a zone whose active key lacks a verified record, closing the gap
  between "the ceremony forgot" and "clients notice".

## 8. Alternatives considered and future work

### 8.1 How the entry could have carried a name

Three shapes were considered for getting a monitorable apex into a Rekor v2
leaf. Only one exists today.

- **A DSSE entry carrying the Statement.** *Impossible.* Rekor v2's server
  rejects every type but `hashedrekord`, and `DSSELogEntryV002` is deprecated
  and only ever stored a `payloadHash` — so no entry type in Rekor v2 can
  hold a statement body at all. This is empirically established, not inferred
  from documentation.
- **A deterministic apex-derived digest — the "beacon".** Publish a second
  entry whose `data.digest` is a fixed function of the apex (say
  `SHA-256("synchronicity-zone-key:" ‖ apex)`), so a monitor who knows the
  apex can search for that digest without downloading the log. It is smaller
  and it does not disclose the zone list. It is **not adopted**, because it
  is unmonitorable in the direction that matters: a third party cannot
  *enumerate* what is being logged, only confirm a name they already guessed,
  and a searchable index is a server-side query that a compromised log can
  answer selectively. It stays documented as **plan B**: if a future Rekor
  release ever adds certificate policy that rejects self-signed
  end-entity certificates, the beacon is the fallback that needs no new entry
  type.
- **A self-signed certificate with the apex in a `dNSName` SAN.** *Shipped.*
  Rekor validates certificates not at all and copies the DER into the leaf
  verbatim, so the name lands inside the Merkle commitment where it can be
  indexed by anyone reading the log (§2.1). The cost is the disclosure in §6
  and about 4 KB per proof record.

**Resolving a contradiction in an earlier draft.** This section previously
rejected "`hashedrekord` over raw key bytes — no apex binding, no monitorable
name", and then the system shipped exactly that. The rejection was right and
the implementation was wrong: the v2 entry *was* apex-anonymous, and the
monitoring story in §5.5 described a property it did not have. v3 is the fix,
and the raw-key form is now refused outright by the client with no branch to
reach.

### 8.2 Still rejected

- **Client queries Rekor online** — couples cluster liveness and query
  privacy to Sigstore infrastructure; a second transport on the hot path.
- **HTTPS side-channel for the proof** (control-plane API on the hot path) —
  same objection; kept only for the air-gapped direct mode that already
  bypasses DNS.
- **Fulcio/OIDC signing identity** — drags an interactive identity provider
  into an offline ceremony; CSK possession is precisely the authority at
  stake. (Note that the certificate this design mints is *not* a step toward
  Fulcio: nothing issues it and nothing validates it.)
- **Client-side RRSIG window checks on the carried chain** — there is no
  trustworthy clock in the input (`integratedTime` is outside the Merkle
  commitment) and RRSIGs expire in weeks while entries are read for years
  (§4.2.1).
- **Client-side enforcement of the succession countersignature** — would
  break every genesis key and every disaster recovery, and buys nothing:
  omitting it already makes an attacker *louder* (§4.2.1).
- **Logging every zone publish** — high write volume, no trust gained: zone
  contents are already signed by the (logged) key.
- **Per-network proof records** — duplicates the proof once per network for a
  zone-scoped fact.
- **Interpreting the checkpoint's witness cosignatures** — a deliberate
  non-goal, not deferred hardening. Sigstore's checkpoints carry cosignature
  lines from independent witnesses, and an earlier build read them for two
  things: counting attestations (`--min-witnesses`) and taking their
  timestamps as an attested clock for chain-staleness notes. Both are gone.
  Counting lines is not verification — this design pins no witness keys, so
  the count was structural and a log free to invent lines could satisfy it.
  And the staleness note it fed was forensic detail on a tier B finding that
  never changed a verdict, so it bought a whole clock-handling surface for
  something no decision depended on. Doing this *properly* means pinning
  witness keys, verifying their signatures, and defining an N-of-M policy —
  a real feature with a real trust-distribution question behind it, not a
  refinement of what was here. Until someone does that, the honest position
  is that this design has no third-party attestation and says so (§5.5).
  **The checkpoint parser still tolerates the lines**, because a real
  checkpoint carries four signatures and rejecting them would reject every
  checkpoint the production log serves.

### 8.3 Future work

**Register an IANA Private Enterprise Number and move both extension OIDs
under `1.3.6.1.4.1.<PEN>`.** The current `2.25.<31-bit>` arcs are provisional:
they are UUID-arc OIDs whose UUID has 97 leading zero bits, chosen because a
full-width UUID arc is unusable against a Go certificate parser (§2.2). They
are almost certainly unique in practice and they are cheap to change — one
constant on each side and a fixture regeneration — but "almost certainly
unique" is not what an allocation is for. Doing this is a format change and
should ride a proof-version bump, so it is worth batching with any other
breaking change rather than done alone.

An in-client TUF root for log-key rotation (designed in §10, and now
shipped); logging device-key membership *sets* (a much chattier, much larger
design); `retire`-entry enforcement as a soft revocation signal; and a monitor
that also fetches the zone's *served* proof records and diffs them against
what the log holds, which would catch a control plane serving a proof it never
logged.

Witness cosignatures are **not** on this list. See §8.2 — they are a
non-goal, not deferred work.

## 9. Testing

Three kinds of test, and the split matters: synthetic material can provoke
any failure but proves nothing about reality, while real material proves
interoperation but cannot be made to misbehave on demand.

**Real bytes, checked in.**

- `crates/synch-net/tests/fixtures/rekor_v3` — a published entry
  (`logIndex 67766084`, HTTP 201), read back out of the log's own tiles, and
  **total**: the real `rekor::verify` runs to a successful `VerifiedRecord`
  over it. The leaf, the RFC 6962 inclusion walk through a real tree of
  67.7 M entries, the checkpoint under the *embedded* Sigstore key, three
  the body's tags, the
  certificate, its single SAN, possession, the statement-digest link, the
  Statement's byte-exact round trip through this build's renderer, and the
  carried DNSSEC chain. With teeth: the same proof offered for a different
  key, or a different apex, is refused. `crates/synch-monitor/tests/
  real_entry.rs` classifies the same bytes, so one fixture covers both halves
  of the invariant.

  Two limits, stated in its PROVENANCE.txt rather than glossed. The chain is
  **self-anchored** — we own no DNSSEC-signed domain, so the apex is its own
  trust anchor and a monitor rooted at ICANN files this entry tier C,
  correctly; ICANN-rooted validation is the `dnssec_chain` fixture's job. And
  it is a `rollover` whose predecessor private key was not retained, so it
  classifies tier B, with the tier A path exercised by seeding the
  predecessor's SPKI out of the extension itself.

  It also settles empirically what §2.2's bisect opened: the certificate
  carries **both** extensions under the narrowed OIDs at **944 bytes** and the
  log accepted it. Size was the open question after the OID fix, and it is
  now answered by a `201` rather than by an estimate.
- `crates/synch-net/tests/fixtures/dnssec_chain` — a real `cloudflare.com`
  delegation captured from the live DNS, validated offline to the ICANN root:
  RSASHA256 at the root, ECDSAP256SHA256 below it, a two-level DS ladder, and
  real canonical-form RRSIGs. It keeps verifying after its signatures expire,
  which is the archival property. Regenerate with the collector recorded in
  its PROVENANCE.txt.
- `control-plane/test/fixtures/rekor/crossval` — deterministic DER written by
  the Gleam encoders (`gleam run -m tools/gen_crossval`) and asserted by both
  suites: the chain extension, the succession extension, the countersigned
  payload, and a whole Gleam-built certificate the Rust parser reads. This is
  what keeps a hand-rolled DER reader and OTP's ASN.1 encoder from agreeing
  with themselves rather than with each other. It caught a real bug on its
  first run — the Rust OID constants encoded `2.25` as 40×1+25.

**What no fixture can catch.** The `int32` OID constraint in §2.2 was invisible
to every test here, and would have been invisible to any test built the same
way: both encoders agreed, both parsers agreed, the DER was well-formed, and
OpenSSL rendered it correctly. Only the *log* disagreed. The lesson is
specific — a conformance fixture proves this implementation matches itself and
matches captured bytes, and proves nothing about a remote parser's
tolerances — and the mitigation is equally specific: before changing anything
about the certificate's shape, submit one and read the status code. Rejected
submissions are not logged, so bisecting against the real log is free.

The same session turned up a second trap worth naming, because it is a
*plausible* wrong answer rather than an obvious one: Rekor's
`TransparencyLogEntry.logId.keyId` is the C2SP note key id,
`SHA-256(origin ‖ 0x0A ‖ 0x01 ‖ raw32)`, not `SHA-256(DER SPKI)`. Both are 32
bytes, both arrive in the same JSON response within a few fields of each
other, and substituting one for the other yields a proof that matches no pin
and fails as "unknown log" — which reads like a misconfigured client. The
production code was always right (it derives the id from the *pinned* key,
never from anything the server said); only the submission driver was wrong.
Both `rekor::EMBEDDED_LOG_KEYS` and `rekor/proof.log_id` now say so where
somebody would look.

**Both chain shapes, always.** `SimDelegation` builds a synthetic
root → TLD → apex ladder with real DS records and its own anchor, beside the
degenerate self-anchored chain a `--dnssec-anchor` deployment produces. Until
it existed, every sim test ran on the one-link shape — so the suites asserting
the invariant "over every shape the two sides could disagree about" were
exercising a single branch of the validator, and a divergence that only
appears once a chain has a parent to climb to was invisible. A test asserts
both shapes are present and structurally different, so the coverage cannot
quietly collapse back.

**Synthetic material, for the failures reality will not perform.**

- `synch-net::sim` grows a deterministic in-memory tile log and a signed
  zone: every verification failure is provoked one at a time — possession,
  the apex binding, the key binding, statement binding, an absent chain, a
  broken chain, a chain for another key, a raw-public-key entry, a retire
  presented as authorization, inclusion, checkpoint, unknown log, absent
  record — through the unit path *and* through the whole resolver.
- An expired-but-valid-at-logging-time chain verifies, on both sides, and the
  test asserts the window really is in the past so it cannot pass vacuously.
- `synch-monitor` tests the tile arithmetic against an independent reference
  Merkle implementation at ten tree sizes that straddle every tile boundary,
  and the three-tier classification over eight entry shapes.

**One composition, not two.** The client and the monitor reach the chain
walk through a single function, `chain::authorize`, which extracts the SAN,
**parses it once**, derives the key from the certificate's SPKI, and validates
against exactly those. Neither side can supply its own apex. This is
structural rather than stylistic: the two used to share `chain::validate` and
compose the call themselves, and they diverged on what to feed it — the
client passed the well-formed apex from DNS, the monitor the raw SAN string.
A certificate whose SAN was `victim.example..` then satisfied the client's
trailing-dot-trimming comparison *and* validated, while the monitor could not
parse the SAN at all and filed the entry tier C. Every client accepts, no
monitor alerts: precisely the evasion the tiering exists to prevent. Sharing
a primitive is not sharing a decision.

**The invariant, tested directly.** `crates/synch-monitor/tests/tiers.rs`
generates valid, chainless, broken-chain, wrong-key-chain, expired-chain,
countersigned, forged-countersignature, unknown-predecessor, malformed-SAN
and wrong-zone-SAN proofs — **each in both chain shapes**, self-anchored and
root-anchored — and asserts over every one of them, using the real verifier
and the real classifier rather than restatements of either:

> `client_accepts(p)` ⟹ `monitor_tier(p) ∈ {A, B}`, and `tier(p) = C` ⟹
> `¬client_accepts(p)`.

**The control-plane e2e** extends its crossval: the Gleam publisher's stored
proof and served TXT record must verify under the real Rust client verifier —
the same load-bearing pattern as the existing delv + resolver e2e.

**Driving a real submission.** Nothing in the suite ever POSTs. To exercise
the real path against the public log:

```
export CP_REKOR_URL=https://log2025-1.rekor.sigstore.dev
export CP_DNSSEC_CHAIN_RESOLVER=https://cloudflare-dns.com/dns-query
# ...after the DS is live in the parent:
gleam run -- rekor-publish sync.example.dev /etc/synchronicity/csk.key
# then watch it arrive, from the other side:
echo '{"known":{"keys":{"sync.example.dev":[]}}}' > monitor.json
cargo run -p synch-monitor -- --state monitor.json --from-index <n> --max-entries 512
```

## 10. TUF-driven pin refresh, in-band

Sigstore rotates its tiled logs regularly — a new shard, a new key, roughly
yearly — and eventually removes compromised keys from its trust root. A
build-time snapshot alone turns each of those events into a client upgrade.
This section makes the pin set follow Sigstore's TUF repository
automatically, without any new transport and without any new liveness
coupling: **the zone relays Sigstore's TUF metadata, and the client verifies
it offline against an embedded TUF root.**

The principle is the one the proof records already run on: the zone may
carry anything that verifies against something the client pins. TUF metadata
is self-authenticating — every byte chains to the TUF root role — so the
zone never becomes an authority over the pin set; it is a relay, and a
tampering relay produces material that simply fails verification and is
ignored.

### 10.1 What travels: the TUF bundle record

```
_synchronicity-tuf.<apex>   86400  IN  TXT  ( "<b64url chunk>" ... )

TufBundle v1 (binary, base64url, chunked like RekorProof)
  u8       version        = 1
  u8       root_count       root.json versions, ascending, so a client
  u32+[]   root_json[..]    embedded at version N can chain to current
  u32+[]   timestamp_json   all files verbatim, exactly as the TUF
  u32+[]   snapshot_json    repository serves them — signatures cover
  u32+[]   targets_json     these bytes
  u32+[]   trusted_root     the target the chain authenticates
```

Roughly 15–20 KB before base64 — chunky, but it rides a 24 h TTL and the
DoH/TCP message limit comfortably. The root chain starts one past the
oldest root version any supported build embeds, a floor stated per release.

### 10.2 Client rules

The client embeds two artifacts: the Sigstore **TUF root role**
(`root.json`, version N — the ultimate pin) and the current
**bootstrap log-key snapshot** (`EMBEDDED_LOG_KEYS`, unchanged). Pin
resolution order: an explicit `--rekor-key` file (a static, different
universe — TUF refresh disabled entirely); else the last TUF-verified pin
set persisted in the daemon's data directory; else the embedded bootstrap.

On a `require` refresh the client also resolves the TUF record (cached on
its own TTL, one extra query a day) and attempts an update before verifying
the proof:

1. decode the bundle; walk the `root.json` chain from the persisted (else
   embedded) root version — each step signed by the thresholds of both the
   old root and the new;
2. verify `timestamp → snapshot → targets → trusted_root` — signatures over
   canonical JSON of each file's `signed` object, hashes and versions
   matching, every expiry in the future;
3. accept only if every version is ≥ the persisted one (monotonic, global
   across domains: one state file, `<data-dir>/rekor-pins.json`, 0600);
4. on acceptance, the pin set becomes the tlogs of the new `trusted_root` —
   **replacing** the previous set, never unioning with it, so a key
   Sigstore removes is a key clients drop.

Two rules preserve the availability posture, and they are load-bearing:

- **Expiry gates updates, never operation.** An absent, stale, or invalid
  bundle is ignored and the current pins stand. To change pins the chain
  must be valid and unexpired; to keep working, nothing is required. A
  control plane that stops fetching degrades to a frozen pin set — today's
  behavior — not to a failed cluster.
- **Monotonicity bounds hostile relays.** A zone can serve old-but-valid
  material, but it cannot roll a client's persisted versions back, and a
  freeze holds only until the served timestamp expires. The residual window
  — a fresh install fed an unexpired stale chain — is bounded by the
  timestamp expiry, the standard TUF client guarantee.

Failure classes get their own errors and `synch doctor` copy, but none of
them fail a refresh: TUF trouble is never worse than not having the record.

### 10.3 Control plane: fetch, store, serve

- `CP_TUF_URL` (default `https://tuf-repo-cdn.sigstore.dev`) names the
  repository; the primary fetches the metadata files verbatim — walking
  timestamp → snapshot → targets to the consistent-snapshot target names —
  and stores them in a `tuf_material` table with their versions and the
  timestamp expiry.
- The CP is a **relay, not the verifier**: it checks structure, versions and
  expiries (refusing obvious garbage and regressions) but the cryptographic
  gate is the client's, and the e2e keeps the relay honest by running the
  real Rust verifier against what the zone serves. Bad stored material
  costs nothing but zone bytes: clients ignore it and keep their pins.
- `zone/build` emits the bundle record from `tuf_material`; the hourly job
  refetches when the stored timestamp is within 3 days of expiry and, when
  the fetch changed anything, republishes in the same tick — the zone is
  presigned, so stored material a client can see only exists after a
  publish. `controlplane tuf-refresh` does the same on demand (the
  air-gapped ceremony runs it where there is egress and couriers the
  database, as with everything else).
- `/healthz` reports the stored timestamp expiry and root version.

### 10.4 What this changes about §4.1 and §8

Pin refresh becomes automatic where §8 deferred it as operator-driven. The
stance is deliberate: membership itself already refreshes automatically
from DNS, and the ethos line this system draws is that a node never changes
*its own* keys unprompted — accepting third-party material that verifies
against a pinned root is the same texture as DNSSEC validation. The
"new build required" events shrink to TUF-root-level incidents: root
compromise, or a root chain the embedded floor can no longer reach.

### 10.5 Testing

- Conformance fixtures: the real TUF chain, checked in verbatim, verified
  by the Rust client; canonical-JSON serialization exercised against the
  actual repository bytes, where TUF implementations historically break.
- A synthetic TUF repository builder in `sim` (own root keys) exercising
  behaviors the real repo cannot: root rotation across multiple versions,
  threshold failures, expired timestamps, version rollback, a tampered
  target, a trusted_root that drops a shard key (revocation reaches the
  pin set).
- e2e: the zone serves a bundle; the Rust verifier accepts it and a
  mutated copy is refused; the crossval asserts the Gleam encoder and the
  Rust decoder agree on the bundle framing, fixture-pinned like the proof.
