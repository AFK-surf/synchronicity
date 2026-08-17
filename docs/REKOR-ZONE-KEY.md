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
- Telling a rotation apart from a substitution, automatically. An attacker
  who has taken the registrar holds the DS, so they can assemble a delegation
  chain exactly as valid as the operator's own; the entry they publish is
  indistinguishable, byte for byte, from the entry a routine rollover
  publishes. What transparency provides is narrower than it looks: the key is
  *public*, and the
  operator's own record of which keys they minted is what says whether a
  reported key is theirs. That is a real transfer of work onto the operator,
  and it is stated here rather than buried in §5.5.

## 2. What gets logged

One Rekor entry per zone-key lifecycle event, over a DSSE statement whose
**subject is the apex DNSKEY RRset the entry's chain proves** — the
authorized key set — and whose signer is an ephemeral key minted for the
entry and discarded. The signature is attribution, never authorization
(docs/EXTERNAL-DNS-PROVIDER.md §2.1): authorization is carried entirely by
the embedded DNSSEC chain, which is also what lets a zone whose keys a
managed provider holds be logged at all. Keeping Fulcio/OIDC out keeps the
ceremony runnable offline.

The chain does not begin at the apex. It begins one label below it, at the
**declaration** — `_synchronicity-transparency.<apex> TXT
"v=sync1 transparency"`, signed by the zone that holds it. Everything above
that record is public data: anybody can read a zone's DNSKEY and DS records
out of an open resolver, so an entry proving only those would be something a
stranger could mint about a zone that never heard of them, and a monitor
could not tell an operator's own publication from a bystander's. The
declaration is the part that takes write access to the zone, which is exactly
the authority the entry claims to speak with — and it asks nothing of the
private key, so a provider-held zone publishes one with an ordinary record
write.

**The apex and the signing zone are two different names.** The apex is the
control plane's *name*; the **signing zone** is whatever DNS zone actually
holds and signs its records. Usually they coincide, because the control plane
runs a delegated zone of its own. They need not: a control plane at
`sync.example.com` may live entirely inside the `example.com` zone, with no
delegation and no DNSKEY of its own. Then `example.com` signs everything —
membership answers, the declaration, all of it — and it is `example.com`'s key
set the chain proves. So a chain reads as the declaration at the apex, then
the ladder starting at the **signing zone**, and the rule tying them together
is that the signing zone must contain the apex. `CP_SIGNING_ZONE` names it
when it differs (§5.1); it defaults to the apex.

**The proof records live at the apex**, and the membership answer says where
that apex is (`apex=`, §3). An earlier revision put them at the signing zone,
on the grounds that it was the only name a client could compute from an
answer — true before the `apex=` field existed, and the reason that claim
still appears in older prose. It is wrong now, and it mattered: two control
planes inside one signing zone would have had to share a single record name,
and would have deleted each other's records forever. The one name a client
takes from the answer itself is the **signing zone**, from the RRSIG signer
field, and it is used to *bound* the apex rather than to find anything:
`signing zone ⊇ apex ⊇ membership domain`.

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
`log2025-1.rekor.sigstore.dev` (HTTP 201 Created, `logIndex 68295246`, SAN
`DNS:zone-key-transparency.demo.invalid`), in an 1118-byte certificate
carrying the custom extension this design defines. The whole record —
inclusion, the checkpoint with its witness cosignatures, the certificate
interop, and the claim itself — verifies offline through the client's own
verifier, unmodified. It is checked in as
`crates/synch-net/tests/fixtures/rekor_v3`.

A Statement reaches the log only as the SHA-256 of its DSSE PAE, so nothing
inside it — the predicate type included — can be edited after the fact:
changing any of it means publishing again. That is the standing cost of this
fixture and it is worth naming, because **regenerating it is a permanent,
public, irreversible write**. The certificate's shape should not be changed
casually.

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
  2.25.1555716359    the declaration and the DNSSEC chain above it
```

### 2.2 The custom extension

We hold no IANA Private Enterprise Number, and inventing an arc under
somebody else's is how OID collisions happen. `2.25` is the UUID arc, which
needs no registration. The OID is hardcoded as a named constant on both
sides (`crates/synch-net/src/zonecert.rs`,
`control-plane/src/rekor/cert.gleam`) and pinned by the crossval fixtures.

| OID | DER content bytes | Carries |
|---|---|---|
| `2.25.1555716359` | `69 85 e5 e9 b2 07` | the DNSSEC chain |

**The arc must stay inside 31 bits, and this is not a style preference.**
Rekor is Go, its certificate parser is `crypto/x509`, and Go's
`encoding/asn1` `parseBase128Int` rejects any OID component that overflows
`int32`. A wider arc therefore fails inside `x509.ParseCertificate` *before*
Rekor looks at the extension at all, and the submission comes back
`400 invalid hashedrekord request` naming no field.

A full 128-bit UUID arc such as
`2.25.293397732029928475482264626946701631422` is **unusable**. The
failure was found by live submission and could not have been found any other
way: OpenSSL and Erlang's `public_key` — the encoder that builds these
certificates and the tool that reads them back — both parse a 128-bit arc
happily, so every test on both sides of this repo passed against a
certificate the log would refuse. Bisected against
`log2025-1.rekor.sigstore.dev`, where a rejected submission is not logged and
so costs nothing. The sizes below are the certificates as they were measured;
what the table establishes is about *OID arc width*, so it is kept as run:

| Certificate | Size | Result |
|---|---|---|
| bare (no custom extensions) | 410 B | `201` |
| chain extension only | 771 B | `400 invalid hashedrekord request` |

and then, with the extension *bytes held byte-identical* and only the OID
changed:

| OID | Result |
|---|---|
| `2.25.<128-bit uuid arc>` | `400 invalid hashedrekord request` |
| `1.3.6.1.4.1.99999.1` | `201` |

The extension structure was never the problem. The arc chosen instead is the
first four bytes of the original UUID masked into 31 bits — `0xdcba5907` — so
it stays inside `int32` while remaining a syntactically valid UUID-arc OID.
Both sides assert the `int32` bound in a unit test, so widening it fails
locally instead of in production.

**This OID is provisional.** `2.25.<31-bit>` is a syntactically valid
UUID-arc OID but semantically a UUID with 97 leading zero bits, which carries
a small collision risk against anyone else doing the same trick. The right
long-term fix is an IANA Private Enterprise Number and an OID under
`1.3.6.1.4.1.<PEN>` — recorded as follow-up in §8.3.

**The DNSSEC chain extension.** Non-critical.

```asn1
DnssecChain ::= SEQUENCE OF Link
Link        ::= SEQUENCE { zone IA5String, rrs OCTET STRING }
```

`rrs` is a run of concatenated **uncompressed wire-format** resource records
— `NAME | TYPE | CLASS | TTL | RDLENGTH | RDATA`, names spelled out in full,
because a Merkle leaf has no DNS message for a compression pointer to point
into. Links are ordered **upward from the declaration**, and each link holds
the records *owned by* `zone`:

- link 0 — the declaration at `_synchronicity-transparency.<apex>`: its `TXT`
  RRset and the `RRSIG` the apex made over it. This is the link that makes
  the entry the zone's own statement rather than a transcription of its
  public records (§2).
- link 1 — the apex: its `DNSKEY` RRset + `RRSIG` (self-signed) and its `DS`
  RRset + `RRSIG` (signed by the parent). The RRset *is* the claim: the walk
  proves DS → covered key → RRset, and a reader then checks the key that
  signed its answer for membership in it. A split-key zone's DS never names
  the ZSK that signs answers, and this is how DNSSEC itself authorizes it.
- links 2..n−1 — each ancestor: its `DNSKEY` RRset + `RRSIG` (self-signed)
  and its `DS` RRset + `RRSIG` (signed by *its* parent).
- link n — the root: its `DNSKEY` RRset + `RRSIG`, terminated by the IANA
  trust anchor every reader already holds.

The root link is **always included, and this is not configurable**. A reader
anchors the chain by finding a key it trusts in the **top link's DNSKEY
RRset**; a chain topped by a TLD's DNSKEY contains no such key, so omitting
the root to save its ~1.1 KB would only produce entries every client and
every monitor refuses. `rekor/chain.check_shape` walks the whole shape before
anything is published, so a chain that starts in the wrong place or stops
short fails at the ceremony rather than at every client afterwards.

A real chain to the root measures ~2.2 KB of DER (root DNSKEY 1.1 KB, `com`
DNSKEY+DS 0.6 KB, the apex DNSKEY+DS 0.2 KB, the declaration ~0.3 KB); about
480 B per extra delegation level.

### 2.3 The Statement

The DSSE payload is an in-toto v1 Statement, and it travels *alongside* the
entry in the proof record (§3) because the leaf commits only to its digest:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "sync.example.",
      "digest": { "sha256": "<hex sha256 of one DNSKEY rdata>" } }
  ],
  "predicateType": "https://synchronicity.sh/zone-key/v2",
  "predicate": {
    "apex": "sync.example.",
    "keys": [
      { "keyTag": 34918, "algorithm": 13, "flags": 257,
        "sha256": "<the same hex digest>" }
    ],
    "action": "create"
  }
}
```

- The subject is the **key set** — one entry per key of the apex DNSKEY
  RRset the chain proves, in one canonical order (ascending tag, ties by
  digest), each digest over exact key bytes (the DNSKEY rdata: flags,
  protocol, algorithm, public key). The predicate repeats the set with the
  tag, algorithm and flags an operator wants at a glance, and the two
  lists must agree entry for entry.
- `predicate.apex` binds it to one zone; the certificate's SAN says the same
  thing where a monitor can see it without the Statement.
- `action` is `create`, `rollover`, or `retire`. Clients accept **only**
  `create` and `rollover` as authorization: a retire is a monitor
  breadcrumb and may be published chainless (§5.4), so treating one as
  authorization would accept an entry carrying no proof of delegation at
  all.
- The DSSE signature is ECDSA P-256/SHA-256 by the entry's ephemeral
  signer, named by the certificate.

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

The proof travels **inside the zone itself**, as TXT records under the
**apex**. One proof does not fit in one record, or even at one name, so it is
split into numbered **parts**, one per owner name:

```
_synchronicity-rekor.<apex>     86400 IN TXT "sync1p <group> 1/5 <b64url>"
_synchronicity-rekor-2.<apex>   86400 IN TXT "sync1p <group> 2/5 <b64url>"
...
_synchronicity-rekor-5.<apex>   86400 IN TXT "sync1p <group> 5/5 <b64url>"
```

Part 1 says how many parts there are, and the client fetches the rest by
index.

**Everything hangs off the apex, and the membership record says where that
is.** A signing zone may hold several control planes, so scoping these names
to it would make two of them share one name — and each reconciler would then
see the other's records as strays at a name it manages and delete them, on
every sweep, forever. Scoping to the apex makes that unrepresentable. The
client cannot *derive* the apex, so the membership record it has already
validated carries it:

```
_synchronicity.<network>.<org>.<apex>  TXT  "v=sync1 id=nas nk=<z32> apex=<apex>"
```

That field is a pointer, not an authority. It is checked at both ends — the
apex it names must contain the membership domain, and must sit inside the
zone whose RRSIG signed the answer — and the log entry's own certificate has
to name the same apex. A wrong value points at a name with no usable proof,
which fails closed; a forged one requires control of the signing zone, which
is already game over. `group` is the first four bytes of the SHA-256 of
the encoded proof, in hex: it ties one proof's parts together where two
proofs are in flight (a rollover serves both), and every reader re-derives it
after reassembly, so parts of different proofs cannot be spliced into
something that decodes.

**Why parts, and why across names.** Both limits are the provider's, not
DNS's. Cloudflare refuses a single TXT record past **4096 wire-format bytes**
and the *combined* content of one name and type past **8192** — measured, not
inferred. An ICANN-rooted proof is ~6.1 KB encoded, 8202 base64url
characters, which clears neither. Splitting into ~2 KB chunks answers the
first; spreading those chunks across names answers the second, and keeps
headroom as chains get deeper (~480 B of DER per extra delegation level).
A zone with several control planes shares only the base name, and only
~2 KB of it.

There is no selector field: a record's subject is a key set, so a client
tries each proof it reassembles and membership in a verified set decides:

```
RekorProof v4
  u8       version            = 4
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
`tests/fixtures/rekor_v3`: **3027 bytes, 4036 base64url characters**. That is
a floor rather than a typical figure, for two reasons the fixture makes
explicit — its entry sits near the tree's frontier, so its audit path is 15
hashes rather than the ~26 a deep entry in a 10⁸-entry log carries (+352 B),
and its chain is self-anchored at the apex rather than climbing to the ICANN
root (that one-link chain extension measures 343 B inside the certificate,
against a root-terminated chain's ~1.9 KB, and the difference rides base64'd
inside the body: ~+2.1 KB). A deep, ICANN-rooted proof is therefore about
**5.7 KB, ≈ 7.6 KB base64url** across TXT character-strings: inside the
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
membership name. The client learns the apex from the `apex=` field of the
membership answer it just validated, and holds it between two names it
already knows — it must contain the membership domain, and be contained by
the signing zone the RRSIG names. A wrong value points at a name with no
usable proof, which fails closed.

One more record rides the same mechanism at the apex: the **declaration** at
`_synchronicity-transparency.<apex>`, a fixed 20-byte TXT the zone always
publishes, which is what the bottom link of every chain is a signed copy of
(§2). It is not fetched on the membership path — it reaches a client inside
the proof it is already reading.

What the zone never carries is the pin set itself: *which* log keys a proof
is checked against comes from Sigstore's TUF repository, which every party
reads directly (§10).

## 4. Data plane: consuming and verifying

### 4.1 Policy surface

`ResolverOptions` (crates/synch-net) grows four operator knobs, mirrored as
daemon flags/env — and a fifth field, `rekor_state`, which is not a knob: the
daemon fills it with `<data-dir>/rekor-pins.json` and nothing on the command
line names it.

| Knob | Flag / env | Meaning |
|---|---|---|
| `rekor` | `--rekor <require\|off>` / `SYNCH_REKOR` | Whether a validated answer additionally requires a verified log record for the signing zone key. |
| `rekor_key` | `--rekor-key <file>` / `SYNCH_REKOR_KEY` | File of log checkpoint-verification key(s), *replacing* the embedded Sigstore production keys — the same "an override is a different universe" semantics as `--dnssec-anchor`. It also turns TUF pin refresh off entirely (§10.2): a named key file is static in both directions. |
| `tuf_url` | `--tuf <url>` / `SYNCH_TUF` | The Sigstore TUF repository the pin set follows, default `https://tuf-repo-cdn.sigstore.dev`. A mirror knob, not a trust knob: whatever it names is verified against the TUF root this build embeds (§10.1). |
| `no_tuf` | `--no-tuf` / `SYNCH_NO_TUF` | Never contact that repository; run on the pins already persisted, else the embedded bootstrap (§10.2). |

Default: `require`, everywhere — behind `--dnssec-anchor` as much as on the
ICANN path. A pinned anchor closes the delegation chain to substitution,
but the requirement is about the key being *public*; an internal deployment
that wants neither the public log nor its own says `--rekor off` in so many
words rather than inheriting it from an unrelated flag.

The embedded default keys are the logs Sigstore's `trusted_root.json` names,
and the client ships **that artifact** rather than keys copied out of it
(`tuf::EMBEDDED_TRUSTED_ROOT`, whose SHA-256 is the one the signed
`targets.json` gives for the target). It is the **bootstrap** set, not the
last word: a client that has accepted a chain from Sigstore's TUF repository
runs on the pin set that chain's `trusted_root.json` names instead, and that
state persists in `<data-dir>/rekor-pins.json`. §10 is the whole of that
mechanism —
including why naming `--rekor-key` disables it outright. So the resolution
order is: `--rekor-key` if given, else the last TUF-verified pin set, else the
embedded bootstrap. Only the last of those is a build-time constant.

Shipping the artifact rather than an extract is what lets everything else in
this design stop naming a log. A trusted root is a **directory**: for each
shard, where it is served, its key, and the window it was in service for. The
key set and the endpoint therefore come from one signed file, at every layer
that needs either (§5.1, §5.5, §10.6).

### 4.2 Refresh pipeline

A membership refresh under `require` performs three validated lookups over
the one DoH transport, then verifies entirely offline:

1. `_synchronicity.<domain> TXT` — as today (hickory in-process validation,
   secure-proof-only, owner-name check).
2. `<signing zone> DNSKEY` — the signing zone taken from the TXT answer's
   RRSIG signer field (which is also checked to *contain* the queried name,
   RFC 4035 §5.3.1); select the DNSKEY whose key tag matches that RRSIG.
   This yields the exact zone-key rdata bytes the chain must prove.
3. `_synchronicity-rekor.<apex> TXT` — the proof records, at the apex the
   membership answer named, which must sit between the signing zone and the
   domain being resolved. A proof spanning several records continues at
   `_synchronicity-rekor-<n>.<apex>`, bounded by `MAX_PROOF_PARTS`.

Before step 3, and off the DNS transport entirely, the pin set may be
refreshed from Sigstore's TUF repository — at most once a day, so this is not
part of the steady-state cost. It runs *first* so that a proof from a shard
Sigstore added since this build shipped verifies in the same refresh that
learned about it, and nothing about it can fail the refresh: an unreachable,
stale or invalid repository leaves the current pins standing (§10).

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
- **the DNSSEC chain**: the chain extension is present and validates
  cryptographically — every RRSIG verifies, the links form an unbroken
  delegation ladder to the trust anchor *this resolver holds*, and what the
  walk proves is the apex DNSKEY RRset: the **authorized key set**;
- **the declaration**: the chain's bottom link is
  `_synchronicity-transparency.<apex>`, its TXT RRset reads
  `v=sync1 transparency`, it was not expanded from a wildcard (RFC 4035
  §5.3.2: a short `num_labels` in the RRSIG gives it away), and the apex's
  chain-proven keys signed it with the apex named as the signer (RFC 4035
  §5.3.1). Without this the entry proves only public records, which anyone
  could have collected about a zone that never heard of them;
- **attribution**: `signature.content` verifies under the certificate's own
  SubjectPublicKeyInfo over the entry's digest as a prehash — equivalently,
  ECDSA-SHA256 over the DSSE PAE, which is how ring is asked (ASN.1/DER,
  not the raw `r‖s` of DNSSEC);
- `data.digest` = SHA-256 of the DSSE PAE of the carried Statement;
- **statement and key binding**: the Statement's claimed set is exactly the
  chain-proven set — digest for digest, tag for tag, canonical order — the
  key that signed the answer is a **member** of it, `predicate.apex` = the
  RRSIG signer, and `action` ∈ {`create`, `rollover`};

Steps 2 and 3 carry their own TTLs — the proof records are served with a
24 h one, and the zone key changes rarely — but **the client does not
currently cache them**, so a membership refresh under `require` really does
perform all three lookups every time, plus whatever DNSKEY and DS queries
hickory issues to validate each of them. At a TTL clamped to the 60 s floor
that is tens of round trips a minute, not the one TXT query an earlier
revision of this section claimed. The TTLs make the caching *possible*; a
cache in front of the DoH handle is what would make it real, and it is not
written yet. Stated here rather than left as an aspiration the numbers
elsewhere in this document quietly assume.

### 4.2.1 Why the client verifies a chain it does not need

The client already knows the delegation is real: it validated it natively,
to its own anchor, before reaching any of this. It verifies the carried chain
**on behalf of monitors**, and the reasoning generalizes:

> A client must enforce whatever property makes an entry *discoverable*, or
> an attacker simply omits it.

An entry with no chain, or a broken one, or one covering some other key, is
tier B to a monitor — the bin a monitor records and does **not** report on
(§5.5). If a client accepted such an entry, an attacker would hold a key that
works against victims *and* rings no bell, which is strictly worse than not
logging at all. So the invariant both halves preserve is:

> **Anything a client accepts is classified tier A.** Never tier B.

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

**Only what silences a monitor is enforced.** The rule above — enforce
whatever makes an entry discoverable — is the entire reason a client pays for
a chain walk whose answer it already knows: chain absence silences a monitor,
and a client that
tolerated it would be handing an attacker an inaudible key. Nothing else the
certificate carries has that property, so nothing else is enforced on a
monitor's behalf.

Under an explicit `--dnssec-anchor` the chain is validated to *that* anchor,
not the ICANN root: an override is a different universe in both directions, or
a client anchored elsewhere would demand a chain to a root it does not trust.
A public monitor anchored at ICANN classifies such an entry tier B, which is
the honest answer — nothing outside that private universe can tell whether the
key was authorized.

### 4.3 Failure semantics

Identical posture to a bogus DNSSEC chain: the answer is **discarded
entirely and the previously cached member set is retained until its own
expiry**. Fail closed, degrade toward static-only trust. New `NetError`
variants distinguish: proof record absent, proof malformed, attribution/
binding/inclusion/checkpoint/chain failure, unknown log. `synch doctor` explains
each (an absent record on a not-yet-upgraded control plane reads differently
from a binding mismatch, which is an alarm).

TUF trouble is the deliberate exception: `NetError::Tuf` carries the failure
class for reporting, and never fails a refresh (§10.2).

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
| `CP_REKOR_URL` | primary | Rekor v2 write endpoint (`POST /api/v2/log/entries`). No default: absent, the shard in service is read from the stored `trusted_root.json` (§10.6). |
| `CP_REKOR_KEY` | primary | Optional file pinning a self-hosted log's verification key. Absent, the key is the one the trusted root names beside the endpoint — one key, not the client's whole pinned set, because this side submits to exactly one log and verifies what that log returns. Redirecting `CP_REKOR_URL` to a log the trusted root does not name, without naming the matching key here, is refused up front rather than storing something clients would reject. |
| `CP_DNSSEC_CHAIN_RESOLVER` | primary | DoH endpoint the DNSSEC chain is collected from. Default `https://cloudflare-dns.com/dns-query`. Not a trust decision — every reader verifies the signatures itself — so point it at your own validating resolver if you would rather not tell a third party when you rotate keys. |
| `CP_REKOR_REQUIRE` | primary | `true` arms the publish gate of §5.3. Off by default, because the rollout publishes before it enforces (§7). |
| `CP_TUF_URL` | primary | The Sigstore TUF repository this service follows to find the log shard in service (§10.3). Default `https://tuf-repo-cdn.sigstore.dev`. |
| `CP_SIGNING_ZONE` | primary, external only | The DNS zone the provider actually hosts, when it is not the apex — a control plane at `sync.example.com` served out of `example.com` sets it to `example.com`. Defaults to `CP_BASE_DOMAIN`, and must be a name that *contains* it; boot refuses anything else, and refuses the variable outright in serve mode, where this service is the authoritative nameserver for its own apex and the two are the same by construction. It decides where the proof records go and where a chain's ladder starts (§2). |

Every one of these is read at its use site rather than through boot
configuration, so `rekor-publish` sees the same values a
running primary would.

Replicas need nothing: the proof is public data in the database and rides the
existing operator-owned replication.

### 5.2 Ceremony and publication — the order is inverted

`controlplane keygen` is unchanged — it stays runnable on an offline host.
Publication is a separate, explicit, idempotent step:

```
controlplane rekor-publish <apex> <keyfile>
controlplane rekor-retire  <apex> <keyfile>
```

Whether an entry is a `create` or a `rollover` is derived from the records
already stored for the apex — a set already logged keeps its action and
re-running is a refresh; a new set is a `create` when the zone has no
record yet and a `rollover` after that — never from an operator naming a
file correctly. A third argument is a usage error rather than a silently
ignored one.

**Run it after the DS is live in the parent.** This reverses the original
ceremony, and the reason is §2.2: a `create` or `rollover` entry carries a
DNSSEC chain, a chain starts at the apex's DS, and there is no DS to fetch
before the parent publishes it. So the sequence is: create the key → publish
the DNSKEY in the zone → get the DS into the parent → **then** log. The
existing two-key rollover window covers the gap; the old key keeps signing
until the new one is logged, which is exactly what that window is for.

The command says out loud what publishing now means, because there is no
longer any way to publish quietly:

```
zone key set 34918 rollover: log index 67673584 (entry added),
DNSSEC chain carried (monitors will report this key)
```

That sentence is a warning, not a status line. Every monitor watching the apex
reports this key the first time it sees it (§5.5), and nothing in the command
suppresses that — so tell whoever watches the monitor *before* running it, and
write the key tag down. A retire, which carries no chain, says so instead:
`no DNSSEC chain (retire breadcrumb)`.

The step collects the chain over DoH — the apex DNSKEY RRset it observes
there *is* the claimed set, so the claim and its proof cannot disagree —
builds the Statement, mints an ephemeral signer and its certificate,
computes `digest = SHA-256(PAE)`, signs as **DER ECDSA** and discards the
signer, POSTs a protojson `hashedRekordRequestV002` `CreateEntryRequest` to
`CP_REKOR_URL`, parses the returned `TransparencyLogEntry` (its
`canonicalizedBody`, inclusion proof and signed checkpoint), **verifies that
returned proof locally with the same rules as the client** — the body's
digest against the PAE, attribution against the entry's own certificate,
the name binding, inclusion, and the checkpoint signature — and only then
stores it:

```sql
CREATE TABLE rekor_records (
  keyset_sha256      BLOB    NOT NULL,   -- the claimed set's identity
  apex               TEXT    NOT NULL,
  action             TEXT    NOT NULL,   -- create | rollover | retire
  statement          BLOB    NOT NULL,   -- the in-toto Statement (PAE preimage)
  canonicalized_body BLOB    NOT NULL,   -- the log's hashedrekord body (leaf preimage)
  log_id             BLOB    NOT NULL,
  log_index          INTEGER NOT NULL,
  checkpoint         BLOB    NOT NULL,
  inclusion_path     BLOB    NOT NULL,
  chainless          INTEGER NOT NULL    -- CHECK (chainless = 0 OR action = 'retire')
                     DEFAULT 0,
  integrated_at      INTEGER NOT NULL,
  verified_at        INTEGER NOT NULL,
  PRIMARY KEY (keyset_sha256, action)   -- claimed keys: rekor_record_keys
);
```

It arrives whole, in the control plane's migration **v3** — the same step that
adds `tuf_material` for §10.3. There is no
intermediate shape of this table in any database that exists: the work landed
over several migrations while it was being written, and those were squashed
into one before release. So there is no "before" to migrate from, and nothing
here describes schema arriving in stages.

**A claim is identified by its key set, not by a checksum of it.** The
table is keyed on `(keyset_sha256, action)` — the SHA-256 over the claimed
set's canonical rdata digests — with one `rekor_record_keys` row per
claimed key. An RFC 4034 key tag is a 16-bit checksum over the DNSKEY
rdata, so two distinct keys collide with odds around 1/65536 per rollover;
tags are display data beside the digests, never identity, and never
selection: the client tries each served record and membership decides.

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
every `create` and `rollover` has a chain — a zone's genesis key included,
which is what makes genesis an ordinary case here rather than a special one.
A publish that cannot build a chain fails, with the error an operator actually
needs: *no DS RRset at `<apex>` — is the DS live in the parent yet?*

### 5.3 Serving and enforcement

- `zone/build` emits the `_synchronicity-rekor.<apex>` TXT record(s) from
  `rekor_records` for every DNSKEY the zone publishes; they are signed like
  any RRset and re-signed on every publish.
- `publish_in_tx` gains a gate: if the active CSK (by rdata digest) is
  claimed by no verified, servable `rekor_records` row, publish **refuses**
  with `PublishError::NoRekorRecord` — the same stance as the existing §3.2
  build-time checks: the service refuses to publish rather than emit a zone
  clients will reject. (Phase-gated; see §7.)

**Three things this section does not do.** They are named rather than left
unsaid, because each is the kind of thing a reader may assume is present:

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
  `/healthz` reports the SOA serial, the soonest RRSIG expiry, and — when
  there is stored TUF material — `tuf_root_version` and
  `tuf_timestamp_expires_at` (§10.3). Nothing about `rekor_records` is
  exposed there at all. An operator checks transparency state with
  `rekor-publish` (which prints it) or by reading `rekor_records`.
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
4. `rekor-publish <apex> <newkey>` — action `rollover`, naming the old tag,
   carrying the chain that the new DS makes buildable. The action and the
   replaced tag come from the records already stored for the apex; there is
   no old key file to name. **Expect every monitor
   watching the zone to report the new key** — that is what publishing now
   means, there is nothing to suppress it with, and it is the reason step 0
   of this runbook is telling whoever watches the monitor.
5. Publish the new proof record (the command republishes the zone for you).
6. Switch signing to the new key.
7. Retire: `rekor-retire <apex> <oldkey>`, then drop the old DNSKEY, DS and
   proof record.

**Nothing enforces that ordering but the operator.** In particular the
dashboard does not refuse the signing-switch step while the new key lacks a
verified record: it says nothing about zone keys at all, and manages orgs,
networks and devices. The only automatic enforcement
anywhere on this side is the publish gate of §5.3, which is off by default and
is about the *active* key rather than about the order of a rollover. Steps 1–7
are a runbook, and they are a runbook because a zone-key rollover is rare,
manual and human-supervised on purpose.

Key *loss* recovery follows the same steps and is **not a special case**: an
ordinary `rekor-publish` producing an ordinary reported authorization,
indistinguishable from any other. That is the honest shape — the operator
already knows a recovery happened, and everyone else only learns that a new
key was authorized.

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
runs, deliberately the same code. `--dnssec-anchor` replaces that anchor for a
monitor watching a privately-anchored deployment, with the same
different-universe semantics the client's flag has, and `--rekor-key`
replaces the log keys. Those two flags are the monitor's whole trust surface.

**Its TUF path is the client's** (§10.6). The monitor walks Sigstore's
repository and verifies what it gets with `synch_net::tuf` — the client's
code, against the client's embedded root — persisting the pin state in
`rekor-pins.json` beside its state file, the same file name under the same
rules. That is where **both** the keys and the log's base URL come from, so a
Sigstore shard rotation is no more an upgrade for the monitor than it is for
a client. `--no-tuf` runs on the pins already persisted, and `--log` names an
endpoint outright.
Signature *windows* are not enforced
(§4.2.1), and the monitor has **no clock at all** to enforce them against: an
entry's `integratedTime` sits outside the Merkle commitment and is therefore
attacker-supplied, and the only other signed time near a leaf is in the
checkpoint's witness cosignatures, which nothing here interprets.
An entry whose RRSIGs expired years ago classifies exactly like one signed
this morning — asserted directly, reasons and all. What is lost is forensic
detail ("this chain had already expired when the world last saw this tree"),
not security: neither side ever consulted a clock to reach a verdict.

**Two tiers, lettered A and B.**

| Tier | Condition | Response |
|---|---|---|
| **A** | the chain verifies to the anchor in force **and** covers this key | an **authorization**: report it the first time, then record it |
| **B** | no chain, an invalid chain, or a chain covering a different key | an unauthorized claim: note it, never record it |

Classification is a **pure function of the certificate and the trust
anchors**. `classify()` takes no state at all, so nothing the monitor has seen
before can steer what it concludes about an entry. That separation is the
point: what an entry *is* and
whether it is *news* are different questions, and only the second one consults
memory.

**What tier A costs, honestly.** An attacker who has taken the registrar holds
the DS and can therefore always assemble a chain as valid as the operator's —
and can publish the declaration too, since taking the zone means being able to
write records in it. So a routine rotation and a registrar-compromised
substitution produce *identical* tier A entries, and nothing in the log
distinguishes them. The same is true one level up: a **parent** zone can
nullify its child's delegation, absorb the namespace, declare and log for
*itself*, and every resolver will validate the result. No record inside DNS
can prevent that, because the parent is the authority DNS would consult. What
the design does instead is make the attempt loud — the attacker must publish
a declaration in public DNS and a chain for it in a public append-only log,
both naming a zone on the victim's delegation path — and then point the
monitor at that whole path.
Detection therefore rests with the operator comparing reports against their
own record of what they published, not with the monitor making a judgement it
has no basis for. That is exactly how Certificate Transparency monitoring works
— a CT monitor tells you a certificate exists for your name and leaves "did
you ask for it?" to you — and it is nonetheless a shift of work onto the
operator, who now has to *keep* such a record for it to be worth anything.
`crates/synch-monitor/tests/tiers.rs` keeps the rotation and the substitution
as two separate cases precisely because they are byte-for-byte
indistinguishable to a monitor; collapsing them into one would let that fact
quietly stop being tested.

**Reporting once, not forever.** `KnownKeys` is the monitor's memory: the keys
already reported for an apex. A tier A entry whose
key is not recorded for that apex is a **new authorization** — it goes to
stdout with the apex, key tag, expected DS, SPKI digest and log index, and is
then recorded so the next run stays quiet. A tier A entry for a key already
recorded is silent. The apexes are also the watch list: an apex with an empty
key list says "tell me about this zone, I have accounted for nothing yet",
and an operator seeding a zone whose history predates the monitor lists the
keys they already know about. `--no-save` classifies and reports without
writing anything, so the same news arrives again next run — a dry run rather
than a run that silently consumed the report.

It is **bookkeeping, not a trust store**, and the distinction is load-bearing.
An attacker's substituted key is recorded the moment it is reported, exactly
like the operator's, because the monitor draws no distinction and does not
pretend to. Nothing about being recorded makes a later entry look more
routine; the record says only what has already been *said*, never what is
legitimate.

**The watch follows the delegation path, in both directions.** Naming
`cp.example.com` watches every entry for `cp.example.com`, for everything
*above* it — `example.com`, `com`, the root — and for everything *beneath*
it. The upward half is the one that matters: a takeover by an ancestor
appears in the log as an entry naming the ancestor, so a monitor that matched
only the exact name would be watching the one place an attacker never has to
touch. The downward half catches somebody standing up a control plane inside
the operator's own zone. The cost is noise, and it is the right trade: only
the zone's own operators can say whether `example.com` publishing
synchronicity entries is ordinary or an emergency, and they can only say it
if they are told. A tier A entry for a related-but-unconfigured apex is
therefore news by construction — nothing is recorded for that name yet.

**Tier B is noted, never recorded.** It goes to stderr as a running
commentary — an operator who sees the exit code has to be able to see what was
claimed without re-running with different flags — and it is deliberately kept
out of the state file. Recording it would suppress the real report if that same
key later reappeared with a chain that *does* verify, which is the one thing a
silent bin must never do.

Tier B is quiet because anybody may write anything into a public log — but
that is only safe because **no client would have accepted a tier B entry
either**. The client enforces the chain for exactly this reason (§4.2.1), and
the invariant — anything a client accepts is tier A — is asserted directly in
the test suite over every shape the two sides could disagree about.

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

**Streams and exit codes** are the interface a cron job or an alerting rule
reads. stdout is the report and nothing else — newly authorized keys, one line
each — and stderr is everything else, so a job that mails stdout mails exactly
the events that need a human.

| Code | Meaning |
|---|---|
| `0` | nothing new for a watched apex |
| `10` | unauthorized claims only — tier B naming a watched apex; no client would have accepted one |
| `20` | new authorizations — a key was authorized for a watched apex that this monitor had not recorded: check it against what you published |
| `2` | the run could not finish (transport, checkpoint, state) |

They are **ordered by severity**, so an alerting rule testing `>=` reads
correctly rather than inverting on the outcome that matters most.

## 6. Costs, stated plainly

- **The apex is disclosed, and the log becomes enumerable.** The zone name is
  written *in the clear* inside the Merkle leaf — that is the entire
  mechanism, not a side effect — so anyone who consumes the log can list
  every zone using synchronicity, and watch each one's key history. There is
  no version of this design that is both monitorable by third parties and
  private about which zones exist; those are the same property seen from two
  sides. An organization that cannot accept it has one path: a self-hosted
  log plus `--rekor-key`/`CP_REKOR_KEY`, accepting that transparency then
  reaches only as far as who can read that log.
- **Clients subsidize monitors, in bandwidth.** A proof record runs from
  ~4.4 KB to ~7.6 KB base64url for a deep, ICANN-rooted entry — most of it
  the ~1.9 KB DNSSEC chain and the certificate around it. (The measured
  record in the conformance fixture is 4036 characters, 3027 bytes before
  base64; §3 explains why that is a floor.) The client downloads all of it
  and uses the chain
  only to enforce a property it already knows — see §4.2.1 for why it must
  anyway. The 24 h TTL would amortize it if the client cached; it does not
  yet (§4.2), so today this is paid on every refresh. Either way it is a real
  transfer of cost from the parties who benefit (monitors, and through them
  every operator) to the parties who pay (clients).
- **Clients acquire a CDN dependency, bounded.** Following Sigstore's pin set
  means a daemon reaches `tuf-repo-cdn.sigstore.dev`: a few hundred KB, at
  most once a day, on a path where failure is a non-event by construction
  (§10.2). It buys a Sigstore log rotation that is not a client upgrade. An
  operator who would rather pay the upgrade, or who will not have a daemon
  touch a CDN at all, sets `--no-tuf` and nothing else changes.
- **Ceremony gains a network step, and an ordering constraint**:
  `rekor-publish` needs egress to the log *and* to a DoH resolver, and it can
  only run once the parent DS is live (§5.2). A fully air-gapped primary now
  needs a courier step before first publish.
- **A new pin ships in the client.** The log keys themselves now follow
  Sigstore's TUF repository (§10), so they are not the standing obligation
  they were. What replaces them is the **TUF root role** — one more embedded
  artifact with the same update-story obligations as the ICANN anchor, and
  one that a root-level Sigstore incident still turns into a client upgrade.
  The obligation did not go away; it moved up a level and got rarer.
- **A monitor is now infrastructure.** Reported authorizations are the
  product; nobody running one is done at "it publishes".
- **And the operator owns the judgement, not the monitor.** A
  reported key means *a key was authorized for your zone*, not *something is
  wrong* — the monitor cannot tell a rotation you performed from a
  substitution by whoever took your registrar, and does not try (§5.5). The
  discriminator is your own record of every key you minted: its key tag and
  SPKI digest, written down at the ceremony, kept where an incident can reach
  it. That record is a new operational obligation created by this design, it
  is cheap only if it is kept as a habit, and without it the reports are
  strictly less useful than they look.

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

**`hashedrekord` over raw key bytes** — rejected, and refused outright by the
client with no branch to reach. Such an entry is apex-anonymous: nothing in
its leaf names a zone, so no monitor can index it and the whole of §5.5 would
describe a property the entry does not have.

### 8.2 Still rejected

- **Client queries Rekor online** — couples cluster liveness and query
  privacy to Sigstore infrastructure; a second transport on the hot path.
- **HTTPS side-channel for the proof** (control-plane API on the hot path) —
  same objection. No such endpoint exists: `/api/zone/anchor` is the only
  zone endpoint the control plane serves, and the air-gapped path is a
  database courier rather than a second way to fetch a proof (§5.3).
- **Fulcio/OIDC signing identity** — drags an interactive identity provider
  into an offline ceremony to attest a signer identity that carries no
  authority: the signature is attribution, the chain is the authorization,
  and the signer is an ephemeral key by design. (Note that the certificate
  this design mints is *not* a step toward Fulcio: nothing issues it and
  nothing validates it.)
- **Client-side RRSIG window checks on the carried chain** — there is no
  trustworthy clock in the input (`integratedTime` is outside the Merkle
  commitment) and RRSIGs expire in weeks while entries are read for years
  (§4.2.1).
- **Logging every zone publish** — high write volume, no trust gained: zone
  contents are already signed by the (logged) key.
- **Per-network proof records** — duplicates the proof once per network for a
  zone-scoped fact.
- **Interpreting the checkpoint's witness cosignatures** — a deliberate
  non-goal, not deferred hardening. Sigstore's checkpoints carry cosignature
  lines from independent witnesses, which could be read for two things:
  counting attestations, and taking their timestamps as an attested clock.
  Neither is done. Counting lines is not verification — this design pins no
  witness keys, so a count would be structural and a log free to invent lines
  could satisfy it.
  And the staleness note it fed was forensic detail on a finding that
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

**Register an IANA Private Enterprise Number and move the extension OID
under `1.3.6.1.4.1.<PEN>`.** The current `2.25.<31-bit>` arc is provisional:
a UUID-arc OID whose UUID has 97 leading zero bits, chosen because a
full-width UUID arc is unusable against a Go certificate parser (§2.2). It is
almost certainly unique in practice and it is cheap to change — one
constant on each side and a fixture regeneration — but "almost certainly
unique" is not what an allocation is for. Doing this is a format change and
should ride a proof-version bump, so it is worth batching with any other
breaking change rather than done alone.

Still open: logging device-key membership *sets* (a much chattier, much
larger design); `retire`-entry enforcement as a soft revocation signal; and a
monitor that also fetches the zone's *served* proof records and diffs them
against what the log holds, which would catch a control plane serving a proof
it never logged.

Witness cosignatures are **not** on this list. See §8.2 — they are a
non-goal, not deferred work.

## 9. Testing

Three kinds of test, and the split matters: synthetic material can provoke
any failure but proves nothing about reality, while real material proves
interoperation but cannot be made to misbehave on demand.

**Real bytes, checked in.**

- `crates/synch-net/tests/fixtures/rekor_v3` — a published entry
  (`logIndex 68295246`, HTTP 201). The **whole client verifier** runs over
  it, unmodified: the leaf, the RFC 6962 inclusion walk through a real tree
  of 68.3 M entries, the checkpoint under the *embedded* Sigstore key (found
  among the four signature lines that note carries), the digest↔PAE link,
  attribution, the declaration, the chain, and the key-set binding. Plus the
  interop no local test can establish — that the log accepted an 1118-byte
  certificate carrying the chain extension under the narrowed OID.
  `crates/synch-monitor/tests/real_entry.rs` classifies the same bytes, so
  the fixture covers the monitor half too.

  One limit, stated in its PROVENANCE.txt rather than glossed. The chain is
  **self-anchored** — we own no DNSSEC-signed domain, and minting a
  certificate naming a domain we do not control would be squatting a name in
  a permanent public log, so the apex is its own trust anchor and a monitor
  rooted at ICANN files this entry tier B, correctly; ICANN-rooted validation
  is the `dnssec_chain` fixture's job. Under the anchor it *is* published
  under — the one shipped beside it, which is what a `--dnssec-anchor`
  operator's own monitor would hold — it is tier A, and the monitor tests
  assert both that it is reported the first time and that it is silent once
  recorded.

  It also settles empirically what §2.2's bisect opened: the certificate
  carries the chain extension under the narrowed OID at **1118 bytes** and
  the log accepted it. Size was the open question after the OID fix, and it
  is answered by a `201` rather than by an estimate.

  **Regenerating it costs a permanent public write** (§2.1), so the pinned
  constants that move with it are listed in PROVENANCE.txt: `LOG_INDEX`,
  `KEY_TAG` and the certificate length in `tests/rekor_zone_key.rs`, and the
  log index, key tag and DS prefix in
  `crates/synch-monitor/tests/real_entry.rs`. The publisher is the ignored
  test `publish_a_real_entry`, which mints the entry, submits it, verifies
  what comes back through the full client verifier, and only then rewrites
  the fixture.
- `crates/synch-net/tests/fixtures/dnssec_chain` — a real `cloudflare.com`
  delegation captured from the live DNS, walked offline to the ICANN root:
  RSASHA256 at the root, ECDSAP256SHA256 below it, a two-level DS ladder, and
  real canonical-form RRSIGs. It keeps verifying after its signatures expire,
  which is the archival property. It is a *ladder* fixture and can be nothing
  else — `cloudflare.com` publishes no synchronicity declaration — so it
  exercises the delegation walk beside that walk in `src/chain.rs`, and the
  whole-chain contract is tested over zones the suite can sign for. That it
  is refused as an entry, for want of a declaration, is itself asserted:
  public records anyone can collect must buy an attacker nothing. Regenerate
  with the collector recorded in its PROVENANCE.txt.
- `control-plane/test/fixtures/rekor/crossval` — deterministic DER written by
  the Gleam encoders (`gleam run -m tools/gen_crossval`) and asserted by both
  suites: the chain extension and a whole Gleam-built certificate the Rust
  parser reads. This is
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
Both `rekor::LogKeys` and `rekor/proof.log_id` now say so where somebody
would look, and `tuf::tlogs` derives the id from `publicKey.rawBytes` rather
than reading the `logId.keyId` sitting beside it in the trusted root.

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
  zone: every verification failure is provoked one at a time — a
  misattributed signature, the apex binding, an observed key outside the
  proven set, a statement describing keys its chain never proved, an
  absent chain, a broken chain, a chain for another zone, a
  raw-public-key entry, a retire presented as authorization, inclusion,
  checkpoint, unknown log, absent record — through the unit path *and*
  through the whole resolver.
- An expired-but-valid-at-logging-time chain verifies, on both sides, and the
  test asserts the window really has lapsed so it cannot pass vacuously.
- `synch-monitor` tests the tile arithmetic against an independent reference
  Merkle implementation at ten tree sizes that straddle every tile boundary,
  and the two-tier classification over every entry shape below.

**One composition, not two.** The client and the monitor reach the chain
walk through a single function, `chain::authorize`, which extracts the SAN,
**parses it once**, walks the chain against exactly that name, and returns
the proven key set the chain itself carries. Neither side can supply its
own apex, and neither believes any key the chain did not prove. This is
structural rather than stylistic. Were the two to share `chain::validate` and
compose the call themselves, they could feed it different things — the client
the well-formed apex from DNS, the monitor the raw SAN string — and a
certificate whose SAN is `victim.example..` would then satisfy a
trailing-dot-trimming comparison on the client *and* validate, while the
monitor failed to parse the SAN at all and filed the entry tier B. Every
client accepts, no monitor alerts: precisely the evasion the tiering exists
to prevent. Sharing
a primitive is not sharing a decision.

**The invariant, tested directly.** `crates/synch-monitor/tests/tiers.rs`
generates a genesis key, a routine rotation, a substitution, a chainless
entry, a broken chain, a chain for another key, an expired chain, four
unparseable SANs (a trailing double dot, a triple dot, an upper-case double
dot, and the empty string) and a well-formed SAN naming another zone — **each
in both chain shapes**, self-anchored and root-anchored, so twelve
constructions become twenty-four — and asserts over every one of them, using
the real verifier and the real classifier rather than restatements of either:

> `client_accepts(p)` ⟹ `monitor_tier(p) = A`, and `tier(p) = C` ⟹
> `¬client_accepts(p)`.

The invariant is satisfied vacuously by a client that accepts nothing, so the
same test also pins what acceptance *is*, shape by shape — including that the
substitution is accepted, because it is meant to be reported rather than
refused. **The rotation and the substitution are kept as two cases** although
they are built identically and expected to classify identically: that is the
assertion, and the day the two stop being indistinguishable to a monitor is a
day this test should have to be edited.

Three properties sit beside it, each a separate test: that classification is
unchanged by anything the monitor has recorded (there is no argument left to
pass it, which is the strong form of "state cannot steer a verdict"); that a
key is news until recorded and not afterwards; and that an extension nothing
reads — carried under an OID this build has no name for — changes neither the
tier nor the reasons.

**What the control-plane e2e does and does not do.** It runs the real client
resolver against a real served zone, and its zone-key leg is a *negative*
one: the e2e zone logs nothing, and the test asserts that under the default
policy it therefore fails closed while the plain TXT lookup still works. It
does **not** verify a stored proof under the Rust verifier. It cannot without
either POSTing throwaway keys to the public log on every CI run or standing
up a Rekor v2 server, and neither is worth it. What stands in for it is the
fixtures: `rekor_v3` pins what a real published proof verifies to, and the
crossval and TUF fixtures are read by *both* suites, so the Gleam encoders
and the Rust readers are held against one artifact rather than against each
other's behavior. That is a weaker guarantee than an end-to-end run and it is
worth saying so — nothing in CI ever carries a Gleam-built proof through the
Rust verifier.

**Driving a real submission.** Nothing in the suite ever POSTs. To exercise
the real path against the public log:

```
# No CP_REKOR_URL: the shard in service comes out of the stored
# trusted_root.json, and `rekor-publish` fetches it if nothing is stored.
export CP_DNSSEC_CHAIN_RESOLVER=https://cloudflare-dns.com/dns-query
# ...after the DS is live in the parent:
gleam run -- rekor-publish sync.example /etc/synchronicity/csk.key
# then watch it arrive, from the other side:
echo '{"known":{"keys":{"sync.example":[]}}}' > monitor.json
cargo run -p synch-monitor -- --state monitor.json --from-index <n> --max-entries 512
```

## 10. TUF-driven pin refresh

Sigstore rotates its tiled logs regularly — a new shard, a new key, roughly
yearly — and eventually removes compromised keys from its trust root. A
build-time snapshot alone turns each of those events into a client upgrade.
This section makes the pin set follow Sigstore's TUF repository
automatically: **every party reads that repository itself and verifies what
it read offline against an embedded TUF root.**

The reason this needs no in-band transport is what TUF metadata *is*. Every
byte chains to the TUF root role, so nothing between the repository and the
verifier is trusted with anything: not the CDN serving the files, not the
TLS that carried them, not a caching mirror in front of either. A hostile
transport can deny the fetch; it cannot make it mean anything. The pin set is
a property of Sigstore, not of any zone being resolved, and it is read from
Sigstore.

### 10.1 The walk

Three parties read the repository and all three run the same code path:

| Component | What it reads it for |
|---|---|
| Client (`synch daemon`) | its own transparency-log pin set, before verifying a proof out of a zone |
| `synch-monitor` | the pin set, and the log endpoint to audit |
| Control plane | the log endpoint to *submit* to, and the key to check the returned proof against (§10.6) |

The walk is TUF's consistent-snapshot naming and nothing more: `<n>.root.json`
upward from the version the reader already trusts until the repository has no
more; `timestamp.json`, which names the snapshot version;
`<n>.snapshot.json`, which names the targets version; `<n>.targets.json`,
which names the target's digest; and
`targets/<sha256>.trusted_root.json`. **It checks nothing** — collecting is
one step and verifying is the next (`tuf::fetch_metadata` then `tuf::update`;
`tuf/fetch` then `tuf/verify` on the Gleam side), which is what keeps "a
tampering mirror produces material that fails verification" a structural
property rather than a claim about the fetch.

Everything below the root refreshes on its own. The root itself is a build:
`crates/synch-net` embeds `root.json` version 15 as `EMBEDDED_TUF_ROOT`, the
control plane ships the byte-identical file at
`priv/tuf/sigstore_tuf_root.json`, and the walk starts at whatever version
that file declares — so the floor and the anchor cannot disagree. Raising the
floor is a release note: a client below it has nothing to bridge the gap and
keeps its pins rather than guessing.

`SYNCH_TUF` / `--tuf` (client), `--tuf` (monitor) and `CP_TUF_URL` name a
different repository; `CP_TUF_ROOT` replaces the control plane's anchor for a
deployment running its own Sigstore. These are mirror knobs, not trust knobs —
whatever they name is still checked against the anchor in force.

### 10.2 Client rules

The client embeds two artifacts: the Sigstore **TUF root role**
(`EMBEDDED_TUF_ROOT`, the ultimate pin) and the current **bootstrap trusted
root** (`EMBEDDED_TRUSTED_ROOT` — Sigstore's own `trusted_root.json`, which
names the logs *and* where they are served). Pin resolution order: an
explicit `--rekor-key` file (a static, different universe — TUF refresh
disabled entirely, and nothing is fetched); else the last TUF-verified pin
set persisted in the daemon's data directory; else the embedded bootstrap.

On a `require` refresh, before verifying the proof, the client walks the
repository and attempts an update:

1. walk the `root.json` chain from the persisted (else embedded) root version
   — one version at a time, no gaps, each step signed by the thresholds of
   both the old root and the new. Roots at or below the version already
   trusted are skipped rather than refused: old-but-valid material is allowed
   to travel, it just moves nothing;
2. check the **final** root's expiry, and only that one. Intermediates in a
   chain are expected to be expired — the real Sigstore chain has been, every
   time a rotation ran late — and refusing them would strand a client that
   fell behind (TUF's own client workflow §5.3.11);
3. verify `timestamp → snapshot → targets → trusted_root` — signatures over
   canonical JSON of each file's `signed` object, each file's expiry in the
   future, and each named by the one above it. Versions are matched exactly;
   hashes and lengths are checked when the metadata gives them, which for
   Sigstore means the target but not the `meta` entries, since that
   repository lists `snapshot.json` and `targets.json` by version alone. The
   target's `hashes.sha256` is *not* optional — without it nothing in the
   chain says anything about those bytes;
4. accept only if every version is ≥ the persisted one (monotonic, global
   across domains: one state file, `<data-dir>/rekor-pins.json`, 0600). The
   file is re-read under the lock at each attempt rather than trusted from
   memory, because two resolvers can share one data directory and
   monotonicity is a property of the file;
5. on acceptance, the pin set becomes the tlogs of the new `trusted_root` —
   **replacing** the previous set, never unioning with it, so a key Sigstore
   removes is a key clients drop. A `trusted_root` naming no transparency log
   at all is refused rather than adopted: an empty pin set would silently
   refuse every zone from then on, which is exactly the "worse than not
   having asked" this section forbids.

**At most one walk a day** (`tuf::REFRESH_INTERVAL`). Membership re-resolves
on the zone's TTL, which can be a minute; the pin set moves when Sigstore
opens or closes a shard, which is a yearly event. The last-walked stamp is
seeded from the persisted state's `updated_at`, so a restart does not reset
the clock, and it is stamped *before* the walk, so a repository that is down
costs one attempt a day rather than one per lookup. `--no-tuf` /
`SYNCH_NO_TUF` turns the walk off entirely for a deployment that will not
have its daemon reach a CDN; the cost is §10.4's — a new build the day
Sigstore rotates.

Two rules preserve the availability posture, and they are load-bearing:

- **Expiry gates updates, never operation.** An unreachable repository, or
  stale or invalid material from one, is ignored and the current pins stand.
  To change pins the chain must be valid and unexpired; to keep working,
  nothing is required. A client that cannot reach Sigstore degrades to a
  frozen pin set — what a build-time snapshot always was — not to a failed
  cluster. No TUF error ever reaches a caller of `member_set`.
- **Monotonicity bounds hostile mirrors.** A mirror can serve old-but-valid
  material, but it cannot roll a client's persisted versions back, and a
  freeze holds only until the served timestamp expires. The residual window
  — a fresh install fed an unexpired stale chain — is bounded by the
  timestamp expiry, the standard TUF client guarantee.

Failure classes get their own errors and `synch doctor` copy, but none of
them fails a refresh: TUF trouble is never worse than not having asked.

### 10.3 Control plane: fetch, verify, store

The control plane reads the repository for one thing — §10.6's question of
which log shard it submits to, and which key checks the proof that comes
back. It publishes nothing about TUF into the zone; clients do their own
reading.

- `CP_TUF_URL` (default `https://tuf-repo-cdn.sigstore.dev`) names the
  repository; the primary walks it and stores the files verbatim in a
  `tuf_material` table with their versions and the timestamp expiry. The root
  chain is not stored: every walk starts from the anchor in `priv/tuf`, so a
  copy would be bytes nobody reads.
- **The CP verifies what it stores** (`tuf/verify`), running the same
  workflow the client runs against the same anchor —
  `priv/tuf/sigstore_tuf_root.json`, byte-identical to `EMBEDDED_TUF_ROOT`.
  Root chain endorsed by both the old root and the new, thresholds counted
  over *distinct* keys, signatures checked over canonical JSON, expiries,
  monotonicity against what is stored, and the target's digest. Nothing that
  fails is stored, so whatever was stored before keeps being used.

  This matters here more than anywhere else, because the decision it feeds is
  the one nobody downstream re-checks. A mirror that beat TLS could otherwise
  point a control plane at a log nobody monitors, have its forged proof
  believed, and satisfy `CP_REKOR_REQUIRE` on the way past. Clients would
  still refuse the zone — the forged log matches no pin of theirs — so it was
  a fail-closed denial rather than a silent compromise, but "loud at the
  client" is not "checked at the source".

  What keeps the two implementations honest is the shared fixture
  (`control-plane/test/fixtures/tuf`): one checked-in copy of the real
  Sigstore chain that *both* verifiers must walk to the real pin set.
  Canonical JSON is checked a third way on top of that — against digests from
  an implementation in neither language — because two implementations that
  share an author can be wrong together.

  What verification does **not** do is gate use. Stored material that has
  since expired keeps naming the log: expiry gates updates, never operation
  (§10.2), so it is checked at ingestion, where refusing costs nothing but a
  retry.
- The refresh job (`jobs/tuf_refresh`) fetches when nothing is stored —
  at boot, so a fresh control plane can name a shard within seconds — and
  refetches hourly once the stored timestamp is within 3 days of expiry,
  in both primary modes. It does not republish the zone — no record
  depends on this. There is no on-demand command and none is needed:
  `rekor-publish` itself fetches first when the stored material cannot
  name a log, so the air-gapped ceremony on its egress host leaves the
  couriered database carrying the material, as with everything else.
- `/healthz` reports the stored timestamp expiry and root version, as
  `tuf_timestamp_expires_at` and `tuf_root_version`, so an operator can see a
  service heading for a stale idea of which shard is in service. Absent
  material is reported by their absence, not as unhealthy.

### 10.4 What this changes about §4.1 and §8

Pin refresh is automatic. §4.1 and §8.3 both left it operator-driven while
this section was unwritten, and both now point here instead. The
stance is deliberate: membership itself already refreshes automatically
from DNS, and the ethos line this system draws is that a node never changes
*its own* keys unprompted — accepting third-party material that verifies
against a pinned root is the same texture as DNSSEC validation. The
"new build required" events shrink to TUF-root-level incidents: root
compromise, or a root chain the embedded floor can no longer reach. A
deployment that sets `--no-tuf` opts back into the old situation and should
expect the old cost.

### 10.5 Testing

- **One shared fixture, read by both suites.**
  `control-plane/test/fixtures/tuf` holds the real Sigstore chain verbatim —
  roots 13, 14 and 15, timestamp, snapshot, targets and `trusted_root.json`,
  beside a `meta.txt` recording when it was fetched and what it should verify
  to. Both suites serve it under the consistent-snapshot paths a real
  repository publishes at, so a walk that resolved the wrong version, or read
  a digest out of the wrong field, finds nothing rather than quietly
  assembling something. `crates/synch-net/tests/tuf_pin_refresh.rs` reaches
  across the tree for that directory deliberately (the Gleam suite can only
  read files from its own) and walks the real chain at the moment it was
  fetched, to the two log ids the pin set is supposed to contain. It also
  asserts the negative halves — that the chain *does* expire, and that a
  client below the floor cannot reach it — so neither can pass vacuously.
  Regenerating is a deliberate, network-touching, `#[ignore]`d act with a
  date attached, never something a test run does behind anyone's back.
  Canonical-JSON serialization is exercised against those actual repository
  bytes, which is where TUF implementations historically break.
- **A synthetic TUF repository builder in `sim`** (`SimTuf`, own root keys)
  exercising behaviors the real repo cannot: root rotation across multiple
  versions, a root the old root did not sign, threshold failures, expired
  timestamps, an expired intermediate root that is *accepted* beside an
  expired final root that is not, version rollback, a tampered target, a
  `trusted_root` naming no logs, a `trusted_root` that drops a shard key
  (revocation reaches the pin set), and two clients sharing one state file
  without either rolling the other back.
- **Through the whole resolver**: a client that walks a repository teaching
  it a log its bootstrap set never knew, then verifies a proof from that log
  in the same refresh — the case the whole section exists for — plus the
  control (the same zone with the walk disabled fails with *unknown log*),
  the non-events (a repository serving nonsense, and one serving nothing,
  neither of which may fail a refresh or move a pin), and the once-a-day
  bound. Every repository in that suite is injected, so no test run reaches
  Sigstore.

There is no TUF leg in the control-plane e2e. See §9 for why that e2e is a
negative test and what stands in for the positive one.

### 10.6 The endpoint follows too

Pinning keys through TUF while hardcoding a hostname only moves the rotation
problem. A build that knows `log2025-1…` submits into a closed shard the day
the next one opens, and a monitor pointed at it goes quiet — *silently*,
because an empty log reads exactly like a log with nothing new in it. So the
same signed artifact that supplies the keys supplies the endpoint. Nothing in
this repository names a Sigstore log outside of fixtures and this document.

A `trusted_root.json` entry carries `baseUrl`, `publicKey.rawBytes`, and
`publicKey.validFor`. The **log in service** is the latest-started of those
whose window contains now; retired shards stay listed, stay pinned — a proof
from a closed shard is still a proof — and are never selected. Both
implementations select with that one rule (`tuf/trusted_root.current` and
`tuf::current_tlog`), because the control plane writes to whichever shard it
picks and the client has to verify what comes back.

| Component | Where it gets the log | Override |
|---|---|---|
| Control plane | the stored `trusted_root.json` in `tuf_material`, read at the moment of use — so the 15-minute external-mode key watcher picks up a rotation without a restart. With nothing stored, `rekor-publish` fetches first. | `CP_REKOR_URL` + `CP_REKOR_KEY`, together, for a self-hosted log |
| Client | never talks to a log at all: a proof arrives inside the zone (§1) | — |
| `synch-monitor` | the trusted root in force, persisted in `rekor-pins.json` beside its state file | `--log`, `--rekor-key`, `--no-tuf` |
