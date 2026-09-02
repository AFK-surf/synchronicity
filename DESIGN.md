# synchronicity — Design Document

**An omnipresent peer-to-peer file store, written in Rust.**

Status: draft v0.1 · 2026-08-12

---

## 1. Goals and non-goals

### Goals

- **Omnipresent**: every trusted node eventually knows the full metadata state of the
  cluster (what exists, who has it), and can fetch any content from any node that holds
  it. Metadata is replicated everywhere; content moves on demand or by policy.
- **Cross-platform**: Linux, macOS, Windows, and BSDs. No platform-specific kernel
  features (no FUSE, no kernel drivers, no admin privileges). The default distribution
  is two static, dependency-free binaries: the CLI/daemon and the S3 gateway (§9.1).
- **Hierarchy-agnostic networking**: every node is a peer. There are no servers,
  coordinators, leaders, or super-nodes. Any node can sync with, relay for, and serve
  any other node. Built on [iroh](https://github.com/n0-computer/iroh).
- **Convergent metadata sync** (`mptsync`): filesystem structure and metadata are
  reconciled with active anti-entropy over Merkle-Patricia Tries, so two nodes can
  detect and repair divergence in `O(diff × log n)` regardless of how long they were
  partitioned.
- **Verifiable content**: content-addressed storage with a hash tree per object, so
  random reads are verifiable without downloading whole files, and any holder of any
  subtree can serve it.
- **One tree, honest versions**: users see a single hierarchy aggregated from every
  node, but the system never invents a merged state. Each path carries the full set
  of per-origin versions; a file written by several nodes has several versions.
  Divergence is first-class and visible, choosing between versions is an explicit,
  deterministic policy, and resolution only ever happens by a node adopting a
  version as its own (§8).

### Non-goals

- POSIX filesystem semantics, mounting, or transparent virtual filesystems (v1).
- Automatic conflict merging (CRDT-style) — deliberately out of scope.
- Untrusted / open-world swarms. Membership is a closed, mutually-trusting set.
- Byzantine fault tolerance beyond authentication and content verification.
- Internet-scale DHTs. Target deployment is personal/team scale: 2–~100 nodes.

---

## 2. System overview

```
┌────────────────────────────── node ───────────────────────────────┐
│                                                                    │
│  ┌──────────┐   ┌──────────────────────────────────────────────┐   │
│  │   CLI    │──▶│                 engine (daemon)              │   │
│  └──────────┘   │                                              │   │
│   local RPC     │  ┌─────────┐ ┌─────────┐ ┌────────────────┐  │   │
│                 │  │ scanner │ │ mptsync │ │  blob fetcher  │  │   │
│                 │  │ watcher │ │ anti-   │ │  (bao verified │  │   │
│                 │  │         │ │ entropy │ │   range reads) │  │   │
│                 │  └────┬────┘ └────┬────┘ └───────┬────────┘  │   │
│                 └───────┼───────────┼──────────────┼───────────┘   │
│                         ▼           ▼              ▼               │
│                 ┌──────────────────────────┐ ┌──────────────┐      │
│                 │   SQLite (all metadata)  │ │  CAS blob    │      │
│                 │ tries · heads · bindings │ │  store (fs)  │      │
│                 │  entries · scanner state │ │              │      │
│                 └──────────────────────────┘ └──────────────┘      │
│                              │                                     │
│                 ┌────────────┴────────────┐                        │
│                 │      iroh endpoint      │                        │
│                 │  ALPN sync/mpt/1        │                        │
│                 │  ALPN sync/blob/1       │                        │
│                 └────────────┬────────────┘                        │
└──────────────────────────────┼─────────────────────────────────────┘
                               ▼
                     other trusted peers
```

The core mental model:

1. Every node owns exactly one **origin trie**: a signed Merkle-Patricia Trie containing
   that node's published records — its file metadata and its blob inventory.
2. Every node **replicates the origin tries of all trusted peers** via anti-entropy
   (`mptsync`). The stored state is the *union* of per-origin tries — origins' tries
   are never merged. What the user is shown is a **unified tree** derived from that
   union: one hierarchy in which each path carries one version per distinct content
   root published for it (§8).
3. File content lives in a local **content-addressed store**, addressed by BLAKE3 hash
   tree roots. Who-has-what is discoverable from the synced tries, so any node can fetch
   any range of any object from any holder, with per-read cryptographic verification.

Because origin tries are **single-writer** (only the origin ever mutates its own trie),
metadata sync is conflict-free by construction: replicating a peer's trie is just
"catch up to their latest signed root". All the hard conflict questions are pushed to
the *interpretation* layer (§8), where they belong.

---

## 3. Identity, trust, and membership

### 3.1 Node identity: origins vs. device keys

Two deliberately separate notions, so that keys can rotate without identity changing:

- **Device key** — an Ed25519 keypair, the same keypair used as the iroh `NodeId`. It
  authenticates *connections* (mutually authenticated QUIC: after the handshake both
  sides have cryptographic proof of the remote `NodeId`) and *signs heads*. Device
  keys are rotatable (§3.4).
- **`OriginId`** — the stable identity that owns a trie and keys all replicated state:
  heads, `f:`/`b:` records, provider views. It never changes for the lifetime of a
  node, across any number of key rotations.

```rust
enum OriginId {
    Key(NodeId),                          // no name: the device key is the identity
    Named { domain: String, id: String }, // dns membership: rendered "<id>@<domain>"
}
```

For DNS-discovered members, the `OriginId` comes from the `id=` field of the TXT
record (§3.2), scoped by the membership domain: `nas@cluster.example.com`. For
statically trusted peers, the OriginId is the device key itself — self-certifying, but
not rotatable. Static trust names nobody: a name comes from a zone, and only from the
zone that issued it (§3.2).

A **binding** is the association `OriginId → device key`, with a source (static or
dns) and a validity window. An origin may have several simultaneously bound device
keys (the rotation window, §3.4). Every trust check and every head verification goes
through the bindings table — nothing in the durable data model references a bare
device key as an identity.

Device secret keys are generated on `synch init` (and on `synch key rotate`) and stored
in the SQLite database (created `0600` inside the data directory). Display/interchange
encoding for keys is z-base-32 (iroh's native encoding).

**Where a node's own identity comes from** is decided by one fact: whether it has a
membership domain. With none it is `Key(K_active)`, self-certifying and not rotatable;
with one it is `Named { domain, id }`, named and rotatable by that zone.

A name comes from a zone and only from a zone; there is no way to name a node by hand.
The domain is the `@domain` half of that name, and it is the zone whose members this
node necessarily resolves.

**Belonging to a zone and being named by one are different questions.** A node resolves
the zone it *belongs to*; whether that zone names it decides only what it is called. A
full member is named and so the two coincide, which is why they were once one setting.
A delegated node (§3.5) belongs to a cluster and is named by no zone in it — so
resolving only the zone in its own name left it resolving nothing, and reaching a member
that publishes under a name meant pinning a static binding by hand: one that never
expires, and so shadows the record it names until an operator removes it, which stops
dropping a member from the zone being how that member is dropped. `synch domain set` is
the same command for both, and a delegate gets `Dns` bindings that lapse on TTL plus
grace like everyone else's. There is no third case: a node belongs to one cluster, so
this is one zone or none, never a set.

**Discovery.** A node with a domain resolves it once at `synch daemon run`, before the
endpoint binds and before any loop starts, and freezes the answer: **identity is
immutable for the lifetime of the process**, which is what lets a changed name be
adopted with no daemon stopped. The answer is the origin the validated record set binds
this node's active device key to under §3.2's malformed-set rules — nothing at all when
that key is absent or ambiguous, and nothing adoptable when its record carries no
`id=`, since taking `Key(nk)` there would trade a rotatable identity for a fixed one on
the strength of a missing field.

Such an answer is adopted whether the node had no name, the same one, or a different
one — the last migrating its local state (below). When there is no such answer:

| Why there is none                                     | Action                                     |
|-------------------------------------------------------|--------------------------------------------|
| the zone no longer names a key it named before         | keep that name, report it, do not poll     |
| the node has no name, or one from a zone since replaced| **unidentified**: poll, old state intact   |
| resolution failed                                      | keep the stored name if any, else poll     |

A resolution failure is not evidence that a record was withdrawn, so the two never
collapse: a node that un-identified itself on an unreachable resolver would lose its
name every time DNS hiccuped. Nor does a withdrawal un-identify one — its bindings
expire at every peer on `dns_trust_grace` and its data goes unavailable per the edge
§3.4 accepts, and destroying local state on top of that buys nothing. An identity from
a zone the node no longer resolves is neither case: nothing currently names it.

**Unidentified**, a node cannot sign heads, publish, or scan, and no peer accepts its
connections — the same absent record leaves them without a binding for its key. It runs
the reduced service §3.4's recovery state establishes: control socket up, endpoint
bound, publishing commands failing with the record to publish filled in (`v=sync1
id=<name> nk=<K> apex=<apex>`). It polls on the negative answer's TTL clamped to
`[30s, 5m]`, re-queries at once on `synch domain refresh`, and stops for good once an
identity is adopted; the membership refresh loop, which is about *other* nodes, runs on
regardless.

**The socket is not a convenience here, it is what keeps the state escapable.** The
command that lifts it is `synch domain set`, and every command but `init` and `daemon
run` is a call over that socket (§9.1) — so a node that waited without one could never
be pointed at a different zone. A data directory whose configured domain is wrong, or
whose zone will never name it, would be unrecoverable with its key, its published
history and its content still in it. So `domain set`, `domain clear`, `domain ls`,
`domain refresh`, `id`, `daemon status` and `daemon stop` are answered while
unidentified, and everything else is refused with the record to publish and the command
that changes zones.

Pointing a node at a zone does not ask that zone to name it, and the cost of the gap
falls at the next start rather than at the edit — so `domain set` answers with the
record that zone must carry for this key, and with `domain clear` as the way back. An
operator who walks away after setting a domain has already been told why the daemon is
waiting when they return.

**Adopting a name** — a first one, or one that displaced it — happens on the next start,
in one transaction, before the endpoint binds: the self binding moves, both head slots
and the old origin's `entries` and `blob_providers` views are dropped, read selections
pinned to it (§7.2) are rewritten, and `publish_floor` is cleared. Blobs stay and the
next scan republishes them; `head_history` is untouched, so heads signed under the old
name survive as the fork evidence §4.4 makes of them. `synch domain set` and `synch
domain clear` reach the same migration by another route, since what fills the domain
slot is what names the node — the running daemon is untouched by the edit, a move waits
for the new zone to name it, and clearing waits for nothing.

A relabel costs a full republish: the new origin starts at `seq = 1`, peers keep the old
one's trie until its bindings expire, and `synch doctor` says so. Every adoption is
recorded in `identity_history` (§10), the audit trail §3.4 wants behind a change of
signing identity — here the deliberateness is the zone operator's, one edit upstream.

### 3.2 Trust sources

A remote node is **trusted** iff at least one of the following holds:

1. **Static trust** — its public key was explicitly added:

   ```
   synch trust add <node-id> [--note "zeynep's laptop"]
   ```

   Static trust is unilateral per node and never expires (until removed). For two nodes
   to sync, *each* must trust the other; there is no transitive trust. The key is the
   identity: static trust binds `OriginId::Key`, never a name — a hand-made name would
   be a standing, non-expiring override of the zone, so dropping a record would stop
   being how a member is dropped.

2. **DNSSEC-based discovery** — the node's key appears in a TXT record of the
   membership domain:

   ```
   synch domain set cluster.example.com
   ```

   The domain a node resolves is the one that names it (§3.1), so every dns binding
   it holds is for an origin in its own zone.

   The resolver queries `_synchronicity.<domain> TXT` and accepts records of the form:

   ```
   _synchronicity.cluster.example.com.  300  IN  TXT  "v=sync1 id=nas    nk=<z-base32 device key> apex=example.com"
   _synchronicity.cluster.example.com.  300  IN  TXT  "v=sync1 id=laptop nk=<z-base32 device key> apex=example.com"
   _synchronicity.cluster.example.com.  300  IN  TXT  "v=sync1 id=laptop nk=<z-base32 device key> apex=example.com"  ; rotation window
   ```

   Each record binds one device key to the origin named by `id=`. The `id` field is
   the member's stable identifier — an opaque label matching `[a-z0-9-]{1,63}`,
   case-insensitive, unique per member within the domain — and is what the data model
   keys the node by (`OriginId::Named`). The `nk` field is the *current* device key.
   The `apex` field names the control plane whose zone-key transparency records
   cover this answer, and the records of one answer must agree about it: it is
   where the client looks for the proof set, held between the zone the RRSIG
   names and the domain being resolved (docs/REKOR-ZONE-KEY.md §3). Under the
   default `--rekor require` an answer whose records name no apex has no proof to
   find and is refused, so a zone published without it resolves for nobody.
   **Multiple records with the same `id` and different `nk` are valid** and mean all
   listed device keys are simultaneously bound — this is the key-rotation window
   (§3.4). A record without an `id=` field is accepted for backward simplicity and
   binds `OriginId::Key(nk)` (non-rotatable, as if statically trusted).

   Malformed-set rules: if the same `nk` appears under two different `id=`s (or once
   with and once without `id=`), the key is ambiguous and **every binding it would
   create is dropped** — so that member is not trusted at all and stops appearing in
   `trust ls`. Nothing else in the system explains that, which is why `synch doctor`
   reports the ambiguity by key and domain, on the scheduled refresh path as much as
   on an explicit `synch domain refresh`. Two different
   machines accidentally sharing one `id=` is indistinguishable from a rotation
   window at the resolver; it manifests as *sustained* same-seq equivocation, which
   `synch doctor` diagnoses with the likely cause ("duplicate id assignment?").
   Finally, a key statically trusted as `OriginId::Key` while publishing heads under
   a Named origin would sync nothing, silently — doctor detects the mismatch and
   names the zone to resolve (`synch domain set`) to pick that origin up by name.

   The lookup MUST be DNSSEC-validated end to end, and it travels one
   transport: DNS-over-HTTP(S), RFC 8484, against `--doh <url>` (`SYNCH_DOH`,
   default `https://1.1.1.1/dns-query`). There is no UDP path and no system
   stub resolver in the loop — hickory is used purely as the in-process
   DNSSEC validation engine over that transport (we never trust an upstream
   resolver's AD bit). If the chain of trust does not validate — missing
   signatures, expired RRSIGs, broken chain — the response is **discarded
   entirely** and the previously cached member set is retained until its own
   expiry. Fail closed.

   A plaintext `http://` endpoint is accepted for internal deployments, and
   it is not the hole it looks like: the transport carries nothing trusted,
   so http concedes query privacy and a denial lever — exactly what classic
   UDP resolution always conceded — and nothing about integrity.
   `--dnssec-anchor <file>` (`SYNCH_DNSSEC_ANCHOR`) *replaces* the ICANN
   root trust anchor with a file of DNSKEY records, for internal deployments
   and tests that run their own signed root; with it set, nothing signed
   under the real root validates — an override is a different universe, not
   an addition. Both are daemon flags: every refresh, scheduled or requested
   over the control socket, resolves the same way.

   Records are re-resolved on the TTL (clamped to `[60s, 24h]`). A binding that
   disappears from DNS expires after `dns_trust_grace` to absorb propagation
   glitches. Adding a machine to the cluster is: `synch init --domain <d>`, publish
   one TXT record — the machine takes its own name from that same record (§3.1).

   **Expiry is dated, and the date is checked.** Every binding check is
   `now < expires_at`, so the instant is an input to an authorization decision and
   the host clock is not authenticated. A reading no build of this software could
   produce — a dead RTC at the epoch, a container with no time source — dates
   nothing: DNS bindings are all treated as expired, membership is not extended,
   and `synch doctor` and `synch daemon status` say so in as many words. Static
   trust consults no clock and keeps working, which is the escape hatch. The
   highest trustworthy reading is persisted, and every check is floored by it, so a
   clock stepped *backwards* cannot hand back trust that already lapsed; a large
   forward step expires bindings early, which is the fail-closed direction and is
   undone by the next successful refresh.

Both sources feed a single `bindings` table (§10). Enforcement is at connection accept
time and on every incoming message: connections from device keys with no live binding
are closed immediately after the QUIC handshake; trie heads whose signing key is not
bound to the claimed origin are ignored even if relayed by a trusted peer.

Trust admits a node to the cluster in full: it may read all metadata and all content,
and its published trie is replicated by everyone. (Finer-grained ACLs are future work,
§13.)

### 3.3 Peer discovery (addresses, not membership)

Membership (who is allowed) is separate from address discovery (where they are).
For dialing, we use iroh's standard discovery stack — pkarr/DNS node discovery and
relay servers — so nodes behind NATs work out of the box. The defaults are n0's
public infrastructure (the `iroh.link` discovery service and n0's relays); the
`--discovery <pkarr-url>` and `--relay <url>` flags on `synch daemon run` point
discovery and relays at a self-hosted iroh-dns-server / iroh-relay instead, so
nothing in synchronicity requires n0's infrastructure. None of this stack is
trusted: a broken or hostile lookup or relay can strand a dial but never redirect
one — the QUIC handshake authenticates the device key, and membership is enforced
at accept. Optionally, the TXT record may carry a hint: `relay=https://...` or
`addr=ip:port`, which is fed into iroh as dialing hints. Each field means one
thing and is read that way: a value that is neither an `ip:port` nor an
`http(s)://host` URL is dropped rather than retried as the other shape. And a hint
is applied only for a key that holds a live binding, because a hint is dialing data
about a member and a key the set does not bind is not one. To reach a named origin,
a node dials whichever device key(s) are currently bound to it.

`--dht` on `synch daemon run` adds Mainline DHT discovery alongside the
pkarr/DNS one, off by default. It is the same signed pkarr record, stored on the
BitTorrent DHT instead of handed to a server: pkarr relays and DNS resolvers are
caches in front of that DHT, and `--dht` talks to it directly. This is additive,
not exclusive — a dial resolves through every configured lookup at once and takes
whichever answers first — so a node keeps its address reachable when the
discovery server is down, blocked, or simply never deployed, and a deployment can
run with no discovery server at all. It costs a UDP socket and an hourly
republish. `--dht-bootstrap <host:port>` replaces mainline's public bootstrap
nodes, which is what makes a swarm private: point every node at your own
bootstrap nodes and they form a DHT that reaches none of mainline's and is
reached by none of them. It only makes the DHT private, though — the pkarr/DNS
lookup is a separate leg and still goes wherever it is pointed, so a deployment
that must touch no outside infrastructure pairs `--dht-bootstrap` with
`--discovery`, which is the leg that moves the pkarr side in house.
Because the DHT is a public, world-readable index, only
relay URLs are published to it by default; `--dht-publish-addrs` adds direct IP
addresses, worth it for a node already answering on a public address, where it
buys peers a dial without the relay round trip. Trust is unchanged: a DHT record
is discovery, so it can strand a dial but never redirect one. `--offline`
refuses all three flags, as it does `--relay` and `--discovery`.

### 3.4 Key rotation

Because every piece of durable state — tries, heads, entries, provider views, content
— is keyed by `OriginId`, rotating a device key changes *nothing* about replicated
data. It only changes which key may sign for the origin and which `NodeId` peers dial.
No trie rewrite, no re-hashing, no history loss.

**Planned rotation** (origin `nas@cluster.example.com`, `K_old → K_new`):

1. `synch key rotate` generates `K_new` locally, keeps `K_old` active, and prints the
   TXT record to publish. The node continues operating (transport + signing) on
   `K_old`.
2. The operator publishes the second record: `v=sync1 id=nas nk=<K_new>`, alongside
   the existing one. Both keys are now bound; peers pick this up on their next
   validated refresh.
3. Once the new record has had time to propagate — one TTL is the safe bound, and
   `synch key ls` asks each reachable peer (`GetBindings`, §5.1) which of our keys
   it currently holds bound and reports the tally per key — the
   operator runs `synch key activate <K_new>`. That re-signs the current root as a
   new head (`seq+1`, `signed_by = K_new`) and brings up a second iroh endpoint as
   `K_new`. **Both endpoints stay live** until the old binding has expired everywhere
   (worst case one DNS TTL, clamp max 24 h), so peers whose DNS refresh lags are never
   locked out mid-window; an inbound connection attempt from an unknown key
   additionally triggers an immediate DNS re-resolution.
4. The operator removes the `K_old` record and runs `synch key retire <K_old>`, which
   drops the second endpoint and deletes the old secret. Peers log every rebinding,
   and `synch doctor` lists recent binding changes per origin. Validated DNS is the
   *sole* authority on which keys hold an origin — the protocol makes no attempt to
   distinguish a legitimate rotation from a domain-level rebinding; see §12 for what
   that implies and §13 for the deferred hardening.

**Rotation is operator-driven throughout: a node never polls its own domain and never
switches signing keys on its own.** The judgement the switch-over needs — "have my
peers picked up the new binding yet?" — depends on resolvers the node cannot observe,
so a node auto-switching on its own view of DNS would strand exactly the peers whose
refresh lags furthest. Making each step an explicit command also keeps a change of
signing identity a deliberate act with an audit trail, rather than background
behavior that fires while nobody is watching. The cost is that a rotation spans two
operator commands separated by a propagation wait; that is the intended trade.

**Key-loss recovery**: the operator replaces the TXT record with a fresh `K_new` —
from the cluster's point of view this is just a rotation without the overlap window.
The recovering node (fresh DB, which rediscovers the same `id=` name from the zone,
§3.1) must assume the peers it can
currently reach may not hold its true latest head, so recovery is a distinct,
explicitly driven state rather than something a node does on startup:

1. **Detection.** A node that holds no head of its own but finds peers advertising
   heads for its own origin is *in recovery*. It refuses to publish — a node that
   silently started over at `seq = 1` would have every peer correctly reject it, and
   the reason would be invisible. `synch doctor` reports the state, the highest seq
   seen so far, and **which peer claimed it** — detection rests on peers'
   unauthenticated summaries (deliberately: the true heads are signed by the lost
   key and cannot validate), so within the trust stance (§12) any member could
   assert a huge seq and hold a fresh node in recovery; the attribution is what
   lets an operator judge the claim. Publishing commands fail pointing at
   `synch recover`.
2. **Observation.** The heads peers hold for this origin are signed by the lost key,
   which is no longer bound, so they cannot be accepted as heads (§4.4) — but their
   *existence* is what matters. Peers report `(origin, seq, root, complete)` for every
   origin they track in the `Hello` summary (§5.1), and that summary is what recovery
   reads. No new wire message, and no need to trust an unbound signature to learn that
   a higher seq once existed.
3. **Resumption.** `synch recover` collects those summaries from every reachable peer
   for at least `recovery_quiesce` (default 1 h, `--wait` to override), then sets the
   node's publishing floor to `max_observed_seq + seq_gap` (default 1 000). The gap
   makes a same-seq collision with history held only by an unreachable peer
   improbable rather than merely unlikely. Publishing resumes from the floor.

Recovery is operator-driven for the same reason rotation is: the node cannot see the
peers it cannot reach, so "how far had I got?" is a judgement made on partial
information. An operator knows whether the NAS that holds the newest history is
merely asleep or genuinely gone; the node does not.

Be precise about what recovery does **not** guarantee. Seq monotonicity protects each
peer against heads older than what *that peer* has already verified — it is not a
global no-fork property. If a peer holding newer pre-loss heads was partitioned
throughout recovery, a fork exists: when that peer returns, its retired-key head is
kept as **fork evidence** (heads verified while their signer was bound remain
provable history, §4.4), `synch doctor` surfaces it on every node ("origin nas has
unreconciled pre-recovery history at seq 100"), and the affected entries' content
remains fetchable for manual salvage via `synch adopt path`. The fork is resolved by the
origin's operator, never silently by the protocol.

**During the window**, both keys could in principle sign competing heads; the
deterministic `(seq, root)` ordering (§4.4) still converges everyone, and competing
same-seq heads are flagged as equivocation exactly as in the single-key case. A
well-behaved node signs with exactly one key at any moment.

Rotation runs through the zone or not at all. A key-identified origin (§3.1) has no
name to carry across a key change, and no peer holds a hand-made binding that could
be pointed at a new key, so replacing its key makes it a different origin — which is
what `OriginId::Key` means.

One availability edge is accepted deliberately: a peer that first learns of an origin
*after* a rotation, while the origin is offline and has not yet re-signed its head
under the new key, cannot validate that head — its signer has no live binding, and
heads from unbound signers must stay untrusted, since any member could fabricate
them for an absent origin. That origin's data is simply unavailable to the new peer
until the origin returns and republishes. The alternative — trusting unbound
signatures — would trade a temporary availability gap for a forgery hole, and is
rejected.

### 3.5 Delegated space-restricted trust

A member whose key is already rooted — static or DNSSEC (§3.2) — may admit
one other device key to the cluster, confined to a named list of spaces. It does so
by publishing a record into its own trie:

```rust
// key: d:<32-byte device key>   — the delegated key IS the trie key
struct Delegation {
    v: u8,
    spaces: Vec<String>,   // closed list, ≤ 32, distinct, never a wildcard
    not_after: i64,        // unix nanos
    note: Option<String>,
}
```

There is **no credential**. Nothing is handed to the subject and nothing is
presented by it: the record is signed by the head that carries it, replicated by
mptsync, and materialized into the `bindings` table with `source = 'delegated'`
exactly as an `f:` record is materialized into `entries` — derived state, written in
the same transaction as the head flip. A delegate is admitted because every member
has read the record, so the accept path (§3.2) is unchanged and asks the same
question it always did.

Keying by the delegated key settles three things at once: re-issuing is an update
rather than a second record, revoking is a deletion of the obvious key, and the
accept-time question is a direct lookup. The issuer is implicit — the record sits in
the issuer's trie — so there is no issuer field to check, and none to forge.

**One level, and it is structural.** A delegation is honored only from an origin
holding a live *rooted* binding, and a delegation only ever produces a `delegated`
binding. So a delegate's own `d:` records are read by nobody: depth 2 fails on a
lookup in the reader's own binding table, not on a depth counter a publisher could
set, and not in an order-dependent way. A delegate additionally cannot publish `d:`
at all, so the rule is refused where it is broken rather than silently ignored.

**Scope is a projection, both ways.** The list bounds what the delegate may publish
under its own origin *and* what it may read of everyone else's — and outside it,
data is not refused but never sent (§5.5). A space is a cluster-wide namespace, so
delegating `photos` grants every member's `photos`: it has to, because the unified
tree (§8) merges across origins by `(space, path)`, and a per-origin grant would
describe a view no reader could render.

**A delegation binds `OriginId::Key` only.** If it could name a `Named` origin, any
member could delegate `nas@cluster.example.com` and squat a label the DNS zone
controls — a hijack with no DNSSEC compromise behind it. The trie key *is* the device
key, so there is no field in which to name anything else. Delegates therefore do not
rotate; they are re-issued, which is the right lifecycle for something that expires
in days.

**Revocation is deletion.** `synch delegate rm <key>` removes the trie key and
publishes. §4.2's account of why tombstones are not what makes deletion propagate
applies unchanged: tries are single-writer and replicated whole, so a deleted key
vanishes from the new root and the diff surfaces it, even to peers partitioned for
years. There is no revocation state to retain and nothing to expire. Propagation is
epidemic, so a partitioned member honors a withdrawn delegation until it syncs;
`not_after` is the hard bound on that, and it is the only job expiry has here.

**Renaming an issuer revokes what it issued.** A node takes its own name from its
membership zone (§3.1), and adopting a new one retires the origin the old name
named — its heads, its derived views and its own binding all go. The delegations
it issued go with them: a `d:` record lives only in the trie of the origin that
published it, so the record is gone from what the node publishes, and the row it
materialized into is deleted rather than left pointing at an origin nobody holds.
Vouching is something an *origin* does, and the origin that vouched has ceased to
exist; re-vouching under the new name is a deliberate act, not something a rename
should perform on an operator's behalf. `synch domain set` and `synch domain
clear` say how many delegations the pending rename will revoke, because the rename
lands at the next start and that is while there is still a choice.

**Derived trust cannot outlive its source.** A delegated binding is live only while
the issuing origin's own rooted binding is live, evaluated on read rather than
stamped on write — so `synch trust rm nas` and `nas`'s TXT record lapsing each cut
off `nas`'s delegates in the same instant they cut off `nas`. Without this, removal
has a hole exactly where it matters most, and the hole is invisible: the delegate
keeps syncing and nothing says why. The clock rules are inherited unchanged — every
delegated binding is gated by `clock_is_trusted`, so a node that cannot date a
decision honors no delegation, and static trust remains the escape hatch that
consults no clock.

Two rooted origins may delegate the same key with different lists; each vouches
independently and the effective scope is the union, which is how the binding table
already treats a key held by both `static` and `dns`. `issuer` is therefore part of
the row's identity (§10).

Two consequences of a delegated binding being a *derived* row rather than an
independent one. A head from an origin holding no live binding is not promoted at all
— collapsing "no binding" into "unrestricted" would make revoking a delegation
*promote* the head its scope had been refusing, which is the opposite of what revoking
is for. And the expiry sweep that deletes lapsed DNS bindings leaves these alone:
materialization only ever applies deltas, so a row deleted out of band never returns —
the `d:` leaf it came from has not changed — and a forward clock skew would silently
drop trust the issuer never withdrew. They stop counting the instant they date-lapse,
and go when the record that made them does.

This is the first transitive trust in the system, and §3.2's "there is no transitive
trust" is spent knowingly. What it buys is bounded: a rooted member already reads
every space and can hand over its own device secret invisibly and forever, so
delegation does not open a path that was closed — it replaces an unbounded, unlogged,
unexpiring one with a path that is scoped, dated, bound to a named key, and published
in the issuer's own trie where `synch delegate ls` on any node can read it.

---

## 4. Data model

### 4.1 Origin tries and the record keyspace

Each origin trie maps byte-string keys to record values. Keys are namespaced by a
single prefix byte:

| Prefix | Key                                  | Value          | Meaning                          |
|--------|--------------------------------------|----------------|----------------------------------|
| `f:`   | `f:<space-id>/<utf8 relative path>`  | `FileEntry`    | this origin's copy of a file     |
| `b:`   | `b:<32-byte object root hash>`       | `BlobAd`       | "I hold (part of) this object"   |
| `m:`   | `m:self`                             | `NodeManifest` | node info: name, software        |
| `m:`   | `m:space/<space-id>`                 | `SpaceInfo`    | what this origin says about one space |
| `d:`   | `d:<32-byte device key>`             | `Delegation`   | a delegation this origin has issued (§3.5) |

Paths are UTF-8, NFC-normalized, `/`-separated, no leading slash, no `.`/`..`
components. Because the MPT compresses shared prefixes, the `f:` namespace naturally
mirrors directory structure, and a directory listing is a range scan over
`f:<space>/<dir>/`.

A **space** is a named sync root (like a Syncthing folder): a user configures
`synch source add photos ~/Pictures`, and that subtree is indexed under `f:photos/...`.
Spaces are the unit of sharing policy and of local materialization.

The keyspace is laid out so that **the redaction boundary falls on key prefixes**,
which §5.5 depends on: a peer delegated a space is served the subtrees under `f:<space>/`, that space's own
`m:space/<space>` record, `m:self`, and `d:` — and of every other space, nothing.
A prefix is the only shape that boundary can take, which is why `m:space/<id>` and
`m:self` are carried as *exact* keys rather than prefixes: used as prefixes they would
admit every key that merely starts with them, so a delegation of `photos` would carry
`m:space/photos-raw` along with it. `m:self` therefore carries no per-space information — a leaf
value cannot be partly redacted, so a single manifest listing every space could be
shown to a delegate not at all. Any new record type is checked against this rule at
design time, because retrofitting it costs a migration and a cluster-wide republish.

### 4.2 Records

All records are `postcard`-encoded, versioned structs (first field is a `u8` schema
version).

```rust
struct FileEntry {
    v: u8,                    // schema version
    kind: EntryKind,          // File | Dir | Symlink | Tombstone
    size: u64,                // content length (0 for dirs)
    mtime_ns: i64,            // origin's observed mtime
    unix_mode: Option<u32>,   // advisory; best-effort cross-platform
    content: Option<Hash>,    // BLAKE3 hash-tree root (None for Dir/Tombstone)
    chunking: ChunkParams,    // { format: Bao, group_log2: u4 } — fixed per object
    seq: u64,                 // origin trie seq at which this version was published
    prev: Option<Hash>,       // previous content root (1-step lineage, see §8)
    symlink_target: Option<String>,
}

struct BlobAd {
    v: u8,
    size: u64,                // object length in bytes
    state: AdState,
}
enum AdState {
    Complete,
    Partial { spans: Vec<(u64, u64)> },  // held byte spans, coalesced at 16 MiB granularity
}

struct NodeManifest {
    v: u8,
    name: String,             // human-friendly node name
    software: String,         // "synchronicity/0.1.0"
}

struct SpaceInfo {            // one per space, under m:space/<space-id>
    v: u8,
    description: String,
    entry_count: u64,
}

struct Delegation {           // under d:<32-byte device key> (§3.5)
    v: u8,
    spaces: Vec<String>,      // closed list, <= 32, distinct, never a wildcard
    not_after: i64,
    note: Option<String>,
}
```

Notes:

- **Tombstones**: deletion publishes `kind: Tombstone` (with `content: None`).
  Tombstones are *not* what makes deletion propagate — tries are single-writer and
  replicated whole (head flip + root diff), so a deleted key simply vanishes from
  the new root and the diff surfaces it, even to peers partitioned for years. Their
  purpose is interpretation: distinguishing "deleted at seq N" from "never existed"
  in `synch status`/`synch log`. They are retained for
  `tombstone_ttl` (default 90 days), then dropped in a later root. Two residual
  risks, both accepted and both with the same remedy: (1) the *origin itself*
  restoring from an old database backup republishes its old trie at a higher seq,
  resurrecting its own deletions — visible in `head_history`, not preventable by
  the protocol; (2) under the unified tree (§8), a deletion whose divergence was
  never resolved expires: if another origin still publishes a live version when
  the tombstone's TTL runs out, that live version becomes the only one and
  `newest` surfaces silently re-serve the file. The remedy for both is ending the
  divergence while it is visible — `synch adopt path` the deletion (§8) on the holdout,
  or the holdout deletes its copy — rather than letting the TTL decide.
- **`BlobAd` granularity — one record per object per holder.** Advertising every
  hash-tree node individually is the obvious alternative and is unsound at scale: a
  single 100 GB file yields ~6.1 M leaf groups and ~12 M trie records — larger than
  the entire per-origin metadata quota (§12) — and replicating per-chunk ad churn
  during swarm downloads amplifies metadata O(N²) exactly when the network is
  busiest. The
  any-subtree-servable property does **not** depend on per-node ads: it comes from
  bao itself (§6.1) — any holder of a verified slice necessarily also holds the
  root-path hashes needed to re-serve it. Ads therefore carry only a coarse span
  summary (16 MiB granularity); exact chunk-level availability is discovered at fetch
  time from `SliceEnd` (§6.4).

### 4.3 The Merkle-Patricia Trie

We implement our own small MPT (crate `synch-mpt`, no consensus-chain baggage):

- **Radix-16** (nibble) trie with three node kinds, à la Ethereum, but simplified:

  ```rust
  enum TrieNode {
      Leaf   { key_rest: Nibbles, value: ValueRef },
      Ext    { prefix: Nibbles, child: Hash },
      Branch { children: [Option<Hash>; 16], value: Option<ValueRef> },
  }
  enum ValueRef {
      Inline(Vec<u8>),   // ≤ 128 bytes, embedded in the node
      Hash(Hash),        // larger values stored out-of-line, content-addressed
  }
  ```

- **Hashing**: `node_hash = BLAKE3(domain_sep || canonical postcard encoding)`, with a
  domain-separation tag per node kind. No RLP, no keccak.
- **Content-addressed node store**: every trie node is stored by hash in SQLite
  (`trie_nodes`). Successive roots share unchanged subtrees structurally — publishing a
  new root after touching one file allocates only the path from that leaf to the root
  (≤ ~key-length/2 nodes). This same property makes diffing cheap and makes *any* node
  able to serve *any* trie node to *any* peer.
- **Proofs**: a key's value is provable against a root with the node path (Merkle
  proof), including proofs of absence. No v1 flow needs them — every node replicates
  whole tries — so this is capability kept deliberately ahead of its use: partial
  trie replication (§13) is the design that requires it, and building the proof
  machinery alongside the trie is far cheaper than retrofitting it.

### 4.4 Signed heads

The mutable pointer per origin is a **head**:

```rust
struct SignedHead {
    origin: OriginId,
    seq: u64,          // strictly monotonic per origin, across key rotations
    root: Hash,        // MPT root hash ("empty" sentinel for the empty trie)
    created_at: i64,   // unix nanos, informational only
    signed_by: NodeId, // the device key that produced sig
    sig: Signature,    // ed25519 over ("sync-head/1" || origin || seq || root || created_at || signed_by)
}
```

- A head is **valid** iff `sig` verifies under `signed_by` *and* `signed_by` is
  currently bound to `origin` (§3.1). Accepted heads record the binding check in
  `heads.verified_at`, so history signed by since-retired keys stays valid — a
  rotation never invalidates already-replicated state. Verified-then-displaced heads
  are retained *with their signatures* in `head_history` (§10) as provable history
  and fork evidence (§3.4).
- Heads are **relayable**: any peer can hand you a newer signed head for any origin;
  the signature makes provenance independent of the carrier.
- Ordering is `(seq, root)` lexicographic. `created_at` is never used for ordering
  (clocks lie); it is display metadata.
- **Equivocation** (an origin signing two different roots at the same seq) is detected
  and logged loudly (`synch doctor` reports it); the deterministic `(seq, root)` max —
  which the §5.2 acceptance rule implements exactly (equal-seq, greater-root heads
  are accepted, not ignored) — still converges everyone to the same head. Both
  conflicting signed heads are retained in `head_history` as proof. Equivocation only
  harms the equivocator's own published view.

---

## 5. mptsync — active anti-entropy on Merkle-Patricia Tries

ALPN: `sync/mpt/1`. All messages are length-framed `postcard` on QUIC streams.

### 5.1 Protocol messages

```rust
// bidirectional stream 0 on connect: head gossip (push-pull)
Hello      { proto: u16, heads: Vec<HeadSummary>,
             scope: Option<Vec<String>> }               // the spaces the sender will serve this peer,
                                                        //   None for everything (§5.5)
                                                        // HeadSummary = (origin: OriginId, seq, root,
                                                        //   complete: bool)  — "complete" = I hold the
                                                        //   full trie under this root and can serve it;
                                                        //   a signed head alone proves nothing about that
HeadsWant  { origins: Vec<OriginId> }                   // "yours is newer, send full signed head"
Heads      { heads: Vec<SignedHead> }
HeadPush   { head: SignedHead }                         // reactive: sent on any head change

// one bidirectional stream per fetch batch. Each want carries the nibble
// position it claims, which is what a responder authorizes on (§5.5): a hash
// carries no position and none can be recovered from it, since structural
// sharing lets one node sit under several prefixes.
GetNodes   { root: Hash, wants: Vec<(Nibbles, Hash)> }  // ≤ 256, ≤ 64 KiB of paths
Nodes      { nodes: Vec<(Hash, Bytes)>, missing: Vec<Hash> }
GetValues  { root: Hash, wants: Vec<(Nibbles, Hash)> }  // out-of-line ValueRef payloads
Values     { values: Vec<(Hash, Bytes)>, missing: Vec<Hash> }

// provider hints for cold caches: a node holding an object root whose ads it has
// not replicated yet (bootstrap, or an origin just admitted). Hints are unverified —
// content is hash-verified regardless, so a wrong hint only wastes a dial. The
// fetcher falls back to this when it wants a root no local ad covers:
FindProviders { object_root: Hash }
Providers  { ads: Vec<(OriginId, BlobAd)> }                // ≤ 256 ads per answer

// binding introspection: which device keys does the answering peer currently hold
// bound for an origin? Purely informational within the trusted cluster; this is
// what `synch key ls` aggregates to tell an operator when a rotation's new key
// has actually propagated (§3.4):
GetBindings  { origin: OriginId }
BindingsFor  { origin: OriginId, keys: Vec<NodeId> }
```

### 5.2 Reconciliation algorithm

For each trusted origin `O`, a node tracks `local_head(O)` and a fully materialized
copy of that trie in `trie_nodes`. On learning a newer head `H` for `O` (via `Hello`
exchange or `HeadPush`):

```
verify sig(H) under H.signed_by; check H.signed_by is bound to O (else ignore)
check (H.seq, H.root) > (local.seq, local.root) lexicographically (else ignore)
  // NB: strictly-greater on seq ALONE would not converge — two peers receiving
  // different same-seq heads in different orders would diverge permanently. The
  // (seq, root) rule accepts an equal-seq, greater-root head; the displaced head
  // is retained in head_history as equivocation evidence (§4.4).
record H as pending_head(O)                            // durable; complete head untouched
R ← complete_head(O).root, if this node holds that trie WHOLE, else ⊥
frontier ← { (R, H.root) }                             // (reference position, wanted)
while frontier ≠ ∅:                                    // ONE walk, resumed between batches
    drop (r, h) where r = h                            // same hash under a trie held whole:
                                                       //   that subtree is already here
    want ← { h : (r, h) ∈ frontier, h ∉ trie_nodes }
    if want = ∅ and frontier is drained: break
    nodes ← GetNodes(want) from this peer (or any peer advertising complete ≥ H.seq)
    verify each node hashes to its requested hash      // reject & disconnect on mismatch
    store nodes; re-queue what was fetched, pairing each child with the child at
    the same position under r, so the next descent can prune the same way
atomically, in ONE SQLite transaction:
    set complete_head(O) ← H; clear pending
    re-materialize changed leaves into `entries` / `blob_providers` (computed from
    the node-level diff between old and new root — only touched subtrees visited)
// the flip and the materialization are the same transaction (§10): a crash can
// never leave `entries` — what the unified tree, checkouts, and S3 serve from —
// missing a promoted head's delta. Local publishes obey the same rule: trie
// writes, head, history, and materialization commit together or not at all.
```

Properties:

- **Idempotent and resumable**: everything fetched is content-addressed; a crash
  mid-sync loses nothing. Per origin there are **two durable head slots** (§10): the
  in-progress target is recorded as the `pending` head, and the `complete` head —
  the one `entries` is materialized from, the one advertised as servable — flips only
  when the trie is fully present under the new root.
- **Bandwidth *and work* ∝ change**: unchanged subtrees are pruned at the first
  shared hash. The distinction is worth stating because getting one without the
  other is easy: a walk that filters *requests* by presence still descends into
  everything present, so bandwidth is proportional to the change while CPU is
  proportional to the tree. Pruning traversal needs a
  stronger fact than "I have this node" — a node is committed the moment it
  arrives, so a present node's children may be absent, and presence alone proves
  nothing about a subtree. The reference root `R` supplies it: hashes matching a
  trie held *whole* are subtrees held whole. Cold sync has no such reference and
  is honestly proportional to the trie, but it walks it once — the frontier is
  resumed between batches, never restarted at the root, or a fetch of `n` nodes in
  batches of `b` would re-descend what it has already pulled and cost `n²/b`.
- **A completeness answer is computed once**: "do I hold this trie whole?" is asked
  on every `Hello`, and answering it means walking everything reachable. A root is
  immutable, so the answer cannot change once computed: a store may remember it,
  and a node that just built or just fetched a root records it outright rather than
  proving it again. Without that a converged cluster pays for the size of its
  metadata on every anti-entropy round, on both sides, forever.
- **Verified piecewise**: every trie node is checked against the hash it was requested
  by; a malicious or corrupt peer cannot inject data, only fail to help.
- **Peer-agnostic**: because trie nodes are content-addressed, missing nodes may be
  fetched from *any* peer advertising a `complete` head for `O` at ≥ `H.seq` (§5.1) —
  including nodes that are neither `O` nor the peer that told us about `H`.
  Hierarchy-agnostic in practice: a laptop that heard about a NAS's update from a VPS
  can pull the trie nodes from either.
- **No wedging on unservable heads**, by three rules with disjoint triggers,
  because no one of them reaches the others' cases:
  - If a peer being fetched from persistently returns `missing` for wanted nodes
    (default: 3 rounds within one fetch — possible when a head was relayed but its
    trie never fully propagated, or when a serving peer GC'd a root out of
    retention mid-fetch), the pending head is **abandoned** and head selection
    re-runs, typically re-targeting the origin's newest complete-advertised head.
    Structural sharing makes the restart cost proportional to what actually
    changed, not to what was already fetched — this is also the recovery path for
    the laggard-vs-GC race (§5.4). The counter lives in the fetch, so it only
    counts against a peer a fetch was actually attempted against.
  - If *no* peer advertises a complete head at or above the pending one, no fetch
    is ever attempted and that counter never runs. Such a head still holds
    `head_floor` above every servable head for its origin, so the maintenance
    pass abandons it after `pending_head_ttl` (default 900 s, thirty anti-entropy
    intervals). This is the case a publisher going offline between its push and
    anyone's fetch produces.

    The clock is on the **slot**, not on the head occupying it. It used to be on
    the head — every accepted head rewrote `heads.received_at` — and that made
    this rule unreachable for the case it exists to cover. A node that can be
    pushed to but cannot dial the origin, with the origin publishing faster than
    the TTL, holds a pending head that is always strictly above every servable
    head in the cluster and always freshly stamped: rule one never runs because
    no fetch is attempted, rule three never runs because the trie is absent, and
    this rule never fires because the clock keeps restarting. The node stays
    frozen at its last complete head and advertises that stale root to everyone.
    Occupying an empty slot starts the clock; adopting a newer head into an
    occupied slot inherits it; a fetch that commits something restarts it, so a
    trie that legitimately takes longer than the TTL to arrive is not swept out
    from under the fetch filling it — but only for the head that fetch is
    actually about. A fetch reads the pending head once and then spends many
    round trips on that root while `HeadPush` keeps writing the slot, so an
    unnamed restart would let progress on one root extend the deadline of a
    different, unservable head that had taken the slot since: the same reason
    abandonment is compare-and-clear rather than an unconditional delete.
  - A pending head whose trie *is* wholly present is promoted by the same pass
    rather than abandoned. Promotion otherwise happens only on an accepted offer
    or at the end of a successful fetch, and a crash between a fetch's last
    committed batch and the promotion that would have followed leaves a head that
    neither path revisits — holding the floor while sitting on every byte it
    needs.
  - A head whose trie is wholly present and whose *promotion* this node's own
    rules refuse — an undecodable `f:` record, say — never keeps the slot it was
    written into: the offer that wrote it retires it again, leaving the head in
    `head_history` as evidence and dropping the floor back to what this node can
    serve. Left in place it looked to the TTL rule like a head one promotion away
    from complete, which it is not, and the cycle that followed (abandon, re-adopt,
    fail, abandon) cost a full promotion diff under the write lock every round.

Abandonment names the head it is abandoning. All three rules reach their verdict
on a snapshot — after several network round trips, or after a trie walk — and the
slot is written by any concurrent `offer_head`, so a delete that took *whatever
occupies the slot* could discard a strictly newer head that arrived in between.

The `seq` a local publish carries is derived from **everything this node has
recorded for its own origin** — both slots and the retained history — not from the
complete slot alone. A database restored from a backup still holds a complete
head, so §3.4's key-loss recovery does not cover it, and deriving the next seq
from that slot alone lets the node sign a second root at a seq its own history
already names. Both roots are valid and bound, so every peer takes the greater
under the rule above — and if that is the older root, this node's own `entries`
are rolled back to it everywhere.

### 5.3 Anti-entropy scheduling

- **Reactive**: a local publish (§7) is pushed (`HeadPush`) to *every* trusted
  peer immediately — dialling the ones not already connected, all concurrently —
  which gives sub-second propagation on connected clusters. Pushing to the whole
  membership rather than to current connections is what makes a second hop
  unnecessary at the N ≤ 100 §12 sizes: the publisher already reaches everyone it
  can reach. A received head is *not* relayed onward, so a member reachable from
  some peer but not from the origin learns of it on its next pull rather than by
  epidemic spread.

  A pushed head lands in the receiver's **pending** slot — by construction, since
  a head worth pushing names a root the receiver has never seen — and the head
  alone moves nothing a reader looks at: `entries`, the unified tree, checkouts and
  the S3 gateway all sit behind promotion. So the receiver's anti-entropy loop
  waits on that adoption as well as on its interval, and dials for the trie at
  once. Without that arm the "sub-second" above was true of the pointer and false
  of the data, which followed up to one jittered interval (45 s) later. Rounds
  driven this way are floored at one per 2 s, so an origin publishing in a burst
  costs its peers one round rather than one per head.

  The adoption signal **stores a permit**, and that is load-bearing rather than an
  implementation detail. The loop is parked on it only *between* rounds; it spends
  the rest of its time inside a round, dialling peers — which is exactly when the
  pushes it needs to hear about arrive, because a publisher pushes to the whole
  membership concurrently, so peer X's round is in flight while pushes from other
  origins land. A signal that keeps nothing for an unparked listener is therefore
  silent for precisely the pushes that matter, and the interval-length wait comes
  straight back. The promotion signal that drives replica acquisition is the same shape for
  the same reason.
- **Periodic**: every `aae_interval` (default 30s with ±50% jitter), pick one random
  trusted peer, connect if needed, run a full `Hello` push-pull exchange. This repairs
  anything the reactive path missed (dropped connections, simultaneous partitions) and
  is the mechanism that guarantees convergence.
- **On-connect**: an mpt session (`sync/mpt/1`) begins with a `Hello` exchange, and
  each ALPN's session is held open and reused across requests for as long as it is
  live. The two are independent: `Hello` exists only on the mpt ALPN, and the blob
  ALPN carries nothing but `GetSlice`/`SliceEnd` and `GetProof`/`ProofEnd`, so a
  blob fetch neither opens nor needs an mpt session.

Expected staleness with push + pull-gossip is `O(log N)` rounds after any partition
heals; at N ≤ 100 and 30 s rounds this is well under 5 minutes worst-case, typically
sub-second via push.

### 5.4 Trie garbage collection

Old roots are kept for `root_retention` (default 7 days) to serve laggard peers cheap
diffs and to power `synch log` history (§8). Age is measured from when this node
recorded the row, not from the `created_at` the signer chose: the signed time is
display metadata, and keying retention on it would let an origin make its rows —
and every trie node reachable from them — permanent on every peer. GC is mark-and-sweep in SQLite: mark from
all retained heads (each origin's **complete and pending** heads + retained history
roots — pending heads must be in the mark set or GC would eat an in-progress
bootstrap), sweep unmarked
`trie_nodes`/`trie_values`. Runs incrementally in the maintenance loop.

The same pass sweeps CAS files that no `blobs` row accounts for — what a fetch
that failed verification leaves behind — and the staging files of ingests that
never finished, using the content retention horizon as
the cutoff, so a payload written moments before its row, or an ingest still
streaming, is never mistaken for a leftover.

### 5.5 Scoped replication

A delegated node (§3.5) must not see the metadata of a space it was not delegated —
not the paths, not the sizes, not that the space exists. Tries are replicated whole,
and a signed root spans every space, so this is a property of what a *responder*
hands over.

**Redaction is free at the node boundary.** A `Branch` already carries the hashes of
all sixteen children, so withholding a subtree means declining to send its nodes: the
parent that *was* sent already commits to it, and the delegate recomputes the signed
root exactly as it would from a whole trie. No proof format, no new verification rule
— every node is checked against the hash it was reached by, which §5.2 already does.
The boundary is therefore the child hash inside the last in-scope node, never the
first out-of-scope node: an `Ext` above an undelegated space spells that space's name
in its prefix, so it is the node that must not travel.

**A hash cannot be authorized; a position can.** Refusing out-of-scope *hashes* is
unsound twice over. The delegate legitimately holds the hashes it must not expand —
they are inside the branch node that makes the root verify — so possession cannot be
what qualifies it. And structural sharing means one node hash may sit under several
prefixes, so a node-to-prefix index is many-valued and "is *any* position in scope?"
is the wrong question. So `GetNodes`/`GetValues` carry the position each hash is
claimed to occupy: the responder descends that path from a root *it* holds and
compares the path against the peer's scope. A fabricated root fails at the first
step, and a lie about the position resolves to whatever genuinely sits there, which
is in scope by construction. Between rooted peers the path is carried and ignored.

**Both sides prune.** The fetch walk stops at the boundary rather than asking for
what it would be refused, so an out-of-scope request is not a race — an honest walk
never generates one — and is logged as the probe it is. The scoped walk is also what
the head-promotion diff runs under, since a node reading under a scope holds only
that part of the trie.

**The root a request names must be one this node holds a head for.** Given an
arbitrary root the empty path resolves to that root itself, and every position under
it is whatever the caller put there — so without this check, authorization by
position authorizes nothing at all. Roots reached through `head_history` are ones an
origin signed and this node verified, which is what makes the positions in them real.

**A node is judged by what it reveals, not only by where it sits.** The trie
compresses, and a compressed node carries key material of its own: an `Ext` spells
the nibbles between its position and its child, a `Leaf` spells the rest of a key
together with that key's value. Both can sit at a spine position the scope
legitimately admits — the spine is what makes the root recompute — while describing a
key range that runs out of the scope entirely. Such a node is refused as a
**boundary**, reported distinctly from an absence: `missing` means "ask again", while
a redacted position means "there is nothing here for you, ever". A scoped node
records the distinction durably, because a completeness walk that re-read a refused
position as merely missing would never settle and a fetch would retry until its head
was abandoned. To every walk over what this node *does* hold, a redacted position
reads as empty — both roots of a diff redact the same positions, so the two sides
agree and no spurious change is emitted.

**`complete` becomes scope-relative.** A delegate never holds a foreign trie whole,
so it advertises `complete: false` for every origin but its own and drops out of the
swarm as a source for foreign metadata, which is correct — it could not serve it. The
§5.2 reference-root pruning survives, restricted: "held whole" becomes "held whole
within scope", and its soundness condition holds because the walk never commits part
of a subtree it is *inside* — every boundary it holds is a scope edge. The
completeness memo is keyed by root *and* scope, so widening a scope re-derives rather
than inherits.

**Learning the scope.** A delegate's scope lives in the delegating origin's trie,
which it cannot read until it knows its scope. So the peer serving it says, in the
`Hello` that opens every session, and the value is one node-wide setting. `synch
doctor` reports it, because a partial trie and a broken fetch look alike from the
outside, and because the same scope decides the servable column below it: a foreign
head on a confined node is judged whole *within the grant*, and this node's own head —
the one trie it built rather than was served — is judged whole outright.

**A delegate talks only to peers that hold its issuer's trie whole.** A delegate holds
every foreign trie in part, so it can be *served* one only by a node that holds it
whole; pulling from another delegate yields a trie short in exactly the spaces that
peer was not granted, which nothing downstream can tell from a trie still arriving.
Membership is not a domain suffix — it is holding the cluster's tries, and `complete`
in the `Hello` is where a peer says so. A peer that cannot serve the issuer's trie has
not read the record that grants this node its scope, so its declaration is refused as
well as its data. Content is unaffected: it is content-addressed and verified by hash,
so a delegate fetches bytes from anyone (§6).

That is what keeps one node-wide value honest. Every peer a delegate will listen to
has read the same `d:` record, so every declaration it hears carries the same answer —
and a delegation outranks a local `trust add` when a responder computes what it will
serve, so two members of one cluster cannot answer differently for the same key.
Promoting a delegate is therefore *revoking its delegation*, the cluster-visible
operation, and not merely rooting its key beside a record that still confines it.

**A scope that moves discards everything derived under the old one.** This section used
to read "adopting a peer's word costs nothing … a wrong or stale value can only make a
node ask for *less* than it is entitled to", and that was wrong. Asking for less is free
only while nothing durable is derived from it, and three things are: what a fetch asks
for, what `is_complete_scoped` counts as whole, and what `materialize_diff` walks.

There is no diff that reconciles rows built under one scope with a walk under another,
because the promotion diff prunes at equal node hashes: widen the grant and the space
just gained is pruned over and never appears; narrow it and the space just revoked is
never removed. Where the newly admitted subtree also *changed*, the diff descends into
an old root that has no node there — it was never fetched under the old scope — and the
`MissingNode` that follows reads as the *origin's* fault, so the head is retired into
the refusal memo and that origin stops replicating on this node for good.

So nothing is reconciled. `entries`, `blob_providers` and the delegated bindings are
derived state, and the honest thing to do with derived state whose premise changed is to
throw it away: the rows go, the redaction boundaries go, and every foreign complete head
drops back to the pending slot. The ordinary fetch then fills each trie out under the
new scope and the ordinary promotion rebuilds the rows — finding no complete head, its
diff runs from the empty root, which touches the stale one not at all. That is what
makes the whole class unreachable rather than handled, and it is why no per-origin
bookkeeping is needed to detect it: the scope moves in exactly one place.

The cost is paid where it belongs. A scope that has not moved costs one comparison; a
scope that has costs a re-materialization of every foreign origin, on an operator
action that happens rarely. Trie nodes are content-addressed and are *not* discarded, so
the only bytes fetched are the ones the new scope actually adds. This node's own origin
is never touched: it built that trie, and there is nobody to refetch it from.

**`b:` is not served to a delegate at all.** Ads are keyed by content hash, so the
shape of that subtree would leak how many objects an origin holds. A delegate learns
availability through `FindProviders` instead — the path §5.1 already provides for a
node holding no ads for a root it wants — which makes the namespace invisible rather
than merely filtered. A delegate still *publishes* `b:` for content it holds, or no
member could fetch from it.

**What remains visible**, stated exactly. Of an *undelegated space*: the existence and
count of sibling subtrees along the spine, and one nibble of discrimination each, since
a branch on the path to a granted space necessarily says which of its sixteen slots are
occupied. Where a granted space's name shares a prefix with another's, the shared prefix
is on the spine legitimately and the discriminating nibble is all that is added. Nothing
else — no names, no paths, no sizes, no mtimes, no content hashes, no counts. Driving
even that to zero would mean hashing trie keys so prefixes carry no meaning, which would
destroy the range-scan property §4.1 is built on.

Two things outside that accounting are served to a delegate deliberately, and are worth
naming rather than leaving to be discovered: `m:self`, which is node-wide and carries
nothing about any space; and the whole of `d:`, so a delegate reads every *other*
delegation the cluster holds — including the ids of spaces it was not granted, since a
`Delegation` names its own list. That is the transitive-trust concession made legible
(§3.5), and it is what lets `synch delegate ls` answer from any node.

---

**Structural sharing does not cross the delegation boundary: presence is with
provenance.** The redaction above withholds a subtree's *nodes*, never its hash —
the hash sits in the branch that makes the signed root recompute — so a delegate
holds the hash of everything it was denied and may publish a trie of its own that
places that hash at an in-scope position. A member fetching that head already
holds the nodes, from the issuer's trie, in the one content-addressed store that
lets identical nodes be stored once; judged by presence, the trie is complete, the
head promotes, and the member then serves the withheld subtree to every delegate
with the same grant, at a position each is entitled to. Every position is
admitted; the content was never the grafting origin's to publish.

So for an origin that is not rooted — a confined one, or one with no live binding
— "present" means *present as that origin's*: served under one of its roots by a
peer that vouches for the node, recorded per `(origin, hash)` in
`trie_node_origins` in the same transaction as the node. The fetch walk for such an
origin's head reads presence through that relation and asks again for a node it
merely holds; `is_complete` is asked with the same provenance, and memoized under a
key of its own; and a responder serves a node under any root only if the root's
origin is rooted, or the responder was itself served the node as that origin's, or
the responder *is* that origin and holds the node — for every peer, scoped or not,
since a full member handed the node under the grafting root would record
provenance for it and move the leak one hop. Vouching therefore bottoms out in the
origin, and an origin cannot serve what it never held: the grafted head is asked
for its subtree, told `missing`, and abandoned, on every member. Rooted origins are
judged by presence alone, as before, and a node's own trie by construction. The
cost is one row per node per confined origin, and one re-fetch of the nodes a
confined origin's trie shares with another's. `specs/lean/Synchronicity/Provenance.lean`
is the model: `Legit` is what "legitimately a reader's" means across every trie a
node may be read through, and `privacy` and `integrity` are the theorem — a
confined participant holds only what is legitimately its, and a member vouches
for a confined origin's head only if every node under it is legitimately that
origin's; `withheld_root_incomplete` is this graft excluded, for any trie.

## 6. Content storage and transfer

### 6.1 Hash trees (bao / BLAKE3)

Every object (file content) is hashed with **BLAKE3**, whose native Merkle-tree
structure we expose rather than hide:

- Leaf unit: **chunk group** of 16 KiB (16 blake3 chunks), the same convention as
  `iroh-blobs`/`bao-tree`. Interior nodes are standard blake3 parent nodes.
- The **object address is the blake3 root hash** — identical to the plain `blake3(file)`
  digest, so addresses are checkable with any blake3 tool.
- Each stored object keeps an **outboard** encoding (the interior tree — 64 bytes of
  child hashes per ~16 KiB leaf group, so ~1/256 of the content size) alongside the
  raw bytes, enabling verified slice serving without recomputation.

**Verified random reads**: a read of any byte range is served as a *bao slice* — the
chunk groups covering the range plus the sibling hashes on the paths to the root. The
client verifies the slice incrementally against the root hash alone; a flipped bit
anywhere fails verification at the exact 16 KiB group it occurs in. Cost is
`O(range + log(size))`.

We build this on the `bao-tree` crate (the engine inside iroh-blobs) rather than
reimplementing.

### 6.2 Local store (CAS)

- Blob payloads live as flat files in the data dir: `store/<hex[0..2]>/<hex>` plus
  `store/<hex>.obao` for the outboard. Small blobs (≤ 16 KiB) are inlined in SQLite.
  An ingest streams into `store/incoming/` and renames onto its content address, so
  the shard directories only ever hold whole objects and the CAS root only ever
  holds directories — a regular file among the shards is what the orphan sweep
  descends into and fails on (§5.4).
- All *index* metadata — sizes, completeness bitmaps (which chunk groups of a partially
  fetched object are present and verified), refcounts, pin state — is in SQLite (§10).
- Partial objects are first-class: the completeness bitmap tracks verified groups, and
  the object's single `BlobAd` summarizes them as coarse spans — so even a node
  holding the first half of a video usefully advertises and serves it.

### 6.3 Availability publishing

Each locally held object is advertised by exactly **one `b:` record**, keyed by the
object root, whose value summarizes held bytes as coarse spans (16 MiB granularity).
Ad updates are milestone-driven to bound churn: a record is (re)published when an
object is first ingested, when it completes, and otherwise at most once per
`ad_update_interval` (default 60 s) per object while a download is in flight — never
per chunk. A swarm of N nodes downloading the same object costs O(N) small ad updates
per interval cluster-wide, not O(N²) per-chunk trie deltas.

Consequences:

- "Who can serve byte range R of object X?" is answered *locally*, by scanning the
  synced `blob_providers` view for ads on `X` whose spans intersect R, across all
  origins. No query round-trip, no DHT.
- Any holder of any verified subtree can serve it (a bao slice carries its own
  root-path hashes, §6.1) and is discoverable at span granularity — swarm behavior
  (fetching different ranges from different peers in parallel) falls out naturally.
  Span summaries are **hints, not promises**: the fetcher learns exact availability
  from `SliceEnd` and re-plans, so a stale ad costs one wasted round-trip, never
  correctness. They are hints in one direction only, though: spans round *inward*
  to the granularity, so a holder advertises the largest aligned run it can
  actually serve and never a byte more. Over-reporting sends a fetcher to a
  provider that cannot serve, while under-reporting costs at most a re-fetch — and
  because "I hold all of this" is read off the spans, rounding outward made a node
  holding one 8 MiB window of a 10 MiB object claim the whole object, which is not
  a hint but a wrong answer. The cost is that a partial holder advertises in whole
  16 MiB units, so the first slice window of a span buys no advertisement.
- Cost model: availability metadata is ~1 trie record per (object, holder). For the
  §14 media example, 40 k objects ≈ 40 k ads per holding node — the same order as
  the `f:` namespace itself, and consistent with the §12 quota.

### 6.4 Blob transfer protocol

ALPN: `sync/blob/1`.

```rust
GetSlice   { root: Hash, ranges: ChunkRanges }   // ChunkRanges in 16 KiB group units
// response: bao slice stream, verified incrementally by the requester
SliceEnd   { served: ChunkRanges }               // what the provider actually had
```

A slice is encoded into memory whole and travels in one framed message, so one
exchange carries a bounded **window** — 512 groups, 8 MiB of payload — whatever
was asked for. The provider clamps to it and says so in `SliceEnd`; the
requester walks a larger range one window at a time, committing each as it
arrives. Without the bound, an object larger than a frame could not be served at
all, and the size of a provider's allocation would be the requester's to choose.

The fetcher:

1. Resolves providers from `blob_providers`, ranks them (recent latency EWMA, then
   random tiebreak), and splits the wanted range across up to `fetch_fanout` (default 3)
   providers — each getting a contiguous share **of what it claims**, taken in rank
   order so nothing is handed to two of them. Cutting the range positionally and
   handing piece *i* to provider *i* is only an assignment if every provider claims
   the whole object: two peers holding complementary halves are each handed the half
   they do not have.
2. Streams and verifies groups as they arrive; verified groups are committed to the
   CAS and the completeness bitmap immediately (progress survives restarts).
3. Re-plans on provider failure: a provider that cannot help is dropped from the
   plan and its groups are re-split across the remainder. Fetching is on-demand and
   request-scoped — the caller (`synch cat/get`, replica acquisition, the S3 gateway)
   drives it and owns retry policy; there is no persistent download queue. Progress
   still survives restarts, because verified groups are committed to the CAS as
   they arrive and a re-issued fetch skips whatever is already held.

This is intentionally the same shape as iroh-blobs' protocol; we keep our own ALPN and
message frame so the availability semantics (partial serving, `SliceEnd`) stay under
our control, but the heavy machinery (bao verification) is shared code.

---

## 7. Local filesystem integration (no FUSE)

synchronicity is a **sync-directory** tool, not a mounted filesystem. Cross-platform
behavior with zero kernel dependencies:

### 7.1 Filesystem-source scanning and publication

- **Watcher**: the `notify` crate (inotify / FSEvents / ReadDirectoryChangesW, with
  polling fallback) provides change hints per space. Hints are debounced (default
  500 ms) and only ever *schedule rescans* — correctness never depends on watcher
  completeness.
- **Scanner**: a periodic (default 1 h) and on-demand full walk. A file is considered
  unchanged if `(size, mtime_ns, file_id)` matches the `local_files` table — only then
  is hashing skipped. Changed files are re-hashed (streaming blake3, outboard emitted
  as a by-product), the CAS is updated, and a new `FileEntry` is staged. **Symlinks
  are tracked exactly like files**: recorded in `local_files`, carrying the link's
  own (lstat) mtime and its target as the change signal — an unchanged symlink
  stages nothing (republishing one every scan would defeat the "unchanged tree
  publishes no head" property), a retargeted one stages an update, and a deleted
  one is swept into a tombstone like any other path.
- **Publisher**: staged changes are batched (default: quiesce 2 s or 1000 entries) into
  a single new trie root: bump `seq`, sign, store, `HeadPush` to connected peers. One
  save in an editor costs one head; a 100k-file initial index costs a handful.

Ignore rules: `.syncignore` per space root (gitignore syntax), plus sensible built-in
defaults (`.DS_Store`, `Thumbs.db`, temp/lock patterns).

### 7.2 Materialization and adoption

Materialization reads the unified tree (§8), so every read surface takes one
selection policy: `--select newest` (default), `--select origin=<id>`, or
`--select strict`. An origin-qualified reference is shorthand for the origin policy.

- `synch cat` streams a selected version, with optional verified range reads.
- `synch get` writes one selected version to an explicitly named destination.
- `synch adopt path` writes one selected path into a local source and immediately
  publishes it as this node's assertion. A selected tombstone removes the local
  path and publishes that deletion.
- `synch adopt tree` does the same additively for a subtree. Existing differing
  files are reported unless `--replace` is explicit; `--dry-run` is a complete
  preview. It never infers removal from absence. A successful non-dry run scans,
  publishes, and pushes before returning.

A replica may also have `--checkout <path>`. That directory is only a view of
content the replica already holds: checkout never creates retention demand and
never fetches. It continuously materializes the `newest` unified view, is never
scanned or published, and has no independent command or policy. Removing the
replica stops updating the checkout but leaves its files in place.

Adoption writes only to a filesystem source and obeys its `.syncignore`,
missing-root, recovery, race, and path-validity guards. The engine rechecks the
target immediately before replacement, so a file that appeared or changed after
planning is left alone. It also refuses to replace an unpublished local edit with
this node's own selected version. Written files carry the selected version's mtime
and masked advisory mode; matching local files are not restamped.

Checkout and source roots may not overlap. Trie paths are case-sensitive NFC UTF-8,
while local filesystems may fold case or reject names, so colliding or invalid paths
are skipped and reported rather than clobbered.

Two-way shared folders are two nodes holding filesystem source roles for the same
namespace. Divergence remains visible in `synch status` and is resolved explicitly
with `synch adopt path` or `synch adopt tree`.
---

## 8. The unified tree and its versions

What a user sees is **one tree**: per space, the union of every origin's published
paths. What the system stores and syncs is unchanged — per-origin single-writer tries
(§4), replicated whole. The unified tree is a *derived view* (`entries` grouped by
`(space, path)`), never a stored structure and never itself synced; there is nothing
to reconcile about the view because it is recomputed from the assertions.

Principles: **every origin publishes only its own copy; the system never merges
content.** What it does do is aggregate:

- Each `(origin, space, path)` triple remains an independent assertion: "this is my
  current copy". A path's state in the unified tree is the *set* of those assertions.
- A **version** of a path is a distinct assertion identity among the origins'
  current entries for it: for regular files, the content root; for content-less
  kinds, the pair (kind, target) — two symlinks are the same version iff their
  targets match, and a symlink is never the same version as a file. Origins
  asserting the same identity collapse into one version with several attestors —
  agreement is the common case, and it renders as a plain file.
- A path **exists** in the tree iff at least one origin currently publishes a live
  (non-tombstone) entry for it. Origins that never published a path simply don't
  contribute — absence is not an assertion. A tombstone *is* an assertion ("deleted
  at seq N") and counts as a content-less version: live + tombstone on the same path
  is deletion divergence, and the path stays visible (marked) until it is resolved
  or every publisher tombstones it.
- **Divergent** = two or more versions. Divergence is data, not an error: `synch ls`
  marks it, `synch status <space>/<path>` shows every version side by side (content
  root, attestors, size, mtime, seq), `synch doctor` counts them cluster-wide. No
  version is ever combined with another, and every origin's assertion stays
  individually addressable as `<origin>:<space>/<path>`.
- **Selection, not resolution**: any read of a bare `<space>/<path>` must pick one
  version, and does so by an explicit, deterministic policy:
  - `newest` (default) — the greatest `(mtime_ns, content_root, symlink target,
    origin)` among the path's **live** versions, a total order, so every node
    selects the same version from the same assertions. A tombstone takes its own
    origin's version out of the running rather than the path: the path resolves
    to the newest live version among the remaining origins and is absent only
    once every publisher has tombstoned it, which is the same rule as "a path
    exists iff at least one origin publishes a live entry for it" above. This is
    presentation, not resolution: nothing is written, no assertion changes, and
    the losing versions remain first-class and marked.
    The row a node materializes is the trie leaf verbatim, so every component of
    the order is data every node holds identically; `mtime_ns` is read as no
    later than the reading node's own clock, which bounds what a stamp can claim
    to the present instant without making the stored view a function of when it
    was stored. Two trust caveats are inherent and accepted (§12): `mtime_ns` is
    member-supplied file metadata — a member with a skewed clock or a deliberate
    `touch -d` wins `newest` on every surface until its entries are outranked,
    adopted over, or the member is removed; and determinism holds only over *the
    same assertions* — two nodes that have synced different subsets of heads
    select differently until anti-entropy converges them, so a lagging checkout
    can briefly serve different bytes than a current one, unmarked. Deployments
    for which either is unacceptable use `strict` or an `origin=` pin.
  - `origin=<id>` — select one origin's view, the right tool for "serve exactly
    what the NAS publishes".
  - `strict` — refuse to read a divergent path, returning the version list instead;
    for workflows where silently reading either side is worse than failing.
  Selection is explicit and uniform: `cat`, `get`, pinning, and adoption accept
  `--select newest|strict|origin=<id>`. S3 bucket configuration stores the same
  selection (§7.2, §9.4).
- **Adoption is explicit — and deletions are adoptable**: `synch adopt path
  <space>/<path> --select origin=<id>` makes that origin's version our own. For a live
  version, it fetches the content, writes it into the local space, and thereby
  (via the filesystem-source scan) publishes it as the local node's own new entry.
  For a **tombstone** version, it deletes our local copy from the space, and the
  next scan publishes our own tombstone — adopting the deletion exactly as one
  adopts content. Adoption is how *all* divergence ends, deletion divergence
  included: as publishers converge on one identity, their assertions collapse
  back into a single unanimous version. `prev` is set to the replaced local
  content root, recording 1-step lineage so UIs can distinguish "adopted theirs
  on top of X" from "changed independently".
- **History**: retained old roots (§5.4) give each origin a record of its own
  publishes: `synch log <space>/<path>` walks historical roots' leaves for the key
  and shows each version's seq and content root. An old version's *bytes* remain
  readable for as long as some node's CAS still holds that root (content GC is
  pin/retention-driven, so history depth is a storage policy, not a protocol
  constant); reading one back is done by content root, not by a time-travel flag.
- No branches, no merge commits, no vector clocks in v1. `prev` plus per-origin `seq`
  is deliberately the entire causality story; experience (Syncthing, Unison) says
  users resolve file conflicts by *looking at the file*, not the DAG.

---

## 9. CLI and process model

### 9.1 Two binaries, no dependencies

The workspace ships **two binary targets**, both thin argument-parsing shells over
the same reusable library crates (§11):

- **`synch`** — the daemon, and the CLI client that drives it (§9.2). Named `synch`,
  not `sync`: the bare word collides with coreutils' `sync(1)` and half the package
  ecosystem.
- **`synch-s3`** — an S3-compatible gateway server (§9.4).

Both are dependency-free static binaries:

- `rusqlite` with the `bundled` feature (SQLite compiled in — no system SQLite),
- `rustls` everywhere (no OpenSSL),
- musl static builds for Linux releases; standard static-ish builds for macOS/Windows.

**The daemon owns the node; the CLI is only a client of it.** `synch init` creates the
datadir, `synch daemon run` is the daemon, and `synch daemon start` launches it in the
background; every other command is a request over the control socket (§9.3). There is
no in-process fallback: with no daemon running, a command fails with a message naming
the socket path and both ways to start one.

This is a deliberate narrowing. A CLI that could also open the database directly meant
two code paths to the same state, two processes contending on one SQLite file, and —
worse — a short-lived second iroh endpoint sharing the daemon's device key, fighting
it over relay registration and discovery records. One writer, one endpoint, one
lifecycle is worth more than the convenience of running commands without a daemon.
The rule binds every process, `synch-s3` included (§9.4): concurrent publishers on
one database do not merely contend, they can mint same-seq forks and lose published
files.

### 9.2 Command surface (v1)

`synch init` and `synch daemon run` act on the datadir directly, while `synch
daemon start` launches the latter in the background and waits for its socket;
every other command is a control-service call to a running daemon (§9.3).

```
synch init [--domain <d>]                    create device key + database (no daemon);
                                             --domain joins the zone that will name
                                             this node (§3.1)
synch daemon run|start|status|stop
synch id                                     print OriginId + current device key(s),
                                             where the name came from, and adoptions
synch key rotate|activate|retire|ls          operator-driven device-key rotation (§3.4)

synch trust add [--addr <hint>]|rm|ls        static membership; key-identified peers
                                             only — names come from zones (§3.2)
synch domain set|clear|ls|refresh            the DNSSEC zone this node belongs to
                                             (§3.2) — its members are resolved from
                                             here whether or not the zone names this
                                             node, which is how a delegate reaches its
                                             cluster; refresh re-resolves now, set and
                                             clear change the name at the next start
                                             (§3.1) and clear drops the zone's bindings
synch peer ls|sync                           inspect peers or exchange metadata now

synch source add <id> <path>|--api           configure this node to publish a space
synch source ls|scan|rm [<id>]               inspect, scan, or stop a publisher
synch replica add|set|rm <id> [options]      configure independent durable retention
synch replica ls|sync [<id>]                 coverage or an immediate content pass

synch ls   [<origin>:]<space>[/<dir>] [--all] list the unified tree (divergent paths
                                             marked with version counts; --all shows
                                             every version with attestors); origin-
                                             prefixed form lists one origin's view
synch status [<space>[/<path>]]              the version inspector: every version of
                                             a path, its attestors, side by side
synch cat  [<origin>:]<space>/<path>         verified streaming read of the selected
           [--range] [--select <policy>]     version (§8 policy; default newest)
synch cat|get --root <hex>                   read an object by content root, no path
                                             involved — how a superseded version is read
synch get  [<origin>:]<space>/<path> [-o …]  fetch the selected version to a file
           [--select <policy>]
synch fetch <url> <space>/<path>             stream an http(s) URL into the tree as
                                             this node's own version, redirects
                                             followed; a destination ending in `/`
                                             keeps the URL's file name
synch adopt path [<origin>:]<space>/<path>   adopt one version as my own
           [--select <policy>]
synch adopt tree <space>[/<dir>]             additive bulk adoption into a source
           [--select <policy>]
           [--replace] [--dry-run]
synch log  [<origin>:]<space>/<path>         per-origin publish history
synch compare <space>[/<dir>] --to <origin>  name-status diff (created/modified/deleted)
           [--from <origin>] [--json]        between two origins' published trees; no
                                             content fetched, --from defaults to self
synch pin add|rm|ls <root|space/path>        keep content in CAS regardless of policy
                                             (a path pins its selected version's root;
                                             `ls` and `rm` name every holder, since a
                                             replica may hold it too)
synch recover [--wait <dur>] [--gap <n>]     resume publishing after key/database loss (§3.4)
synch doctor                                 connectivity, DNSSEC, equivocation, GC stats,
                                             the trust policy in force and the clock it dates by
```

### 9.3 The control service

The CLI reaches the daemon by gRPC over a local, single-user transport. The schema is
`crates/synch-cli/proto/control.proto`, compiled at build time by `protox` — a pure-Rust
protobuf compiler, so no `protoc` is needed on any machine that builds this.

- **Unix**: a domain socket at `<data_dir>/control.sock`, created `0600` in a `0700`
  data directory. Stale sockets from a crashed daemon are detected by connect-then-
  fail and removed on startup.
- **Windows**: a named pipe, `\\.\pipe\synchronicity-<16 hex of the data dir path
  hash>`, so several nodes on one machine do not collide.

The socket is never exposed beyond the local machine — remote access is what the iroh
endpoint and `synch-s3` are for. HTTP/2 runs over it in the clear: the transport is a
filesystem object with an owner, so a TLS handshake between two processes of the same
user would authenticate nothing that the socket has not already established.

Authentication is a 32-byte random token in `<data_dir>/control.token` (`0600`),
regenerated on every daemon start and sent as an `x-synch-control-token-bin` header on
every call. Filesystem permissions are the primary control on Unix; the token is what
actually carries the check on Windows, where pipe ACLs are easy to get subtly wrong,
and it also prevents a different user's client from talking to a pipe it managed to
open. An `x-synch-control-version` header travels beside it: client and daemon are
normally the same binary, so a mismatch — reported with both versions named — catches
the upgrade-while-running case rather than supporting mixed versions.

The service has two surfaces, which is what the split in `proto/control.proto` is:

- **`Run`** answers a CLI subcommand (§9.2). The command travels as a `oneof` of one
  message per subcommand, carrying arguments as the text the user typed — references
  and keys are parsed by the daemon, so a parse failure comes back as an ordinary
  coded error. The response is a server stream of `line`, `chunk`, and `progress`
  frames: `synch cat`, `synch get`, and a long `synch ls` stream their payload in
  bounded chunks, so a multi-gigabyte read is never buffered in either process, and
  progress-reporting commands (`source scan`, `replica sync`) emit reports the CLI renders and
  discards.
- **`List`, `Resolve`, `Read`, `Put`, `GetConfig`, `AppendConfig`** answer a *program*
  — the S3 gateway (§9.4) — in the data itself rather than in rendered lines, naming
  space, path, and policy as separate fields. An S3 key may contain a colon, which the
  `[<origin>:]<space>/<path>` text form would read as an origin, so the gateway cannot
  go through the text parser at all.

Failures cross as a gRPC status carrying an `x-synch-error-code` trailer: the CLI
renders a daemon-side failure as its own exit status rather than a transport error,
and the gateway maps it to an HTTP status. The trailer exists because more codes are
meaningful here — `not-initialized`, `divergent`, `unavailable` — than gRPC has status
codes to keep apart.

### 9.4 S3-compatible gateway (`synch-s3`)

The second binary target exposes a subset of the S3 HTTP API, so existing S3
tooling (aws cli, rclone, restic, mc, the SDKs) can read and write a synchronicity
cluster without knowing anything about it.

**The gateway is a control client of the daemon — nothing more.** It never
opens the database, never binds an iroh endpoint, and holds no persistent state of
its own; its only datadir touch is reading `control.token`, exactly like the CLI.
This is §9.1's one-writer/one-endpoint rule applied to the gateway, and it is not
optional hygiene: a second process computing `next_seq` beside the daemon can sign
two heads at the same seq — self-equivocation broadcast cluster-wide, with the
losing batch's files recorded as scanned but present in no surviving root. Every
gateway operation is a daemon call: `Read`'s chunks stream straight into the HTTP
response, `Put` streams the HTTP body into the daemon's ingest-and-publish path,
and bucket/access-key configuration is stored by the daemon (config namespace
`s3.*`) through `GetConfig`/`AppendConfig` — so `synch-s3 bucket add`/`key add`
are control clients too, and the daemon remains the only writer and the only
endpoint. Objects of any size flow
through both directions **without either process buffering more than a chunk**.

- **Bucket mapping**: a bucket names a space of the unified tree plus a version
  policy — `synch-s3 bucket add <bucket> <space> [--policy newest|origin=<id>|strict]`
  (default `newest`; `synch-s3 bucket add <bucket> <origin>:<space>` is shorthand
  for the origin pin). Reads serve the policy-selected version of each path (§8);
  content flows through the normal verified path (local CAS first, then peer
  fetch). A `strict` bucket answers a divergent key with `409 Conflict` naming the
  versions. Writes are always publishes of the *local* node's own view — the
  version model (§8) forbids publishing someone else's — so every bucket is
  writable, and a write simply adds/updates our assertion for that path (under an
  `origin=` pin on a *foreign* origin, the bucket is effectively read-only since
  reads would not see our writes; the gateway warns on such a configuration).
- **Operations (v1)**:
  - `GetObject` — including `Range` requests, served as verified range reads (§6.1).
  - `HeadObject` — size, mtime, ETag straight from the entry metadata; no content
    fetch.
  - `ListObjectsV2` — prefix + delimiter listing as a range scan over the `f:`
    namespace (§4.3); continuation tokens are trie cursor positions.
  - `PutObject` — writes into the filesystem-source directory, then runs the normal
    ingest pipeline (hash → CAS → stage entry, §7.1); responds once durably staged,
    with the head publish following the usual batching.
  - `DeleteObject` — removes this node's copy and publishes its tombstone
    through the ordinary source scan, exactly as an `rm` in the source
    directory would (§8). It obeys the same rule a write does: a delete
    publishes *this node's own view*, because the version model cannot publish
    anyone else's. So if another origin still asserts the key, the key is still
    readable afterwards with one fewer version, and only that origin can retract
    its own — which is what `synch adopt path` of a tombstone is for. S3 has no status
    for "deleted my version of it", and inventing one would break every client
    that treats `rm` as a loop over keys, so the answer is the `204` S3 promises
    and the surviving publishers are logged. Idempotent: a key that is already
    absent here is a delete that has already happened, which is what `rm -f`,
    retried deletes, and losing a race to a concurrent writer all rely on. The
    recovery gate is taken *before* the unlink, not after: a node that cannot
    publish would otherwise remove the file and be unable to tell anyone (§3.4),
    which loses the data outright — the tombstone that justified the removal
    never gets signed.
  - **Multipart upload** — `CreateMultipartUpload`, `UploadPart`,
    `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListParts`,
    `ListMultipartUploads`. Not optional in practice: Mountpoint for Amazon S3
    wraps *every* write in a multipart upload, whatever its size, so a gateway
    without this is read-only to it.

    The upload lives in the daemon (`s3_uploads`, `s3_upload_parts`, §10), not
    in the gateway: the gateway holds no state and any number of gateway
    processes may serve one daemon, so an upload created through one has to be
    completable through another. Parts are staged one payload per part under
    `<data-dir>/s3-uploads/<id>/`, and a part row is written only once its
    payload is fsynced and renamed into place — so a row implies bytes, while
    the reverse is deliberately allowed to fail, because an unreferenced
    payload is collectable and an unbacked row is not.

    Completion assembles the named parts into a *fresh* staging file and hands
    it to the ordinary ingest pipeline, so a completed upload is an ordinary
    version. There is no rename-the-single-part shortcut: `rename(2)` fails
    across filesystems, which is the normal shape when the data dir and the
    space are on different devices, and a renamed payload keeps the mtime it
    was *uploaded* with, which is what §8's `newest` policy orders by — a
    completion would publish a version that loses to the content it supersedes.

    `state` is a three-step latch (`open → completing → completed`) rather than
    a flag. A completed row remembers its result, so a client that never saw the
    response to its completion is answered from the record instead of being told
    its upload is gone; a refused completion returns to `open`, because
    `InvalidPart` and `EntityTooSmall` are things the client can fix and retry.
    Uploads nobody finishes leak by design in S3 — its own answer is a lifecycle
    rule — so the daemon sweeps them on a TTL, and sweeps unreferenced payloads
    inside live uploads on the same pass.
  - **`aws-chunked` request bodies** — a client that checksums while it streams
    cannot put the result in a header, so it frames the body and sends the
    digest in a trailer, announcing it in `x-amz-content-sha256`. Mountpoint
    does this by default. The framing is stripped and the trailing checksum is
    *verified*; a mismatch ends the body in an error, which the daemon treats
    exactly as a truncated one — the staging file goes and nothing is published.
- **ETag** is the object's blake3 root hash, hex, quoted. S3 permits opaque ETags
  (MD5 equivalence is only conventional for non-multipart uploads); tooling that
  insists on MD5 validation must have it disabled. A multipart object's ETag
  carries **no `-N` suffix**: it is the root of the assembled bytes, so the same
  content uploaded at a different part size compares equal, and a single-part
  upload produces the ETag its `PutObject` equivalent would — neither of which
  real S3 does. A *part's* ETag is that part's own root, and a completion that
  echoes one back has it checked, which is the point of having issued it.
- **Auth**: SigV4 with static access-key pairs configured on the gateway
  (`synch-s3 access-key add`), or `--anonymous` for localhost-only development. The
  gateway authenticates S3 clients only; cluster access is the node's own
  membership (§3).
- **Headers are refused, not ignored.** A header that says the payload is
  somewhere else — `x-amz-copy-source`, `x-amz-rename-source` — makes reading
  the body the wrong thing to do, so the request is answered `NotImplemented`
  rather than with an object built from a body it does not have. Ignoring one
  is how a `mv` over a mountpoint became a truncated destination, a source that
  never went away, and a client that recorded the rename as done. The list is a
  denylist and not an allowlist: it only has to name the headers whose absence
  produces a *wrong object*, which is a closed set, where an allowlist has to
  know every header every SDK sends before it can let a working client through.
- **Not in v1**: `DeleteObjects` (the batch delete, which is its own API and its
  own body format), CopyObject and UploadPartCopy, DeleteBucket — a bucket is a
  mapping the operator made, not a thing HTTP may unmake — bucket versioning
  APIs, presigned URLs.

---

## 10. SQLite schema

One database per node, `synchronicity.db` in the platform data dir
(`~/.local/share/synchronicity`, `~/Library/Application Support/…`, `%APPDATA%\…`).
WAL mode, `synchronous=NORMAL`, all access through one mutex-guarded connection —
the invariant that matters is that every multi-step state change (head flips,
publish batches) is a single transaction and no partial state is ever observable;
read concurrency is deliberately traded away for that simplicity.

**Blocking work never runs on the runtime, and that is checked.** The store and
the CAS are synchronous by design — `synch-store` has no async runtime
dependency at all — and so is everything built directly on them: the scanner's
directory walks and BLAKE3 hashing, publish transactions, slice encode and
decode, checkout materialization, GC. None of that belongs on a tokio worker
thread. A worker hashing a 10 GB file is a worker that is not polling the
endpoint, the control socket, or a timer, and the multi-thread runtime has only
one worker per core, so a few concurrent scans would stall the daemon outright.
Every blocking operation reachable from an async context is therefore dispatched
to tokio's blocking pool (`synch_engine::blocking`, `synch_net::blocking`, and
the control server's own helper).

**Every** one, with no "short enough to stay inline" exception. There used to be
one, for a single indexed `SELECT` or a `stat`, and it was the wrong shape of
rule twice over. It measured the wrong thing: what a store call costs on a
worker is not the query, it is the wait for the one connection mutex, and a
publish batch or a GC pass holds that for as long as it runs whatever the
waiting caller wanted to read. And it made correctness a per-call-site
judgement across a couple of hundred sites, which is not a rule a reader can
check — four separate audit passes moved call sites off the runtime and each one
left some behind, because a violation compiles, passes its tests, and shows up
only as a daemon that goes quiet under load.

So the rule is now enforced rather than described. `synch_core::blocking`'s
`offload` marks its thread with a `BlockingScope`, and `Store::conn` asserts, in
debug builds, that it is either inside one or not on a multi-thread runtime at
all — the same shape as the guard that made "no `Store::conn` inside a
transaction" a named panic instead of a silent deadlock.

The violation **ends the process**, and that is not severity theatre. The check
was a `debug_assert!` first, and a panic fires inside whatever task made the
call: tokio catches it, so in a detached `tokio::spawn` it kills one task and
nothing else. `cargo test --workspace` on the commit that introduced the check
printed four of these panics and reported every suite green with exit status 0,
while in the daemon under test the same panic had silently removed a standing
loop. A checker whose failure mode is "one task quietly disappears" reproduces
exactly the defect it was written to stop, so this one aborts.

An assertion only earns its keep where something runs it. It is silent on a
current-thread runtime — one worker the test itself is driving is not the hazard
— so a `#[tokio::test]` suite left at the default flavor would have been a
checker nothing ever executed, and that is precisely how the previous passes
kept leaving call sites behind. Every integration suite that drives an async
production surface therefore runs `flavor = "multi_thread"`: the cluster and
two-node sync paths, recovery, the control socket, and the S3 gateway. Between
them they cover the accept/exchange/fetch/publish/maintain path, every control
command, and every gateway verb, on the same runtime flavor the daemon binary
starts. A test's own body drives its world synchronously — that is what a test
thread is for — so it declares that with a `BlockingScope`, which exempts that
one thread and leaves every runtime worker the node uses checked. In-crate
`#[cfg(test)]` suites follow the same rule wherever they drive an async
production surface; the cloud attach module is the one that had to be converted
after the fact, and four live violations were behind it.

What the check covers is `Store::conn`, so it sees blocking work that reaches
the connection and not blocking *CPU* that never does. That is most of it —
the scanner, the CAS, GC and checkout writes all end at a row — but not all of
it, and the gap is real: `Proven::absorb` is pure CPU and was found by reading,
not by the checker.

Standing loops are supervised by their own liveness, not only by this rule.
The daemon reads every loop's join result rather than discarding it: a loop that
ends by panicking is gone for the process's lifetime, nothing restarts it, and
a daemon that keeps answering `daemon status` while it has no publisher is worse
than one that exits.

This relocates the queue rather than removing it: the one connection mutex is
still the bottleneck, and a long exclusive holder (a GC pass, a full publish
batch) now parks blocking-pool threads instead of runtime workers. What it buys
is that the parked threads are no longer the ones that have to poll the
endpoint, the timers, and every other connection — the daemon stays responsive
while it is slow, rather than going silent. Since a blocking task cannot be
cancelled, anything that must happen even if the caller walks away — restaging a
failed publish batch — belongs inside the closure, not around the await.

**Migrations.** The schema's single source of truth is an ordered chain of
migrations: `MIGRATIONS[v]` takes a database from version `v` to `v+1`, and version
1 is the original schema. A fresh database is built by replaying the whole chain
from empty — there is no separate "current schema" bootstrap path that could drift
from what upgrades produce; the DDL below documents the final shape, and a test
asserts that replaying the chain yields exactly it (compared via `sqlite_master`).
Rules:

- Each migration runs in **one transaction**, with the `schema_version` stamp
  updated inside that same transaction — a crash mid-upgrade leaves a database that
  is exactly at some version, never between two.
- Migrations only ever move forward; a database stamped newer than the binary knows
  is **refused**, not probed. No `IF NOT EXISTS` anywhere — whether an object exists
  is determined by the version number, never discovered by trying.
- Anything a plain SQL statement can't express (a backfill, a table rewrite) is a
  Rust migration step in the same numbered chain, under the same transaction rule.

`config` also holds the membership domain — the zone this node belongs to, which
decides both where its name comes from (§3.1) and whose member records it resolves
(§3.2) — it has to be readable before there is a name to read it out of — the name
itself in `self_origin_id`, and, after a recovery (§3.4), the `publish_floor`.

```sql
-- node & config
CREATE TABLE config        (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                                         -- 'schema_version', 'membership.domain',
                                         -- 'self_origin_id', 'publish_floor'
CREATE TABLE device_keys (                -- own keys; >1 row only during rotation
  node_id     BLOB PRIMARY KEY,
  secret_key  BLOB NOT NULL,
  state       TEXT NOT NULL,             -- 'active' | 'retiring'
  created_at  INTEGER NOT NULL
);

-- every identity this node has adopted from the zone (§3.1). A relabel is
-- unattended and destructive, so the trail of what was adopted and when is
-- the only record of it; `synch id` reads this.
CREATE TABLE identity_history (
  at          INTEGER NOT NULL,
  previous    TEXT,                      -- NULL for this node's first name
  adopted     TEXT NOT NULL,
  node_id     BLOB NOT NULL,             -- the device key the zone bound
  domain      TEXT NOT NULL
);

-- membership: OriginId → device-key bindings.
-- origin_id is the canonical rendering: '<id>@<domain>' or 'key:<z-base32>'.
-- `domain` names the zone a dns binding came from. A node resolves only its
-- own zone (§3.1), so this is one value at any instant — but not across a
-- domain change, which is exactly when every binding from the zone being
-- left has to be found and dropped. `key:<z-base32>` renders no domain of
-- its own, so an `id=`-less record's row would otherwise not say which zone
-- vouched for it. '' rather than NULL for a static binding, because SQLite
-- admits no expression in a PRIMARY KEY.
CREATE TABLE bindings (
  origin_id    TEXT NOT NULL,
  node_id      BLOB NOT NULL,            -- bound device key (32 bytes)
  source       TEXT NOT NULL,            -- 'static' | 'dns' | 'delegated'
  domain       TEXT NOT NULL DEFAULT '', -- the membership domain, '' if not dns
  issuer       TEXT NOT NULL DEFAULT '', -- for delegated source: the vouching origin
  spaces       TEXT,                     -- for delegated source: newline-separated space ids
  note         TEXT,
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,                  -- NULL for static
  PRIMARY KEY (origin_id, node_id, source, domain, issuer)
);
CREATE INDEX bindings_by_key    ON bindings (node_id);   -- connection-accept lookup
CREATE INDEX bindings_by_issuer ON bindings (issuer);    -- the §3.5 cascade

-- mptsync
-- A slot is a *pointer* at a signed head, not a copy of one: the signature,
-- and the `created_at` it covers, live once in `head_history`. Copying them
-- here meant every head that reached the complete slot was written twice under
-- two separate rules — on arrival and again on displacement, the second
-- provably redundant — and the duplication then had to be patched around, with
-- an explicit retention exemption so pruning would not delete the rows the
-- current heads shadowed, and a UNION across both tables for the GC mark set.
CREATE TABLE heads (
  origin_id   TEXT NOT NULL,
  slot        TEXT NOT NULL,             -- 'complete': fully materialized, servable, backs `entries`
                                         -- 'pending' : fetch in progress (§5.2 resumability)
  seq         INTEGER NOT NULL,          -- with root, names a row of head_history
  root        BLOB NOT NULL,
  received_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,          -- when the signed_by↔origin binding was checked
  PRIMARY KEY (origin_id, slot)
);
CREATE TABLE head_history  (origin_id TEXT, seq INTEGER, root BLOB, created_at INTEGER,
                            signed_by BLOB, sig BLOB,    -- sig kept: provable fork/equivocation evidence
                            recorded_at INTEGER NOT NULL,-- when this node received the row: what
                                                         -- retention keys on, since created_at is
                                                         -- the signer's own unclamped choice
                            PRIMARY KEY (origin_id, seq, root)); -- same-seq forks both stored;
                                                                 -- for §8 history + §3.4 evidence,
                                                                 -- pruned by retention
CREATE TABLE trie_nodes    (hash BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE trie_values   (hash BLOB PRIMARY KEY, data BLOB NOT NULL);
-- Positions a peer serving a scoped view refused to show (§5.5). A boundary,
-- not an absence: without it a scoped node could not tell "the peer does not
-- have this" from "the peer will not show me this", and its completeness walk
-- would never settle. Keyed by position as well as hash: a refusal is about
-- where a node sits, and the same node can stand at two spine positions and
-- be refused at only one of them.
CREATE TABLE redacted_nodes (
  hash BLOB NOT NULL,
  path BLOB NOT NULL,
  PRIMARY KEY (hash, path)
);
-- which origin's trie a node was served as part of: presence with provenance
-- for a confined origin's root (v27, §5.5)
CREATE TABLE trie_node_origins (
  origin_id TEXT NOT NULL,
  hash      BLOB NOT NULL,
  PRIMARY KEY (origin_id, hash)
);
CREATE INDEX trie_node_origins_by_hash ON trie_node_origins (hash);

-- materialized views of trie leaves (rebuilt incrementally from diffs)
CREATE TABLE entries (
  origin_id   TEXT NOT NULL,
  space       TEXT NOT NULL,
  path        TEXT NOT NULL,
  kind        INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  mtime_ns    INTEGER NOT NULL,
  unix_mode   INTEGER,                   -- advisory mode a checkout reproduces (§7.2)
  content     BLOB,                      -- object root hash
  seq         INTEGER NOT NULL,
  prev        BLOB,
  symlink_target TEXT,                   -- link target; half of a content-less
                                         --   kind's version identity (§8)
  PRIMARY KEY (origin_id, space, path)
);
CREATE INDEX entries_by_path    ON entries (space, path);
CREATE INDEX entries_by_content ON entries (content);
CREATE INDEX entries_by_space_content ON entries (space, content);

CREATE TABLE blob_providers (
  object_root BLOB NOT NULL,
  origin_id   TEXT NOT NULL,
  size        INTEGER NOT NULL,
  complete    INTEGER NOT NULL,
  spans       BLOB,                      -- coalesced 16 MiB-granularity byte spans when partial
  PRIMARY KEY (object_root, origin_id)
);
CREATE INDEX blob_providers_by_origin ON blob_providers (origin_id);

-- local content store index
CREATE TABLE blobs (
  root        BLOB PRIMARY KEY,
  size        INTEGER NOT NULL,
  complete    INTEGER NOT NULL,
  bitmap      BLOB,                      -- verified 16 KiB-group bitmap when partial
  inline      BLOB,                      -- payload for small blobs, else NULL (fs store)
  last_access INTEGER NOT NULL,
  durable     INTEGER NOT NULL DEFAULT 0  -- backend stable-storage promise (docs/SERVERLESS.md §5)
);
CREATE TABLE pins (                       -- who holds an object (docs/REPLICATION.md §3.1)
  root          BLOB NOT NULL,
  holder        TEXT NOT NULL,            -- 'operator' | 'source:<space>' | 'replica:<space>'
  created_at    INTEGER NOT NULL,
  release_after INTEGER,                  -- NULL = held; set = due to go then
  PRIMARY KEY (root, holder)
);
CREATE INDEX pins_pending_release ON pins (release_after) WHERE release_after IS NOT NULL;
CREATE INDEX pins_by_holder ON pins (holder);
CREATE TABLE content_want (               -- content a durable role lacks (§3.3)
  root         BLOB NOT NULL,
  holder       TEXT NOT NULL,
  size         INTEGER NOT NULL,
  prev         BLOB,                      -- delta donor: the root this version replaced
  first_wanted INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_attempt INTEGER,
  last_error   TEXT,
  PRIMARY KEY (root, holder)
);
CREATE INDEX content_want_by_holder ON content_want (holder, first_wanted);
-- indexing / engine state
CREATE TABLE sources (
  space       TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('filesystem', 'api')),
  local_path  TEXT,
  CHECK ((kind = 'filesystem' AND local_path IS NOT NULL) OR
         (kind = 'api' AND local_path IS NULL))
);
CREATE TABLE replicas (
  space          TEXT PRIMARY KEY,
  retention      TEXT NOT NULL CHECK (retention IN ('current', 'forever')),
  grace_seconds  INTEGER,
  budget_bytes   INTEGER,
  checkout_path  TEXT,
  CHECK ((retention = 'current' AND grace_seconds IS NOT NULL) OR
         (retention = 'forever' AND grace_seconds IS NULL))
);
CREATE TABLE local_files   (space TEXT, relpath TEXT, size INTEGER, mtime_ns INTEGER,
                            file_id BLOB, content BLOB, scanned_at INTEGER,
                            PRIMARY KEY (space, relpath));
CREATE TABLE peers_seen    (node_id BLOB PRIMARY KEY, last_addr BLOB, last_seen INTEGER,
                            last_sync INTEGER, latency_ewma_us INTEGER);

-- recovery (§3.4): the greatest (seq, root) any peer has advertised for an origin,
-- observed from Hello summaries — never verified, never adopted as a head
CREATE TABLE observed_heads (origin_id TEXT PRIMARY KEY, seq INTEGER NOT NULL,
                             root BLOB NOT NULL, complete INTEGER NOT NULL,
                             claimed_by BLOB,   -- which peer asserted it (§3.4)
                             observed_at INTEGER NOT NULL);

-- S3 multipart uploads in flight (§9.4). The gateway holds no state and any
-- number of gateway processes may serve one daemon, so an upload created
-- through one and completed through another lives here or nowhere.
-- state is open -> completing -> completed; a completed row remembers its
-- result so a retried CompleteMultipartUpload replays it rather than reporting
-- an upload that no longer exists.
CREATE TABLE s3_uploads (id TEXT PRIMARY KEY,  -- the UploadId: 32 random hex
                         space TEXT NOT NULL, path TEXT NOT NULL,
                         principal TEXT,           -- the access key that opened it
                         created_ns INTEGER NOT NULL,
                         state TEXT NOT NULL
                           CHECK (state IN ('open','completing','completed')),
                         etag BLOB, size INTEGER,   -- the result, once completed
                         latched_ns INTEGER,        -- when a completion took the latch
                         completed_ns INTEGER);
CREATE INDEX s3_uploads_by_age ON s3_uploads (created_ns);
CREATE INDEX s3_uploads_by_target ON s3_uploads (space, path);

-- One row per part whose payload is already durable: a row implies bytes, and
-- never the reverse (a crash before the row leaves a collectable orphan file).
CREATE TABLE s3_upload_parts (upload TEXT NOT NULL
                                REFERENCES s3_uploads(id) ON DELETE CASCADE,
                              number INTEGER NOT NULL,   -- 1..=10000
                              file TEXT NOT NULL,        -- name within the upload dir
                              size INTEGER NOT NULL,
                              root BLOB NOT NULL,        -- the part's own blake3 root
                              created_ns INTEGER NOT NULL,
                              PRIMARY KEY (upload, number));

-- ---- sockets (`docs/SOCKETS.md` §3) --------------------------------------
--
-- Local operator state, never published and never replicated. Publication
-- cannot gate execution: `synch adopt path`, `synch adopt tree --replace` and an S3 PUT all
-- write bytes into a filesystem-source directory that the scanner publishes as this
-- node's own view. Activating a path makes those write paths deployment
-- channels for it: while the row exists, whatever the path holds is a socket
-- and its current content serves under its own embedded manifest. No content
-- root is ever an authorization pin.
CREATE TABLE socket_activations (space TEXT NOT NULL, path TEXT NOT NULL,
                      config TEXT NOT NULL DEFAULT '',   -- newline-separated k=v
                      max_streams INTEGER,       -- NULL: the daemon's default
                      note TEXT NOT NULL DEFAULT '',
                      activated_at INTEGER NOT NULL,
                      PRIMARY KEY (space, path));
```

The trie is authoritative; `entries` and `blob_providers` are derived caches and can
always be rebuilt from `trie_nodes` (`synch repair rebuild-views`).

---

## 11. Crate layout

Cargo workspace. All logic lives in reusable library crates — the two binaries are
thin shells, so any Rust application can embed a full node by depending on
`synch-engine`. Crate names carry the `synch-` prefix throughout (`sync` is far too
common a name to squat on — coreutils, countless crates):

```
synchronicity/
├── crates/
│   ├── synch-core     # types: OriginId, Hash, records, keys, signed heads; postcard schemas
│   ├── synch-mpt      # the Merkle-Patricia Trie: nodes, hashing, diff, proofs, cursors
│   ├── synch-store    # SQLite layer + CAS (bao-tree outboards, bitmaps, GC)
│   ├── synch-net      # iroh endpoint, ALPN handlers: mptsync + blob protocols, DNSSEC resolver
│   ├── synch-engine   # the embeddable node API: scanner/watcher/publisher, anti-entropy
│   │                  # scheduler, fetcher, checkouts — everything a host app needs
│   ├── synch-cli      # binary target `synch`: the daemon, the control service
│   │                  # (schema, server, client), and the clap CLI that drives it
│   └── synch-s3       # binary target `synch-s3`: S3-compatible gateway (§9.4)
└── .github/workflows/ # ci.yml, release.yml (below)
```

Key dependencies: `iroh`, `bao-tree`, `blake3`, `ed25519-dalek` (via iroh),
`rusqlite` (bundled), `notify`, `hickory-resolver` (dnssec), `tokio`, `postcard`,
`serde`, `clap`, `tracing`, `directories`; `tonic`/`prost` (with `protox` at build
time) for the control service; `axum`/`hyper` (rustls) for `synch-s3`.

Testing strategy:

- `synch-mpt`: property tests (proptest) — insert/delete/iterate vs. a BTreeMap model;
  root-hash determinism; diff completeness (diff(a,b) applied to a yields b).
- `mptsync`: in-memory duplex-transport simulation of N nodes with random partitions,
  message loss, and interleaved publishes; assert convergence of all heads and tries.
- `synch-engine`: temp-dir integration tests across 2–3 real endpoints on localhost.
- `synch-cli`: control round-trips against a daemon in a temp datadir on both
  transports — every command variant, a streamed multi-megabyte `cat`, a rejected bad
  token, a version mismatch, a stale socket left by a killed daemon, and the
  no-daemon error path.
- `synch-s3`: integration tests driving the gateway over plain HTTP (GET/HEAD/LIST/
  PUT round-trips, Range reads, ETag checks).

CI (GitHub Actions):

- `ci.yml` — on push and pull request: rustfmt check, `clippy -D warnings`, and the
  full test suite across a linux / macos / windows matrix.
- `release.yml` — on `v*` tags: release builds of both binaries for
  x86_64-unknown-linux-musl (fully static), aarch64-unknown-linux-musl,
  macOS (arm64 + x86_64), and Windows x86_64, attached to a GitHub Release with
  checksums.

---

## 12. Security considerations

- **Transport**: iroh QUIC — encrypted, mutually authenticated by NodeId. No plaintext
  path exists.
- **Authorization**: membership-based (§3.2), enforced on accept and per-origin on
  every head/record; a trusted peer relaying data for an untrusted origin is ignored.
  Binary for members, and space-scoped for delegates (§3.5): a delegated key may read
  and publish only within its list, enforced at four points — the trie serve (by
  position, §5.5), the blob serve (by whether a granted path names the content), the
  head promotion of the delegated origin (its trie must hold nothing outside the
  list), and the ordinary accept gate, which is unchanged because a delegated binding
  is a binding. What delegation does *not* do is constrain the members that issue it:
  a rooted member is unrestricted by construction, so any of them may delegate any
  space. That power is not created by delegation — a member already reads every space
  and can hand over its device secret — but delegation is what makes an exercise of it
  bounded, dated and published where `synch delegate ls` on any node can read it.
  Sockets extend what membership grants, and both extensions are operator-gated: a
  member may *invoke* programs at paths the callee has activated (docs/SOCKETS.md),
  and such a program may, within prefixes its own manifest declares, cause the callee
  to *publish* new versions of its own view (docs/TREE-WRITES.md). Every such write
  is the callee's own assertion, so the version model bounds it — divergence stays
  first-class and visible, and no other origin's assertion can be touched. An org
  that hosts a network on a control plane (docs/CLOUD-DATAPLANE.md) extends the same
  grant once more: that control plane's hosted member may publish versions on the
  org's members' behalf, through the control plane's file API, attributed to that
  member and bounded by the version model as every publish is
  (docs/CLOUD-WRITES.md).
- **Protocol integrity**: trie nodes are verified against requested hashes, heads
  against origin signatures, and content received from peers against object roots per
  16 KiB group. A compromised peer can withhold, but never inject bytes. LocalFs and
  the configured OpenDAL service are trusted storage boundaries; stored bytes are not
  re-hashed by the application.
- **DNSSEC blast radius**: whoever controls the membership domain (or its DNSSEC keys)
  controls membership — adding a hostile node grants full read access and publish
  rights. With named origins the exposure is strictly larger: the domain controller
  can *rebind an existing origin's `id=` to an attacker key*, hijacking that
  namespace for future publishes. It also controls what each member believes its own
  name to be, since a node takes its `id=` from the same record set (§3.1): editing
  the record that names a member's key relabels that member on its next start,
  dropping its published views and restarting it at `seq = 1` under the new name,
  unattended. That is the cost of the zone being the single authority on a name —
  a node holds no second opinion to check it against, so `identity_history` and
  `synch doctor` make every adoption visible after the fact and nothing prevents one
  in advance. Established peers won't accept lower seqs and
  retain signed history as evidence — but that is per-peer protection only (see the
  rollback bullet below); new peers get none, and forward overwrites at higher seq
  remain possible for any binding holder. The protocol still makes no attempt to
  distinguish a legitimate rotation from a domain-level takeover *cryptographically* —
  a continuity scheme (old-key cross-signing of rebindings) was considered and
  deliberately deferred (§13).

  What v1 adds instead is **transparency**, which does not prevent the takeover but
  makes it public: the zone key that signed a membership answer must additionally
  appear in Sigstore's Rekor log, with an offline-verifiable inclusion proof carried
  inside the zone. An attacker who has taken the registrar must therefore either log
  their key under the operator's own apex, where a monitor watching that delegation
  path reports it, or fail client validation. Covert targeted substitution stops
  being covert. It is on by default on the client side (`--rekor off` states the
  opt-out), so domain-controller power is no longer something a deployment simply
  accepts. **See [docs/REKOR-ZONE-KEY.md](docs/REKOR-ZONE-KEY.md)** for
  the mechanism, its threat model, and — importantly — what it still does not
  protect against: key *theft* leaves a valid record, and the monitor cannot tell
  your rotation from a substitution. It tells you a key was authorized; your own
  record of what you published is the discriminator.

  Everything else v1 provides is unchanged: every rebinding is logged and listed by
  `synch doctor`, plus the base mitigations — validated in-process resolution (no
  resolver trust), TTL-bounded caching, and `synch doctor` surfacing the full live
  member set, bindings, and their provenance. Deployments that can't accept
  domain-controller power use static trust only, and pay its price in full: every
  origin is key-identified, so nothing has a name and nothing rotates (§3.1). The
  flip side of
  failing closed is worth stating: a prolonged DNSSEC outage expires dns bindings
  and shrinks the member set toward static-only — the cluster degrades to a halt
  rather than falling open. Deliberate.
- **Equivocation & rollback — stated precisely**: seq monotonicity is a *per-peer*
  property: each peer refuses heads older than what it has already verified, from
  first contact onward (trust-on-first-use). It is **not** a global guarantee. A new
  peer with no prior state has no floor — a binding holder (including a domain
  hijacker) can feed it fabricated or truncated history wholesale; its protection is
  epidemic, not cryptographic: one `Hello` with any honest, fresher peer raises it to
  the cluster's floor via the ordinary max-head rule. And any *current* binding
  holder can always publish `seq_max+1` with arbitrary content — an effective
  forward wipe no seq rule prevents; `head_history` retention plus fork-evidence
  surfacing (§3.4) makes it visible. Same-seq forks are detected
  and reported with retained signed proofs (§4.4). A malicious *origin* publishing
  garbage about its own files pollutes its own namespace, which the version model
  already treats as "their claim, not truth" — but the unified tree (§8) is a
  merge across namespaces by `(space, path)`, and `space` is a plain string in the
  trie key any member may publish under. Under `newest`, a member can therefore
  put its own version of any path in front of every other member's: `mtime_ns` is
  its own assertion, and while a read orders it as of the reader's clock rather
  than as of the number published, an entry claiming the present instant is
  exactly what an honest publish claims. What it cannot do is *remove* another
  member's file: a tombstone asserts that the publishing origin deleted its copy,
  so it takes that origin's version out of the running and leaves the path
  carrying the newest live version among the rest (§8). A space where one
  member's assertions must not stand in for another's is a space to read under
  `origin=` or `strict`, which select from one origin's view and refuse
  divergence respectively.
- **Resource exhaustion — a trust stance, not a defense**: every peer that can send
  us a request at all is an authorized member (§3.2), and members are extended basic
  trust not to DoS each other. There are therefore **no per-peer rate limits and no
  per-origin publish quotas** — a member behaving abusively is a membership problem,
  and the remedy is the membership machinery: `synch trust rm` or removal from the
  DNS record set cuts the node off from all *future* participation — connections
  refused, new heads ignored.

  The stance holds because the party bearing the cost is the party holding the
  remedy. That equivalence is what an *embedder* can break, and one does: the cloud
  data plane runs one node per hosted network in one process, and org A's members are
  not org B's to curate. So `NetOptions::max_inflight_requests` exists — off by
  default, because a daemon serving one cluster wants the stance above — and caps how
  much of the shared blocking pool one endpoint's peers can hold at once. It is a
  concurrency bound rather than a rate limit: an honest peer waits microseconds for a
  slot and never notices. See docs/CLOUD-DATAPLANE.md §9.1 for what a multi-tenant
  host must add on top of this section, and — stated there rather than left implied —
  what it still does not bound. Data it already published stays replicated (nothing
  cascades deletion through everyone's tries — that would hand any removal a blast
  radius) and ages out with normal retention; `synch doctor` lists origins whose
  data is held without a live binding. What remains are sanity bounds that
  cap the cost of any *single* malformed or extreme message: `GetNodes`/`GetValues`
  batches are capped at 256 hashes *and* at half a frame of payload, because a
  count alone bounds nothing when the payloads are the publishing origin's to
  choose; trie keys are bounded to 4 KiB and trie values to 32 KiB; and the fetch
  that ingests a peer's trie stops descending at the ~8 K nibbles a 4 KiB key
  reaches. That last one is a canonicality rule about *positions*, and the key
  bound does not imply it: the node encoding caps one node's nibble run, so
  without it a chain reaching past that depth was pulled, committed, vouched for
  by `is_complete`, reflected in no `entries` row, and marked by every GC pass
  thereafter. It is not a quota — the ingest walk deduplicates on hash, so what a
  member can make a peer store is what it uploads, which is the membership
  question above rather than a sanity bound. A `GetSlice` is bounded the same way, on
  both axes: at
  most 512 groups are encoded per exchange (§6.4), and at most 4 096 ranges are
  accepted in one request, because the range set operations are quadratic in the
  number of ranges. Trust does not extend to the *shape* of replicated
  structure, because a member gets it wrong by accident as readily as on
  purpose: nothing canonicalizes the node graph a peer serves, so every walk
  over it — the promotion diff above all — keeps its frames on the heap and
  stops descending past the ~8 K nibbles a valid key can occupy. A recursive
  walk would meet a hand-built deep chain with a stack overflow, and that aborts
  the process rather than failing the exchange. In the same spirit, a record
  this node cannot apply fails *its own origin* and no other: the head does not
  flip, the exchange carries on, and the count of origins left behind is in the
  sync report.
- **Privacy**: metadata (paths, sizes, mtimes) is visible to all *members* — inherent
  to omnipresence — and to a *delegate* only within the spaces it was delegated, which
  §5.5 enforces by never sending the rest and states the exact residue of. Content is fetched on demand, so bytes only land where requested or
  mirrored. At-rest encryption of the CAS and DB is delegated to OS disk encryption in
  v1 (noted in §13).

---

## 13. Future work (explicit non-v1)

- Per-space ACLs on *rooted* members. §3.5 confines a delegated node to a space
  list; it does not confine the members that issue delegations, and a rooted member
  is unrestricted by construction.
- Rotation continuity attestation: cryptographically distinguishing a legitimate key
  rotation from a domain-level rebinding (e.g. an old-key cross-signed rotation log).
  Still not v1. Note that the transparency layer shipped since (§12,
  [docs/REKOR-ZONE-KEY.md](docs/REKOR-ZONE-KEY.md)) attacks the same exposure from
  the other side — it makes a substitution *public* rather than making it
  *distinguishable* — so this remains the thing that would let a client tell the
  two apart on its own, without a monitor and without an operator's records.
- Encrypted spaces (per-space content keys; metadata padding).
- Partial trie replication *for scale*. §5.5 ships the mechanism, driven by
  delegation rather than by cluster size; pointing it at very large clusters is a
  policy question that has not been answered.
- Smarter placement policies ("keep ≥ 2 replicas of every object cluster-wide"),
  built on the same `BlobAd` availability data. The role such a policy would be
  placed on — a *replica* of a space, holding a whole copy of every version the
  unified tree currently names and releasing a root once the tree stops naming
  it — is implemented as an independent local role (`synch replica add <id>`),
  while cluster-wide placement remains
  where this bullet has it. (Content replication in that sense, not the
  trie-scope sense of §5.5; and on a cloud backend, a claim and a cache rather
  than a bill — `docs/SERVERLESS.md` §6.5.)
- Optional platform-specific mounts (FUSE/WinFsp/NFSv3-loopback) as *plugins*,
  never as core. (HTTP access ships as the S3 gateway, §9.4.)
- Bandwidth scheduling / QoS between anti-entropy and bulk fetches.

---

## 14. End-to-end walkthrough

Three nodes: `laptop`, `nas`, `vps`, all in `_synchronicity.cluster.example.com`.

0. Each ran `synch init --domain cluster.example.com` and had its printed device key
   published in one TXT record. Each daemon resolved the zone at startup, found the
   record naming its own key, and took that record's `id=` as its name (§3.1).
1. `nas` runs `synch source add media /srv/media`. The scanner hashes 40 k files,
   the publisher signs head `(seq=1, root=r1)` containing 40 k `f:` records and 40 k
   per-object `b:` ads.
2. `laptop` connects (dns-discovered membership, iroh-dialed), `Hello` exchanges heads,
   sees `nas@1 > nas@0`, pulls the trie breadth-first with `GetNodes` — a few MB of
   trie nodes for 40 k entries. It now knows every path, size, mtime, and object root
   on the NAS, holding zero content bytes.
3. `laptop` runs `synch cat nas:media/talks/keynote.mp4 --range 0..`. Providers for the
   root resolve to `{nas}`; the fetcher streams bao-verified slices; the player seeks —
   each seek is a new verified range read. Fetched groups land in laptop's CAS, and
   its next milestone ad update (§6.3) advertises its partial — later complete —
   copy of the object.
4. `vps` runs `synch replica add media --checkout /srv/media-view`. Its replica
   first durably acquires the content, then projects the unified newest view.
   Provider resolution returns `{nas, laptop}` and it can pull from both.
5. `nas` edits a file; `laptop` had edited its own copy of the same path an hour
   earlier. Watcher → rescan → head `(seq=2, r2)` → `HeadPush` to both peers; each
   pulls exactly the changed path's trie nodes. `synch ls media` on any node still
   shows one tree, with that path marked `⑂2`: two versions, one asserted by `nas`,
   one by `laptop`. `synch cat media/that/file` reads the newest deterministically;
  `--select origin=laptop@cluster.example` reads the other; `synch status
  media/that/file` lays both out —
   divergence visible, nothing auto-resolved, adoption one `synch adopt path` away, after
   which the path collapses back to a single unanimous version.
6. `nas`'s operator rotates its key: `synch key rotate`, publish the second
   `id=nas nk=<K_new>` TXT record, wait for propagation, then `synch key activate
   <K_new>` — which re-signs the head as `K_new` at `seq=3` and brings up the
   `K_new` endpoint alongside the old one for the TTL window. Nothing here happens
   on the node's own initiative (§3.4). `laptop` and `vps` pick up the rebinding on
   their next validated DNS refresh and now dial `K_new`. Every trie node, entry,
   and blob ad is untouched — `nas@cluster…` is the same origin it always was. The
   operator removes the old TXT record and runs `synch key retire <K_old>` once it
   has expired out of everyone's bindings a TTL later.

---

*This document is the v0.1 design baseline. Sections are numbered for reference in
issues and PRs; substantive changes should update this file in the same PR.*
