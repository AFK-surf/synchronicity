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
membership domain.

| Membership domain | Own `OriginId`         | Rotatable | Authority on the name |
|-------------------|------------------------|-----------|-----------------------|
| none              | `Key(K_active)`        | no        | the device key itself |
| one, `<d>`        | `Named { domain, id }` | yes       | the zone (below)      |

A domainless node needs no identity configuration at all: the identity *is* the key,
self-certifying and not rotatable. A named, rotatable identity comes from a zone and
only from a zone — there is no way to name a node by hand, because a hand-set name is
a second authority on something the zone already decides. An isolated deployment that
wants named origins runs its own signed root and points `--dnssec-anchor` at it (§3.2).

**One node, one zone.** The domain in that slot is the `@domain` half of the node's own
name: a node resolves the zone that names it. A node with no domain resolves no zone at
all and trusts only what it is told statically (§3.2). Every dns binding a node holds
is therefore for an origin in its own zone.

**Identity discovery.** A node with a membership domain resolves it once at `synch
daemon run`, before the endpoint binds and before any loop starts, and freezes the
answer:
**a node's identity is immutable for the lifetime of the process**. Everything that
reads it — seq monotonicity, trie keying, head signing — sees one value from first
call to shutdown, which is exactly what lets a *changed* identity be adopted with no
daemon stopped.

The oracle is the one §3.2's malformed-set rules already define: the origin the
validated record set binds this node's active device key to, or nothing at all when
that key is absent from the set or ambiguous within it. Only a `Named` result is
adopted — a key published without an `id=` resolves to `Key(nk)`, and adopting that
would quietly turn a rotatable node into a non-rotatable one on the strength of a
missing field, so it is refused and reported instead.

| Stored identity            | Resolution        | Action                                            |
|----------------------------|-------------------|---------------------------------------------------|
| none                       | `<id>@<domain>`   | adopt it; first boot                              |
| `o`                        | `o`               | nothing; steady state                             |
| `p`                        | some other `o`    | adopt `o`, migrating local state (below)          |
| none                       | no match          | **unidentified**: poll                            |
| `p`, from the current zone | no match          | keep `p`, report it, do not poll                  |
| `p`, from a replaced zone  | no match          | **unidentified**: poll; `p`'s state left intact   |
| any                        | resolution failed | keep the stored identity if there is one, else poll |

"A validated answer that says nothing about this key" and "no validated answer" are
different facts and never collapse. A resolution failure — unreachable resolver,
expired RRSIG, a clock that dates nothing (§3.2) — is not evidence that a record was
withdrawn, and a node that un-identified itself on one would lose its name every time
its resolver hiccuped. Failing closed here means keeping what you have.

The same asymmetry covers a record that genuinely *is* withdrawn: the node keeps its
name, keeps signing, and keeps a coherent trie, while its bindings expire at every
peer on `dns_trust_grace` and its data goes unavailable per the edge §3.4 accepts.
Un-adopting would destroy local state on top of that, irreversibly, and buy nothing.

**The unidentified state.** A node with a device key and no identity can speak QUIC
and has nothing to say: it cannot sign heads, publish, or scan into a trie. It is
also inert in practice — the same absent record leaves every peer without a binding
for its key, so no peer accepts its connections. It runs the reduced service §3.4's
recovery state establishes: control socket up so `synch daemon status` and `synch
doctor` can explain the state, endpoint bound, and every publishing command failing
with the record to publish filled in (`v=sync1 id=<name> nk=<K> apex=<apex>`).

The identity poll is a one-shot-until-success task, separate from the membership
refresh loop: it stops the moment an identity is adopted and never runs again in that
process, while the membership loop — which is about *other* nodes — keeps running. It
re-queries on the negative answer's TTL, clamped to `[30s, 5m]`: tight enough that
publishing the record and watching the node come up feels immediate, loose enough not
to flood a name that does not exist yet. `synch domain refresh` triggers it at once,
so nobody waits on the clamp.

Bringing up a machine is therefore `synch init --domain cluster.example.com`, which
prints the device key, then publishing one TXT record naming that key. The ordering is
forced: a record cannot name a key that does not exist yet.

**Adopting a changed identity.** When the zone binds this node's key to a different
`id=` than the one it holds, the new name is adopted on the next start, in one
transaction, before the endpoint binds: the self binding moves, both head slots and
the old origin's `entries` and `blob_providers` views are dropped, any mirror policy
pinned to the old origin (§7.2) is rewritten to the new one, and `publish_floor` is
cleared, since it floors history under a name nobody holds. Blobs stay — they are
content-addressed — and the next scan republishes them under the new name.
`head_history` is untouched, so heads signed under the old name survive as the fork
evidence §4.4 makes of them. No daemon has to be stopped, because the migration runs
before there is one.

It fires only on a validated answer yielding a single unambiguous `Named` origin for
the active device key: never on a resolution failure, never on ambiguity, never on
absence, never on an `id=`-less match. That precondition is the whole safety argument
for an unattended and destructive operation, and every part of it is a rule §3.2
enforces anyway.

`synch domain set` and `synch domain clear` are the same event arriving by another
route, and take effect the same way. What fills the domain slot is what names the
node, so changing it changes where the name comes from — one zone to another, no zone
to a zone, or a zone back to the device key — and each is the migration above, run at
the next start, dropping the bindings of any zone left behind. The running daemon is
untouched by the edit: it goes on resolving the zone its current name comes from, so
one node, one zone holds at every instant.

A node moving *to* a zone waits for that zone to name it: until it does it is
unidentified and polling (the table above), holding intact the state published under
its previous name but signing nothing new. Clearing the slot waits for nothing, since
the device key is always there to name a node.

A relabel is not cheap, and `synch doctor` says so: the new origin starts at `seq = 1`,
peers keep the old origin's trie until its bindings expire, and the cluster briefly
lists the machine twice. Every adoption is recorded durably in `identity_history`
(§10) and surfaced by `synch id` and `synch doctor`. §3.4 makes a change of signing
identity a deliberate act with an audit trail; here the deliberateness is the zone
operator's, one edit upstream, so the trail carries the weight alone.

### 3.2 Trust sources

A remote node is **trusted** iff at least one of the following holds:

1. **Static trust** — its public key was explicitly added:

   ```
   synch trust add <node-id> [--note "zeynep's laptop"]
   ```

   Static trust is unilateral per node and never expires (until removed). For two nodes
   to sync, *each* must trust the other; there is no transitive trust. The key is the
   identity: static trust binds `OriginId::Key`, never a name.

   Naming a peer by hand would be a standing override of the only authority on names,
   and it never expires — so a member the zone had dropped would stay trusted under
   its name forever, and removing a record would stop being how a member is removed.
   That is the fail-closed property (below) inverted. A node that wants named,
   rotatable members resolves the zone that issues those names; a node that does not
   trust a zone gets key-identified peers, which cannot rotate. There is no third
   arrangement, and no command that manufactures one.

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
remains fetchable for manual salvage via `synch take`. The fork is resolved by the
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

---

## 4. Data model

### 4.1 Origin tries and the record keyspace

Each origin trie maps byte-string keys to record values. Keys are namespaced by a
single prefix byte:

| Prefix | Key                                  | Value          | Meaning                          |
|--------|--------------------------------------|----------------|----------------------------------|
| `f:`   | `f:<space-id>/<utf8 relative path>`  | `FileEntry`    | this origin's copy of a file     |
| `b:`   | `b:<32-byte object root hash>`       | `BlobAd`       | "I hold (part of) this object"   |
| `m:`   | `m:self`                             | `NodeManifest` | node info: name, spaces, version |

Paths are UTF-8, NFC-normalized, `/`-separated, no leading slash, no `.`/`..`
components. Because the MPT compresses shared prefixes, the `f:` namespace naturally
mirrors directory structure, and a directory listing is a range scan over
`f:<space>/<dir>/`.

A **space** is a named sync root (like a Syncthing folder): a user configures
`synch space add photos ~/Pictures`, and that subtree is indexed under `f:photos/...`.
Spaces are the unit of sharing policy and of local materialization.

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
    spaces: Vec<SpaceInfo>,   // advertised spaces: id, description, entry count
    software: String,         // "synchronicity/0.1.0"
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
  divergence while it is visible — `synch take` the deletion (§8) on the holdout,
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
Hello      { proto: u16, heads: Vec<HeadSummary> }      // HeadSummary = (origin: OriginId, seq, root,
                                                        //   complete: bool)  — "complete" = I hold the
                                                        //   full trie under this root and can serve it;
                                                        //   a signed head alone proves nothing about that
HeadsWant  { origins: Vec<OriginId> }                   // "yours is newer, send full signed head"
Heads      { heads: Vec<SignedHead> }
HeadPush   { head: SignedHead }                         // reactive: sent on any head change

// one bidirectional stream per fetch batch:
GetNodes   { hashes: Vec<Hash> }                        // ≤ 256 per batch
Nodes      { nodes: Vec<(Hash, Bytes)>, missing: Vec<Hash> }
GetValues  { hashes: Vec<Hash> }                        // out-of-line ValueRef payloads
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
// never leave `entries` — what the unified tree, mirrors, and s3 serve from —
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

---

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
   request-scoped — the caller (`synch cat/get`, a mirror pass, the s3 gateway)
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

### 7.1 Indexing pipeline (own spaces)

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

### 7.2 Materialization (the unified tree, under a policy)

Materialization reads the unified tree (§8), so every materializing surface names a
**version policy** — `newest` (default), `origin=<id>`, or `strict`:

- `synch get <space>/<path> [-o dest] [--from <origin>|--strict]` — single fetch of
  the selected version into a local file. `synch get <origin>:<space>/<path>` remains
  the origin-pinned form.
- `synch mirror add <space> <local-dir> [--policy newest|origin=<id>|strict]` —
  continuous read-only mirror of the unified tree for that space: the engine keeps
  the directory in sync with the policy-selected version of every path (fetching
  content via §6.4). A standing loop runs a pass the moment the tree changes — a
  head flipping to complete on any exchange, a local publish, a newly added mirror
  all ring it — once at startup, and on a 60 s backstop interval; a pass over an
  unchanged tree costs the tree's stats, not its bytes (docs/DELTA-SYNC.md §3.5).
  Under `strict`, divergent paths are skipped and reported —
  the mirror never guesses. Mirrored trees are never indexed back into the local
  origin trie (no echo).
- `synch cat <space>/<path> [--range a..b] [--from <origin>|--strict]` — stream to
  stdout with verified random access; this is where hash-tree reads shine (e.g.
  seeking in a large video).

Materialized files carry the metadata their selected version published, not the
metadata of the copy: the origin's `mtime_ns`, and the permission bits of its
advisory `unix_mode` (§4.2, masked — setuid/setgid/sticky are never reproduced,
since the mode is a peer's assertion and the daemon may be privileged). A file
whose bytes are already current but whose mode or mtime has drifted is stamped
back in place rather than refetched. A symbolic link's metadata is not
reproduced: its target *is* its version (§8), and stamping a link's own times
needs a facility the standard library does not expose.

Materialization safety: trie paths are case-sensitive NFC UTF-8, but local
filesystems may not be. When two published paths collide under the target
filesystem's folding (case-insensitivity, Unicode normalization), materialization
writes the lexicographically first and **skips and reports** the rest — never
silently clobbers. Names invalid on the target platform (Windows reserved device
names, trailing dot/space, forbidden characters) are likewise skipped and reported.
And mirror targets may not overlap any configured space root (or vice versa):
`synch mirror add` and `synch space add` refuse overlapping paths, which makes the
"no echo" guarantee structural rather than conventional.

Two-way "shared folder" workflows are the unified tree working as intended: both
nodes index their own copy of a space (same space id), the tree shows one hierarchy,
agreement renders as plain files, and divergence between the copies is marked and
surfaced by `synch status` (§8) for explicit adoption with `synch take`.

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
    select differently until anti-entropy converges them, so a lagging mirror
    can briefly serve different bytes than a current one, unmarked. Deployments
    for which either is unacceptable use `strict` or an `origin=` pin.
  - `origin=<id>` — pin to one origin's view (the old per-origin behavior, still the
    right tool for "serve exactly what the NAS publishes").
  - `strict` — refuse to read a divergent path, returning the version list instead;
    for workflows where silently reading either side is worse than failing.
  Policy is a property of the reading surface: a flag on `cat`/`get` (`--from
  <origin>`, `--strict`), a stored policy per mirror and per s3 bucket (§7.2, §9.4).
- **Adoption is explicit — and deletions are adoptable**: `synch take
  <origin>:<space>/<path>` makes that origin's version our own. For a live
  version, it fetches the content, writes it into the local space, and thereby
  (via the indexing pipeline) publishes it as the local node's own new entry.
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

**The daemon owns the node; the CLI is only a client of it.** Every command except the
two that bootstrap or *are* the daemon — `synch init`, which creates the datadir before
any daemon can exist, and `synch daemon run` itself — is a request over the control
socket (§9.3). There is no in-process fallback: with no daemon running, a command
fails with a message naming the socket path and the command to start one.

This is a deliberate narrowing. A CLI that could also open the database directly meant
two code paths to the same state, two processes contending on one SQLite file, and —
worse — a short-lived second iroh endpoint sharing the daemon's device key, fighting
it over relay registration and discovery records. One writer, one endpoint, one
lifecycle is worth more than the convenience of running commands without a daemon.
The rule binds every process, `synch-s3` included (§9.4): concurrent publishers on
one database do not merely contend, they can mint same-seq forks and lose published
files.

### 9.2 Command surface (v1)

`synch init` and `synch daemon run` act on the datadir directly; every other command
is a control-service call to a running daemon (§9.3).

```
synch init [--domain <d>]                    create device key + database (no daemon);
                                             --domain joins the zone that will name
                                             this node (§3.1)
synch daemon run|status|stop
synch id                                     print OriginId + current device key(s),
                                             where the name came from, and adoptions
synch key rotate|activate|retire|ls          operator-driven device-key rotation (§3.4)

synch trust add [--addr <hint>]|rm|ls        static membership; key-identified peers
                                             only — names come from zones (§3.2)
synch domain set|clear|ls|refresh            this node's own DNSSEC membership domain
                                             (§3.2); refresh re-resolves it now; set
                                             and clear change where the node's name
                                             comes from, at the next start (§3.1)
synch peers                                  live peers, addresses, last sync, lag

synch space add <id> <path>                  index a local directory as a space
synch space ls|rm
synch scan                                   walk every space now: hash changes, publish

synch ls   [<origin>:]<space>[/<dir>] [--all] list the unified tree (divergent paths
                                             marked with version counts; --all shows
                                             every version with attestors); origin-
                                             prefixed form lists one origin's view
synch status [<space>[/<path>]]              the version inspector: every version of
                                             a path, its attestors, side by side
synch cat  [<origin>:]<space>/<path>         verified streaming read of the selected
           [--range] [--from <o>|--strict]   version (§8 policy; default newest)
synch get  [<origin>:]<space>/<path> [-o …]  fetch the selected version to a file
           [--from <o>|--strict]
synch take <origin>:<space>/<path>           adopt a version as my own (ends divergence)
synch log  [<origin>:]<space>/<path>         per-origin publish history
synch compare <space>[/<dir>] --to <origin>  name-status diff (created/modified/deleted)
           [--from <origin>] [--json]        between two origins' published trees; no
                                             content fetched, --from defaults to self
synch mirror add <space> <dir> [--policy …]  continuous materialization of the unified
synch mirror rm|ls|sync                      tree under a version policy (§7.2)

synch pin add|rm|ls <root|space/path>        keep content in CAS regardless of policy
                                             (a path pins its selected version's root)
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
  progress-reporting commands (`scan`, `mirror sync`) emit reports the CLI renders and
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
  - `PutObject` — writes into the local space directory, then runs the normal
    ingest pipeline (hash → CAS → stage entry, §7.1); responds once durably staged,
    with the head publish following the usual batching.
- **ETag** is the object's blake3 root hash, hex, quoted. S3 permits opaque ETags
  (MD5 equivalence is only conventional for non-multipart uploads); tooling that
  insists on MD5 validation must have it disabled.
- **Auth**: SigV4 with static access-key pairs configured on the gateway
  (`synch-s3 key add`), or `--anonymous` for localhost-only development. The
  gateway authenticates S3 clients only; cluster access is the node's own
  membership (§3).
- **Not in v1**: DeleteObject (maps naturally to a tombstone publish — first in
  line for v1.1), multipart upload, CopyObject, bucket versioning APIs, presigned
  URLs.

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
decode, mirror materialization, GC. None of that belongs on a tokio worker
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
one thread and leaves every runtime worker the node uses checked.

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

`config` also holds the membership domain that decides where this node's name comes
from (§3.1) — it has to be readable before there is a name to read it out of — the
name itself in `self_origin_id`, and, after a recovery (§3.4), the `publish_floor`.

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
-- the only record of it; `synch id` and `synch doctor` both read this.
CREATE TABLE identity_history (
  at          INTEGER NOT NULL,
  previous    TEXT NOT NULL,
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
  source       TEXT NOT NULL,            -- 'static' | 'dns'
  domain       TEXT NOT NULL DEFAULT '', -- the membership domain, '' if static
  note         TEXT,
  added_at     INTEGER NOT NULL,
  expires_at   INTEGER,                  -- NULL for static
  PRIMARY KEY (origin_id, node_id, source, domain)
);
CREATE INDEX bindings_by_key ON bindings (node_id);   -- connection-accept lookup

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

-- materialized views of trie leaves (rebuilt incrementally from diffs)
CREATE TABLE entries (
  origin_id   TEXT NOT NULL,
  space       TEXT NOT NULL,
  path        TEXT NOT NULL,
  kind        INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  mtime_ns    INTEGER NOT NULL,
  unix_mode   INTEGER,                   -- advisory mode a mirror reproduces (§7.2)
  content     BLOB,                      -- object root hash
  seq         INTEGER NOT NULL,
  prev        BLOB,
  symlink_target TEXT,                   -- link target; half of a content-less
                                         --   kind's version identity (§8)
  PRIMARY KEY (origin_id, space, path)
);
CREATE INDEX entries_by_path    ON entries (space, path);
CREATE INDEX entries_by_content ON entries (content);

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
  pinned      INTEGER NOT NULL DEFAULT 0,
  last_access INTEGER NOT NULL
);

-- indexing / engine state
CREATE TABLE spaces        (id TEXT PRIMARY KEY, local_path TEXT NOT NULL);
CREATE TABLE local_files   (space TEXT, relpath TEXT, size INTEGER, mtime_ns INTEGER,
                            file_id BLOB, content BLOB, scanned_at INTEGER,
                            PRIMARY KEY (space, relpath));
CREATE TABLE mirrors       (local_path TEXT PRIMARY KEY,   -- one mirror per directory
                            space TEXT NOT NULL,
                            policy TEXT NOT NULL);          -- 'newest' | 'origin=<id>' | 'strict' (§7.2)
CREATE TABLE peers_seen    (node_id BLOB PRIMARY KEY, last_addr BLOB, last_seen INTEGER,
                            last_sync INTEGER, latency_ewma_us INTEGER);

-- recovery (§3.4): the greatest (seq, root) any peer has advertised for an origin,
-- observed from Hello summaries — never verified, never adopted as a head
CREATE TABLE observed_heads (origin_id TEXT PRIMARY KEY, seq INTEGER NOT NULL,
                             root BLOB NOT NULL, complete INTEGER NOT NULL,
                             claimed_by BLOB,   -- which peer asserted it (§3.4)
                             observed_at INTEGER NOT NULL);
```

The trie is authoritative; `entries` and `blob_providers` are derived caches and can
always be rebuilt from `trie_nodes` (`synch doctor --rebuild`).

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
│   │                  # scheduler, fetcher, mirrors — everything a host app needs
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
- **Authorization**: binary, membership-based (§3.2). Enforced on accept and per-origin
  on every head/record. A trusted peer relaying data for an untrusted origin is ignored.
- **Data integrity**: three independent hash-verification layers — trie nodes verified
  against requested hashes, heads verified against origin signatures, content verified
  against object roots per 16 KiB group. A compromised peer can withhold, but never
  corrupt.
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
  refused, new heads ignored. Data it already published stays replicated (nothing
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
- **Privacy**: metadata (paths, sizes, mtimes) is visible to *all* members — inherent
  to omnipresence. Content is fetched on demand, so bytes only land where requested or
  mirrored. At-rest encryption of the CAS and DB is delegated to OS disk encryption in
  v1 (noted in §13).

---

## 13. Future work (explicit non-v1)

- Read-only membership tier and per-space ACLs.
- Rotation continuity attestation: cryptographically distinguishing a legitimate key
  rotation from a domain-level rebinding (e.g. an old-key cross-signed rotation log).
  Still not v1. Note that the transparency layer shipped since (§12,
  [docs/REKOR-ZONE-KEY.md](docs/REKOR-ZONE-KEY.md)) attacks the same exposure from
  the other side — it makes a substitution *public* rather than making it
  *distinguishable* — so this remains the thing that would let a client tell the
  two apart on its own, without a monitor and without an operator's records.
- Encrypted spaces (per-space content keys; metadata padding).
- Partial trie replication for very large clusters (the proof machinery in §4.3
  already permits it).
- Smarter placement policies ("keep ≥ 2 replicas of every object cluster-wide"),
  built on the same `BlobAd` availability data.
- Optional platform-specific mounts (FUSE/WinFsp/NFSv3-loopback) as *plugins*,
  never as core. (HTTP access ships as the S3 gateway, §9.4.)
- Bandwidth scheduling / QoS between anti-entropy and bulk fetches.

---

## 14. End-to-end walkthrough

Three nodes: `laptop`, `nas`, `vps`, all in `_synchronicity.cluster.example.com`.

0. Each ran `synch init --domain cluster.example.com` and had its printed device key
   published in one TXT record. Each daemon resolved the zone at startup, found the
   record naming its own key, and took that record's `id=` as its name (§3.1).
1. `nas` runs `synch space add media /srv/media`. The scanner hashes 40 k files,
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
4. `vps` (which runs `synch mirror add media /srv/mirror` — unified tree, default
   `newest` policy) later fetches the same file — provider resolution now returns
   `{nas, laptop}` and it pulls from both in parallel.
5. `nas` edits a file; `laptop` had edited its own copy of the same path an hour
   earlier. Watcher → rescan → head `(seq=2, r2)` → `HeadPush` to both peers; each
   pulls exactly the changed path's trie nodes. `synch ls media` on any node still
   shows one tree, with that path marked `⑂2`: two versions, one asserted by `nas`,
   one by `laptop`. `synch cat media/that/file` reads the newest deterministically;
   `--from laptop` reads the other; `synch status media/that/file` lays both out —
   divergence visible, nothing auto-resolved, adoption one `synch take` away, after
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
