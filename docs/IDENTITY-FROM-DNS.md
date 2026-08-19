# Identity from DNS

**Status: proposal.** Supersedes the §3.2 rule that a node's own `OriginId` is
explicit and never inferred from DNS. Nothing here is implemented yet.

The current rule is that a node is told who it is (`synch init --id
nas@cluster.example.com`) and DNS is consulted only to decide who *else* to
trust. This proposal inverts that for DNS-discovery deployments: the zone
becomes the sole authority on a node's own identity, discovered at startup and
re-adopted automatically when it changes.

The trade is stated plainly in §8 rather than buried: this removes the only
self-check the node has, and makes a one-character zone edit a destructive,
unattended, cluster-wide operation. Everything else here is about making that
operation sound.

---

## 1. Two identity regimes, each with one authority

Today three things can name a node — `--id`, `synch id set`, and static trust's
`--as` — while DNS names everything except the node itself. That is one
authority too many, and the redesign collapses it to a single explicit config
value, `identity.mode`, fixed at `synch init`:

| `identity.mode` | Membership domain | `OriginId`             | Rotatable | Identity comes from    |
|-----------------|-------------------|------------------------|-----------|------------------------|
| `key`           | none              | `Key(K_active)`        | no        | the device key         |
| `dns`           | exactly one       | `Named { domain, id }` | yes       | the zone (§3)          |
| `static`        | none              | `Named { domain, id }` | yes       | `synch id set`, once   |

`key` is the default and needs no configuration at all — the identity *is* the
key, which is the existing `OriginId::Key` case. `dns` is the subject of this
document. `static` exists only to keep §3.2's airgapped named origins working
(`trust add --as`, `trust rebind`); it is the one place a self id stays manually
configurable, because there is no zone to ask. A node in `static` mode cannot
have a membership domain, and `synch domain set` refuses on one — a node must
not have two authorities on its own name.

Making the mode explicit rather than inferring it from "is a domain configured?"
is deliberate: the inferred version means `synch domain clear` silently changes
what a node believes it is.

## 2. One membership domain in `dns` mode

`membership_domains` (`membership.rs:34`, a newline-joined list) becomes
`membership.domain`, a single value.

- `synch domain add` / `synch domain rm` → `synch domain set <d>` / `synch domain clear`.
- `domain ls` and `domain status` keep working, over the one domain.

The plurality was only ever meaningful for trusting *other* nodes; once the
domain is half of this node's own `OriginId` it must be singular, or "the joined
domain" names nothing.

**Migration from a multi-domain config.** A migration must not fail — §10 makes
migrations a numbered chain run inside `Store::open`, and a failing one bricks
the data dir into a state no CLI command can reach, because every command needs
the store open. So the migration is total: exactly one domain moves to
`membership.domain`; zero is a no-op; more than one writes nothing and parks the
list in `membership.domains_conflict`. `Node::open` then refuses to start with
the domains named and the remedy spelled out (`synch domain set <one-of-them>`),
and `domain set` is a data-dir-direct command like `init`, so it runs without a
daemon.

## 3. Discovery: what the zone is asked, and when

Discovery consumes a `MemberSet` that is already DNSSEC-validated, so it
inherits the §3.2 transport rules unchanged — DoH only, fail-closed on a broken
chain, `apex=` and the Rekor proof set under `--rekor require`, the clock rules.
Nothing new is trusted.

The oracle is `MemberSet::self_origin(&K)` (`dns.rs`), which already implements
exactly the semantics identity needs: it returns `None` when the key is absent
*or* ambiguous under the malformed-set rule, and never guesses. Only its doc
comment changes — it currently says the caller should fall back to an explicit
`--id`.

One new restriction. In `dns` mode, discovery accepts only a `Named` result. A
node whose key appears in an `id=`-less record resolves to `Key(K)`, and
adopting that would silently convert a rotatable node into a non-rotatable one
on the strength of a missing field. That result is refused and reported as a
misconfiguration ("`<K>` is published without an `id=`"), and the node keeps
whatever identity it already had.

### 3.1 Startup, once per process

`Node::open` resolves the domain exactly once, before the endpoint binds and
before any loop starts, then freezes the answer. **Identity is immutable for the
lifetime of the process** — `Node::origin()` returns the same value from first
call to shutdown, which is what keeps every invariant that reads it (seq
monotonicity, trie keying, head signing) intact while allowing §5's migration to
happen with no daemon stopped.

Six cases, and the distinction between the last two is the one that carries the
design:

| Local `self_origin_id` | Resolution        | Action                                             |
|------------------------|-------------------|----------------------------------------------------|
| absent                 | `Some(o)`         | adopt `o`; first boot                               |
| `Some(o)`              | `Some(o)`         | nothing; steady state                               |
| `Some(p)`              | `Some(o)`, `o≠p`  | migrate `p → o` (§5), then start                    |
| absent                 | `None`            | **unidentified** (§4): poll                         |
| `Some(p)`              | `None`            | keep `p`, report, **do not poll**, do not un-adopt  |
| any                    | **failed**        | keep local identity if any, else poll               |

"The zone validly says nothing about my key" and "I could not ask the zone" are
different answers and must never collapse. A resolution failure — unreachable
resolver, expired RRSIG, dead RTC — is not evidence that the record was removed,
and a node that erased its identity on one would lose itself every time its
resolver hiccuped. Fail-closed here means *keep what you have*.

Row 5 is the deliberate asymmetry: a record that disappears does not un-identify
a node. Its bindings expire at every peer on `dns_trust_grace` and its data goes
unavailable per §3.4's accepted availability edge, but it keeps its name, keeps
signing, and keeps a coherent trie. Un-adopting would additionally destroy the
local state, which is strictly worse and irreversible.

### 3.2 The poll loop

The identity poll is a **separate, one-shot-until-success task**, not a change
to the membership refresh loop. The membership loop keeps running forever after
identity is fixed — it is about other nodes. The identity poll stops the moment
an identity is adopted and never runs again in that process, so a later zone
edit is picked up at the *next* start and nowhere else.

Cadence: the negative answer's TTL, clamped to `[30s, 5m]` — tight enough that
"publish the record, watch the node come up" feels immediate, loose enough not
to be a query flood against a name that does not exist yet. `synch domain
refresh` over the control socket triggers it immediately, so nobody waits on a
clamp.

## 4. The unidentified state

A node with a device key and no identity can speak QUIC but has nothing to say:
it cannot sign heads, cannot publish, cannot scan into a trie. It is also
unreachable in practice — no peer will accept its connections, because the same
absent record that leaves it unidentified leaves every peer without a binding
for its key.

It runs a reduced service, modelled on the §3.4 recovery state, which already
establishes the pattern of a daemon that is up and deliberately refusing to
publish:

- Control socket up, so `daemon status` and `doctor` can explain the state.
- Endpoint bound, for uniformity; inert for the reason above.
- Every publishing command fails with the record to publish, filled in:
  `v=sync1 id=<name> nk=<K> apex=<apex>`.
- The identity poll runs.

Onboarding becomes: `synch init` (prints `K`), publish one TXT record, done —
the node identifies itself and starts. That is the ergonomic win, and it is
worth stating that the two-step ordering is forced: the record cannot name a key
that does not exist yet.

## 5. Automatic migration

`Node::adopt_named_origin` (`node.rs:237`) becomes an internal
`migrate_identity`, called from `Node::open` on row 3 above. Three changes to
what it does:

1. **The stopped-daemon guard goes** (`commands.rs:103`). It is unnecessary
   rather than merely relaxed: the migration now runs inside `open`, before the
   endpoint binds, so there is no running daemon at that instant by
   construction.
2. **The `Named → Named` refusal is lifted** (`node.rs:254`). Relabelling
   `nas → nas-01` is precisely the case bullet 3 asks for.
3. **Mirror policies are rewritten in the same transaction.** `mirrors.policy`
   stores `origin=nas@x.example` as text (`schema.rs:202`, `unified.rs:45`), and
   nothing rewrites it today. After a relabel those pins select nothing —
   silently, since an `origin=` pin that matches no origin is
   indistinguishable from one whose origin has published nothing. This is a
   latent gap in the existing `Key → Named` path too.

Everything else is unchanged and already correct: one transaction (§10), blobs
retained and republished by the next scan, and `head_history` untouched, so
pre-migration heads survive as the §4.4 fork evidence they are.

**Preconditions, all required.** The migration fires only on a DNSSEC-validated
answer that yields a single unambiguous `Named` origin for the active device
key. Never on a resolution failure, never on ambiguity, never on absence, never
on an `id=`-less match. This is the whole safety argument for an unattended
destructive operation, and it is entirely inherited from rules §3.2 already
enforces.

**Audit.** A new `identity_history (previous, adopted, node_id, domain, at)`
records every migration durably. §3.4 argues that a change of signing identity
should be a deliberate act with an audit trail; automation removes the
deliberateness, so the trail has to carry more weight. `synch id` and `synch
doctor` both surface it.

**Cost, which `doctor` should state.** A relabel is a full republish: the new
origin starts at seq 1, peers keep the old origin's trie until its bindings
expire, and the cluster briefly lists the machine twice. Automatic does not mean
cheap, and an operator who relabels three nodes should be told what they just
bought.

## 6. Config and schema

```
identity.mode              'key' | 'dns' | 'static'      (new, set at init)
membership.domain          the one domain                (replaces membership_domains)
membership.domains_conflict  parked list, migration only (new, transient)
self_origin_id             unchanged; now written by discovery in dns mode
```

```sql
CREATE TABLE identity_history (
  at        INTEGER NOT NULL,
  previous  TEXT NOT NULL,
  adopted   TEXT NOT NULL,
  node_id   BLOB NOT NULL,
  domain    TEXT NOT NULL
);
```

## 7. CLI

| Today                        | Proposed                                        |
|------------------------------|-------------------------------------------------|
| `synch init --id <o>`        | removed in `dns`/`key`; `static` only           |
| `synch id set <o>`           | `static` mode only; refused with a domain set   |
| `synch domain add/rm <d>`    | `synch domain set <d>` / `synch domain clear`   |
| `synch id`                   | also reports provenance and migration history   |

`doctor` loses `self_origin_mismatch` (§8) and gains, in its place, the
provenance of the identity it holds: which domain it came from, when it was
resolved, any refused-because-ambiguous or published-without-`id=` finding, and
recent migrations.

## 8. What this costs

**The self-check becomes unconstructible.** `membership.rs:517-519` is
`set.self_origin(&self.node_id()).filter(|o| o != self.origin())` — two
independent witnesses to this node's name, compared. Under this proposal they
are the same expression and can never disagree. The failure mode §3.2 singles
out — a node that "syncs nothing and looks healthy doing it" — becomes
undetectable by the node itself. Nothing replaces it; §7's provenance reporting
is strictly weaker, because it can only say what the zone said, never whether
the zone is wrong.

**Zone control widens from authorization to identity.** Today whoever controls
the zone decides which keys hold an origin (§12). Under this proposal they also
decide what each node believes it is, and a one-character edit (`id=nas` →
`id=nas-01`) runs `migrate_identity` unattended on the next restart of every
affected node: entries and providers deleted, seq restarted, mirror pins
rewritten. The `identity_history` table and `doctor`'s report are the whole
mitigation, and they are after-the-fact.

**Signing depends on DNS at first boot.** A `dns`-mode node that has never
identified cannot publish until the zone resolves. §3.1's availability property
survives only for already-identified nodes (rows 5 and 6), which is why those
rows matter so much.

These are consequences of the requirement, not objections to it. They are listed
so the trade is on the record, and because two of them are things `doctor`
should say out loud rather than facts a reader has to reconstruct.

## 9. Open decisions

1. **`static` mode: keep or drop?** Dropping it removes rotation-without-DNS
   entirely (`trust add --as`, `trust rebind`, §3.4's last line) and leaves two
   regimes instead of three, which is cleaner. Keeping it preserves a documented
   airgapped capability. Recommendation: keep — it costs one enum value and the
   `dns` rules are unaffected either way.
2. **`publish_floor` across a relabel.** It is node-wide config, not per-origin.
   After a relabel it describes history nobody holds under the new name.
   Retaining it is safe (it only raises seq) but stale; recommendation: clear it
   in the migration transaction, since a fresh name has no history to floor.
3. **Should a relabel be *loud* as well as automatic?** The requirement is
   unattended migration, and this proposal delivers that. A middle option exists
   — migrate automatically but leave the node refusing to publish until an
   operator acknowledges via `synch id ack` — which keeps the "no stopped
   daemon" property while making a destructive zone edit visible before it
   propagates. Not proposed, but it is the natural place to retreat to if
   unattended relabelling proves too sharp in practice.
