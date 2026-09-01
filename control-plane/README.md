# synchronicity control plane

A managed, multi-tenant control plane for [synchronicity](../README.md):
the authoritative, DNSSEC-signed source of truth for cluster membership
zones, plus a web dashboard for managing them.

Synchronicity clusters discover their members through DNSSEC-validated
TXT records at `_synchronicity.<domain>` (`v=sync1 id=<label>
nk=<z-base-32 key>`), resolved over DoH and validated fail-closed by
every node. This service serves those zones — signed with ECDSA P-256
(DNSSEC algorithm 13), over authoritative DNS on port 53 (UDP + TCP)
and RFC 8484 DoH — and gives organizations a dashboard to manage them.

## Model

- **Organizations** have **users** (owner / admin / member roles, via
  invites) and **devices**.
- The zone key can be put on the public Sigstore Rekor v2 transparency log
  (`controlplane rekor-publish`), with the proof served inside the zone at
  `_synchronicity-rekor.<apex>` so clients verify it offline — a
  substituted DS then has to be a *public* substitution or fail
  validation. The entry's verifier is a **self-signed certificate naming
  the apex in a `dNSName` SAN**: Rekor validates certificates not at all
  and copies the DER verbatim into the Merkle leaf, so the zone name lands
  where anyone reading the log can index it. Inside it rides one custom
  extension — the DNSSEC chain, from the zone's own signed declaration up
  through the delegation's zone cuts to the root — which is what lets a
  monitor confirm offline that the key really is authorized for the zone the
  entry names. `rekor-publish` takes the apex from `CP_BASE_DOMAIN` rather
  than the command line, because the entry names it in a public log;
  it collects the chain over DoH, mints the certificate, POSTs a
  `hashedrekord` v0.0.2 `CreateEntryRequest` to `CP_REKOR_URL`, then
  verifies the returned entry locally (canonicalized body, inclusion,
  checkpoint, possession, the certificate's key and name bindings) before
  storing it. **Run it after the DS is live in the parent** — there is no
  chain to collect before then. A self-hosted, Rekor-v2-compatible log
  works via `CP_REKOR_KEY`.
  See [docs/REKOR-ZONE-KEY.md](../docs/REKOR-ZONE-KEY.md) §2, §3, §5.
- It learns which transparency log shard is in service from
  **`priv/tuf/sigstore_trusted_root.json`**, the directory it ships,
  byte-identical to the one the client embeds. It walks no TUF repository:
  nothing about this material reaches a client — they pin their own log keys
  from their own walk — so getting it wrong yields a proof clients refuse and
  a zone that fails closed, never a trust bypass. A Sigstore shard rotation
  therefore costs this service a deploy, which it can pay and a NAS daemon
  cannot; that asymmetry is why the client still walks and this side does not
  (docs/REKOR-ZONE-KEY.md §10.3). `CP_REKOR_URL` + `CP_REKOR_KEY` name a log
  outright.
- Each org has **networks**; a network is one synchronicity cluster and
  owns one membership name: `_synchronicity.<network>.<org>.<base>`.
- A **device** is one `id=` label plus its keys. Key rotation follows
  synchronicity's operator-driven window: two keys publish under one
  label until the old one is retired. The §3.2 ambiguity rule (one key,
  one identity) is unrepresentable in the schema and re-checked before
  every publish.
- Sign-in: Google, GitHub, per-org custom OIDC (never auto-linked —
  org-controlled issuers can't capture existing accounts), and email
  magic links. The login and settings screens offer only what this
  deployment has configured — `GET /api/auth/methods` is what they ask,
  and it answers booleans to anyone, since the login page needs it before
  a session exists. Magic links stay on the page when nothing else is
  configured, mail relay or not: an empty login screen is worse than a
  link the operator reads off the service log.
- **API keys** are the second credential the API takes, for callers that
  are programs. Two kinds. An **org key** belongs to an *org*, not to a
  person: it names one org and carries its own role (`admin` or `member`,
  never `owner`), so it can never reach another org and no change to
  anybody's membership can widen it. A **join key** is narrower still — one
  *network*, and the single operation of adding a device to it, which is
  what makes it safe to bake into a provisioning image. Send either as
  `Authorization: Bearer synch_…`; a bearer request needs no CSRF token,
  because nothing attaches that header on its own. Accounts, membership and
  key management stay a signed-in person's — see [API keys](#api-keys)
  below.
- **Cloud browse** lets the dashboard read a cluster's files. Nodes are
  unreachable from here, so the connection is one they open: a daemon
  discovers this deployment from
  `_synchronicity-cp.<apex>` in the zone it already DNSSEC-validates, dials
  out over WSS, and proves itself with the device key this service already
  publishes — no command needed, for the tunnel is on unless a node's
  operator opted it out with `synch control-plane disable`. It is read-only by
  construction — the tunnel encodes no write opcode and the API is GET-only —
  and fail-closed on the org's choice: an org admin must enable browsing for
  the network, and until then nothing is readable however many daemons are
  attached. Which spaces are browsable is decided here, not on the node: an
  attached daemon serves whatever this service requests, for every space it
  holds. File bytes pass through this service's memory in bounded chunks and
  are never stored.

  The same tunnel carries two questions that are not about files: who the
  cluster admits on a delegation, and **what each node replicates**
  (`docs/REPLICATION.md` §8.1). The second is asked of *every* attached daemon
  rather than the first one, because replication is a decision each node makes
  for itself — one node replicates `media`, its neighbour does not, and both
  are correct — so each answer is labelled with the node that gave it, and a
  node that could not be asked is reported as that rather than as a node
  replicating nothing. Nothing is stored: a held-object count is stale the
  moment a fetch lands, and the tunnel is what makes storing it unnecessary.

  **The tunnel version is negotiated, not required to match.** An attach
  settles on the daemon's version, clamped to the newest this build speaks, and
  only a daemon below the floor (v2 today) is refused. Each question records
  the version it appeared in, so a node whose operator has not upgraded keeps
  its tunnel and everything its own version defines, and is never sent a frame
  it could not decode — a frame that fails to decode ends a connection, which
  is why the number exists at all. Such a node shows in the replication panel
  as one that does not report it.

  The clamp matters in the other direction too. Nodes belong to their
  operators, so a node is often upgraded before the control plane it attaches
  to; refusing it for knowing *more* would cost that org browse, reads and
  delegations to protect against nothing. It settles at this build's version
  and is asked what this build knows to ask.

  The record names **every node** of the deployment, one `v=synccp1 url=`
  each (`CP_ENDPOINTS` on the primary), and a daemon opens a tunnel to all of
  them. It has to: the registry of open tunnels is one process's memory, so a
  replica no daemon attached to can answer nothing however current its copy
  of the database is. There is no deployment-level switch — the org admin's
  per-network toggle is the whole of the gate, and it is off until they turn
  it on.
- **Cloud hosting** is a second, independent per-network switch: with it on,
  an operator-run fleet joins the network as one more ordinary device
  (`cloud-1`) and durably replicates everything published on it. This service
  is the authority and the API; the fleet is cattle that polls it. See
  [The cloud data plane](#the-cloud-data-plane) below and
  [docs/CLOUD-DATAPLANE.md](../docs/CLOUD-DATAPLANE.md).

## API keys

For scripts, CI and anything else that is not a person at a browser. Org
owners and admins manage them under **Settings → API keys**, or over the
API itself:

| Method   | Path                              | Role  |
| -------- | --------------------------------- | ----- |
| `GET`    | `/api/orgs/:slug/api-keys`        | admin |
| `POST`   | `/api/orgs/:slug/api-keys`        | admin |
| `PATCH`  | `/api/orgs/:slug/api-keys/:id`    | admin |
| `DELETE` | `/api/orgs/:slug/api-keys/:id`    | admin |

`POST` takes `{"name": "ci", "role": "member", "expires_in": 2592000}` —
`role` defaults to `member`, and `expires_in` is seconds from now, `0` (the
default) for no expiry. `role: "join"` mints a **join key** and additionally
requires `network` *and* `expires_in`; role and network imply each other in
both directions, here and in the schema's CHECK, and the expiry is required
because nothing else bounds a join key — see below. A duration rather than a date, so nothing depends on
the caller's clock agreeing with the service's. It answers with the token:

```json
{ "id": "…", "name": "ci", "role": "member", "network": "",
  "prefix": "synch_A1b2C3d4", "expires_at": 1795123456, "token": "synch_…" }
```

`network` is empty for an org key and names the network for a join key;
`expires_at` is `0` when the key never expires.

**That is the only time the token exists outside the holder's hands.** The
row keeps its SHA-256 and the `prefix` above, which is what lets the list say
which key a leaked or forgotten token is without holding enough to be one.
Lose it and mint another.

`PATCH` takes any of `name`, `role` and `expires_in`; an absent field is left
alone, and `expires_in: 0` clears the expiry. It will not move a key across
the org/join boundary: a key's kind is settled when it is minted, because a
join key promoted to admin is not an edit but a different credential with a
secret that is already deployed. The secret is not among them:
rotating a credential is minting a new key and deleting the old, which is two
audited acts rather than one that silently invalidates whatever is deployed.
`DELETE` revokes — the row goes, and with it the hash the token
authenticates by.

Then use it:

```bash
curl -H "Authorization: Bearer $SYNCH_TOKEN" \
  https://cp.example.com/api/orgs/acme/networks
```

### The join key

A join key names one network and can do exactly one thing with it:

```
POST /api/orgs/:slug/networks/:net/devices
{"label": "nas", "nk": "<device key>", "relay": "", "addr": ""}
```

That route creates the device and puts it in the network in one transaction
and one zone republish — one call, because a device in no network appears in
no zone, so a caller that stopped halfway has enrolled nothing. Org keys and
people reach it too, at the `member` floor; it is the same act.

Everything else answers `403 join_key_forbidden`, including a `GET` on the
very network it may add to, and including the two older routes (`POST
/devices`, `PUT /networks/:net/devices/:dev`) that between them do the same
job less tightly. That is not a maintained list: every org-scoped route
resolves its caller through one function, and that function refuses the whole
family before it reads a rank. Aimed at another network — a sibling in the
same org, or the same name elsewhere — a join key gets the `404` a stranger
gets, so a leaked one reveals nothing about what else the org runs.

What it does not bound is *how many*. Anyone holding it can enrol devices
until it expires or is revoked — which is why `expires_in` is required on a
join key rather than merely offered. Every use is in the audit log as
`network.join` under `key:<id>`, with the key's name and its minter beside
it.

### What an org key may do

What an org key may do is what its role may do, in its own org: networks,
devices and their keys, the browse and download surface, the audit trail.
What no key of either kind may do:

- **manage accounts** — create an org, accept an invitation, read
  `/api/me`. These are about a person, and a key is not one.
- **manage membership** — invitations, role changes, removals, the roster
  read at `GET /api/orgs/:slug/members`, and the audit trail at
  `GET /api/orgs/:slug/audit`. An admin key that could invite an admin would
  be handing out standing human access that outlives the key; a leaked one
  should not carry the address book; and the trail carries the address book
  *and* an inventory of the org's other keys, so closing the roster while
  leaving the trail open would have closed nothing.
- **manage keys** — including reading the list. A key that could mint keys
  could mint one that never expires, and revoking the one you knew about
  would not have ended the access.

Those three answer `403 api_key_forbidden`. **Owner-gated routes** —
ownership transfer, org deletion, the SSO configuration — refuse every key
too, since no key is ever an owner, but which code you get depends on which
check runs first: transfer and deletion name keys, while the SSO
configuration is refused by the ordinary role floor and answers `forbidden`,
*"requires owner role"*. Branch on the 403, not on the code.

A key aimed at an org that is not its own answers `404` — the same answer a
person outside that org gets, since an org is not enumerable by whoever
cannot see it.

Every *change* a key makes is in the org's audit log under the actor
`key:<id>`, which names the credential rather than whoever minted it — true
still after that person's role has changed or they have left. The detail
carries `key_name` and `key_minted_by` beside it, so a row says which key and
whose without a second lookup, and goes on saying it after the key is revoked
and its row is gone. Reads are not recorded, browse reads included: that is a
deliberate choice about logging ordinary use, and it means the trail says what
a key *did*, never what it saw.

## The cloud data plane

Hosted replicas (docs/CLOUD-DATAPLANE.md). An org admin turns hosting on for
one network; within a poll interval a device labelled `cloud-1` appears in it,
in the device list and as one more `v=sync1 id=cloud-1 nk=…` record in the
zone, and an operator-run fleet holds a replica of every space on that network
in provider object storage. Customer nodes admit it the way they admit any
member — no new protocol, no configuration, no upgrade — because that is all
it is: the daemon's replicate mode, operated as a service.

**Why this adds no new trust.** This service already signs the membership zone;
it can already, today, put any device key into any network it serves. An org
running its networks here has already extended exactly the authority hosting
exercises. The toggle *narrows* that authority to an explicit, auditable,
org-controlled grant. It does not widen anything, which is the same argument
the browse toggle makes and the reason both flags live in this database rather
than in the zone: enforcement takes effect at the next call, not a TTL later,
and never reaches public DNS.

### The org's switch

```
PUT /api/orgs/:slug/networks/:net/cloud-hosting/enabled
{"enabled": true}
```

Admin-gated, off by default, audited as `cloud-hosting.enable` /
`cloud-hosting.disable`, and exposed as `cloud_hosted` on
`GET /api/orgs/:slug/networks` and `GET /api/orgs/:slug/networks/:net` — the
browse switch's shape throughout, because it is the same kind of decision.

Two ways it is not the browse switch. It is a **zone mutation**, so the answer
carries a `soa_serial` like every other zone-shaping call: turning hosting
*off* deletes the network's `cloud-*` devices in the same commit, so the flag
and the membership record it caused stop being true together — the zone must
never go on naming a hosted key the org has just withdrawn consent for. And
turning it *on* publishes too, even though nothing in the zone changes, because
the serial is what the fleet's `If-None-Match` poll is watching (below); a
grant that did not move it would be a network nobody ever hosted.

Disabling also stamps `cloud_disabled_at`, which starts the retention clock
over the tenant's object storage — re-enabling within the hold is a cheap
re-provision, and after it the network shows up in the `collect` list below and
the fleet deletes the prefix. That date outlives the device rows the same
transaction removes, which is why it lives on the network.

The two toggles stay independent and independently fail-closed. Hosting without
browse replicates, and is observable only through the status heartbeat below;
with browse on, the hosted node shows up in the ordinary replication panel like
any attached daemon, because it *is* one — "is the cloud replica keeping up" is
a question the dashboard already knows how to ask, with no new UI.

### The reserved label namespace

Device labels beginning `cloud-` belong to hosting slots and nobody else's —
the whole prefix, so that nothing in a device list can be mistaken for the
slot beside it. Every customer-facing path that takes a label — `POST
…/networks/:net/devices` and `POST …/devices`, the two the dashboard and the
join key use — answers `409 reserved-label`, and the data-plane API is the only
place one can be created. That confinement is what bounds a leaked data-plane
key: it can enumerate hosted networks and forge heartbeats, and its one write
cannot displace or impersonate a customer's device.

The suffix is the **slot**, not the shard. v1 hosts every network once, in slot
1, so the device is always `cloud-1` whichever pod happens to be running it; a
tenant moving between shards is no zone change at all. Redundant hosting, later,
is a second slot — `cloud-1` and `cloud-2` as two ordinary devices, because two
replicas of one network is already something the protocol does.

### `/dp/v1`, and the credential that reaches it

The fleet is a program, so it holds a credential — but not an API key. Every
row in `api_keys` names one org, and `api/common.check_org` treats "a
credential names one org" as load-bearing; the data plane's whole question is
"which networks, of *every* org, have hosting on", which no org-scoped
credential can be allowed to ask. So it is a fourth kind, in its own table,
resolved to its own principal:

```sh
controlplane dataplane register dp-1
controlplane dataplane-key mint dp-1 --dp dp-1 --expires-in 31536000
```

The key names the data plane it was minted for, and that is what decides
which networks it may see and write: `data_planes` is the fleet's registry,
`networks.cloud_dp_id` is the assignment, and `GET /dp/v1/networks` answers
with the caller's share alone. Placement happens once, when an org switches
hosting on — the least-loaded pod takes it, and nothing moves it afterwards
except `controlplane dataplane assign <org> <network> <dp-id>`.
`controlplane dataplane list` shows the fleet's counts and names every hosted
network assigned to nobody. See docs/CLOUD-DATAPLANE.md §7.2 for why the
name rides the credential rather than the pod's environment.

Printed once, the same posture as `seed-admin`, and **no HTTP route mints,
renames or lists these keys** — the credential that can see every org is never
reachable through the API it authorizes, or one leak buys a replacement that
outlives the revocation. `--expires-in` is optional here, unlike on a join key:
the fleet holds this for as long as the fleet runs, and an expiry nobody
arranged to renew would stop every hosted tenant converging at an hour nobody
chose.

Sent as `Authorization: Bearer synchdp_…`. The distinct prefix is not
decoration: `synchdp_` does not start with `synch_`, so neither resolver can
ever answer for the other's token, in the middleware or in a log line.

| Method   | Path                                          | What |
| -------- | --------------------------------------------- | ---- |
| `GET`    | `/dp/v1/networks`                             | the desired-state document: every hosted network of every org |
| `PUT`    | `/dp/v1/networks/:org/:net/device`            | `{"label": "cloud-1", "nk": "…"}` — idempotent registration |
| `DELETE` | `/dp/v1/networks/:org/:net/device/keys/:nk`   | close a rotation (`?revoke=1` to withdraw outright) |
| `POST`   | `/dp/v1/networks/:org/:net/status`            | the metering heartbeat |
| `DELETE` | `/dp/v1/networks/:org/:net/storage`           | record that an offboarded tenant's storage has been collected |

**Nothing else accepts this credential, and it accepts nothing else.** Both
halves are one `case` arm rather than a maintained list: `api/common.check_org`
names the variant and refuses it, so every org-scoped route in the service is
closed to a data-plane key by construction; `api/dataplane_api` admits only
that variant, so a session cookie or an admin key aimed at `/dp/v1` gets `403
dataplane_only`. A dashboard user who could register hosted devices by hand
would be a second, unaudited way into the reserved namespace.

The `GET` is a read and a replica answers it, like the rest of the read half;
the four writes are the primary's, like every write, and a write that reaches
a replica gets the ordinary `409 read-only-replica` naming where to take it.

**The desired-state document** is what the whole design turns on:

```json
{ "generation": 4183,
  "networks": [
    { "org": "acme", "network": "prod",
      "domain": "prod.acme.synchronicity.example",
      "budget_bytes": 2199023255552,
      "retention": "current",
      "device": { "label": "cloud-1", "nk": "…", "state": "active" } } ],
  "collect": [ { "org": "acme", "network": "old" } ] }
```

`domain` is the membership domain verbatim, because the fleet must never
assemble a name itself. `budget_bytes` and `retention` are **policy, decided
here** — the data plane is mechanism only — and they travel in the document
rather than in the fleet's configuration precisely so that a plan change is a
control-plane change and nothing else; today every network gets 2 TiB and
`current` retention. `device` is `null` until a key has been registered, which
is how a disk-less pod tells "a network I have never joined" from "a network
whose identity I must recover".

`collect` is the other list, and the one the fleet acts on with a delete rather
than a provision: offboarded networks whose retention hold has run out. It is
described on its own below.

`generation` is the zone's SOA serial, and the response carries it — plus one
more component, in a moment — as an `ETag`, so the steady-state poll is one
`304` per interval. The serial is already bumped in the same transaction by
everything that can change the `networks` half of this document — a device
registered or retired, a network deleted, the toggle flipped — so nothing has
to remember to move a counter, which is the class of mistake that shows up as a
fleet quietly serving last week's tenant set. It is deliberately *loose* rather
than tight: it is deployment-wide, and the hourly re-sign moves it too, so the
fleet occasionally refetches a small document it already had. The failure mode
of a loose generation costs bytes; the failure mode of a tight one that missed a
change is a network that never gets hosted.

The `collect` half cannot ride on the serial, though, and that is why the
`ETag` is not simply the generation. A network becomes due for collection
because a *clock* passed its stamp plus the hold: no transaction ran, no zone
fact changed, and the serial sits exactly where it was. A tag built from the
serial alone would answer `304` to every poll from then on and the fleet would
never see the entry — not a late collection, a collection that never happens,
which is the bug the list exists to fix. So the tag carries a second component:
how many networks are due, and the sum of their `cloud_disabled_at` stamps.
Both move under any change to the due set, including the one a count alone
would miss — a network falling due in the same interval as another is collected,
which leaves the count where it was and the set different.

What that still leaves, and it is fine: a collection can be **up to one poll
interval late**. The tag moves the moment the hold elapses, but nothing pushes;
the fleet finds out when it next asks. A deletion that happens sixty seconds
after it fell due is not a correctness problem, and it is said here rather than
left as a silent hole.

**Registration** creates the `devices`, `device_keys` and `network_devices`
rows in one transaction with the zone republish — the same transaction shape
`join_device` uses, so **the commit is the publish** and the zone names the key
immediately, which turns the fleet's wait for identification from a propagation
window into a DoH-cache-sized one. Re-`PUT` with the same `(label, nk)` is a
`200` that writes nothing and publishes nothing (`result.changed` says so),
which matters: a republish per poll would churn the very serial the `ETag` is
built from. The same label with a *new* key opens the standard two-key rotation
window when the old key is live, and replaces outright when the old key is
already revoked — the recovery path after a lost tenant database. `created_by`
on those rows is `system-dataplane`, a user seeded by migration v12 whose
"email" carries no `@` and which therefore no sign-in path can ever reach: no
human's id is impersonated, and the audit trail names the service.

The `DELETE` is what *closes* a rotation, and it exists because without it one
could be opened and never closed — the zone would carry two keys per label
forever, which the zone build caps but no design should lean on. Plain, it
moves the key to `retiring`; with `?revoke=1` it goes straight to `revoked`. It
refuses the last `active` key unless revoking, so the route cannot orphan a
healthy tenant, and it is confined to `cloud-*` devices of the named network,
so it cannot reach a customer's key however the path is spelled.

The **heartbeat** is stored, one row per network, last write wins — unlike the
browse tunnel's replication answer, which is deliberately unstored. The
difference is what each is for: the tunnel's answer is a live view and is
worthless stale, while this is the billing record and its whole value is that
it survives the tenant being down. A heartbeat that has stopped moving *is* the
alert. It is not audited: it arrives per tenant every few minutes, and a row
per breath would bury every act a human took.

### The retention hold, and collecting what it releases

Turning hosting off drains the tenant and takes its device out of the zone in
the same commit, but the bytes stay: thirty days, stated in
docs/CLOUD-DATAPLANE.md §6 and held here as a module constant in
`api/dataplane_api`, because the hold is policy and the fleet is mechanism. A
service that holds the bucket credentials must not also hold an opinion about
when a customer's data may go.

Within the hold, re-enabling is a cheap re-provision: the stamp is cleared, the
tenant database is restored from its replica stream, and the prefix is
re-adopted rather than replicated afresh. After it, the network appears in
`collect` — `cloud_hosted = 0`, a live `cloud_disabled_at`, and `now` past
`cloud_disabled_at + 30 days` — and the fleet deletes `tenants/<org>/<net>/`
and `db/<org>/<net>/`. The entry is just the two names, because those are what
the prefixes are keyed by; handing over the stamp or the deadline would be
giving the deleting service a second opinion about whether the hold had run.

Then it says so:

```
DELETE /dp/v1/networks/:org/:net/storage
{"ok": true, "network": "old", "collected": true}
```

Called **after** the bytes are gone, never before. It clears
`cloud_disabled_at`, which is what takes the network out of `collect` — without
it the list would repeat the same instruction on every poll for the rest of the
deployment's life — and writes one `cloud-hosting.storage.collect` row carrying
the stamp it just cleared and how long the hold actually ran, since the column
that would answer that later is the one being erased.

Two properties it is built around. It **refuses a network with `cloud_hosted =
1`, `409 cloud-hosting-enabled`**: collecting a live tenant's storage is the
catastrophic operation in this design, and while this service performs no
deletion, it must never be able to *record* one — a row asserting that a
running customer's bytes were collected is a claim somebody would have to
disprove later. And it is **idempotent**: a network with no stamp is a `200`
no-op with `"collected": false`, because the fleet deletes a great many objects
and then calls this, and a pod that died between the last object and the call
has no way to know which side of it it was on.

It is not a zone mutation, unlike the toggle that starts the clock. The toggle
republishes even when turning hosting *on* changes nothing in the zone, purely
so the serial moves and the fleet's conditional poll notices — but that reason
does not apply here, because the `collect` list has its own component in the
`ETag` and moves the tag by itself. Republishing would be worse than
unnecessary: nothing in the zone depends on `cloud_disabled_at` (the hosted
devices went a month earlier, in the commit that stamped it), so it would
re-sign and bump a deployment-wide serial — making *every* shard refetch —
because one tenant's bucket was emptied. It would also put a housekeeping call
behind the transparency gate, where it could be held back and leave the fleet
asked to collect the same prefix on every poll until a human noticed.

Audit actions this adds, all under the actor `dpkey:<id>` (its own namespace,
because `key:<id>` is resolvable against `api_keys` and this one is not):
`cloud-hosting.device.register`, `cloud-hosting.device.rotate`,
`cloud-hosting.key.retire`, `cloud-hosting.key.revoke`,
`cloud-hosting.storage.collect`. The mint itself is `dataplane.key.mint`, with
no org, under `system:dataplane-key-mint`.

**What this service does not do.** It runs no hosted replicas and stores no
customer bytes; `crates/synch-dp` does that, against this API. And a hosted
replica holds customer plaintext, as any replica does — that is stated in the
product, not discovered in the fine print, and it is why enabling hosting is an
explicit org-admin act.

## `GET /SKILL.md`

Every role serves [`priv/skill/SKILL.md`](priv/skill/SKILL.md) at
`/SKILL.md` as `text/markdown` — a guide to the `synch` CLI written for
whoever, or whatever, has to drive a node: the daemon model, references
and version policies, membership and delegation, key rotation, recovery,
and the error messages each of those produces.

It also documents **this service's own API**, since the node that answers
`/SKILL.md` is the node that answers `/api`: how to hold an org-scoped API
key, every route one can reach, the four families it never can, and what each
refusal means. A guide that tells an agent to "add the device on the network's
page" and stops there has handed it a step it cannot take.

It is mounted beside `/healthz` rather than behind the product API, and
so is public and role-agnostic: it needs no session, no database and no
zone, and an operator pointed at any node of a deployment — primary,
replica, external — gets the same document from the same URL. That is
the only property that makes the URL worth handing out.

The file rides in the shipment, and `ops/image-smoke.sh` fetches it from
the built image rather than trusting the `COPY`; a build that dropped it
would boot, serve, and pass every other check.

## Stack

- **Backend**: Gleam on OTP 27 (pinned via `.tool-versions`, asdf).
  SQLite behind `csqlite/` — a small C port program speaking a framed
  stdio protocol, one OS process per connection, so the BEAM never loads
  SQLite (no NIFs; links against the system libsqlite3). Each worker
  sandboxes itself before reading its first frame: Landlock + a seccomp
  allowlist + rlimits on Linux, pledge + unveil on OpenBSD, confining
  it to stdio and the database's own directory. Zones are pre-signed at
  mutation time and served straight from SQLite through a pool of
  reset-on-checkout workers (one read transaction per answer).
- **Frontend**: Vite + React + TypeScript + Tailwind (`web/`).
- **Replication**: primary + read-only replicas fed by external,
  operator-owned tooling (e.g. litestream). Replicas serve the dashboard,
  the read half of the API and the file browser off the same copy, and DNS
  too where this deployment serves its own zone. See `ops/RUNBOOK.md`, and
  `ops/worker/` for a Cloudflare Worker that balances the entry name.

## Developing

```sh
asdf install            # erlang + gleam per .tool-versions
                        # also install rebar3 (builds Erlang deps like ranch):
                        #   curl -fsSL -o ~/bin/rebar3 https://s3.amazonaws.com/rebar3/rebar3 && chmod +x ~/bin/rebar3
                        # CI gets it from setup-beam's rebar3-version input
make -C csqlite         # needs libsqlite3-dev
gleam test              # backend suite
just dev                # backend :8080 + vite dev server
just e2e                # delv + the real synchronicity resolver validate
                        # a served zone end to end (needs bind9-dnsutils,
                        # rust, and the repo's crates/)
node --test ops/worker/lb.test.mjs   # the entry-name balancer
```

`just dev` reads the `CP_*` environment (see the table below); every node
needs at least `CP_ROLE`, `CP_BASE_DOMAIN`, `CP_DB_PATH`, `CP_SESSION_SECRET`
and `CP_PUBLIC_URL`, plus `CP_KEY_FILE` on a serving primary and
`CP_PRIMARY_URL` on a replica.

The e2e is the load-bearing test: `delv` must report `fully validated`
for positive, NODATA and NXDOMAIN answers over UDP and TCP, and the
actual client resolver (`crates/synch-net`) must validate and parse the
member set over DoH — rotation windows, revocations and all.

## Container image

`ghcr.io/afk-surf/synchronicity/control-plane`, built from
[`Dockerfile`](Dockerfile) by
[`.github/workflows/control-plane-image.yml`](../.github/workflows/control-plane-image.yml)
for `linux/amd64` and `linux/arm64`. `latest` follows `main`; tagged
releases get `X.Y.Z` and `X.Y`; every build is also tagged
`sha-<commit>` and carries signed build provenance
(`gh attestation verify oci://…` / `cosign verify-attestation`).

The image contains what the systemd deployment does — the Erlang
shipment, `priv/csqlite`, and the built SPA in `priv/web` — and runs the
primary and the replica alike: `CP_ROLE` picks, and every other setting
is the same `CP_*` environment described below. It runs as uid/gid
10001, and the entrypoint takes the service's subcommands, so `keygen`,
`ds`, `rekor-publish`, `seed-admin` and `migrate-check`
work the same way `serve` does.

```sh
# The zone key, generated once and kept outside the database's directory
# (the csqlite sandbox grants that directory — see Configuration).
docker run --rm -v cp-keys:/etc/synch-controlplane \
  ghcr.io/afk-surf/synchronicity/control-plane \
  keygen sync.example /etc/synch-controlplane/csk.key

docker run -d --name cp \
  -e CP_ROLE=primary \
  -e CP_BASE_DOMAIN=sync.example \
  -e CP_KEY_FILE=/etc/synch-controlplane/csk.key \
  -e CP_SESSION_SECRET="$(openssl rand -hex 32)" \
  -e CP_NS_HOSTS='ns1=192.0.2.1;ns2=192.0.2.53' \
  -e CP_PUBLIC_URL=https://sync.example \
  -v cp-keys:/etc/synch-controlplane \
  -v cp-data:/var/lib/synch-controlplane \
  -p 8080:8080 -p 53:53/udp -p 53:53/tcp \
  ghcr.io/afk-surf/synchronicity/control-plane
```

- **Volumes.** `/var/lib/synch-controlplane` holds the database at
  `/var/lib/synch-controlplane/db/cp.db` — the image's only default,
  `CP_DB_PATH`, and a path rather than a policy. The zone key belongs on
  a *separate* mount (`/etc/synch-controlplane` above): a csqlite worker
  sandboxes itself to the database's own directory, so anything else
  living there is inside the sandbox. Replicas mount the database
  read-write (SQLite needs it) and must leave `CP_KEY_FILE` unset —
  they hold no key material. Replication stays external and
  operator-owned; the atomic-rename contract in `ops/RUNBOOK.md` is
  unchanged by containers, and litestream sees the same file.
- **Ports.** 8080/tcp (dashboard, API, DoH) and 53 on UDP and TCP.
  Binding 53 as a non-root user works under Docker, which sets
  `net.ipv4.ip_unprivileged_port_start=0` in the container's network
  namespace. On a runtime that does not (Kubernetes), either set that
  sysctl or move `CP_DNS_LISTEN` to a high port and map 53 to it.
- **The sandbox needs the host's cooperation.** Each csqlite worker
  still applies its seccomp allowlist and rlimits, but Landlock needs a
  kernel that has it enabled and a container seccomp profile that
  permits the `landlock_*` syscalls (Docker's default profile does).
  Where it is missing the worker warns on stderr —
  `csqlite: landlock unsupported here; filesystem unconfined` — and
  keeps serving; treat that line as a deployment defect, not noise.
- **Health.** `HEALTHCHECK` polls `/healthz`, which reports the served
  SOA serial and signature expiry — on a replica that is how a stalled
  restore loop shows up. It probes port 8080; if `CP_HTTP_LISTEN` moves,
  set `CP_HEALTHCHECK_PORT` to match.

Nothing is published until that exact image has booted:
[`ops/image-smoke.sh`](ops/image-smoke.sh) runs the built image the way
this section tells you to run it — `keygen` and `seed` into fresh named
volumes, then `serve` — and checks what only running it can check. The
shipped SPA is served with its bundle, `/SKILL.md` answers with the CLI
guide, `/healthz` reports a loaded zone,
the authoritative DNS answers over UDP and TCP with signatures, the
csqlite workers come up sandboxed under the default runtime profile, the
service is uid 10001, and the image's own `HEALTHCHECK` goes healthy.
The publish job depends on it, so a green image is one that ran.

To build it locally, from the repository root:

```sh
docker build -t controlplane control-plane
```

Or from `control-plane/`, build and smoke-test it in one step (needs
`docker`, `curl` and `dig`):

```sh
just image-smoke
```

## Configuration

The service reads only `CP_*` environment variables. Missing required
values refuse to start — there are no defaults for anything that
changes what the service *is*. Unset optional providers (SMTP, Google,
GitHub) disable that path.

IPv6 listen addresses are written in brackets: `[::1]:53`.
`CP_HTTP_PORT` and `CP_DNS_PORT` are gone; the port lives in the
listen address.

Two DNS modes. `CP_DNS_MODE=serve` (the default) makes this service the
authoritative nameserver: it signs the zone with its own CSK and answers
on `CP_DNS_LISTEN`. `CP_DNS_MODE=external` instead publishes the
membership records into a zone a managed provider hosts and signs
(Cloudflare or Bunny), running no DNS listeners and holding no zone key
— the provider's fleet is the redundancy, so the mode is primary-only
and `CP_KEY_FILE`, `CP_DNS_LISTEN` and `CP_NS_HOSTS` must be unset.
Provider configuration present while the mode is `serve` refuses to
start: a credential that quietly does nothing is a lie. See
[docs/EXTERNAL-DNS-PROVIDER.md](../docs/EXTERNAL-DNS-PROVIDER.md).

| Variable | Role | Meaning |
|---|---|---|
| `CP_ROLE` | both | Required. `primary` or `replica`. |
| `CP_BASE_DOMAIN` | both | Required. Zone apex, no trailing dot (`sync.example`). |
| `CP_DB_PATH` | both | Required. SQLite file, absolute path, in its own directory (the sandbox grants that directory — keep the key out of it). |
| `CP_KEY_FILE` | primary | Required on the primary in serve mode (zone CSK). Must live outside the database's directory. **Must be unset on replicas** and with `CP_DNS_MODE=external` — there is no zone CSK to hold. |
| `CP_HTTP_LISTEN` | both | HTTP / DoH bind as `address:port`. Default `0.0.0.0:8080`. |
| `CP_DNS_LISTEN` | both | Authoritative DNS (UDP + TCP) bind as `address:port`. Default `0.0.0.0:53`. Must be unset with `CP_DNS_MODE=external` — the provider answers. |
| `CP_NS_HOSTS` | primary | Semicolon-separated `host=ipv4[,ipv6]` NS glue, e.g. `ns1=192.0.2.1;ns2=192.0.2.53,2001:db8::53`. Hostnames without dots are relative to the apex. Must be unset with `CP_DNS_MODE=external`. |
| `CP_DNS_MODE` | both | `serve` (default) or `external`; `external` is primary-only. See "Two DNS modes" above. |
| `CP_DNS_PROVIDER` | primary | Required with `CP_DNS_MODE=external`: `cloudflare`, `bunny` or `log-only` (no credentials — prints the change set instead of applying it). |
| `CP_SIGNING_ZONE` | primary | External mode only. The zone the provider actually hosts, when it is not the apex — e.g. a control plane at `sync.example.com` living inside the `example.com` zone, with no delegation of its own. Must contain the apex; default is the apex. |
| `CP_CLOUDFLARE_API_TOKEN` | primary | Required when the provider is `cloudflare`. Zone-scoped API token. |
| `CP_CLOUDFLARE_ZONE_ID` | primary | Cloudflare zone id. Default empty: discovered by zone name at boot. |
| `CP_CLOUDFLARE_API_URL` | primary | Cloudflare API base URL override; default empty means the real endpoint. A test/e2e hook, like `CP_REKOR_URL`. |
| `CP_BUNNY_API_KEY` | primary | Required when the provider is `bunny`. |
| `CP_BUNNY_ZONE_ID` | primary | Bunny DNS zone id. Default empty: discovered by zone name at boot. |
| `CP_BUNNY_API_URL` | primary | Bunny API base URL override; default empty means the real endpoint. |
| `CP_PUBLIC_URL` | both | **Required.** This node's own external base URL: links and OAuth callbacks on the primary, and on every node the attach endpoint daemons dial and sign their proof over. It is published verbatim at `_synchronicity-cp.<base>`, so it must be an `https://` or `http://` origin with no whitespace — refused at boot rather than in every daemon a TTL later. |
| `CP_SESSION_SECRET` | both | Required, ≥32 characters. Signs session cookies. **The same value on every node**: a replica verifies cookies the primary minted, and one byte of difference is a dashboard nobody can sign in to. |
| `CP_PRIMARY_URL` | replica | Required. The primary's URL — what a refused write and the login screen point at. Nothing in a replicated database says which node holds the pen, so this is the one fact a read-only node cannot derive. |
| `CP_SMTP_HOST` | primary | SMTP hostname. Absent means log-only mail — magic links and invitations go to the service's stdout — and the login page stops offering the form unless no other sign-in method is configured. |
| `CP_SMTP_PORT` | primary | SMTP port. Default `587`. Used only when `CP_SMTP_HOST` is set. |
| `CP_SMTP_USER` | primary | SMTP username. Default empty. Set, the relay must offer STARTTLS and present a certificate this host trusts: the credential is never put on the wire in the clear. |
| `CP_SMTP_PASS` | primary | SMTP password. Default empty. |
| `CP_SMTP_FROM` | primary | Required when `CP_SMTP_HOST` is set. The `From` header, so a display name is welcome — `Synchronicity <sync@example.com>`. The envelope sender is the bare address inside it. |
| `CP_GOOGLE_CLIENT_ID` | primary | Google OAuth client id. Both id and secret must be set to enable Google sign-in; unset, it is hidden from the login and settings screens. |
| `CP_GOOGLE_CLIENT_SECRET` | primary | Google OAuth client secret. |
| `CP_GITHUB_CLIENT_ID` | primary | GitHub OAuth client id. Both id and secret must be set to enable GitHub sign-in; unset, it is hidden from the login and settings screens. |
| `CP_GITHUB_CLIENT_SECRET` | primary | GitHub OAuth client secret. |
| `CP_REKOR_URL` | primary | Zone-key transparency log write endpoint (Rekor v2, `POST /api/v2/log/entries`). Unset — the normal case — the shard in service is read from the stored `trusted_root.json`, so a Sigstore rotation costs a metadata refresh and not a release. |
| `CP_REKOR_KEY` | primary | File pinning the log's verification key — a PEM `PUBLIC KEY` block or one base64 SubjectPublicKeyInfo, `#` starting a comment. Exactly one key: this service submits to one log and stores the proof under that log's id. Unset, the key comes from the same trusted-root entry as the endpoint. Set it for a self-hosted log, together with `CP_REKOR_URL`. |
| `CP_REKOR_REQUIRE` | primary | `true` refuses to publish a zone whose active key has no verified log record. Default off — the rollout publishes before it enforces. |
| `CP_ENTRY_URL` | both | The name a browser reaches this deployment at — the load-balanced entry name. Defaults to `CP_PUBLIC_URL`, which is right for a single node. OAuth callbacks, magic links and invitations are built from it: behind a balancer, a link built from one node's own name returns the person there and leaves their new session cookie on it. `ops/worker/` is a Cloudflare Worker that balances the entry name correctly. |
| `CP_ENDPOINTS` | primary | This deployment's *other* control-plane endpoints, comma- or semicolon-separated. Each becomes its own `v=synccp1 url=` record at `_synchronicity-cp.<base>` beside this node's `CP_PUBLIC_URL`, which is how the apex says where this base's control plane answers. Cloud attach is the first thing to dial them, and today the only one: every daemon opens a standing tunnel to **each**, because the registry of attached daemons is one node's memory and a node no daemon attached to can answer no browse question however current its copy of the database is. At most 8 endpoints in total, refused at boot rather than by counting sockets. |
| `CP_DNSSEC_CHAIN_RESOLVER` | primary | DoH endpoint the DNSSEC chain in a log entry is collected from. Default `https://cloudflare-dns.com/dns-query`. Not a trust decision — every reader verifies the signatures itself — so point it at your own validating resolver if you would rather not tell a third party when you rotate keys. |

Day-2 operations (replicas, key ceremony, backups) live in
`ops/RUNBOOK.md`.
