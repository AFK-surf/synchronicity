# Control-plane load balancer

One Cloudflare Worker, [`lb.js`](lb.js), for the entry name of a
primary + replicas deployment (see [`../RUNBOOK.md`](../RUNBOOK.md)).

The control plane already splits itself: a replica answers every GET off its
read-only copy and refuses every write with `409 read-only-replica`. This
Worker's whole job is to send each request somewhere that can serve it, and
to spread the reads — which are the load.

| Request | Goes to |
|---|---|
| `GET`/`HEAD` under `/api`, the SPA, `/healthz`, `/SKILL.md`, `/dns-query` | a replica, then the next, then the primary |
| Anything else under `/api` | the primary |
| Anything under `/auth` | the primary — these end in a session row |
| `GET /api/auth/methods` | the primary — a replica answers about *itself* |
| `/agent/v1/attach` | nowhere: **421**, with the record to read instead |

Reads are **sticky per reader, per region**. Replication is asynchronous, so
two replicas are two different moments of the same database: a reader bounced
between them watches the zone go backwards — a network they just created is
there, gone, and there again. So the replica that served a reader is
remembered against a digest of their address in a Cache API namespace of the
Worker's own — `caches.open(...)`, not `caches.default`, so pins never share a
namespace with real responses and no request can name one — and reused for
five minutes. The Cache API is per colo, which is where "per region" comes
from.

Best-effort, and the ways it gives way are all the same shape — the reader is
balanced instead of pinned, never refused:

- a reader whose requests land in two colos has two pins, and may see two
  replicas;
- a reader behind no `cf-connecting-ip` (and no `x-forwarded-for`) is not
  pinned at all, because one shared pin would put a whole colo's anonymous
  traffic on one replica;
- a pin naming a node no longer in `REPLICAS` is ignored;
- a pinned node that fails is retried past *and the pin moves* to whatever
  answered — a pin nobody updates on failure sends every later request
  through a dead node first;
- the primary is never pinned. It is the fallback, not a replica.

The pin is written after the response is on its way (`waitUntil`), so no
reader ever waits on a cache write whose only purpose is to make a *later*
request consistent.

It is not a route table. The service guarantees that every route a replica
mounts is a `GET`, so method and prefix decide it, and there is no second copy
of the router here to fall out of date. The three named paths are the
exceptions to that shape, and each says why in the source.

**Attach is never proxied.** A daemon signs its attach proof over the URL it
dialed and each node verifies against its own `CP_PUBLIC_URL`, so a tunnel
relayed from the entry name presents a proof for the wrong URL. Daemons read
each node's own name from `_synchronicity-cp.<base>` and dial it directly.

## Configure

Two vars, in [`wrangler.toml`](wrangler.toml) or the dashboard:

    PRIMARY   https://cp0.sync.example
    REPLICAS  https://cp1.sync.example,https://cp2.sync.example

`REPLICAS` may be empty — then every request goes to the primary, which is a
single-node deployment with a balancer in front of it and works fine.

On the nodes, set `CP_ENTRY_URL` to this Worker's name so magic links, OAuth
callbacks and invitations come back here rather than to whichever node minted
them.

## Test

    node --test ops/worker/lb.test.mjs

Twenty-seven cases: where each route in the service's own read and write
tables is sent; the handler driven against stub origins for forwarding, retry
and the two refusals; and stickiness against a stubbed Cache API — one reader
staying put, two readers pinned independently, a re-pin past a failed node, a
stale pin ignored, and every way it degrades. The cache stub throws if
`caches.default` is touched, so the namespace is a property the tests hold
rather than one the source merely happens to have. CI runs it in the `worker`
job.
