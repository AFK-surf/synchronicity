# Source and replica roles

Status: **implemented**.

Synchronicity models three independent local facts:

- a **source** publishes this node's assertions for a space;
- a **replica** durably retains content published by every visible origin;
- a **checkout** is an optional newest-view filesystem projection of a replica.

Metadata exchange is independent of all three. Trusted nodes can discover and
read a space without publishing it, retaining it, or materializing it.

## Sources

```text
synch source add media /srv/media
synch source add uploads --api
synch source ls [media]
synch source scan [media]
synch source rm media
```

A filesystem source is scanned and watched. An API source has no directory and
is populated through typed writes such as the control API or a read-write S3
bucket.

Publishing a live file or socket is transactional with a durable source hold.
Before the own head may move, the store must contain the complete object at the
published size with `durable = 1`. The same transaction installs
`source:<space>` ownership and a complete `BlobAd`. Deleting or replacing the
last own live entry that names a root releases that source hold.

Removing a source unpublishes this origin's entries. It does not remove a
replica of the same namespace.

## Replicas

```text
synch replica add media                         # current retention
synch replica add archive --retention forever
synch replica add media --grace 30d --budget 8TiB
synch replica set media --checkout /srv/media-view
synch replica ls [media]
synch replica sync [media]
synch replica rm media
synch replica rm media --pin-held
```

A replica acquires every content root named by the visible current entries for
its space, from every origin. It publishes no file entries of its own.

Retention policies are:

- `current`: roots leaving the current tree are released after the grace
  period;
- `forever`: roots observed while the replica is active are never released.

The optional budget is an admission ceiling. It accepts exact bytes or decimal
and binary units such as `500GB` and `8TiB`; zero admits no non-empty object.
It stops new acquisitions and does not evict already-held data or shorten grace
periods. Omitting it, or using `replica set --no-budget`, removes the ceiling.

Replica removal always removes the standing policy. By default its replica
holds are released. `--pin-held` converts them to explicit operator pins first,
so there is no unnamed “inactive replica that still retains everything” state.

## Checkouts

A replica may own one checkout:

```text
synch replica add media --checkout /srv/media-view
synch replica set media --checkout /srv/new-view
synch replica set media --no-checkout
```

The checkout always follows the unified `newest` selection. Origin-specific,
strict, historical, and multiple checkouts are deliberately unsupported.
Foreground reads provide those views without creating another standing mode.

A checkout never fetches content itself. Replica acquisition first establishes
the durable hold; checkout reconciliation then materializes only content the
replica already holds. Checkout roots may not overlap source roots or another
checkout. Removing checkout configuration leaves ordinary files in place.

## Healing

Durable roles are persistent intent. If a local payload is missing or
truncated, or a cloud backend authoritatively reports the object absent, the
node:

1. withdraws the false complete/durable claim;
2. removes the invalid source/replica hold;
3. creates a `content_want` for every affected persistent holder;
4. fetches and verifies the object from an advertising peer;
5. restores the durable hold and complete advertisement.

There is no proactive periodic byte scrub in this change. Healing begins when
an actual read or backend response proves loss. Cache-only content has no
persistent holder and is not automatically repaired.

## Role independence

The persistent model uses separate `sources` and `replicas` tables. Either,
both, or neither may exist for a namespace. The `pins` holder and
`content_want` holder identify which promise owns a root.

| Local state | Publishes | Durably retains peer content | Filesystem view |
|---|---:|---:|---:|
| remote only | no | no | no |
| filesystem/API source | yes | own live content | filesystem source only |
| replica | no | yes | optional checkout |
| source + replica | yes | yes | source and optional checkout |
