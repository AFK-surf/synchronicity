# CAS / mptsync / ingest Lean model

This package proves the small transition system behind the CAS safety claim.
It is intentionally not a model of SQLite or a filesystem. Instead, each Lean
transition corresponds to one named Rust linearization point, and
`check-anchors.sh` makes that correspondence bidirectional.

```sh
cd specs/lean
lake build --wfail
./check-anchors.sh
```

The proof boundary is explicit:

- one process owns the data directory through `LifecycleLock`;
- SQLite immediate transactions are atomic;
- the Store connection guard orders lease registration against GC unlink;
- the unconditional `Store::delete_blob` API is not concurrent with writers;
- verified content hashes identify the bytes, and the configured durable
  backend satisfies its write contract.

The principal theorem is
`Synchronicity.Safety.gc_cannot_create_promised_missing`: every reachable
state with a pin still has available durable content. Metadata-only entries
are deliberately not promises, so the model also permits GC to win before a
remote promotion and requires a replica promotion to produce a `want`.
