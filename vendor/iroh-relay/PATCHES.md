# Local ping deadline accessor

This is iroh-relay 1.0.3, from upstream commit
`f2eb930dda3779c6d852b72f3712aacd6e573ab1`, under MIT OR Apache-2.0.

The root MIT and Apache license files are copied from that same upstream commit.
The packaged changelog has its extra trailing blank line removed.

`src/ping_tracker.rs` adds `PingTracker::deadline`, a read-only view of the
pending ping deadline. It lets the patched Iroh receiver inspect buffered pongs
before consuming a timeout. The existing timeout method, adaptive timeout
calculation, and relay-server behavior are unchanged.

See [the Iroh patch description](../iroh/PATCHES.md) for the failure mode,
bounded receive behavior, tests, and removal condition.
