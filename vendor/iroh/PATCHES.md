# Local Iroh relay scheduling and discovery patches

This is Iroh 1.0.3, from upstream commit
`f2eb930dda3779c6d852b72f3712aacd6e573ab1`, under MIT OR Apache-2.0.
The root MIT and Apache license files are copied from that same upstream commit.
The workspace patches both `iroh` and `iroh-relay` to these local copies.
The relay dependency in this manifest also points to `../iroh-relay`, so its
standalone tests exercise the same patch.

The relay actor's biased select checked an expired ping timer before its
receive stream. After a scheduling delay, a matching pong could already be
buffered while the actor reported a ping timeout and reconnected. The adaptive
ping deadline can be only 500 ms. On a busy hosted data plane, unnecessary
reconnections add TLS work and make scheduling delays worse.

Both the connected and sending loops now wait for a non-consuming deadline.
Before declaring that deadline a failure, they poll at most 32 ready responses
through the existing decoder and message handler. A matching pong preserves the
connection. Missing or incorrect responses still time out; unrelated traffic
cannot extend the deadline indefinitely. The bounded drain bypasses Tokio's
cooperative budget so an exhausted task budget cannot masquerade as an empty
receive buffer. Normal receive processing and timeout durations are unchanged.

The paired `iroh-relay` patch adds the read-only `PingTracker::deadline` accessor.
The existing consuming `timeout` method and relay-server behavior are unchanged.
No membership, TLS verification, discovery, relay fallback, or protocol formats
change.

Address discovery consumed the first QUIC address report, then initialized the
retained connection's result cache to `None`. The stream emits only changes, so
a stable address never populated that cache. Every incremental report could
therefore open new QUIC/TLS connections despite retaining a healthy connection.
Both address families now cache the initial report. Full scans still refresh
connections, and closed connections are still replaced.

The retained connection's address watcher also used the cancellation token for
surplus probes. Finishing a scan early could stop that watcher. It now follows
the report's shutdown token instead; dropping the retained connection still
aborts the watcher through its existing owned task handle.

Regression tests in `src/socket/transports/relay/actor.rs` cover a buffered
matching pong after a scheduling delay in the real send loop, a pong behind
unrelated responses, an exhausted cooperative task budget, missing or incorrect
pongs, and an always-ready response flood. The buffered-pong send-loop test fails
against the original selection order and passes with this patch.

Tests in `src/net_report.rs` use real local QUIC servers and count completed
handshakes. For both IPv4 and IPv6, six stable reports establish one connection,
then a full refresh and a closed connection each establish one replacement.
Before the cache fix, those six stable reports establish six connections. A
separate regression cancels a surplus probe, rebinds the client UDP socket, and
checks that the retained connection reports the new address without another
handshake; it fails if the address watcher shares the surplus-probe token.

Run the vendored crate separately; excluded workspace dependencies do not
resolve their test dependencies through the workspace root:

```sh
cargo test --manifest-path vendor/iroh/Cargo.toml \
  --target-dir /tmp/synch-iroh-test-target \
  --no-default-features --features tls-aws-lc-rs,platform-verifier,test-utils \
  --lib socket::transports::relay::actor::tests

cargo test --manifest-path vendor/iroh/Cargo.toml \
  --target-dir /tmp/synch-iroh-test-target \
  --no-default-features --features tls-aws-lc-rs,platform-verifier,test-utils \
  --lib net_report
```

Remove these patches when upstream preserves buffered pongs across scheduler
delays and reuses healthy discovery connections while continuing to observe
address changes, with equivalent bounded processing and regressions.
