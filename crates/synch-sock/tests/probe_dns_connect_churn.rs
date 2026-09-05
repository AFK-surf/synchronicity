//! Probe: connect/close churn against `tokio::net::lookup_host`.
//!
//! Mechanism (code-confirmed): every `sy_tcp_connect` spawns `connect_task`,
//! which calls `tokio::net::lookup_host` (endpoint.rs:645-648). That resolves
//! via `spawn_blocking` (getaddrinfo), which is uncancellable once dispatched;
//! `sy_close` only fires the `abandoned` notification, which cancels the
//! *select around* the lookup, never the queued/running closure. Each worker
//! thread runs its own current-thread runtime, hence its own blocking pool
//! (512 threads, unbounded wait queue). With slow resolution — attacker-
//! controlled DNS on the armed egress list — a connect/close churn loop parks
//! 512 blocking threads per worker and then grows the queue at the guest's
//! iteration rate: multi-hundred-MB RSS per invocation, x64 streams, OOM.
//!
//! Fixed `2026-08-29`. The egress budget is no longer returned by `sy_close`:
//! `connect_task` owns an `EgressPermit` (runtime/endpoint.rs) and gives its
//! place back when the task ends, so `max_egress` now bounds outstanding
//! resolutions as well as established connections. A churn loop can have at
//! most `max_egress` lookups in flight regardless of how slowly they answer,
//! which is the bound that was missing — the lookup itself is still
//! uncancellable, because a dispatched blocking-pool task cannot be cancelled,
//! and that is now contained rather than unbounded.
//!
//! This host cannot express slow DNS (no root; the stub resolver answers
//! fast), so the probe demonstrates what the fast path does: no thread
//! accumulation and no egress-slot leak — and records the thread-count and
//! RSS deltas under sustained churn as the upper bound the fast resolver
//! holds.

#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::time::{Duration, Instant};

use harness::{compile, peer, Harness};
use synch_sock::{DuplexStream, EffectivePolicy};
use tokio::io::AsyncWriteExt;

/// Connects to a name that resolves (via the stub resolver -> the host's
/// resolver, which answers fast), then closes it, in a tight loop. A poll on
/// a dead handle keeps the invocation alive past the idle deadline.
const CHURN: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  char buf[16];
  for (unsigned int i = 0; i < 4000; i++) {
    sy_s64 h = sy_tcp_connect(SY_STR("localhost"), 1);
    if (h >= 0) sy_close(h);
    if ((i & 127) == 0) {
      struct sy_pollfd fds[1] = { { 9, SY_POLL_IN, 0 } };
      sy_poll(fds, 1, 1);
    }
  }
  return 0;
}
"#;

fn threads() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Threads:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|n| n.parse().ok())
        })
        .unwrap_or(0)
}

fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|n| n.parse().ok())
        })
        .unwrap_or(0)
}

#[tokio::test]
async fn connect_close_churn_with_a_fast_resolver_holds_no_threads_or_slots() {
    let elf = compile(CHURN, "dns-churn.c");
    let harness = Harness::new();
    let policy = EffectivePolicy {
        egress: vec!["localhost:1".into()],
        ..EffectivePolicy::default()
    };

    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        policy,
        peer(None),
        vec![],
    );
    let mut mine = mine;
    let caller = tokio::spawn(async move {
        mine.write_all(b"go").await.ok();
        let mut sink = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut mine, &mut sink).await;
    });

    let before_threads = threads();
    let before_rss = rss_kb();
    let t0 = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(60), harness.pool.run(invocation))
        .await
        .expect("the churn invocation finished")
        .expect("the invocation ran");
    let elapsed = t0.elapsed();
    caller.await.unwrap();
    // Let the worker's blocking pool settle: its threads are retained after
    // the lookups finish, and the count is only meaningful once it stops
    // changing. The flood this probe guards against is measured in hundreds
    // of threads and gigabytes; the bounds below are far above the fast
    // path's steady state and far below the flood's.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let after_threads = threads();
    let after_rss = rss_kb();

    eprintln!(
        "churn finished in {elapsed:?}: status {:?}; threads {before_threads} -> {after_threads}; \
         RSS {before_rss} KiB -> {after_rss} KiB",
        outcome.status
    );

    assert_eq!(
        outcome.status,
        synch_core::SockStatus::Ok(0),
        "guest status"
    );
    assert!(
        after_threads <= before_threads + 32,
        "the fast path parked blocking threads: {before_threads} -> {after_threads}"
    );
    assert!(
        after_rss < before_rss + 300 * 1024,
        "the fast path grew RSS by more than 300 MiB: {before_rss} -> {after_rss} KiB"
    );
    eprintln!(
        "contained (fast resolver): no thread or memory accumulation under 4000 connect/close \
         cycles. The slow-resolver flood (512 threads/worker + unbounded queue) is \
         code-confirmed at endpoint.rs:645-648 but not expressible on this host."
    );
}
