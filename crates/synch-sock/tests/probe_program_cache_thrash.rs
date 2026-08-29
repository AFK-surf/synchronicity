//! Probe: a caller cycling more than 32 armed content roots forces a JIT
//! recompile on every admission (fixed `2026-08-29`: the recompile no longer
//! runs on the worker thread — see `probe_compile_offthread`, which measures
//! that directly with a program big enough for the difference to be visible;
//! the small programs here compile in under a millisecond, which is why this
//! probe never reproduced the stall it describes).
//!
//! `program_for` (runtime/mod.rs:575-609) JIT-compiles on a cache miss,
//! synchronously, on the worker's single current-thread runtime, *before*
//! `run_job` enters the select loop that services preemption, the idle
//! deadline, and cancel. The cache holds `MAX_CACHED_PROGRAMS = 32` entries
//! per worker with oldest-first eviction. So a member who can reach >= 33
//! armed sockets (or whose `--auto` re-arms keep minting fresh roots)
//! alternates admissions and forces a full ELF load + JIT per admission.
//!
//! Break signature: (a) re-admitting a root that was evicted measurably costs
//! a compile (cold admission latency >> warm hit), and (b) while cold
//! admissions happen, a co-resident invocation's echo round-trips stall.

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::time::{Duration, Instant};

use harness::{compile_with, peer, Harness};
use synch_sock::{DuplexStream, EffectivePolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A poll-echo loop, parameterized by `RET` so each compile yields a distinct
/// content root.
const ECHO: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  char buf[64];
  for (;;) {
    struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
    sy_s64 r = sy_poll(fds, 1, -1);
    if (r < 0) return r;
    if (r > 0) {
      sy_s64 n = sy_read(SY_SELF, buf, sizeof buf);
      if (n == 0) return RET;
      if (n < 0 && n != SY_EAGAIN) return n;
      sy_write(SY_SELF, buf, n);
    }
  }
}
"#;

/// One round-trip of the resident echo.
async fn ping(
    w: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
    r: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
) -> Duration {
    let t0 = Instant::now();
    w.write_all(b"x").await.unwrap();
    let mut one = [0u8; 1];
    r.read_exact(&mut one).await.unwrap();
    t0.elapsed()
}

/// A one-shot invocation of `elf` that echoes a byte and returns.
async fn one_shot(harness: &Harness, elf: &[u8]) -> Duration {
    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let (mut mine_r, mut mine_w) = tokio::io::split(mine);
    let t0 = Instant::now();
    let caller = tokio::spawn(async move {
        mine_w.write_all(b"x").await.ok();
        mine_w.shutdown().await.ok();
        let mut out = Vec::new();
        mine_r.read_to_end(&mut out).await.ok();
    });
    let _ = harness.pool.run(invocation).await.unwrap();
    caller.await.unwrap();
    t0.elapsed()
}

#[tokio::test]
async fn cycling_more_roots_than_the_cache_evicts_and_stalls_residents() {
    let harness = Harness::new(); // one worker, like a degraded daemon

    // 33 distinct programs: one resident, 32 churners. 33 > MAX_CACHED (32).
    let programs: Vec<Vec<u8>> = (0..33u32)
        .map(|i| compile_with(ECHO, "echo.c", &[("RET", &i.to_string())]))
        .collect();

    // Resident: an invocation of program #0 kept alive by the test.
    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let resident = harness.invocation(
        &programs[0],
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let (mut my_r, mut my_w) = tokio::io::split(mine);
    let pool = harness.pool.clone();
    let resident_task = tokio::spawn(async move { pool.run(resident).await });
    let mut first = [0u8; 1];
    my_w.write_all(b"x").await.unwrap();
    my_r.read_exact(&mut first).await.unwrap();

    // Baseline round-trip latency while nothing else runs.
    let mut baseline: Vec<Duration> = Vec::new();
    for _ in 0..10 {
        baseline.push(ping(&mut my_w, &mut my_r).await);
    }
    let base_median = median(&mut baseline);
    eprintln!("baseline echo round-trip: {base_median:?}");

    // Churn: cold-admit programs 1..=32, each a one-shot invocation. Every
    // admission is a cache miss -> synchronous JIT on the worker, during
    // which the resident's polls sit unpolled.
    let mut churn_stalls: Vec<Duration> = Vec::new();
    for elf in &programs[1..=32] {
        let _ = one_shot(&harness, elf).await;
        churn_stalls.push(ping(&mut my_w, &mut my_r).await);
    }
    let churn_median = median(&mut churn_stalls);
    eprintln!("echo round-trip during churn: {churn_median:?}");

    // Re-admit root #0: if the cache evicted it, this costs a full compile.
    let readmission = one_shot(&harness, &programs[0]).await;
    eprintln!("re-admission of the evicted root: {readmission:?}");

    // Warm-hit control: program #1 is still cached.
    let warm = one_shot(&harness, &programs[1]).await;
    eprintln!("warm re-admission of a cached root: {warm:?}");

    resident_task.abort();

    let stall_ratio = churn_median.as_nanos() as f64 / base_median.as_nanos().max(1) as f64;
    let readmit_ratio = readmission.as_nanos() as f64 / warm.as_nanos().max(1) as f64;
    eprintln!(
        "resident stall ratio during churn: {stall_ratio:.1}x; re-admission ratio: {readmit_ratio:.1}x"
    );

    if stall_ratio > 3.0 || readmit_ratio > 3.0 {
        panic!(
            "BREAK: cold admissions stalled the resident {stall_ratio:.1}x (baseline {base_median:?} \
             -> churn {churn_median:?}) and re-admission cost {readmit_ratio:.1}x a warm hit \
             ({warm:?} -> {readmission:?}): a caller cycling >32 roots forces synchronous JIT \
             recompiles that freeze a worker's other invocations"
        );
    }
    eprintln!("contained: churn did not measurably stall the resident");
}

fn median(v: &mut [Duration]) -> Duration {
    v.sort();
    v[v.len() / 2]
}
