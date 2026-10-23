//! Compiling a program does not freeze the worker running everybody else.
//!
//! `program_for` JIT-compiles on a cache miss. That used to happen
//! synchronously in `run_job`, on the worker's single current-thread runtime,
//! *before* the select loop that services every co-resident invocation's
//! pumps, poll waits and idle deadline — so one cold admission stopped the
//! whole worker for as long as the compile took. With a 32-entry per-worker
//! cache and oldest-first eviction, a caller reaching more than 32 armed roots
//! makes every admission a miss.
//!
//! This probe used to time a compile big enough to take ~170ms and compare the
//! resident's round-trips against it, which failed on its own once runners
//! loaded that program in 15ms. It now holds the cold load in flight
//! (`synch_sock::compile_hold`) instead: for as long as the hold lasts, a
//! worker compiling on its own thread serves nobody, and one that hands the
//! load to the blocking pool keeps answering. That is the same on a fast
//! machine and a slow one.

#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::time::Duration;

use harness::{compile_with, peer, Harness};
use synch_sock::{compile_hold, DuplexStream, EffectivePolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A poll-echo loop. `RET` keeps each variant a distinct content root.
const ECHO: &str = r#"#include <synch.h>
SY_ENTRY sy_s64 entry(void) {
  char buf[64];
  sy_s64 acc = RET;
  for (;;) {
    struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
    sy_s64 r = sy_poll(fds, 1, -1);
    if (r < 0) return r;
    sy_s64 n = sy_read(SY_SELF, buf, sizeof buf);
    if (n == SY_EAGAIN) continue;
    if (n <= 0) return 0;
    acc += buf[0];
    sy_write(SY_SELF, buf, (sy_u64)n);
  }
}
"#;

/// Round-trips the resident answers while the cold load is held.
const PINGS_DURING_HOLD: usize = 100;

/// How long a round-trip may take before the worker counts as stalled. A free
/// worker answers in microseconds; a stalled one never answers while the hold
/// lasts, so this bounds a hang rather than measuring anything.
const STALLED: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cold_compile_does_not_stall_a_co_resident_invocation() {
    // One worker, so the two invocations are certainly co-resident.
    let harness = Harness::new();

    let resident_elf = compile_with(ECHO, "resident.c", &[("RET", "1")]);
    let cold_elf = compile_with(ECHO, "cold.c", &[("RET", "2")]);

    // A resident invocation, already compiled and answering.
    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let resident = harness.invocation(
        &resident_elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let (mut my_r, mut my_w) = tokio::io::split(mine);
    let pool = harness.pool.clone();
    let resident_task = tokio::spawn(async move { pool.run(resident).await });

    async fn ping(
        w: &mut (impl tokio::io::AsyncWrite + Unpin),
        r: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> bool {
        let round_trip = async {
            w.write_all(b"x").await.unwrap();
            let mut b = [0u8; 1];
            r.read_exact(&mut b).await.unwrap();
        };
        tokio::time::timeout(STALLED, round_trip).await.is_ok()
    }

    assert!(ping(&mut my_w, &mut my_r).await, "the resident must answer");

    // Admit the cold program, and hold its load in flight.
    compile_hold::hold();
    let (cold_mine, cold_theirs) = tokio::io::duplex(64 * 1024);
    let (cold_r, cold_w) = tokio::io::split(cold_theirs);
    let cold = harness.invocation(
        &cold_elf,
        DuplexStream::new(cold_r, cold_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let pool = harness.pool.clone();
    let cold_task = tokio::spawn(async move { pool.run(cold).await });
    // The resident's load was the first; this one is the second.
    tokio::task::spawn_blocking(|| compile_hold::wait_entered(2))
        .await
        .expect("the wait ran");

    for answered in 0..PINGS_DURING_HOLD {
        if !ping(&mut my_w, &mut my_r).await {
            compile_hold::release();
            panic!(
                "BREAK: the resident stopped answering after {answered} round-trips while \
                 another program was compiling: the worker is compiling on its own thread and \
                 is unavailable to everything else placed on it"
            );
        }
    }

    // Once released, the cold program loads and answers.
    compile_hold::release();
    let (mut r, mut w) = tokio::io::split(cold_mine);
    w.write_all(b"y").await.unwrap();
    let mut b = [0u8; 1];
    r.read_exact(&mut b)
        .await
        .expect("the cold invocation must answer");

    resident_task.abort();
    cold_task.abort();
}
