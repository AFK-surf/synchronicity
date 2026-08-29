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
//! `probe_program_cache_thrash` measures the same property with the small
//! programs the rest of the suite uses, where a compile is under a millisecond
//! and the stall is lost in the noise. This one compiles a program big enough
//! for the JIT to take ~100ms, which is the only way the difference is visible
//! at all: with the compile on the worker thread a co-resident's round-trip
//! jumps to the whole compile time, and with it on the blocking pool the
//! co-resident does not notice.

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::time::{Duration, Instant};

use harness::{compile_with, peer, Harness};
use synch_sock::{DuplexStream, EffectivePolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A poll-echo loop with `ROUNDS` straight-line statements in it, so the JIT
/// has real work to do. `RET` keeps each variant a distinct content root.
fn echo_source(rounds: usize) -> String {
    // `rounds` helper functions, chained so that only `f0` is named from the
    // entrypoint and nothing ever calls it. The ELF is large, so the eager
    // load has real work to do; the entrypoint stays small, so the lazy
    // per-function JIT that async-ebpf does on the running thread stays cheap
    // and does not mask what this test is measuring.
    let fns: String = (0..rounds)
        .map(|i| {
            let ops: String = (0..40)
                .map(|j| format!("a += {j}; a ^= (a>>2); "))
                .collect();
            let tail = if i + 1 < rounds {
                format!("if (a == 7) return f{}(a);", i + 1)
            } else {
                String::new()
            };
            format!("static sy_s64 f{i}(sy_s64 x) {{ sy_s64 a=x; {ops} {tail} return a; }}\n")
        })
        .collect();
    // Never true, so the functions above are in the object and never run.
    let never = if rounds > 0 {
        "    if (acc == 987654321) return f0(acc);\n".to_string()
    } else {
        String::new()
    };
    let protos: String = (0..rounds)
        .map(|i| format!("static sy_s64 f{i}(sy_s64 x);\n"))
        .collect();
    format!(
        r#"#include <synch.h>
{protos}
{fns}
SY_ENTRY sy_s64 entry(void) {{
  char buf[64];
  sy_s64 acc = RET;
  for (;;) {{
    struct sy_pollfd fds[1] = {{ {{ SY_SELF, SY_POLL_IN, 0 }} }};
    sy_s64 r = sy_poll(fds, 1, -1);
    if (r < 0) return r;
    sy_s64 n = sy_read(SY_SELF, buf, sizeof buf);
    if (n == SY_EAGAIN) continue;
    if (n <= 0) return 0;
    acc += buf[0];
{never}    sy_write(SY_SELF, buf, (sy_u64)n);
  }}
}}
"#
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cold_compile_does_not_stall_a_co_resident_invocation() {
    // One worker, so the two invocations are certainly co-resident.
    let harness = Harness::new();

    let resident_elf = compile_with(&echo_source(0), "resident.c", &[("RET", "1")]);
    let big_elf = compile_with(&echo_source(120), "big.c", &[("RET", "2")]);
    eprintln!("big program: {} bytes of ELF", big_elf.len());

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
    ) -> Duration {
        let t0 = Instant::now();
        w.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        r.read_exact(&mut b).await.unwrap();
        t0.elapsed()
    }

    // Warm up, then take a baseline with nothing else on the worker.
    for _ in 0..5 {
        ping(&mut my_w, &mut my_r).await;
    }
    let mut baseline = Vec::new();
    for _ in 0..20 {
        baseline.push(ping(&mut my_w, &mut my_r).await);
    }
    baseline.sort();
    let base_median = baseline[baseline.len() / 2];
    let base_max = *baseline.last().expect("twenty samples");
    eprintln!("baseline round-trip: median {base_median:?}, max {base_max:?}");

    // Admit the big program: a cache miss, and a compile of real length.
    let (cold_mine, cold_theirs) = tokio::io::duplex(64 * 1024);
    let (cold_r, cold_w) = tokio::io::split(cold_theirs);
    let cold = harness.invocation(
        &big_elf,
        DuplexStream::new(cold_r, cold_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let pool = harness.pool.clone();
    let compile_started = Instant::now();
    let cold_task = tokio::spawn(async move { pool.run(cold).await });
    let cold_driver = tokio::spawn(async move {
        let (mut r, mut w) = tokio::io::split(cold_mine);
        w.write_all(b"y").await.unwrap();
        let mut b = [0u8; 1];
        let got = r.read_exact(&mut b).await;
        (got.is_ok(), Instant::now())
    });

    // Keep the resident talking for as long as the cold admission takes.
    let mut during = Vec::new();
    while !cold_driver.is_finished() {
        during.push(ping(&mut my_w, &mut my_r).await);
        if during.len() > 100_000 {
            break;
        }
    }
    let (cold_ok, cold_done) = cold_driver.await.expect("the cold driver ran");
    let compile_elapsed = cold_done - compile_started;
    assert!(cold_ok, "the cold invocation must answer");

    during.sort();
    let during_max = *during.last().expect("at least one ping during the compile");
    let during_median = during[during.len() / 2];
    eprintln!(
        "cold admission took {compile_elapsed:?}; resident round-trip during it: \
         median {during_median:?}, max {during_max:?} over {} pings",
        during.len()
    );

    resident_task.abort();
    cold_task.abort();

    // The compile has to be long enough for the question to mean anything.
    assert!(
        compile_elapsed > Duration::from_millis(40),
        "this machine loaded the big program in {compile_elapsed:?}, too fast for this probe \
         to tell a stalled worker from a busy one; raise the function count"
    );

    // The property, measured as throughput rather than as a worst case.
    //
    // A single round-trip can still be unlucky — the JIT maps and re-protects
    // its code arena, and those take the process-wide mmap lock, so the worker
    // can lose a scheduling quantum to a compile happening on another thread.
    // What changed is whether the worker is *available* at all: with the load
    // inline it serves nobody for the whole compile, and with it on the
    // blocking pool it keeps answering throughout. Counting completed
    // round-trips sees that; a maximum does not.
    //
    // If the worker were blocked for the compile, the resident could complete
    // about one round-trip in the window. Unblocked it manages thousands. The
    // threshold sits an order of magnitude clear of both.
    let ideal = compile_elapsed.as_nanos() / base_median.as_nanos().max(1);
    let achieved = during.len() as u128;
    let fraction = achieved as f64 / ideal.max(1) as f64;
    eprintln!(
        "resident completed {achieved} round-trips during the compile, against {ideal} if the \
         worker had never paused ({:.0}%)",
        fraction * 100.0
    );
    assert!(
        fraction > 0.15,
        "BREAK: the resident completed only {achieved} round-trips ({:.1}%) of the {ideal} it \
         could have during a {compile_elapsed:?} compile: the worker is compiling on its own \
         thread and is unavailable to everything else placed on it",
        fraction * 100.0
    );
}
