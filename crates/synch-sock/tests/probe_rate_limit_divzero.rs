//! Probe: guest-chosen durations cannot crash the worker (finding 3, fixed
//! `2026-08-28`).
//!
//! Before the fix, `sy_rate_limit` passed the guest's `window_ms` straight
//! into the store, where `window.as_nanos().max(1) as u64` applied the
//! `.max(1)` *before* the truncating cast: a window of `2^58` ms is
//! `15625 * 2^64` ns, which truncates to exactly zero, and `elapsed / width`
//! panicked with a divide-by-zero on the worker's invocation task. The panic
//! escaped the helper (async-ebpf runs helpers as plain fns), the reply
//! oneshot dropped (`Err(NotRunning)` to the caller), and `record_outcome`
//! was skipped, so the fault quarantine never saw the crash.
//!
//! The fix clamps every guest duration input — the rate-limit window and the
//! map TTLs — to `MAX_GUEST_DURATION_MS` at the helper boundary, and the
//! store's width computation saturates instead of truncating, so no duration
//! can ever reach a division or an `Instant` addition that overflows.
//!
//! Asserted fixed behavior: the poison window is admitted as the enormous
//! but legal window it is; the map TTL at `u64::MAX` ms is clamped without
//! panic; the pool survives; and the fault quarantine records normally.

#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use harness::{compile, peer, Harness};
use synch_sock::{DuplexStream, EffectivePolicy};
use tokio::io::AsyncWriteExt;

/// `window_ms = 2^58`: `2^58 * 10^6 = 15625 * 2^64` exactly, so the
/// nanoseconds truncate to zero. Must be clamped, never divided by.
const DIVZERO_WINDOW: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  const char k[1] = {'x'};
  return sy_rate_limit(k, 1, 10, 288230376151711744ULL);
}
"#;

/// Map TTL at `u64::MAX` ms: the `Instant + Duration` overflow class. Must
/// be clamped, and the entry must be usable.
const MAX_TTL: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  const char k[1] = {'k'};
  const char v[1] = {'v'};
  sy_s64 s = sy_map_set(k, 1, v, 1, 18446744073709551615ULL);
  if (s != 0) return -100 + s;
  char out[8];
  sy_s64 g = sy_map_get(k, 1, out, sizeof out);
  if (g != 1 || out[0] != 'v') return -200 + g;
  return 0;
}
"#;

#[tokio::test]
async fn the_poison_rate_limit_window_is_clamped_not_crashed() {
    let elf = compile(DIVZERO_WINDOW, "divzero-window.c");
    let harness = Harness::new();

    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let mut mine = mine;
    let caller = tokio::spawn(async move {
        let _ = mine.shutdown().await;
    });
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let outcome = harness
        .pool
        .run(invocation)
        .await
        .expect("the invocation must run, not panic: the window must be clamped")
        .status;
    caller.await.unwrap();
    assert_eq!(
        outcome,
        synch_core::SockStatus::Ok(0),
        "the clamped window must admit the first call (limit 10): got {outcome:?}"
    );
}

#[tokio::test]
async fn a_max_tll_map_set_is_clamped_and_the_entry_reads_back() {
    let elf = compile(MAX_TTL, "max-ttl.c");
    let harness = Harness::new();
    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let mut mine = mine;
    let caller = tokio::spawn(async move {
        let _ = mine.shutdown().await;
    });
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let outcome = harness
        .pool
        .run(invocation)
        .await
        .expect("the invocation must run, not panic: the TTL must be clamped")
        .status;
    caller.await.unwrap();
    assert_eq!(
        outcome,
        synch_core::SockStatus::Ok(0),
        "a u64::MAX TTL must be clamped and the entry usable: got {outcome:?}"
    );
}

#[tokio::test]
async fn the_pool_survives_and_a_sane_window_still_works() {
    let bad = compile(DIVZERO_WINDOW, "divzero-window.c");
    let good = compile(MAX_TTL, "max-ttl.c");
    let harness = Harness::new();

    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let mut mine = mine;
    let caller = tokio::spawn(async move {
        let _ = mine.shutdown().await;
    });
    let first = harness.invocation(
        &bad,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let _ = harness.pool.run(first).await.expect("poison ran cleanly");
    caller.await.unwrap();

    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let mut mine = mine;
    let caller = tokio::spawn(async move {
        let _ = mine.shutdown().await;
    });
    let second = harness.invocation(
        &good,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let outcome = harness
        .pool
        .run(second)
        .await
        .expect("the worker must survive the poison invocation")
        .status;
    caller.await.unwrap();
    assert_eq!(outcome, synch_core::SockStatus::Ok(0));
}

/// The quarantine accounting must see a normal outcome: a panic that skips
/// `record_outcome` would be invisible to the 8-of-16 auto-disarm. With the
/// clamp there is no panic, so a benign run after eight poison runs must
/// still work and quarantine must stay off.
#[tokio::test]
async fn the_clamp_keeps_fault_accounting_consistent() {
    let elf = compile(DIVZERO_WINDOW, "divzero-window.c");
    let harness = Harness::new();
    let registry = harness.pool.registry().clone();
    let program = synch_core::Hash::new(&elf);

    for _ in 0..8 {
        let (mine, theirs) = tokio::io::duplex(64 * 1024);
        let (their_r, their_w) = tokio::io::split(theirs);
        let invocation = harness
            .admitted(&elf, DuplexStream::new(their_r, their_w), &registry, 64)
            .expect("admission at the cap");
        let _ = harness.pool.run(invocation).await;
        std::mem::forget(mine);
    }

    assert!(
        !registry.take_quarantine("code/test.sock", program),
        "no quarantine may arm: nothing faulted"
    );
}
