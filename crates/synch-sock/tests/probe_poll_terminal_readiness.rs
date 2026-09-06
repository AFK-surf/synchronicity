//! Probe: readiness on terminal or bogus handles is not progress, so the
//! idle deadline still ends the invocation (finding 2, fixed `2026-08-28`).
//!
//! Before the fix, `h_poll` called `made_progress()` whenever ANY watched
//! handle was ready, and readiness is permanent with no work behind it: a
//! nonexistent handle answers `poll::ERR` forever, a Failed/Closed endpoint
//! reports `ERR | HUP` unconditionally, and SY_SELF past the caller's EOF
//! keeps `IN` set. A guest looping `sy_poll` on such a handle got an instant
//! `count >= 1` every iteration, so the idle deadline — which `run_job`
//! re-reads after every sleep precisely so that progress postpones it — was
//! pushed a full `idle_deadline` away on every poll, forever. No other
//! select branch ended a running invocation.
//!
//! The fix: progress is bytes moved (`sy_read`/`sy_write`/`sy_splice`), and
//! nothing else. `h_poll` no longer records readiness as progress, so a
//! guest that polls a handle whose readiness it never services is idle by
//! the deadline's own definition and is ended with `Deadline`.
//!
//! Three variants, each its own test. The guest loops `sy_poll(..., -1)` and
//! does nothing else — it never services the readiness it is told about:
//!
//! 1. `a_bogus_handle_polled_forever_is_ended_by_the_idle_deadline` — handle
//!    9 was never allocated; every poll returns ERR-readiness instantly.
//! 2. `a_failed_endpoint_polled_forever_is_ended_by_the_idle_deadline` — a
//!    declared `sy_tcp_connect` to a closed 127.0.0.1 port; the endpoint
//!    reaches Failed and reports ERR|HUP forever; the guest never calls
//!    `sy_errno`.
//! 3. `self_past_caller_eof_polled_forever_is_ended_by_the_idle_deadline` —
//!    the caller half-closes; `rx_eof` keeps SY_SELF's IN set forever; the
//!    guest never calls `sy_read`.
//!
//! Asserted fixed behavior per variant: `pool.run` resolves with
//! `SockStatus::Deadline` within 8 s with `idle_deadline = 1 s`. A
//! regression — readiness counting as progress again — shows up as the
//! invocation outliving the window, and the probe then uses pool shutdown
//! to end it, which doubles as evidence that the kill path still reaches it.

#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::time::{Duration, Instant};

use harness::{compile, peer, Harness};
use synch_core::{NodeId, SockStatus};
use synch_sock::{DuplexStream, EffectivePolicy, Limits};
use tokio::io::AsyncWriteExt;

const IDLE: Duration = Duration::from_secs(1);
const OBSERVE: Duration = Duration::from_secs(8);

/// Polls handle 9, which no invocation ever holds, forever. The runtime
/// answers ERR for a nonexistent handle rather than refusing the call, so
/// every poll comes back instantly with count 1.
const BOGUS_HANDLE: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  struct sy_pollfd fds[1] = { { 9, SY_POLL_IN, 0 } };
  for (;;) {
    sy_s64 r = sy_poll(fds, 1, -1);
    if (r < 0) return r;
  }
}
"#;

/// Connects to a port nothing listens on, then polls the handle forever,
/// never reading `sy_errno`. Once the connect fails, the endpoint is Failed
/// and reports ERR|HUP on every poll, forever.
const FAILED_ENDPOINT: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 h = sy_tcp_connect("127.0.0.1", 9, __PORT__);
  if (h < 0) return h;
  struct sy_pollfd fds[1] = { { h, SY_POLL_IN, 0 } };
  for (;;) {
    sy_s64 r = sy_poll(fds, 1, -1);
    if (r < 0) return r;
  }
}
"#;

/// Polls SY_SELF for input forever, never reading. Once the caller
/// half-closes, the pending EOF keeps IN set on every poll, forever.
const SELF_AT_EOF: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
  for (;;) {
    sy_s64 r = sy_poll(fds, 1, -1);
    if (r < 0) return r;
  }
}
"#;

fn harness() -> Harness {
    Harness::with_limits(Limits {
        idle_deadline: IDLE,
        ..Limits::default()
    })
}

/// What one variant's run came to. The interesting case is `Immortal`, and
/// it is the one that fails the assertion in `run_and_expect_deadline`.
enum Ending {
    Ended(SockStatus, Duration),
    Immortal { shutdown_worked: bool },
}

/// Runs one invocation against a caller that has already been arranged, and
/// watches for the idle deadline to end it. On a timeout, asks pool shutdown
/// to finish the job — both to leave the box tidy and to record whether the
/// one remaining kill path reaches an invocation the deadline cannot.
async fn run_variant(harness: &Harness, invocation: synch_sock::Invocation) -> Ending {
    let started = Instant::now();
    let ran = harness.pool.run(invocation);
    match tokio::time::timeout(OBSERVE, ran).await {
        Ok(Ok(outcome)) => Ending::Ended(outcome.status, started.elapsed()),
        Ok(Err(e)) => panic!("the invocation errored instead of running: {e}"),
        Err(_) => {
            let shutdown = tokio::time::timeout(Duration::from_secs(5), harness.pool.shutdown())
                .await
                .is_ok();
            Ending::Immortal {
                shutdown_worked: shutdown,
            }
        }
    }
}

/// The assertion every variant shares: readiness the guest never services is
/// not progress, so the idle deadline must still end the invocation.
fn expect_deadline(variant: &str, ending: Ending) {
    match ending {
        Ending::Ended(status, elapsed) => {
            assert_eq!(
                status,
                SockStatus::Deadline,
                "{variant}: the invocation ended, but not on its idle deadline"
            );
            assert!(
                elapsed < OBSERVE,
                "{variant}: deadline ending took {elapsed:?} with idle_deadline {IDLE:?}"
            );
        }
        Ending::Immortal { shutdown_worked } => {
            panic!(
                "{variant}: BREAK — the invocation outlived {OBSERVE:?} with \
                 idle_deadline {IDLE:?}: terminal readiness counted as progress \
                 on every poll, so the idle deadline never fired. \
                 Pool shutdown afterwards ended it: {shutdown_worked}."
            );
        }
    }
}

#[tokio::test]
async fn a_bogus_handle_polled_forever_is_ended_by_the_idle_deadline() {
    let elf = compile(BOGUS_HANDLE, "poll-bogus-handle.c");
    let harness = harness();

    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );

    // The caller opens the stream, sends nothing, and holds it open.
    let mut mine = mine;
    let caller = tokio::spawn(async move {
        let _ = mine.flush().await;
        std::future::pending::<()>().await;
    });

    let ending = run_variant(&harness, invocation).await;
    caller.abort();
    expect_deadline("bogus handle", ending);
}

#[tokio::test]
async fn a_failed_endpoint_polled_forever_is_ended_by_the_idle_deadline() {
    // A port nothing listens on: bound, noted, and released, so the connect
    // is refused at once instead of timing out.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    };
    let source = FAILED_ENDPOINT.replace("__PORT__", &port.to_string());
    let elf = compile(&source, "poll-failed-endpoint.c");
    let harness = harness();

    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let policy = EffectivePolicy {
        egress: vec![format!("127.0.0.1:{port}")],
        ..EffectivePolicy::default()
    };
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        policy,
        peer(None),
        vec![],
    );

    // The caller holds the stream open and silent: the only terminal handle
    // in this variant is the failed egress endpoint.
    let mut mine = mine;
    let caller = tokio::spawn(async move {
        let _ = mine.flush().await;
        std::future::pending::<()>().await;
    });

    let ending = run_variant(&harness, invocation).await;
    caller.abort();
    expect_deadline("failed endpoint", ending);
}

#[tokio::test]
async fn self_past_caller_eof_polled_forever_is_ended_by_the_idle_deadline() {
    let elf = compile(SELF_AT_EOF, "poll-self-at-eof.c");
    let harness = harness();

    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );

    // The caller half-closes at once — its EOF keeps SY_SELF's IN set — and
    // stays connected, so nothing else about the stream ends the invocation.
    let mut mine = mine;
    let caller = tokio::spawn(async move {
        let _ = mine.shutdown().await;
        std::future::pending::<()>().await;
    });

    let ending = run_variant(&harness, invocation).await;
    caller.abort();
    expect_deadline("SY_SELF at caller EOF", ending);
}

/// The composition: an invocation that never ends never releases its
/// registry slot, and the slot is what the per-socket stream cap counts
/// (runtime/mod.rs drops it only as `run_job` returns). Two spinning
/// invocations against a cap of two stand for "64 of them against 64".
///
/// Asserted fixed behavior: after three idle deadlines the deadline has
/// ended both guests, their slots are released, and a third admission
/// succeeds. A regression — readiness counting as progress again — shows up
/// as the third admission refused because both slots are still held by
/// invocations only pool shutdown can end.
#[tokio::test]
async fn spinning_invocations_release_their_slots_by_the_deadline() {
    let elf = compile(BOGUS_HANDLE, "poll-bogus-handle-slots.c");
    let harness = harness();
    let registry = harness.pool.registry().clone();
    let program = synch_core::Hash::new(&elf);

    let mut callers = Vec::new();
    let mut runs = Vec::new();
    for _ in 0..2 {
        let (mine, theirs) = tokio::io::duplex(64 * 1024);
        let (their_r, their_w) = tokio::io::split(theirs);
        let invocation = harness
            .admitted(&elf, DuplexStream::new(their_r, their_w), &registry, 2)
            .expect("admission under the cap");
        let mut mine = mine;
        callers.push(tokio::spawn(async move {
            let _ = mine.flush().await;
            std::future::pending::<()>().await;
        }));
        let pool = harness.pool.clone();
        runs.push(tokio::spawn(async move { pool.run(invocation).await }));
    }

    // Three idle deadlines go by. If readiness on a bogus handle were not
    // counted as progress, both guests would be dead and their slots
    // released well before this wakes.
    tokio::time::sleep(3 * IDLE).await;

    let third = registry.reserve(
        harness.pool.next_id(),
        "code/test.sock",
        "laptop@cluster.example",
        NodeId::from_bytes(&synch_sock::policy::NOBODY).unwrap(),
        program,
        2,
        Instant::now(),
    );

    if let Some(slot) = third {
        drop(slot);
        for run in runs {
            let outcome = tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("a released slot means its invocation already ended")
                .expect("the spawned run")
                .expect("the invocation ran");
            assert_eq!(outcome.status, SockStatus::Deadline);
        }
        for caller in callers {
            caller.abort();
        }
        return;
    }

    // Break: both slots are still held by invocations the idle deadline
    // could not end. Show that the only thing that ends them is the
    // pool-wide kill switch.
    tokio::time::timeout(Duration::from_secs(5), harness.pool.shutdown())
        .await
        .expect("pool shutdown hangs on the immortal invocations");
    for run in runs {
        let outcome = run
            .await
            .expect("the spawned run")
            .expect("the invocation ran");
        assert_eq!(
            outcome.status,
            SockStatus::Shutdown,
            "the invocation took pool shutdown to end"
        );
    }
    for caller in callers {
        caller.abort();
    }
    panic!(
        "BREAK: two invocations spinning on bogus-handle polls held every stream \
         slot the socket cap allowed for 3x the idle deadline; a third caller \
         was refused admission, and only pool shutdown ended them"
    );
}
