//! Regression tests for the eBPF socket audit (`2026-08-27`).
//!
//! Each test stands for one finding the audit confirmed, asserting the
//! *fixed* behavior:
//!
//! * `an_idle_stream_is_ended_by_its_deadline` — the idle deadline is a real
//!   invocation deadline now, not only a poll-wait clamp: a guest looping on
//!   timed-out polls is ended with `Deadline` instead of spinning a worker
//!   forever (helpers.rs:712, runtime/mod.rs).
//! * `one_callers_faults_do_not_quarantine_a_shared_socket` — fault history is
//!   attributed to the caller, and the quarantine latch needs two distinct
//!   callers, so one member force-faulting a shared program cannot trip its
//!   fault window for everyone (registry.rs).
//! * `the_in_place_decode_helpers_decode_in_place` — `sy_base64_decode_in_place`
//!   and `sy_hex_decode_in_place` work, reading and writing the one registered
//!   region (helpers.rs).

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use harness::{compile, peer, Harness};
use synch_core::{FaultKind, NodeId, OriginId, SockStatus};
use synch_sock::{DuplexStream, EffectivePolicy, Limits, PeerIdentity};
use tokio::io::AsyncWriteExt;

/// A program shaped like every long-lived server: poll for input, and when a
/// poll times out, go around again. This is the SDK-documented shape for a
/// socket that keeps running between callers — and the shape the old runtime
/// let a caller pin a worker with forever.
const POLL_FOREVER: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
  for (;;) {
    sy_s64 r = sy_poll(fds, 1, -1);
    if (r < 0) return r;
    if (r > 0) {
      char buf[64];
      sy_s64 n = sy_read(SY_SELF, buf, sizeof buf);
      if (n == 0) return 0;
      if (n < 0 && n != SY_EAGAIN) return n;
    }
  }
}
"#;

#[tokio::test]
async fn an_idle_stream_is_ended_by_its_deadline() {
    let elf = compile(POLL_FOREVER, "poll-forever.c");
    let harness = Harness::with_limits(Limits {
        idle_deadline: std::time::Duration::from_secs(1),
        ..Limits::default()
    });

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

    // Once the 1 s idle deadline passes, every sy_poll returns 0 instantly and
    // the guest spins in its poll loop. The runtime must end it with
    // `Deadline` — the deadline is an invocation deadline, not a clamp.
    let ran = harness.pool.run(invocation);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(8), ran)
        .await
        .expect("the idle deadline did not end a spinning invocation")
        .expect("the invocation ran");
    caller.abort();
    assert_eq!(
        outcome.status,
        SockStatus::Deadline,
        "a guest spinning in poll after its idle deadline must be ended by the runtime"
    );
}

/// Faults when the caller's first byte is 'X'; fine on anything else.
const FAULT_ON_INPUT: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  char c = 0;
  for (;;) {
    sy_s64 n = sy_read(SY_SELF, &c, 1);
    if (n == 1) break;
    if (n < 0 && n != SY_EAGAIN) return n;
    struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
    sy_poll(fds, 1, -1);
  }
  if (c == 'X') {
    volatile char *p = (volatile char *)0x4141414141414141ULL;
    *p = 1;
  }
  return 0;
}
"#;

/// A second caller identity: same shape as `harness::peer`, other device key.
fn other_peer() -> PeerIdentity {
    let mut bytes = synch_sock::policy::NOBODY;
    bytes[31] ^= 0x80; // the negation of the base point is the next valid key
    PeerIdentity {
        origin: OriginId::named("other", "cluster.example").unwrap(),
        device_key: NodeId::from_bytes(&bytes).expect("a valid key"),
        spaces: None,
        addr: "198.51.100.8:44321".into(),
        stream_index: 1,
    }
}

#[tokio::test]
async fn one_callers_faults_do_not_quarantine_a_shared_socket() {
    let elf = compile(FAULT_ON_INPUT, "fault-on-input.c");
    let harness = Harness::new();
    // The pool's own registry: this is where run_job records outcomes and the
    // engine reads the quarantine latch from, so the slot and the outcome must
    // land in the same place (as they do in the daemon).
    let registry = harness.pool.registry().clone();
    let program = synch_core::Hash::new(&elf);

    // The attacker sends the poison byte eight times across eight admissions,
    // all from one device key. Each fault is recorded against (socket,
    // program, caller) — and one caller's faults must never trip the latch.
    for _ in 0..8 {
        let (mine, theirs) = tokio::io::duplex(64 * 1024);
        let (their_r, their_w) = tokio::io::split(theirs);
        let invocation = harness
            .admitted(&elf, DuplexStream::new(their_r, their_w), &registry, 64)
            .expect("admission at the cap");
        let mut mine = mine;
        let caller = tokio::spawn(async move {
            let _ = mine.write_all(b"X").await;
            let _ = mine.shutdown().await;
        });
        let outcome = harness
            .pool
            .run(invocation)
            .await
            .expect("the invocation ran");
        caller.await.unwrap();
        assert!(
            matches!(outcome.status, SockStatus::Fault(FaultKind::Memory)),
            "poison invocation did not fault: {outcome:?}"
        );
    }
    assert!(
        !registry.take_quarantine("code/test.sock", program),
        "one caller's repeated faults quarantined the shared socket"
    );

    // A second caller's genuine fault is the breadth the rule needs: whatever
    // makes the program fault for two different devices is broken, not picky.
    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let id = harness.pool.next_id();
    let slot = registry
        .reserve(
            id,
            "code/test.sock",
            "other@cluster.example",
            other_peer().device_key,
            program,
            64,
            std::time::Instant::now(),
        )
        .expect("admission at the cap");
    let mut invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        other_peer(),
        vec![],
    );
    invocation.id = id;
    invocation.slot = Some(slot);
    let mut mine = mine;
    let caller = tokio::spawn(async move {
        let _ = mine.write_all(b"X").await;
        let _ = mine.shutdown().await;
    });
    let outcome = harness
        .pool
        .run(invocation)
        .await
        .expect("the invocation ran");
    caller.await.unwrap();
    assert!(
        matches!(outcome.status, SockStatus::Fault(FaultKind::Memory)),
        "the second caller's invocation did not fault: {outcome:?}"
    );
    assert!(
        registry.take_quarantine("code/test.sock", program),
        "two distinct callers faulting the program did not quarantine it"
    );
}

const IN_PLACE_DECODERS: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  char b64[16] = "aGVsbG8=";
  char hex[16] = "aabb";
  sy_s64 r1 = sy_base64_decode_in_place(b64, 8, 0);
  sy_s64 r2 = sy_hex_decode_in_place(hex, 4);
  /* The decoded forms are "hello" (5 bytes) and {0xaa, 0xbb} (2 bytes), and
     both helpers write them back into the same region they read. */
  if (r1 != 5) return -1000 + r1;
  if (r2 != 2) return -2000 + r2;
  if (b64[0] != 'h' || b64[4] != 'o') return -3000;
  if (hex[0] != (char)0xaa || hex[1] != (char)0xbb) return -4000;
  return 0;
}
"#;

#[tokio::test]
async fn the_in_place_decode_helpers_decode_in_place() {
    let elf = compile(IN_PLACE_DECODERS, "in-place-decoders.c");
    let harness = Harness::new();
    let (status, _) = harness::exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(
        status,
        SockStatus::Ok(0),
        "the in-place decode helpers must decode in place"
    );
}
