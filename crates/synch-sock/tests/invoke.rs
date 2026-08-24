//! End-to-end: a C program compiled to eBPF, run against a real stream.
//!
//! The fixtures here are written to provoke the runtime — a program that
//! spins, a program that faults, a program that waits for something that never
//! comes. The programs anybody would actually write live in `examples/` and are
//! exercised by `examples.rs`.
//!
//! Nothing skips. These used to need a clang with a BPF backend and skipped
//! where there was none, which meant they had never run on macOS at all;
//! `synch-cc` compiles them now, and clang is used only where the question is
//! specifically whether the runtime loads somebody else's object.

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::sync::Arc;

use harness::{compile, exchange, peer, Harness};
use synch_core::{FaultKind, SockStatus};
use synch_sock::{DuplexStream, EffectivePolicy, Limits, SocketId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ECHO: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  char buf[1024];
  struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
  for (;;) {
    if (sy_poll(fds, 1, 2000) <= 0) break;
    if (fds[0].revents & SY_POLL_IN) {
      sy_s64 n = sy_read(SY_SELF, buf, sizeof buf);
      if (n == 0) break;
      if (n < 0) { if (n == SY_EAGAIN) continue; break; }
      sy_s64 off = 0;
      while (off < n) {
        sy_s64 w = sy_write(SY_SELF, buf + off, (sy_u64)(n - off));
        if (w == SY_EAGAIN) continue;
        if (w < 0) return w;
        off += w;
      }
    }
    if (fds[0].revents & (SY_POLL_ERR | SY_POLL_HUP)) break;
  }
  sy_shutdown(SY_SELF);
  return 0;
}
"#;

#[tokio::test]
async fn a_program_echoes_a_stream_and_returns_cleanly() {
    let elf = compile(ECHO, "echo.c");
    let harness = Harness::new();
    let (status, out) = exchange(
        &harness,
        &elf,
        b"hello sockets",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"hello sockets");
}

const POLL_IMMEDIATE_ONE: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  /* SY_SELF starts with tx room, so this must complete in the helper's
     synchronous path and write the reply into the same 16-byte frame. */
  struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_OUT, 0 } };
  sy_s64 n = sy_poll(fds, 1, 5000);
  sy_shutdown(SY_SELF);
  if (n != 1) return -1;
  if (!(fds[0].revents & SY_POLL_OUT)) return -2;
  return 0;
}
"#;

#[tokio::test]
async fn an_immediately_ready_poll_writes_revents() {
    let elf = compile(POLL_IMMEDIATE_ONE, "poll-immediate-one.c");
    let harness = Harness::new();
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
}

const POLL_IMMEDIATE_TWO: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  /* The proxy-shaped 32-byte in/out array that exposed overlapping guest
     memory registrations. Duplicate handles are separate poll entries. */
  struct sy_pollfd fds[2] = {
    { SY_SELF, SY_POLL_OUT, 0 },
    { SY_SELF, SY_POLL_OUT, 0 },
  };
  sy_s64 n = sy_poll(fds, 2, 5000);
  sy_shutdown(SY_SELF);
  if (n != 2) return -1;
  sy_u64 nonzero = (fds[0].revents != 0) + (fds[1].revents != 0);
  if (nonzero != (sy_u64)n) return -2;
  if (!(fds[0].revents & SY_POLL_OUT)) return -3;
  if (!(fds[1].revents & SY_POLL_OUT)) return -4;
  return 0;
}
"#;

#[tokio::test]
async fn two_immediately_ready_poll_entries_write_both_revents() {
    let elf = compile(POLL_IMMEDIATE_TWO, "poll-immediate-two.c");
    let harness = Harness::new();
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
}

const WRITE_AFTER_RECEIVE_EOF: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  char buf[1024];

  /* Observe the caller's EOF before producing the reply. The peer's FIN must
     leave this endpoint's write half usable. */
  for (;;) {
    struct sy_pollfd in[1] = { { SY_SELF, SY_POLL_IN, 0 } };
    if (sy_poll(in, 1, 5000) <= 0) return 10;
    sy_s64 n = sy_read(SY_SELF, buf, sizeof buf);
    if (n == 0) break;
    if (n < 0 && n != SY_EAGAIN) return 11;
  }

  for (sy_u64 i = 0; i < sizeof buf; i++) buf[i] = (char)(i % 251);
  sy_u64 sent = 0;
  while (sent < 65536) {
    sy_u64 want = 65536 - sent;
    if (want > sizeof buf) want = sizeof buf;
    sy_s64 n = sy_write(SY_SELF, buf, want);
    if (n == SY_EAGAIN) {
      struct sy_pollfd out[1] = { { SY_SELF, SY_POLL_OUT, 0 } };
      sy_s64 ready = sy_poll(out, 1, 5000);
      if (ready == 0) return 12;
      if (ready < 0) return 13;
      if (out[0].revents & (SY_POLL_RDHUP | SY_POLL_HUP)) return 14;
      if (!(out[0].revents & SY_POLL_OUT)) return 15;
      continue;
    }
    if (n < 0) return 16;
    sent += (sy_u64)n;
  }

  sy_shutdown(SY_SELF);
  struct sy_pollfd terminal[1] = { { SY_SELF, 0, 0 } };
  if (sy_poll(terminal, 1, 5000) != 1) return 17;
  if (terminal[0].revents != SY_POLL_HUP) return 18;
  return 42;
}
"#;

#[tokio::test]
async fn receive_eof_does_not_end_a_backpressured_output_wait() {
    let elf = compile(WRITE_AFTER_RECEIVE_EOF, "write-after-receive-eof.c");
    let harness = Harness::with_limits(Limits {
        ring_bytes: 4096,
        ..Limits::default()
    });
    let (mine, theirs) = tokio::io::duplex(1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );

    let driver = tokio::spawn(async move {
        let mut mine = mine;
        mine.shutdown().await.unwrap();
        // Hold the read side still long enough for both the host write and tx
        // ring to fill. The guest must remain parked on OUT until this drains.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut out = Vec::new();
        mine.read_to_end(&mut out).await.unwrap();
        out
    });

    let outcome = harness.pool.run(invocation).await.expect("the program ran");
    let out = driver.await.unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(42));
    assert_eq!(out.len(), 65536, "the response ended under backpressure");
    for (i, byte) in out.into_iter().enumerate() {
        assert_eq!(byte, (i % 1024 % 251) as u8, "wrong byte at {i}");
    }
}

const IDENTITY: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  char buf[256];

  /* Authorization is the handshake. A caller that is not delegated `code`
     gets nothing, whatever it says in its metadata. */
  if (!sy_peer_has_space(SY_STR("code"))) {
    sy_write(SY_SELF, SY_STR("denied"));
    sy_shutdown(SY_SELF);
    return 7;
  }

  sy_peer_origin(buf, sizeof buf);
  sy_write(SY_SELF, buf, sy_strlen(buf));
  sy_write(SY_SELF, SY_STR(" "));

  sy_s64 kind = sy_peer_kind();
  sy_write(SY_SELF, kind == SY_PEER_MEMBER ? "member" : "delegate",
           kind == SY_PEER_MEMBER ? 6 : 8);

  if (sy_conn_meta(SY_STR("tag"), buf, sizeof buf) > 0) {
    sy_write(SY_SELF, SY_STR(" "));
    sy_write(SY_SELF, buf, sy_strlen(buf));
  }
  sy_shutdown(SY_SELF);
  return 0;
}
"#;

#[tokio::test]
async fn identity_comes_from_the_handshake_and_metadata_is_only_a_hint() {
    let elf = compile(IDENTITY, "identity.c");
    let harness = Harness::new();

    // A rooted member reads every space by construction.
    let (status, out) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(None),
        vec![("tag".into(), "ci".into())],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(
        String::from_utf8_lossy(&out),
        "laptop@cluster.example member ci"
    );

    // A delegate of `code` is let in and is told it is a delegate.
    let (_, out) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(Some(vec!["code".into()])),
        vec![],
    )
    .await;
    assert_eq!(
        String::from_utf8_lossy(&out),
        "laptop@cluster.example delegate"
    );

    // A delegate of something else is refused, and no amount of metadata
    // claiming otherwise changes that.
    let (status, out) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(Some(vec!["photos".into()])),
        vec![("spaces".into(), "code".into())],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(7));
    assert_eq!(out, b"denied");
}

const EGRESS: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 h = sy_tcp_connect(SY_STR("blocked.example"), 80);
  if (h == SY_EPERM) {
    sy_write(SY_SELF, SY_STR("refused"));
    sy_shutdown(SY_SELF);
    return 0;
  }
  sy_write(SY_SELF, SY_STR("allowed"));
  sy_shutdown(SY_SELF);
  return 1;
}
"#;

#[tokio::test]
async fn undeclared_egress_is_refused() {
    let elf = compile(EGRESS, "egress.c");
    let harness = Harness::new();
    let (status, out) = exchange(
        &harness,
        &elf,
        b"",
        // Nothing was declared, so the program asks for a capability it lacks.
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"refused");
}

const TREE: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 obj = sy_open(SY_STR("code/readme"));
  if (obj < 0) return obj;

  char buf[128];
  sy_s64 n;
  struct sy_pollfd fds[1] = { { obj, SY_POLL_IN, 0 } };
  /* A cold read is an ordinary poll wait, not a hidden stall. */
  for (;;) {
    n = sy_pread(obj, buf, sizeof buf, 0);
    if (n != SY_EAGAIN) break;
    if (sy_poll(fds, 1, 2000) <= 0) return -1;
  }
  if (n < 0) return n;
  sy_write(SY_SELF, buf, (sy_u64)n);
  sy_shutdown(SY_SELF);
  return 0;
}
"#;

#[tokio::test]
async fn a_program_reads_its_own_nodes_tree() {
    let elf = compile(TREE, "tree.c");
    let harness = Harness::with_tree(&[("code/readme", "the tree, read from inside")]);
    let (status, out) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"the tree, read from inside");
}

const SPIN: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  /* No sy_poll anywhere: only asynchronous preemption can stop this. */
  volatile sy_u64 x = 0;
  for (;;) { x += 1; }
  return 0;
}
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spinning_program_is_preempted_rather_than_holding_its_worker() {
    let elf = compile(SPIN, "spin.c");
    let harness = Harness::new();
    let (mine, theirs) = tokio::io::duplex(1024);
    drop(mine);
    let (r, w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(r, w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );

    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let pool = harness.pool.clone();
    let run = tokio::spawn(async move { pool.run_cancellable(invocation, cancelled).await });

    // The guest never yields on its own. If the watcher were not signalling the
    // worker thread, this cancel would never be observed and the test would
    // hang rather than fail.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    cancel.send(()).unwrap();

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), run)
        .await
        .expect("a spinning guest held its worker past the cancel")
        .unwrap()
        .expect("the run completed");
    assert_eq!(outcome.status, SockStatus::Killed);
}

const FAULT: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  /* Reach far outside the cage. The pointer is masked back inside a guard
     region, which faults, which the runtime contains. */
  volatile char *p = (volatile char *)0x4141414141414141ULL;
  *p = 1;
  return 0;
}
"#;

#[tokio::test]
async fn a_fault_is_contained_and_the_worker_survives_it() {
    let faulting = compile(FAULT, "fault.c");
    let echo = compile(ECHO, "echo.c");
    let harness = Harness::new();

    let (status, _) = exchange(
        &harness,
        &faulting,
        b"",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert!(
        matches!(status, SockStatus::Fault(FaultKind::Memory)),
        "expected a contained memory fault, got {status:?}"
    );

    // The whole point of containment: the next invocation on the same worker
    // runs normally.
    let (status, out) = exchange(
        &harness,
        &echo,
        b"still here",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"still here");
}

const DECLARE: &str = r#"
#include <synch.h>

SY_INIT_ENTRY sy_s64 declare(void) {
  sy_declare_name(SY_STR("git-http"));
  sy_declare_egress(SY_STR("git.internal"), 9418);
  sy_declare_tree_read(SY_STR("code"));
  sy_declare_max_streams(32);
  if (sy_declare_stack_frame_size(17) != SY_EINVAL) return -1;
  if (sy_declare_stack_frame_size(32784) != SY_ELIMIT) return -2;
  sy_declare_stack_frame_size(512);
  if (sy_declare_guarded_stack_frames(2) != SY_EINVAL) return -3;
  sy_declare_guarded_stack_frames(0);
  /* An I/O helper here has nothing to reach, and is refused before it tries. */
  if (sy_tcp_connect(SY_STR("git.internal"), 9418) != SY_EPERM) return -4;
  return 0;
}

SY_ENTRY sy_s64 entry(void) {
  /* A declaration helper outside the hook is refused the same way. */
  if (sy_declare_egress(SY_STR("anywhere.example"), 80) != SY_EPERM) return -1;
  sy_shutdown(SY_SELF);
  return 0;
}
"#;

#[test]
fn the_init_hook_declares_and_cannot_reach_anything() {
    let elf = compile(DECLARE, "declare.c");
    let declared =
        synch_sock::declare(&elf, Arc::new(harness::FakeTree::default())).expect("the hook ran");
    assert_eq!(declared.name, "git-http");
    assert_eq!(declared.egress, vec!["git.internal:9418".to_string()]);
    assert_eq!(declared.tree_reads, vec!["code".to_string()]);
    assert_eq!(declared.max_streams, Some(32));
    assert_eq!(declared.stack_frame_size, Some(512));
    assert_eq!(declared.guarded_stack_frames, Some(false));
}

const SMALL_FRAMES: &str = r#"
#include <synch.h>

SY_INIT_ENTRY sy_s64 declare(void) {
  if (sy_declare_stack_frame_size(512) < 0) return -1;
  return sy_declare_guarded_stack_frames(0);
}

static sy_s64 descend(sy_s64 n) {
  volatile sy_s64 local = n;
  if (n == 0) return 0;
  sy_s64 below = descend(n - 1);
  return below + (local != 0);
}

SY_ENTRY sy_s64 entry(void) {
  return descend(16);
}
"#;

#[tokio::test]
async fn a_declared_stack_frame_size_configures_stream_local_calls() {
    let elf = compile(SMALL_FRAMES, "small-frames.c");
    let harness = Harness::new();

    let (default_status, _) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert!(
        matches!(default_status, SockStatus::Fault(_)),
        "the 16 KiB default unexpectedly admitted 17 recursive frames: {default_status:?}"
    );

    let declaration = synch_sock::declare(&elf, harness.tree.clone()).expect("the hook ran");
    let policy = EffectivePolicy::armed(&declaration, vec![], None, 64);
    let (declared_status, _) = exchange(&harness, &elf, b"", policy, peer(None), vec![]).await;
    assert_eq!(declared_status, SockStatus::Ok(16));
}

const MISALIGNED_GUARDED_FRAMES: &str = r#"
#include <synch.h>

SY_INIT_ENTRY sy_s64 declare(void) {
  if (sy_declare_stack_frame_size(512) < 0) return -1;
  return sy_declare_guarded_stack_frames(1);
}

SY_ENTRY sy_s64 entry(void) { return 0; }
"#;

#[test]
fn custom_frames_require_page_alignment_unless_guarding_is_disabled() {
    let elf = compile(MISALIGNED_GUARDED_FRAMES, "misaligned-guarded-frames.c");
    let error = synch_sock::declare(&elf, Arc::new(harness::FakeTree::default()))
        .expect_err("512-byte guarded frames cannot be host-page aligned");
    assert!(error.to_string().contains("not aligned"), "{error}");
}

const UNSAFE_DECLARATION: &str = r#"
#include <synch.h>

SY_INIT_ENTRY sy_s64 declare(void) {
  if (sy_declare_name(SY_STR("benign\negress evil.example:443")) != SY_EINVAL) return -1;
  if (sy_declare_tree_read(SY_STR("public\x1b[2J")) != SY_EINVAL) return -2;
  return 0;
}

SY_ENTRY sy_s64 entry(void) { return 0; }
"#;

#[test]
fn declaration_helpers_reject_line_and_terminal_control_text() {
    let elf = compile(UNSAFE_DECLARATION, "unsafe-declaration.c");
    let declared =
        synch_sock::declare(&elf, Arc::new(harness::FakeTree::default())).expect("the hook ran");
    assert_eq!(declared, synch_core::Declaration::default());
}

#[tokio::test]
async fn a_declaration_helper_is_refused_outside_the_init_hook() {
    let elf = compile(DECLARE, "declare.c");
    let harness = Harness::new();
    let (status, _) = exchange(
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
        "a declaration helper was allowed outside the init hook"
    );
}

#[test]
fn a_program_with_no_stream_entrypoint_is_refused_at_arm_time() {
    let elf = compile(
        r#"
        #include <synch.h>
        SY_INIT_ENTRY sy_s64 declare(void) { return 0; }
        "#,
        "init-only.c",
    );
    let out = synch_sock::declare(&elf, Arc::new(harness::FakeTree::default()));
    assert!(
        matches!(out, Err(synch_sock::SockError::NoEntrypoint)),
        "expected NoEntrypoint, got {out:?}"
    );
}

const WAIT_FOREVER: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  /* A negative timeout means "until something happens". Nothing ever will:
     the caller sends nothing and never hangs up. */
  struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
  sy_s64 n = sy_poll(fds, 1, -1);
  return n == 0 ? 42 : 1;
}
"#;

#[tokio::test]
async fn a_wait_with_nothing_happening_ends_at_the_idle_deadline() {
    let elf = compile(WAIT_FOREVER, "wait-forever.c");
    let harness = Harness::with_limits(Limits {
        idle_deadline: std::time::Duration::from_millis(300),
        ..Limits::default()
    });

    // A stream that stays open and silent: the guest's only handle can still
    // become ready in principle, so `all_quiet` does not short-circuit it and
    // the deadline is the only thing that ends the wait.
    let (mine, theirs) = tokio::io::duplex(1024);
    let (r, w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(r, w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        harness.pool.run(invocation),
    )
    .await
    .expect("the idle deadline did not end an infinite wait")
    .expect("the program ran");
    drop(mine);

    assert_eq!(
        outcome.status,
        SockStatus::Ok(42),
        "the wait should have come back as a timeout, not as readiness"
    );
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(250),
        "the wait returned before the deadline it was clamped to"
    );
}

const CHATTY: &str = r#"
#include <synch.h>

/* Reads for longer than one idle deadline, a little at a time. A total
   wall-clock cap would kill this; an idle deadline must not. */
SY_ENTRY sy_s64 entry(void) {
  char buf[64];
  sy_s64 total = 0;
  struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
  for (;;) {
    if (sy_poll(fds, 1, 5000) <= 0) return -1;
    sy_s64 n = sy_read(SY_SELF, buf, sizeof buf);
    if (n == 0) break;
    if (n < 0) { if (n == SY_EAGAIN) continue; return n; }
    total += n;
  }
  sy_shutdown(SY_SELF);
  return total;
}
"#;

#[tokio::test]
async fn steady_progress_keeps_an_invocation_alive_past_the_idle_deadline() {
    let elf = compile(CHATTY, "chatty.c");
    // Short enough that a *total* cap would fire well before the exchange ends.
    let harness = Harness::with_limits(Limits {
        idle_deadline: std::time::Duration::from_millis(200),
        ..Limits::default()
    });

    let (mine, theirs) = tokio::io::duplex(4096);
    let (their_r, their_w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );

    let driver = tokio::spawn(async move {
        let mut mine = mine;
        for _ in 0..10 {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            mine.write_all(b"tick").await.unwrap();
        }
        mine.shutdown().await.unwrap();
        // Held open so the guest sees an EOF rather than a reset.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    });

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        harness.pool.run(invocation),
    )
    .await
    .expect("a steadily-fed invocation was killed by a deadline")
    .expect("the program ran");
    driver.await.unwrap();

    assert_eq!(
        outcome.status,
        SockStatus::Ok(40),
        "every byte should have arrived: an idle deadline is not a total cap"
    );
}

/// The worked example from `docs/SOCKETS.md` §8, extracted from the document.
///
/// A design document's example is the first thing anybody writes a socket from,
/// and an example that does not compile teaches the reader that the document is
/// approximate. Extracted rather than copied, so the two cannot drift.
fn documented_example() -> Option<String> {
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/SOCKETS.md"
    ))
    .ok()?;
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in doc.lines() {
        match (&mut current, line.trim_end()) {
            (None, "```c") => current = Some(Vec::new()),
            (Some(body), "```") => {
                blocks.push(body.join("\n"));
                current = None;
            }
            (Some(body), line) => body.push(line),
            (None, _) => {}
        }
    }
    // The one that is a whole program, rather than the header excerpt in §7
    // that merely *defines* those macros.
    blocks
        .into_iter()
        .find(|b| b.contains("SY_ENTRY sy_s64 entry(void)"))
}

#[test]
fn the_documented_example_compiles_against_the_shipped_header() {
    let source = documented_example().expect("docs/SOCKETS.md §8 has a complete example");
    assert!(
        source.contains("sy_pump"),
        "the example should use the header's pump rather than open-coding it"
    );
    // `compile` panics with the compiler's own diagnostics if the example is
    // wrong, which is exactly the failure worth having.
    let elf = compile(&source, "documented.c");

    // And it is a program the runtime will actually accept: both sections
    // present, and the declaration hook says what the document says it says.
    let declared = synch_sock::declare(&elf, Arc::new(harness::FakeTree::default()))
        .expect("the documented example loads and declares");
    assert_eq!(declared.name, "git-http");
    assert_eq!(declared.egress, vec!["git.internal:9418".to_string()]);
    assert_eq!(declared.max_streams, Some(32));
}

const HOLD_OPEN: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_label_set(SY_STR("phase"), SY_STR("waiting"));
  sy_metric_add(SY_STR("started"), 1);
  char buf[64];
  struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
  for (;;) {
    if (sy_poll(fds, 1, 10000) <= 0) break;
    sy_s64 n = sy_read(SY_SELF, buf, sizeof buf);
    if (n == 0) break;
    if (n < 0) { if (n == SY_EAGAIN) continue; break; }
    sy_write(SY_SELF, buf, (sy_u64)n);
  }
  sy_shutdown(SY_SELF);
  return 0;
}
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_shutdown_cancels_and_drains_running_invocations() {
    let elf = compile(HOLD_OPEN, "shutdown.c");
    let harness = Harness::new();
    let registry = harness.pool.registry().clone();
    let (_mine, theirs) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(theirs);
    let invocation = harness
        .admitted(&elf, DuplexStream::new(reader, writer), &registry, 1)
        .expect("the invocation is admitted");
    let pool = harness.pool.clone();
    let running = tokio::spawn(async move { pool.run(invocation).await.unwrap() });

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while registry
            .snapshot(None, std::time::Instant::now())
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the invocation never started");

    tokio::time::timeout(std::time::Duration::from_secs(10), harness.pool.shutdown())
        .await
        .expect("pool shutdown did not join its workers");
    assert_eq!(running.await.unwrap().status, SockStatus::Shutdown);
    assert!(registry
        .snapshot(None, std::time::Instant::now())
        .is_empty());

    // Cloned handles share ownership of the same joins; shutdown is idempotent.
    harness.pool.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_registry_shows_a_running_invocation_and_caps_how_many_there_are() {
    let elf = compile(HOLD_OPEN, "hold-open.c");
    let harness = Harness::new();
    // The pool's own registry, as the daemon uses: the slot and the cancel
    // channel have to be in the same one for a kill to reach anything.
    let registry = harness.pool.registry().clone();

    // One slot, and it is taken.
    let (mut mine, theirs) = tokio::io::duplex(4096);
    let (r, w) = tokio::io::split(theirs);
    let first = harness
        .admitted(&elf, DuplexStream::new(r, w), &registry, 1)
        .expect("the first invocation is admitted");
    let id = first.id;

    let pool = harness.pool.clone();
    let running = tokio::spawn(async move { pool.run(first).await });

    // A second admission is refused while the first holds the only slot. This
    // is the cap that `Refused{Busy}` exists for, and before the registry it
    // was never checked anywhere.
    let (_spare, other) = tokio::io::duplex(64);
    let (r2, w2) = tokio::io::split(other);
    assert!(
        harness
            .admitted(&elf, DuplexStream::new(r2, w2), &registry, 1)
            .is_none(),
        "the concurrency cap admitted a second invocation"
    );

    // Drive it, so there is something to see.
    mine.write_all(b"hello").await.unwrap();
    let mut echoed = [0u8; 5];
    mine.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello");

    let seen = registry.snapshot(None, std::time::Instant::now());
    assert_eq!(
        seen.len(),
        1,
        "the running invocation is not in the registry"
    );
    assert_eq!(seen[0].id, id);
    assert_eq!(seen[0].bytes_in, 5);
    assert_eq!(seen[0].bytes_out, 5);
    assert_eq!(seen[0].handles, 1, "SY_SELF is the only handle it holds");
    assert!(seen[0].polls > 0);
    assert_eq!(
        seen[0].labels,
        vec![("phase".to_string(), "waiting".to_string())]
    );
    assert_eq!(seen[0].metrics, vec![("started".to_string(), 1)]);

    // A kill reaches it, and the slot comes back.
    assert!(registry.kill(id), "the kill found no invocation");
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), running)
        .await
        .expect("the killed invocation did not end")
        .unwrap()
        .expect("the program ran");
    assert_eq!(outcome.status, SockStatus::Killed);

    assert!(
        registry
            .snapshot(None, std::time::Instant::now())
            .is_empty(),
        "a finished invocation stayed in the registry"
    );
    let (_a, b) = tokio::io::duplex(64);
    let (r3, w3) = tokio::io::split(b);
    assert!(
        harness
            .admitted(&elf, DuplexStream::new(r3, w3), &registry, 1)
            .is_some(),
        "the slot was not given back"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_worker_can_run_two_long_lived_invocations_concurrently() {
    let elf = compile(HOLD_OPEN, "hold-open-concurrent.c");
    let harness = Harness::new();
    let registry = harness.pool.registry().clone();

    let (mut first_caller, first_guest) = tokio::io::duplex(4096);
    let (first_r, first_w) = tokio::io::split(first_guest);
    let first = harness
        .admitted(&elf, DuplexStream::new(first_r, first_w), &registry, 2)
        .expect("the first invocation is admitted");

    let (mut second_caller, second_guest) = tokio::io::duplex(4096);
    let (second_r, second_w) = tokio::io::split(second_guest);
    let second = harness
        .admitted(&elf, DuplexStream::new(second_r, second_w), &registry, 2)
        .expect("the second invocation is admitted");

    let first_pool = harness.pool.clone();
    let first_run = tokio::spawn(async move { first_pool.run(first).await });
    let second_pool = harness.pool.clone();
    let second_run = tokio::spawn(async move { second_pool.run(second).await });

    first_caller.write_all(b"first").await.unwrap();
    let mut first_echo = [0; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        first_caller.read_exact(&mut first_echo),
    )
    .await
    .expect("the first invocation did not start")
    .unwrap();
    assert_eq!(&first_echo, b"first");

    // Keep the first invocation open while driving the second. A worker that
    // awaits each job in its receive loop cannot produce this echo.
    second_caller.write_all(b"second").await.unwrap();
    let mut second_echo = [0; 6];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        second_caller.read_exact(&mut second_echo),
    )
    .await
    .expect("the second invocation was serialized behind the first")
    .unwrap();
    assert_eq!(&second_echo, b"second");

    first_caller.shutdown().await.unwrap();
    second_caller.shutdown().await.unwrap();
    for run in [first_run, second_run] {
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), run)
            .await
            .expect("an invocation did not finish")
            .unwrap()
            .expect("the program ran");
        assert_eq!(outcome.status, SockStatus::Ok(0));
    }
}

const TALKATIVE: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_log(SY_STR("first line\n"));
  sy_log(SY_STR("second line\n"));
  sy_shutdown(SY_SELF);
  return 0;
}
"#;

#[tokio::test]
async fn what_a_program_logs_is_kept_for_its_socket() {
    let elf = compile(TALKATIVE, "talkative.c");
    let harness = Harness::new();
    let registry = harness.pool.registry().clone();

    let (mine, theirs) = tokio::io::duplex(1024);
    drop(mine);
    let (r, w) = tokio::io::split(theirs);
    let mut invocation = harness.invocation(
        &elf,
        DuplexStream::new(r, w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    invocation.socket = SocketId::new("code", "talkative.sock");
    harness.pool.run(invocation).await.expect("the program ran");

    let lines = registry.logs("code/talkative.sock");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0].text, "first line");
    assert_eq!(lines[1].text, "second line");
    assert!(
        registry.logs("code/other.sock").is_empty(),
        "log lines leaked between sockets"
    );
}

const SHORT_BUFFER: &str = r#"
#include <synch.h>

/* Every buffer here sits in the top of the frame, where fewer than a chunk's
   worth of bytes follow it. */
SY_ENTRY sy_s64 entry(void) {
  char small[16];
  sy_s64 n = sy_peer_origin(small, sizeof small);   /* truncated on purpose */
  if (n != 22) return -1;              /* snprintf semantics: what it needed */
  if (sy_strlen(small) != 15) return -2;         /* 16 bytes, one of them NUL */

  char tiny[8];
  tiny[0] = 'a'; tiny[1] = 'b'; tiny[2] = 0;
  if (sy_strlen(tiny) != 2) return -3;

  /* And a literal, which lives in the data section rather than the stack and
     is measured the same way — `SY_STR` uses `sy_strlen` under the macro. */
  sy_write(SY_SELF, SY_STR("ok"));
  sy_shutdown(SY_SELF);
  return 0;
}
"#;

/// Header-side `sy_strlen` reads only the bytes of the string, including when
/// the string is near the end of a stack frame or in the data section.
#[tokio::test]
async fn a_string_near_the_end_of_its_region_still_has_a_length() {
    let elf = compile(SHORT_BUFFER, "short-buffer.c");
    let harness = Harness::new();
    let (status, out) = exchange(
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
        "{}",
        String::from_utf8_lossy(&out)
    );
    assert_eq!(out, b"ok");
}

const LATE_READ: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  /* Read the caller's request to its end first, so the inbound stream is at
     EOF before the tree read starts — the ordinary shape of a request/response
     socket, and the one that used to break. */
  char scratch[64];
  for (;;) {
    struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_IN, 0 } };
    if (sy_poll(fds, 1, 5000) <= 0) break;
    sy_s64 n = sy_read(SY_SELF, scratch, sizeof scratch);
    if (n == SY_EAGAIN) continue;
    if (n <= 0) break;
  }

  sy_s64 obj = sy_open(SY_STR("code/readme"));
  if (obj < 0) return obj;
  char buf[128];
  for (;;) {
    sy_s64 n = sy_pread(obj, buf, sizeof buf, 0);
    if (n == SY_EAGAIN) {
      struct sy_pollfd fds[1] = { { obj, SY_POLL_IN, 0 } };
      if (sy_poll(fds, 1, 5000) <= 0) return -1;
      continue;
    }
    if (n < 0) return n;
    sy_write(SY_SELF, buf, (sy_u64)n);
    break;
  }
  sy_shutdown(SY_SELF);
  return 0;
}
"#;

/// A fetch in flight is not "nothing can happen".
///
/// `sy_poll` short-circuits when every handle is finished, which is what stops
/// a program waiting out its deadline for a peer that has gone. An object with
/// a read outstanding was counted as finished, so a socket that read the tree
/// *after* its caller had stopped talking — a request/response socket, in other
/// words — was told its pending read would never land.
#[tokio::test]
async fn a_tree_read_outlives_the_caller_that_asked_for_it() {
    let elf = compile(LATE_READ, "late-read.c");
    let harness = Harness::with_tree(&[("code/readme", "read after the question ended")]);
    let (status, out) = exchange(
        &harness,
        &elf,
        b"please\n",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"read after the question ended");
}

const LIST_RETRY: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 cur = sy_list_open(SY_STR("code/"));
  if (cur < 0) return cur;
  char tiny[2];
  sy_s64 needed = sy_list_next(cur, tiny, sizeof tiny);
  if (needed <= 0 || needed >= 64) return -10;
  char name[64];
  sy_s64 n = sy_list_next(cur, name, (sy_u64)needed + 1);
  if (n != needed) return -11;
  sy_write(SY_SELF, name, (sy_u64)n);
  sy_shutdown(SY_SELF);
  return 0;
}
"#;

#[tokio::test]
async fn a_short_list_buffer_can_retry_the_same_entry() {
    let elf = compile(LIST_RETRY, "list-retry.c");
    let harness = Harness::with_tree(&[("code/a-long-name", "body"), ("code/z", "body")]);
    let (status, out) = exchange(
        &harness,
        &elf,
        b"",
        EffectivePolicy::default(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(out, b"code/a-long-name");
}
