//! The descriptor model (`docs/HANDLES.md`), pinned.
//!
//! What is checked here is the model itself rather than any one family: the
//! data plane refuses foreign kinds with `SY_EBADF` while the lifecycle plane
//! takes them all, quiet is claimed only by handles nothing can ever wake,
//! and a handle closed mid-flight stays sound. The per-family behavior lives
//! in the families' own suites; this one keeps the seams between them honest.

#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use harness::{compile, exchange, peer, Harness};
use synch_core::{ProcessCapability, SockStatus, TreeWriteCapability, TREE_WRITE_CREATE};
use synch_sock::EffectivePolicy;

fn policy_with_writes_and_processes() -> EffectivePolicy {
    let mut policy = EffectivePolicy::default();
    policy.tree_writes.push(TreeWriteCapability {
        id: 1,
        modes: TREE_WRITE_CREATE,
        prefix: "code/inbox".into(),
        max_bytes: 0,
    });
    policy.processes.push(ProcessCapability {
        id: 1,
        flags: 0x02,
        executable: "/bin/sh".into(),
        argv: vec!["sh".into(), "-c".into(), "sleep 0.2".into()],
        allowed_signals: 0,
    });
    policy
}

/// One handle of each obtainable kind, probed against every foreign data
/// verb: the typed data plane is `SY_EBADF` across kinds, and the lifecycle
/// plane (`sy_close`, `sy_errno`, `sy_poll`) takes them all
/// (`docs/HANDLES.md` §3, §7).
#[tokio::test]
async fn the_data_plane_is_typed_and_the_lifecycle_plane_is_not() {
    const MATRIX: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 obj = sy_open(SY_STR("code/a.txt"));
  if (obj < 0) return 1;
  sy_s64 cur = sy_list_open(SY_STR("code/"));
  if (cur < 0) return 2;
  sy_s64 json = sy_json_new_object();
  if (json < 0) return 3;
  sy_s64 w = sy_put_open(1, SY_STR("code/inbox/probe"));
  if (w < 0) return 4;

  /* Endpoint verbs refuse every non-endpoint kind. */
  char buf[8];
  if (sy_read(obj, buf, sizeof buf) != SY_EBADF) return 10;
  if (sy_write(cur, "x", 1) != SY_EBADF) return 11;
  if (sy_readable(json) != SY_EBADF) return 12;
  if (sy_writable(w) != SY_EBADF) return 13;
  if (sy_shutdown(obj) != SY_EBADF) return 14;
  if (sy_splice(w, SY_SELF, 16) != SY_EBADF) return 15;
  if (sy_splice(SY_SELF, json, 16) != SY_EBADF) return 16;

  /* Object verbs refuse the others. */
  if (sy_stat(cur) != SY_EBADF) return 20;
  if (sy_pread(w, buf, sizeof buf, 0) != SY_EBADF) return 21;

  /* Cursor, JSON, writer and process verbs, likewise. */
  if (sy_list_next(json, buf, sizeof buf) != SY_EBADF) return 30;
  if (sy_json_type(w) != SY_EBADF) return 31;
  if (sy_json_len(obj) != SY_EBADF) return 32;
  if (sy_put_write(json, "x", 1) != SY_EBADF) return 33;
  sy_u8 root[32];
  if (sy_put_commit(cur, root) != SY_EBADF) return 34;
  if (sy_process_status(obj) != SY_EBADF) return 35;
  if (sy_process_signal(json, SY_STR("TERM")) != SY_EBADF) return 36;

  /* Endpoint attribute helpers: not-in-the-table stays SY_EBADF. */
  if (sy_pty_resize(json, 80, 24, 0, 0) != SY_EBADF) return 40;
  if (sy_ssh_channel_type(cur, buf, sizeof buf) != SY_EBADF) return 41;

  /* An index that was never allocated, on both planes. */
  if (sy_read(99, buf, sizeof buf) != SY_EBADF) return 50;
  if (sy_errno(99) != SY_EBADF) return 51;
  if (sy_close(99) != SY_EBADF) return 52;

  /* The lifecycle plane takes every kind: errno answers, poll reports a
     JSON value as inert rather than refusing to watch it. */
  if (sy_errno(obj) != 0) return 60;
  if (sy_errno(cur) != 0) return 61;
  if (sy_errno(json) != 0) return 62;
  if (sy_errno(w) != 0) return 63;
  struct sy_pollfd inert = { json, SY_POLL_IN, 0 };
  if (sy_poll(&inert, 1, 0) != 0) return 64;
  if (inert.revents != 0) return 65;

  /* And closes every kind exactly once. */
  if (sy_close(obj) != 0) return 70;
  if (sy_close(obj) != SY_EBADF) return 71;
  if (sy_close(cur) != 0) return 72;
  if (sy_close(json) != 0) return 73;
  if (sy_close(w) != 0) return 74;
  if (sy_close(w) != SY_EBADF) return 75;
  return 0;
}
"#;
    let elf = compile(MATRIX, "matrix.c");
    let harness = Harness::with_tree(&[("code/a.txt", "alpha")]);
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        policy_with_writes_and_processes(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
}

/// A running child is waiting, not finished (`docs/HANDLES.md` §7, §8): with
/// every stream closed and only the process handle left, `sy_poll` must wait
/// for the exit and report it, not return `0` as if nothing could ever become
/// ready. Before the process arm existed in the quiet test, this returned `0`
/// immediately while the child ran.
#[tokio::test]
async fn a_running_process_is_waiting_not_finished() {
    const WAITS: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 p = sy_process_spawn(1);
  if (p < 0) return 1;
  /* Close everything but the process handle, so only the child's exit can
     make this invocation ready again. */
  sy_s64 io = sy_process_stdio(p, SY_STR("main"));
  if (io < 0) return 2;
  sy_close(io);
  sy_s64 err = sy_process_stdio(p, SY_STR("stderr"));
  if (err > 0) sy_close(err);
  sy_close(SY_SELF);
  struct sy_pollfd wait = { p, SY_POLL_IN, 0 };
  sy_s64 n = sy_poll(&wait, 1, 5000);
  if (n <= 0) return 3; /* 0 here is the "you are finished" lie */
  if (!(wait.revents & SY_POLL_IN)) return 4;
  sy_s64 status = sy_process_status(p);
  if (status <= 0) return 5;
  sy_close(status);
  sy_close(p);
  return 0;
}
"#;
    let elf = compile(WAITS, "waits.c");
    let harness = Harness::new();
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        policy_with_writes_and_processes(),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
}

/// Closing an object whose read is still in flight is sound: the landing
/// fetch settles against the slot it holds, not the index (`docs/HANDLES.md`
/// §8 rule 5), and the index is free for the next open immediately.
#[tokio::test]
async fn a_handle_closed_mid_flight_stays_sound() {
    const MIDFLIGHT: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 obj = sy_open(SY_STR("code/a.txt"));
  if (obj < 0) return 1;
  char buf[16];
  /* Dispatch the read and let go before collecting it. */
  if (sy_pread(obj, buf, 5, 0) != SY_EAGAIN) return 2;
  if (sy_close(obj) != 0) return 3;
  if (sy_pread(obj, buf, 5, 0) != SY_EBADF) return 4;
  /* Give the orphaned fetch a moment to land against the closed slot. */
  struct sy_pollfd idle = { SY_SELF, SY_POLL_IN, 0 };
  sy_poll(&idle, 1, 50);
  /* The table and the accounting are intact: the same file opens and reads
     to completion. */
  sy_s64 again = sy_open(SY_STR("code/a.txt"));
  if (again < 0) return 5;
  sy_s64 n;
  while ((n = sy_pread(again, buf, 5, 0)) == SY_EAGAIN) {
    struct sy_pollfd fd = { again, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, 5000) <= 0) return 6;
  }
  if (n != 5) return 7;
  if (sy_memcmp(buf, "alpha", 5) != 0) return 8;
  sy_close(again);
  return 0;
}
"#;
    let elf = compile(MIDFLIGHT, "midflight.c");
    let harness = Harness::with_tree(&[("code/a.txt", "alpha")]);
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
