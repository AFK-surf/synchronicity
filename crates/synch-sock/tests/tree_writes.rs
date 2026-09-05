//! The `sy_put_*` writer family, end to end against a fake host
//! (`docs/TREE-WRITES.md`).
//!
//! What is checked here is the runtime's half of the contract: the declared
//! grant is the gate, the writer lifecycle (open → write/splice → commit →
//! spent) refuses what it should with the errno a program can act on, and the
//! poll integration behaves like every other handle. The engine's half — the
//! real gates, the publish, the tombstone — lives in
//! `crates/synch-engine/tests/tree_writes.rs`.

#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use harness::{compile, exchange, peer, Harness};
use synch_core::{
    Hash, SockStatus, TreeWriteCapability, TREE_WRITE_CREATE, TREE_WRITE_DELETE, TREE_WRITE_REPLACE,
};
use synch_sock::EffectivePolicy;

fn grants(capabilities: Vec<TreeWriteCapability>) -> EffectivePolicy {
    EffectivePolicy {
        tree_writes: capabilities,
        ..EffectivePolicy::default()
    }
}

fn inbox_grant(modes: u32, max_bytes: u64) -> TreeWriteCapability {
    TreeWriteCapability {
        id: 1,
        modes,
        prefix: "code/inbox".into(),
        max_bytes,
    }
}

/// Stages the caller's whole stream at a fixed path and answers with the
/// published root, hex — the drop-box shape from the design document.
const DROP: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 w = sy_put_open(1, SY_STR("code/inbox/drop.bin"));
  if (w < 0) return w;
  for (;;) {
    sy_s64 n = sy_put_splice(w, SY_SELF, 65536);
    if (n == 0) break;                        /* caller's clean EOF */
    if (n == SY_EAGAIN) {
      struct sy_pollfd fds[2] = { { SY_SELF, SY_POLL_IN, 0 },
                                  { w, SY_POLL_OUT, 0 } };
      if (sy_poll(fds, 2, 5000) <= 0) return 100;
      if ((fds[0].revents | fds[1].revents) & SY_POLL_ERR) return 101;
    } else if (n < 0) return n;
  }
  sy_u8 root[32];
  sy_s64 rc;
  while ((rc = sy_put_commit(w, root)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, 5000) <= 0) return 102;
  }
  if (rc < 0) return rc;
  /* Spent: further bytes are a lifecycle error, not a quiet no-op. */
  if (sy_put_write(w, "x", 1) != SY_ESTATE) return 103;
  char hex[65];
  sy_hex_encode(root, sizeof root, hex, sizeof hex, 0);
  sy_write_all(SY_SELF, hex, 64, 5000);
  sy_close(w);
  return 0;
}
"#;

#[tokio::test]
async fn a_program_stages_a_stream_and_commits_it() {
    let elf = compile(DROP, "drop.c");
    let harness = Harness::new();
    let payload = b"the whole upload, spliced through host memory".to_vec();
    let (status, out) = exchange(
        &harness,
        &elf,
        &payload,
        grants(vec![inbox_grant(TREE_WRITE_CREATE, 0)]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(
        String::from_utf8(out).unwrap(),
        Hash::new(&payload).to_hex(),
        "the receipt is the root of exactly what the caller sent"
    );
    let written = harness.tree.written.lock().unwrap();
    assert_eq!(
        written.get("code/inbox/drop.bin").map(Vec::as_slice),
        Some(payload.as_slice())
    );
}

#[tokio::test]
async fn a_write_needs_a_grant_and_stays_inside_its_prefix() {
    const PROBES: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  /* No capability 9 was declared. */
  if (sy_put_open(9, SY_STR("code/inbox/a")) != SY_EPERM) return 1;
  /* Component-wise: code/inbox-evil is not under code/inbox. */
  if (sy_put_open(1, SY_STR("code/inbox-evil/a")) != SY_EPERM) return 2;
  if (sy_put_open(1, SY_STR("media/inbox/a")) != SY_EPERM) return 3;
  /* A path must name a file inside a space. */
  if (sy_put_open(1, SY_STR("code")) != SY_EINVAL) return 4;
  if (sy_put_open(1, SY_STR("../escape")) != SY_EINVAL) return 5;
  /* The host's declared-socket refusal comes back as policy. */
  if (sy_put_open(1, SY_STR("code/inbox/git.sock")) != SY_EPERM) return 6;
  /* And a covered, ordinary path opens. */
  sy_s64 w = sy_put_open(1, SY_STR("code/inbox/fine"));
  if (w < 0) return 7;
  sy_close(w);
  return 0;
}
"#;
    let elf = compile(PROBES, "probes.c");
    let harness = Harness::with_tree_and_refused(&[], &["code/inbox/git.sock"]);
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        grants(vec![inbox_grant(TREE_WRITE_CREATE, 0)]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
}

#[tokio::test]
async fn the_size_bound_refuses_bytes_as_they_enter_staging() {
    const BOUNDED: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 w = sy_put_open(1, SY_STR("code/inbox/small"));
  if (w < 0) return w;
  /* Nine bytes into an eight-byte grant: refused before any are taken. */
  if (sy_put_write(w, "123456789", 9) != SY_ELIMIT) return 1;
  if (sy_put_write(w, "12345678", 8) != 8) return 2;
  /* The bound is on staged bytes, so one more is over it. */
  if (sy_put_write(w, "x", 1) != SY_ELIMIT) return 3;
  sy_u8 root[32];
  sy_s64 rc;
  while ((rc = sy_put_commit(w, root)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, 5000) <= 0) return 4;
  }
  return rc;
}
"#;
    let elf = compile(BOUNDED, "bounded.c");
    let harness = Harness::new();
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        grants(vec![inbox_grant(TREE_WRITE_CREATE, 8)]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(
        harness
            .tree
            .written
            .lock()
            .unwrap()
            .get("code/inbox/small")
            .map(Vec::as_slice),
        Some(b"12345678".as_slice())
    );
}

#[tokio::test]
async fn a_lost_condition_is_stale_and_the_writer_stays_usable() {
    const CONDITIONAL: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 w = sy_put_open(1, SY_STR("code/inbox/x"));
  if (w < 0) return w;
  if (sy_put_write(w, "new", 3) != 3) return 1;
  /* All-zero expected: "no live version of ours" — but one exists. */
  sy_u8 absent[32] = {0};
  sy_u8 root[32];
  sy_s64 rc;
  while ((rc = sy_put_commit_if(w, absent, root)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, 5000) <= 0) return 2;
  }
  if (rc != SY_ESTALE) return 3;
  /* Retryable: the same writer commits unconditionally. */
  while ((rc = sy_put_commit(w, root)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, 5000) <= 0) return 4;
  }
  return rc;
}
"#;
    let elf = compile(CONDITIONAL, "conditional.c");
    let harness = Harness::new();
    harness
        .tree
        .written
        .lock()
        .unwrap()
        .insert("code/inbox/x".into(), b"old".to_vec());
    // Replace is granted because the retry unconditionally overwrites the
    // live version — with create alone, the engine's mode condition would
    // refuse it (`a_create_only_grant_cannot_replace`, engine-side).
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        grants(vec![inbox_grant(TREE_WRITE_CREATE | TREE_WRITE_REPLACE, 0)]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(
        harness
            .tree
            .written
            .lock()
            .unwrap()
            .get("code/inbox/x")
            .map(Vec::as_slice),
        Some(b"new".as_slice())
    );
}

/// The runtime fake mirrors the engine's mode condition: an unconditional
/// commit still needs the mode for what it actually does, so a create-only
/// grant over a live version is `SY_EPERM` — the same answer
/// `a_create_only_grant_cannot_replace` proves against a real node.
#[tokio::test]
async fn an_unconditional_commit_needs_the_mode_for_what_it_does() {
    const CREATE_ONLY: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 w = sy_put_open(1, SY_STR("code/inbox/x"));
  if (w < 0) return 1;
  if (sy_put_write(w, "new", 3) != 3) return 2;
  sy_u8 root[32];
  sy_s64 rc;
  while ((rc = sy_put_commit(w, root)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, 5000) <= 0) return 3;
  }
  return rc == SY_EPERM ? 0 : 4;
}
"#;
    let elf = compile(CREATE_ONLY, "create_only.c");
    let harness = Harness::new();
    harness
        .tree
        .written
        .lock()
        .unwrap()
        .insert("code/inbox/x".into(), b"old".to_vec());
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        grants(vec![inbox_grant(TREE_WRITE_CREATE, 0)]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(
        harness
            .tree
            .written
            .lock()
            .unwrap()
            .get("code/inbox/x")
            .map(Vec::as_slice),
        Some(b"old".as_slice()),
        "the live version survives a commit the grant's modes refuse"
    );
}

/// A payload of exactly `max_bytes` reaches its clean EOF: the source's end
/// is checked before the grant bound, so the documented splice loop ends at
/// `0` instead of `SY_ELIMIT` with everything already staged.
#[tokio::test]
async fn a_payload_exactly_at_the_bound_splices_to_its_clean_eof() {
    let elf = compile(DROP, "drop.c");
    let harness = Harness::new();
    let payload = b"exactly as much as the grant allows".to_vec();
    let (status, out) = exchange(
        &harness,
        &elf,
        &payload,
        grants(vec![inbox_grant(TREE_WRITE_CREATE, payload.len() as u64)]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(
        String::from_utf8(out).unwrap(),
        Hash::new(&payload).to_hex()
    );
}

/// A parked answer is collected only by the call that dispatched it: a
/// commit collecting a delete's bare success would hand back an unwritten
/// root buffer as a receipt.
#[tokio::test]
async fn a_parked_answer_belongs_to_the_call_that_asked() {
    const MISMATCH: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 w = sy_put_open(1, SY_STR("code/inbox/gone"));
  if (w < 0) return 1;
  if (sy_put_delete(w) != SY_EAGAIN) return 2;
  /* The wrong collector, in flight and parked alike: SY_ESTATE, and the
     delete's own answer stays collectible. */
  sy_u8 root[32];
  if (sy_put_commit(w, root) != SY_ESTATE) return 3;
  sy_s64 rc;
  while ((rc = sy_put_delete(w)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, 5000) <= 0) return 4;
  }
  if (rc != 0) return 5;
  if (sy_put_commit(w, root) != SY_ESTATE) return 6;
  return 0;
}
"#;
    let elf = compile(MISMATCH, "mismatch.c");
    let harness = Harness::new();
    harness
        .tree
        .written
        .lock()
        .unwrap()
        .insert("code/inbox/gone".into(), b"bye".to_vec());
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        grants(vec![inbox_grant(TREE_WRITE_CREATE | TREE_WRITE_DELETE, 0)]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(
        harness.tree.deleted.lock().unwrap().as_slice(),
        ["code/inbox/gone".to_string()]
    );
}

/// A commit that fails host-side (disk, CAS — anything but a refusal) is
/// sticky: the staging may already be consumed, and a retry over unknown
/// staging is how an empty file would get published under a valid receipt.
#[tokio::test]
async fn a_broken_commit_is_sticky_not_retryable() {
    const RETRIES: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 w = sy_put_open(1, SY_STR("code/inbox/x"));
  if (w < 0) return 1;
  if (sy_put_write(w, "data", 4) != 4) return 2;
  sy_u8 root[32];
  sy_s64 rc;
  while ((rc = sy_put_commit(w, root)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, 5000) <= 0) return 3;
  }
  if (rc != SY_EIO) return 4;
  /* Broken, not parked-and-retryable: every further call answers the same. */
  if (sy_put_commit(w, root) != SY_EIO) return 5;
  if (sy_put_write(w, "x", 1) != SY_EIO) return 6;
  return 0;
}
"#;
    let elf = compile(RETRIES, "retries.c");
    let harness = Harness::new();
    *harness.tree.fail_commits.lock().unwrap() = 1;
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        grants(vec![inbox_grant(TREE_WRITE_CREATE, 0)]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert!(
        !harness
            .tree
            .written
            .lock()
            .unwrap()
            .contains_key("code/inbox/x"),
        "nothing was published by the failed commit or after it"
    );
}

#[tokio::test]
async fn delete_requires_its_mode_and_a_clean_writer() {
    const DELETES: &str = r#"
#include <synch.h>

static sy_s64 drive(sy_s64 w) {
  sy_s64 rc;
  while ((rc = sy_put_delete(w)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, 5000) <= 0) return -100;
  }
  return rc;
}

SY_ENTRY sy_s64 entry(void) {
  /* Capability 2 was granted create only: no delete. */
  sy_s64 w = sy_put_open(2, SY_STR("code/inbox/a"));
  if (w < 0) return 1;
  if (drive(w) != SY_EPERM) return 2;
  sy_close(w);
  /* Capability 1 may delete, but not through a writer holding bytes. */
  w = sy_put_open(1, SY_STR("code/inbox/b"));
  if (w < 0) return 3;
  if (sy_put_write(w, "x", 1) != 1) return 4;
  if (sy_put_delete(w) != SY_ESTATE) return 5;
  sy_close(w);
  /* A clean writer deletes. */
  w = sy_put_open(1, SY_STR("code/inbox/b"));
  if (w < 0) return 6;
  sy_s64 rc = drive(w);
  if (rc != 0) return 7;
  /* Delivered: the writer is spent. */
  if (sy_put_delete(w) != SY_ESTATE) return 8;
  sy_close(w);
  return 0;
}
"#;
    let elf = compile(DELETES, "deletes.c");
    let harness = Harness::new();
    harness
        .tree
        .written
        .lock()
        .unwrap()
        .insert("code/inbox/b".into(), b"going".to_vec());
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        grants(vec![
            inbox_grant(TREE_WRITE_CREATE | TREE_WRITE_DELETE, 0),
            TreeWriteCapability {
                id: 2,
                ..inbox_grant(TREE_WRITE_CREATE, 0)
            },
        ]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
    assert_eq!(
        harness.tree.deleted.lock().unwrap().as_slice(),
        ["code/inbox/b".to_string()]
    );
    assert!(!harness
        .tree
        .written
        .lock()
        .unwrap()
        .contains_key("code/inbox/b"));
}

#[tokio::test]
async fn writers_are_bounded_per_invocation() {
    const MANY: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 held[4];
  for (int i = 0; i < 4; i++) {
    held[i] = sy_put_open(1, SY_STR("code/inbox/n"));
    if (held[i] < 0) return 1;
  }
  if (sy_put_open(1, SY_STR("code/inbox/n")) != SY_ELIMIT) return 2;
  /* Closing one gives the place back. */
  sy_close(held[0]);
  if (sy_put_open(1, SY_STR("code/inbox/n")) < 0) return 3;
  return 0;
}
"#;
    let elf = compile(MANY, "many.c");
    let harness = Harness::new();
    let (status, _) = exchange(
        &harness,
        &elf,
        b"",
        grants(vec![inbox_grant(TREE_WRITE_CREATE, 0)]),
        peer(None),
        vec![],
    )
    .await;
    assert_eq!(status, SockStatus::Ok(0));
}

/// The manifest's half: a tree-write grant is data in the object, and the
/// grant it captures round-trips through the rendered declaration.
#[test]
fn the_manifest_captures_a_tree_write_grant() {
    const DECLARES: &str = r#"
#include <synch.h>

SY_MANIFEST("{\"manifest\":1,\"tree_writes\":[{\"id\":1,"
            "\"prefix\":\"code/inbox\",\"allow\":[\"create\",\"delete\"]}]}");

SY_ENTRY sy_s64 entry(void) { return 0; }
"#;
    let elf = compile(DECLARES, "declares.c");
    let declared = synch_sock::manifest::manifest_declaration(&elf).expect("the manifest parses");
    assert_eq!(declared.tree_writes.len(), 1);
    let grant = &declared.tree_writes[0];
    assert_eq!(grant.id, 1);
    assert_eq!(grant.prefix, "code/inbox");
    assert_eq!(grant.modes, TREE_WRITE_CREATE | TREE_WRITE_DELETE);
    assert_eq!(
        grant.max_bytes,
        synch_core::DEFAULT_TREE_WRITE_MAX_BYTES,
        "an undeclared bound is the modest default, not unbounded"
    );
    let parsed = synch_core::Declaration::parse(&declared.render());
    assert_eq!(parsed.tree_writes, declared.tree_writes);
}
