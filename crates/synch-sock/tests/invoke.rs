//! End-to-end: a C program compiled to eBPF, run against a real stream.
//!
//! These tests need `clang` with a BPF target. Where it is absent they skip
//! rather than fail — a machine without the toolchain cannot say anything about
//! whether the runtime works, and a red test that means "no compiler" trains
//! people to ignore red tests.

#![cfg(all(
    any(target_os = "linux", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::{process::Command, sync::Arc};

use synch_core::{FaultKind, Hash, NodeId, OriginId, SockStatus};
use synch_sock::{
    DuplexStream, EffectivePolicy, HostError, Invocation, Limits, ObjectInfo, PeerIdentity,
    SocketHost, SocketId, WorkerHandle,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Compiles C to an eBPF object, or returns `None` when there is no toolchain.
fn compile(source: &str) -> Option<Vec<u8>> {
    let dir = tempdir()?;
    let src = dir.join("prog.c");
    let obj = dir.join("prog.o");
    std::fs::write(&src, source).ok()?;
    let out = Command::new("clang")
        .args(["-target", "bpf", "-O2", "-g0"])
        // The guest gets 4 KiB per local call frame; the default BPF stack
        // size is 512, and a program with a 4 KiB buffer will not compile
        // without this.
        .args(["-mllvm", "-bpf-stack-size=4096"])
        .arg("-I")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/sdk"))
        .arg("-c")
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .output()
        .ok()?;
    if !out.status.success() {
        // A compiler that is present and rejects the fixture is a real failure,
        // and saying so beats skipping.
        panic!(
            "clang rejected the fixture:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::read(&obj).ok()
}

fn tempdir() -> Option<std::path::PathBuf> {
    let base = std::env::temp_dir().join(format!(
        "synch-sock-test-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&base).ok()?;
    Some(base)
}

fn have_clang() -> bool {
    Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A tree with a couple of files in it.
#[derive(Default)]
struct FakeTree {
    files: std::collections::HashMap<String, Vec<u8>>,
}

#[async_trait::async_trait]
impl SocketHost for FakeTree {
    fn open(&self, _origin: Option<&str>, path: &str) -> Result<ObjectInfo, HostError> {
        let bytes = self.files.get(path).ok_or(HostError::NotFound)?;
        Ok(ObjectInfo {
            root: Hash::new(bytes),
            size: bytes.len() as u64,
            mtime_ns: 42,
            mode: 0o644,
            kind: 0,
        })
    }

    fn open_root(&self, root: &Hash) -> Result<ObjectInfo, HostError> {
        let bytes = self
            .files
            .values()
            .find(|b| Hash::new(b) == *root)
            .ok_or(HostError::NotFound)?;
        Ok(ObjectInfo {
            root: *root,
            size: bytes.len() as u64,
            mtime_ns: 42,
            mode: 0o644,
            kind: 0,
        })
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, HostError> {
        let mut names: Vec<String> = self
            .files
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        names.sort();
        Ok(names)
    }

    async fn pread(&self, root: Hash, offset: u64, len: u64) -> Result<Vec<u8>, HostError> {
        let bytes = self
            .files
            .values()
            .find(|b| Hash::new(b) == root)
            .ok_or(HostError::NotFound)?;
        let start = (offset as usize).min(bytes.len());
        let end = (start + len as usize).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }
}

fn peer(spaces: Option<Vec<String>>) -> PeerIdentity {
    PeerIdentity {
        origin: OriginId::named("laptop", "cluster.example").unwrap(),
        device_key: NodeId::from_bytes(&synch_sock::policy::NOBODY).unwrap(),
        spaces,
        addr: "198.51.100.7:44321".into(),
        stream_index: 0,
    }
}

struct Harness {
    pool: WorkerHandle,
    tree: Arc<FakeTree>,
}

impl Harness {
    fn new() -> Harness {
        Harness {
            pool: WorkerHandle::start(1, Limits::default()),
            tree: Arc::new(FakeTree::default()),
        }
    }

    fn with_tree(files: &[(&str, &str)]) -> Harness {
        let mut tree = FakeTree::default();
        for (name, body) in files {
            tree.files
                .insert(name.to_string(), body.as_bytes().to_vec());
        }
        Harness {
            pool: WorkerHandle::start(1, Limits::default()),
            tree: Arc::new(tree),
        }
    }

    fn invocation(
        &self,
        elf: &[u8],
        stream: DuplexStream,
        policy: EffectivePolicy,
        peer: PeerIdentity,
        meta: Vec<(String, String)>,
    ) -> Invocation {
        Invocation {
            program: Arc::new(elf.to_vec()),
            program_root: Hash::new(elf),
            socket: SocketId::new("code", "test.sock"),
            peer,
            policy,
            meta,
            stream,
            self_origin: OriginId::named("nas", "cluster.example").unwrap(),
            host: self.tree.clone(),
            id: self.pool.next_id(),
        }
    }
}

/// Runs a program against an in-memory stream, returning what it wrote back.
async fn exchange(
    harness: &Harness,
    elf: &[u8],
    input: &[u8],
    policy: EffectivePolicy,
    peer: PeerIdentity,
    meta: Vec<(String, String)>,
) -> (SockStatus, Vec<u8>) {
    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let invocation =
        harness.invocation(elf, DuplexStream::new(their_r, their_w), policy, peer, meta);

    let mut mine = mine;
    let input = input.to_vec();
    let driver = tokio::spawn(async move {
        mine.write_all(&input).await.unwrap();
        mine.shutdown().await.unwrap();
        let mut out = Vec::new();
        mine.read_to_end(&mut out).await.unwrap();
        out
    });

    let outcome = harness.pool.run(invocation).await.expect("the program ran");
    let out = driver.await.unwrap();
    (outcome.status, out)
}

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
    if !have_clang() {
        eprintln!("skipping: no clang with a BPF target");
        return;
    }
    let elf = compile(ECHO).expect("the fixture compiles");
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
    if !have_clang() {
        eprintln!("skipping: no clang with a BPF target");
        return;
    }
    let elf = compile(IDENTITY).expect("the fixture compiles");
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
async fn egress_outside_the_armed_intersection_is_refused() {
    if !have_clang() {
        eprintln!("skipping: no clang with a BPF target");
        return;
    }
    let elf = compile(EGRESS).expect("the fixture compiles");
    let harness = Harness::new();
    let (status, out) = exchange(
        &harness,
        &elf,
        b"",
        // Nothing declared, nothing allowed: the program asks anyway.
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
    if !have_clang() {
        eprintln!("skipping: no clang with a BPF target");
        return;
    }
    let elf = compile(TREE).expect("the fixture compiles");
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
    if !have_clang() {
        eprintln!("skipping: no clang with a BPF target");
        return;
    }
    let elf = compile(SPIN).expect("the fixture compiles");
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
    if !have_clang() {
        eprintln!("skipping: no clang with a BPF target");
        return;
    }
    let faulting = compile(FAULT).expect("the fixture compiles");
    let echo = compile(ECHO).expect("the fixture compiles");
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
  /* An I/O helper here has nothing to reach, and is refused before it tries. */
  if (sy_tcp_connect(SY_STR("git.internal"), 9418) != SY_EPERM) return -1;
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
    if !have_clang() {
        eprintln!("skipping: no clang with a BPF target");
        return;
    }
    let elf = compile(DECLARE).expect("the fixture compiles");
    let declared = synch_sock::declare(&elf, Arc::new(FakeTree::default())).expect("the hook ran");
    assert_eq!(declared.name, "git-http");
    assert_eq!(declared.egress, vec!["git.internal:9418".to_string()]);
    assert_eq!(declared.tree_reads, vec!["code".to_string()]);
    assert_eq!(declared.max_streams, Some(32));
}

#[tokio::test]
async fn a_declaration_helper_is_refused_outside_the_init_hook() {
    if !have_clang() {
        eprintln!("skipping: no clang with a BPF target");
        return;
    }
    let elf = compile(DECLARE).expect("the fixture compiles");
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
    if !have_clang() {
        eprintln!("skipping: no clang with a BPF target");
        return;
    }
    let elf = compile(
        r#"
        #include <synch.h>
        SY_INIT_ENTRY sy_s64 declare(void) { return 0; }
        "#,
    )
    .expect("the fixture compiles");
    let out = synch_sock::declare(&elf, Arc::new(FakeTree::default()));
    assert!(
        matches!(out, Err(synch_sock::SockError::NoEntrypoint)),
        "expected NoEntrypoint, got {out:?}"
    );
}
