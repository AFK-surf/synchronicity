//! Reading the tree needs no declaration, and refuses nothing.
//!
//! This node's sockets read every path in every origin it holds, and every
//! blob in its CAS by content root, with no `tree-read` declaration and no
//! per-path check (`docs/SOCKETS.md` §7.6). Socket entries are readable too:
//! the bytes are not secret — any member fetches them out of the tree — and
//! what executes on this node is decided by the arming table, not by who can
//! read an ELF.
//!
//! This file was a probe asserting the opposite. It recorded that
//! `sy_open_root` reached the whole CAS while `sy_open_from` was gated on a
//! declaration and `sy_open` refused socket entries — a split that made the
//! gate decorative, since the same bytes came back by hash. The gate was
//! removed rather than extended, so the tests now pin the model that replaced
//! it: three ways to reach the same bytes, all of them allowed, none of them
//! declared.
//!
//! (a) An invocation with an empty policy, called by a delegate restricted to
//!     space `code`, reads `secrets/key.pem` both by foreign-origin path and
//!     by content hash.
//! (b) A neighbouring socket's ELF object is readable both by its `.sock` path
//!     and by content hash.

#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
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

  /* The same content by path from a foreign origin: allowed, and declared
   * nowhere. */
  sy_s64 of = sy_open_from(SY_STR("nas@cluster.example"), SY_STR("secrets/key.pem"));
  wr_all(SY_STR("OPEN_FROM="));
  wr_num(of);
  wr_all(SY_STR("\n"));

  /* And the same content by hash. */
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

  /* Opening the neighbour socket by path: allowed. */
  sy_s64 so = sy_open(SY_STR("code/neighbour.sock"));
  wr_all(SY_STR("OPEN_SOCK="));
  wr_num(so);
  wr_all(SY_STR("\n"));

  /* And the same socket's bytes by content hash. */
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

/// A host that mirrors the engine's `TreeHost`: a path open reports the
/// entry's real kind and refuses nothing that has content (`TreeHost::info`),
/// and `open_root` resolves any content in the store by hash alone, reporting
/// `kind: 0` (`TreeHost::open_root`).
struct KindAwareTree {
    /// path -> (entry kind as `ObjectInfo::kind`, content)
    files: std::collections::HashMap<String, (u32, Vec<u8>)>,
}

#[async_trait::async_trait]
impl SocketHost for KindAwareTree {
    fn open(&self, _origin: Option<&str>, path: &str) -> Result<ObjectInfo, HostError> {
        let (kind, bytes) = self.files.get(path).ok_or(HostError::NotFound)?;
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

    fn list_page(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<synch_sock::ListPage, HostError> {
        let mut names: Vec<String> = self
            .files
            .keys()
            .filter(|k| k.starts_with(prefix))
            .filter(|k| start_after.is_none_or(|after| k.as_str() > after))
            .cloned()
            .collect();
        names.sort();
        names.truncate(limit);
        let next = (names.len() == limit)
            .then(|| names.last().cloned())
            .flatten();
        Ok(synch_sock::ListPage {
            entries: names,
            next,
        })
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

/// (a) An empty policy and a delegate restricted to space `code` still read
/// `secrets/key.pem`, by foreign-origin path and by content hash alike.
#[tokio::test]
async fn a_foreign_path_and_a_content_root_are_both_readable_undeclared() {
    const SECRET: &str = "PRIVATE-KEY-MATERIAL: 0123456789abcdef do not exfiltrate";
    let root = Hash::new(SECRET.as_bytes());
    let elf = build_guest(POLICY_PROBE_C, &root, "policy-probe.c");

    let harness = Harness::with_tree(&[("secrets/key.pem", SECRET)]);
    let (status, out) = harness::exchange(
        &harness,
        &elf,
        b"",
        // Nothing declared: an empty policy grants every read there is.
        EffectivePolicy::default(),
        // And the caller is a delegate scoped to space `code`, which bounds
        // which sockets it may invoke, not what an invocation may read.
        peer(Some(vec!["code".into()])),
        vec![],
    )
    .await;

    let text = String::from_utf8_lossy(&out);
    eprintln!("status: {status:?}\nreply:\n{text}");

    // A foreign-origin path open needs no declaration.
    assert!(
        !text.contains("OPEN_FROM=-"),
        "sy_open_from must succeed without a declaration, got: {text}"
    );
    // So does the same content by hash.
    assert!(
        !text.contains("OPEN_ROOT=-"),
        "sy_open_root must return a handle, got: {text}"
    );
    assert!(
        out.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
        "the bytes must come back over the stream; reply: {text}"
    );
    assert_eq!(status, SockStatus::Ok(0));
}

/// (b) A neighbouring socket's ELF object is readable by path and by hash.
#[tokio::test]
async fn a_neighbouring_sockets_object_is_readable_by_path_and_by_hash() {
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

    // A socket entry is an ordinary readable path.
    assert!(
        !text.contains("OPEN_SOCK=-"),
        "sy_open of a socket path must succeed, got: {text}"
    );

    // And the same object comes back by hash. The whole object is dumped;
    // check the ELF header and the exact length.
    let start = out
        .windows(5)
        .position(|w| w == b"DATA:")
        .map(|i| i + 5)
        .expect("no DATA section in reply");
    let data = &out[start..out.len().min(start + neighbour.len())];
    assert!(
        data.starts_with(b"\x7fELF"),
        "the socket's ELF bytes must cross the stream; first bytes: {:?}",
        data.get(..16)
    );
    assert_eq!(
        data.len(),
        neighbour.len(),
        "the whole object must be readable by hash"
    );
    assert_eq!(status, SockStatus::Ok(0));
}
