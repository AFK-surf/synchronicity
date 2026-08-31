//! What `invoke.rs` and `examples.rs` both need: a compiler, a fake tree, a
//! worker pool, and a way to talk to a program over an in-memory stream.
//!
//! Shared rather than copied because the two files test the same runtime from
//! two directions — one over fixtures written to provoke it, one over the
//! programs shipped in `examples/` — and a harness that had drifted between
//! them would make a disagreement between the two impossible to read.

// Each test binary uses a different part of this, and neither re-exports it.
#![allow(dead_code, unreachable_pub)]

use std::sync::Arc;

use synch_core::{Hash, NodeId, OriginId, SockStatus};
use synch_sock::{
    DuplexStream, EffectivePolicy, HostError, Invocation, Limits, ObjectInfo, PeerIdentity,
    SocketHost, SocketId, WorkerHandle,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The SDK header, as a program `#include`s it.
pub fn sdk() -> [(&'static str, &'static str); 1] {
    [("synch.h", synch_sock::sdk::HEADER)]
}

/// Compiles C to an eBPF object with the compiler built into the workspace.
///
/// Was clang, and skipped where clang had no BPF backend — which is every
/// stock macOS, so the runtime's own tests never ran on one of the three
/// platforms it claims. `synch-cc` is always here, so these never skip.
pub fn compile(source: &str, name: &str) -> Vec<u8> {
    compile_with(source, name, &[])
}

pub fn compile_with(source: &str, name: &str, defines: &[(&str, &str)]) -> Vec<u8> {
    synch_cc::compile(source, name, &sdk(), defines)
        .unwrap_or_else(|e| panic!("{name} does not compile:\n{e}"))
}

/// The same, through clang, or `None` where clang cannot target BPF.
///
/// Kept for the one thing `synch-cc` cannot say: that the runtime loads an
/// object some *other* compiler wrote. Optional on purpose — a machine without
/// the toolchain cannot answer that question, and a red test that means "no
/// compiler" teaches people to ignore red tests.
pub fn compile_with_clang(source: &str, name: &str) -> Option<Vec<u8>> {
    if !clang_targets_bpf() {
        eprintln!("skipping the clang half of {name}: no compatible clang/llc BPF toolchain");
        return None;
    }
    Some(
        synch_cc::compile_with_clang(source, name, &sdk(), &[])
            .unwrap_or_else(|e| panic!("{name} does not compile with clang:\n{e}")),
    )
}

/// Whether compatible clang and llc executables exist with the BPF backend.
///
/// Checked by compiling rather than by running `--version`: Apple's clang is
/// present on every macOS and cannot emit BPF, so "clang exists" answers the
/// wrong question.
fn clang_targets_bpf() -> bool {
    use std::sync::OnceLock;
    static ANSWER: OnceLock<bool> = OnceLock::new();
    *ANSWER.get_or_init(|| {
        synch_cc::compile_with_clang("int probe(void) { return 0; }\n", "probe.c", &[], &[]).is_ok()
    })
}

/// A tree with a couple of files in it.
#[derive(Default)]
pub struct FakeTree {
    pub files: std::collections::HashMap<String, Vec<u8>>,
    /// Paths that resolve to a refused row (a socket, symlink, or tombstone
    /// in the engine's tree): present in the listing (they are keys in
    /// `files`), but `open` refuses them and `entry_kind` refuses to
    /// classify them, so the SFTP backend skips them rather than fabricate
    /// attributes — and `put_open` refuses them the way the engine refuses
    /// a declared socket path.
    pub refused: std::collections::HashSet<String>,
    /// What tree writers committed, observable by tests — and the "live tree"
    /// a conditional commit is evaluated against, mirroring the engine's
    /// condition semantics over a flat map.
    pub written: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    /// Paths tree writers deleted, in order.
    pub deleted: Arc<std::sync::Mutex<Vec<String>>>,
    /// This many upcoming commits fail with `HostError::Io`, for exercising
    /// the runtime's sticky-failure handling.
    pub fail_commits: Arc<std::sync::Mutex<u32>>,
}

/// The [`FakeTree`] half of a `sy_put_*` writer: bytes accumulate in memory,
/// and a commit lands them in the shared `written` map under the engine's
/// condition semantics.
pub struct FakeWriter {
    path: String,
    modes: u32,
    staged: Vec<u8>,
    base: Option<Vec<u8>>,
    written: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    deleted: Arc<std::sync::Mutex<Vec<String>>>,
    fail_commits: Arc<std::sync::Mutex<u32>>,
}

#[async_trait::async_trait]
impl synch_sock::SocketWriter for FakeWriter {
    async fn write(&mut self, data: Vec<u8>) -> Result<(), HostError> {
        self.staged.extend_from_slice(&data);
        Ok(())
    }

    async fn read_at(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, HostError> {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.staged.len());
        let take = usize::try_from(len).unwrap_or(usize::MAX);
        let end = start.saturating_add(take).min(self.staged.len());
        Ok(self.staged[start..end].to_vec())
    }

    async fn write_at(&mut self, offset: u64, data: Vec<u8>) -> Result<(), HostError> {
        let start = usize::try_from(offset)
            .map_err(|_| HostError::Denied("write offset is too large".into()))?;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| HostError::Denied("write range is too large".into()))?;
        self.staged.resize(self.staged.len().max(end), 0);
        self.staged[start..end].copy_from_slice(&data);
        Ok(())
    }

    async fn set_len(&mut self, len: u64) -> Result<(), HostError> {
        let len = usize::try_from(len)
            .map_err(|_| HostError::Denied("staged length is too large".into()))?;
        self.staged.resize(len, 0);
        Ok(())
    }

    async fn set_metadata(
        &mut self,
        _unix_mode: Option<u32>,
        _mtime_ns: Option<i64>,
    ) -> Result<(), HostError> {
        Ok(())
    }

    async fn commit(
        &mut self,
        expected: synch_sock::PutCondition,
    ) -> Result<synch_sock::PutReceipt, HostError> {
        {
            let mut failures = self.fail_commits.lock().unwrap();
            if *failures > 0 {
                *failures -= 1;
                return Err(HostError::Io("injected commit failure".into()));
            }
        }
        // The engine's `evaluate_put_condition`, over the flat map: the
        // grant's modes gate what the commit does, and only then does a
        // stated expectation get compared — same order, same error classes.
        let mut written = self.written.lock().unwrap();
        let deleted = self.deleted.lock().unwrap();
        let current = written.get(&self.path).or_else(|| {
            if deleted.iter().any(|path| path == &self.path) {
                None
            } else {
                self.base.as_ref()
            }
        });
        let live = current.is_some();
        let create = self.modes & synch_core::TREE_WRITE_CREATE != 0;
        let replace = self.modes & synch_core::TREE_WRITE_REPLACE != 0;
        match expected {
            synch_sock::PutCondition::Any => {
                if live && !replace {
                    return Err(HostError::Denied(
                        "a live version exists and the grant cannot replace".into(),
                    ));
                }
                if !live && !create {
                    return Err(HostError::Denied(
                        "no live version exists and the grant cannot create".into(),
                    ));
                }
            }
            synch_sock::PutCondition::Absent => {
                if !create {
                    return Err(HostError::Denied("the grant carries no create mode".into()));
                }
                if live {
                    return Err(HostError::Conflict(
                        "the path now has a live version".into(),
                    ));
                }
            }
            synch_sock::PutCondition::Root(root) => {
                if !replace {
                    return Err(HostError::Denied(
                        "the grant carries no replace mode".into(),
                    ));
                }
                if current.map(|bytes| Hash::new(bytes)) != Some(root) {
                    return Err(HostError::Conflict(
                        "the path no longer has the expected version".into(),
                    ));
                }
            }
        }
        let bytes = std::mem::take(&mut self.staged);
        let receipt = synch_sock::PutReceipt {
            root: Hash::new(&bytes),
            size: bytes.len() as u64,
        };
        written.insert(self.path.clone(), bytes);
        drop(deleted);
        drop(written);
        self.deleted
            .lock()
            .unwrap()
            .retain(|path| path != &self.path);
        Ok(receipt)
    }

    async fn delete(&mut self) -> Result<(), HostError> {
        self.delete_if(synch_sock::PutCondition::Any).await
    }

    async fn delete_if(&mut self, expected: synch_sock::PutCondition) -> Result<(), HostError> {
        // Re-taken as the engine re-takes it, so the fake cannot green-light
        // a runtime that stopped checking.
        if self.modes & synch_core::TREE_WRITE_DELETE == 0 {
            return Err(HostError::Denied("the grant carries no delete mode".into()));
        }
        let mut written = self.written.lock().unwrap();
        let deleted = self.deleted.lock().unwrap();
        let current = written.get(&self.path).or_else(|| {
            if deleted.iter().any(|path| path == &self.path) {
                None
            } else {
                self.base.as_ref()
            }
        });
        let allowed = match expected {
            synch_sock::PutCondition::Any => true,
            synch_sock::PutCondition::Absent => current.is_none(),
            synch_sock::PutCondition::Root(root) => {
                current.is_some_and(|bytes| Hash::new(bytes) == root)
            }
        };
        if !allowed {
            return Err(HostError::Conflict(
                "the path no longer has the expected version".into(),
            ));
        }
        written.remove(&self.path);
        drop(deleted);
        drop(written);
        self.deleted.lock().unwrap().push(self.path.clone());
        Ok(())
    }
}

#[async_trait::async_trait]
impl SocketHost for FakeTree {
    fn open(&self, _origin: Option<&str>, path: &str) -> Result<ObjectInfo, HostError> {
        if self.refused.contains(path) {
            return Err(HostError::NotReadable("refused".into()));
        }
        let written = self.written.lock().unwrap();
        let bytes = if let Some(bytes) = written.get(path) {
            bytes
        } else {
            if self
                .deleted
                .lock()
                .unwrap()
                .iter()
                .any(|deleted| deleted == path)
            {
                return Err(HostError::NotFound);
            }
            self.files.get(path).ok_or(HostError::NotFound)?
        };
        Ok(ObjectInfo {
            root: Hash::new(bytes),
            size: bytes.len() as u64,
            mtime_ns: 42,
            mode: 0o644,
            kind: 0,
        })
    }

    fn open_root(&self, root: &Hash) -> Result<ObjectInfo, HostError> {
        let written = self.written.lock().unwrap();
        let bytes = written
            .values()
            .chain(self.files.values())
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

    fn list_page(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<synch_sock::ListPage, HostError> {
        let written = self.written.lock().unwrap();
        let deleted = self.deleted.lock().unwrap();
        let mut names: Vec<String> = self
            .files
            .keys()
            .chain(written.keys())
            .filter(|key| !deleted.iter().any(|deleted| deleted == *key))
            .filter(|k| k.starts_with(prefix))
            .filter(|k| start_after.is_none_or(|after| k.as_str() > after))
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        names.truncate(limit);
        let next = (names.len() == limit)
            .then(|| names.last().cloned())
            .flatten();
        Ok(synch_sock::ListPage {
            entries: names,
            next,
        })
    }

    fn entry_kind(
        &self,
        _origin: Option<&str>,
        path: &str,
    ) -> Result<synch_sock::HostEntryKind, HostError> {
        // The engine contract, over a flat `files` map: a row's kind comes
        // from the row (every row here is a regular file), a directory that
        // has no row but has descendants is a directory, and a refused row
        // (socket, symlink, tombstone) is refused here too, so the SFTP
        // backend skips it rather than invent attributes.
        if self.refused.contains(path) {
            return Err(HostError::NotReadable("refused".into()));
        }
        let written = self.written.lock().unwrap();
        let deleted = self.deleted.lock().unwrap();
        let live = |key: &str| {
            written.contains_key(key)
                || (self.files.contains_key(key) && !deleted.iter().any(|deleted| deleted == key))
        };
        if live(path) {
            return Ok(synch_sock::HostEntryKind::File);
        }
        if self.files.keys().chain(written.keys()).any(|key| {
            if !live(key) {
                return false;
            }
            key.len() > path.len() && key.starts_with(path) && key.as_bytes()[path.len()] == b'/'
        }) {
            return Ok(synch_sock::HostEntryKind::Directory);
        }
        Err(HostError::NotFound)
    }

    async fn pread(&self, root: Hash, offset: u64, len: u64) -> Result<Vec<u8>, HostError> {
        let written = self.written.lock().unwrap();
        let bytes = written
            .values()
            .chain(self.files.values())
            .find(|b| Hash::new(b) == root)
            .ok_or(HostError::NotFound)?;
        let start = (offset as usize).min(bytes.len());
        let end = (start + len as usize).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }

    fn put_open(
        &self,
        path: &str,
        modes: u32,
    ) -> Result<Box<dyn synch_sock::SocketWriter>, HostError> {
        // The engine's declared-socket refusal, over the same `refused` set
        // the read side uses.
        if self.refused.contains(path) {
            return Err(HostError::Denied(format!("{path} is a declared socket")));
        }
        Ok(Box::new(FakeWriter {
            path: path.to_string(),
            modes,
            staged: Vec::new(),
            base: self.files.get(path).cloned(),
            written: self.written.clone(),
            deleted: self.deleted.clone(),
            fail_commits: self.fail_commits.clone(),
        }))
    }
}

pub fn peer(spaces: Option<Vec<String>>) -> PeerIdentity {
    PeerIdentity {
        origin: OriginId::named("laptop", "cluster.example").unwrap(),
        device_key: NodeId::from_bytes(&synch_sock::policy::NOBODY).unwrap(),
        spaces,
        addr: "198.51.100.7:44321".into(),
        stream_index: 0,
    }
}

pub struct Harness {
    pub pool: WorkerHandle,
    pub tree: Arc<FakeTree>,
}

impl Harness {
    pub fn new() -> Harness {
        Harness {
            pool: WorkerHandle::start(1, Limits::default()),
            tree: Arc::new(FakeTree::default()),
        }
    }

    /// An invocation that takes a real registry slot, as the daemon's does.
    pub fn admitted(
        &self,
        elf: &[u8],
        stream: DuplexStream,
        registry: &Arc<synch_sock::Registry>,
        max_streams: usize,
    ) -> Option<Invocation> {
        let id = self.pool.next_id();
        let slot = registry.reserve(
            id,
            "code/test.sock",
            "laptop@cluster.example",
            NodeId::from_bytes(&synch_sock::policy::NOBODY).unwrap(),
            Hash::new(elf),
            max_streams,
            std::time::Instant::now(),
        )?;
        let mut invocation =
            self.invocation(elf, stream, EffectivePolicy::default(), peer(None), vec![]);
        invocation.id = id;
        invocation.slot = Some(slot);
        Some(invocation)
    }

    pub fn with_limits(limits: Limits) -> Harness {
        Harness {
            pool: WorkerHandle::start(1, limits),
            tree: Arc::new(FakeTree::default()),
        }
    }

    pub fn with_tree(files: &[(&str, &str)]) -> Harness {
        Harness::with_tree_and_limits(files, Limits::default())
    }

    /// A tree whose listed rows also include `refused` paths the host will
    /// not open or classify (sockets, symlinks, tombstones).
    pub fn with_tree_and_refused(files: &[(&str, &str)], refused: &[&str]) -> Harness {
        let mut tree = FakeTree::default();
        for (name, body) in files {
            tree.files
                .insert(name.to_string(), body.as_bytes().to_vec());
        }
        for path in refused {
            tree.refused.insert(path.to_string());
        }
        Harness {
            pool: WorkerHandle::start(1, Limits::default()),
            tree: Arc::new(tree),
        }
    }

    pub fn with_tree_and_limits(files: &[(&str, &str)], limits: Limits) -> Harness {
        let mut tree = FakeTree::default();
        for (name, body) in files {
            tree.files
                .insert(name.to_string(), body.as_bytes().to_vec());
        }
        Harness {
            pool: WorkerHandle::start(1, limits),
            tree: Arc::new(tree),
        }
    }

    pub fn invocation(
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
            slot: None,
        }
    }
}

/// Runs a program against an in-memory stream, returning what it wrote back.
///
/// The caller sends everything, then half-closes, then reads to the end — the
/// shape of a request/response exchange. A program that must interleave the
/// two wants [`converse`] instead, which is a different question and would
/// deadlock here.
pub async fn exchange(
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
        // A broken pipe here is a program that finished before the caller had
        // stopped talking, which is a normal end and several of these examples
        // do it on purpose: a proxy whose upstream closed, a gate that refused,
        // a path validator that read one line and said no. The invocation and
        // this side run concurrently, so which of them gets there first is a
        // race, and treating the loss of that race as a test failure is how a
        // suite gets a flake in it. What was actually asked for is asserted on
        // the *reply*, below.
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

/// The same, but reading while writing, over a deliberately small pipe.
///
/// The only way to see backpressure: `exchange` writes everything before it
/// reads anything, so the program's tx window never fills and a short write
/// never happens. Here both halves run at once and the window is small enough
/// to matter, which is what makes a dropped remainder visible as missing bytes
/// rather than as nothing at all.
pub async fn converse(
    harness: &Harness,
    elf: &[u8],
    input: Vec<u8>,
    window: usize,
) -> (SockStatus, Vec<u8>) {
    let (mine, theirs) = tokio::io::duplex(window);
    let (their_r, their_w) = tokio::io::split(theirs);
    let invocation = harness.invocation(
        elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );

    let (mut reader, mut writer) = tokio::io::split(mine);
    let sending = tokio::spawn(async move {
        // Tolerated for the same reason as in `exchange`, and it costs nothing
        // here either: a caller that could not send all of it gets less back,
        // and less back is what the payload comparison is looking for.
        let _ = writer.write_all(&input).await;
        let _ = writer.shutdown().await;
    });
    let receiving = tokio::spawn(async move {
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        out
    });

    let outcome = harness.pool.run(invocation).await.expect("the program ran");
    sending.await.unwrap();
    let out = receiving.await.unwrap();
    (outcome.status, out)
}
