//! The socket runtime: eBPF host APIs, the endpoint reactor, and the program
//! cache (`docs/SOCKETS.md`).
//!
//! A socket is a file in a node's published tree whose content is an eBPF ELF
//! object. This crate is the half that runs it: everything from an
//! [`Invocation`] arriving with a byte stream attached to the guest's return
//! value coming back. It knows nothing about iroh, SQLite, or the trie — the
//! network layer hands it a stream, and the engine hands it a [`SocketHost`]
//! for the tree reads it cannot do itself.
//!
//! # What is here on every platform, and what is not
//!
//! async-ebpf runs on Linux, macOS and OpenBSD, on x86-64 and arm64. This crate
//! builds everywhere: the ABI, the limits, the policy and the SDK header are
//! portable, and [`SUPPORTED`] says whether the runtime behind them exists.
//! What a node without it loses is *serving*: it can still activate, publish,
//! replicate and materialize socket entries, and `synch socket connect` works from
//! anywhere, because the connecting side executes nothing
//! (`docs/SOCKETS.md` §1).
//!
//! # The shape of an invocation
//!
//! Every helper except one is synchronous against host-side buffers.
//! `sy_poll` is the only helper that suspends, and the only caller of
//! async-ebpf's `post_task`. So a socket program is an ordinary event loop, and
//! the runtime has a single, auditable suspension point rather than a dozen.
//!
//! The guest loop is cooperative and the host loop is not: a program with no
//! `sy_poll` in it is still preempted, because async-ebpf's watcher signals the
//! thread rather than waiting to be asked.
#![deny(missing_docs)]

pub mod abi;
pub mod limits;
pub mod manifest;
pub mod policy;
pub mod registry;
pub mod sdk;
pub mod stream;

#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod runtime;

#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use runtime::{validate_program, SshHostKey, Worker, WorkerHandle};

use std::sync::Arc;

use synch_core::{Hash, NodeId, OriginId, SockStatus};

pub use limits::Limits;
pub use policy::{EffectivePolicy, PeerIdentity, SocketId};
pub use registry::{InvocationInfo, LogLine, Registry, SlotGuard};
pub use stream::DuplexStream;

/// Whether this build has an eBPF runtime, and can therefore *serve* sockets.
///
/// A node without one answers an inbound `Open` with
/// [`RefuseCode::Unsupported`](synch_core::RefuseCode::Unsupported), and
/// `synch socket activate` says so at activation time rather than at 3am.
pub const SUPPORTED: bool = cfg!(all(
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "openbsd"
    ),
    any(target_arch = "x86_64", target_arch = "aarch64")
));

/// What went wrong running a program.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SockError {
    /// The object does not load, link, or compile.
    #[error("the program does not load: {0}")]
    Load(String),
    /// The object has no `synchronicity.stream` section.
    #[error("the program has no `{}` entrypoint", abi::SECTION_STREAM)]
    NoEntrypoint,
    /// The program faulted and was contained.
    #[error("the program faulted: {0}")]
    Fault(String),
    /// This build has no runtime for this platform.
    #[error(
        "this build serves no sockets: async-ebpf supports Linux, macOS and OpenBSD on \
         x86-64 and arm64"
    )]
    Unsupported,
    /// The worker pool is gone, or was never started.
    #[error("the socket worker pool is not running")]
    NotRunning,
}

/// A verified read of this node's tree, for the `sy_open`/`sy_pread` family.
///
/// A trait rather than a dependency on `synch-engine`, so this crate stays
/// unaware of the trie, the CAS, and the fetcher. The engine implements it; the
/// tests implement it with a `HashMap`.
/// Three of the four calls are synchronous, and deliberately.
///
/// They are indexed reads of state this node already holds, and a socket worker
/// runs a **current-thread** runtime — which is exactly the case
/// [`blocking_is_allowed`](synch_core::blocking_is_allowed) permits blocking
/// work in. Making them async would buy nothing and would force `sy_open` into
/// the two-step `EAGAIN` shape `sy_pread` has, so every program would need a
/// state machine for a call that never waits.
///
/// `pread` is the one that can reach the network, and it is the one with the
/// two-step shape.
#[async_trait::async_trait]
pub trait SocketHost: Send + Sync + 'static {
    /// Resolves `space/path` in one origin's view.
    ///
    /// `origin` is `None` for this node's own view, which is the default and
    /// the default when the program names no foreign origin: it is the same
    /// scope the program itself came from.
    fn open(&self, origin: Option<&str>, path: &str) -> Result<ObjectInfo, HostError>;

    /// Metadata for a content root already known.
    fn open_root(&self, root: &Hash) -> Result<ObjectInfo, HostError>;

    /// One bounded page of entry names under `space/prefix` in this node's own
    /// view, ordered lexicographically and strictly after `start_after`.
    ///
    /// Returned names remain space-qualified. Implementations must return at
    /// most `limit` entries. The bounded storage API prevents protocol services
    /// from materializing an arbitrarily large tree before applying their own
    /// response and footprint limits.
    fn list_page(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<ListPage, HostError>;

    /// A verified read of `len` bytes at `offset`.
    ///
    /// May return fewer bytes than asked for at the end of the object. Bytes
    /// that must be fetched from a peer are fetched here, which is why this is
    /// async and why the helper that calls it returns `SY_EAGAIN` and makes the
    /// handle pollable rather than stalling the whole program.
    async fn pread(&self, root: Hash, offset: u64, len: u64) -> Result<Vec<u8>, HostError>;

    /// The semantic type of one resolved path, used by the SFTP backend to
    /// answer `STAT`/`READDIR` honestly without treating every path as a
    /// regular file.
    ///
    /// `origin` is `None` for this node's own view, as in [`SocketHost::open`].
    ///
    /// The default fails: a host without kind support cannot classify a path,
    /// and the SFTP caller skips the entry rather than fabricate attributes
    /// (fail-closed, never an invented directory).
    fn entry_kind(&self, origin: Option<&str>, path: &str) -> Result<HostEntryKind, HostError> {
        let _ = (origin, path);
        Err(HostError::Unavailable(
            "entry kinds are not supported by this host".into(),
        ))
    }

    /// Opens a writer that will publish `space/path` as this node's own new
    /// version (`docs/TREE-WRITES.md` §6).
    ///
    /// The runtime has already checked the manifest's tree-write grant — the
    /// prefix, the modes, the size bound — before this is reached; what the
    /// engine's implementation re-takes are its own durable gates: the
    /// declared-socket refusal, `.syncignore`, path normalization, recovery.
    /// `modes` carries the grant's `TREE_WRITE_*` bits so the create/replace
    /// condition can be evaluated at commit, against the tree as it is then.
    ///
    /// Synchronous for the reason `open` is — the checks are indexed reads of
    /// local state — and the default fails: a host without write support
    /// refuses rather than pretends.
    fn put_open(&self, path: &str, modes: u32) -> Result<Box<dyn SocketWriter>, HostError> {
        let _ = (path, modes);
        Err(HostError::Unavailable(
            "tree writes are not supported by this host".into(),
        ))
    }
}

/// One pending write into this node's own tree, behind a `sy_put_*` writer
/// handle (`docs/TREE-WRITES.md` §5).
///
/// Driven sequentially by the writer's pump task: chunks in order, then one
/// commit or delete. Dropping it without committing aborts the write — the
/// engine's staging cleanup is its `Drop`.
#[async_trait::async_trait]
pub trait SocketWriter: Send + 'static {
    /// Appends one chunk to the staged bytes.
    async fn write(&mut self, data: Vec<u8>) -> Result<(), HostError>;

    /// Reads bytes from the staged payload. Protocol adapters use this for a
    /// handle opened for both reading and writing, before the staged version
    /// is committed.
    async fn read_at(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, HostError> {
        let _ = (offset, len);
        Err(HostError::Unavailable(
            "random-access tree writes are not supported by this host".into(),
        ))
    }

    /// Writes bytes at an arbitrary offset in the staged payload.
    async fn write_at(&mut self, offset: u64, data: Vec<u8>) -> Result<(), HostError> {
        let _ = (offset, data);
        Err(HostError::Unavailable(
            "random-access tree writes are not supported by this host".into(),
        ))
    }

    /// Changes the staged payload's logical length, zero-filling growth.
    async fn set_len(&mut self, len: u64) -> Result<(), HostError> {
        let _ = len;
        Err(HostError::Unavailable(
            "resizing tree writes is not supported by this host".into(),
        ))
    }

    /// Publishes the staged bytes as this node's own new version of the path.
    ///
    /// The condition is evaluated at commit against this node's own live
    /// entry, under the engine's tree-write lock; a lost condition is
    /// [`HostError::Conflict`], and nothing is published.
    async fn commit(&mut self, expected: PutCondition) -> Result<PutReceipt, HostError>;

    /// Publishes this node's tombstone for the path instead of bytes.
    ///
    /// Idempotent like an S3 delete: a path this node already does not
    /// publish live succeeds.
    async fn delete(&mut self) -> Result<(), HostError>;

    /// Publishes a tombstone only if the path still has the expected state.
    ///
    /// Hosts that do not implement conditional deletion retain support for
    /// unconditional deletes, but fail closed for a condition they cannot
    /// enforce. Protocol adapters use this to avoid deleting a version that
    /// raced with a rename or remove operation.
    async fn delete_if(&mut self, expected: PutCondition) -> Result<(), HostError> {
        match expected {
            PutCondition::Any => self.delete().await,
            PutCondition::Absent | PutCondition::Root(_) => Err(HostError::Unavailable(
                "conditional tree deletes are not supported by this host".into(),
            )),
        }
    }
}

/// What a [`SocketWriter::commit`] requires of the path's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutCondition {
    /// Commit whatever is there: last write wins, like an S3 `PUT`.
    Any,
    /// This node must currently publish no live version of its own.
    Absent,
    /// This node's own live version must have exactly this content root.
    Root(Hash),
}

/// What a successful commit published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutReceipt {
    /// The BLAKE3 content root of the published version.
    pub root: Hash,
    /// Its size in bytes.
    pub size: u64,
}

/// One bounded storage page returned by [`SocketHost::list_page`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage {
    /// Live, space-qualified entry names encountered in this page.
    pub entries: Vec<String>,
    /// Cursor for the next page, or `None` when the prefix is exhausted.
    ///
    /// This can name a filtered entry such as a tombstone, so consumers must
    /// retain it separately from `entries`.
    pub next: Option<String>,
}

/// Why a [`SocketHost`] call failed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HostError {
    /// No such path, or no such root.
    #[error("no such path")]
    NotFound,
    /// The path resolves to something with no bytes — a directory, a tombstone,
    /// a symlink — or to a socket, which `sy_open` refuses on purpose.
    #[error("{0}")]
    NotReadable(String),
    /// The bytes could not be produced.
    #[error("{0}")]
    Unavailable(String),
    /// A write refused by the engine's own gates: an activated socket path, a
    /// mode the grant does not carry, an ignored path, a node in recovery.
    #[error("{0}")]
    Denied(String),
    /// A conditional commit lost: the tree moved underneath it.
    #[error("{0}")]
    Conflict(String),
    /// Staging or committing failed host-side: disk, CAS, the store.
    #[error("{0}")]
    Io(String),
}

/// The semantic type of a tree entry exposed through [`SocketHost`].
///
/// This deliberately is not a numeric SFTP or storage enum: hosts and the
/// SFTP adapter share a typed contract, so differing external discriminants
/// cannot silently turn a directory into a skipped or fabricated entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEntryKind {
    /// A regular immutable file.
    File,
    /// A directory, including an implicit prefix directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A deleted tree row.
    Tombstone,
    /// An executable socket entry.
    Socket,
}

/// What a program learns about an object it opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    /// The content root.
    pub root: Hash,
    /// Length in bytes.
    pub size: u64,
    /// The publishing origin's observed mtime.
    pub mtime_ns: i64,
    /// Advisory unix mode, or zero.
    pub mode: u32,
    /// The entry kind: 0 file, 1 dir, 2 symlink, 3 tombstone, 4 socket.
    /// `sy_stat` renders it as the corresponding name.
    pub kind: u32,
}

/// A resolved, authorized invocation that has not been given its stream yet.
///
/// The split exists because the two halves happen in different places. The
/// network layer resolves and authorizes an `Open` *before* it answers it —
/// the reply says which content root is about to run — and only then does the
/// stream it is holding become the guest's `SY_SELF`. Carrying an admission
/// between those two moments keeps the network layer from having to know what
/// an invocation is made of.
pub struct Admission {
    /// The ELF object to run — read from *this node's own* CAS.
    pub program: Arc<Vec<u8>>,
    /// Its content root: the snapshot this invocation runs, however the
    /// path's content moves underneath it.
    pub program_root: Hash,
    /// Which socket this is.
    pub socket: SocketId,
    /// Who is calling, as the handshake established it.
    pub peer: PeerIdentity,
    /// What this invocation may do.
    pub policy: EffectivePolicy,
    /// The caller's `--meta`. Untrusted.
    pub meta: Vec<(String, String)>,
    /// This node's own origin, for `sy_self_origin`.
    pub self_origin: OriginId,
    /// The tree, for the `sy_open` family.
    pub host: Arc<dyn SocketHost>,
    /// The invocation id, as `synch socket ps` prints it.
    pub id: u64,
    /// This invocation's place in the registry.
    ///
    /// `None` only where nothing is watching — a test harness. In the daemon
    /// it is taken at admission and held until the invocation ends, which is
    /// what makes the concurrency cap hold across the window between answering
    /// `Opened` and the first instruction running.
    pub slot: Option<SlotGuard>,
}

impl Admission {
    /// Attaches the stream the guest will see as `SY_SELF`.
    pub fn with_stream(self, stream: DuplexStream) -> Invocation {
        Invocation {
            program: self.program,
            program_root: self.program_root,
            socket: self.socket,
            peer: self.peer,
            policy: self.policy,
            meta: self.meta,
            stream,
            self_origin: self.self_origin,
            host: self.host,
            id: self.id,
            slot: self.slot,
        }
    }
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission")
            .field("id", &self.id)
            .field("socket", &self.socket)
            .field("program_root", &self.program_root)
            .field("peer", &self.peer.origin)
            .finish_non_exhaustive()
    }
}

/// One incoming stream, ready to become an invocation.
pub struct Invocation {
    /// The ELF object to run — read from *this node's own* CAS.
    pub program: Arc<Vec<u8>>,
    /// Its content root: the snapshot this invocation runs, however the
    /// path's content moves underneath it.
    pub program_root: Hash,
    /// Which socket this is.
    pub socket: SocketId,
    /// Who is calling, as the handshake established it.
    pub peer: PeerIdentity,
    /// What this invocation may do.
    pub policy: EffectivePolicy,
    /// The caller's `--meta`. Untrusted.
    pub meta: Vec<(String, String)>,
    /// The inbound byte stream, which the guest sees as `SY_SELF`.
    pub stream: DuplexStream,
    /// This node's own origin, for `sy_self_origin`.
    pub self_origin: OriginId,
    /// The tree, for the `sy_open` family.
    pub host: Arc<dyn SocketHost>,
    /// The invocation id, as `synch socket ps` prints it.
    pub id: u64,
    /// This invocation's place in the registry. See [`Admission::slot`].
    pub slot: Option<SlotGuard>,
}

impl std::fmt::Debug for Invocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invocation")
            .field("id", &self.id)
            .field("socket", &self.socket)
            .field("program_root", &self.program_root)
            .field("peer", &self.peer.origin)
            .finish_non_exhaustive()
    }
}

/// What an invocation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// How it ended, as the caller is told.
    pub status: SockStatus,
    /// Bytes the guest wrote to the caller-facing side: the inbound stream
    /// in raw mode, or SSH channel and lane cleartext after `sy_ssh_start`
    /// (`docs/SSH-SOCKETS.md` §8).
    pub bytes_out: u64,
    /// Bytes the guest read from the same side.
    pub bytes_in: u64,
    /// Counters the program bumped with `sy_metric_add`.
    pub metrics: Vec<(String, i64)>,
    /// Labels the program set with `sy_label_set`.
    pub labels: Vec<(String, String)>,
}

/// A device key rendered the way `sy_peer_device_key` hands it over.
pub(crate) fn device_key_bytes(id: &NodeId) -> [u8; 32] {
    *id.as_bytes()
}
