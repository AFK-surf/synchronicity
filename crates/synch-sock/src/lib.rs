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
//! What a node without it loses is *serving*: it can still declare, publish,
//! replicate and materialize socket entries, and `synch connect` works from
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
pub use runtime::{declare, Worker, WorkerHandle};

use std::sync::Arc;

use synch_core::{Hash, NodeId, OriginId, SockStatus};

pub use limits::Limits;
pub use policy::{EffectivePolicy, PeerIdentity, SocketId};
pub use registry::{InvocationInfo, LiveStats, LogLine, Registry, SlotGuard};
pub use stream::DuplexStream;

/// Whether this build has an eBPF runtime, and can therefore *serve* sockets.
///
/// A node without one answers an inbound `Open` with
/// [`RefuseCode::Unsupported`](synch_core::RefuseCode::Unsupported), and
/// `synch socket add` says so at declaration time rather than at 3am.
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
    /// the only one a program gets without `--allow-tree-read`: it is the same
    /// scope the program itself came from.
    fn open(&self, origin: Option<&str>, path: &str) -> Result<ObjectInfo, HostError>;

    /// Metadata for a content root already known.
    fn open_root(&self, root: &Hash) -> Result<ObjectInfo, HostError>;

    /// Entry names under `space/prefix` in this node's own view.
    fn list(&self, prefix: &str) -> Result<Vec<String>, HostError>;

    /// A verified read of `len` bytes at `offset`.
    ///
    /// May return fewer bytes than asked for at the end of the object. Bytes
    /// that must be fetched from a peer are fetched here, which is why this is
    /// async and why the helper that calls it returns `SY_EAGAIN` and makes the
    /// handle pollable rather than stalling the whole program.
    async fn pread(&self, root: Hash, offset: u64, len: u64) -> Result<Vec<u8>, HostError>;
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
    /// The entry kind, as `SY_KIND_*`.
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
    /// Its content root, which is what was armed.
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
    /// Its content root, which is what was armed.
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
    /// Bytes the guest wrote to the inbound stream.
    pub bytes_out: u64,
    /// Bytes the guest read from it.
    pub bytes_in: u64,
    /// Counters the program bumped with `sy_metric_add`.
    pub metrics: Vec<(String, i64)>,
    /// Labels the program set with `sy_label_set`.
    pub labels: Vec<(String, String)>,
}

/// A device key rendered the way `sy_peer_device_key` hands it over.
pub fn device_key_bytes(id: &NodeId) -> [u8; 32] {
    *id.as_bytes()
}
