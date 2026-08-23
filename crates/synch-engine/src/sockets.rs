//! Sockets, from the engine's side (`docs/SOCKETS.md`).
//!
//! Three things live here, and they are deliberately separate.
//!
//! **Resolution** answers "what would run, if anything?" — a lookup in *this
//! node's own* trie, a kind check, and an arming check against the content root
//! the tree currently names. It is the whole of the rule the design is built
//! on, and it never consults the unified tree: connecting to a socket names an
//! origin, and `newest` would otherwise let any member's `mtime_ns` decide
//! whose program a connection lands on.
//!
//! **Admission** turns that into an invocation: it adds the caller's identity
//! as the handshake established it, and the intersection of what the program
//! declared with what the operator armed.
//!
//! **The tree host** is what the running program reads through. It is the one
//! place a socket touches the rest of the node, and it is read-only.

use std::sync::Arc;

use synch_core::{
    Declaration, EntryKind, Hash, NodeId, OriginId, RefuseCode, SockOpen, SockStatus,
};
use synch_sock::{
    Admission, DuplexStream, EffectivePolicy, HostError, Limits, ObjectInfo, PeerIdentity,
    SocketHost, SocketId,
};
use synch_store::{SocketRow, SocketState};

use crate::{
    error::{EngineError, Result},
    node::Node,
};

/// What a socket path resolves to right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The content root the tree currently names.
    pub root: Hash,
    /// Its size in bytes.
    pub size: u64,
    /// The declaration and its arming record.
    pub state: SocketState,
}

impl Node {
    /// Declares a path in one of this node's spaces to be a socket.
    ///
    /// Does not arm it: what the file contains at declaration time may not be
    /// what the operator meant to approve, and `synch socket arm` is where the
    /// approval happens after the declaration is printed.
    pub fn socket_add(&self, row: &SocketRow) -> Result<()> {
        if self.store().space(&row.space)?.is_none() {
            return Err(EngineError::invalid(format!(
                "`{}` is not a space this node indexes",
                row.space
            )));
        }
        synch_core::normalize_path(&row.path).map_err(|e| EngineError::invalid(e.to_string()))?;
        self.store().put_socket(row)?;
        Ok(())
    }

    /// Every socket this node declares.
    pub fn socket_ls(&self, space: Option<&str>) -> Result<Vec<SocketState>> {
        Ok(match space {
            Some(space) => self.store().sockets_in(space)?,
            None => self.store().sockets()?,
        })
    }

    /// Runs the program's declaration hook and approves the current root.
    ///
    /// The dry run is not a formality. async-ebpf compiles lazily, per function
    /// and per pointer signature, so a program that fails to compile would
    /// otherwise surface that on the first stream that reaches the bad path —
    /// a long way from the operator who armed it.
    pub async fn socket_arm(&self, space: &str, path: &str) -> Result<(Hash, Declaration)> {
        let resolved = self.resolve_socket(space, path)?.ok_or_else(|| {
            EngineError::invalid(format!(
                "`{space}/{path}` is declared a socket but this node publishes no entry for it \
                 — run `synch scan` first"
            ))
        })?;
        let elf = self.socket_program(&resolved).await?;
        let declared = self.declare_program(&elf)?;
        self.store().arm_socket(
            space,
            path,
            &resolved.root,
            &declared.render(),
            synch_core::now_ns(),
        )?;
        // A re-arm is a different program; a session table minted by the old
        // one is not state the new one agreed to inherit.
        self.clear_socket_map(&format!("{space}/{path}"));
        Ok((resolved.root, declared))
    }

    /// Withdraws an approval, leaving the declaration standing.
    pub fn socket_disarm(&self, space: &str, path: &str) -> Result<bool> {
        let out = self.store().disarm_socket(space, path)?;
        self.clear_socket_map(&format!("{space}/{path}"));
        Ok(out)
    }

    /// Removes a declaration and its approval.
    ///
    /// The next scan republishes the path as an ordinary file, because the kind
    /// comes from the declaration and there is no longer one.
    pub fn socket_rm(&self, space: &str, path: &str) -> Result<bool> {
        let out = self.store().remove_socket(space, path)?;
        self.clear_socket_map(&format!("{space}/{path}"));
        Ok(out)
    }

    /// Resolves a socket path in **this node's own** trie.
    ///
    /// `Ok(None)` means this node publishes no entry there, or publishes one
    /// that is not a socket. The distinction between those two is drawn by the
    /// caller, which has a refusal code for each.
    pub fn resolve_socket(&self, space: &str, path: &str) -> Result<Option<Resolved>> {
        let Some(state) = self.store().socket(space, path)? else {
            return Ok(None);
        };
        let Some(entry) = self.store().entry(self.origin(), space, path)? else {
            return Ok(None);
        };
        if entry.kind != EntryKind::Socket {
            return Ok(None);
        }
        let Some(root) = entry.content else {
            return Ok(None);
        };
        Ok(Some(Resolved {
            root,
            size: entry.size,
            state,
        }))
    }

    /// Reads a socket's ELF object out of this node's own CAS.
    async fn socket_program(&self, resolved: &Resolved) -> Result<Vec<u8>> {
        let limits = self.socket_limits();
        if resolved.size > limits.max_program_bytes {
            return Err(EngineError::invalid(format!(
                "the program is {} bytes, past the {} a socket may be",
                resolved.size, limits.max_program_bytes
            )));
        }
        // Its own CAS: the bytes were published by this node, so they are held
        // here. `ensure_cached` covers the one case where they are not — a
        // cloud-backed node whose scratch cache has been replaced.
        self.ensure_blob_cached(&resolved.root, resolved.size)
            .await?;
        Ok(self
            .cas_backend()
            .read_range(resolved.root, 0, resolved.size)
            .await?)
    }

    /// Builds the policy one invocation runs under.
    fn socket_policy(&self, state: &SocketState) -> EffectivePolicy {
        let declared = state
            .arm
            .as_ref()
            .map(|arm| Declaration::parse(&arm.declared))
            .unwrap_or_default();
        EffectivePolicy::intersect(
            &declared,
            &state.declaration.allow_egress,
            &state.declaration.allow_tree_read,
            state.declaration.config.clone(),
            state.declaration.max_streams,
            self.socket_limits().max_streams,
        )
    }

    /// Resolves and authorizes an `Open`.
    ///
    /// Every refusal here is a distinct code, because the caller can act on the
    /// difference: `NotArmed` is the operator's to fix, `SpaceNotDelegated` is
    /// the caller's, and `NoSuchPath` means look again.
    pub async fn admit_socket(
        &self,
        peer: NodeId,
        addr: String,
        stream_index: u64,
        open: &SockOpen,
    ) -> std::result::Result<Admission, (RefuseCode, String)> {
        if !synch_sock::SUPPORTED {
            return Err((
                RefuseCode::Unsupported,
                "this node has no eBPF runtime: async-ebpf supports Linux and OpenBSD on \
                 x86-64 and arm64"
                    .into(),
            ));
        }
        // The `Open` names the origin it is addressed to, so a frame relayed or
        // replayed at another node is undeliverable rather than redirected.
        if open.origin != *self.origin() {
            return Err((
                RefuseCode::NoSuchPath,
                format!(
                    "this node is {}, not {}",
                    self.origin().canonical(),
                    open.origin.canonical()
                ),
            ));
        }

        let scope = self
            .store()
            .socket_scope_for_key(&peer, synch_core::now_ns())
            .map_err(|e| (RefuseCode::Unauthorized, e.to_string()))?;
        let Some((origin, scope)) = scope else {
            return Err((
                RefuseCode::Unauthorized,
                "no live binding for that device key".into(),
            ));
        };
        if let Some(spaces) = &scope {
            if !spaces.contains(&open.space) {
                return Err((
                    RefuseCode::SpaceNotDelegated,
                    format!("`{}` is not one of your delegated spaces", open.space),
                ));
            }
        }

        let resolved = match self.resolve_socket(&open.space, &open.path) {
            Ok(Some(resolved)) => resolved,
            Ok(None) => {
                // Told apart so the caller learns something: a path this node
                // publishes as an ordinary file is a different mistake from a
                // path it publishes nothing for.
                let code = match self.store().entry(self.origin(), &open.space, &open.path) {
                    Ok(Some(_)) => RefuseCode::NotASocket,
                    _ => RefuseCode::NoSuchPath,
                };
                return Err((code, format!("{}/{}", open.space, open.path)));
            }
            Err(e) => return Err((RefuseCode::NoSuchPath, e.to_string())),
        };

        if !resolved.state.is_armed_for(&resolved.root) {
            let message = match &resolved.state.arm {
                Some(arm) => format!(
                    "armed at {}, the tree now names {}",
                    arm.root.to_hex(),
                    resolved.root.to_hex()
                ),
                None => "declared but never armed".into(),
            };
            return Err((RefuseCode::NotArmed, message));
        }

        let program = match self.socket_program(&resolved).await {
            Ok(bytes) => bytes,
            Err(e) => return Err((RefuseCode::ProgramInvalid, e.to_string())),
        };

        let policy = self.socket_policy(&resolved.state);

        Ok(Admission {
            program: Arc::new(program),
            program_root: resolved.root,
            socket: SocketId::new(&open.space, &open.path),
            peer: PeerIdentity {
                origin,
                device_key: peer,
                spaces: scope,
                addr,
                stream_index,
            },
            policy,
            meta: open.meta.clone(),
            self_origin: self.origin().clone(),
            host: Arc::new(TreeHost {
                node: self.clone(),
                own_origin: self.origin().clone(),
            }),
            id: self.next_socket_id(),
        })
    }

    /// Runs an admitted invocation.
    pub async fn run_socket(&self, admission: Admission, stream: DuplexStream) -> SockStatus {
        match self.socket_workers() {
            Some(pool) => match pool.run(admission.with_stream(stream)).await {
                Ok(outcome) => outcome.status,
                Err(e) => {
                    tracing::warn!("socket invocation failed: {e}");
                    SockStatus::Fault(synch_core::FaultKind::Load)
                }
            },
            None => SockStatus::Shutdown,
        }
    }
}

/// The tree, as a running program reads it.
///
/// Read-only, and scoped by default to this node's own view — the same scope
/// the program itself came from. Writing is deliberately absent: publishing is
/// the scanner's job, and a remotely-triggered publish path is a much larger
/// surface than a remotely-triggered read one.
#[derive(Debug)]
struct TreeHost {
    node: Node,
    own_origin: OriginId,
}

impl TreeHost {
    /// Splits `space/path`.
    fn split(path: &str) -> std::result::Result<(&str, &str), HostError> {
        path.split_once('/')
            .filter(|(space, rest)| !space.is_empty() && !rest.is_empty())
            .ok_or_else(|| HostError::NotReadable("a path is `<space>/<path>`".into()))
    }

    fn info(entry: &synch_store::EntryRow) -> std::result::Result<ObjectInfo, HostError> {
        // A socket refuses to open a socket. Not because the bytes are secret —
        // every member reads them out of the tree — but because a program that
        // can read its neighbours' code can also serve it, and "what executes
        // here?" should have one answer that lives in the arming table.
        if entry.kind == EntryKind::Socket {
            return Err(HostError::NotReadable(
                "that path is a socket; a socket does not read out its neighbours' code".into(),
            ));
        }
        let root = entry
            .content
            .ok_or_else(|| HostError::NotReadable("that path has no content".into()))?;
        Ok(ObjectInfo {
            root,
            size: entry.size,
            mtime_ns: entry.mtime_ns,
            mode: entry.unix_mode.unwrap_or(0),
            kind: match entry.kind {
                EntryKind::File => 0,
                EntryKind::Dir => 1,
                EntryKind::Symlink => 2,
                EntryKind::Tombstone => 3,
                EntryKind::Socket => 4,
            },
        })
    }
}

#[async_trait::async_trait]
impl SocketHost for TreeHost {
    fn open(&self, origin: Option<&str>, path: &str) -> std::result::Result<ObjectInfo, HostError> {
        let (space, rest) = TreeHost::split(path)?;
        let origin = match origin {
            None => self.own_origin.clone(),
            Some(text) => text
                .parse::<OriginId>()
                .map_err(|e| HostError::NotReadable(e.to_string()))?,
        };
        let entry = self
            .node
            .store()
            .entry(&origin, space, rest)
            .map_err(|e| HostError::Unavailable(e.to_string()))?
            .ok_or(HostError::NotFound)?;
        TreeHost::info(&entry)
    }

    fn open_root(&self, root: &Hash) -> std::result::Result<ObjectInfo, HostError> {
        let size = self
            .node
            .store()
            .blob(root)
            .map_err(|e| HostError::Unavailable(e.to_string()))?
            .ok_or(HostError::NotFound)?
            .size;
        Ok(ObjectInfo {
            root: *root,
            size,
            mtime_ns: 0,
            mode: 0,
            kind: 0,
        })
    }

    fn list(&self, prefix: &str) -> std::result::Result<Vec<String>, HostError> {
        let (space, rest) = match prefix.split_once('/') {
            Some((space, rest)) => (space, rest),
            None => (prefix, ""),
        };
        let rows = self
            .node
            .store()
            .list_entries(Some(&self.own_origin), space, rest, None, Some(4096))
            .map_err(|e| HostError::Unavailable(e.to_string()))?;
        Ok(rows
            .into_iter()
            .filter(|row| row.kind != EntryKind::Tombstone)
            .map(|row| row.path)
            .collect())
    }

    async fn pread(
        &self,
        root: Hash,
        offset: u64,
        len: u64,
    ) -> std::result::Result<Vec<u8>, HostError> {
        let size = self
            .node
            .store()
            .blob(&root)
            .map_err(|e| HostError::Unavailable(e.to_string()))?
            .ok_or(HostError::NotFound)?
            .size;
        if offset >= size {
            return Ok(Vec::new());
        }
        let end = (offset + len).min(size);
        // Fetches whatever is missing, verified per 16 KiB group like every
        // other read. This is the call that can wait on the network, which is
        // why the helper in front of it returns `SY_EAGAIN` and makes the
        // handle pollable rather than stalling the program.
        self.node
            .fetch_range(&root, size, offset, end)
            .await
            .map_err(|e| HostError::Unavailable(e.to_string()))?;
        self.node
            .cas_backend()
            .read_range(root, offset, end - offset)
            .await
            .map_err(|e| HostError::Unavailable(e.to_string()))
    }
}

/// The engine's implementation of the network layer's service.
///
/// Filled in after the node exists, because the endpoint is bound *by* the
/// node's constructor and the ALPN has to be mounted on it: the handler
/// therefore has to exist before the thing it dispatches to. A `OnceLock`
/// rather than a lock, because this is written once during startup and read on
/// every connection thereafter.
#[derive(Debug, Clone, Default)]
pub struct SocketDispatch {
    node: Arc<std::sync::OnceLock<crate::node::WeakNode>>,
}

impl SocketDispatch {
    /// An unbound dispatcher, ready to be mounted.
    pub fn new() -> Self {
        SocketDispatch::default()
    }

    /// Binds it to the node it serves. Called once, at the end of startup.
    pub fn bind(&self, node: &Node) {
        let _ = self.node.set(node.downgrade());
    }

    /// The node, while it is open.
    fn node(&self) -> Option<Node> {
        self.node.get().and_then(|weak| weak.upgrade())
    }
}

#[async_trait::async_trait]
impl synch_net::sock::SocketService for SocketDispatch {
    async fn admit(
        &self,
        peer: NodeId,
        addr: String,
        stream_index: u64,
        open: &SockOpen,
    ) -> std::result::Result<Admission, (RefuseCode, String)> {
        // The window between the endpoint accepting connections and the node
        // finishing startup is real, if short. `Busy` rather than a harder
        // code because it is exactly what it says: try again.
        let Some(node) = self.node() else {
            return Err((RefuseCode::Busy, "this node is still starting".into()));
        };
        node.admit_socket(peer, addr, stream_index, open).await
    }

    async fn run(&self, admission: Admission, stream: DuplexStream) -> SockStatus {
        match self.node() {
            // A node that has gone away between admission and here is a node
            // shutting down, which is exactly what the caller should be told.
            Some(node) => node.run_socket(admission, stream).await,
            None => SockStatus::Shutdown,
        }
    }
}

/// The limits every socket on this node runs under.
pub fn default_limits() -> Limits {
    Limits::default()
}

/// The worker pool, where there is one.
///
/// Two implementations of the same small API rather than `cfg` at every call
/// site: async-ebpf exists on Linux and OpenBSD on x86-64 and arm64 and
/// nowhere else, and the engine has to build everywhere. What a node without
/// it loses is serving — declaring, publishing, replicating and materializing
/// socket entries all work, and so does `synch connect`, because the
/// connecting side executes nothing.
#[cfg(all(
    any(target_os = "linux", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod pool {
    use super::*;

    /// A started pool.
    #[derive(Debug, Clone)]
    pub struct SocketPool(synch_sock::WorkerHandle);

    impl SocketPool {
        /// Starts `workers` threads.
        pub fn start(workers: usize, limits: Limits) -> Option<SocketPool> {
            Some(SocketPool(synch_sock::WorkerHandle::start(workers, limits)))
        }

        /// The limits every invocation runs under.
        pub fn limits(&self) -> Limits {
            self.0.limits().clone()
        }

        /// The next invocation id.
        pub fn next_id(&self) -> u64 {
            self.0.next_id()
        }

        /// Drops what one socket's map held.
        pub fn clear_map(&self, socket: &str) {
            self.0.clear_map(socket);
        }

        /// Runs one invocation.
        pub async fn run(
            &self,
            invocation: synch_sock::Invocation,
        ) -> std::result::Result<synch_sock::Outcome, synch_sock::SockError> {
            self.0.run(invocation).await
        }
    }

    /// Runs a program's declaration hook.
    pub(super) fn declare(
        elf: &[u8],
        host: Arc<dyn SocketHost>,
    ) -> std::result::Result<Declaration, synch_sock::SockError> {
        synch_sock::declare(elf, host)
    }
}

#[cfg(not(all(
    any(target_os = "linux", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod pool {
    use super::*;

    /// A pool that does not exist on this platform.
    #[derive(Debug, Clone)]
    pub struct SocketPool;

    impl SocketPool {
        /// Never starts: there is no runtime to start.
        pub fn start(_workers: usize, _limits: Limits) -> Option<SocketPool> {
            None
        }

        /// The documented defaults, so `synch socket ls` prints the same
        /// numbers everywhere even where nothing can run.
        pub fn limits(&self) -> Limits {
            Limits::default()
        }

        /// Unreachable: nothing admits an invocation without a pool.
        pub fn next_id(&self) -> u64 {
            0
        }

        /// Nothing to clear.
        pub fn clear_map(&self, _socket: &str) {}

        /// Unreachable: nothing admits an invocation without a pool.
        pub async fn run(
            &self,
            _invocation: synch_sock::Invocation,
        ) -> std::result::Result<synch_sock::Outcome, synch_sock::SockError> {
            Err(synch_sock::SockError::Unsupported)
        }
    }

    /// Refuses: a declaration is what a program says, and nothing here can ask.
    pub(super) fn declare(
        _elf: &[u8],
        _host: Arc<dyn SocketHost>,
    ) -> std::result::Result<Declaration, synch_sock::SockError> {
        Err(synch_sock::SockError::Unsupported)
    }
}

pub use pool::SocketPool;

/// A tree the declaration hook cannot read.
///
/// The init hook runs with no endpoint table and, deliberately, no tree: it is
/// asked what the program *intends*, and a hook that could read files could
/// make its answer depend on them — so what an operator approved would stop
/// being a property of the bytes they approved.
#[derive(Debug)]
pub(crate) struct NoTree;

#[async_trait::async_trait]
impl SocketHost for NoTree {
    fn open(
        &self,
        _origin: Option<&str>,
        _path: &str,
    ) -> std::result::Result<ObjectInfo, HostError> {
        Err(HostError::NotReadable(
            "the declaration hook reads no tree".into(),
        ))
    }

    fn open_root(&self, _root: &Hash) -> std::result::Result<ObjectInfo, HostError> {
        Err(HostError::NotReadable(
            "the declaration hook reads no tree".into(),
        ))
    }

    fn list(&self, _prefix: &str) -> std::result::Result<Vec<String>, HostError> {
        Err(HostError::NotReadable(
            "the declaration hook reads no tree".into(),
        ))
    }

    async fn pread(
        &self,
        _root: Hash,
        _offset: u64,
        _len: u64,
    ) -> std::result::Result<Vec<u8>, HostError> {
        Err(HostError::NotReadable(
            "the declaration hook reads no tree".into(),
        ))
    }
}

/// Runs a declaration hook on a thread that is allowed to block.
pub(crate) fn declare_blocking(elf: &[u8], host: Arc<dyn SocketHost>) -> Result<Declaration> {
    let _scope = synch_core::BlockingScope::enter();
    pool::declare(elf, host).map_err(|e| EngineError::invalid(e.to_string()))
}

impl Node {
    /// Keeps a socket's arming record in step with the bytes the scanner just
    /// published (`docs/SOCKETS.md` §3).
    ///
    /// Two cases, and the difference between them is the whole of `--auto`.
    ///
    /// Without it, nothing happens here: the declaration stands, the old
    /// arming record stands, and the mismatch between the armed root and the
    /// published one is what makes the next connection `Refused{NotArmed}`.
    /// The socket keeps being published and stops being runnable, which is the
    /// intended shape — the operator approved bytes, and these are not those
    /// bytes.
    ///
    /// With it, the declaration follows the file: the new root is armed with
    /// whatever the new program declares. That is correct for a path you are
    /// the only writer of and wrong for any path an S3 key, a fill or a take
    /// can reach, which is why `synch doctor` lists every `--auto` socket.
    pub(crate) fn follow_socket_content(&self, space: &str, path: &str, root: &Hash) -> Result<()> {
        let Some(state) = self.store().socket(space, path)? else {
            return Ok(());
        };
        if state.is_armed_for(root) {
            return Ok(());
        }
        if !state.declaration.auto {
            if state.arm.is_some() {
                tracing::warn!(
                    socket = format!("{space}/{path}"),
                    "socket content changed; it is published but disarmed until \
                     `synch socket arm` approves the new program"
                );
            }
            return Ok(());
        }
        // `--auto` re-arms without asking, but it still re-reads what the new
        // program declares: following the file means following what the file
        // says about itself, not carrying the old program's declaration onto
        // new bytes.
        let elf = match self.read_socket_bytes(root) {
            Ok(elf) => elf,
            Err(e) => {
                tracing::warn!(socket = format!("{space}/{path}"), "auto-arm skipped: {e}");
                return Ok(());
            }
        };
        match self.declare_program(&elf) {
            Ok(declared) => {
                self.store().arm_socket(
                    space,
                    path,
                    root,
                    &declared.render(),
                    synch_core::now_ns(),
                )?;
                self.clear_socket_map(&format!("{space}/{path}"));
                tracing::info!(
                    socket = format!("{space}/{path}"),
                    root = %root,
                    "auto-armed"
                );
            }
            Err(e) => {
                // A program that does not load is left disarmed rather than
                // armed-and-broken: the next connection gets `NotArmed`, which
                // is true, instead of `ProgramInvalid` on every stream.
                tracing::warn!(
                    socket = format!("{space}/{path}"),
                    "auto-arm refused: the program does not load: {e}"
                );
            }
        }
        Ok(())
    }

    /// Reads an object out of the local CAS synchronously.
    ///
    /// The scanner already runs off the runtime, which is why this can be a
    /// blocking read rather than the async CAS path the serving side uses.
    fn read_socket_bytes(&self, root: &Hash) -> Result<Vec<u8>> {
        let size = self
            .store()
            .blob(root)
            .map_err(EngineError::from)?
            .ok_or_else(|| EngineError::invalid(format!("no local bytes for {root}")))?
            .size;
        let limits = self.socket_limits();
        if size > limits.max_program_bytes {
            return Err(EngineError::invalid(format!(
                "the program is {size} bytes, past the {} a socket may be",
                limits.max_program_bytes
            )));
        }
        Ok(self.store().read_range(root, 0, size)?)
    }
}
