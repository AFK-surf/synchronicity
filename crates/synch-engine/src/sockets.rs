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
//! as the handshake established it and the capabilities approved by arming the
//! program's declaration.
//!
//! **The tree host** is what the running program reads through. It is the one
//! place a socket touches the rest of the node, and it is read-only.

use std::sync::Arc;

use synch_core::{
    Declaration, EntryKind, Hash, NodeId, OriginId, RefuseCode, SockOpen, SockStatus,
};
use synch_sock::{
    limits::CURSOR_ENTRY_OVERHEAD, Admission, DuplexStream, EffectivePolicy, HostError, Limits,
    ObjectInfo, PeerIdentity, SocketHost, SocketId,
};
use synch_store::{ArmCandidate, SocketRow, SocketState};

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

/// The immutable result an operator reviews before arming a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketInspection {
    /// The content root that was inspected.
    pub root: Hash,
    /// What that exact execution of the program's init hook declared.
    pub declaration: Declaration,
    /// Opaque approval token binding the root, authorization revision, and
    /// rendered program declaration. Disarm also advances the revision, so a
    /// copied token cannot restore an approval the operator withdrew.
    pub review: Hash,
}

struct CurrentInspection {
    public: SocketInspection,
    generation: Hash,
}

impl Node {
    /// Declares a path in one of this node's spaces to be a socket.
    ///
    /// Does not arm it: what the file contains at declaration time may not be
    /// what the operator meant to approve, and `synch socket arm` is where the
    /// approval happens after the declaration is printed.
    pub fn socket_add(&self, row: &SocketRow) -> Result<()> {
        let _authorization = self.socket_authorization_write();
        let Some(space) = self.store().space(&row.space)? else {
            return Err(EngineError::invalid(format!(
                "`{}` is not a space this node indexes",
                row.space
            )));
        };
        if space.local_path.is_none() {
            return Err(EngineError::invalid(format!(
                "`{}` is detached and has no scanner that can publish a socket",
                row.space
            )));
        }
        let mut row = row.clone();
        row.path = synch_core::normalize_path(&row.path)
            .map_err(|e| EngineError::invalid(e.to_string()))?;
        self.store().put_socket(&row)?;
        // Kind is part of the published entry even when the file's bytes and
        // stat are unchanged. Invalidate the scanner cache so its next pass
        // reaches the declaration check instead of returning early.
        self.store().remove_local_file(&row.space, &row.path)?;
        Ok(())
    }

    /// Every socket this node declares.
    pub fn socket_ls(&self, space: Option<&str>) -> Result<Vec<SocketState>> {
        Ok(match space {
            Some(space) => self.store().sockets_in(space)?,
            None => self.store().sockets()?,
        })
    }

    /// Runs the program's declaration hook without approving anything.
    ///
    /// The dry run is not a formality. async-ebpf compiles lazily, per function
    /// and per pointer signature, so a program that fails to compile would
    /// otherwise surface that on the first stream that reaches the bad path —
    /// a long way from the operator who armed it.
    pub async fn socket_inspect(&self, space: &str, path: &str) -> Result<SocketInspection> {
        Ok(self.inspect_socket_current(space, path).await?.public)
    }

    async fn inspect_socket_current(&self, space: &str, path: &str) -> Result<CurrentInspection> {
        // Resolution opens the SQLite store. This method is reached directly
        // from the daemon's async control handler, so it belongs on the
        // blocking pool rather than on a Tokio worker.
        let node = self.clone();
        let (space_owned, path_owned) = (space.to_string(), path.to_string());
        let resolved =
            crate::blocking::offload(move || node.resolve_socket(&space_owned, &path_owned))
                .await?
                .ok_or_else(|| {
                    EngineError::invalid(format!(
                "`{space}/{path}` is declared a socket but this node publishes no entry for it \
                 — run `synch scan` first"
            ))
                })?;
        let elf = self.socket_program(&resolved).await?;
        // The declaration hook JIT-compiles the program and joins its isolated
        // worker thread. It is deliberately synchronous, so hand that wait to
        // the blocking pool too.
        let node = self.clone();
        let declared = crate::blocking::offload(move || node.declare_program(&elf)).await?;
        let review = socket_review(&resolved.root, &resolved.state.generation, &declared);
        Ok(CurrentInspection {
            public: SocketInspection {
                root: resolved.root,
                declaration: declared,
                review,
            },
            generation: resolved.state.generation,
        })
    }

    /// Approves only the exact init result returned by a prior inspection.
    ///
    /// Init is deliberately rerun here. A root alone is insufficient because
    /// init may consult time or randomness; the opaque token proves that this
    /// second execution produced the declaration the operator actually saw.
    pub async fn socket_approve(&self, space: &str, path: &str, review: &Hash) -> Result<()> {
        let inspected = self.inspect_socket_current(space, path).await?;
        if &inspected.public.review != review {
            return Err(EngineError::invalid(
                "the socket's content, declaration, or init result changed after review; inspect it again",
            ));
        }
        let node = self.clone();
        let (space, path) = (space.to_string(), path.to_string());
        crate::blocking::offload(move || {
            let _authorization = node.socket_authorization_write();
            let armed = node.store().arm_socket_reviewed(
                node.origin(),
                &space,
                &path,
                ArmCandidate {
                    generation: &inspected.generation,
                    root: &inspected.public.root,
                    declared: &inspected.public.declaration.render(),
                    armed_at: synch_core::now_ns(),
                },
            )?;
            if !armed {
                return Err(EngineError::invalid(
                    "the socket's declaration or published content changed while it was being armed; inspect it again",
                ));
            }
            // A re-arm is a different program; a session table minted by the
            // old one is not state the new one agreed to inherit.
            node.clear_socket_map(&format!("{space}/{path}"));
            Ok(())
        })
        .await
    }

    /// Withdraws an approval, leaving the declaration standing.
    pub fn socket_disarm(&self, space: &str, path: &str) -> Result<bool> {
        let _authorization = self.socket_authorization_write();
        let out = self.store().disarm_socket(space, path)?;
        self.clear_socket_map(&format!("{space}/{path}"));
        Ok(out)
    }

    /// Removes a declaration and its approval.
    ///
    /// The next scan republishes the path as an ordinary file, because the kind
    /// comes from the declaration and there is no longer one.
    pub fn socket_rm(&self, space: &str, path: &str) -> Result<bool> {
        let _authorization = self.socket_authorization_write();
        let out = self.store().remove_socket(space, path)?;
        if out {
            self.store().remove_local_file(space, path)?;
        }
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

    /// Reads a socket's ELF object out of this node's own CAS, sharing the
    /// allocation across every admission of one content root.
    ///
    /// Sixty-four streams into one socket must not mean sixty-four copies of
    /// its program: the bytes are immutable once the root is fixed, so all of
    /// the admissions of a root get the same `Arc` — including the concurrent
    /// ones, which wait on the first load's watch channel rather than each
    /// reading the CAS themselves. The [`ProgramBytesCache`] retains up to
    /// [`MAX_CACHED_PROGRAMS`] of them strongly, oldest first.
    async fn socket_program(&self, resolved: &Resolved) -> Result<Arc<Vec<u8>>> {
        let limits = self.socket_limits();
        if resolved.size > limits.max_program_bytes {
            return Err(EngineError::invalid(format!(
                "the program is {} bytes, past the {} a socket may be",
                resolved.size, limits.max_program_bytes
            )));
        }
        match self.socket_program_load(&resolved.root) {
            ProgramLoad::Ready(bytes) => Ok(bytes),
            ProgramLoad::InFlight(mut receiver) => {
                receiver.wait_for(Option::is_some).await.map_err(|_| {
                    EngineError::invalid("a concurrent socket program load was interrupted")
                })?;
                match receiver.borrow().clone().expect("the loader published") {
                    Ok(bytes) => Ok(bytes),
                    Err(text) => Err(EngineError::invalid(text)),
                }
            }
            ProgramLoad::Loader(guard) => {
                // Its own CAS: the bytes were published by this node, so they
                // are held here. `ensure_cached` covers the one case where
                // they are not — a cloud-backed node whose scratch cache has
                // been replaced. If this future is cancelled or panics before
                // `finish`, the guard's drop publishes the failure and frees
                // the root for a fresh load.
                let outcome: ProgramBytes = (async {
                    self.ensure_blob_cached(&resolved.root, resolved.size)
                        .await
                        .map_err(|e| e.to_string())?;
                    self.cas_backend()
                        .read_range(resolved.root, 0, resolved.size)
                        .await
                        .map_err(|e| e.to_string())
                        .map(Arc::new)
                })
                .await;
                guard.finish(outcome.clone());
                outcome.map_err(EngineError::invalid)
            }
        }
    }

    /// Builds the policy one invocation runs under.
    fn socket_policy(&self, state: &SocketState) -> EffectivePolicy {
        let declared = state
            .arm
            .as_ref()
            .map(|arm| Declaration::parse(&arm.declared))
            .unwrap_or_default();
        EffectivePolicy::armed(
            &declared,
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
    pub(crate) async fn admit_socket(
        &self,
        peer: NodeId,
        addr: String,
        stream_index: u64,
        open: &SockOpen,
    ) -> std::result::Result<Admission, (RefuseCode, String)> {
        if !synch_sock::SUPPORTED {
            return Err((
                RefuseCode::Unsupported,
                "this node has no eBPF runtime: async-ebpf supports Linux, macOS and OpenBSD on \
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

        let node = self.clone();
        let scope = crate::blocking::offload(move || {
            Ok(node
                .store()
                .socket_scope_for_key(&peer, synch_core::now_ns())?)
        })
        .await
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

        let node = self.clone();
        let (space, path) = (open.space.clone(), open.path.clone());
        let resolved = crate::blocking::offload(move || {
            let resolved = node.resolve_socket(&space, &path)?;
            let ordinary = if resolved.is_none() {
                node.store().entry(node.origin(), &space, &path)?.is_some()
            } else {
                false
            };
            Ok((resolved, ordinary))
        })
        .await
        .map_err(|e| (RefuseCode::NoSuchPath, e.to_string()))?;
        let resolved = match resolved {
            (Some(resolved), _) => resolved,
            (None, ordinary) => {
                // Told apart so the caller learns something: a path this node
                // publishes as an ordinary file is a different mistake from a
                // path it publishes nothing for.
                let code = if ordinary {
                    RefuseCode::NotASocket
                } else {
                    RefuseCode::NoSuchPath
                };
                return Err((code, format!("{}/{}", open.space, open.path)));
            }
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

        // Program loading may fetch from a remote CAS. Authorization is
        // deliberately not held across that wait, but it must be checked again
        // while the registry slot is made live. Arm/disarm/redeclare take the
        // write side of this gate, so either this admission becomes in-flight
        // first or the revocation wins and this request is refused.
        let qualified = format!("{}/{}", open.space, open.path);
        let node = self.clone();
        let (space, path) = (open.space.clone(), open.path.clone());
        let checked = resolved.clone();
        let qualified_for_slot = qualified.clone();
        let peer_name = origin.canonical();
        // The store read and the registry reservation are one blocking-pool
        // closure so the authorization read guard spans both. A concurrent
        // disarm therefore wins before admission or waits until the live slot
        // exists; there is no unchecked gap between them.
        let prepared = crate::blocking::offload(move || {
            let _authorization = node.socket_authorization_read();
            let current = match node.resolve_socket(&space, &path)? {
                Some(current) => current,
                None => {
                    return Ok(Err((
                        RefuseCode::NotArmed,
                        "the socket was removed or republished during admission".into(),
                    )))
                }
            };
            if !authorization_unchanged(&checked, &current) {
                return Ok(Err((
                    RefuseCode::NotArmed,
                    "the socket was disarmed, redeclared, or changed during admission".into(),
                )));
            }

            let policy = node.socket_policy(&current.state);
            // The pool-wide bound, before the socket's own cap: one caller
            // who can reach many sockets must not be able to fill every
            // worker's queue past the documented daemon limit.
            if node.socket_pool_full() {
                return Ok(Err((
                    RefuseCode::Busy,
                    "the node's socket workers are at capacity; try again shortly".into(),
                )));
            }
            let id = node.next_socket_id();
            // The concurrency cap is taken at admission, before the guest
            // starts, so a caller cannot open idle streams past the cap.
            let Some(slot) = node.reserve_socket_slot(
                id,
                &qualified_for_slot,
                &peer_name,
                peer,
                checked.root,
                policy.max_streams,
            ) else {
                return Ok(Err((
                    RefuseCode::Busy,
                    format!(
                        "{qualified_for_slot} is at its limit of {} concurrent invocations",
                        policy.max_streams
                    ),
                )));
            };
            Ok(Ok((policy, id, slot)))
        })
        .await
        .map_err(|e| (RefuseCode::NotArmed, e.to_string()))?;
        let (policy, id, slot) = prepared?;

        // The pool token is taken *before* the program's bytes are read: the
        // CAS fetch can be the expensive part of an admission (up to 4 MiB,
        // possibly from a remote CAS), and concurrent opens for distinct
        // roots must not bypass the daemon-wide bound during it. A load that
        // fails — the size check, the fetch, the read — gives the token back
        // by dropping the slot, and the admission is refused as it would have
        // been before.
        let program = match self.socket_program(&resolved).await {
            Ok(bytes) => bytes,
            Err(e) => {
                drop(slot);
                return Err((RefuseCode::ProgramInvalid, e.to_string()));
            }
        };

        Ok(Admission {
            program,
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
            id,
            slot: Some(slot),
        })
    }

    /// Runs an admitted invocation.
    ///
    /// `peer_gone` is the caller's connection closing, as the net layer
    /// observed it: the invocation ends with `Deadline` when it fires — the
    /// same non-fault ending as a failed stream — while `synch socket kill`
    /// keeps its own channel and its `Killed` ending.
    pub(crate) async fn run_socket(
        &self,
        admission: Admission,
        stream: DuplexStream,
        peer_gone: tokio::sync::oneshot::Receiver<SockStatus>,
    ) -> SockStatus {
        let socket = admission.socket.clone();
        let program_root = admission.program_root;
        let Some(pool) = self.socket_workers() else {
            return SockStatus::Shutdown;
        };
        let status = match pool
            .run_cancellable(admission.with_stream(stream), peer_gone)
            .await
        {
            Ok(outcome) => outcome.status,
            Err(e) => {
                tracing::warn!("socket invocation failed: {e}");
                SockStatus::Fault(synch_core::FaultKind::Load)
            }
        };
        // The pool has already recorded this outcome against the socket's
        // fault history; what it cannot do is disarm, which is a store write.
        if pool.should_quarantine(&socket.qualified(), program_root) {
            self.quarantine_socket(&socket.space, &socket.path, program_root)
                .await;
        }
        status
    }

    /// Disarms a socket that has been faulting on most of what it is asked.
    ///
    /// A program that cannot run is not left accepting connections: every
    /// caller gets a reset instead of an answer, and the operator finds out
    /// from their users. Disarmed rather than undeclared — the declaration and
    /// its policy are the operator's and survive; what is withdrawn is the
    /// approval of *these bytes*, which have proved they do not work.
    async fn quarantine_socket(&self, space: &str, path: &str, root: Hash) {
        let node = self.clone();
        let (space, path) = (space.to_string(), path.to_string());
        if let Err(e) = crate::blocking::offload(move || {
            let _authorization = node.socket_authorization_write();
            match node.store().disarm_socket_root(&space, &path, &root) {
                Ok(true) => tracing::error!(
                    socket = format!("{space}/{path}"),
                    "socket disarmed: it faulted on most of its recent invocations.                  Fix the program and `synch socket arm` it again."
                ),
                Ok(false) => {}
                Err(e) => tracing::warn!(
                    socket = format!("{space}/{path}"),
                    "could not disarm a faulting socket: {e}"
                ),
            }
            Ok(())
        })
        .await
        {
            tracing::warn!("could not schedule fault quarantine: {e}");
        }
    }

    /// Every invocation running right now, optionally for one socket.
    pub fn socket_ps(&self, socket: Option<&str>) -> Vec<synch_sock::InvocationInfo> {
        match self.socket_workers() {
            Some(pool) => pool.snapshot(socket),
            None => Vec::new(),
        }
    }

    /// Ends one invocation, reporting whether there was one to end.
    pub fn socket_kill(&self, id: u64) -> bool {
        self.socket_workers().is_some_and(|pool| pool.kill(id))
    }

    /// What one socket's programs have written recently.
    pub fn socket_log(&self, space: &str, path: &str) -> Vec<synch_sock::LogLine> {
        match self.socket_workers() {
            Some(pool) => pool.logs(&format!("{space}/{path}")),
            None => Vec::new(),
        }
    }
}

fn authorization_unchanged(reviewed: &Resolved, current: &Resolved) -> bool {
    current.root == reviewed.root
        && current.state.generation == reviewed.state.generation
        && current.state.is_armed_for(&current.root)
}

fn socket_review(root: &Hash, generation: &Hash, declaration: &Declaration) -> Hash {
    let rendered = declaration.render();
    let mut bytes = Vec::with_capacity(32 + 32 + rendered.len() + 31);
    bytes.extend_from_slice(b"synch/socket-review/v1\0");
    bytes.extend_from_slice(root.as_bytes());
    bytes.extend_from_slice(generation.as_bytes());
    bytes.extend_from_slice(rendered.as_bytes());
    Hash::new(&bytes)
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
        const PAGE: usize = 4096;
        // The scan runs synchronously on the socket worker's thread — the one
        // store access in the host that is not offloaded — so it is bounded
        // both ways: by how much it may collect, and by how many rows it may
        // walk to collect it. The byte cap is the same footprint budget
        // `sy_list_open` charges the names against afterwards; a listing that
        // would blow it is refused rather than materialized.
        //
        // Every scanned row counts toward the row cap, tombstones included:
        // they are skipped for the collection, but the scan still paid a row
        // to learn they were there, and a prefix full of them must not be a
        // way to make the worker walk an unbounded number of pages.
        const MAX_ROWS: usize = 65536;
        let max_bytes = self.node.socket_limits().max_footprint as usize;
        let mut after = None;
        let mut names = Vec::new();
        let mut scanned = 0usize;
        let mut bytes = 0usize;
        loop {
            let rows = self
                .node
                .store()
                .list_entries(
                    Some(&self.own_origin),
                    space,
                    rest,
                    after.as_deref(),
                    Some(PAGE),
                )
                .map_err(|e| HostError::Unavailable(e.to_string()))?;
            let done = rows.len() < PAGE;
            after = rows.last().map(|row| row.path.clone());
            for row in rows {
                scanned += 1;
                if scanned > MAX_ROWS {
                    return Err(HostError::NotReadable(
                        "the listing exceeds a socket invocation's footprint; \
                         narrow the prefix"
                            .into(),
                    ));
                }
                if row.kind == EntryKind::Tombstone {
                    continue;
                }
                // Counted the way `sy_list_open` will charge the listing: name
                // bytes plus the per-entry host overhead the cursor retains.
                // A name-byte sum alone would materialize listings the
                // runtime then refuses, and would let a listing of short
                // names exceed the footprint this cap exists to protect.
                bytes += row.path.len() + CURSOR_ENTRY_OVERHEAD as usize;
                names.push(row.path);
                if bytes > max_bytes {
                    return Err(HostError::NotReadable(
                        "the listing exceeds a socket invocation's footprint; \
                         narrow the prefix"
                            .into(),
                    ));
                }
            }
            if done {
                break;
            }
        }
        Ok(names)
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
pub(crate) struct SocketDispatch {
    node: Arc<std::sync::OnceLock<crate::node::WeakNode>>,
}

impl SocketDispatch {
    /// An unbound dispatcher, ready to be mounted.
    pub(crate) fn new() -> Self {
        SocketDispatch::default()
    }

    /// Binds it to the node it serves. Called once, at the end of startup.
    pub(crate) fn bind(&self, node: &Node) {
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

    async fn run(
        &self,
        admission: Admission,
        stream: DuplexStream,
        peer_gone: tokio::sync::oneshot::Receiver<SockStatus>,
    ) -> SockStatus {
        match self.node() {
            // A node that has gone away between admission and here is a node
            // shutting down, which is exactly what the caller should be told.
            Some(node) => node.run_socket(admission, stream, peer_gone).await,
            None => SockStatus::Shutdown,
        }
    }
}

/// The limits every socket on this node runs under.
pub(crate) fn default_limits() -> Limits {
    Limits::default()
}

/// The worker pool, where there is one.
///
/// Two implementations of the same small API rather than `cfg` at every call
/// site: async-ebpf exists on Linux, macOS and OpenBSD on x86-64 and arm64 and
/// nowhere else, and the engine has to build everywhere. What a node without
/// it loses is serving — declaring, publishing, replicating and materializing
/// socket entries all work, and so does `synch connect`, because the
/// connecting side executes nothing.
#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod pool {
    use super::*;

    /// A started pool.
    #[derive(Debug, Clone)]
    pub(crate) struct SocketPool(synch_sock::WorkerHandle);

    impl SocketPool {
        /// Starts `workers` threads.
        pub(crate) fn start(workers: usize, limits: Limits) -> Option<SocketPool> {
            Some(SocketPool(synch_sock::WorkerHandle::start(workers, limits)))
        }

        /// The limits every invocation runs under.
        pub(crate) fn limits(&self) -> Limits {
            self.0.limits().clone()
        }

        /// The next invocation id.
        pub(crate) fn next_id(&self) -> u64 {
            self.0.next_id()
        }

        /// Drops what one socket's map held.
        pub(crate) fn clear_map(&self, socket: &str) {
            self.0.clear_map(socket);
        }

        /// Runs one invocation that may be cut short by `synch socket kill`
        /// or by the caller's connection closing (`peer_gone`).
        ///
        /// The kill sender is attached to the registry here, exactly as
        /// [`SocketPool::run`] does; the peer-gone receiver is the
        /// connection-close signal the net layer watched.
        pub(crate) async fn run_cancellable(
            &self,
            invocation: synch_sock::Invocation,
            peer_gone: tokio::sync::oneshot::Receiver<synch_core::SockStatus>,
        ) -> std::result::Result<synch_sock::Outcome, synch_sock::SockError> {
            let (kill_tx, kill_rx) = tokio::sync::oneshot::channel();
            if invocation.slot.is_some() {
                self.0.registry().attach_cancel(invocation.id, kill_tx);
            }
            self.0.run_cancellable(invocation, kill_rx, peer_gone).await
        }

        /// Whether every worker is at its queued cap.
        pub(crate) fn full(&self) -> bool {
            self.0.full()
        }

        /// Cancels and drains every invocation, then joins all worker threads.
        pub(crate) async fn shutdown(&self) {
            self.0.shutdown().await;
        }

        /// Takes a concurrency slot, or reports the socket full.
        #[allow(
            clippy::too_many_arguments,
            reason = "a pass-through to `Registry::reserve`, whose arguments are                       the facts an entry is made of"
        )]
        pub(crate) fn reserve(
            &self,
            id: u64,
            socket: &str,
            peer: &str,
            peer_key: synch_core::NodeId,
            program: Hash,
            max_streams: usize,
        ) -> Option<synch_sock::SlotGuard> {
            self.0.registry().reserve(
                id,
                socket,
                peer,
                peer_key,
                program,
                max_streams,
                std::time::Instant::now(),
            )
        }

        /// Whether a socket has been faulting enough to be disarmed.
        pub(crate) fn should_quarantine(&self, socket: &str, program: Hash) -> bool {
            // The pool recorded the outcome as the invocation ended; this only
            // reads the verdict it reached.
            self.0.registry().take_quarantine(socket, program)
        }

        /// Everything running.
        pub(crate) fn snapshot(&self, socket: Option<&str>) -> Vec<synch_sock::InvocationInfo> {
            self.0
                .registry()
                .snapshot(socket, std::time::Instant::now())
        }

        /// Ends one invocation.
        pub(crate) fn kill(&self, id: u64) -> bool {
            self.0.registry().kill(id)
        }

        /// One socket's recent log lines.
        pub(crate) fn logs(&self, socket: &str) -> Vec<synch_sock::LogLine> {
            self.0.registry().logs(socket)
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
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod pool {
    use super::*;

    /// A pool that does not exist on this platform.
    #[derive(Debug, Clone)]
    pub(crate) struct SocketPool;

    impl SocketPool {
        /// Never starts: there is no runtime to start.
        pub(crate) fn start(_workers: usize, _limits: Limits) -> Option<SocketPool> {
            None
        }

        /// The documented defaults, so `synch socket ls` prints the same
        /// numbers everywhere even where nothing can run.
        pub(crate) fn limits(&self) -> Limits {
            Limits::default()
        }

        /// Unreachable: nothing admits an invocation without a pool.
        pub(crate) fn next_id(&self) -> u64 {
            0
        }

        /// Nothing to clear.
        pub(crate) fn clear_map(&self, _socket: &str) {}

        /// Unreachable: nothing admits an invocation without a pool.
        pub(crate) async fn run_cancellable(
            &self,
            _invocation: synch_sock::Invocation,
            _peer_gone: tokio::sync::oneshot::Receiver<synch_core::SockStatus>,
        ) -> std::result::Result<synch_sock::Outcome, synch_sock::SockError> {
            Err(synch_sock::SockError::Unsupported)
        }

        /// Nothing runs on an unsupported platform.
        pub(crate) async fn shutdown(&self) {}

        /// Nothing is ever at capacity when nothing can run: admission is
        /// refused before it reaches this.
        pub(crate) fn full(&self) -> bool {
            false
        }

        /// Unreachable: admission refuses before it reaches this.
        #[allow(
            clippy::too_many_arguments,
            reason = "matches the shape of the implementation it stands in for"
        )]
        pub(crate) fn reserve(
            &self,
            _id: u64,
            _socket: &str,
            _peer: &str,
            _peer_key: synch_core::NodeId,
            _program: Hash,
            _max_streams: usize,
        ) -> Option<synch_sock::SlotGuard> {
            None
        }

        /// Nothing runs, so nothing faults.
        pub(crate) fn should_quarantine(&self, _socket: &str, _program: Hash) -> bool {
            false
        }

        /// Nothing runs here.
        pub(crate) fn snapshot(&self, _socket: Option<&str>) -> Vec<synch_sock::InvocationInfo> {
            Vec::new()
        }

        /// Nothing runs here.
        pub(crate) fn kill(&self, _id: u64) -> bool {
            false
        }

        /// Nothing runs here.
        pub(crate) fn logs(&self, _socket: &str) -> Vec<synch_sock::LogLine> {
            Vec::new()
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

pub(crate) use pool::SocketPool;

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
///
/// The hook always runs against [`NoTree`]: a declaration names intent, and
/// granting it a tree to read would let the arming step observe state.
pub(crate) fn declare_blocking(elf: &[u8]) -> Result<Declaration> {
    let _scope = synch_core::BlockingScope::enter();
    pool::declare(elf, Arc::new(NoTree)).map_err(|e| EngineError::invalid(e.to_string()))
}

/// How many socket programs the node keeps in memory after their
/// invocations end.
///
/// A bound on the cache's strong entries: each holds up to
/// `max_program_bytes` (4 MiB), so the whole cache is at most
/// `MAX_CACHED_PROGRAMS * 4 MiB`. Oldest first, like the workers' compiled-
/// program cache.
const MAX_CACHED_PROGRAMS: usize = 4;

/// One root's program bytes, or why the load failed.
type ProgramBytes = std::result::Result<Arc<Vec<u8>>, String>;

/// The watch channel an in-flight load publishes its outcome on.
type LoadWatch = tokio::sync::watch::Sender<Option<ProgramBytes>>;

/// What a claim on [`ProgramBytesCache`] for one root came back as.
pub(crate) enum ProgramLoad {
    /// The bytes were already loaded; share them.
    Ready(Arc<Vec<u8>>),
    /// Another admission is reading this root from the CAS; wait for it.
    InFlight(tokio::sync::watch::Receiver<Option<ProgramBytes>>),
    /// This admission is the one that reads the CAS.
    Loader(LoadGuard),
}

/// The loader's claim on [`ProgramBytesCache`] for one root.
///
/// The claim is released when the load ends, *however* it ends. The happy
/// path calls [`LoadGuard::finish`], which publishes the outcome and
/// remembers the bytes. A load that is cancelled or panics during the CAS
/// await drops the guard instead: the drop removes the root from the
/// in-flight table and publishes the failure to every waiter, so the root's
/// later admissions start a fresh load rather than waiting forever on a
/// sender nobody will ever fill.
#[derive(Debug)]
pub(crate) struct LoadGuard {
    cache: Arc<ProgramBytesCache>,
    root: Hash,
    sender: LoadWatch,
    finished: bool,
}

impl LoadGuard {
    /// Publishes the outcome and releases the loader role.
    pub(crate) fn finish(mut self, outcome: ProgramBytes) {
        self.finished = true;
        self.cache
            .finish_load(self.root, self.sender.clone(), outcome);
    }
}

impl Drop for LoadGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut inner = self.cache.inner.lock().expect("socket program cache");
        inner.loading.remove(&self.root);
        // Wake the waiters with the failure rather than leaving them parked
        // on a sender that will never send.
        let _ = self
            .sender
            .send(Some(Err("socket program load was interrupted".to_string())));
    }
}

/// Socket program bytes, shared across the admissions of one content root.
///
/// Sixty-four streams into one socket must not mean sixty-four copies of
/// its program, and the sharing has to survive *concurrent* cold admissions
/// — the first admission of a root is still reading the CAS while the
/// fifty-ninth arrives. Two structures make it one copy per root:
///
/// * `loading` coalesces those concurrent cold admissions: the first claims
///   the loader role and publishes the outcome on a watch channel; the rest
///   subscribe and share the allocation.
/// * `ready` holds completed programs strongly, FIFO-evicted at
///   [`MAX_CACHED_PROGRAMS`], so a burst of admissions re-reads nothing and
///   memory stays bounded now that the entries are not weak.
#[derive(Debug, Default)]
pub(crate) struct ProgramBytesCache {
    inner: std::sync::Mutex<ProgramBytesInner>,
}

#[derive(Debug, Default)]
struct ProgramBytesInner {
    ready: std::collections::HashMap<Hash, Arc<Vec<u8>>>,
    order: std::collections::VecDeque<Hash>,
    loading: std::collections::HashMap<Hash, LoadWatch>,
}

impl ProgramBytesCache {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(ProgramBytesCache::default())
    }

    /// Claims the cache for one root: the loaded bytes, a seat on an
    /// in-flight load, or the loader role. The lock is held only for the
    /// claim — the CAS read happens outside it, which is what lets the other
    /// admissions wait on the watch channel instead of on the cache.
    pub(crate) fn begin_load(self: &Arc<Self>, root: &Hash) -> ProgramLoad {
        let mut inner = self.inner.lock().expect("socket program cache");
        if let Some(bytes) = inner.ready.get(root) {
            return ProgramLoad::Ready(bytes.clone());
        }
        if let Some(sender) = inner.loading.get(root) {
            return ProgramLoad::InFlight(sender.subscribe());
        }
        let (sender, _receiver) = tokio::sync::watch::channel(None);
        inner.loading.insert(*root, sender.clone());
        ProgramLoad::Loader(LoadGuard {
            cache: self.clone(),
            root: *root,
            sender,
            finished: false,
        })
    }

    /// Publishes the outcome of a load to its waiters, and remembers the
    /// bytes for the next admission. Called by [`LoadGuard::finish`].
    fn finish_load(&self, root: Hash, sender: LoadWatch, outcome: ProgramBytes) {
        let mut inner = self.inner.lock().expect("socket program cache");
        inner.loading.remove(&root);
        if let Ok(bytes) = &outcome {
            inner.ready.insert(root, bytes.clone());
            inner.order.push_back(root);
            while inner.order.len() > MAX_CACHED_PROGRAMS {
                if let Some(oldest) = inner.order.pop_front() {
                    inner.ready.remove(&oldest);
                }
            }
        }
        let _ = sender.send(Some(outcome));
    }
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
        let generation = state.generation;
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
                let _authorization = self.socket_authorization_write();
                let armed = self.store().auto_arm_socket(
                    space,
                    path,
                    ArmCandidate {
                        generation: &generation,
                        root,
                        declared: &declared.render(),
                        armed_at: synch_core::now_ns(),
                    },
                )?;
                if armed {
                    self.clear_socket_map(&format!("{space}/{path}"));
                    tracing::info!(
                        socket = format!("{space}/{path}"),
                        root = %root,
                        "auto-armed"
                    );
                } else {
                    tracing::info!(
                        socket = format!("{space}/{path}"),
                        "auto-arm skipped because the declaration changed or auto-arming was disabled"
                    );
                }
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

impl Node {
    /// Opens a socket on a node (`docs/SOCKETS.md` §4), including this one.
    ///
    /// The connecting side of the design, and it executes nothing: it names a
    /// path, and everything that decides what runs is state the callee already
    /// holds. That is why this half works on platforms where the runtime does
    /// not exist at all.
    ///
    /// One QUIC connection per call rather than a reused session: a socket
    /// stream's lifetime is the caller's, and sharing a connection between two
    /// unrelated `synch connect` invocations would let one close the other's.
    pub async fn connect_socket(
        &self,
        origin: &OriginId,
        space: &str,
        path: &str,
        meta: Vec<(String, String)>,
    ) -> Result<SocketConnection> {
        let open = SockOpen::new(origin.clone(), space, path, meta);
        open.validate()
            .map_err(|e| EngineError::invalid(e.to_string()))?;

        if origin == self.origin() {
            let admission = self
                .admit_socket(self.node_id(), "local".into(), 0, &open)
                .await
                .map_err(|(code, message)| {
                    EngineError::invalid(format!(
                        "{} refused {space}/{path}: {}: {message}",
                        origin.canonical(),
                        code.as_str()
                    ))
                })?;
            let program = admission.program_root;
            let invocation = admission.id;
            let (caller, guest) = tokio::io::duplex(self.socket_limits().ring_bytes);
            let node = self.clone();
            let completion = tokio::spawn(async move {
                let (_, peer_gone) = tokio::sync::oneshot::channel();
                node.run_socket(admission, DuplexStream::from_split(guest), peer_gone)
                    .await
            });
            return Ok(SocketConnection::Local {
                program,
                invocation,
                stream: caller,
                completion,
            });
        }

        let node = self.clone();
        let remote = origin.clone();
        let keys = crate::blocking::offload(move || {
            Ok(node
                .store()
                .keys_for_origin(&remote, synch_core::now_ns())?)
        })
        .await?;
        if keys.is_empty() {
            return Err(EngineError::not_found(format!(
                "no live binding for {} — this node does not know its device key",
                origin.canonical()
            )));
        }

        let mut last: Option<EngineError> = None;
        for key in keys {
            // `peers_seen.last_addr` is only a hint. A live binding with no
            // stored address is the normal shape for a peer reached through
            // iroh/Pkarr discovery, so give iroh the authenticated key and let
            // its configured address lookup resolve it.
            let addr = self
                .peer_addr_off_runtime(&key)
                .await?
                .unwrap_or_else(|| iroh::EndpointAddr::new(key));
            let client = match self.net().connect_sock(addr).await {
                Ok(client) => client,
                Err(e) => {
                    last = Some(EngineError::Net(e));
                    continue;
                }
            };
            // Accepted before the first `Open`, because the callee opens it at
            // connection setup and a status has to have somewhere to arrive.
            let control = client.control().await.map_err(EngineError::Net)?;
            return match client.open(&open).await.map_err(EngineError::Net)? {
                Ok(stream) => Ok(SocketConnection::Remote {
                    client,
                    control,
                    stream,
                }),
                Err(refused) => Err(EngineError::invalid(format!(
                    "{} refused {space}/{path}: {refused}",
                    origin.canonical()
                ))),
            };
        }
        Err(last.unwrap_or_else(|| {
            EngineError::not_found(format!("could not reach {}", origin.canonical()))
        }))
    }
}

/// A live socket connection on the caller's side.
#[derive(Debug)]
pub enum SocketConnection {
    /// A connection to a peer over `sync/sock/1`.
    Remote {
        /// Kept alive: dropping it closes the QUIC connection under the stream.
        client: synch_net::sock::SockClient,
        /// Where the invocation's exit status arrives.
        control: iroh::endpoint::RecvStream,
        /// The invocation itself.
        stream: synch_net::sock::SockStream,
    },
    /// A connection to this node, carried in memory but admitted and run by the
    /// same engine path as a remote invocation.
    Local {
        /// The content root actually running.
        program: Hash,
        /// The callee's invocation id.
        invocation: u64,
        /// Opaque bytes in both directions.
        stream: tokio::io::DuplexStream,
        /// The invocation's eventual status.
        completion: tokio::task::JoinHandle<SockStatus>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_store::{ArmRow, SocketRow};

    fn resolved(generation: Hash, root: Hash) -> Resolved {
        Resolved {
            root,
            size: 3,
            state: SocketState {
                declaration: SocketRow::new("code", "git.sock", 0),
                generation,
                arm: Some(ArmRow {
                    space: "code".into(),
                    path: "git.sock".into(),
                    root,
                    declared: String::new(),
                    armed_at: 0,
                }),
            },
        }
    }

    #[tokio::test]
    async fn concurrent_cold_loads_coalesce_onto_one_allocation() {
        let cache = ProgramBytesCache::new();
        let root = Hash::new(b"program");

        // The first claim is the loader.
        let ProgramLoad::Loader(guard) = cache.begin_load(&root) else {
            panic!("the first claim should be the loader");
        };
        // A concurrent admission of the same root waits on the watch channel
        // instead of reading the CAS itself.
        let ProgramLoad::InFlight(receiver) = cache.begin_load(&root) else {
            panic!("a concurrent claim should be in flight, not a fresh load");
        };
        let waiter = tokio::spawn(async move {
            let mut receiver = receiver;
            receiver.wait_for(Option::is_some).await.unwrap();
            let outcome = receiver.borrow().clone();
            outcome.unwrap().unwrap()
        });

        // The loader publishes one allocation...
        let bytes = Arc::new(b"the program".to_vec());
        guard.finish(Ok(bytes.clone()));
        // ...which the waiter shares, pointer and all.
        let seen = waiter.await.unwrap();
        assert!(
            Arc::ptr_eq(&seen, &bytes),
            "the waiting admission allocated its own copy"
        );

        // And the next admission is served from the ready cache.
        let ProgramLoad::Ready(bytes) = cache.begin_load(&root) else {
            panic!("a loaded root should be ready");
        };
        assert_eq!(&*bytes, b"the program");
    }

    #[tokio::test]
    async fn an_interrupted_load_wakes_its_waiters_and_frees_the_root() {
        let cache = ProgramBytesCache::new();
        let root = Hash::new(b"program");

        let ProgramLoad::Loader(guard) = cache.begin_load(&root) else {
            panic!("the first claim should be the loader");
        };
        let ProgramLoad::InFlight(receiver) = cache.begin_load(&root) else {
            panic!("a concurrent claim should be in flight");
        };
        let waiter = tokio::spawn(async move {
            let mut receiver = receiver;
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                receiver.wait_for(Option::is_some).await.unwrap();
                receiver.borrow().clone()
            })
            .await
            .expect("the interrupted load never woke its waiter");
            outcome
        });

        // The loader dies — cancellation, a panic — without finishing.
        drop(guard);

        // The waiter is told the load failed, not left parked forever...
        let outcome = waiter.await.unwrap();
        assert!(
            matches!(outcome, Some(Err(_))),
            "waiters should see the failure, got {outcome:?}"
        );
        // ...and the root is free for a fresh load.
        assert!(
            matches!(cache.begin_load(&root), ProgramLoad::Loader(_)),
            "an interrupted load left its in-flight entry behind"
        );
    }

    #[test]
    fn the_ready_cache_is_fifo_bounded() {
        let cache = ProgramBytesCache::new();
        for i in 0..MAX_CACHED_PROGRAMS + 4 {
            let root = Hash::new(format!("program {i}").as_bytes());
            let ProgramLoad::Loader(guard) = cache.begin_load(&root) else {
                panic!("a fresh root should claim the loader role");
            };
            guard.finish(Ok(Arc::new(vec![i as u8])));
        }
        // The oldest roots are gone; the newest are served from memory.
        let oldest = Hash::new(b"program 0");
        assert!(
            !matches!(cache.begin_load(&oldest), ProgramLoad::Ready(_)),
            "the oldest program was not evicted"
        );
        let newest = Hash::new(format!("program {}", MAX_CACHED_PROGRAMS + 3).as_bytes());
        assert!(matches!(cache.begin_load(&newest), ProgramLoad::Ready(_)));
    }

    #[test]
    fn final_admission_rejects_every_authorization_change() {
        let root = Hash::new(b"program");
        let generation = Hash::new(b"authorization");
        let reviewed = resolved(generation, root);
        assert!(authorization_unchanged(
            &reviewed,
            &resolved(generation, root)
        ));

        let after_disarm = Resolved {
            state: SocketState {
                generation: Hash::new(b"after disarm"),
                arm: None,
                ..reviewed.state.clone()
            },
            ..reviewed.clone()
        };
        assert!(!authorization_unchanged(&reviewed, &after_disarm));
        assert!(!authorization_unchanged(
            &reviewed,
            &resolved(generation, Hash::new(b"new program"))
        ));
    }
}
