//! The `sync/sock/1` wire schema (`docs/SOCKETS.md` §4).
//!
//! One QUIC connection per (caller, callee) pair; one bidirectional stream per
//! invocation. Each stream opens with a length-framed [`SockOpen`], is answered
//! with a length-framed [`SockOpened`], and then carries **opaque bytes with no
//! framing at all** in both directions until FIN.
//!
//! The payload is unframed deliberately. A trailer carrying the invocation's
//! exit status would put a length prefix on every proxied byte for the sake of
//! a value that arrives once; a QUIC `RESET_STREAM` would carry it for free but
//! discards data the peer has not read, so a program that writes a final
//! response and returns would race its own output away. The status therefore
//! rides a per-connection control uni-stream ([`SockClosed`]) and the data
//! stream always closes cleanly.

use serde::{Deserialize, Serialize};

use crate::{hash::Hash, origin::OriginId};

/// ALPN for socket invocation (`docs/SOCKETS.md` §4).
pub const ALPN_SOCK: &[u8] = b"sync/sock/1";

/// Protocol version carried in [`SockOpen::v`].
///
/// Checked before anything else in the frame is trusted. Like `Hello`'s
/// version on the metadata ALPN, a peer on another version is refused rather
/// than negotiated with.
pub(crate) const SOCK_PROTO_VERSION: u8 = 1;

/// The most metadata pairs one [`SockOpen`] may carry.
pub(crate) const MAX_OPEN_META_PAIRS: usize = 16;

/// The most bytes [`SockOpen::meta`] may occupy, keys and values summed.
pub(crate) const MAX_OPEN_META_BYTES: usize = 4096;

/// The largest accepted `Open` frame, in bytes (`docs/SOCKETS.md` §10).
///
/// Derived rather than chosen, for the reason
/// [`MAX_BATCH_PATH_BYTES`](crate::MAX_BATCH_PATH_BYTES) is: a cap below what a
/// legal frame can carry is a wedge, not a guard. The resolver is deterministic,
/// so an over-cap `Open` is over it on every retry and the caller can never
/// reach that socket at all. The slack covers the origin (a named one carries a
/// name and a domain), the space, and postcard's length varints.
///
/// Enforced by the framing layer *before* the decode, so nothing inside this
/// module ever sees an allocation it did not bound.
pub const MAX_OPEN_FRAME_LEN: usize = crate::MAX_KEY_LEN + MAX_OPEN_META_BYTES + 1024;

/// The most bytes a [`SockOpened::Refused`] message may carry.
pub(crate) const MAX_REFUSE_MESSAGE_LEN: usize = 512;

/// Opens one invocation. The caller's whole influence over what runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SockOpen {
    /// Protocol version; must be `SOCK_PROTO_VERSION`.
    pub v: u8,
    /// The origin whose tree the socket is to be resolved in.
    ///
    /// Must be the callee's *own* origin. Carrying it — rather than letting the
    /// callee assume "me" — is what makes a relayed or replayed `Open`
    /// undeliverable anywhere but where it was addressed.
    pub origin: OriginId,
    /// The space the socket lives in.
    pub space: String,
    /// The socket's path within that space.
    pub path: String,
    /// Caller-supplied metadata, readable by the program via `sy_conn_meta`.
    ///
    /// **Untrusted.** It is whatever the caller typed after `--meta`, and the
    /// only reason it is in the protocol at all is that a program that wants a
    /// hint from its caller should get one through a bounded, named channel
    /// rather than by parsing the first line of the payload.
    #[serde(deserialize_with = "bounded_meta")]
    pub meta: Vec<(String, String)>,
}

/// Why a [`SockOpen`] was refused.
///
/// Appended to, never reordered: postcard numbers variants by position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefuseCode {
    /// No entry at that path in the callee's own trie.
    NoSuchPath,
    /// There is an entry, but its kind is not [`Socket`](crate::EntryKind::Socket).
    NotASocket,
    /// Declared but not armed, or armed at a root the bytes no longer have.
    NotArmed,
    /// The caller is not a member, or the space is not one it may read.
    Unauthorized,
    /// The caller is a delegate and this space is outside its list (§3.5).
    SpaceNotDelegated,
    /// The socket is at its concurrency cap.
    Busy,
    /// The object does not load, link or compile.
    ProgramInvalid,
    /// The callee has no eBPF runtime on this platform.
    Unsupported,
}

impl RefuseCode {
    /// A short, stable machine-readable name, for logs and `synch connect`.
    pub fn as_str(self) -> &'static str {
        match self {
            RefuseCode::NoSuchPath => "no-such-path",
            RefuseCode::NotASocket => "not-a-socket",
            RefuseCode::NotArmed => "not-armed",
            RefuseCode::Unauthorized => "unauthorized",
            RefuseCode::SpaceNotDelegated => "space-not-delegated",
            RefuseCode::Busy => "busy",
            RefuseCode::ProgramInvalid => "program-invalid",
            RefuseCode::Unsupported => "unsupported",
        }
    }
}

/// The callee's answer to a [`SockOpen`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SockOpened {
    /// Accepted; raw bytes follow in both directions.
    Ok {
        /// The content root actually running.
        ///
        /// Echoed so the caller can audit what it reached: with arming keyed by
        /// content root, "which program answered me?" has an exact answer and
        /// the protocol may as well give it.
        program: Hash,
        /// The callee's id for this invocation, as `synch socket ps` prints it.
        invocation: u64,
    },
    /// Refused; the stream carries nothing further.
    Refused {
        /// Why.
        code: RefuseCode,
        /// A human-readable elaboration, bounded at `MAX_REFUSE_MESSAGE_LEN`.
        #[serde(deserialize_with = "bounded_message")]
        message: String,
    },
}

/// How an invocation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SockStatus {
    /// The program returned this value.
    Ok(i64),
    /// The program faulted and was contained.
    Fault(FaultKind),
    /// `synch socket kill`.
    Killed,
    /// The daemon is shutting down.
    Shutdown,
    /// The idle deadline expired with no readiness and no progress.
    Deadline,
}

impl SockStatus {
    /// The process exit code `synch connect` reports for this status.
    ///
    /// A clean return is the program's own value, truncated to a byte the way
    /// every other exit status is. Everything else is a distinct code above the
    /// range a shell reads as "the command ran and said no".
    pub fn exit_code(self) -> i32 {
        match self {
            SockStatus::Ok(n) => (n & 0xff) as i32,
            SockStatus::Fault(_) => 70,
            SockStatus::Killed => 71,
            SockStatus::Shutdown => 72,
            SockStatus::Deadline => 73,
        }
    }
}

/// What kind of fault ended an invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    /// A guest memory access landed in a guard region.
    Memory,
    /// A helper refused, and the runtime could not continue.
    Helper,
    /// The program could not be loaded, linked or compiled.
    Load,
    /// A documented per-invocation bound was exceeded.
    Limit,
}

/// A completed invocation, pushed on the connection's control uni-stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SockClosed {
    /// The QUIC stream id the invocation ran on.
    pub stream_id: u64,
    /// How it ended.
    pub status: SockStatus,
}

/// Why a [`SockOpen`] was rejected before it reached any policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// The protocol version is not one this build speaks.
    #[error("socket protocol version {0}, not the {SOCK_PROTO_VERSION} this build speaks")]
    Version(u8),
    /// The space name is not a legal one.
    #[error("invalid space name: {0}")]
    Space(String),
    /// The path is not a legal relative path.
    #[error("invalid path: {0}")]
    Path(String),
    /// The metadata exceeds its documented bounds.
    #[error("metadata exceeds its bounds: {0}")]
    Meta(&'static str),
}

impl SockOpen {
    /// Builds an `Open` for a socket on `origin`.
    pub fn new(
        origin: OriginId,
        space: impl Into<String>,
        path: impl Into<String>,
        meta: Vec<(String, String)>,
    ) -> Self {
        SockOpen {
            v: SOCK_PROTO_VERSION,
            origin,
            space: space.into(),
            path: path.into(),
            meta,
        }
    }

    /// Checks everything about this frame that can be checked without knowing
    /// anything about the node it arrived at.
    ///
    /// Deliberately separate from the policy checks in `synch-net`: this is the
    /// syntactic gate, and it runs first so that a malformed frame never
    /// reaches code that would have to reason about a path with `..` in it.
    pub fn validate(&self) -> Result<(), OpenError> {
        if self.v != SOCK_PROTO_VERSION {
            return Err(OpenError::Version(self.v));
        }
        crate::record::validate_space(&self.space).map_err(|e| OpenError::Space(format!("{e}")))?;
        crate::path::normalize_path(&self.path).map_err(|e| OpenError::Path(format!("{e}")))?;
        if self.meta.len() > MAX_OPEN_META_PAIRS {
            return Err(OpenError::Meta("too many pairs"));
        }
        let bytes: usize = self.meta.iter().map(|(k, v)| k.len() + v.len()).sum();
        if bytes > MAX_OPEN_META_BYTES {
            return Err(OpenError::Meta("too many bytes"));
        }
        Ok(())
    }
}

/// The most destinations one program may declare.
pub const MAX_DECLARED_EGRESS: usize = 32;

/// The most exact process capabilities one program may declare.
pub const MAX_DECLARED_PROCESSES: usize = 16;

/// The most file-transfer capabilities one program may declare.
pub const MAX_DECLARED_FILE_TRANSFERS: usize = 16;

/// The most tree-write capabilities one program may declare.
pub const MAX_DECLARED_TREE_WRITES: usize = 16;

/// The most arguments in an exact process declaration.
pub const MAX_PROCESS_ARGS: usize = 8;

/// The most bytes in one process argument.
pub const MAX_PROCESS_ARG_BYTES: usize = 128;

/// The most bytes in an exact executable path or file-transfer scope.
pub const MAX_CAPABILITY_PATH_BYTES: usize = 256;

/// An exact process capability embedded in a socket program.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProcessCapability {
    /// Program-local, nonzero identifier.
    pub id: u32,
    /// `SY_PROCESS_ALLOW_*` bits.
    pub flags: u32,
    /// Exact absolute executable path.
    pub executable: String,
    /// Exact argv, including `argv[0]`.
    pub argv: Vec<String>,
    /// `SY_PROCESS_SIGNAL_*` bits.
    pub allowed_signals: u64,
}

/// A scoped built-in file-transfer capability embedded in a socket program.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileTransferCapability {
    /// Program-local, nonzero identifier.
    pub id: u32,
    /// Protocol selector, initially `SY_FILE_TRANSFER_SFTP`.
    pub protocol: u32,
    /// `SY_FILE_TRANSFER_*` access bits.
    pub access: u32,
    /// Exact normalized tree scope.
    pub scope: String,
}

/// The program may publish a path where this node holds no live version of
/// its own.
pub const TREE_WRITE_CREATE: u32 = 0x01;
/// The program may publish over this node's own live version of a path.
pub const TREE_WRITE_REPLACE: u32 = 0x02;
/// The program may publish this node's tombstone for a path.
pub const TREE_WRITE_DELETE: u32 = 0x04;

/// Bytes one tree-write commit may stage when the declaration names no bound.
///
/// Modest on purpose: staged bytes cost the callee disk before any
/// operator-visible record exists, so a larger appetite has to be declared —
/// and an unbounded one (`max_bytes: 0`) is printed loudly at the arm prompt.
pub const DEFAULT_TREE_WRITE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// A prefix-scoped tree-write capability embedded in a socket program
/// (`docs/TREE-WRITES.md` §3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TreeWriteCapability {
    /// Program-local, nonzero identifier.
    pub id: u32,
    /// `TREE_WRITE_*` mode bits.
    pub modes: u32,
    /// Normalized tree prefix the grant covers: `space`, or `space/dir`.
    ///
    /// Matched by path component, never by string prefix — `code/inbox` does
    /// not admit `code/inbox-evil` — and there is no way to spell "every
    /// space": a prefix begins with a space id or the declaration is invalid.
    pub prefix: String,
    /// The most bytes one commit may stage. `0` means unbounded.
    pub max_bytes: u64,
}

impl TreeWriteCapability {
    /// Whether this grant covers `path`, by whole path components.
    pub fn covers(&self, path: &str) -> bool {
        path == self.prefix
            || (path.len() > self.prefix.len()
                && path.starts_with(&self.prefix)
                && path.as_bytes()[self.prefix.len()] == b'/')
    }

    /// The declared modes as the arm prompt and `synch socket ls` name them.
    pub fn mode_names(&self) -> String {
        let mut names = Vec::new();
        if self.modes & TREE_WRITE_CREATE != 0 {
            names.push("create");
        }
        if self.modes & TREE_WRITE_REPLACE != 0 {
            names.push("replace");
        }
        if self.modes & TREE_WRITE_DELETE != 0 {
            names.push("delete");
        }
        names.join(", ")
    }
}

/// The most UTF-8 bytes one human-readable declaration value may carry.
///
/// Declaration text is both an approval surface and persisted policy input.
/// Keeping each value small bounds that surface independently of the guest's
/// stack size.
pub(crate) const MAX_DECLARATION_VALUE_BYTES: usize = 4096;

/// The local-call frame size used when a socket does not declare another one.
pub const DEFAULT_EBPF_STACK_FRAME_SIZE: u32 = 16 * 1024;

/// Smallest local-call frame async-ebpf accepts.
pub(crate) const MIN_EBPF_STACK_FRAME_SIZE: u32 = 16;

/// Largest local-call frame a socket may request.
///
/// At eight frames this keeps one invocation's frame storage at 256 KiB.
pub const MAX_EBPF_STACK_FRAME_SIZE: u32 = 32 * 1024;

/// Alignment required by async-ebpf's local-call ABI.
pub(crate) const EBPF_STACK_FRAME_ALIGNMENT: u32 = 16;

/// Whether `size` is a local-call frame size the socket runtime can load.
pub fn valid_ebpf_stack_frame_size(size: u32) -> bool {
    (MIN_EBPF_STACK_FRAME_SIZE..=MAX_EBPF_STACK_FRAME_SIZE).contains(&size)
        && size.is_multiple_of(EBPF_STACK_FRAME_ALIGNMENT)
}

/// Why a program declaration cannot be reviewed or armed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationError {
    /// One value is too large to present safely to an operator.
    #[error("{field} is longer than {MAX_DECLARATION_VALUE_BYTES} bytes")]
    TooLong {
        /// Which declaration field was invalid.
        field: &'static str,
    },
    /// One value contains terminal or line-control text.
    #[error("{field} contains a control or directional-formatting character")]
    UnsafeText {
        /// Which declaration field was invalid.
        field: &'static str,
    },
    /// More values were supplied than the declaration format permits.
    #[error("too many {field} values")]
    TooMany {
        /// Which repeated declaration field exceeded its bound.
        field: &'static str,
    },
    /// The requested eBPF local-call frame cannot be represented by the runtime.
    #[error(
        "stack-frame-size must be a multiple of {EBPF_STACK_FRAME_ALIGNMENT} from \
         {MIN_EBPF_STACK_FRAME_SIZE} through {MAX_EBPF_STACK_FRAME_SIZE} bytes"
    )]
    InvalidStackFrameSize,
    /// A structured backing capability was malformed or duplicated.
    #[error("invalid {kind} capability: {reason}")]
    InvalidCapability {
        /// Capability family.
        kind: &'static str,
        /// Validation failure.
        reason: &'static str,
    },
}

/// Whether text may be displayed verbatim in an operator-facing line.
///
/// Besides ASCII/C0 controls, Unicode directional formatting is excluded: it
/// can visually reorder otherwise printable capability text. Callers that need
/// arbitrary bytes must encode them rather than presenting them as a trusted
/// line.
pub fn display_text_is_safe(value: &str) -> bool {
    value.len() <= MAX_DECLARATION_VALUE_BYTES && value.chars().all(display_char_is_safe)
}

fn display_char_is_safe(c: char) -> bool {
    !c.is_control()
        && !matches!(
            c,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn validate_declaration_value(field: &'static str, value: &str) -> Result<(), DeclarationError> {
    if value.len() > MAX_DECLARATION_VALUE_BYTES {
        return Err(DeclarationError::TooLong { field });
    }
    if !display_text_is_safe(value) {
        return Err(DeclarationError::UnsafeText { field });
    }
    Ok(())
}

fn escaped_declaration_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        if display_char_is_safe(c) {
            escaped.push(c);
        } else {
            escaped.extend(c.escape_default());
        }
    }
    escaped
}

/// What a program's `synchronicity.init` hook said about itself
/// (`docs/SOCKETS.md` §3.1).
///
/// The point of the hook is that an approval which says only "these bytes are
/// fine" asks the operator to read eBPF. This is the list they are shown
/// instead. It is compiled into the object, so editing it changes the content
/// root, which disarms the socket: a program cannot widen its own reach
/// without a fresh approval.
///
/// Arming approves these capabilities for this exact program root. Egress the
/// program did not declare remains denied. Reading the tree is not declared and
/// not restricted (`docs/SOCKETS.md` §7.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Declaration {
    /// A human name, for `synch socket ls` and `synch socket ps`.
    pub name: String,
    /// Destinations, as `host` or `host:port`. A bare host is any port on it.
    pub egress: Vec<String>,
    /// Exact process capabilities local to this program root.
    pub processes: Vec<ProcessCapability>,
    /// Exact file-transfer capabilities local to this program root.
    pub file_transfers: Vec<FileTransferCapability>,
    /// Prefix-scoped tree-write capabilities local to this program root.
    pub tree_writes: Vec<TreeWriteCapability>,
    /// A self-imposed concurrency cap, bounded by operator and daemon caps.
    pub max_streams: Option<u32>,
    /// Bytes in each eBPF local-call frame; absent means the 16 KiB default.
    pub stack_frame_size: Option<u32>,
    /// Whether inaccessible host-page gaps must separate local-call frames.
    pub guarded_stack_frames: Option<bool>,
}

impl Declaration {
    /// Checks that this declaration is bounded, line-safe, and suitable for
    /// both operator review and persisted policy.
    pub fn validate(&self) -> Result<(), DeclarationError> {
        if self.egress.len() > MAX_DECLARED_EGRESS {
            return Err(DeclarationError::TooMany { field: "egress" });
        }
        if self.processes.len() > MAX_DECLARED_PROCESSES {
            return Err(DeclarationError::TooMany { field: "process" });
        }
        if self.file_transfers.len() > MAX_DECLARED_FILE_TRANSFERS {
            return Err(DeclarationError::TooMany {
                field: "file-transfer",
            });
        }
        validate_declaration_value("name", &self.name)?;
        for host in &self.egress {
            validate_declaration_value("egress", host)?;
        }
        let mut process_ids = std::collections::BTreeSet::new();
        for process in &self.processes {
            if process.id == 0 || !process_ids.insert(process.id) {
                return Err(DeclarationError::InvalidCapability {
                    kind: "process",
                    reason: "id must be nonzero and unique",
                });
            }
            if process.flags == 0 || process.flags & !0x03 != 0 {
                return Err(DeclarationError::InvalidCapability {
                    kind: "process",
                    reason: "unsupported flags",
                });
            }
            if process.allowed_signals & !0x07 != 0 {
                return Err(DeclarationError::InvalidCapability {
                    kind: "process",
                    reason: "unsupported signal",
                });
            }
            if !process.executable.starts_with('/')
                || process.executable.len() > MAX_CAPABILITY_PATH_BYTES
                || !display_text_is_safe(&process.executable)
            {
                return Err(DeclarationError::InvalidCapability {
                    kind: "process",
                    reason: "executable must be a safe absolute path of at most 256 bytes",
                });
            }
            if process.argv.is_empty() || process.argv.len() > MAX_PROCESS_ARGS {
                return Err(DeclarationError::InvalidCapability {
                    kind: "process",
                    reason: "argv must contain one through eight arguments",
                });
            }
            if process.argv.iter().any(|arg| {
                arg.len() > MAX_PROCESS_ARG_BYTES
                    || arg.as_bytes().contains(&0)
                    || !display_text_is_safe(arg)
            }) {
                return Err(DeclarationError::InvalidCapability {
                    kind: "process",
                    reason: "argument is unsafe or longer than 128 bytes",
                });
            }
        }
        let mut transfer_ids = std::collections::BTreeSet::new();
        for transfer in &self.file_transfers {
            if transfer.id == 0 || !transfer_ids.insert(transfer.id) {
                return Err(DeclarationError::InvalidCapability {
                    kind: "file-transfer",
                    reason: "id must be nonzero and unique",
                });
            }
            if transfer.protocol != 0x01
                || transfer.access & 0x01 == 0
                || transfer.access & !0x05 != 0
            {
                return Err(DeclarationError::InvalidCapability {
                    kind: "file-transfer",
                    reason: "unsupported protocol or access flags",
                });
            }
            if transfer.scope.len() > MAX_CAPABILITY_PATH_BYTES
                || !display_text_is_safe(&transfer.scope)
                || crate::normalize_path(&transfer.scope).as_deref() != Ok(transfer.scope.as_str())
            {
                return Err(DeclarationError::InvalidCapability {
                    kind: "file-transfer",
                    reason: "scope must be a safe normalized tree path of at most 256 bytes",
                });
            }
        }
        if self.tree_writes.len() > MAX_DECLARED_TREE_WRITES {
            return Err(DeclarationError::TooMany {
                field: "tree-write",
            });
        }
        let mut write_ids = std::collections::BTreeSet::new();
        for write in &self.tree_writes {
            if write.id == 0 || !write_ids.insert(write.id) {
                return Err(DeclarationError::InvalidCapability {
                    kind: "tree-write",
                    reason: "id must be nonzero and unique",
                });
            }
            if write.modes == 0 || write.modes & !0x07 != 0 {
                return Err(DeclarationError::InvalidCapability {
                    kind: "tree-write",
                    reason: "unsupported modes",
                });
            }
            if write.prefix.len() > MAX_CAPABILITY_PATH_BYTES
                || !display_text_is_safe(&write.prefix)
                || crate::normalize_path(&write.prefix).as_deref() != Ok(write.prefix.as_str())
            {
                return Err(DeclarationError::InvalidCapability {
                    kind: "tree-write",
                    reason: "prefix must be a safe normalized tree path of at most 256 bytes",
                });
            }
        }
        if self
            .stack_frame_size
            .is_some_and(|size| !valid_ebpf_stack_frame_size(size))
        {
            return Err(DeclarationError::InvalidStackFrameSize);
        }
        Ok(())
    }

    /// Renders the declaration as the stable text an approval is stored as.
    ///
    /// Line-oriented and sorted within each kind, so two runs of the same hook
    /// produce the same text and `synch socket ls` can diff what was approved
    /// against what is claimed now without the diff being an artifact of
    /// ordering.
    pub fn render(&self) -> String {
        let mut out = Vec::new();
        if !self.name.is_empty() {
            out.push(format!("name {}", escaped_declaration_value(&self.name)));
        }
        let mut egress = self.egress.clone();
        egress.sort();
        egress.dedup();
        for host in egress {
            out.push(format!("egress {}", escaped_declaration_value(&host)));
        }
        let mut processes = self.processes.clone();
        processes.sort_by_key(|capability| capability.id);
        for capability in processes {
            let encoded = serde_json::to_string(&capability)
                .expect("a process declaration contains only serializable values");
            out.push(format!("process {encoded}"));
        }
        let mut transfers = self.file_transfers.clone();
        transfers.sort_by_key(|capability| capability.id);
        for capability in transfers {
            let encoded = serde_json::to_string(&capability)
                .expect("a file-transfer declaration contains only serializable values");
            out.push(format!("file-transfer {encoded}"));
        }
        let mut writes = self.tree_writes.clone();
        writes.sort_by_key(|capability| capability.id);
        for capability in writes {
            let encoded = serde_json::to_string(&capability)
                .expect("a tree-write declaration contains only serializable values");
            out.push(format!("tree-write {encoded}"));
        }
        if let Some(n) = self.max_streams {
            out.push(format!("max-streams {n}"));
        }
        if let Some(n) = self.stack_frame_size {
            out.push(format!("stack-frame-size {n}"));
        }
        if let Some(enabled) = self.guarded_stack_frames {
            let value = if enabled { "enabled" } else { "disabled" };
            out.push(format!("guarded-stack-frames {value}"));
        }
        out.join("\n")
    }

    /// Parses what [`Declaration::render`] wrote.
    ///
    /// Unknown directives are kept out of the parsed result rather than
    /// refused: an approval stored by a later build must still be *readable* by
    /// this one, and what it cannot understand it must not silently treat as
    /// permission.
    pub fn parse(text: &str) -> Declaration {
        let mut out = Declaration::default();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            match line.split_once(' ') {
                Some(("name", v)) if display_text_is_safe(v) => out.name = v.to_string(),
                Some(("egress", v))
                    if out.egress.len() < MAX_DECLARED_EGRESS && display_text_is_safe(v) =>
                {
                    out.egress.push(v.to_string())
                }
                Some(("process", v)) if out.processes.len() < MAX_DECLARED_PROCESSES => {
                    if let Ok(capability) = serde_json::from_str(v) {
                        out.processes.push(capability);
                    }
                }
                Some(("file-transfer", v))
                    if out.file_transfers.len() < MAX_DECLARED_FILE_TRANSFERS =>
                {
                    if let Ok(capability) = serde_json::from_str(v) {
                        out.file_transfers.push(capability);
                    }
                }
                Some(("tree-write", v)) if out.tree_writes.len() < MAX_DECLARED_TREE_WRITES => {
                    if let Ok(capability) = serde_json::from_str(v) {
                        out.tree_writes.push(capability);
                    }
                }
                Some(("max-streams", v)) => out.max_streams = v.parse().ok(),
                Some(("stack-frame-size", v)) => {
                    out.stack_frame_size =
                        v.parse().ok().filter(|n| valid_ebpf_stack_frame_size(*n))
                }
                Some(("guarded-stack-frames", "enabled")) => out.guarded_stack_frames = Some(true),
                Some(("guarded-stack-frames", "disabled")) => {
                    out.guarded_stack_frames = Some(false)
                }
                _ => {}
            }
        }
        out
    }
}

/// True if a declared egress rule admits `host:port`.
///
/// A rule is `host` or `host:port`. Host comparison is ASCII-case-insensitive
/// because DNS is, and exact otherwise: no wildcards, no suffix matching. A
/// rule admitting `*.internal` would be a rule whose blast radius changes when
/// somebody else registers a name, and these lists are short by construction.
pub fn egress_rule_matches(rule: &str, host: &str, port: u16) -> bool {
    // Split from the right, and only when what follows is digits: an IPv6
    // literal is written `[::1]:9418`, and splitting from the left would cut it
    // at the first colon of the address itself.
    let (rule_host, rule_port) = match rule.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => {
            let Ok(port) = p.parse::<u16>() else {
                return false;
            };
            (h, Some(port))
        }
        _ => (rule, None),
    };
    let strip = |s: &str| s.trim_matches(['[', ']']).to_string();
    strip(rule_host).eq_ignore_ascii_case(&strip(host))
        && rule_port.is_none_or(|declared| declared == port)
}

/// Decodes [`SockOpen::meta`] under [`MAX_OPEN_META_PAIRS`].
///
/// Applied *during* the decode, like `AdState`'s span cap: a `Vec` that has
/// already been deserialized has already cost what the bound was meant to deny.
/// Pairs past the cap are read and dropped so the rest of the frame still
/// decodes — the frame is bounded at [`MAX_OPEN_FRAME_LEN`] by the caller, so
/// what is being dropped is small by construction and dropping it keeps a
/// clumsy client's connection working rather than failing it at the handshake.
fn bounded_meta<'de, D>(deserializer: D) -> std::result::Result<Vec<(String, String)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<(String, String)>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "at most {MAX_OPEN_META_PAIRS} metadata pairs")
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_OPEN_META_PAIRS));
            while let Some(pair) = seq.next_element::<(String, String)>()? {
                if out.len() < MAX_OPEN_META_PAIRS {
                    out.push(pair);
                }
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(Visitor)
}

/// Decodes a refusal message under [`MAX_REFUSE_MESSAGE_LEN`], truncating on a
/// character boundary rather than failing: a refusal that cannot be read is
/// worse than one that is cut short.
fn bounded_message<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut s = String::deserialize(deserializer)?;
    if s.len() > MAX_REFUSE_MESSAGE_LEN {
        let mut end = MAX_REFUSE_MESSAGE_LEN;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> OriginId {
        OriginId::named("nas", "cluster.example.com").unwrap()
    }

    fn open() -> SockOpen {
        SockOpen::new(origin(), "code", "git.sock", vec![])
    }

    #[test]
    fn round_trips() {
        for msg in [
            open(),
            SockOpen::new(
                origin(),
                "code",
                "a/b/c.sock",
                vec![("user".into(), "zoe".into())],
            ),
        ] {
            let bytes = postcard::to_stdvec(&msg).unwrap();
            assert_eq!(postcard::from_bytes::<SockOpen>(&bytes).unwrap(), msg);
        }

        for msg in [
            SockOpened::Ok {
                program: Hash::new(b"elf"),
                invocation: 7,
            },
            SockOpened::Refused {
                code: RefuseCode::NotArmed,
                message: "armed at 9f86, tree has aa11".into(),
            },
        ] {
            let bytes = postcard::to_stdvec(&msg).unwrap();
            assert_eq!(postcard::from_bytes::<SockOpened>(&bytes).unwrap(), msg);
        }

        for status in [
            SockStatus::Ok(0),
            SockStatus::Ok(-1),
            SockStatus::Fault(FaultKind::Memory),
            SockStatus::Killed,
            SockStatus::Shutdown,
            SockStatus::Deadline,
        ] {
            let msg = SockClosed {
                stream_id: 12,
                status,
            };
            let bytes = postcard::to_stdvec(&msg).unwrap();
            assert_eq!(postcard::from_bytes::<SockClosed>(&bytes).unwrap(), msg);
        }
    }

    #[test]
    fn a_legal_open_fits_the_frame_bound() {
        // No honest caller can build a frame its peer refuses: the largest
        // legal `Open` has to fit, or the bound is a wedge rather than a guard.
        let meta = (0..MAX_OPEN_META_PAIRS)
            .map(|i| {
                let half = MAX_OPEN_META_BYTES / MAX_OPEN_META_PAIRS / 2;
                (format!("{i:0half$}", half = half), "v".repeat(half))
            })
            .collect();
        let big = SockOpen::new(origin(), "code", "x".repeat(crate::MAX_KEY_LEN - 8), meta);
        big.validate().unwrap();
        assert!(
            postcard::to_stdvec(&big).unwrap().len() <= MAX_OPEN_FRAME_LEN,
            "the largest legal Open does not fit MAX_OPEN_FRAME_LEN"
        );
    }

    #[test]
    fn validation_refuses_what_the_resolver_must_never_see() {
        let mut o = open();
        o.v = SOCK_PROTO_VERSION + 1;
        assert!(matches!(o.validate(), Err(OpenError::Version(_))));

        let mut o = open();
        o.path = "../../etc/passwd".into();
        assert!(matches!(o.validate(), Err(OpenError::Path(_))));

        // A space name may hold a space character — `validate_space` bars only
        // the empty string, `/`, control characters and over-length. The one
        // that matters here is `/`, which would otherwise let a caller reach
        // out of the space it named and into the key of another.
        let mut o = open();
        o.space = "code/../secrets".into();
        assert!(matches!(o.validate(), Err(OpenError::Space(_))));

        let mut o = open();
        o.meta = vec![("k".into(), "v".repeat(MAX_OPEN_META_BYTES))];
        assert!(matches!(o.validate(), Err(OpenError::Meta(_))));
    }

    #[test]
    fn oversized_meta_is_dropped_during_the_decode() {
        // Built by hand rather than through `SockOpen`, because `validate`
        // refuses it — the point is that the *decoder* bounds the allocation
        // before any validation runs.
        #[derive(Serialize)]
        struct Unbounded {
            v: u8,
            origin: OriginId,
            space: String,
            path: String,
            meta: Vec<(String, String)>,
        }
        let bytes = postcard::to_stdvec(&Unbounded {
            v: SOCK_PROTO_VERSION,
            origin: origin(),
            space: "code".into(),
            path: "git.sock".into(),
            meta: (0..MAX_OPEN_META_PAIRS * 4)
                .map(|i| (format!("k{i}"), String::new()))
                .collect(),
        })
        .unwrap();
        let decoded: SockOpen = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.meta.len(), MAX_OPEN_META_PAIRS);
    }

    #[test]
    fn egress_rules_match_host_and_port_exactly() {
        assert!(egress_rule_matches(
            "git.internal:9418",
            "git.internal",
            9418
        ));
        assert!(
            !egress_rule_matches("git.internal:9418", "git.internal", 22),
            "a declared port was ignored"
        );
        // A bare host allows any port on it.
        assert!(egress_rule_matches(
            "cache.internal",
            "cache.internal",
            6379
        ));
        assert!(
            egress_rule_matches("CACHE.INTERNAL", "cache.internal", 80),
            "DNS is case-insensitive and this comparison is not"
        );
        assert!(
            !egress_rule_matches("cache.internal:99999", "cache.internal", 80),
            "an invalid numeric port became an unrestricted host rule"
        );
        // No suffix matching: a rule whose reach changes when somebody else
        // registers a name is not a rule.
        assert!(!egress_rule_matches(
            "git.internal",
            "evil-git.internal",
            80
        ));
        assert!(!egress_rule_matches(
            "git.internal",
            "git.internal.evil",
            80
        ));
    }

    #[test]
    fn an_ipv6_literal_rule_is_not_cut_at_its_first_colon() {
        assert!(egress_rule_matches("[::1]:9418", "::1", 9418));
        assert!(!egress_rule_matches("[::1]:9418", "::1", 9419));
        assert!(egress_rule_matches("[fe80::1]", "fe80::1", 443));
    }

    #[test]
    fn a_declaration_round_trips_through_its_stored_text() {
        let d = Declaration {
            name: "git-http".into(),
            egress: vec!["git.internal:9418".into(), "cache.internal".into()],
            processes: vec![],
            file_transfers: vec![],
            tree_writes: vec![],
            max_streams: Some(32),
            stack_frame_size: Some(512),
            guarded_stack_frames: Some(false),
        };
        let parsed = Declaration::parse(&d.render());
        // `render` sorts, so compare against a sorted original rather than
        // asserting an ordering the renderer deliberately does not preserve.
        let mut expected = d.clone();
        expected.egress.sort();
        assert_eq!(parsed, expected);
        assert_eq!(
            parsed.render(),
            d.render(),
            "rendering is not stable across a round trip"
        );
    }

    #[test]
    fn declaration_values_cannot_inject_or_conceal_capabilities() {
        // A newline in one value must not become a second directive.
        let injected = Declaration {
            name: "benign\negress evil.example:443".into(),
            ..Declaration::default()
        };
        assert!(matches!(
            injected.validate(),
            Err(DeclarationError::UnsafeText { .. })
        ));

        let rendered = injected.render();
        assert_eq!(rendered.lines().count(), 1, "the name spanned two lines");
        let reparsed = Declaration::parse(&rendered);
        assert!(reparsed.egress.is_empty(), "a name became an egress rule");

        // And a control character is refused, and never reaches the rendered
        // text an operator reads at the arm prompt.
        let control = Declaration {
            egress: vec!["public\u{1b}[2J".into()],
            ..Declaration::default()
        };
        assert!(control.validate().is_err());
        assert!(!control.render().contains('\u{1b}'));

        let directional = Declaration {
            name: "safe-looking\u{202e}txt".into(),
            ..Declaration::default()
        };
        assert!(directional.validate().is_err());
    }

    #[test]
    fn an_unreadable_directive_is_not_read_as_permission() {
        // An approval written by a later build must stay readable, and what
        // this build cannot understand it must not treat as a grant.
        let parsed = Declaration::parse("name x\nudp-egress anywhere:53\negress git:9418");
        assert_eq!(parsed.egress, vec!["git:9418".to_string()]);
        assert!(!parsed
            .egress
            .iter()
            .any(|rule| egress_rule_matches(rule, "anywhere", 53)));
    }

    #[test]
    fn a_declaration_cannot_grow_past_its_bounds_through_its_text() {
        let text = (0..MAX_DECLARED_EGRESS * 4)
            .map(|i| format!("egress h{i}.example:80"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(Declaration::parse(&text).egress.len(), MAX_DECLARED_EGRESS);
    }

    #[test]
    fn invalid_stack_frame_sizes_are_not_accepted_from_stored_text() {
        for size in [0, 15, 17, MAX_EBPF_STACK_FRAME_SIZE + 16] {
            let parsed = Declaration::parse(&format!("stack-frame-size {size}"));
            assert_eq!(parsed.stack_frame_size, None, "accepted {size}");
        }
        assert_eq!(
            Declaration::parse("stack-frame-size 512").stack_frame_size,
            Some(512)
        );
        assert!(matches!(
            Declaration {
                stack_frame_size: Some(17),
                ..Declaration::default()
            }
            .validate(),
            Err(DeclarationError::InvalidStackFrameSize)
        ));
    }

    #[test]
    fn guarded_stack_frame_choice_round_trips_only_known_values() {
        assert_eq!(
            Declaration::parse("guarded-stack-frames disabled").guarded_stack_frames,
            Some(false)
        );
        assert_eq!(
            Declaration::parse("guarded-stack-frames enabled").guarded_stack_frames,
            Some(true)
        );
        assert_eq!(
            Declaration::parse("guarded-stack-frames perhaps").guarded_stack_frames,
            None
        );
    }

    #[test]
    fn backing_capabilities_round_trip_and_sort_by_local_id() {
        let declaration = Declaration {
            processes: vec![
                ProcessCapability {
                    id: 9,
                    flags: 2,
                    executable: "/usr/bin/printf".into(),
                    argv: vec!["printf".into(), "hello world".into()],
                    allowed_signals: 0,
                },
                ProcessCapability {
                    id: 2,
                    flags: 1,
                    executable: "/bin/sh".into(),
                    argv: vec!["sh".into(), "-l".into()],
                    allowed_signals: 7,
                },
            ],
            file_transfers: vec![FileTransferCapability {
                id: 3,
                protocol: 1,
                access: 5,
                scope: "code/releases".into(),
            }],
            ..Declaration::default()
        };
        declaration.validate().unwrap();
        let rendered = declaration.render();
        assert!(rendered.lines().next().unwrap().contains("\"id\":2"));
        let parsed = Declaration::parse(&rendered);
        assert_eq!(parsed.render(), rendered);
        parsed.validate().unwrap();
    }

    #[test]
    fn a_tree_write_capability_round_trips_and_validates_its_shape() {
        let declaration = Declaration {
            tree_writes: vec![TreeWriteCapability {
                id: 1,
                modes: TREE_WRITE_CREATE | TREE_WRITE_DELETE,
                prefix: "code/inbox".into(),
                max_bytes: DEFAULT_TREE_WRITE_MAX_BYTES,
            }],
            ..Declaration::default()
        };
        declaration.validate().unwrap();
        let parsed = Declaration::parse(&declaration.render());
        assert_eq!(parsed, declaration);
        assert_eq!(parsed.tree_writes[0].mode_names(), "create, delete");

        for (modes, prefix) in [
            (0, "code/inbox"),     // no mode at all
            (0x08, "code/inbox"),  // an unknown mode bit
            (0x01, "../etc"),      // not a normalized tree path
            (0x01, "code/inbox/"), // not normalized either
            (0x01, ""),            // no space to begin the prefix
        ] {
            let bad = Declaration {
                tree_writes: vec![TreeWriteCapability {
                    id: 1,
                    modes,
                    prefix: prefix.into(),
                    max_bytes: 0,
                }],
                ..Declaration::default()
            };
            assert!(
                matches!(
                    bad.validate(),
                    Err(DeclarationError::InvalidCapability {
                        kind: "tree-write",
                        ..
                    })
                ),
                "accepted modes {modes:#x} prefix {prefix:?}"
            );
        }
    }

    #[test]
    fn a_tree_write_prefix_matches_by_component_not_by_string() {
        let grant = TreeWriteCapability {
            id: 1,
            modes: TREE_WRITE_CREATE,
            prefix: "code/inbox".into(),
            max_bytes: 0,
        };
        assert!(grant.covers("code/inbox"));
        assert!(grant.covers("code/inbox/report.txt"));
        assert!(grant.covers("code/inbox/deep/er"));
        assert!(!grant.covers("code/inbox-evil"), "a string prefix matched");
        assert!(!grant.covers("code"));
        assert!(!grant.covers("media/inbox/x"));

        let space_wide = TreeWriteCapability {
            prefix: "code".into(),
            ..grant
        };
        assert!(space_wide.covers("code/anything/at/all"));
        assert!(!space_wide.covers("codex/anything"));
    }

    #[test]
    fn duplicate_capability_ids_are_rejected_within_their_family() {
        let process = ProcessCapability {
            id: 1,
            flags: 2,
            executable: "/bin/true".into(),
            argv: vec!["true".into()],
            allowed_signals: 0,
        };
        let declaration = Declaration {
            processes: vec![process.clone(), process],
            ..Declaration::default()
        };
        assert!(matches!(
            declaration.validate(),
            Err(DeclarationError::InvalidCapability {
                kind: "process",
                ..
            })
        ));
    }

    #[test]
    fn a_status_exit_code_distinguishes_the_program_from_the_runtime() {
        assert_eq!(SockStatus::Ok(0).exit_code(), 0);
        assert_eq!(SockStatus::Ok(3).exit_code(), 3);
        assert_eq!(SockStatus::Ok(-1).exit_code(), 255);
        assert_eq!(SockStatus::Fault(FaultKind::Memory).exit_code(), 70);
        assert_ne!(
            SockStatus::Killed.exit_code(),
            SockStatus::Shutdown.exit_code()
        );
    }
}
