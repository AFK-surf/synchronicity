//! The control protocol: framing, the handshake, and the request/response
//! schema (§9.3).
//!
//! Framing is a little-endian `u32` length followed by that many bytes of
//! postcard, the same shape the network protocols use (§5.1). The length is
//! checked against [`MAX_FRAME_LEN`] before anything is allocated.
//!
//! A connection carries one command:
//!
//! ```text
//! C→D  Hello    { version, token }
//! D→C  Ready                        — or Error, and the connection ends
//! C→D  Request
//! C→D  Upload …                     — only for a request that streams a payload
//! D→C  Line | Chunk | Entry | …     — zero or more
//! D→C  End                          — or Error at any point
//! ```

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use synch_core::{EntryKind, Hash, MAX_FRAME_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The control protocol version.
///
/// Client and daemon are normally the same binary, so this exists to catch the
/// upgrade-while-running case rather than to support mixed versions (§9.3).
///
/// Bumped to 2 by `synch recover`, which added a [`Request`] variant, and to 3
/// by the unified tree (§8), which gave `cat`/`get` a version policy and
/// re-shaped the `mirror` requests: postcard identifies variants by position
/// and fields by order, so a client and a daemon from either side of such a
/// change must say so plainly rather than mis-decode each other. Bumped to 4
/// when `domain refresh` grew an optional domain and `pin add`/`pin rm` grew a
/// `<space>/<path>` form — both reshape an existing variant's fields. Bumped to
/// 5 by the gateway becoming a control-socket client (§9.4): six structured
/// requests, a client-to-daemon [`Upload`] frame, and a [`Response::Entry`]
/// frame that carries entry metadata rather than a rendered line. Bumped to 6
/// by `synch sync` (a new [`Request`] variant) and by `TreePut` growing a
/// [`Response::Ready`] ack before the client streams. Bumped to 7 when
/// `key activate` grew `--bind` and to 8 when `trust rm` grew `--key` — each
/// a new field reshaping an existing variant.
pub const CONTROL_VERSION: u32 = 8;

/// How many payload bytes one `Chunk` frame carries.
///
/// Small enough that a multi-gigabyte read is never held in memory by either
/// process, large enough that the per-frame cost stays negligible.
pub const CHUNK_SIZE: usize = 256 * 1024;

/// The first frame a client sends: the protocol version and the datadir token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The version the client speaks.
    pub version: u32,
    /// The contents of `<data_dir>/control.token`.
    pub token: Vec<u8>,
}

/// Why a request failed, as it crosses the socket.
///
/// The CLI renders these as its own exit status rather than as a transport
/// error (§9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// The token did not match the daemon's.
    Unauthorized,
    /// Client and daemon speak different control protocol versions.
    VersionMismatch,
    /// The datadir has no identity.
    NotInitialized,
    /// The named origin, space, entry, or key does not exist.
    NotFound,
    /// The request was malformed or not applicable.
    Invalid,
    /// The daemon failed while serving the request.
    Internal,
    /// A `strict` read met a divergent path (§8); the message lists the
    /// versions. Appended last: postcard numbers variants by position.
    Divergent,
    /// The daemon is in a state that cannot serve this request yet, and the
    /// message names what clears it — key-loss recovery (§3.4) is the case
    /// that exists. Neither a malformed request nor a fault: a caller that
    /// renders codes as protocol statuses owes this one a "come back later"
    /// rather than a "you asked wrong".
    Unavailable,
}

impl ErrorCode {
    /// The stable short name used in messages and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::VersionMismatch => "version-mismatch",
            ErrorCode::NotInitialized => "not-initialized",
            ErrorCode::NotFound => "not-found",
            ErrorCode::Invalid => "invalid",
            ErrorCode::Internal => "internal",
            ErrorCode::Divergent => "divergent",
            ErrorCode::Unavailable => "unavailable",
        }
    }
}

/// A structured failure: a code plus a human-readable message (§9.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct ControlError {
    /// What kind of failure this is.
    pub code: ErrorCode,
    /// What went wrong, in the words the CLI prints.
    pub message: String,
}

impl ControlError {
    /// Builds an error with an explicit code.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> ControlError {
        ControlError {
            code,
            message: message.into(),
        }
    }

    /// Builds an [`ErrorCode::Invalid`] error.
    pub fn invalid(message: impl Into<String>) -> ControlError {
        ControlError::new(ErrorCode::Invalid, message)
    }

    /// Builds an [`ErrorCode::Internal`] error.
    pub fn internal(message: impl Into<String>) -> ControlError {
        ControlError::new(ErrorCode::Internal, message)
    }
}

impl From<synch_engine::EngineError> for ControlError {
    fn from(e: synch_engine::EngineError) -> ControlError {
        use synch_engine::EngineError as E;
        let code = match &e {
            E::NotInitialized => ErrorCode::NotInitialized,
            E::NotFound(_) => ErrorCode::NotFound,
            // Divergence is data, not a malformed request: it gets a code of
            // its own so a caller can tell "there are several versions" from
            // "you asked for something impossible" (§8).
            E::Divergent { .. } => ErrorCode::Divergent,
            // A node in recovery is not broken and the request is not
            // malformed; what is wrong is the state it was made in, and the
            // message says which command resolves it (§3.4).
            E::InRecovery { .. } => ErrorCode::Unavailable,
            E::Invalid(_) | E::Key(_) => ErrorCode::Invalid,
            _ => ErrorCode::Internal,
        };
        ControlError::new(code, format!("{e}"))
    }
}

impl From<synch_store::StoreError> for ControlError {
    fn from(e: synch_store::StoreError) -> ControlError {
        ControlError::internal(e.to_string())
    }
}

impl From<synch_mpt::MptError> for ControlError {
    fn from(e: synch_mpt::MptError) -> ControlError {
        ControlError::internal(e.to_string())
    }
}

impl From<std::io::Error> for ControlError {
    fn from(e: std::io::Error) -> ControlError {
        ControlError::internal(format!("io: {e}"))
    }
}

/// One command, as it crosses the socket: one variant per CLI subcommand
/// (§9.2).
///
/// References and keys travel as the text the user typed and are parsed by the
/// daemon, so a parse failure comes back as an ordinary structured error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// `synch id`
    Id,
    /// `synch key rotate`
    KeyRotate,
    /// `synch key activate <key> [--bind <addr>]`
    KeyActivate {
        /// The z-base-32 device key to switch signing to.
        key: String,
        /// The address the new key's endpoint binds, `HOST:PORT`.
        ///
        /// `None` takes an ephemeral port on the configured interface. A
        /// static-address deployment names the next address here — the old
        /// one stays with the retiring endpoint until `key retire` frees it.
        bind: Option<String>,
    },
    /// `synch key retire <key>`
    KeyRetire {
        /// The z-base-32 device key to drop.
        key: String,
    },
    /// `synch key ls`
    KeyLs,
    /// `synch daemon status`
    DaemonStatus,
    /// `synch daemon stop`
    DaemonStop,
    /// `synch trust add`
    TrustAdd {
        /// The peer's z-base-32 device key.
        key: String,
        /// The name to bind it under.
        name: Option<String>,
        /// The membership domain for the named origin.
        domain: Option<String>,
        /// A note for `synch trust ls`.
        note: Option<String>,
        /// A direct address to remember for dialing.
        addr: Option<String>,
    },
    /// `synch trust rebind <origin> <key>`
    TrustRebind {
        /// The origin to rebind.
        origin: String,
        /// Its new z-base-32 device key.
        key: String,
    },
    /// `synch trust rm <origin> [--key <key>]`
    TrustRm {
        /// The origin to stop trusting.
        origin: String,
        /// Drop only this key's binding, keeping the origin's others (§3.4:
        /// the cleanup step after a rotation window closes).
        key: Option<String>,
    },
    /// `synch trust ls`
    TrustLs,
    /// `synch domain add <domain>`
    DomainAdd {
        /// The membership domain.
        domain: String,
    },
    /// `synch domain rm <domain>`
    DomainRm {
        /// The membership domain.
        domain: String,
    },
    /// `synch domain ls`
    DomainLs,
    /// `synch domain refresh [<domain>]`
    DomainRefresh {
        /// The one domain to refresh, or `None` for every configured domain.
        domain: Option<String>,
    },
    /// `synch peers`
    Peers,
    /// `synch space add <id> <path>`
    SpaceAdd {
        /// The space id.
        id: String,
        /// The local directory, already made absolute by the client.
        path: String,
    },
    /// `synch space ls`
    SpaceLs,
    /// `synch space rm <id>`
    SpaceRm {
        /// The space id.
        id: String,
    },
    /// `synch ls [<origin>:]<space>[/<dir>]`
    Ls {
        /// The entry reference. Without an origin, the unified tree (§8).
        reference: String,
        /// Show every version of every path, with its attestors.
        all: bool,
    },
    /// `synch status [<space>[/<path>]]`
    Status {
        /// The reference, or `None` for every known space.
        reference: Option<String>,
    },
    /// `synch cat [<origin>:]<space>/<path>`
    Cat {
        /// The entry reference.
        reference: String,
        /// A byte range, as `START..END`, `START..`, or `..END`.
        range: Option<String>,
        /// `--from <origin>`: read that origin's version.
        from: Option<String>,
        /// `--strict`: refuse a divergent path.
        strict: bool,
    },
    /// `synch get [<origin>:]<space>/<path>`
    Get {
        /// The entry reference.
        reference: String,
        /// `--from <origin>`: fetch that origin's version.
        from: Option<String>,
        /// `--strict`: refuse a divergent path.
        strict: bool,
    },
    /// `synch take <origin>:<space>/<path>`
    Take {
        /// The entry reference.
        reference: String,
    },
    /// `synch log [<origin>:]<space>/<path>`
    Log {
        /// The entry reference.
        reference: String,
    },
    /// `synch compare <space>[/<dir>] --to <origin> [--from <origin>]`
    Compare {
        /// The space and optional directory to compare, as `<space>[/<dir>]`.
        reference: String,
        /// The baseline origin; `None` means this node's own origin.
        from: Option<String>,
        /// The target origin to compare against. Required.
        to: String,
        /// Emit machine-readable JSON instead of the status listing.
        json: bool,
    },
    /// `synch mirror add <space> <dir> [--policy ...]`
    MirrorAdd {
        /// The space of the unified tree to materialize.
        space: String,
        /// The local directory, already made absolute by the client.
        path: String,
        /// The version policy, as the user typed it (§8).
        policy: Option<String>,
    },
    /// `synch mirror rm <dir>`
    MirrorRm {
        /// The local directory, already made absolute by the client.
        path: String,
    },
    /// `synch mirror ls`
    MirrorLs,
    /// `synch mirror sync`
    MirrorSync,
    /// `synch pin add <root>|<space>/<path>`
    PinAdd {
        /// A hex object root, or a `<space>/<path>` whose selected version's
        /// root is pinned (§8).
        target: String,
    },
    /// `synch pin rm <root>|<space>/<path>`
    PinRm {
        /// A hex object root, or a `<space>/<path>` whose selected version's
        /// root is unpinned (§8).
        target: String,
    },
    /// `synch pin ls`
    PinLs,
    /// `synch recover [--wait <dur>] [--gap <n>]`
    Recover {
        /// How long to collect peer summaries, as the user typed it.
        wait: Option<String>,
        /// How far above the highest observed seq to resume publishing.
        gap: Option<u64>,
    },
    /// `synch doctor`
    Doctor {
        /// Rebuild the derived views from the authoritative trie first.
        rebuild: bool,
    },
    /// `synch scan`
    Scan,

    // ---- structured requests (§9.4) ---------------------------------------
    //
    // The variants above answer a CLI subcommand and travel as the text the
    // user typed. These answer a *program* — the S3 gateway, which is a control
    // client and nothing more (§9.1, §9.4) — so they name space, path, and
    // policy as separate fields. An S3 key may contain a colon, which the
    // `[<origin>:]<space>/<path>` text form would read as an origin, so the
    // gateway cannot go through the text parser at all.
    /// The unified listing under a prefix, resolved by a policy (§8): one
    /// [`Response::Entry`] frame per path the policy selects.
    ///
    /// Paths the policy refuses — divergent under `strict`, unpublished by the
    /// pinned origin under `origin=` — are left out rather than answered with
    /// one side's metadata; a direct [`Request::TreeResolve`] of such a path
    /// still says what is wrong.
    TreeList {
        /// The space of the unified tree.
        space: String,
        /// The path prefix to list under, empty for the whole space.
        prefix: String,
        /// Resume after this path, exclusive — a listing cursor.
        start_after: Option<String>,
        /// At most this many paths, before the policy filters them.
        limit: Option<u64>,
        /// The version policy, as `newest`, `origin=<id>`, or `strict`.
        policy: Option<String>,
    },
    /// The version a policy selects for one path, as one [`Response::Entry`]
    /// frame and no content — what `HeadObject` answers from (§9.4).
    TreeResolve {
        /// The space of the unified tree.
        space: String,
        /// The path within the space.
        path: String,
        /// The version policy, as `newest`, `origin=<id>`, or `strict`.
        policy: Option<String>,
    },
    /// A verified byte range of the version a policy selects, streamed as
    /// [`Response::Chunk`] frames.
    TreeRead {
        /// The space of the unified tree.
        space: String,
        /// The path within the space.
        path: String,
        /// The version policy, as `newest`, `origin=<id>`, or `strict`.
        policy: Option<String>,
        /// The first byte to read.
        start: u64,
        /// How many bytes, or `None` to the end of the object.
        len: Option<u64>,
    },
    /// A streamed write into one of this node's own spaces (§7.1, §9.4).
    ///
    /// The daemon takes its gates — publishability, a resolvable target —
    /// and answers [`Response::Ready`] before the first byte; the client
    /// waits for that ack, then follows with [`Upload`] frames. The daemon
    /// writes them into the space directory as they arrive, runs the ordinary
    /// ingest pipeline, and answers with the published entry. Nothing is
    /// buffered whole at either end. The ack is what lets a refusal arrive
    /// as the coded error it is: a client already streaming into a refused
    /// write would instead see the transport fail under it, and on a Windows
    /// named pipe the unread error frame is discarded with the connection.
    TreePut {
        /// The space to write into.
        space: String,
        /// The path within the space.
        path: String,
    },
    /// Reads a config value from the `s3.*` namespace, one
    /// [`Response::Line`] per stored record.
    ConfigGet {
        /// The config key, which must be in the `s3.` namespace.
        key: String,
    },
    /// Appends one record to a config value in the `s3.*` namespace.
    ///
    /// Append, never replace: the gateway's bucket map and access keys are
    /// lists that more than one process reads and writes, and a read-modify-
    /// write of the whole list loses whichever concurrent edit commits first.
    /// One atomic append cannot.
    ConfigAppend {
        /// The config key, which must be in the `s3.` namespace.
        key: String,
        /// The record to append. One line: newlines separate records.
        record: String,
    },
    /// `synch sync` — one push-pull exchange with every dialable peer, now.
    ///
    /// Anti-entropy runs on its jittered interval and owes nobody an early
    /// round; this is the operator saying "I am watching, do one now" — after
    /// a publish they want a peer to see, or in a script that would otherwise
    /// poll `status` until the interval elapses.
    SyncNow,
}

/// One entry of the unified tree, as it crosses the socket (§8).
///
/// The metadata half of a read: what a listing renders and what `HeadObject`
/// answers from, with no content fetched. The content root travels as the hash
/// it is, so a caller that renders it — an S3 ETag, say — does its own
/// formatting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInfo {
    /// The origin whose assertion the policy selected, canonically rendered.
    pub origin: String,
    /// The space the entry lives in.
    pub space: String,
    /// The path within the space.
    pub path: String,
    /// What the entry describes.
    pub kind: EntryKind,
    /// The content length in bytes.
    pub size: u64,
    /// The selected origin's observed mtime, in unix nanoseconds.
    pub mtime_ns: i64,
    /// The object root, for files.
    pub content: Option<Hash>,
    /// The origin trie seq this version was published at.
    pub seq: u64,
    /// The link target, for a symlink.
    pub symlink_target: Option<String>,
    /// How many versions the path carries in the unified tree (§8). One means
    /// every publisher agrees; more means the selection above chose a side.
    pub versions: u32,
}

/// One frame of a payload the *client* streams to the daemon
/// ([`Request::TreePut`]).
///
/// The mirror image of [`Response::Chunk`], and it exists for the same reason:
/// an object of any size has to cross the socket without either process holding
/// more than a chunk of it (§9.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Upload {
    /// A piece of the payload, at most [`CHUNK_SIZE`] bytes.
    Chunk(Vec<u8>),
    /// The payload is complete; the daemon may commit it.
    End,
    /// The client is abandoning the write and the daemon must keep nothing.
    ///
    /// A truncated HTTP body is the case that matters: without a way to say so,
    /// a half-received object would be indistinguishable from a complete one
    /// and would get published as the client's own assertion.
    Abort(String),
}

/// One frame from the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// The handshake was accepted; send the request.
    Ready,
    /// One line of ordinary output.
    Line(String),
    /// A piece of a byte payload (`cat`, `get`).
    Chunk(Vec<u8>),
    /// A progress report the CLI renders and discards (`scan`, `mirror sync`).
    Progress(String),
    /// The response is complete.
    End,
    /// The request failed.
    Error(ControlError),
    /// One entry of the unified tree, as structured metadata (§9.4).
    ///
    /// Boxed because it dwarfs every other variant, and appended last because
    /// postcard numbers variants by position.
    Entry(Box<EntryInfo>),
}

/// Writes one length-framed postcard message.
pub async fn write_frame<T, W>(writer: &mut W, message: &T) -> std::io::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let bytes = postcard::to_stdvec(message)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    if bytes.len() > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("control frame of {} bytes is too large", bytes.len()),
        ));
    }
    writer
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one length-framed postcard message.
///
/// Returns `UnexpectedEof` when the peer closed the connection cleanly between
/// frames, which is how a client that stopped reading is recognized.
pub async fn read_frame<T, R>(reader: &mut R) -> std::io::Result<T>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("control frame of {len} bytes is too large"),
        ));
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut body).await?;
    }
    postcard::from_bytes(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// Compares two tokens without leaking their contents through timing.
pub fn tokens_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip() {
        let mut buffer: Vec<u8> = Vec::new();
        let request = Request::Cat {
            reference: "nas@x:media/a.txt".into(),
            range: Some("0..10".into()),
            from: None,
            strict: false,
        };
        write_frame(&mut buffer, &request).await.unwrap();
        write_frame(&mut buffer, &Response::Chunk(vec![1, 2, 3]))
            .await
            .unwrap();
        write_frame(&mut buffer, &Response::End).await.unwrap();

        let mut reader = buffer.as_slice();
        assert_eq!(
            read_frame::<Request, _>(&mut reader).await.unwrap(),
            request
        );
        assert_eq!(
            read_frame::<Response, _>(&mut reader).await.unwrap(),
            Response::Chunk(vec![1, 2, 3])
        );
        assert_eq!(
            read_frame::<Response, _>(&mut reader).await.unwrap(),
            Response::End
        );
        assert_eq!(
            read_frame::<Response, _>(&mut reader)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused_before_allocating() {
        let mut framed = ((MAX_FRAME_LEN + 1) as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(b"body");
        let err = read_frame::<Response, _>(&mut framed.as_slice())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn token_comparison_is_length_and_content_sensitive() {
        assert!(tokens_match(&[1, 2, 3], &[1, 2, 3]));
        assert!(!tokens_match(&[1, 2, 3], &[1, 2, 4]));
        assert!(!tokens_match(&[1, 2, 3], &[1, 2]));
        assert!(tokens_match(&[], &[]));
    }

    /// The write direction has frames of its own now, and a structured entry
    /// has to survive the same round trip a rendered line does (§9.4).
    #[tokio::test]
    async fn uploads_and_entries_round_trip() {
        let mut buffer: Vec<u8> = Vec::new();
        let request = Request::TreePut {
            space: "media".into(),
            // A colon in a key is exactly what the text reference form cannot
            // carry, which is why these requests are structured.
            path: "uploads/2024:07:01.bin".into(),
        };
        let entry = EntryInfo {
            origin: "nas@cluster.example".into(),
            space: "media".into(),
            path: "uploads/2024:07:01.bin".into(),
            kind: EntryKind::File,
            size: 7,
            mtime_ns: 42,
            content: Some(Hash::new(b"payload")),
            seq: 3,
            symlink_target: None,
            versions: 1,
        };
        write_frame(&mut buffer, &request).await.unwrap();
        write_frame(&mut buffer, &Upload::Chunk(vec![9, 8, 7]))
            .await
            .unwrap();
        write_frame(&mut buffer, &Upload::End).await.unwrap();
        write_frame(&mut buffer, &Response::Entry(Box::new(entry.clone())))
            .await
            .unwrap();

        let mut reader = buffer.as_slice();
        assert_eq!(
            read_frame::<Request, _>(&mut reader).await.unwrap(),
            request
        );
        assert_eq!(
            read_frame::<Upload, _>(&mut reader).await.unwrap(),
            Upload::Chunk(vec![9, 8, 7])
        );
        assert_eq!(
            read_frame::<Upload, _>(&mut reader).await.unwrap(),
            Upload::End
        );
        assert_eq!(
            read_frame::<Response, _>(&mut reader).await.unwrap(),
            Response::Entry(Box::new(entry))
        );
    }

    #[test]
    fn engine_errors_carry_their_kind_across_the_socket() {
        let e: ControlError = synch_engine::EngineError::not_found("nope").into();
        assert_eq!(e.code, ErrorCode::NotFound);
        let e: ControlError = synch_engine::EngineError::invalid("bad").into();
        assert_eq!(e.code, ErrorCode::Invalid);
        assert_eq!(e.message, "bad");
        let e: ControlError = synch_engine::EngineError::NotInitialized.into();
        assert_eq!(e.code, ErrorCode::NotInitialized);
    }
}
