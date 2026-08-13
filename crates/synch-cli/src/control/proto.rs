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
//! D→C  Line | Chunk | Progress …    — zero or more
//! D→C  End                          — or Error at any point
//! ```

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use synch_core::MAX_FRAME_LEN;
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
/// change must say so plainly rather than mis-decode each other.
pub const CONTROL_VERSION: u32 = 3;

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
            E::Invalid(_) | E::Key(_) | E::InRecovery { .. } => ErrorCode::Invalid,
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
    /// `synch key activate <key>`
    KeyActivate {
        /// The z-base-32 device key to switch signing to.
        key: String,
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
    /// `synch trust rm <origin>`
    TrustRm {
        /// The origin to stop trusting.
        origin: String,
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
    /// `synch domain refresh`
    DomainRefresh,
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
    /// `synch pin add <root>`
    PinAdd {
        /// The object root, hex.
        root: String,
    },
    /// `synch pin rm <root>`
    PinRm {
        /// The object root, hex.
        root: String,
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
