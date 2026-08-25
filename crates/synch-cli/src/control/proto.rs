//! The control protocol: the generated gRPC surface, and the types that cross
//! it in shapes protobuf has no word for (§9.3).
//!
//! The schema lives in `proto/control.proto` and is compiled at build time.
//! [`pb`] is that generated code; everything else here is the seam between it
//! and the rest of the daemon — the error a failure travels as, and the entry
//! metadata rendered back into `synch-core` types.

use synch_core::{EntryKind, Hash};
use tonic::{metadata::MetadataValue, Code, Status};

/// The generated control service: messages, client, and server.
///
/// `proto/control.proto` is where this is documented and where a change to it
/// is made; the comments there travel into the generated items. `missing_docs`
/// is allowed because protobuf has no way to document the wrappers prost adds
/// around a `oneof`, not because the schema is undocumented.
#[allow(
    clippy::all,
    missing_debug_implementations,
    missing_docs,
    unreachable_pub
)]
pub mod pb {
    tonic::include_proto!("synch.control.v1");
}

pub use pb::{
    command::Kind as Command, frame::Payload as Frame, put_request::Part as PutPart,
    upload_part_request::Part as UploadPartPart,
};

/// The control protocol version.
///
/// Client and daemon are normally the same binary, so this catches the
/// upgrade-while-running case rather than supporting mixed versions: protobuf
/// keeps a field addition readable but cannot make a daemon that has learnt a
/// new command out of one that has not. Bumped whenever the meaning of an
/// existing request changes, and travels as a header on every call.
///
/// v2 added the multipart upload calls (§9.4): a field addition would not need
/// a bump, but a *call* addition does — an old daemon answers a new one with a
/// bare gRPC `Unimplemented`, which reads as an internal error rather than the
/// "restart the daemon" a version mismatch says.
///
/// v3 changes socket arming from approval by content root to approval by an
/// opaque token that also binds the authorization revision and init result.
pub const CONTROL_VERSION: u32 = 3;

/// How many payload bytes one chunk carries.
///
/// Small enough that a multi-gigabyte read is never held in memory by either
/// process, large enough that the per-message cost stays negligible.
pub const CHUNK_SIZE: usize = 256 * 1024;

/// The largest message either side will encode or accept.
///
/// A chunk is [`CHUNK_SIZE`] and nothing else in the protocol is close, so the
/// ceiling bounds what a malformed length can make the other side allocate
/// rather than being reached.
pub(crate) const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

/// The header carrying the client's [`CONTROL_VERSION`].
pub(crate) const VERSION_HEADER: &str = "x-synch-control-version";

/// The header carrying the datadir token.
pub(crate) const TOKEN_HEADER: &str = "x-synch-control-token-bin";

/// The trailer naming the [`ErrorCode`] of a failed call.
pub(crate) const ERROR_CODE_HEADER: &str = "x-synch-error-code";

/// Why a request failed.
///
/// The CLI renders these as its own exit status rather than as a transport
/// error (§9.3). Each maps to a gRPC status code and travels alongside it in
/// the [`ERROR_CODE_HEADER`] trailer, because more of them exist than gRPC has
/// codes to keep apart — and a caller that renders codes as protocol statuses,
/// as the S3 gateway does, needs the distinction the mapping loses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// versions.
    Divergent,
    /// The daemon is in a state that cannot serve this request yet, and the
    /// message names what clears it — key-loss recovery (§3.4) is the case
    /// that exists. Neither malformed nor a fault: a caller that renders codes
    /// as protocol statuses owes this one "come back later", not "you asked
    /// wrong".
    Unavailable,
}

impl ErrorCode {
    /// The stable short name used in messages, trailers, and tests.
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

    /// The short name, back again.
    fn from_str(text: &str) -> Option<ErrorCode> {
        Some(match text {
            "unauthorized" => ErrorCode::Unauthorized,
            "version-mismatch" => ErrorCode::VersionMismatch,
            "not-initialized" => ErrorCode::NotInitialized,
            "not-found" => ErrorCode::NotFound,
            "invalid" => ErrorCode::Invalid,
            "internal" => ErrorCode::Internal,
            "divergent" => ErrorCode::Divergent,
            "unavailable" => ErrorCode::Unavailable,
            _ => return None,
        })
    }

    /// The gRPC status code a client that does not know this protocol would
    /// see.
    pub(crate) fn grpc(self) -> Code {
        match self {
            ErrorCode::Unauthorized => Code::Unauthenticated,
            ErrorCode::VersionMismatch | ErrorCode::NotInitialized => Code::FailedPrecondition,
            ErrorCode::NotFound => Code::NotFound,
            ErrorCode::Invalid => Code::InvalidArgument,
            ErrorCode::Internal => Code::Internal,
            // A divergent path is a conflict the caller resolves by naming a
            // version, which is what `Aborted` is for; it is not a malformed
            // request and not a fault.
            ErrorCode::Divergent => Code::Aborted,
            ErrorCode::Unavailable => Code::Unavailable,
        }
    }

    /// The code a status carries no trailer for: a failure raised by the
    /// transport rather than by the daemon.
    fn from_grpc(code: Code) -> ErrorCode {
        match code {
            Code::Unauthenticated => ErrorCode::Unauthorized,
            Code::NotFound => ErrorCode::NotFound,
            Code::InvalidArgument => ErrorCode::Invalid,
            Code::Unavailable => ErrorCode::Unavailable,
            _ => ErrorCode::Internal,
        }
    }
}

/// A structured failure: a code plus a human-readable message (§9.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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

impl synch_core::TaskLost for ControlError {
    fn task_lost(reason: String) -> Self {
        ControlError::internal(format!("a blocking task did not complete: {reason}"))
    }
}

impl From<ControlError> for Status {
    fn from(e: ControlError) -> Status {
        let mut status = Status::new(e.code.grpc(), e.message);
        // Infallible: every name is a lowercase ASCII literal.
        if let Ok(value) = MetadataValue::try_from(e.code.as_str()) {
            status.metadata_mut().insert(ERROR_CODE_HEADER, value);
        }
        status
    }
}

impl From<Status> for ControlError {
    fn from(status: Status) -> ControlError {
        let named = status
            .metadata()
            .get(ERROR_CODE_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(ErrorCode::from_str);
        ControlError::new(
            named.unwrap_or_else(|| ErrorCode::from_grpc(status.code())),
            status.message().to_string(),
        )
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

/// One entry of the unified tree, in the types the rest of the node uses (§8).
///
/// [`pb::Entry`] is the same thing as protobuf can express it — a kind as an
/// integer, a root as raw bytes; this is that decoded back into
/// [`EntryKind`] and [`struct@Hash`], so a caller never handles a 32-byte `Vec`
/// that might not be 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl From<EntryInfo> for pb::Entry {
    fn from(info: EntryInfo) -> pb::Entry {
        pb::Entry {
            origin: info.origin,
            space: info.space,
            path: info.path,
            kind: kind_to_pb(info.kind) as i32,
            size: info.size,
            mtime_ns: info.mtime_ns,
            content: info.content.map(|root| root.as_bytes().to_vec()),
            seq: info.seq,
            symlink_target: info.symlink_target,
            versions: info.versions,
        }
    }
}

impl TryFrom<pb::Entry> for EntryInfo {
    type Error = ControlError;

    fn try_from(entry: pb::Entry) -> Result<EntryInfo, ControlError> {
        let content = match &entry.content {
            Some(bytes) => Some(Hash::from_slice(bytes).map_err(|e| {
                ControlError::internal(format!("the daemon sent a malformed content root: {e}"))
            })?),
            None => None,
        };
        Ok(EntryInfo {
            kind: kind_from_pb(entry.kind())?,
            origin: entry.origin,
            space: entry.space,
            path: entry.path,
            size: entry.size,
            mtime_ns: entry.mtime_ns,
            content,
            seq: entry.seq,
            symlink_target: entry.symlink_target,
            versions: entry.versions,
        })
    }
}

fn kind_to_pb(kind: EntryKind) -> pb::EntryKind {
    match kind {
        EntryKind::File => pb::EntryKind::File,
        EntryKind::Dir => pb::EntryKind::Dir,
        EntryKind::Symlink => pb::EntryKind::Symlink,
        EntryKind::Tombstone => pb::EntryKind::Tombstone,
        EntryKind::Socket => pb::EntryKind::Socket,
    }
}

fn kind_from_pb(kind: pb::EntryKind) -> Result<EntryKind, ControlError> {
    Ok(match kind {
        pb::EntryKind::File => EntryKind::File,
        pb::EntryKind::Dir => EntryKind::Dir,
        pb::EntryKind::Symlink => EntryKind::Symlink,
        pb::EntryKind::Tombstone => EntryKind::Tombstone,
        pb::EntryKind::Socket => EntryKind::Socket,
        pb::EntryKind::Unspecified => {
            return Err(ControlError::internal(
                "the daemon sent an entry with no kind",
            ))
        }
    })
}

/// Compares two tokens without leaking their contents through timing.
pub(crate) fn tokens_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // A code has to survive the round trip through a status: the CLI's exit
    // status and the gateway's HTTP status are both read off it.
    #[test]
    fn every_code_crosses_a_status_intact() {
        for code in [
            ErrorCode::Unauthorized,
            ErrorCode::VersionMismatch,
            ErrorCode::NotInitialized,
            ErrorCode::NotFound,
            ErrorCode::Invalid,
            ErrorCode::Internal,
            ErrorCode::Divergent,
            ErrorCode::Unavailable,
        ] {
            let sent = ControlError::new(code, "why");
            let received = ControlError::from(Status::from(sent.clone()));
            assert_eq!(received, sent, "{}", code.as_str());
        }
    }

    // A status the daemon never wrote still has to land on a code.
    #[test]
    fn a_status_without_a_named_code_falls_back_to_the_grpc_one() {
        assert_eq!(
            ControlError::from(Status::unavailable("nothing is listening")).code,
            ErrorCode::Unavailable
        );
        assert_eq!(
            ControlError::from(Status::unknown("the connection went away")).code,
            ErrorCode::Internal
        );
    }

    #[test]
    fn entries_round_trip_through_their_message() {
        let entry = EntryInfo {
            origin: "nas@cluster.example".into(),
            space: "media".into(),
            // A colon in a key is exactly what the text reference form cannot
            // carry, which is why these requests are structured.
            path: "uploads/2024:07:01.bin".into(),
            kind: EntryKind::File,
            size: 7,
            mtime_ns: 42,
            content: Some(Hash::new(b"payload")),
            seq: 3,
            symlink_target: None,
            versions: 1,
        };
        let wire = pb::Entry::from(entry.clone());
        assert_eq!(EntryInfo::try_from(wire).unwrap(), entry);

        let empty = pb::Entry {
            kind: pb::EntryKind::Unspecified as i32,
            ..pb::Entry::from(entry)
        };
        assert_eq!(
            EntryInfo::try_from(empty).unwrap_err().code,
            ErrorCode::Internal
        );
    }
}
