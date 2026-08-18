//! The client side of the control service (§9.3).
//!
//! Every command except `synch init` and `synch daemon run` goes through here,
//! and so does every gateway operation. There is no in-process fallback: with
//! no daemon running, [`Client::connect`] fails with a message naming the
//! socket and `synch daemon run` (§9.1).

use std::path::Path;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    metadata::MetadataValue,
    service::{interceptor::InterceptedService, Interceptor},
    transport::Channel,
    Request, Status, Streaming,
};

use crate::control::{
    proto::{
        pb::{self, control_client::ControlClient},
        Command, ControlError, EntryInfo, ErrorCode, Frame, MAX_MESSAGE_LEN, TOKEN_HEADER,
        VERSION_HEADER,
    },
    transport,
};

/// A connected control client.
#[derive(Debug, Clone)]
pub struct Client {
    inner: ControlClient<InterceptedService<Channel, Credentials>>,
}

/// The version and token every call carries.
#[derive(Debug, Clone)]
pub struct Credentials {
    version: MetadataValue<tonic::metadata::Ascii>,
    token: MetadataValue<tonic::metadata::Binary>,
}

impl Interceptor for Credentials {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert(VERSION_HEADER, self.version.clone());
        request
            .metadata_mut()
            .insert_bin(TOKEN_HEADER, self.token.clone());
        Ok(request)
    }
}

impl Client {
    /// Connects to the daemon owning `data_dir`.
    pub async fn connect(data_dir: &Path) -> Result<Client, ControlError> {
        let token = transport::read_token(data_dir).map_err(no_daemon)?;
        Client::open(data_dir, super::proto::CONTROL_VERSION, token).await
    }

    /// Connects while claiming a specific protocol version.
    ///
    /// Only the version check needs this; ordinary clients use
    /// [`Client::connect`].
    pub async fn connect_as(data_dir: &Path, version: u32) -> Result<Client, ControlError> {
        let token = transport::read_token(data_dir).map_err(no_daemon)?;
        Client::open(data_dir, version, token).await
    }

    /// Connects with a token of the caller's choosing, for testing the check.
    pub async fn connect_with_token(
        data_dir: &Path,
        token: Vec<u8>,
    ) -> Result<Client, ControlError> {
        Client::open(data_dir, super::proto::CONTROL_VERSION, token).await
    }

    async fn open(data_dir: &Path, version: u32, token: Vec<u8>) -> Result<Client, ControlError> {
        let channel = transport::connect(data_dir).await.map_err(no_daemon)?;
        let credentials = Credentials {
            version: MetadataValue::try_from(version.to_string())
                .map_err(|e| ControlError::internal(format!("bad protocol version: {e}")))?,
            token: MetadataValue::from_bytes(&token),
        };
        Ok(Client {
            inner: ControlClient::with_interceptor(channel, credentials)
                .max_decoding_message_size(MAX_MESSAGE_LEN)
                .max_encoding_message_size(MAX_MESSAGE_LEN),
        })
    }

    /// Runs one CLI subcommand, streaming its output back as it is produced.
    pub async fn run(&mut self, command: Command) -> Result<Frames, ControlError> {
        let request = pb::Command {
            kind: Some(command),
        };
        let stream = self.inner.run(request).await?.into_inner();
        Ok(Frames { stream })
    }

    /// The unified listing under a prefix, resolved by a policy (§8).
    pub async fn list(&mut self, request: pb::ListRequest) -> Result<Entries, ControlError> {
        let stream = self.inner.list(request).await?.into_inner();
        Ok(Entries { stream })
    }

    /// The version a policy selects for one path, with no content fetched.
    pub async fn resolve(
        &mut self,
        request: pb::ResolveRequest,
    ) -> Result<EntryInfo, ControlError> {
        EntryInfo::try_from(self.inner.resolve(request).await?.into_inner())
    }

    /// A verified byte range of the version a policy selects.
    pub async fn read(&mut self, request: pb::ReadRequest) -> Result<Chunks, ControlError> {
        let stream = self.inner.read(request).await?.into_inner();
        Ok(Chunks { stream })
    }

    /// Opens a streamed write into one of this node's own spaces (§7.1, §9.4).
    ///
    /// Returns once the daemon has taken its gates — publishability, a
    /// resolvable target — so a refusal arrives here, before a byte of the
    /// payload is sent.
    pub async fn put(&mut self, space: &str, path: &str) -> Result<Put, ControlError> {
        // Two messages of slack: enough that a writer is never blocked on the
        // daemon having taken the previous chunk, small enough that a stalled
        // daemon stops the writer within a chunk or two.
        let (parts, body) = mpsc::channel(2);
        parts
            .send(pb::PutRequest {
                part: Some(super::proto::PutPart::Header(pb::PutHeader {
                    space: space.to_string(),
                    path: path.to_string(),
                })),
            })
            .await
            .map_err(|_| ControlError::internal("the write was closed before it opened"))?;
        let written = self
            .inner
            .put(ReceiverStream::new(body))
            .await?
            .into_inner();
        Ok(Put { parts, written })
    }

    /// Reads one config value from the `s3.*` namespace, a record per line.
    pub async fn config(&mut self, key: &str) -> Result<Vec<String>, ControlError> {
        let request = pb::GetConfigRequest {
            key: key.to_string(),
        };
        Ok(self.inner.get_config(request).await?.into_inner().records)
    }

    /// Appends one record to a config value in the `s3.*` namespace.
    pub async fn append_config(&mut self, key: &str, record: &str) -> Result<(), ControlError> {
        let request = pb::AppendConfigRequest {
            key: key.to_string(),
            record: record.to_string(),
        };
        self.inner.append_config(request).await?;
        Ok(())
    }
}

/// The output of a running command.
#[derive(Debug)]
pub struct Frames {
    stream: Streaming<pb::Frame>,
}

impl Frames {
    /// The next piece of output, or `None` once the command has finished.
    ///
    /// A daemon-side failure comes back as `Err` carrying its code and message,
    /// never as a transport error.
    pub async fn next(&mut self) -> Result<Option<Frame>, ControlError> {
        loop {
            match self.stream.message().await? {
                Some(pb::Frame { payload: Some(one) }) => return Ok(Some(one)),
                // Nothing the daemon writing this protocol can have meant.
                // Skipped rather than treated as the end, which would silently
                // truncate everything after it.
                Some(pb::Frame { payload: None }) => continue,
                None => return Ok(None),
            }
        }
    }
}

/// A listing, one entry at a time.
#[derive(Debug)]
pub struct Entries {
    stream: Streaming<pb::Entry>,
}

impl Entries {
    /// The next entry, or `None` at the end of the listing.
    pub async fn next(&mut self) -> Result<Option<EntryInfo>, ControlError> {
        match self.stream.message().await? {
            Some(entry) => Ok(Some(EntryInfo::try_from(entry)?)),
            None => Ok(None),
        }
    }
}

/// A byte payload, one chunk at a time.
#[derive(Debug)]
pub struct Chunks {
    stream: Streaming<pb::Chunk>,
}

impl Chunks {
    /// The next chunk, or `None` at the end of the range.
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, ControlError> {
        Ok(self.stream.message().await?.map(|chunk| chunk.data))
    }
}

/// A write in progress (§9.4).
#[derive(Debug)]
pub struct Put {
    parts: mpsc::Sender<pb::PutRequest>,
    written: Streaming<pb::Written>,
}

impl Put {
    /// Sends one piece of the payload.
    pub async fn chunk(&mut self, bytes: Vec<u8>) -> Result<(), ControlError> {
        self.send(super::proto::PutPart::Chunk(bytes)).await
    }

    /// Abandons the write, so the daemon keeps nothing.
    ///
    /// There is no success to report, so the daemon's account of what it threw
    /// away is the return value: an abandoned write always ends in an error.
    pub async fn abort(mut self, why: impl Into<String>) -> ControlError {
        if let Err(e) = self.send(super::proto::PutPart::Abort(why.into())).await {
            return e;
        }
        drop(self.parts);
        match self.written.message().await {
            Err(status) => status.into(),
            Ok(_) => ControlError::internal("the daemon published a write that was abandoned"),
        }
    }

    /// Completes the write and returns the published entry.
    pub async fn finish(mut self) -> Result<Written, ControlError> {
        // The commit is a message of its own, so that every other way this
        // handle can end — an early `?`, a cancelled future, a process that
        // died — leaves the daemon with a payload it was never told to keep.
        self.send(super::proto::PutPart::Commit(pb::Commit {}))
            .await?;
        drop(self.parts);
        let written = self
            .written
            .message()
            .await?
            .ok_or_else(|| ControlError::internal("the daemon did not report the write"))?;
        let entry = written
            .entry
            .ok_or_else(|| ControlError::internal("the daemon did not report the entry"))?;
        Ok(Written {
            path: written.path,
            entry: EntryInfo::try_from(entry)?,
        })
    }

    async fn send(&mut self, part: super::proto::PutPart) -> Result<(), ControlError> {
        if self
            .parts
            .send(pb::PutRequest { part: Some(part) })
            .await
            .is_err()
        {
            // The daemon dropped its side, which means it has already decided
            // the write cannot go on; its reason is on the response stream.
            return Err(match self.written.message().await {
                Err(status) => status.into(),
                Ok(_) => ControlError::internal("the daemon stopped reading the write"),
            });
        }
        Ok(())
    }
}

/// What a completed write published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// The file the payload landed in, as the daemon sees it.
    pub path: String,
    /// The published entry.
    pub entry: EntryInfo,
}

/// Turns a failure to reach the daemon into a structured error.
///
/// [`ErrorCode::Unavailable`] rather than `NotFound`: nothing the caller asked
/// for is missing — the daemon is, and the message names the socket and the
/// command that starts one (§9.1). A client that renders codes as protocol
/// statuses, as the S3 gateway does, would otherwise answer "no such key" to
/// every request made while the daemon was down.
fn no_daemon(e: std::io::Error) -> ControlError {
    let code = match e.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::AddrNotAvailable => ErrorCode::Unavailable,
        _ => ErrorCode::Internal,
    };
    ControlError::new(code, e.to_string())
}
