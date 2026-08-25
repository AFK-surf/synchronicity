//! The client side of the control service (§9.3).
//!
//! Every command except `synch init`, `synch daemon run`, and its background
//! launcher `synch daemon start` goes through here, and so does every gateway
//! operation. There is no in-process fallback: with no daemon running,
//! [`Client::connect`] fails with a message naming the socket and both ways to
//! start it (§9.1).

use std::path::Path;

use synch_core::Hash;
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

    /// Opens one socket invocation on a named node and pipes bytes both ways.
    ///
    /// The daemon owns the only iroh endpoint (§9.1), so this is how the CLI
    /// reaches a socket at all.
    pub async fn open_socket(
        &mut self,
        requests: ReceiverStream<pb::ConnectRequest>,
    ) -> Result<tonic::Streaming<pb::ConnectResponse>, ControlError> {
        Ok(self.inner.open_socket(requests).await?.into_inner())
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
        Ok(Put {
            parts,
            answer: written,
        })
    }

    /// Removes this node's copy of a path and publishes its tombstone.
    pub async fn delete(&mut self, space: &str, path: &str) -> Result<Deleted, ControlError> {
        let response = self
            .inner
            .delete(pb::DeleteRequest {
                space: space.to_string(),
                path: path.to_string(),
            })
            .await?
            .into_inner();
        Ok(Deleted {
            removed: response.removed,
            still_published: response.still_published,
        })
    }

    /// Opens a multipart upload and returns its id (§9.4).
    pub async fn create_upload(
        &mut self,
        space: &str,
        path: &str,
        principal: Option<&str>,
    ) -> Result<String, ControlError> {
        Ok(self
            .inner
            .create_upload(pb::CreateUploadRequest {
                space: space.to_string(),
                path: path.to_string(),
                principal: principal.unwrap_or_default().to_string(),
            })
            .await?
            .into_inner()
            .upload_id)
    }

    /// Opens a streamed write of one part.
    ///
    /// Returns once the daemon has checked the upload is still open and the
    /// part number is one S3 defines, so a refusal arrives before a byte of the
    /// part is sent — the same contract [`Client::put`] gives.
    pub async fn upload_part(
        &mut self,
        upload: UploadRef,
        number: u32,
    ) -> Result<PartUpload, ControlError> {
        let (parts, body) = mpsc::channel(2);
        parts
            .send(pb::UploadPartRequest {
                part: Some(super::proto::UploadPartPart::Header(pb::UploadPartHeader {
                    upload: Some(upload.into_pb()),
                    number,
                })),
            })
            .await
            .map_err(|_| ControlError::internal("the part was closed before it opened"))?;
        // The response stream's headers arrive as soon as the daemon has taken
        // its gates, which is what makes this `await` return before the payload
        // has been sent (§9.4).
        let recorded = self
            .inner
            .upload_part(ReceiverStream::new(body))
            .await?
            .into_inner();
        Ok(PartUpload {
            parts,
            answer: recorded,
        })
    }

    /// Assembles the named parts and publishes the object.
    pub async fn complete_upload(
        &mut self,
        upload: UploadRef,
        parts: &[(u32, Option<Hash>)],
    ) -> Result<CompletedUpload, ControlError> {
        let response = self
            .inner
            .complete_upload(pb::CompleteUploadRequest {
                upload: Some(upload.into_pb()),
                parts: parts
                    .iter()
                    .map(|(number, root)| pb::CompletionPart {
                        number: *number,
                        root: root.map(|r| r.as_bytes().to_vec()).unwrap_or_default(),
                    })
                    .collect(),
            })
            .await?
            .into_inner();
        Ok(CompletedUpload {
            etag: hash_from(&response.etag, "etag")?,
            size: response.size,
            replayed: response.replayed,
        })
    }

    /// Drops an upload and everything staged for it.
    pub async fn abort_upload(&mut self, upload: UploadRef) -> Result<bool, ControlError> {
        Ok(self
            .inner
            .abort_upload(pb::AbortUploadRequest {
                upload: Some(upload.into_pb()),
            })
            .await?
            .into_inner()
            .existed)
    }

    /// Every upload still accepting parts under a prefix.
    pub async fn list_uploads(
        &mut self,
        space: &str,
        prefix: &str,
        principal: Option<&str>,
    ) -> Result<Vec<OpenUpload>, ControlError> {
        let mut stream = self
            .inner
            .list_uploads(pb::ListUploadsRequest {
                space: space.to_string(),
                prefix: prefix.to_string(),
                principal: principal.unwrap_or_default().to_string(),
            })
            .await?
            .into_inner();
        let mut out = Vec::new();
        while let Some(upload) = stream.message().await? {
            out.push(OpenUpload {
                upload_id: upload.upload_id,
                path: upload.path,
                created_ns: upload.created_ns,
            });
        }
        Ok(out)
    }

    /// Every part recorded for one upload, in part-number order.
    pub async fn list_parts(
        &mut self,
        upload: UploadRef,
    ) -> Result<Vec<RecordedPart>, ControlError> {
        let mut stream = self
            .inner
            .list_parts(pb::ListPartsRequest {
                upload: Some(upload.into_pb()),
            })
            .await?
            .into_inner();
        let mut out = Vec::new();
        while let Some(part) = stream.message().await? {
            out.push(RecordedPart {
                number: part.number,
                size: part.size,
                root: hash_from(&part.root, "part root")?,
                created_ns: part.created_ns,
            });
        }
        Ok(out)
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

/// One streamed-write family (§9.4): the request envelope, the daemon's one
/// answer, and what a committed write yields.
///
/// [`Put`] and [`PartUpload`] are [`StreamedWrite`] over the two families —
/// the machine exists once, and this trait is the whole of the difference.
pub trait WriteFamily: Sized {
    /// The request envelope around one part.
    type Request: Send + 'static;
    /// The daemon's one answer.
    type Response;
    /// What a committed write yields to the caller.
    type Output;
    /// This write's name in errors: "the write" or "the part".
    const WHAT: &'static str;
    /// The impossible success the daemon must not report after an abort.
    const ABANDONED: &'static str;
    /// One piece of the payload.
    fn chunk(bytes: Vec<u8>) -> Self;
    /// The abandonment, with its reason.
    fn abort(why: String) -> Self;
    /// The explicit commit.
    fn commit() -> Self;
    /// Wraps this part in its request envelope.
    fn into_request(self) -> Self::Request;
    /// Reads the daemon's answer into what the caller keeps.
    fn output(answer: Self::Response) -> Result<Self::Output, ControlError>;
}

impl WriteFamily for super::proto::PutPart {
    type Request = pb::PutRequest;
    type Response = pb::Written;
    type Output = Written;
    const WHAT: &'static str = "the write";
    const ABANDONED: &'static str = "the daemon published a write that was abandoned";
    fn chunk(bytes: Vec<u8>) -> Self {
        Self::Chunk(bytes)
    }
    fn abort(why: String) -> Self {
        Self::Abort(why)
    }
    fn commit() -> Self {
        Self::Commit(pb::Commit {})
    }
    fn into_request(self) -> pb::PutRequest {
        pb::PutRequest { part: Some(self) }
    }
    fn output(written: pb::Written) -> Result<Written, ControlError> {
        let entry = written
            .entry
            .ok_or_else(|| ControlError::internal("the daemon did not report the entry"))?;
        Ok(Written {
            path: written.path,
            entry: EntryInfo::try_from(entry)?,
        })
    }
}

impl WriteFamily for super::proto::UploadPartPart {
    type Request = pb::UploadPartRequest;
    type Response = pb::UploadPartResponse;
    type Output = RecordedPart;
    const WHAT: &'static str = "the part";
    const ABANDONED: &'static str = "the daemon recorded a part that was abandoned";
    fn chunk(bytes: Vec<u8>) -> Self {
        Self::Chunk(bytes)
    }
    fn abort(why: String) -> Self {
        Self::Abort(why)
    }
    fn commit() -> Self {
        Self::Commit(pb::Commit {})
    }
    fn into_request(self) -> pb::UploadPartRequest {
        pb::UploadPartRequest { part: Some(self) }
    }
    fn output(recorded: pb::UploadPartResponse) -> Result<RecordedPart, ControlError> {
        Ok(RecordedPart {
            number: recorded.number,
            size: recorded.size,
            root: hash_from(&recorded.root, "part root")?,
            created_ns: recorded.created_ns,
        })
    }
}

/// A write in progress (§9.4).
pub type Put = StreamedWrite<super::proto::PutPart>;

/// A streamed write, which the daemon keeps nothing of until it is committed.
#[derive(Debug)]
pub struct StreamedWrite<P: WriteFamily> {
    parts: mpsc::Sender<P::Request>,
    answer: Streaming<P::Response>,
}

impl<P: WriteFamily> StreamedWrite<P> {
    /// Sends one piece of the payload.
    pub async fn chunk(&mut self, bytes: Vec<u8>) -> Result<(), ControlError> {
        self.send(P::chunk(bytes)).await
    }

    /// Abandons the write, so the daemon keeps nothing.
    ///
    /// There is no success to report, so the daemon's account of what it threw
    /// away is the return value: an abandoned write always ends in an error.
    /// A send that fails here already carries that account — [`Self::send`]
    /// reads it off the answer stream — so it is returned as it stands: a
    /// second read of the stream would find it ended and misreport the daemon
    /// as having kept the write. The two machines had drifted exactly here,
    /// and the copy that read twice was the wrong one.
    pub async fn abort(mut self, why: impl Into<String>) -> ControlError {
        if let Err(e) = self.send(P::abort(why.into())).await {
            return e;
        }
        drop(self.parts);
        match self.answer.message().await {
            Err(status) => status.into(),
            Ok(_) => ControlError::internal(P::ABANDONED),
        }
    }

    /// Completes the write and returns what the daemon reports.
    pub async fn finish(mut self) -> Result<P::Output, ControlError> {
        // The commit is a message of its own, so that every other way this
        // handle can end — an early `?`, a cancelled future, a process that
        // died — leaves the daemon with a payload it was never told to keep.
        self.send(P::commit()).await?;
        drop(self.parts);
        let answer = self.answer.message().await?.ok_or_else(|| {
            ControlError::internal(format!("the daemon did not report {}", P::WHAT))
        })?;
        P::output(answer)
    }

    async fn send(&mut self, part: P) -> Result<(), ControlError> {
        if self.parts.send(part.into_request()).await.is_err() {
            // The daemon dropped its side, which means it has already decided
            // the write cannot go on; its reason is on the response stream.
            return Err(match self.answer.message().await {
                Err(status) => status.into(),
                Ok(_) => ControlError::internal(format!("the daemon stopped reading {}", P::WHAT)),
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

/// Which upload a call is about, and the key it must belong to (§9.4).
///
/// The key travels with the id on every call because an id names one key: a
/// request that quotes it against another key is answered as though the upload
/// did not exist, which is what stops an id from being a way into a path the
/// client never named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadRef {
    /// The upload id.
    pub upload_id: String,
    /// The space it must be against.
    pub space: String,
    /// The path it must be against.
    pub path: String,
    /// The access key that must own it, or `None` when the gateway is anonymous.
    pub principal: Option<String>,
}

impl UploadRef {
    /// Names an upload against a key, and the principal that must own it.
    pub fn new(
        upload_id: impl Into<String>,
        space: &str,
        path: &str,
        principal: Option<&str>,
    ) -> UploadRef {
        UploadRef {
            upload_id: upload_id.into(),
            space: space.to_string(),
            path: path.to_string(),
            principal: principal.map(str::to_string),
        }
    }

    fn into_pb(self) -> pb::UploadRef {
        pb::UploadRef {
            upload_id: self.upload_id,
            space: self.space,
            path: self.path,
            principal: self.principal.unwrap_or_default(),
        }
    }
}

/// A streamed write of one part, which records nothing until it is finished.
pub type PartUpload = StreamedWrite<super::proto::UploadPartPart>;

/// One part the daemon has recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPart {
    /// The part number.
    pub number: u32,
    /// How many bytes it carries.
    pub size: u64,
    /// Its own object root, which is the ETag the client is given.
    pub root: Hash,
    /// When it was recorded, unix nanoseconds.
    pub created_ns: i64,
}

/// One upload still accepting parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenUpload {
    /// The upload id.
    pub upload_id: String,
    /// The path it will publish to.
    pub path: String,
    /// When it was created, unix nanoseconds.
    pub created_ns: i64,
}

/// What a completion produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedUpload {
    /// The assembled object's root.
    pub etag: Hash,
    /// Its size in bytes.
    pub size: u64,
    /// True when a retry was answered from the recorded result.
    pub replayed: bool,
}

/// Reads a 32-byte hash column off the wire.
fn hash_from(bytes: &[u8], what: &str) -> Result<Hash, ControlError> {
    Hash::from_slice(bytes)
        .map_err(|_| ControlError::internal(format!("the daemon sent a malformed {what}")))
}

/// What a delete did, and what it left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deleted {
    /// Whether there was a local copy to remove.
    pub removed: bool,
    /// Whether some origin still publishes a live entry for the path (§8).
    pub still_published: bool,
}
