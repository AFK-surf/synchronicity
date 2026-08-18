//! The gateway's link to the daemon (§9.1, §9.4).
//!
//! **The gateway is a control client of the daemon — nothing more.** It never
//! opens the database, never binds an iroh endpoint, and holds no persistent
//! state of its own; its only datadir touch is reading `control.token`, exactly
//! like the CLI. That is not optional hygiene: a second process computing
//! `next_seq` beside the daemon can sign two heads at the same seq —
//! self-equivocation broadcast cluster-wide, with the losing batch's files
//! recorded as scanned but present in no surviving root.

use std::path::{Path, PathBuf};

use axum::body::Body;
use synch_cli::control::{
    proto::{pb, CHUNK_SIZE},
    Client, Command, CompletedUpload, Deleted, EntryInfo, Frame, OpenUpload, RecordedPart,
    UploadRef,
};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};

use crate::error::{S3Error, S3Result};

/// How many chunks may sit between the daemon and the HTTP client.
///
/// The point of the bound is that it exists: a reader that stalls stops the
/// daemon's writer within a couple of chunks, so a slow client costs bounded
/// memory rather than a buffered object.
const READ_AHEAD: usize = 2;

/// A daemon the gateway talks to, identified by its data directory.
#[derive(Debug, Clone)]
pub struct Daemon {
    data_dir: PathBuf,
}

impl Daemon {
    /// Points the gateway at the datadir whose daemon it serves.
    pub fn new(data_dir: impl Into<PathBuf>) -> Daemon {
        Daemon {
            data_dir: data_dir.into(),
        }
    }

    /// The data directory whose `control.token` authenticates every request.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Connects to the daemon.
    async fn connect(&self) -> S3Result<Client> {
        Ok(Client::connect(&self.data_dir).await?)
    }

    /// Every line a CLI subcommand answers with.
    async fn lines(&self, command: Command) -> S3Result<Vec<String>> {
        let mut client = self.connect().await?;
        let mut frames = client.run(command).await?;
        let mut out = Vec::new();
        while let Some(frame) = frames.next().await? {
            if let Frame::Line(text) = frame {
                out.push(text);
            }
        }
        Ok(out)
    }

    /// This node's own origin, canonically rendered.
    ///
    /// Read from the first line of the daemon's identity report, which is the
    /// one thing in it the gateway needs: a bucket pinned to a *foreign* origin
    /// is writable but reads back someone else's view, and saying so requires
    /// knowing which origin is ours (§9.4).
    pub async fn origin(&self) -> S3Result<String> {
        self.lines(Command::Id(pb::Id {}))
            .await?
            .iter()
            .find_map(|line| line.strip_prefix("origin: ").map(str::to_string))
            .ok_or_else(|| S3Error::store("the daemon did not report an origin"))
    }

    /// Whether any origin publishes `space`, or a local space claims the id.
    ///
    /// `bucket add` warns on false rather than refusing: mapping a bucket
    /// before its space first syncs is a legitimate order of operations, but
    /// doing it to a typo'd id would otherwise be indistinguishable from
    /// success.
    pub async fn space_known(&self, space: &str) -> S3Result<bool> {
        match self
            .lines(Command::Status(pb::Status {
                reference: Some(space.to_string()),
            }))
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if error.status == axum::http::StatusCode::NOT_FOUND => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// The version a policy selects for one path, with no content fetched —
    /// what `HeadObject` answers from.
    pub async fn resolve(&self, space: &str, path: &str, policy: &str) -> S3Result<EntryInfo> {
        Ok(self
            .connect()
            .await?
            .resolve(pb::ResolveRequest {
                space: space.to_string(),
                path: path.to_string(),
                policy: Some(policy.to_string()),
            })
            .await?)
    }

    /// The unified listing under a prefix, resolved by a policy.
    ///
    /// `wanted` bounds what is *read*, not what the daemon offers: the caller
    /// stops consuming and the call is dropped, which is an ordinary way for a
    /// listing to end (§9.3). Returns whether the daemon still had more to
    /// say — S3's `IsTruncated`.
    pub async fn list(
        &self,
        space: &str,
        prefix: &str,
        start_after: Option<&str>,
        wanted: usize,
        policy: &str,
    ) -> S3Result<(Vec<EntryInfo>, bool)> {
        let mut client = self.connect().await?;
        let mut entries = client
            .list(pb::ListRequest {
                space: space.to_string(),
                prefix: prefix.to_string(),
                start_after: start_after.map(str::to_string),
                // Bounded by what this page can use, `+1` so the `more` check
                // below still sees one row past the budget. `None` made the
                // daemon materialize a `VersionSet` for *every* path in the
                // prefix — every path times every publishing origin — collected
                // into a `Vec` before the stream even opened, and then dropped
                // all but `max-keys` of them. A one-line `max-keys=1` request
                // therefore cost the whole space, on the connection that also
                // owns the single write connection, from a principal who is not
                // a cluster member and so is outside §12's trust stance.
                limit: Some(wanted as u64 + 1),
                policy: Some(policy.to_string()),
            })
            .await?;
        let mut out = Vec::new();
        while let Some(entry) = entries.next().await? {
            if out.len() == wanted {
                return Ok((out, true));
            }
            out.push(entry);
        }
        Ok((out, false))
    }

    /// Streams a verified byte range straight into an HTTP response body.
    ///
    /// The daemon's chunks become body frames one for one: nothing on this side
    /// ever holds more than a couple of them, whatever the object's size
    /// (§9.4). A failure the daemon reports up front — no provider for the
    /// content, a strict bucket's divergence — is this call's own error rather
    /// than a body that dies after a 200 has already gone out.
    pub async fn read(
        &self,
        space: &str,
        path: &str,
        policy: &str,
        start: u64,
        len: Option<u64>,
    ) -> S3Result<Body> {
        let mut client = self.connect().await?;
        let mut chunks = client
            .read(pb::ReadRequest {
                space: space.to_string(),
                path: path.to_string(),
                policy: Some(policy.to_string()),
                start,
                len,
            })
            .await?;

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(READ_AHEAD);
        tokio::spawn(async move {
            // The client is held for the life of the read: it owns the
            // connection the chunks are arriving over.
            let _client = client;
            loop {
                match chunks.next().await {
                    Ok(None) => return,
                    // A send that fails means the HTTP client hung up; the
                    // dropped stream takes the daemon's side down with it.
                    Ok(Some(bytes)) => {
                        if tx.send(Ok(bytes)).await.is_err() {
                            return;
                        }
                    }
                    // Mid-body there is no status left to change, so the body
                    // ends in an error and the connection is what carries the
                    // bad news.
                    Err(e) => {
                        let _ = tx.send(Err(std::io::Error::other(e.message))).await;
                        return;
                    }
                }
            }
        });
        Ok(Body::from_stream(ReceiverStream::new(rx)))
    }

    /// Streams an HTTP request body into a space and returns the published
    /// entry.
    ///
    /// Pieces are coalesced up to one [`CHUNK_SIZE`] message — an HTTP body
    /// arrives in whatever pieces the network chose, and a message per TCP
    /// segment would be all overhead — and never beyond it.
    pub async fn put(&self, space: &str, path: &str, body: Body) -> S3Result<EntryInfo> {
        let mut client = self.connect().await?;
        // The daemon takes its gates before it answers, so a refusal — a node
        // in recovery, say — arrives as the coded error it is (§3.4), before a
        // byte of the body has been read.
        let mut put = client.put(space, path).await?;

        let mut stream = body.into_data_stream();
        let mut coalesce = Coalesce::default();
        let mut truncated = None;
        while let Some(piece) = stream.next().await {
            let piece = match piece {
                Ok(piece) => piece,
                // A body that stopped early must not be published as a whole
                // object, and only the daemon can decide that: it is the one
                // holding the staging file.
                Err(e) => {
                    truncated = Some(e.to_string());
                    break;
                }
            };
            for chunk in coalesce.push(&piece) {
                put.chunk(chunk).await?;
            }
        }
        if let Some(why) = truncated {
            return Err(put.abort(why).await.into());
        }
        if let Some(rest) = coalesce.rest() {
            put.chunk(rest).await?;
        }
        Ok(put.finish().await?.entry)
    }

    /// Removes this node's copy of a path and publishes its tombstone (§8).
    pub async fn delete(&self, space: &str, path: &str) -> S3Result<Deleted> {
        Ok(self.connect().await?.delete(space, path).await?)
    }

    /// Opens a multipart upload and returns its id (§9.4).
    pub async fn create_upload(&self, space: &str, path: &str) -> S3Result<String> {
        Ok(self.connect().await?.create_upload(space, path).await?)
    }

    /// Streams one part of an upload, returning what the daemon recorded.
    ///
    /// The same shape as [`Daemon::put`], and for the same reasons: the gates
    /// are taken before the body is read, the payload is coalesced into
    /// protocol-sized messages rather than network-sized ones, and a truncated
    /// body aborts the part rather than recording a short one as whole.
    pub async fn upload_part(
        &self,
        upload: UploadRef,
        number: u32,
        body: Body,
    ) -> S3Result<RecordedPart> {
        let mut client = self.connect().await?;
        let mut part = client.upload_part(upload, number).await?;

        let mut stream = body.into_data_stream();
        let mut coalesce = Coalesce::default();
        let mut truncated = None;
        while let Some(piece) = stream.next().await {
            let piece = match piece {
                Ok(piece) => piece,
                Err(e) => {
                    truncated = Some(e.to_string());
                    break;
                }
            };
            for chunk in coalesce.push(&piece) {
                part.chunk(chunk).await?;
            }
        }
        if let Some(why) = truncated {
            return Err(part.abort(why).await.into());
        }
        if let Some(rest) = coalesce.rest() {
            part.chunk(rest).await?;
        }
        Ok(part.finish().await?)
    }

    /// Assembles the named parts and publishes the object.
    pub async fn complete_upload(
        &self,
        upload: UploadRef,
        parts: &[(u32, Option<synch_core::Hash>)],
    ) -> S3Result<CompletedUpload> {
        Ok(self.connect().await?.complete_upload(upload, parts).await?)
    }

    /// Drops an upload and everything staged for it.
    pub async fn abort_upload(&self, upload: UploadRef) -> S3Result<bool> {
        Ok(self.connect().await?.abort_upload(upload).await?)
    }

    /// Every upload still accepting parts under a prefix.
    pub async fn list_uploads(&self, space: &str, prefix: &str) -> S3Result<Vec<OpenUpload>> {
        Ok(self.connect().await?.list_uploads(space, prefix).await?)
    }

    /// Every part recorded for one upload, in part-number order.
    pub async fn list_parts(&self, upload: UploadRef) -> S3Result<Vec<RecordedPart>> {
        Ok(self.connect().await?.list_parts(upload).await?)
    }

    /// Reads one of the gateway's config values, a record per line.
    pub async fn config(&self, key: &str) -> S3Result<Vec<String>> {
        Ok(self.connect().await?.config(key).await?)
    }

    /// Appends one record to one of the gateway's config values.
    pub async fn append(&self, key: &str, record: &str) -> S3Result<()> {
        self.connect().await?.append_config(key, record).await?;
        Ok(())
    }
}

/// Gathers an HTTP body's pieces into control-protocol chunks.
///
/// A body arrives in whatever pieces the network chose — a TCP segment, a TLS
/// record, whatever the client's writer flushed — and a control message per
/// piece would be all overhead. This accumulates to exactly [`CHUNK_SIZE`] and
/// never beyond it, so the message size is a property of the protocol rather
/// than of the sender's write pattern.
#[derive(Debug, Default)]
struct Coalesce {
    pending: Vec<u8>,
}

impl Coalesce {
    /// Takes one piece of the body and returns every whole chunk it completed.
    fn push(&mut self, piece: &[u8]) -> Vec<Vec<u8>> {
        let mut full = Vec::new();
        let mut rest = piece;
        while !rest.is_empty() {
            if self.pending.capacity() < CHUNK_SIZE {
                self.pending.reserve(CHUNK_SIZE - self.pending.len());
            }
            let take = (CHUNK_SIZE - self.pending.len()).min(rest.len());
            self.pending.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.pending.len() == CHUNK_SIZE {
                full.push(std::mem::take(&mut self.pending));
            }
        }
        full
    }

    /// Whatever is left once the body has ended.
    fn rest(self) -> Option<Vec<u8>> {
        Some(self.pending).filter(|p| !p.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalescing_produces_protocol_sized_chunks() {
        let mut coalesce = Coalesce::default();
        // Nothing under a chunk is emitted early.
        assert!(coalesce.push(&[1u8; 10]).is_empty());
        // A piece that spans a boundary emits exactly the whole chunks in it.
        let chunks = coalesce.push(&vec![2u8; CHUNK_SIZE * 2]);
        assert_eq!(chunks.len(), 2);
        assert!(chunks.iter().all(|c| c.len() == CHUNK_SIZE));
        assert_eq!(coalesce.rest().map(|r| r.len()), Some(10));
    }

    #[test]
    fn an_empty_body_coalesces_to_nothing() {
        let mut coalesce = Coalesce::default();
        assert!(coalesce.push(&[]).is_empty());
        assert_eq!(coalesce.rest(), None);
    }

    #[test]
    fn an_exact_multiple_leaves_no_remainder() {
        let mut coalesce = Coalesce::default();
        assert_eq!(coalesce.push(&vec![7u8; CHUNK_SIZE]).len(), 1);
        assert_eq!(coalesce.rest(), None);
    }
}
