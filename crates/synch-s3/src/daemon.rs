//! The gateway's link to the daemon (§9.1, §9.4).
//!
//! **The gateway is a control-socket client of the daemon — nothing more.** It
//! never opens the database, never binds an iroh endpoint, and holds no
//! persistent state of its own; its only datadir touch is reading
//! `control.token`, exactly like the CLI. That is not optional hygiene: a
//! second process computing `next_seq` beside the daemon can sign two heads at
//! the same seq — self-equivocation broadcast cluster-wide, with the losing
//! batch's files recorded as scanned but present in no surviving root.
//!
//! One connection carries one command (§9.3), so every method here opens one,
//! says one thing, and drops it.

use std::path::{Path, PathBuf};

use axum::body::Body;
use synch_cli::control::{
    proto::{Response, CHUNK_SIZE},
    Client, EntryInfo, Request, Upload,
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

    /// Opens a connection, completes the handshake, and sends one request.
    async fn send(&self, request: Request) -> S3Result<Client> {
        let mut client = Client::connect(&self.data_dir).await?;
        client.send(&request).await?;
        Ok(client)
    }

    /// Every `Line` of a response, for the requests that answer in text.
    pub async fn lines(&self, request: Request) -> S3Result<Vec<String>> {
        let mut client = self.send(request).await?;
        let mut out = Vec::new();
        while let Some(frame) = client.next().await? {
            if let Response::Line(text) = frame {
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
        self.lines(Request::Id)
            .await?
            .iter()
            .find_map(|line| line.strip_prefix("origin: ").map(str::to_string))
            .ok_or_else(|| S3Error::store("the daemon did not report an origin"))
    }

    /// Whether any origin publishes `space`, or a local space claims the id.
    ///
    /// `bucket add` warns on false rather than refusing: mapping a bucket
    /// before its space first syncs is a legitimate order of operations, but
    /// doing it to a typo'd id used to be indistinguishable from success.
    pub async fn space_known(&self, space: &str) -> S3Result<bool> {
        match self
            .lines(Request::Status {
                reference: Some(space.to_string()),
            })
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
        let mut client = self
            .send(Request::TreeResolve {
                space: space.to_string(),
                path: path.to_string(),
                policy: Some(policy.to_string()),
            })
            .await?;
        let mut found = None;
        while let Some(frame) = client.next().await? {
            if let Response::Entry(info) = frame {
                found = Some(*info);
            }
        }
        found.ok_or_else(|| S3Error::no_such_key(path))
    }

    /// The unified listing under a prefix, resolved by a policy.
    ///
    /// `wanted` bounds what is *read*, not what the daemon offers: the caller
    /// stops consuming and the connection is dropped, which is an ordinary way
    /// for a control response to end (§9.3). Returns whether the daemon still
    /// had more to say — S3's `IsTruncated`.
    pub async fn list(
        &self,
        space: &str,
        prefix: &str,
        start_after: Option<&str>,
        wanted: usize,
        policy: &str,
    ) -> S3Result<(Vec<EntryInfo>, bool)> {
        let mut client = self
            .send(Request::TreeList {
                space: space.to_string(),
                prefix: prefix.to_string(),
                start_after: start_after.map(str::to_string),
                limit: None,
                policy: Some(policy.to_string()),
            })
            .await?;
        let mut out = Vec::new();
        while let Some(frame) = client.next().await? {
            if let Response::Entry(info) = frame {
                if out.len() == wanted {
                    return Ok((out, true));
                }
                out.push(*info);
            }
        }
        Ok((out, false))
    }

    /// Streams a verified byte range straight into an HTTP response body.
    ///
    /// The socket's `Chunk` frames become body frames one for one: nothing on
    /// this side ever holds more than a couple of them, whatever the object's
    /// size (§9.4).
    pub async fn read(
        &self,
        space: &str,
        path: &str,
        policy: &str,
        start: u64,
        len: Option<u64>,
    ) -> S3Result<Body> {
        let mut client = self
            .send(Request::TreeRead {
                space: space.to_string(),
                path: path.to_string(),
                policy: Some(policy.to_string()),
                start,
                len,
            })
            .await?;
        // The first frame is pulled here rather than in the pump, so a failure
        // the daemon reports up front — no provider for the content, a strict
        // bucket's divergence — becomes an S3 error instead of a body that dies
        // after a 200 has already gone out.
        let first = client.next().await?;

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(READ_AHEAD);
        tokio::spawn(async move {
            let mut frame = first;
            loop {
                if let Some(Response::Chunk(bytes)) = frame {
                    // A send that fails means the HTTP client hung up; the
                    // dropped `Client` takes the daemon's side down with it.
                    if tx.send(Ok(bytes)).await.is_err() {
                        return;
                    }
                }
                frame = match client.next().await {
                    Ok(None) => return,
                    Ok(frame) => frame,
                    // Mid-body there is no status left to change, so the body
                    // ends in an error and the connection is what carries the
                    // bad news.
                    Err(e) => {
                        let _ = tx.send(Err(std::io::Error::other(e.message))).await;
                        return;
                    }
                };
            }
        });
        Ok(Body::from_stream(ReceiverStream::new(rx)))
    }

    /// Streams an HTTP request body into a space and returns the published
    /// entry.
    ///
    /// Pieces are coalesced up to one [`CHUNK_SIZE`] frame — an HTTP body
    /// arrives in whatever pieces the network chose, and a frame per TCP
    /// segment would be all overhead — and never beyond it.
    pub async fn put(&self, space: &str, path: &str, body: Body) -> S3Result<EntryInfo> {
        let mut client = self
            .send(Request::TreePut {
                space: space.to_string(),
                path: path.to_string(),
            })
            .await?;
        // The daemon acks once its gates are taken. Waiting for the ack is
        // what turns a refusal — a node in recovery, say — into the coded
        // error it is (§3.4): a client already streaming would race the error
        // frame against its own writes and could lose it to the transport.
        match client.next().await? {
            Some(Response::Ready) => {}
            _ => return Err(S3Error::store("the daemon did not acknowledge the write")),
        }

        let mut stream = body.into_data_stream();
        let mut pending: Vec<u8> = Vec::with_capacity(CHUNK_SIZE);
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
            let mut rest: &[u8] = &piece;
            while !rest.is_empty() {
                let take = (CHUNK_SIZE - pending.len()).min(rest.len());
                pending.extend_from_slice(&rest[..take]);
                rest = &rest[take..];
                if pending.len() == CHUNK_SIZE {
                    client
                        .upload(&Upload::Chunk(std::mem::take(&mut pending)))
                        .await?;
                    pending.reserve(CHUNK_SIZE);
                }
            }
        }
        match truncated {
            Some(why) => client.upload(&Upload::Abort(why)).await?,
            None => {
                if !pending.is_empty() {
                    client.upload(&Upload::Chunk(pending)).await?;
                }
                client.upload(&Upload::End).await?;
            }
        }

        let mut published = None;
        while let Some(frame) = client.next().await? {
            if let Response::Entry(info) = frame {
                published = Some(*info);
            }
        }
        published.ok_or_else(|| S3Error::store("the daemon did not report the published entry"))
    }

    /// Reads one of the gateway's config values, a record per line.
    pub async fn config(&self, key: &str) -> S3Result<Vec<String>> {
        self.lines(Request::ConfigGet {
            key: key.to_string(),
        })
        .await
    }

    /// Appends one record to one of the gateway's config values.
    pub async fn append(&self, key: &str, record: &str) -> S3Result<()> {
        self.lines(Request::ConfigAppend {
            key: key.to_string(),
            record: record.to_string(),
        })
        .await?;
        Ok(())
    }
}
