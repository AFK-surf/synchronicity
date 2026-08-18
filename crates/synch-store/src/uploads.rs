//! The multipart uploads an S3 client has open (§9.4).
//!
//! A multipart upload outlives every request in it. The client creates one,
//! streams its parts over minutes or days, and completes it — possibly through
//! a *different* gateway process, since the gateway holds no state of its own
//! and any number of them may point at one daemon (§9.1). The daemon is
//! therefore the only place the conversation can live, and this is where it
//! lives.
//!
//! Two invariants carry the design:
//!
//! - **A part row implies bytes.** A row is written only after its payload is
//!   fsynced and renamed into place, so nothing ever names a file that is not
//!   there. The converse is deliberately allowed to fail — a crash between the
//!   rename and the commit leaves a file no row names — because an
//!   unreferenced file is collectable and an unbacked row is not.
//! - **State is a latch, not a flag.** `open -> completing -> completed`, with
//!   a return to `open` when a completion is refused for something the client
//!   can fix. A boolean cannot tell a retried completion (replay the answer)
//!   from an unknown upload (say so), and S3 clients retry completions
//!   routinely.

use std::path::PathBuf;

use rusqlite::{params, OptionalExtension};
use synch_core::Hash;

use crate::{
    db::Store,
    error::{Result, StoreError},
};

/// The directory under the data dir that holds every open upload's parts.
pub const UPLOADS_DIR: &str = "s3-uploads";

/// The largest part number S3 defines.
pub const MAX_PART_NUMBER: u32 = 10_000;

/// The largest a single part may be: S3's 5 GiB.
pub const MAX_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// The smallest a part may be when it is not the last one: S3's 5 MiB.
pub const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

/// Where an upload is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadState {
    /// Accepting parts.
    Open,
    /// A completion is assembling it right now.
    Completing,
    /// Assembled and published; the row remembers the answer.
    Completed,
}

impl UploadState {
    /// The stored spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            UploadState::Open => "open",
            UploadState::Completing => "completing",
            UploadState::Completed => "completed",
        }
    }

    fn parse(text: &str) -> Result<UploadState> {
        match text {
            "open" => Ok(UploadState::Open),
            "completing" => Ok(UploadState::Completing),
            "completed" => Ok(UploadState::Completed),
            other => Err(StoreError::Column {
                column: "state",
                reason: format!("{other:?} is not an upload state"),
            }),
        }
    }
}

/// One multipart upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upload {
    /// The `UploadId` the client quotes.
    pub id: String,
    /// The space it will publish into.
    pub space: String,
    /// The already-normalized path within that space.
    pub path: String,
    /// When it was created, unix nanoseconds.
    pub created_ns: i64,
    /// Where it is in its life.
    pub state: UploadState,
    /// The object root, once it has completed.
    pub etag: Option<Hash>,
    /// The object size, once it has completed.
    pub size: Option<u64>,
}

/// One uploaded part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPart {
    /// The part number, 1..=10000.
    pub number: u32,
    /// The payload's file name within the upload's directory.
    pub file: String,
    /// Its length in bytes.
    pub size: u64,
    /// Its own blake3 root, which is the ETag the client is given.
    pub root: Hash,
}

fn hash_column(value: Vec<u8>, column: &'static str) -> Result<Hash> {
    let bytes: [u8; 32] = value.try_into().map_err(|v: Vec<u8>| StoreError::Column {
        column,
        reason: format!("{} bytes, not 32", v.len()),
    })?;
    Ok(Hash::from(bytes))
}

fn upload_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Upload, String)> {
    Ok((
        Upload {
            id: row.get(0)?,
            space: row.get(1)?,
            path: row.get(2)?,
            created_ns: row.get(3)?,
            // Parsed outside the closure: `rusqlite` wants its own error type
            // here and the state's validity is this crate's business.
            state: UploadState::Open,
            etag: None,
            size: row.get::<_, Option<i64>>(6)?.map(|n| n as u64),
        },
        row.get::<_, String>(4)?,
    ))
}

fn finish_upload(mut upload: Upload, state: &str, etag: Option<Vec<u8>>) -> Result<Upload> {
    upload.state = UploadState::parse(state)?;
    upload.etag = etag.map(|e| hash_column(e, "etag")).transpose()?;
    Ok(upload)
}

impl Store {
    /// Where an upload's parts are staged.
    ///
    /// Under the data dir rather than beside the target: an abandoned upload
    /// can sit for days, and leaving days of half-uploaded objects inside the
    /// user's own space directory — visible to them, and orphaned outright by
    /// a `space rm` — is not something a gateway should do behind their back.
    pub fn upload_dir(&self, id: &str) -> PathBuf {
        self.data_dir().join(UPLOADS_DIR).join(id)
    }

    /// The root every upload's directory lives under.
    pub fn uploads_dir(&self) -> PathBuf {
        self.data_dir().join(UPLOADS_DIR)
    }

    /// Records a new upload, which the caller has already made a directory for.
    pub fn create_upload(&self, id: &str, space: &str, path: &str, now_ns: i64) -> Result<()> {
        self.with_tx(|tx| {
            tx.execute(
                "INSERT INTO s3_uploads (id, space, path, created_ns, state)
                 VALUES (?1, ?2, ?3, ?4, 'open')",
                params![id, space, path, now_ns],
            )?;
            Ok(())
        })
    }

    /// One upload, by id.
    pub fn upload(&self, id: &str) -> Result<Option<Upload>> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT id, space, path, created_ns, state, etag, size
                   FROM s3_uploads WHERE id = ?1",
                params![id],
                |row| {
                    let (upload, state) = upload_from_row(row)?;
                    Ok((upload, state, row.get::<_, Option<Vec<u8>>>(5)?))
                },
            )
            .optional()?;
        row.map(|(upload, state, etag)| finish_upload(upload, &state, etag))
            .transpose()
    }

    /// Records a part whose payload is already durable.
    ///
    /// Refused unless the upload is still `open`, and refused in the same
    /// statement that checks it: a part accepted while a completion is reading
    /// the part list would be assembled or not depending on which side of the
    /// read it landed, and the client would have no way to know which.
    ///
    /// Returns the file name of the attempt this one superseded, if any. The
    /// caller does **not** unlink it: a completion may already have it open,
    /// and the sweeper collects unreferenced payloads on its own schedule.
    pub fn record_part(&self, upload: &str, part: &UploadPart) -> Result<Option<String>> {
        self.with_immediate_tx(|tx| {
            let open: Option<String> = tx
                .query_row(
                    "SELECT state FROM s3_uploads WHERE id = ?1",
                    params![upload],
                    |row| row.get(0),
                )
                .optional()?;
            match open.as_deref() {
                Some("open") => {}
                Some(_) => {
                    return Err(StoreError::invalid(format!(
                        "upload {upload} is no longer accepting parts"
                    )))
                }
                None => {
                    return Err(StoreError::invalid(format!("no upload {upload}")));
                }
            }
            let superseded: Option<String> = tx
                .query_row(
                    "SELECT file FROM s3_upload_parts WHERE upload = ?1 AND number = ?2",
                    params![upload, part.number],
                    |row| row.get(0),
                )
                .optional()?;
            tx.execute(
                "INSERT OR REPLACE INTO s3_upload_parts (upload, number, file, size, root)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    upload,
                    part.number,
                    part.file,
                    part.size as i64,
                    part.root.as_bytes().as_slice()
                ],
            )?;
            Ok(superseded.filter(|f| *f != part.file))
        })
    }

    /// Every part recorded for an upload, in part-number order.
    pub fn upload_parts(&self, upload: &str) -> Result<Vec<UploadPart>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT number, file, size, root FROM s3_upload_parts
              WHERE upload = ?1 ORDER BY number",
        )?;
        let rows = stmt.query_map(params![upload], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (number, file, size, root) = row?;
            out.push(UploadPart {
                number,
                file,
                size: size as u64,
                root: hash_column(root, "root")?,
            });
        }
        Ok(out)
    }

    /// Latches an upload into `completing` and reads its parts in one step.
    ///
    /// The two have to be one transaction. Reading the parts and *then* taking
    /// the latch would let a part land in between, so the assembly would use a
    /// list the row no longer describes; taking the latch first and reading
    /// after is the same race with the steps swapped. `BEGIN IMMEDIATE` — what
    /// [`Store::with_immediate_tx`] takes — is what makes the pair atomic
    /// against another daemon-side caller and against another process.
    ///
    /// A row already `completed` comes back as `Err(AlreadyCompleted)` carrying
    /// its remembered answer, which is a retried completion, not a failure.
    pub fn begin_complete(&self, id: &str) -> Result<CompleteStart> {
        self.with_immediate_tx(|tx| {
            let found: Option<UploadRow> = tx
                .query_row(
                    "SELECT state, space, path, etag, size FROM s3_uploads WHERE id = ?1",
                    params![id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((state, space, path, etag, size)) = found else {
                return Err(StoreError::invalid(format!("no upload {id}")));
            };
            match UploadState::parse(&state)? {
                UploadState::Completed => {
                    let etag = etag
                        .map(|e| hash_column(e, "etag"))
                        .transpose()?
                        .ok_or_else(|| StoreError::Column {
                            column: "etag",
                            reason: "a completed upload with no root".into(),
                        })?;
                    return Ok(CompleteStart::AlreadyCompleted {
                        etag,
                        size: size.unwrap_or_default() as u64,
                    });
                }
                // Another completion holds the latch. Two clients completing
                // one upload is the case S3 answers by letting exactly one win.
                UploadState::Completing => {
                    return Err(StoreError::invalid(format!(
                        "upload {id} is already being completed"
                    )))
                }
                UploadState::Open => {}
            }
            tx.execute(
                "UPDATE s3_uploads SET state = 'completing' WHERE id = ?1",
                params![id],
            )?;
            let mut stmt = tx.prepare(
                "SELECT number, file, size, root FROM s3_upload_parts
                  WHERE upload = ?1 ORDER BY number",
            )?;
            let rows = stmt.query_map(params![id], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?;
            let mut parts = Vec::new();
            for row in rows {
                let (number, file, size, root) = row?;
                parts.push(UploadPart {
                    number,
                    file,
                    size: size as u64,
                    root: hash_column(root, "root")?,
                });
            }
            Ok(CompleteStart::Ready { space, path, parts })
        })
    }

    /// Returns a latched upload to `open`.
    ///
    /// What a refused completion does: `InvalidPart`, `EntityTooSmall` and
    /// their siblings are all things the client can fix and retry, and an
    /// upload that could not be retried after one of them would strand its
    /// bytes until the sweeper's deadline for no reason.
    pub fn reopen_upload(&self, id: &str) -> Result<()> {
        self.with_tx(|tx| {
            tx.execute(
                "UPDATE s3_uploads SET state = 'open' WHERE id = ?1 AND state = 'completing'",
                params![id],
            )?;
            Ok(())
        })
    }

    /// Records a completed upload's answer and drops its parts.
    ///
    /// The part rows go, so nothing points at payloads the caller is about to
    /// unlink; the upload row stays, remembering the answer, so a client that
    /// never saw the response gets the same one when it retries.
    pub fn finish_complete(&self, id: &str, etag: &Hash, size: u64, now_ns: i64) -> Result<()> {
        self.with_tx(|tx| {
            tx.execute("DELETE FROM s3_upload_parts WHERE upload = ?1", params![id])?;
            tx.execute(
                "UPDATE s3_uploads
                    SET state = 'completed', etag = ?2, size = ?3, completed_ns = ?4
                  WHERE id = ?1",
                params![id, etag.as_bytes().as_slice(), size as i64, now_ns],
            )?;
            Ok(())
        })
    }

    /// Drops an upload outright, parts and all.
    ///
    /// Refused while a completion holds the latch: unlinking the parts out
    /// from under an assembly that is reading them would fail the completion
    /// halfway, and the client that asked for the abort is not the one that
    /// would be told.
    pub fn abort_upload(&self, id: &str) -> Result<bool> {
        self.with_immediate_tx(|tx| {
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM s3_uploads WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()?;
            match state.as_deref() {
                None => return Ok(false),
                Some("completing") => {
                    return Err(StoreError::invalid(format!(
                        "upload {id} is being completed and cannot be aborted"
                    )))
                }
                Some(_) => {}
            }
            tx.execute("DELETE FROM s3_upload_parts WHERE upload = ?1", params![id])?;
            tx.execute("DELETE FROM s3_uploads WHERE id = ?1", params![id])?;
            Ok(true)
        })
    }

    /// Every upload still accepting parts for a space, in key order.
    pub fn open_uploads(&self, space: &str, prefix: &str) -> Result<Vec<Upload>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, space, path, created_ns, state, etag, size FROM s3_uploads
              WHERE space = ?1 AND state = 'open' AND path LIKE ?2 ESCAPE '\\'
              ORDER BY path, id",
        )?;
        let pattern = format!("{}%", like_escape(prefix));
        let rows = stmt.query_map(params![space, pattern], |row| {
            let (upload, state) = upload_from_row(row)?;
            Ok((upload, state, row.get::<_, Option<Vec<u8>>>(5)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (upload, state, etag) = row?;
            out.push(finish_upload(upload, &state, etag)?);
        }
        Ok(out)
    }

    /// Every upload older than a deadline, whatever state it is in.
    ///
    /// The sweeper's input. A `completed` row is swept on the same clock: it
    /// exists only so a retried completion can be answered, and a retry that
    /// has not arrived within the window is not going to.
    pub fn uploads_before(&self, created_before_ns: i64) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT id FROM s3_uploads WHERE created_ns < ?1 ORDER BY created_ns")?;
        let rows = stmt.query_map(params![created_before_ns], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(StoreError::from)
    }

    /// Every upload id the database knows, for reconciling against the disk.
    pub fn upload_ids(&self) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id FROM s3_uploads")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(StoreError::from)
    }

    /// Returns every `completing` upload to `open`.
    ///
    /// Run once at startup. A completion is severed by a daemon stop or a
    /// crash, and the latch it left behind would otherwise refuse every retry
    /// of an upload whose parts are all still there.
    pub fn reopen_interrupted_uploads(&self) -> Result<usize> {
        self.with_tx(|tx| {
            Ok(tx.execute(
                "UPDATE s3_uploads SET state = 'open' WHERE state = 'completing'",
                [],
            )?)
        })
    }
}

/// The columns `begin_complete` reads before it decides what to do:
/// `(state, space, path, etag, size)`.
type UploadRow = (String, String, String, Option<Vec<u8>>, Option<i64>);

/// What [`Store::begin_complete`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompleteStart {
    /// The upload is latched and these are its parts.
    Ready {
        /// The space it publishes into.
        space: String,
        /// The path within that space.
        path: String,
        /// Every part recorded, in part-number order.
        parts: Vec<UploadPart>,
    },
    /// It had already completed, and this was the answer.
    AlreadyCompleted {
        /// The object root.
        etag: Hash,
        /// The object size.
        size: u64,
    },
}

/// Escapes the wildcards in a `LIKE` prefix, so a key containing `%` or `_`
/// matches itself rather than everything.
fn like_escape(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len());
    for c in prefix.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
