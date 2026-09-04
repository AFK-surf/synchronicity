//! `synch put` and `synch delete` — this node's own writes, made without a
//! checkout.
//!
//! Both are clients of the daemon's typed write path (§9.4). `put` streams a
//! local file, or stdin, into the same `Put` the S3 gateway and `synch fetch`
//! write through, so no copy of the payload is ever held whole anywhere and
//! the entry is published only once the reader ended — a read that *fails*
//! partway aborts the write and the daemon keeps nothing. What put cannot
//! tell apart is a producer that finished from one that died: a pipe whose
//! writer was killed delivers a clean end of stream, and that is the end of
//! the payload. `fetch` has `Content-Length` to hold a server to; a pipe
//! promises nothing. `delete` publishes this node's tombstone through the
//! same `Delete` the gateway's `DeleteObject` uses. Neither needs the space
//! to have a directory: on an API source the payload goes CAS-direct and
//! nothing is materialized (`docs/SERVERLESS.md` §10).

use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::control::{
    proto::{PutPart, CHUNK_SIZE},
    Client, Deleted, StreamedWrite, Written,
};

/// The argument that names stdin instead of a file.
const STDIN: &str = "-";

/// Runs `synch put <file> <destination>`.
pub async fn run_put(data_dir: &Path, file: &Path, destination: &str) -> Result<()> {
    let written = put(data_dir, file, destination).await?;
    println!(
        "wrote {}/{} ({} bytes)",
        written.entry.space, written.entry.path, written.entry.size
    );
    Ok(())
}

/// Streams the file — or stdin, for `-` — into the tree and publishes it at
/// the destination.
///
/// Split from [`run_put`] so the tests get the published entry back rather
/// than reading stdout.
pub async fn put(data_dir: &Path, file: &Path, destination: &str) -> Result<Written> {
    let destination = Destination::parse(destination)?;
    let from_stdin = file.as_os_str() == STDIN;

    // The name is settled, and the file opened, before the daemon is asked
    // for anything: a destination that needs a name stdin cannot give, or a
    // file that is not there, is this process's mistake to report, and no
    // write should have opened for it.
    let path = match destination.explicit_path() {
        Some(path) => path,
        None if from_stdin => {
            anyhow::bail!("stdin carries no file name; give the destination an explicit file name")
        }
        None => {
            // `file_name` is already one component — never `.`, `..`, or a
            // separator — so the only way to lack a name is to be `..`, a
            // root, or not UTF-8.
            let name = file
                .file_name()
                .and_then(|name| name.to_str())
                .with_context(|| {
                    format!(
                        "{} does not name a file; give the destination an explicit file name",
                        file.display()
                    )
                })?;
            destination.join(name)
        }
    };
    let opened = match from_stdin {
        true => None,
        false => Some(open(file).await?),
    };

    match opened {
        Some(reader) => {
            stream(
                data_dir,
                reader,
                &destination.space,
                &path,
                &file.display().to_string(),
            )
            .await
        }
        None => {
            stream(
                data_dir,
                tokio::io::stdin(),
                &destination.space,
                &path,
                "stdin",
            )
            .await
        }
    }
}

/// Streams any reader into the tree and publishes it at the destination,
/// which must name a file: there is no file name to complete a directory
/// with.
///
/// The entry point for a caller that holds the payload as a stream rather
/// than a path — and the one the tests drive with a reader that fails, since
/// no file on disk fails to read on cue.
pub async fn put_from<R: AsyncRead + Unpin>(
    data_dir: &Path,
    reader: R,
    destination: &str,
) -> Result<Written> {
    let destination = Destination::parse(destination)?;
    let Some(path) = destination.explicit_path() else {
        anyhow::bail!(
            "`{}/{}` names no file; a stream has no file name to complete a directory with",
            destination.space,
            destination.path
        );
    };
    stream(data_dir, reader, &destination.space, &path, "the payload").await
}

/// Opens the file to stream, refusing what could never be one payload.
async fn open(file: &Path) -> Result<tokio::fs::File> {
    let metadata = tokio::fs::metadata(file)
        .await
        .with_context(|| format!("reading {}", file.display()))?;
    // A directory opens fine and fails on the first read, with the kernel's
    // wording; naming the actual problem is worth the extra call.
    if metadata.is_dir() {
        anyhow::bail!(
            "{} is a directory; put takes one file, or `synch adopt tree` for a tree",
            file.display()
        );
    }
    tokio::fs::File::open(file)
        .await
        .with_context(|| format!("reading {}", file.display()))
}

/// Opens the write, streams a reader into it in protocol-sized chunks, and
/// commits it once the reader ends.
///
/// The payload arrives in whatever pieces the reader chose — a pipe hands
/// over what its writer wrote, a file what the kernel read — and they are
/// coalesced into full chunks exactly as `synch fetch` and the S3 gateway
/// do, so the message size is a property of the protocol rather than of the
/// source's write pattern.
async fn stream<R: AsyncRead + Unpin>(
    data_dir: &Path,
    mut reader: R,
    space: &str,
    path: &str,
    what: &str,
) -> Result<Written> {
    // The daemon takes its gates — publishability, a resolvable target —
    // before `put` returns, so a destination it refuses fails here, before
    // a byte of the payload is read (§9.4).
    let mut client = Client::connect(data_dir).await?;
    let mut put: StreamedWrite<PutPart> = client.put(space, path).await?;

    let mut ended = false;
    while !ended {
        // A fixed buffer filled to the brim, rather than a `Vec` grown by
        // `read_buf`: the chunk is exactly `CHUNK_SIZE` by construction, not
        // by an allocator's opinion of what "at least this capacity" means.
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let mut filled = 0;
        while filled < CHUNK_SIZE {
            match reader.read(&mut chunk[filled..]).await {
                Ok(0) => {
                    ended = true;
                    break;
                }
                Ok(n) => filled += n,
                // A read that fails — a disk that errored, a stream that
                // broke — aborts the write: a truncated payload must never be
                // published as this node's own assertion (§9.4). The abort's
                // answer is the daemon's own account of what it threw away,
                // so it travels in the error rather than being discarded.
                Err(e) => {
                    let failed = format!("reading {what} failed");
                    let aborted = put.abort(format!("reading {what} failed: {e}")).await;
                    return Err(anyhow::Error::from(e).context(aborted).context(failed));
                }
            }
        }
        chunk.truncate(filled);
        if !chunk.is_empty() {
            put.chunk(chunk).await?;
        }
    }
    Ok(put.finish().await?)
}

/// Runs `synch delete <space>/<path>`.
pub async fn run_delete(data_dir: &Path, target: &str) -> Result<()> {
    let (target, deleted) = delete(data_dir, target).await?;
    let note = match deleted.still_published {
        true => "another origin still publishes this path, so it stays readable",
        false => "no origin publishes this path any more",
    };
    println!("deleted {}/{}: {note}", target.space, target.path);
    Ok(())
}

/// Removes this node's copy of the path and publishes its tombstone.
///
/// Returns the parsed target with the daemon's answer, so the caller can
/// name what was deleted without parsing twice.
pub async fn delete(data_dir: &Path, target: &str) -> Result<(Destination, Deleted)> {
    let target = Destination::parse(target)?;
    if target.explicit_path().is_none() {
        anyhow::bail!(
            "`{}/{}` names no file; a delete takes one <space>/<path>",
            target.space,
            target.path
        );
    }
    let mut client = Client::connect(data_dir).await?;
    let deleted = client.delete(&target.space, &target.path).await?;
    Ok((target, deleted))
}

/// Where a write lands: a space, and the path — or directory — within it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// The space to write into.
    pub space: String,
    /// The path within the space. Empty or `/`-terminated means a directory,
    /// to be completed with the file name the source carries.
    pub path: String,
}

impl Destination {
    /// Parses `<space>/<path>` or `<space>/<dir>/`.
    pub fn parse(text: &str) -> Result<Destination> {
        // The messages stay neutral about which command is asking: `put`
        // and `fetch` also take `<space>/<dir>/`, `delete` does not, and
        // each says so in its own `--help`.
        let Some((space, path)) = text.split_once('/') else {
            anyhow::bail!("`{text}` is not a destination; use <space>/<path>");
        };
        if space.is_empty() {
            anyhow::bail!("`{text}` names no space; use <space>/<path>");
        }
        // Every reference-taking read accepts `<origin>:`, so say why this
        // one cannot rather than failing on a space that does not exist.
        if space.contains(':') {
            anyhow::bail!(
                "`{text}` names an origin, and this command acts on this node's own version; \
                 use <space>/<path>"
            );
        }
        Ok(Destination {
            space: space.to_string(),
            path: path.to_string(),
        })
    }

    /// The path as written, when the destination names a file rather than a
    /// directory to complete.
    pub fn explicit_path(&self) -> Option<String> {
        let named = !self.path.is_empty() && !self.path.ends_with('/');
        named.then(|| self.path.clone())
    }

    /// Completes a directory destination with a file name.
    pub fn join(&self, name: &str) -> String {
        format!("{}{name}", self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_destination_names_a_space() {
        for bad in ["workspace", "", "/path"] {
            assert!(Destination::parse(bad).is_err(), "{bad}");
        }
        // An origin prefix is refused with its reason, not as a missing space.
        let e = Destination::parse("nas@cluster.example:media/f").unwrap_err();
        assert!(e.to_string().contains("own version"), "{e:#}");
    }

    #[test]
    fn a_file_destination_is_explicit_and_a_directory_one_is_completed() {
        let file = Destination::parse("workspace/images/system.img").unwrap();
        assert_eq!(file.explicit_path().as_deref(), Some("images/system.img"));

        for (text, joined) in [
            ("workspace/documents/", "documents/1.txt"),
            ("workspace/", "1.txt"),
        ] {
            let dir = Destination::parse(text).unwrap();
            assert_eq!(dir.explicit_path(), None, "{text}");
            assert_eq!(dir.join("1.txt"), joined, "{text}");
        }
    }
}
