//! `synch fetch` — an http(s) URL streamed into the tree.
//!
//! The download happens in this process, not the daemon: the daemon speaks to
//! peers and owns no HTTP client, and the CLI is only ever a client bringing
//! it bytes (§9.1). The response body streams into the same typed `Put` the
//! S3 gateway writes through (§9.4), so no copy of the payload is ever held
//! whole anywhere, and the entry is published only when the body completed —
//! a download that fails partway aborts the write and the daemon keeps
//! nothing.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::control::{proto::CHUNK_SIZE, Client, Written};

/// How long establishing the HTTP connection may take. The transfer itself
/// has no deadline: a large file over a slow link is not a fault.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs `synch fetch <url> <destination>`.
pub async fn run(data_dir: &Path, url: &str, destination: &str) -> Result<()> {
    let written = fetch(data_dir, url, destination).await?;
    println!(
        "fetched {}/{} ({} bytes)",
        written.entry.space, written.entry.path, written.entry.size
    );
    Ok(())
}

/// Downloads the URL and publishes it at the destination.
///
/// Split from [`run`] so the tests get the published entry back rather than
/// reading stdout.
pub async fn fetch(data_dir: &Path, url: &str, destination: &str) -> Result<Written> {
    let url = reqwest::Url::parse(url).with_context(|| format!("`{url}` is not a URL"))?;
    match url.scheme() {
        "http" | "https" => {}
        other => anyhow::bail!("cannot fetch `{other}` URLs; fetch takes http:// or https://"),
    }
    let destination = Destination::parse(destination)?;

    // Redirects are followed to reqwest's default depth of ten, and
    // environment proxies are honored, as everywhere else this workspace
    // speaks HTTP (`synch_net::dns`).
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .context("building the HTTP client")?;
    let mut response = http
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("{} answered {status}", response.url());
    }
    // The file name comes off the URL the response actually came from, so a
    // redirect to the real file names the entry after what was served.
    let path = destination.entry_path(response.url())?;

    // The daemon takes its gates — publishability, a resolvable target —
    // before `put` returns, so a destination it refuses fails here, before
    // the body is read (§9.4).
    let mut client = Client::connect(data_dir).await?;
    let mut put = client.put(&destination.space, &path).await?;

    // The body arrives in whatever pieces the network chose; they are
    // coalesced into protocol-sized chunks exactly as the S3 gateway does,
    // so the message size is a property of the protocol rather than of the
    // server's write pattern.
    let mut pending: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(piece)) => {
                let mut rest = &piece[..];
                while !rest.is_empty() {
                    let take = (CHUNK_SIZE - pending.len()).min(rest.len());
                    pending.extend_from_slice(&rest[..take]);
                    rest = &rest[take..];
                    if pending.len() == CHUNK_SIZE {
                        put.chunk(std::mem::take(&mut pending)).await?;
                    }
                }
            }
            Ok(None) => break,
            // A body that stopped early — a dropped connection, a length the
            // server never honored — aborts the write: a truncated download
            // must never be published as this node's own assertion (§9.4).
            Err(e) => {
                let failed = format!(
                    "the download from {} failed; nothing was published",
                    response.url()
                );
                let _ = put.abort(format!("the download failed: {e}")).await;
                return Err(anyhow::Error::from(e).context(failed));
            }
        }
    }
    if !pending.is_empty() {
        put.chunk(pending).await?;
    }
    Ok(put.finish().await?)
}

/// Where a fetch lands: a space, and the path — or directory — within it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Destination {
    /// The space to write into.
    space: String,
    /// The path within the space. Empty or `/`-terminated means a directory,
    /// completed with the file name the URL carries.
    path: String,
}

impl Destination {
    /// Parses `<space>/<path>` or `<space>/<dir>/`.
    fn parse(text: &str) -> Result<Destination> {
        let Some((space, path)) = text.split_once('/') else {
            anyhow::bail!(
                "`{text}` is not a destination; use <space>/<path>, or <space>/<dir>/ to \
                 keep the URL's file name"
            );
        };
        if space.is_empty() {
            anyhow::bail!("`{text}` names no space; use <space>/<path>");
        }
        Ok(Destination {
            space: space.to_string(),
            path: path.to_string(),
        })
    }

    /// The path this fetch publishes, completing a directory destination with
    /// the file name the URL carries.
    fn entry_path(&self, url: &reqwest::Url) -> Result<String> {
        if !self.path.is_empty() && !self.path.ends_with('/') {
            return Ok(self.path.clone());
        }
        let name = file_name(url).with_context(|| {
            format!("{url} does not name a file; give the destination an explicit file name")
        })?;
        Ok(format!("{}{name}", self.path))
    }
}

/// The file name a URL carries: its last path segment, percent-decoded.
///
/// `None` when there is nothing usable — a URL ending in `/`, a bare host, an
/// escape that does not decode, or a decoded name that would not stay a
/// single path component.
fn file_name(url: &reqwest::Url) -> Option<String> {
    let segment = url.path_segments()?.next_back()?;
    let name = percent_decode(segment)?;
    let single_component = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.contains('\0');
    single_component.then_some(name)
}

/// Decodes `%XX` escapes. Small and strict rather than a dependency: an
/// escape that is not two hex digits, or bytes that are not UTF-8, is `None`.
fn percent_decode(text: &str) -> Option<String> {
    if !text.contains('%') {
        return Some(text.to_string());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_path(destination: &str, url: &str) -> Result<String> {
        Destination::parse(destination)?.entry_path(&reqwest::Url::parse(url).unwrap())
    }

    #[test]
    fn a_file_destination_is_taken_as_written() {
        assert_eq!(
            entry_path(
                "workspace/images/system.img",
                "https://example.com/test.img"
            )
            .unwrap(),
            "images/system.img"
        );
    }

    #[test]
    fn a_directory_destination_keeps_the_urls_file_name() {
        assert_eq!(
            entry_path("workspace/documents/", "https://example.com/1.txt").unwrap(),
            "documents/1.txt"
        );
        // The space root is a directory too.
        assert_eq!(
            entry_path("workspace/", "http://localhost:1234/test.png").unwrap(),
            "test.png"
        );
        // The query is not part of the name.
        assert_eq!(
            entry_path("w/d/", "https://example.com/a/report.pdf?token=abc#frag").unwrap(),
            "d/report.pdf"
        );
        // Escapes decode into the published name.
        assert_eq!(
            entry_path("w/d/", "https://example.com/my%20notes.txt").unwrap(),
            "d/my notes.txt"
        );
    }

    #[test]
    fn a_url_without_a_file_name_needs_an_explicit_one() {
        for url in [
            "https://example.com/",
            "https://example.com",
            "https://example.com/dir/",
            // A decoded separator would not stay one path component.
            "https://example.com/a%2Fb",
            "https://example.com/%2e%2e",
            // An escape that is not two hex digits.
            "https://example.com/bad%zzname",
        ] {
            let e = entry_path("workspace/documents/", url).unwrap_err();
            assert!(
                e.to_string().contains("does not name a file"),
                "{url}: {e:#}"
            );
        }
    }

    #[test]
    fn a_destination_names_a_space() {
        for bad in ["workspace", "", "/path"] {
            assert!(Destination::parse(bad).is_err(), "{bad}");
        }
    }
}
