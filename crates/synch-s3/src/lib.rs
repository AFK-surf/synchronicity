//! An S3-compatible gateway onto a synchronicity cluster (§9.4).
//!
//! The gateway exposes a subset of the S3 HTTP API so existing S3 tooling can
//! read and write a cluster without knowing anything about it. **It is a
//! control client of the daemon and nothing more** (§9.1): it never
//! opens the database, never binds an iroh endpoint, and holds no persistent
//! state of its own. Every operation is a daemon request — reads stream the
//! socket's `Chunk` frames straight into the HTTP response, writes stream the
//! HTTP body over the socket into the daemon's ingest-and-publish path, and
//! bucket and access-key configuration is stored by the daemon under the `s3.*`
//! config namespace.
//!
//! Objects of any size therefore flow through both directions without either
//! process buffering more than a chunk. Reads serve the version each bucket's
//! policy selects from the unified tree (§8) and content flows through the
//! normal verified path — local CAS first, then peer fetch, with per-16 KiB
//! group verification. ETags are the selected version's BLAKE3 root, hex,
//! quoted.
#![deny(missing_docs)]

pub mod auth;
pub mod buckets;
pub mod daemon;
pub mod error;
pub mod xml;

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Router,
};
use synch_cli::control::EntryInfo;
use synch_core::EntryKind;

use crate::{
    auth::{AuthMode, SignedRequest, UNSIGNED_PAYLOAD},
    buckets::Bucket,
    daemon::Daemon,
    error::{S3Error, S3Result},
    xml::{format_http_date, format_timestamp, list_buckets_xml, ListResult, ListedObject},
};

/// The default `max-keys` for a listing.
pub const DEFAULT_MAX_KEYS: usize = 1000;

/// The gateway's shared state: a daemon to ask, and how to authenticate the
/// clients asking.
#[derive(Debug, Clone)]
pub struct Gateway {
    daemon: Daemon,
    auth: Arc<AuthMode>,
    /// This node's own origin, read once at startup.
    ///
    /// Only used to recognize a bucket pinned to somebody else's view, and a
    /// node's origin does not change while it runs — a key rotation moves the
    /// key, not the identity (§3.1).
    origin: Arc<String>,
}

impl Gateway {
    /// Builds a gateway over a daemon.
    pub async fn new(daemon: Daemon, auth: AuthMode) -> S3Result<Gateway> {
        let origin = daemon.origin().await?;
        Ok(Gateway {
            daemon,
            auth: Arc::new(auth),
            origin: Arc::new(origin),
        })
    }

    /// The daemon the gateway serves from.
    pub fn daemon(&self) -> &Daemon {
        &self.daemon
    }

    /// This node's own origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The axum router, ready to serve.
    pub fn router(self) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
}

/// True if a bind address is loopback-only, which `--anonymous` requires (§9.4).
pub fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

async fn handle(State(gateway): State<Gateway>, request: Request) -> Response {
    match dispatch(&gateway, request).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

async fn dispatch(gateway: &Gateway, request: Request) -> S3Result<Response> {
    let (parts, body) = request.into_parts();
    let headers = lowercase_headers(&parts.headers);
    let query = parse_query(&parts.uri);
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .cloned()
        .unwrap_or_else(|| UNSIGNED_PAYLOAD.to_string());

    let path = percent_decode(parts.uri.path());
    // Sign over the *decoded* path: `canonical_uri` URI-encodes each segment
    // exactly once, mirroring what a spec-compliant client signs. Passing the
    // still-encoded wire path here would re-encode the `%` and double-encode any
    // key with a space, Unicode, or reserved character, so every such request
    // would fail with SignatureDoesNotMatch. (Query params are already handled
    // this way — decoded in `parse_query`, re-encoded once in `canonical_request`.)
    auth::verify(
        &gateway.auth,
        &SignedRequest {
            method: parts.method.as_str(),
            path: &path,
            query: &query,
            headers: &headers,
            payload_hash: &payload_hash,
        },
        now_unix_secs(),
    )?;

    // Path-style addressing: /<bucket>/<key...>
    let trimmed = path.trim_start_matches('/');
    let (bucket_name, key) = match trimmed.split_once('/') {
        Some((bucket, key)) => (bucket, key),
        None => (trimmed, ""),
    };

    if bucket_name.is_empty() {
        if parts.method != Method::GET {
            return Err(S3Error::not_implemented("this service-level operation"));
        }
        let names: Vec<String> = buckets::load(&gateway.daemon)
            .await?
            .into_iter()
            .map(|b| b.name)
            .collect();
        return Ok(xml_response(StatusCode::OK, list_buckets_xml(&names)));
    }

    let bucket = buckets::find(&gateway.daemon, bucket_name).await?;

    match (&parts.method, key.is_empty()) {
        // Buckets are mapped by the operator, not minted over HTTP — but SDK
        // write paths (rclone's among them) probe with CreateBucket and
        // HeadBucket before an upload and give up if either fails. A bucket
        // that exists answers both truthfully; one that does not already
        // failed the lookup above with NoSuchBucket.
        (&Method::PUT, true) => Ok((StatusCode::OK).into_response()),
        (&Method::HEAD, true) => Ok((StatusCode::OK).into_response()),
        (&Method::GET, true) => list_objects(gateway, &bucket, &query).await,
        (&Method::GET, false) => get_object(gateway, &bucket, key, &headers, false).await,
        (&Method::HEAD, false) => get_object(gateway, &bucket, key, &headers, true).await,
        (&Method::PUT, false) => put_object(gateway, &bucket, key, body).await,
        (&Method::DELETE, _) => Err(S3Error::not_implemented("DeleteObject")),
        (&Method::POST, _) => Err(S3Error::not_implemented("multipart upload")),
        _ => Err(S3Error::not_implemented("this operation")),
    }
}

async fn list_objects(
    gateway: &Gateway,
    bucket: &Bucket,
    query: &[(String, String)],
) -> S3Result<Response> {
    let prefix = param(query, "prefix").unwrap_or_default();
    let delimiter = param(query, "delimiter").filter(|d| !d.is_empty());
    let max_keys = param(query, "max-keys")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_KEYS)
        .clamp(1, DEFAULT_MAX_KEYS);
    // Continuation tokens are trie cursor positions: the last key returned.
    let token = param(query, "continuation-token").filter(|t| !t.is_empty());
    let start_after = token.clone().or_else(|| param(query, "start-after"));

    // The unified tree, one key per path (§8), already resolved under the
    // bucket's policy by the daemon. `max_keys + 1` rows is what it takes to
    // know whether there is a next page; a delimiter can fold several of them
    // into one common prefix, so the loop below may ask for no more than it
    // was given and still stop short.
    let (listing, more) = gateway
        .daemon
        .list(
            &bucket.space,
            &prefix,
            start_after.as_deref(),
            max_keys + 1,
            &bucket.policy.render(),
        )
        .await?;

    let mut result = ListResult {
        bucket: bucket.name.clone(),
        prefix: prefix.clone(),
        delimiter: delimiter.clone(),
        max_keys,
        continuation_token: token,
        ..ListResult::default()
    };
    // The cursor advances past every path this page has dealt with, whether it
    // became an object, a common prefix, or nothing at all — so a page made
    // entirely of skipped rows still hands back a token that moves.
    let mut cursor = None;
    for row in &listing {
        // Only a regular file is an S3 object. A directory marker and a
        // tombstone are obviously not, and neither is a symlink: its version
        // identity is its target, not content (§8), so it has no object root
        // to be an ETag and no bytes to serve. Listing one would advertise a
        // key whose GET can only fail.
        if row.kind != EntryKind::File {
            cursor = Some(row.path.clone());
            continue;
        }
        let full = result.contents.len() + result.common_prefixes.len() >= max_keys;
        // The delimiter rolls everything below the next separator into a
        // common prefix, which is how S3 tooling renders directories.
        if let Some(delimiter) = &delimiter {
            let rest = &row.path[prefix.len().min(row.path.len())..];
            if let Some(idx) = rest.find(delimiter.as_str()) {
                let common = format!("{}{}{}", prefix, &rest[..idx], delimiter);
                if !result.common_prefixes.contains(&common) {
                    if full {
                        result.is_truncated = true;
                        break;
                    }
                    result.common_prefixes.push(common);
                }
                cursor = Some(row.path.clone());
                continue;
            }
        }
        if full {
            result.is_truncated = true;
            break;
        }
        result.contents.push(ListedObject {
            key: row.path.clone(),
            size: row.size,
            etag: etag(row.content.as_ref()),
            last_modified: format_timestamp(row.mtime_ns),
        });
        cursor = Some(row.path.clone());
    }
    // Everything the daemon offered fit on the page, but it had more to offer:
    // the page ends here anyway, and the cursor resumes past its last row.
    if more {
        result.is_truncated = true;
    }
    if result.is_truncated {
        result.next_continuation_token = cursor;
    }
    Ok(xml_response(StatusCode::OK, result.to_xml()))
}

async fn get_object(
    gateway: &Gateway,
    bucket: &Bucket,
    key: &str,
    headers: &BTreeMap<String, String>,
    head_only: bool,
) -> S3Result<Response> {
    let policy = bucket.policy.render();
    // Metadata first, and metadata only: `HeadObject` answers size, mtime, and
    // ETag straight from the entry, with no content fetched at all (§9.4).
    let entry = gateway
        .daemon
        .resolve(&bucket.space, key, &policy)
        .await
        .map_err(|e| e.with_key(key))?;
    // Whatever a listing leaves out, a direct read leaves out too, or the
    // gateway would answer for keys it will not admit to having.
    if entry.kind != EntryKind::File {
        return Err(S3Error::no_such_key(key));
    }

    let mut response_headers = HeaderMap::new();
    insert(
        &mut response_headers,
        header::ETAG,
        &etag(entry.content.as_ref()),
    );
    insert(&mut response_headers, header::ACCEPT_RANGES, "bytes");
    // The header wants HTTP-date, not the RFC 3339 the XML body uses — SDKs
    // parse `Last-Modified` strictly, and rclone refused the wrong shape.
    insert(
        &mut response_headers,
        header::LAST_MODIFIED,
        &format_http_date(entry.mtime_ns),
    );
    insert(
        &mut response_headers,
        header::CONTENT_TYPE,
        "application/octet-stream",
    );

    let range = headers
        .get("range")
        .map(|value| parse_range(value, entry.size))
        .transpose()?;

    if head_only {
        insert(
            &mut response_headers,
            header::CONTENT_LENGTH,
            &entry.size.to_string(),
        );
        return Ok((StatusCode::OK, response_headers).into_response());
    }

    let (start, end, status) = match range {
        Some((start, end)) => {
            insert(
                &mut response_headers,
                header::CONTENT_RANGE,
                &format!("bytes {start}-{}/{}", end.saturating_sub(1), entry.size),
            );
            (start, end, StatusCode::PARTIAL_CONTENT)
        }
        None => (0, entry.size, StatusCode::OK),
    };
    let length = end.saturating_sub(start);
    insert(
        &mut response_headers,
        header::CONTENT_LENGTH,
        &length.to_string(),
    );

    // The content flows through the normal verified path — local CAS first,
    // then a peer fetch, every 16 KiB group checked against the object root —
    // and the socket's chunks become body frames one for one, so a multi-
    // gigabyte object costs a chunk of memory here and a chunk in the daemon.
    let body = gateway
        .daemon
        .read(&bucket.space, key, &policy, start, Some(length))
        .await
        .map_err(|e| e.with_key(key))?;
    Ok((status, response_headers, body).into_response())
}

async fn put_object(
    gateway: &Gateway,
    bucket: &Bucket,
    key: &str,
    body: Body,
) -> S3Result<Response> {
    // §9.4: a write is always a publish of the local node's own view — the
    // version model forbids publishing someone else's — so every bucket is
    // writable. A bucket pinned to a foreign origin still accepts the write,
    // but its reads keep serving the pinned origin, which is worth saying out
    // loud rather than silently surprising the client.
    if let Some(warning) = bucket.foreign_pin_warning(gateway.origin()) {
        tracing::warn!("{warning}");
    }
    // The body streams over the socket into the daemon's ingest pipeline —
    // space directory, hash, CAS, stage, publish (§7.1) — and comes back as the
    // published entry, so the ETag is the root the daemon computed rather than
    // one this process hashed from a copy it kept.
    let published: EntryInfo = gateway
        .daemon
        .put(&bucket.space, key, body)
        .await
        .map_err(|e| e.with_key(key))?;

    let mut headers = HeaderMap::new();
    insert(
        &mut headers,
        header::ETAG,
        &etag(published.content.as_ref()),
    );
    Ok((StatusCode::OK, headers).into_response())
}

/// The ETag for an entry: the object's BLAKE3 root hash, hex, quoted (§9.4).
///
/// S3 permits opaque ETags; MD5 equivalence is only conventional for
/// non-multipart uploads, so tooling that insists on MD5 validation must have
/// it disabled.
pub fn etag(content: Option<&synch_core::Hash>) -> String {
    match content {
        Some(hash) => quoted(&hash.to_hex()),
        None => quoted(""),
    }
}

fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

/// Parses an HTTP `Range` header into a half-open byte range.
pub fn parse_range(value: &str, size: u64) -> S3Result<(u64, u64)> {
    let spec = value
        .strip_prefix("bytes=")
        .ok_or_else(|| S3Error::invalid_range(format!("unsupported range unit in {value:?}")))?;
    if spec.contains(',') {
        return Err(S3Error::invalid_range(
            "multi-range requests are not supported",
        ));
    }
    let (start, end) = spec
        .split_once('-')
        .ok_or_else(|| S3Error::invalid_range(format!("malformed range {value:?}")))?;

    let (start, end) = match (start.trim(), end.trim()) {
        ("", "") => return Err(S3Error::invalid_range("empty range")),
        // `bytes=-N` is the last N bytes.
        ("", suffix) => {
            let n: u64 = suffix
                .parse()
                .map_err(|_| S3Error::invalid_range(format!("malformed range {value:?}")))?;
            (size.saturating_sub(n), size)
        }
        (start, "") => {
            let start: u64 = start
                .parse()
                .map_err(|_| S3Error::invalid_range(format!("malformed range {value:?}")))?;
            (start, size)
        }
        (start, end) => {
            let start: u64 = start
                .parse()
                .map_err(|_| S3Error::invalid_range(format!("malformed range {value:?}")))?;
            let end: u64 = end
                .parse()
                .map_err(|_| S3Error::invalid_range(format!("malformed range {value:?}")))?;
            // HTTP ranges are inclusive at both ends.
            (start, end.saturating_add(1).min(size))
        }
    };
    if start >= size || start >= end {
        return Err(S3Error::invalid_range(format!(
            "range {value:?} is outside a {size}-byte object"
        )));
    }
    Ok((start, end))
}

fn lowercase_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            Some((
                name.as_str().to_ascii_lowercase(),
                value.to_str().ok()?.to_string(),
            ))
        })
        .collect()
}

fn parse_query(uri: &Uri) -> Vec<(String, String)> {
    let Some(query) = uri.query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

fn param(query: &[(String, String)], name: &str) -> Option<String> {
    query
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// Decodes percent-escapes and `+` in a URI component.
/// The gateway's wall clock in Unix seconds, for the SigV4 skew check.
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&text[i + 1..i + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 3;
                }
                Err(_) => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn insert(headers: &mut HeaderMap, name: header::HeaderName, value: &str) {
    if let Ok(value) = header::HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn xml_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etags_are_quoted_blake3_roots() {
        let hash = synch_core::Hash::new(b"payload");
        let tag = etag(Some(&hash));
        assert_eq!(tag, format!("\"{}\"", hash.to_hex()));
        assert_eq!(tag.len(), 66);
        assert_eq!(etag(None), "\"\"");
    }

    #[test]
    fn ranges_parse() {
        assert_eq!(parse_range("bytes=0-9", 100).unwrap(), (0, 10));
        assert_eq!(parse_range("bytes=10-", 100).unwrap(), (10, 100));
        assert_eq!(parse_range("bytes=-20", 100).unwrap(), (80, 100));
        // An end past the object clamps rather than failing.
        assert_eq!(parse_range("bytes=90-200", 100).unwrap(), (90, 100));
    }

    #[test]
    fn bad_ranges_are_rejected() {
        assert!(parse_range("items=0-9", 100).is_err());
        assert!(parse_range("bytes=0-9,20-29", 100).is_err());
        assert!(parse_range("bytes=-", 100).is_err());
        assert!(parse_range("bytes=abc-def", 100).is_err());
        assert!(parse_range("bytes=100-200", 100).is_err());
        assert!(parse_range("bytes=50-40", 100).is_err());
    }

    #[test]
    fn query_parsing() {
        let uri: Uri = "/bucket?list-type=2&prefix=a%2Fb&delimiter=%2F&empty"
            .parse()
            .unwrap();
        let query = parse_query(&uri);
        assert_eq!(param(&query, "list-type").as_deref(), Some("2"));
        assert_eq!(param(&query, "prefix").as_deref(), Some("a/b"));
        assert_eq!(param(&query, "delimiter").as_deref(), Some("/"));
        assert_eq!(param(&query, "empty").as_deref(), Some(""));
        assert_eq!(param(&query, "absent"), None);
        assert!(parse_query(&"/bucket".parse::<Uri>().unwrap()).is_empty());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("caf%C3%A9"), "café");
        assert_eq!(percent_decode("plain"), "plain");
        // A truncated escape is passed through rather than dropped.
        assert_eq!(percent_decode("a%"), "a%");
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback(&"127.0.0.1:9000".parse().unwrap()));
        assert!(is_loopback(&"[::1]:9000".parse().unwrap()));
        assert!(!is_loopback(&"0.0.0.0:9000".parse().unwrap()));
        assert!(!is_loopback(&"10.0.0.1:9000".parse().unwrap()));
    }
}
