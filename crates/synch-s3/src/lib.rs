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
pub mod chunked;
pub mod daemon;
pub mod error;
mod record_log;
pub mod xml;

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Router,
};
use synch_cli::control::{EntryInfo, UploadRef};

use crate::{
    auth::{AuthMode, SignedRequest, UNSIGNED_PAYLOAD},
    buckets::Bucket,
    daemon::Daemon,
    error::{S3Error, S3Result},
    xml::{format_http_date, format_timestamp, list_buckets_xml, ListResult, ListedObject},
};

/// The default `max-keys` for a listing.
pub(crate) const DEFAULT_MAX_KEYS: usize = 1000;

/// The smallest a multipart part may be when it is not the last one: S3's
/// 5 MiB.
///
/// Restated here rather than imported: the gateway depends on neither the store
/// nor the engine (§9.1), and this is the one number it needs to name the
/// difference between `EntityTooSmall` and an ordinary short final part. The
/// daemon enforces the same bound on its own side, which is where it binds.
pub const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

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
    // The authenticated key is kept, not discarded. Every multipart call is
    // scoped by it: an upload id authorizes adding parts and completing, so
    // without an owner recorded beside it any key holder who can see an id can
    // overwrite and complete another client's upload — and what this node then
    // signs and broadcasts is content of their choosing.
    let principal = auth::verify(
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
    let principal = principal.as_deref();

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
    if matches!(parts.method, Method::PUT | Method::POST | Method::DELETE) {
        bucket.require_writable()?;
    }

    // Multipart routing comes first, because every one of these requests would
    // otherwise land on an existing arm and be answered as something else: a
    // `GET /b?uploads` reads as a listing whose unknown parameter is ignored, a
    // `PUT /b/k?partNumber=1&uploadId=U` reads as a plain PutObject, and both
    // would report success for an operation that never happened.
    let upload_id = param(&query, "uploadId").filter(|id| !id.is_empty());
    let initiating = query.iter().any(|(k, _)| k == "uploads");
    // A `partNumber` with no upload to attach it to is not a request this
    // gateway can answer, and answering it as something else is how a part
    // becomes the whole object behind a `200`. A proxy that mangled the query,
    // an SDK that dropped it on a retry, and an empty `uploadId=` all land here.
    if upload_id.is_none() && param(&query, "partNumber").is_some() {
        return Err(match parts.method {
            // S3 does serve one part of a multipart object this way. This
            // gateway stores the assembled object and not its parts, so it has
            // nothing to serve — and saying so beats returning the whole object
            // as though it were the part that was asked for.
            Method::GET | Method::HEAD => S3Error::not_implemented("reading a single part"),
            _ => S3Error::invalid("partNumber names a part of an upload, so it needs an uploadId"),
        });
    }
    match (&parts.method, upload_id, initiating) {
        (&Method::POST, None, true) if !key.is_empty() => {
            return create_upload(gateway, &bucket, key, principal, &headers).await
        }
        (&Method::GET, None, true) if key.is_empty() => {
            return list_uploads(gateway, &bucket, principal, &query).await
        }
        (&Method::PUT, Some(id), _) => {
            let reference = UploadRef::new(&id, &bucket.space, key, principal);
            let number: u32 = param(&query, "partNumber")
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| S3Error::invalid("partNumber must be a number in 1..=10000"))?;
            return upload_part(gateway, reference, number, &headers, body).await;
        }
        (&Method::POST, Some(id), _) => {
            return complete_upload(gateway, &bucket, key, &id, principal, &headers, body).await
        }
        (&Method::GET, Some(id), _) => {
            return list_parts(gateway, &bucket, key, &id, principal, &query).await
        }
        (&Method::DELETE, Some(id), _) => {
            return abort_upload(gateway, &bucket, key, &id, principal).await
        }
        _ => {}
    }

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
        (&Method::PUT, false) => put_object(gateway, &bucket, key, &headers, body).await,
        (&Method::DELETE, false) => delete_object(gateway, &bucket, key, &headers).await,
        // A bucket is a mapping the operator made, not a thing HTTP may
        // unmake: deleting one here would leave a space nobody serves and an
        // operator who never asked for that.
        (&Method::DELETE, true) => Err(S3Error::not_implemented("DeleteBucket")),
        // `?delete` is the batch delete: its own API, its own body format, and
        // worth naming so an operator reading the error knows what to reach for.
        (&Method::POST, _) if query.iter().any(|(k, _)| k == "delete") => {
            Err(S3Error::not_implemented("DeleteObjects, the batch delete"))
        }
        (&Method::POST, _) => Err(S3Error::not_implemented("this operation")),
        _ => Err(S3Error::not_implemented("this operation")),
    }
}

/// `DeleteObject` (§8, §9.4).
///
/// A delete publishes this node's own view, exactly as a write does: our copy
/// goes and our tombstone is signed. That is the whole of what a delete can
/// mean in the version model, and it has one consequence worth being explicit
/// about — if another origin still publishes the key, the key is still
/// readable afterwards. S3 has no status for "deleted my version of it", and
/// inventing one would break every client that treats `rm` as a loop over
/// keys, so the answer is the `204` S3 promises and the surviving publishers
/// are logged.
async fn delete_object(
    gateway: &Gateway,
    bucket: &Bucket,
    key: &str,
    headers: &BTreeMap<String, String>,
) -> S3Result<Response> {
    check_headers(headers)?;
    let deleted = gateway
        .daemon
        .delete(&bucket.space, key)
        .await
        .map_err(|e| e.with_key(key))?;
    if deleted.still_published {
        tracing::warn!(
            bucket = %bucket.name,
            key,
            "deleted this node's version, but another origin still publishes the key: \
             it stays readable until every publisher tombstones it (§8)"
        );
    }
    // 204 whether or not there was anything here to remove. S3 makes
    // `DeleteObject` idempotent and tooling leans on it: a retried delete, an
    // `rm -f`, or a key a concurrent writer already took is not an error.
    Ok((StatusCode::NO_CONTENT).into_response())
}

/// Headers that change what an object *is*, which this gateway does not honor.
///
/// Ignoring a header is only safe when it does not change the answer. These
/// change it entirely: `x-amz-rename-source` and `x-amz-copy-source` say the
/// payload is somewhere else, and a gateway that reads the (empty) body instead
/// writes an empty object and reports `200`. Mountpoint's `rename` is exactly
/// that request, so a silently-ignored header turned `mv a b` into a truncation
/// of `b` and a `a` that never went away.
///
/// A denylist and not an allowlist: an allowlist has to know every header every
/// SDK sends before it can let a working client through, and gets that wrong in
/// the direction of breaking things that work. This list only has to name the
/// headers whose absence produces a *wrong object*, which is a closed set.
const REFUSED_HEADERS: &[&str] = &[
    "x-amz-copy-source",
    "x-amz-rename-source",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-website-redirect-location",
];

/// Refuses a request carrying a header that would make the answer a lie.
fn check_headers(headers: &BTreeMap<String, String>) -> S3Result<()> {
    for name in REFUSED_HEADERS {
        if headers.contains_key(*name) {
            return Err(S3Error::not_implemented(&format!("the {name} header")));
        }
    }
    Ok(())
}

/// Unwraps a request body that arrived `aws-chunked`, if it did.
///
/// Both write paths take it, because both can receive one: mountpoint sends
/// `--upload-checksums crc32c` by default, and every upload it makes is framed.
fn payload(
    headers: &BTreeMap<String, String>,
    body: Body,
) -> S3Result<(Body, chunked::DecodeFault)> {
    let declared = headers
        .get("x-amz-content-sha256")
        .map(String::as_str)
        .unwrap_or(auth::UNSIGNED_PAYLOAD);
    let framing = chunked::framing(
        declared,
        headers.get("content-encoding").map(String::as_str),
    )?;
    let length = headers
        .get("x-amz-decoded-content-length")
        .and_then(|v| v.parse::<u64>().ok());
    chunked::check_declared_length(framing, length.is_some())?;
    Ok(chunked::decode(body, framing, length))
}

/// `CreateMultipartUpload`.
async fn create_upload(
    gateway: &Gateway,
    bucket: &Bucket,
    key: &str,
    principal: Option<&str>,
    headers: &BTreeMap<String, String>,
) -> S3Result<Response> {
    // Refused at creation rather than at the first part: a client that names a
    // header this gateway will not honor should find out before it streams.
    check_headers(headers)?;
    let upload_id = gateway
        .daemon
        .create_upload(&bucket.space, key, principal)
        .await?;
    Ok(xml_response(
        StatusCode::OK,
        xml::initiate_upload_xml(&bucket.name, key, &upload_id),
    ))
}

/// `UploadPart`.
async fn upload_part(
    gateway: &Gateway,
    reference: UploadRef,
    number: u32,
    headers: &BTreeMap<String, String>,
    body: Body,
) -> S3Result<Response> {
    // `UploadPartCopy` is this request plus `x-amz-copy-source`. Refusing the
    // header is what stops it being answered as an ordinary part upload of the
    // empty body a copy request carries.
    check_headers(headers)?;
    let upload_id = reference.upload_id.clone();
    let (body, fault) = payload(headers, body)?;
    let part = gateway
        .daemon
        .upload_part(reference, number, body)
        .await
        .map_err(|e| fault.explain(e).about_upload(&upload_id))?;

    let mut response = HeaderMap::new();
    insert(&mut response, header::ETAG, &quoted(&part.root.to_hex()));
    Ok((StatusCode::OK, response).into_response())
}

/// `CompleteMultipartUpload`.
async fn complete_upload(
    gateway: &Gateway,
    bucket: &Bucket,
    key: &str,
    upload_id: &str,
    principal: Option<&str>,
    headers: &BTreeMap<String, String>,
    body: Body,
) -> S3Result<Response> {
    check_headers(headers)?;
    // Through the same unwrapping every other body takes. A completion body is
    // small, but nothing stops a client framing it — and a chunk boundary
    // landing mid-tag would corrupt the part list rather than fail.
    let (body, fault) = payload(headers, body)?;
    let bytes = axum::body::to_bytes(body, xml::MAX_COMPLETE_BODY)
        .await
        .map_err(|e| {
            fault.explain(S3Error::malformed_xml(format!(
                "the completion body could not be read: {e}"
            )))
        })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| S3Error::malformed_xml("the completion body is not text"))?;
    let requested = xml::parse_complete_upload(text).map_err(S3Error::malformed_xml)?;
    let named: Vec<(u32, Option<synch_core::Hash>)> = requested
        .iter()
        .map(|part| (part.number, parse_root(&part.etag)))
        .collect();

    let reference = UploadRef::new(upload_id, &bucket.space, key, principal);
    // The completion is attempted before anything is inspected, and the daemon
    // does the validating: it is what publishes, so it is what has to be sure.
    // Asking it first is also what makes a *retried* completion work — the
    // upload has no parts left to inspect by then, and the daemon answers from
    // the result it recorded.
    let completed = match gateway
        .daemon
        .complete_upload(reference.clone(), &named)
        .await
    {
        Ok(completed) => completed,
        // The daemon has one way to say "you asked wrong", and S3 clients
        // branch on which wrong it was: shrink a part, re-upload a part, or
        // start over. The parts are still there — a refused completion reopens
        // the upload — so the precise answer can be worked out here, where the
        // S3 vocabulary is.
        Err(e) if e.status == StatusCode::BAD_REQUEST => {
            return Err(diagnose(gateway, reference, upload_id, &requested, e).await)
        }
        Err(e) => return Err(e.about_upload(upload_id)),
    };
    Ok(xml_response(
        StatusCode::OK,
        xml::complete_upload_xml(&bucket.name, key, &quoted(&completed.etag.to_hex())),
    ))
}

/// Works out which S3 error a refused completion deserves.
///
/// Falls back to the daemon's own answer when nothing here explains it: a
/// diagnosis that cannot find the fault must not invent one.
async fn diagnose(
    gateway: &Gateway,
    reference: UploadRef,
    upload_id: &str,
    requested: &[xml::RequestedPart],
    reported: S3Error,
) -> S3Error {
    let recorded = match gateway.daemon.list_parts(reference).await {
        Ok(recorded) => recorded,
        Err(e) => return e.about_upload(upload_id),
    };
    match validate_parts(requested, &recorded) {
        Err(precise) => precise,
        Ok(()) => reported,
    }
}

/// Restates a refused completion in S3's vocabulary.
///
/// The checks are in the order the daemon makes them, and the order matters:
/// reporting a part as too small when a *later* part was never uploaded sends
/// the client to shrink a part that was fine.
fn validate_parts(
    requested: &[xml::RequestedPart],
    recorded: &[synch_cli::control::RecordedPart],
) -> S3Result<()> {
    let mut previous = 0;
    for part in requested {
        if part.number <= previous {
            return Err(S3Error::invalid_part_order());
        }
        previous = part.number;
    }
    let mut found = Vec::with_capacity(requested.len());
    for part in requested {
        let had = recorded
            .iter()
            .find(|had| had.number == part.number)
            .ok_or_else(|| {
                S3Error::invalid_part(format!("part {} was never uploaded", part.number))
            })?;
        if !part.etag.is_empty() && !part.etag.eq_ignore_ascii_case(&had.root.to_hex()) {
            return Err(S3Error::invalid_part(format!(
                "part {} does not have the ETag the completion named",
                part.number
            )));
        }
        found.push(had);
    }
    for had in found.iter().take(found.len().saturating_sub(1)) {
        if had.size < MIN_PART_SIZE {
            return Err(S3Error::entity_too_small(format!(
                "part {} is {} byte(s); only the last part may be under {MIN_PART_SIZE}",
                had.number, had.size
            )));
        }
    }
    Ok(())
}

/// Reads a part ETag back as the root it is, or `None` if it is not one.
///
/// A client that echoes an ETag this gateway never issued gets the check
/// skipped rather than a parse failure: the daemon still refuses a part that is
/// not there, and inventing a root out of an unparseable ETag would refuse a
/// part that is.
fn parse_root(etag: &str) -> Option<synch_core::Hash> {
    let bytes = hex::decode(etag.trim_matches('"')).ok()?;
    synch_core::Hash::from_slice(&bytes).ok()
}

/// `AbortMultipartUpload`.
async fn abort_upload(
    gateway: &Gateway,
    bucket: &Bucket,
    key: &str,
    upload_id: &str,
    principal: Option<&str>,
) -> S3Result<Response> {
    let existed = gateway
        .daemon
        .abort_upload(UploadRef::new(upload_id, &bucket.space, key, principal))
        .await
        .map_err(|e| e.about_upload(upload_id))?;
    // S3 answers an abort of an upload that is not there with `NoSuchUpload`,
    // and clients use exactly that to tell "my abort worked" from "I was
    // quoting an id that never existed".
    if !existed {
        return Err(S3Error::no_such_upload(upload_id));
    }
    Ok((StatusCode::NO_CONTENT).into_response())
}

/// `ListParts`.
async fn list_parts(
    gateway: &Gateway,
    bucket: &Bucket,
    key: &str,
    upload_id: &str,
    principal: Option<&str>,
    query: &[(String, String)],
) -> S3Result<Response> {
    let marker: u32 = param(query, "part-number-marker")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let max_parts = param(query, "max-parts")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_KEYS)
        .clamp(1, DEFAULT_MAX_KEYS);
    let recorded = gateway
        .daemon
        .list_parts(UploadRef::new(upload_id, &bucket.space, key, principal))
        .await
        .map_err(|e| e.about_upload(upload_id))?;
    let after: Vec<_> = recorded
        .into_iter()
        .filter(|part| part.number > marker)
        .collect();
    let truncated = after.len() > max_parts;
    let page: Vec<xml::ListedPart> = after
        .into_iter()
        .take(max_parts)
        .map(|part| xml::ListedPart {
            number: part.number,
            size: part.size,
            etag: quoted(&part.root.to_hex()),
            last_modified: format_timestamp(part.created_ns),
        })
        .collect();
    Ok(xml_response(
        StatusCode::OK,
        xml::list_parts_xml(
            &bucket.name,
            key,
            upload_id,
            &page,
            max_parts,
            marker,
            truncated,
        ),
    ))
}

/// `ListMultipartUploads`.
async fn list_uploads(
    gateway: &Gateway,
    bucket: &Bucket,
    principal: Option<&str>,
    query: &[(String, String)],
) -> S3Result<Response> {
    let prefix = param(query, "prefix").unwrap_or_default();
    let max_uploads = param(query, "max-uploads")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_KEYS)
        .clamp(1, DEFAULT_MAX_KEYS);
    // The markers are a `(key, upload-id)` cursor, and honoring them is not
    // optional once `IsTruncated` has been said: a paginator handed a marker it
    // re-sends, against a page that ignores it, loops forever.
    let key_marker = param(query, "key-marker").unwrap_or_default();
    let upload_marker = param(query, "upload-id-marker").unwrap_or_default();

    let open = gateway
        .daemon
        .list_uploads(&bucket.space, &prefix, principal)
        .await?;
    // The daemon lists in `(path, id)` order, which is the order the cursor is
    // defined in, so resuming is a matter of dropping everything at or before
    // where the last page ended.
    let after: Vec<_> = open
        .into_iter()
        .filter(|upload| {
            (upload.path.as_str(), upload.upload_id.as_str())
                > (key_marker.as_str(), upload_marker.as_str())
        })
        .collect();
    let truncated = after.len() > max_uploads;
    let page: Vec<xml::ListedUpload> = after
        .into_iter()
        .take(max_uploads)
        .map(|upload| xml::ListedUpload {
            key: upload.path,
            upload_id: upload.upload_id,
            initiated: format_timestamp(upload.created_ns),
        })
        .collect();
    Ok(xml_response(
        StatusCode::OK,
        xml::list_uploads_xml(
            &bucket.name,
            &prefix,
            (&key_marker, &upload_marker),
            &page,
            max_uploads,
            truncated,
        ),
    ))
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
    let policy = bucket.read_policy(&gateway.daemon).await?;
    let (listing, more, scan_cursor) = gateway
        .daemon
        .list(
            &bucket.space,
            &prefix,
            start_after.as_deref(),
            max_keys + 1,
            &policy,
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
        // Only a content-bearing entry is an S3 object. A directory marker and
        // a tombstone are obviously not, and neither is a symlink: its version
        // identity is its target, not content (§8), so it has no object root
        // to be an ETag and no bytes to serve. Listing one would advertise a
        // key whose GET can only fail.
        //
        // A socket is content-bearing and so is served like the file it is on
        // disk (`docs/SOCKETS.md` §2.2). Hiding it here would make the gateway
        // the one surface that disagrees with `synch cat`, a checkout and tree adoption
        // about a path that has a root and bytes — and it would hide it from
        // the operator without hiding it from anyone else, since every member
        // already reads those bytes out of the tree.
        if !row.kind.has_content() {
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
        // A page whose rows were all dropped by the daemon's filters has no
        // row to resume from, and the daemon's own scan position is the only
        // thing that moves the listing past them.
        result.next_continuation_token = cursor.or(scan_cursor);
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
    let policy = bucket.read_policy(&gateway.daemon).await?;
    // Metadata first, and metadata only: `HeadObject` answers size, mtime, and
    // ETag straight from the entry, with no content fetched at all (§9.4).
    let entry = gateway
        .daemon
        .resolve(&bucket.space, key, &policy)
        .await
        .map_err(|e| e.with_key(key))?;
    // Whatever a listing leaves out, a direct read leaves out too, or the
    // gateway would answer for keys it will not admit to having.
    if !entry.kind.has_content() {
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
    headers: &BTreeMap<String, String>,
    body: Body,
) -> S3Result<Response> {
    // A header that says the payload is somewhere else makes reading the body
    // the wrong thing to do, so the request is refused rather than answered
    // with an object built from the body it does not have.
    check_headers(headers)?;
    bucket.require_writable()?;
    // The body streams over the socket into the daemon's ingest pipeline —
    // filesystem-source directory, hash, CAS, stage, publish (§7.1) — and comes back as the
    // published entry, so the ETag is the root the daemon computed rather than
    // one this process hashed from a copy it kept.
    let (body, fault) = payload(headers, body)?;
    let published: EntryInfo = gateway
        .daemon
        .put(&bucket.space, key, body)
        .await
        // A body that died mid-stream reaches here as the daemon's account of
        // an abandoned write; the decoder's account, if it has one, is the more
        // useful of the two and the one a client can act on.
        .map_err(|e| fault.explain(e).with_key(key))?;

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
pub(crate) fn parse_range(value: &str, size: u64) -> S3Result<(u64, u64)> {
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

/// The gateway's wall clock in Unix seconds, for the SigV4 skew check.
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Decodes percent-escapes in a URI component.
///
/// `+` is left alone: it is form encoding, and a URI path or query carries it as
/// a literal — which is what S3 does and what every compliant SDK expects, since
/// they send `%2B` for a key that really contains one. Decoding it to a space
/// made `a+b` and `a b` the same key, so one silently overwrote the other and
/// the `+` key could not be addressed at all.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // Sliced as *bytes*, never as `&str`. `&text[i + 1..i + 3]` panics
            // when those offsets are not char boundaries, which any request
            // target of the shape `%` + one ASCII byte + a multi-byte character
            // produces — and this runs on the path and the query string *before*
            // `auth::verify`, so it needed no credential at all. httparse and
            // `http`'s Uri both pass high bytes through, so the request arrives
            // intact.
            b'%' if i + 2 < bytes.len() => match std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                }
                None => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
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
    fn ranges_parse() {
        // Happy-path boundaries (incl. clamp-past-end and open-ended forms), and the rejections.
        for (value, size, ok) in [
            ("bytes=10-", 100, Some((10, 100))),
            ("bytes=90-200", 100, Some((90, 100))),
            ("items=0-9", 100, None),
            ("bytes=0-9,20-29", 100, None),
            ("bytes=-", 100, None),
            ("bytes=abc-def", 100, None),
            ("bytes=50-40", 100, None),
        ] {
            assert_eq!(parse_range(value, size).ok(), ok, "{value}");
        }
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
        assert_eq!(percent_decode("caf%C3%A9"), "café");
        assert_eq!(percent_decode("plain"), "plain");
        // A truncated escape is passed through rather than dropped.
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("%zz"), "%zz");
        // `+` is a literal, not a space: decoding it as space aliased `a+b`
        // onto `a b`, so the `+` key could not be addressed; clients send `%2B`.
        assert_eq!(percent_decode("a+b"), "a+b");
        assert_eq!(percent_decode("a%2Bb"), "a+b");
    }

    /// A malformed escape before a multi-byte character does not panic: the old
    /// `&text[i + 1..i + 3]` slice was not char-boundary safe, and it runs pre-auth.
    #[test]
    fn a_malformed_escape_before_a_multibyte_character_is_not_a_panic() {
        assert_eq!(percent_decode("%aé"), "%aé");
        assert_eq!(percent_decode("%é"), "%é");
        assert_eq!(percent_decode("%%C3%A9"), "%é");
        // A well-formed escape still decodes before a multi-byte character.
        assert_eq!(percent_decode("%2Fé"), "/é");
    }
}
