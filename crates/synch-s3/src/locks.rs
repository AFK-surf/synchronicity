//! Lock keys and fenced writes (`docs/LOCKS.md` §11).
//!
//! A key a bucket declares with `--locks` is a cluster lock, driven by the
//! conditional writes S3 locking clients already speak: `If-None-Match: *`
//! creates it — acquires — `If-Match` renews it, `GET` reads the holder's
//! body back, and `DELETE` releases or breaks it. Lock keys are virtual:
//! nothing is written into the tree, and listings never show them.

use std::collections::BTreeMap;

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use synch_cli::control::{proto::pb, Fence};

use crate::{
    buckets::Bucket,
    error::{S3Error, S3Result},
    Gateway,
};

/// The metadata header that turns an acquire into a client-renewed lease,
/// in seconds. Without it a lock key is sticky: S3 objects do not expire, so
/// S3 locking clients never renew (§11.1).
const TTL_HEADER: &str = "x-amz-meta-synch-lock-ttl";

/// The header that fences a write: `x-synch-lock: <lock key>; token=<token>`
/// (§11.3).
pub(crate) const FENCE_HEADER: &str = "x-synch-lock";

/// Answers one request on a lock key.
pub(crate) async fn lock_key(
    gateway: &Gateway,
    bucket: &Bucket,
    key: &str,
    method: &Method,
    principal: Option<&str>,
    headers: &BTreeMap<String, String>,
    body: Body,
) -> S3Result<Response> {
    let name = key.to_string();
    match *method {
        Method::PUT => put(gateway, bucket, &name, principal, headers, body).await,
        Method::GET | Method::HEAD => get(gateway, bucket, &name, *method == Method::HEAD).await,
        Method::DELETE => delete(gateway, bucket, &name, headers).await,
        _ => Err(S3Error::invalid(
            "a lock key takes a single conditional PUT, GET, HEAD or DELETE",
        )),
    }
}

async fn put(
    gateway: &Gateway,
    bucket: &Bucket,
    name: &str,
    principal: Option<&str>,
    headers: &BTreeMap<String, String>,
    body: Body,
) -> S3Result<Response> {
    crate::check_headers(headers)?;
    let (body, fault) = crate::payload(headers, body)?;
    let payload = axum::body::to_bytes(body, synch_core::MAX_LOCK_PAYLOAD_BYTES)
        .await
        .map_err(|e| {
            fault.explain(S3Error::new(
                StatusCode::BAD_REQUEST,
                "EntityTooLarge",
                format!("a lock body is at most 16 KiB: {e}"),
            ))
        })?
        .to_vec();
    let hold = match (headers.get("if-none-match"), headers.get("if-match")) {
        (Some(any), None) if any.trim() == "*" => {
            let (mode, ttl_ms) = match headers.get(TTL_HEADER) {
                Some(secs) => {
                    let secs: u64 = secs.trim().parse().map_err(|_| {
                        S3Error::invalid(format!("{TTL_HEADER} is a number of seconds"))
                    })?;
                    (pb::LockMode::Lease, secs.saturating_mul(1000))
                }
                None => (pb::LockMode::Sticky, 0),
            };
            gateway
                .daemon
                .lock(pb::LockRequest {
                    space: bucket.space.clone(),
                    name: name.to_string(),
                    ttl_ms,
                    wait_ms: 0,
                    owner: principal.unwrap_or("anonymous").to_string(),
                    payload,
                    mode: mode as i32,
                    allow_behind: false,
                })
                .await
        }
        (None, Some(token)) => {
            gateway
                .daemon
                .lock_renew(pb::LockRenewRequest {
                    space: bucket.space.clone(),
                    name: name.to_string(),
                    token: unquote(token).to_string(),
                    ttl_ms: None,
                    payload: Some(payload),
                })
                .await
        }
        (Some(_), None) => {
            return Err(S3Error::not_implemented(
                "If-None-Match other than * on a lock key",
            ))
        }
        // An unconditional PUT would be a take-over nobody asked for: refused
        // rather than read as a break (§11.1).
        _ => {
            return Err(S3Error::invalid(
                "a lock key is written with If-None-Match: * to acquire, or If-Match to renew",
            ))
        }
    }
    .map_err(|e| e.with_key(name))?;
    let mut out = HeaderMap::new();
    crate::insert(&mut out, header::ETAG, &crate::quoted(&hold.token));
    Ok((StatusCode::OK, out).into_response())
}

/// The claim that holds the lock as this node sees it: its own hold first,
/// else one reported held.
async fn current(
    gateway: &Gateway,
    bucket: &Bucket,
    name: &str,
) -> S3Result<Option<pb::LockClaim>> {
    let claims = gateway.daemon.lock_claims(&bucket.space, name).await?;
    Ok(claims
        .iter()
        .find(|c| !c.mode.is_empty() && c.state == "held")
        .or_else(|| claims.iter().find(|c| c.state == "held"))
        .cloned())
}

async fn get(
    gateway: &Gateway,
    bucket: &Bucket,
    name: &str,
    head_only: bool,
) -> S3Result<Response> {
    let Some(claim) = current(gateway, bucket, name).await? else {
        return Err(S3Error::no_such_key(name));
    };
    let mut out = HeaderMap::new();
    crate::insert(&mut out, header::ETAG, &crate::quoted(&claim.token));
    crate::insert(&mut out, header::CONTENT_TYPE, "application/octet-stream");
    for (field, value) in [
        ("x-amz-meta-synch-holder", claim.origin.as_str()),
        ("x-amz-meta-synch-owner", claim.owner.as_str()),
    ] {
        if let Ok(value) = HeaderValue::from_str(value) {
            out.insert(HeaderName::from_static(field), value);
        }
    }
    out.insert(
        HeaderName::from_static("x-amz-meta-synch-expires-in"),
        HeaderValue::from(claim.remaining_ms / 1000),
    );
    out.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(claim.payload.len()),
    );
    let body = match head_only {
        true => Body::empty(),
        false => Body::from(claim.payload),
    };
    Ok((StatusCode::OK, out, body).into_response())
}

async fn delete(
    gateway: &Gateway,
    bucket: &Bucket,
    name: &str,
    headers: &BTreeMap<String, String>,
) -> S3Result<Response> {
    let current = current(gateway, bucket, name).await?;
    if let Some(wanted) = headers.get("if-match") {
        if current.as_ref().map(|c| c.token.as_str()) != Some(unquote(wanted)) {
            return Err(S3Error::new(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "the lock is not held under that ETag",
            )
            .with_key(name));
        }
    }
    // Releasing this node's own hold; otherwise breaking the holder's claim,
    // which is what an S3 delete of somebody else's lock object is — and how
    // `terraform force-unlock` works (§4).
    let request = match &current {
        None => return Ok(StatusCode::NO_CONTENT.into_response()),
        Some(claim) if !claim.mode.is_empty() => pb::LockReleaseRequest {
            space: bucket.space.clone(),
            name: name.to_string(),
            token: claim.token.clone(),
            force: false,
            holder: String::new(),
        },
        Some(claim) => pb::LockReleaseRequest {
            space: bucket.space.clone(),
            name: name.to_string(),
            token: String::new(),
            force: true,
            holder: claim.origin.clone(),
        },
    };
    gateway
        .daemon
        .lock_release(request)
        .await
        .map_err(|e| e.with_key(name))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The fence a write names in [`FENCE_HEADER`], resolved against the bucket
/// (§11.3): `<lock key>; token=<token>`.
pub(crate) fn fence(
    bucket: &Bucket,
    headers: &BTreeMap<String, String>,
) -> S3Result<Option<Fence>> {
    let Some(value) = headers.get(FENCE_HEADER) else {
        return Ok(None);
    };
    let malformed = || S3Error::invalid(format!("{FENCE_HEADER} is `<lock key>; token=<token>`"));
    let (key, token) = value.split_once(';').ok_or_else(malformed)?;
    let token = token.trim().strip_prefix("token=").ok_or_else(malformed)?;
    let key = key.trim();
    if !bucket.is_lock_key(key) {
        return Err(S3Error::invalid(format!(
            "{key} is not a lock key of bucket {}",
            bucket.name
        )));
    }
    Ok(Some(Fence {
        lock: format!("{}/{}", bucket.space, key),
        token: unquote(token).to_string(),
    }))
}

fn unquote(value: &str) -> &str {
    value.trim().trim_matches('"')
}
