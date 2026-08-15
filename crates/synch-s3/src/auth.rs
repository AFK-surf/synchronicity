//! SigV4 verification for S3 clients (§9.4).
//!
//! The gateway authenticates S3 clients only; cluster access is the node's own
//! membership (§3). Static access-key pairs are held by the daemon under the
//! `s3.*` config namespace and read over the control socket, like everything
//! else the gateway knows (§9.4).

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::{
    daemon::Daemon,
    error::{S3Error, S3Result},
};

type HmacSha256 = Hmac<Sha256>;

/// The config value holding the gateway's static access keys.
///
/// An append-only record log, like the bucket map: `<id>\t<secret>` adds or
/// replaces a key, `<id>` alone removes it, and the last record naming an id
/// wins (§9.4).
///
/// A removal appends rather than rewrites, which means the removed key's secret
/// stays in the log until an operator clears the value outright. That is a
/// real trade and worth naming: the alternative is a read-modify-write two
/// gateways can lose edits through, and the log lives in the same `0700`
/// datadir as this node's signing key — anyone who can read it can already sign
/// as the node. A secret that has been handed out and withdrawn should be
/// treated as spent regardless.
pub const KEYS_CONFIG: &str = "s3.keys";

/// The SigV4 algorithm string.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The payload-hash sentinel clients send when they do not hash the body.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// A static access-key pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKey {
    /// The access key id.
    pub id: String,
    /// The secret access key.
    pub secret: String,
}

/// How the gateway authenticates clients.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// SigV4 with the configured static access keys.
    SigV4(Vec<AccessKey>),
    /// No authentication. Only legal when bound to loopback (§9.4).
    Anonymous,
}

/// Folds the append-only record log into the key set it describes.
///
/// A record nobody can read is skipped rather than fatal, for the reason the
/// bucket log skips one: a malformed line must not lock every client out.
pub fn fold(records: &[String]) -> Vec<AccessKey> {
    let mut out: Vec<AccessKey> = Vec::new();
    for record in records {
        let mut fields = record.split('\t');
        let Some(id) = fields.next().filter(|id| !id.is_empty()) else {
            continue;
        };
        let secret = fields.next();
        out.retain(|k| k.id != id);
        if let Some(secret) = secret {
            out.push(AccessKey {
                id: id.to_string(),
                secret: secret.to_string(),
            });
        }
    }
    out
}

/// Reads the configured access keys from the daemon.
pub async fn load_keys(daemon: &Daemon) -> S3Result<Vec<AccessKey>> {
    Ok(fold(&daemon.config(KEYS_CONFIG).await?))
}

/// Adds or replaces an access key.
pub async fn put_key(daemon: &Daemon, key: &AccessKey) -> S3Result<()> {
    if key.id.contains('\t') || key.secret.contains('\t') {
        return Err(S3Error::invalid(
            "an access key id and secret may not contain a tab",
        ));
    }
    daemon
        .append(KEYS_CONFIG, &format!("{}\t{}", key.id, key.secret))
        .await
}

/// Removes an access key, returning whether it existed.
pub async fn remove_key(daemon: &Daemon, id: &str) -> S3Result<bool> {
    let existed = load_keys(daemon).await?.iter().any(|k| k.id == id);
    if existed {
        daemon.append(KEYS_CONFIG, id).await?;
    }
    Ok(existed)
}

/// A parsed `Authorization: AWS4-HMAC-SHA256 ...` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Header {
    /// The access key id.
    pub access_key: String,
    /// The credential scope date, `YYYYMMDD`.
    pub date: String,
    /// The credential scope region.
    pub region: String,
    /// The credential scope service, always `s3` here.
    pub service: String,
    /// The lowercase, semicolon-separated signed header names.
    pub signed_headers: Vec<String>,
    /// The hex signature.
    pub signature: String,
}

/// Parses the `Authorization` header.
pub fn parse_authorization(header: &str) -> S3Result<SigV4Header> {
    let rest = header
        .strip_prefix(ALGORITHM)
        .ok_or_else(|| S3Error::unsupported_algorithm(header))?
        .trim_start();

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("Credential=") {
            credential = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("Signature=") {
            signature = Some(value.to_string());
        }
    }

    let credential = credential.ok_or_else(|| S3Error::malformed_auth("missing Credential"))?;
    let scope: Vec<&str> = credential.split('/').collect();
    if scope.len() != 5 || scope[4] != "aws4_request" {
        return Err(S3Error::malformed_auth("malformed Credential scope"));
    }
    Ok(SigV4Header {
        access_key: scope[0].to_string(),
        date: scope[1].to_string(),
        region: scope[2].to_string(),
        service: scope[3].to_string(),
        signed_headers: signed_headers
            .ok_or_else(|| S3Error::malformed_auth("missing SignedHeaders"))?
            .split(';')
            .map(|h| h.trim().to_ascii_lowercase())
            .collect(),
        signature: signature.ok_or_else(|| S3Error::malformed_auth("missing Signature"))?,
    })
}

/// Everything the canonical request needs from the HTTP request.
#[derive(Debug, Clone)]
pub struct SignedRequest<'a> {
    /// The HTTP method, uppercase.
    pub method: &'a str,
    /// The URI path, already percent-decoded exactly once by the router.
    pub path: &'a str,
    /// The query parameters, unsorted.
    pub query: &'a [(String, String)],
    /// Every request header, lowercase names.
    pub headers: &'a BTreeMap<String, String>,
    /// The payload hash the client declared.
    pub payload_hash: &'a str,
}

/// Builds the SigV4 canonical request string.
pub fn canonical_request(request: &SignedRequest<'_>, signed_headers: &[String]) -> String {
    let mut query: Vec<(String, String)> = request
        .query
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    query.sort();
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let mut canonical_headers = String::new();
    for name in signed_headers {
        let value = request.headers.get(name).map(String::as_str).unwrap_or("");
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value.trim());
        canonical_headers.push('\n');
    }

    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        canonical_uri(request.path),
        canonical_query,
        canonical_headers,
        signed_headers.join(";"),
        request.payload_hash
    )
}

/// Encodes a URI path segment-by-segment, as SigV4 requires.
fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    path.split('/')
        .map(|segment| uri_encode(segment, false))
        .collect::<Vec<_>>()
        .join("/")
}

/// The SigV4 URI encoding: unreserved characters pass through, everything else
/// is percent-encoded uppercase. `/` survives only outside query strings.
pub fn uri_encode(value: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Builds the string that gets signed.
pub fn string_to_sign(
    amz_date: &str,
    scope_date: &str,
    region: &str,
    service: &str,
    canonical_request: &str,
) -> String {
    let hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    format!("{ALGORITHM}\n{amz_date}\n{scope_date}/{region}/{service}/aws4_request\n{hash}")
}

/// Derives the SigV4 signing key.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let mut key = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    key = hmac(&key, region.as_bytes());
    key = hmac(&key, service.as_bytes());
    hmac(&key, b"aws4_request")
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Computes the expected signature for a request.
pub fn expected_signature(
    secret: &str,
    header: &SigV4Header,
    amz_date: &str,
    request: &SignedRequest<'_>,
) -> String {
    let canonical = canonical_request(request, &header.signed_headers);
    let to_sign = string_to_sign(
        amz_date,
        &header.date,
        &header.region,
        &header.service,
        &canonical,
    );
    let key = signing_key(secret, &header.date, &header.region, &header.service);
    hex::encode(hmac(&key, to_sign.as_bytes()))
}

/// How far a request's `x-amz-date` may sit from the gateway clock before it is
/// rejected. This window is the only thing bounding replay of a captured signed
/// request, so it is kept tight — the AWS default is the same 15 minutes.
pub const MAX_CLOCK_SKEW_SECS: i64 = 15 * 60;

/// Verifies a request against the configured mode.
///
/// `now_unix` is the gateway's current time in Unix seconds; it bounds how long
/// a captured signed request stays replayable.
///
/// Returns the authenticated access key id, or `None` in anonymous mode.
pub fn verify(
    mode: &AuthMode,
    request: &SignedRequest<'_>,
    now_unix: i64,
) -> S3Result<Option<String>> {
    let keys = match mode {
        AuthMode::Anonymous => return Ok(None),
        AuthMode::SigV4(keys) => keys,
    };
    let authorization = request
        .headers
        .get("authorization")
        .ok_or_else(|| S3Error::access_denied("no Authorization header"))?;
    let header = parse_authorization(authorization)?;
    let amz_date = request
        .headers
        .get("x-amz-date")
        .ok_or_else(|| S3Error::access_denied("no x-amz-date header"))?;

    // Bound replay: a signed request is only valid within the skew window, and
    // the credential-scope date must match the day of x-amz-date (a signature
    // is only valid for the day it was scoped to). Without this a captured
    // request replays indefinitely on the gateway's plaintext port.
    let signed_at =
        parse_amz_date(amz_date).ok_or_else(|| S3Error::access_denied("malformed x-amz-date"))?;
    if (now_unix - signed_at).abs() > MAX_CLOCK_SKEW_SECS {
        return Err(S3Error::access_denied(
            "x-amz-date outside the accepted window",
        ));
    }
    if amz_date.get(..8) != Some(header.date.as_str()) {
        return Err(S3Error::access_denied(
            "credential scope date does not match x-amz-date",
        ));
    }

    let key = keys
        .iter()
        .find(|k| k.id == header.access_key)
        .ok_or_else(|| S3Error::invalid_access_key(&header.access_key))?;

    let expected = expected_signature(&key.secret, &header, amz_date, request);
    if !constant_time_eq(expected.as_bytes(), header.signature.as_bytes()) {
        return Err(S3Error::signature_mismatch());
    }
    Ok(Some(key.id.clone()))
}

/// Parses an ISO8601 basic `x-amz-date` (`YYYYMMDDTHHMMSSZ`) into Unix seconds.
/// Returns `None` on any structural or range error.
pub fn parse_amz_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r).and_then(|v| v.parse::<i64>().ok());
    let (year, month, day) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (hour, min, sec) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + min * 60 + sec)
}

/// Days since the Unix epoch for a proleptic-Gregorian date (Howard Hinnant's
/// `days_from_civil`), so date arithmetic needs no calendar dependency.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`]: `(year, month, day)` from a day count since
/// the Unix epoch.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Formats Unix seconds as an ISO8601 basic `x-amz-date` (`YYYYMMDDTHHMMSSZ`).
/// The scope date a signature needs is its first eight characters.
pub fn format_amz_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs / 3_600,
        (secs % 3_600) / 60,
        secs % 60
    )
}

/// Compares two byte strings without leaking their contents through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parses_an_authorization_header() {
        let header = parse_authorization(
            "AWS4-HMAC-SHA256 Credential=AKID/20240102/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef",
        )
        .unwrap();
        assert_eq!(header.access_key, "AKID");
        assert_eq!(header.date, "20240102");
        assert_eq!(header.region, "us-east-1");
        assert_eq!(header.service, "s3");
        assert_eq!(
            header.signed_headers,
            vec!["host", "x-amz-content-sha256", "x-amz-date"]
        );
        assert_eq!(header.signature, "deadbeef");
    }

    #[test]
    fn rejects_malformed_authorization_headers() {
        assert!(parse_authorization("Basic abc").is_err());
        assert!(parse_authorization("AWS4-HMAC-SHA256 Signature=x").is_err());
        assert!(parse_authorization(
            "AWS4-HMAC-SHA256 Credential=AKID/20240102/us-east-1/s3, SignedHeaders=host, Signature=x"
        )
        .is_err());
    }

    /// Pins the canonical request string against the layout SigV4 defines:
    /// method, URI, query, canonical headers (each terminated by a newline),
    /// a blank line, the signed-header list, and the payload hash.
    #[test]
    fn canonical_requests_match_the_documented_layout() {
        let headers = headers(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            (
                "x-amz-content-sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            ("x-amz-date", "20130524T000000Z"),
            ("range", "  bytes=0-9  "),
        ]);
        let request = SignedRequest {
            method: "GET",
            path: "/test.txt",
            query: &[],
            headers: &headers,
            payload_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        };
        let signed = vec![
            "host".to_string(),
            "range".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        let canonical = canonical_request(&request, &signed);
        assert_eq!(
            canonical,
            concat!(
                "GET\n",
                "/test.txt\n",
                "\n",
                "host:examplebucket.s3.amazonaws.com\n",
                "range:bytes=0-9\n",
                "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
                "x-amz-date:20130524T000000Z\n",
                "\n",
                "host;range;x-amz-content-sha256;x-amz-date\n",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            "canonical request layout drifted"
        );
    }

    /// Pins the string-to-sign layout and the four-step key derivation, both of
    /// which the signature depends on entirely.
    #[test]
    fn string_to_sign_and_key_derivation_are_stable() {
        let to_sign = string_to_sign(
            "20130524T000000Z",
            "20130524",
            "us-east-1",
            "s3",
            "canonical",
        );
        let mut lines = to_sign.lines();
        assert_eq!(lines.next(), Some(ALGORITHM));
        assert_eq!(lines.next(), Some("20130524T000000Z"));
        assert_eq!(lines.next(), Some("20130524/us-east-1/s3/aws4_request"));
        assert_eq!(
            lines.next(),
            Some(hex::encode(Sha256::digest(b"canonical")).as_str())
        );
        assert_eq!(lines.next(), None);

        // The signing key is HMAC-chained date -> region -> service -> suffix,
        // so changing any scope component must change the key.
        let base = signing_key("secret", "20130524", "us-east-1", "s3");
        assert_eq!(base.len(), 32);
        assert_ne!(base, signing_key("secret", "20130525", "us-east-1", "s3"));
        assert_ne!(base, signing_key("secret", "20130524", "eu-west-1", "s3"));
        assert_ne!(base, signing_key("other", "20130524", "us-east-1", "s3"));
    }

    #[test]
    fn verification_accepts_a_correct_signature() {
        let keys = vec![AccessKey {
            id: "AKID".into(),
            secret: "secret".into(),
        }];
        let mut map = headers(&[
            ("host", "localhost:9000"),
            ("x-amz-date", "20240102T030405Z"),
        ]);
        let header = SigV4Header {
            access_key: "AKID".into(),
            date: "20240102".into(),
            region: "us-east-1".into(),
            service: "s3".into(),
            signed_headers: vec!["host".into(), "x-amz-date".into()],
            signature: String::new(),
        };
        let request = SignedRequest {
            method: "GET",
            path: "/bucket/key.txt",
            query: &[],
            headers: &map,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        let signature = expected_signature("secret", &header, "20240102T030405Z", &request);
        map.insert(
            "authorization".into(),
            format!(
                "{ALGORITHM} Credential=AKID/20240102/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-date, Signature={signature}"
            ),
        );
        let request = SignedRequest {
            method: "GET",
            path: "/bucket/key.txt",
            query: &[],
            headers: &map,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        // Verify at the request's own signing time so the skew check passes and
        // the signature is what is under test.
        let now = parse_amz_date("20240102T030405Z").unwrap();
        assert_eq!(
            verify(&AuthMode::SigV4(keys.clone()), &request, now).unwrap(),
            Some("AKID".to_string())
        );

        // A tampered path invalidates the signature.
        let tampered = SignedRequest {
            path: "/bucket/other.txt",
            ..request.clone()
        };
        assert!(verify(&AuthMode::SigV4(keys), &tampered, now).is_err());
    }

    #[test]
    fn verification_rejects_stale_and_future_dates() {
        let keys = vec![AccessKey {
            id: "AKID".into(),
            secret: "secret".into(),
        }];
        let mut map = headers(&[("host", "example.com"), ("x-amz-date", "20240102T030405Z")]);
        let header = SigV4Header {
            access_key: "AKID".into(),
            date: "20240102".into(),
            region: "us-east-1".into(),
            service: "s3".into(),
            signed_headers: vec!["host".into(), "x-amz-date".into()],
            signature: String::new(),
        };
        let request = SignedRequest {
            method: "GET",
            path: "/bucket/key.txt",
            query: &[],
            headers: &map,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        let signature = expected_signature("secret", &header, "20240102T030405Z", &request);
        map.insert(
            "authorization".into(),
            format!(
                "{ALGORITHM} Credential=AKID/20240102/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-date, Signature={signature}"
            ),
        );
        let request = SignedRequest {
            method: "GET",
            path: "/bucket/key.txt",
            query: &[],
            headers: &map,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        let signed_at = parse_amz_date("20240102T030405Z").unwrap();
        // Correct signature, but the clock is an hour past the window: rejected.
        assert!(verify(
            &AuthMode::SigV4(keys.clone()),
            &request,
            signed_at + MAX_CLOCK_SKEW_SECS + 3_600
        )
        .is_err());
        // Within the window: accepted.
        assert!(verify(&AuthMode::SigV4(keys), &request, signed_at + 60).is_ok());
    }

    #[test]
    fn verification_rejects_unknown_keys_and_missing_headers() {
        let keys = vec![AccessKey {
            id: "AKID".into(),
            secret: "secret".into(),
        }];
        let empty = headers(&[]);
        let request = SignedRequest {
            method: "GET",
            path: "/b/k",
            query: &[],
            headers: &empty,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        let now = parse_amz_date("20240102T030405Z").unwrap();
        assert!(verify(&AuthMode::SigV4(keys.clone()), &request, now).is_err());

        let map = headers(&[
            ("x-amz-date", "20240102T030405Z"),
            (
                "authorization",
                "AWS4-HMAC-SHA256 Credential=NOPE/20240102/us-east-1/s3/aws4_request, \
                 SignedHeaders=host, Signature=00",
            ),
        ]);
        let request = SignedRequest {
            headers: &map,
            ..request
        };
        assert!(verify(&AuthMode::SigV4(keys), &request, now).is_err());
    }

    #[test]
    fn anonymous_mode_accepts_everything() {
        let empty = headers(&[]);
        let request = SignedRequest {
            method: "GET",
            path: "/b/k",
            query: &[],
            headers: &empty,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        assert_eq!(verify(&AuthMode::Anonymous, &request, 0).unwrap(), None);
    }

    #[test]
    fn uri_encoding_follows_sigv4() {
        assert_eq!(uri_encode("a b", true), "a%20b");
        assert_eq!(uri_encode("a/b", false), "a/b");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("-_.~", true), "-_.~");
        assert_eq!(uri_encode("é", true), "%C3%A9");
        assert_eq!(canonical_uri(""), "/");
        assert_eq!(canonical_uri("/a b/c"), "/a%20b/c");
    }

    #[test]
    fn query_parameters_are_sorted_and_encoded() {
        let empty = headers(&[]);
        let query = vec![
            ("prefix".to_string(), "a b".to_string()),
            ("list-type".to_string(), "2".to_string()),
        ];
        let request = SignedRequest {
            method: "GET",
            path: "/bucket",
            query: &query,
            headers: &empty,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        let canonical = canonical_request(&request, &[]);
        assert!(
            canonical.contains("list-type=2&prefix=a%20b"),
            "{canonical}"
        );
    }

    fn records(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|l| l.to_string()).collect()
    }

    #[test]
    fn the_key_log_folds_to_the_keys_it_describes() {
        let keys = fold(&records(&["AKID\tsecret", "OTHER\tsecret2"]));
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].id, "AKID");
        assert_eq!(keys[1].secret, "secret2");

        // A later record replaces an id, and a bare id removes it.
        let keys = fold(&records(&["AKID\tone", "AKID\ttwo"]));
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].secret, "two");
        let keys = fold(&records(&["AKID\tone", "OTHER\ttwo", "AKID"]));
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, "OTHER");

        assert!(fold(&[]).is_empty());
        assert!(fold(&records(&["", "\tno-id"])).is_empty());
    }

    #[test]
    fn constant_time_comparison() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
