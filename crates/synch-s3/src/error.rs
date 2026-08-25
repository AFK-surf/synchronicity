//! S3 error codes and their XML rendering (§9.4).

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use synch_cli::control::{ControlError, ErrorCode};

use crate::xml::escape;

/// The gateway result alias.
pub(crate) type S3Result<T> = std::result::Result<T, S3Error>;

/// An S3 API error, rendered as the XML body clients expect.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code}: {message}")]
pub struct S3Error {
    /// The HTTP status.
    pub status: StatusCode,
    /// The S3 error code, e.g. `NoSuchKey`.
    pub code: String,
    /// A human-readable message.
    pub message: String,
    /// The resource the error refers to.
    pub resource: String,
}

impl S3Error {
    /// Builds an error.
    pub fn new(status: StatusCode, code: &str, message: impl Into<String>) -> S3Error {
        S3Error {
            status,
            code: code.to_string(),
            message: message.into(),
            resource: String::new(),
        }
    }

    /// Attaches the resource the error refers to.
    pub(crate) fn with_resource(mut self, resource: impl Into<String>) -> S3Error {
        self.resource = resource.into();
        self
    }

    /// Names the key an error refers to, when it does not already name one.
    ///
    /// The daemon reports failures in terms of a space and a path; the S3
    /// resource is the key, which only the handler that took the request knows.
    /// An error that already carries a resource keeps it.
    pub(crate) fn with_key(mut self, key: &str) -> S3Error {
        if self.resource.is_empty() {
            self.resource = key.to_string();
        }
        self
    }

    /// `NoSuchBucket`.
    pub(crate) fn no_such_bucket(bucket: &str) -> S3Error {
        S3Error::new(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            format!("no bucket named {bucket}"),
        )
        .with_resource(format!("/{bucket}"))
    }

    /// `NoSuchKey`.
    pub(crate) fn no_such_key(key: &str) -> S3Error {
        S3Error::new(StatusCode::NOT_FOUND, "NoSuchKey", "no such key")
            .with_resource(key.to_string())
    }

    /// `AccessDenied`.
    pub(crate) fn access_denied(reason: impl Into<String>) -> S3Error {
        S3Error::new(StatusCode::FORBIDDEN, "AccessDenied", reason)
    }

    /// `InvalidAccessKeyId`.
    pub(crate) fn invalid_access_key(id: &str) -> S3Error {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "InvalidAccessKeyId",
            format!("unknown access key {id}"),
        )
    }

    /// `SignatureDoesNotMatch`.
    pub(crate) fn signature_mismatch() -> S3Error {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "the request signature does not match",
        )
    }

    /// `InvalidRequest` for an unsupported signing algorithm.
    pub(crate) fn unsupported_algorithm(header: &str) -> S3Error {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("unsupported authorization scheme: {header}"),
        )
    }

    /// `AuthorizationHeaderMalformed`.
    pub(crate) fn malformed_auth(reason: impl Into<String>) -> S3Error {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            reason,
        )
    }

    /// `InvalidRange`.
    pub(crate) fn invalid_range(reason: impl Into<String>) -> S3Error {
        S3Error::new(StatusCode::RANGE_NOT_SATISFIABLE, "InvalidRange", reason)
    }

    /// `NoSuchUpload`.
    ///
    /// Distinct from `NoSuchKey`, and it has to be: a client that gets "no such
    /// key" back from a `CompleteMultipartUpload` learns nothing, while
    /// `NoSuchUpload` is the code every SDK branches on to stop retrying and
    /// start the upload over.
    pub(crate) fn no_such_upload(upload_id: &str) -> S3Error {
        S3Error::new(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the upload does not exist, or is not against this key",
        )
        .with_resource(upload_id.to_string())
    }

    /// `InvalidPart`: a completion named a part that was never uploaded, or
    /// one whose ETag does not match what was.
    pub(crate) fn invalid_part(reason: impl Into<String>) -> S3Error {
        S3Error::new(StatusCode::BAD_REQUEST, "InvalidPart", reason)
    }

    /// `InvalidPartOrder`: a completion's part numbers do not ascend.
    pub(crate) fn invalid_part_order() -> S3Error {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidPartOrder",
            "the parts of a completion must be listed in ascending part-number order",
        )
    }

    /// `EntityTooSmall`: an interior part is under S3's 5 MiB minimum.
    pub(crate) fn entity_too_small(reason: impl Into<String>) -> S3Error {
        S3Error::new(StatusCode::BAD_REQUEST, "EntityTooSmall", reason)
    }

    /// `MalformedXML`: a request body this gateway could not read.
    pub(crate) fn malformed_xml(reason: impl Into<String>) -> S3Error {
        S3Error::new(StatusCode::BAD_REQUEST, "MalformedXML", reason)
    }

    /// Restates a "not found" as being about an upload rather than a key.
    ///
    /// The daemon reports a missing upload the only way the control protocol
    /// can — `NotFound` — and the generic conversion turns that into
    /// `NoSuchKey`, which is the wrong answer to a question about an upload.
    /// Only the handler knows which question was asked, so only the handler can
    /// correct it.
    pub(crate) fn about_upload(self, upload_id: &str) -> S3Error {
        if self.status == StatusCode::NOT_FOUND {
            return S3Error::no_such_upload(upload_id);
        }
        self
    }

    /// `NotImplemented`, for the operations §9.4 defers past v1.
    pub(crate) fn not_implemented(operation: &str) -> S3Error {
        S3Error::new(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            format!("{operation} is not implemented in v1"),
        )
    }

    /// `409 Conflict`: a `strict` bucket was asked for a divergent key (§8,
    /// §9.4).
    ///
    /// The versions are named in the body, because refusing without saying
    /// what the alternatives are would leave the caller nothing to act on.
    pub fn divergent(key: &str, message: impl Into<String>) -> S3Error {
        S3Error::new(StatusCode::CONFLICT, "DivergentVersions", message)
            .with_resource(key.to_string())
    }

    /// `InvalidArgument`.
    pub fn invalid(reason: impl Into<String>) -> S3Error {
        S3Error::new(StatusCode::BAD_REQUEST, "InvalidArgument", reason)
    }

    /// `InternalError` from the store.
    pub fn store(e: impl std::fmt::Display) -> S3Error {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            e.to_string(),
        )
    }

    /// The XML body clients parse.
    pub(crate) fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource></Error>",
            escape(&self.code),
            escape(&self.message),
            escape(&self.resource)
        )
    }
}

/// Every failure the gateway can have is a failure the daemon reported, or a
/// failure to reach it (§9.4) — so this is the only conversion there is.
impl From<ControlError> for S3Error {
    fn from(e: ControlError) -> Self {
        match e.code {
            ErrorCode::NotFound => S3Error::new(StatusCode::NOT_FOUND, "NoSuchKey", e.message),
            // A strict bucket answers a divergent key with 409, naming the
            // versions it refused to choose between (§8, §9.4). The resource is
            // filled in by the handler, which is the half that knows the key.
            ErrorCode::Divergent => S3Error::divergent("", e.message),
            ErrorCode::Invalid => S3Error::invalid(e.message),
            // A node in key-loss recovery cannot publish, so it cannot accept a
            // write either. That is a state the operator clears with `synch
            // recover`, not a fault in the request or in the gateway (§3.4).
            ErrorCode::Unavailable => S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                e.message,
            ),
            // No daemon, a stale token, a version skew across an upgrade: the
            // cluster is fine and the request was fine, but this gateway has
            // nothing to serve from until an operator restarts something.
            ErrorCode::Unauthorized | ErrorCode::VersionMismatch | ErrorCode::NotInitialized => {
                S3Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    e.message,
                )
            }
            ErrorCode::Internal => S3Error::store(e.message),
        }
    }
}

impl IntoResponse for S3Error {
    fn into_response(self) -> Response {
        (
            self.status,
            [(header::CONTENT_TYPE, "application/xml")],
            self.to_xml(),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_render_the_expected_codes() {
        let e = S3Error::no_such_key("a/b.txt");
        assert_eq!(e.status, StatusCode::NOT_FOUND);
        let xml = e.to_xml();
        assert!(xml.contains("<Code>NoSuchKey</Code>"), "{xml}");
        assert!(xml.contains("<Resource>a/b.txt</Resource>"), "{xml}");

        let e = S3Error::divergent("a/b.txt", "two versions: nas, laptop");
        assert_eq!(e.status, StatusCode::CONFLICT);
        let xml = e.to_xml();
        assert!(xml.contains("<Code>DivergentVersions</Code>"), "{xml}");
        assert!(xml.contains("nas, laptop"), "{xml}");

        let status = S3Error::not_implemented("DeleteObject").status;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        let status = S3Error::invalid_range("bad").status;
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    }

    /// Every daemon code lands on a status a client can act on (§9.4).
    #[test]
    fn daemon_error_codes_become_s3_statuses() {
        let status = |code| S3Error::from(ControlError::new(code, "why")).status;
        assert_eq!(status(ErrorCode::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(status(ErrorCode::Divergent), StatusCode::CONFLICT);
        assert_eq!(status(ErrorCode::Invalid), StatusCode::BAD_REQUEST);
        let internal = status(ErrorCode::Internal);
        assert_eq!(internal, StatusCode::INTERNAL_SERVER_ERROR);
        for code in [
            ErrorCode::Unavailable,
            ErrorCode::Unauthorized,
            ErrorCode::VersionMismatch,
            ErrorCode::NotInitialized,
        ] {
            assert!(status(code) == StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    /// A question about an upload gets an answer about an upload (§9.4).
    #[test]
    fn missing_uploads_are_not_missing_keys() {
        let missing = S3Error::from(ControlError::new(ErrorCode::NotFound, "no upload"));
        assert_eq!(missing.code, "NoSuchKey");
        let restated = missing.about_upload("abc123");
        assert_eq!(restated.code, "NoSuchUpload");
        assert_eq!(restated.status, StatusCode::NOT_FOUND);
        assert_eq!(restated.resource, "abc123");
        // Anything that was not a 404 is left alone: recovery is not a missing upload.
        let busy = S3Error::from(ControlError::new(ErrorCode::Unavailable, "recovering"));
        assert_eq!(busy.about_upload("abc123").code, "ServiceUnavailable");
    }
}
