//! S3 error codes and their XML rendering (§9.4).

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

use crate::xml::escape;

/// The gateway result alias.
pub type S3Result<T> = std::result::Result<T, S3Error>;

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
    pub fn with_resource(mut self, resource: impl Into<String>) -> S3Error {
        self.resource = resource.into();
        self
    }

    /// `NoSuchBucket`.
    pub fn no_such_bucket(bucket: &str) -> S3Error {
        S3Error::new(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            format!("no bucket named {bucket}"),
        )
        .with_resource(format!("/{bucket}"))
    }

    /// `NoSuchKey`.
    pub fn no_such_key(key: &str) -> S3Error {
        S3Error::new(StatusCode::NOT_FOUND, "NoSuchKey", "no such key")
            .with_resource(key.to_string())
    }

    /// `AccessDenied`.
    pub fn access_denied(reason: impl Into<String>) -> S3Error {
        S3Error::new(StatusCode::FORBIDDEN, "AccessDenied", reason)
    }

    /// `InvalidAccessKeyId`.
    pub fn invalid_access_key(id: &str) -> S3Error {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "InvalidAccessKeyId",
            format!("unknown access key {id}"),
        )
    }

    /// `SignatureDoesNotMatch`.
    pub fn signature_mismatch() -> S3Error {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "the request signature does not match",
        )
    }

    /// `InvalidRequest` for an unsupported signing algorithm.
    pub fn unsupported_algorithm(header: &str) -> S3Error {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("unsupported authorization scheme: {header}"),
        )
    }

    /// `AuthorizationHeaderMalformed`.
    pub fn malformed_auth(reason: impl Into<String>) -> S3Error {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            reason,
        )
    }

    /// `InvalidRange`.
    pub fn invalid_range(reason: impl Into<String>) -> S3Error {
        S3Error::new(StatusCode::RANGE_NOT_SATISFIABLE, "InvalidRange", reason)
    }

    /// `NotImplemented`, for the operations §9.4 defers past v1.
    pub fn not_implemented(operation: &str) -> S3Error {
        S3Error::new(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            format!("{operation} is not implemented in v1"),
        )
    }

    /// `MethodNotAllowed`, used for writes to a foreign-origin bucket.
    ///
    /// The version model (§8) forbids publishing someone else's view, so
    /// foreign buckets are strictly read-only.
    pub fn read_only(bucket: &str) -> S3Error {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            format!(
                "bucket {bucket} maps to another origin's view and is read-only; \
                 publishing another origin's entries is not permitted"
            ),
        )
        .with_resource(format!("/{bucket}"))
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
    pub fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource></Error>",
            escape(&self.code),
            escape(&self.message),
            escape(&self.resource)
        )
    }
}

impl From<synch_engine::EngineError> for S3Error {
    fn from(e: synch_engine::EngineError) -> Self {
        use synch_engine::EngineError;
        match e {
            EngineError::NotFound(what) => S3Error::new(StatusCode::NOT_FOUND, "NoSuchKey", what),
            EngineError::Invalid(what) => S3Error::invalid(what),
            other => S3Error::store(other),
        }
    }
}

impl From<synch_store::StoreError> for S3Error {
    fn from(e: synch_store::StoreError) -> Self {
        S3Error::store(e)
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

        let e = S3Error::read_only("photos");
        assert_eq!(e.status, StatusCode::FORBIDDEN);
        assert!(e.to_xml().contains("read-only"));

        assert_eq!(
            S3Error::not_implemented("DeleteObject").status,
            StatusCode::NOT_IMPLEMENTED
        );
        assert_eq!(
            S3Error::invalid_range("bad").status,
            StatusCode::RANGE_NOT_SATISFIABLE
        );
    }

    #[test]
    fn xml_is_escaped() {
        let e = S3Error::invalid("a<b&c\"d");
        let xml = e.to_xml();
        assert!(xml.contains("a&lt;b&amp;c&quot;d"), "{xml}");
        assert!(!xml.contains("a<b"), "{xml}");
    }
}
