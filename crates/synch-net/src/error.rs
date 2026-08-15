//! Errors produced by the networking layer.

use synch_core::Hash;

/// The networking result alias.
pub type Result<T> = std::result::Result<T, NetError>;

/// An error from the endpoint, either ALPN, or the DNSSEC resolver.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// Binding or dialing the iroh endpoint failed.
    #[error("endpoint: {0}")]
    Endpoint(String),
    /// A QUIC stream failed.
    #[error("stream: {0}")]
    Stream(String),
    /// Reading from a QUIC stream failed.
    #[error("read: {0}")]
    Read(String),
    /// A message could not be encoded.
    #[error("encode: {0}")]
    Encode(String),
    /// A message could not be decoded.
    #[error("decode: {0}")]
    Decode(String),
    /// A framed message exceeded the size cap (§12).
    #[error("frame of {0} bytes exceeds the maximum")]
    FrameTooLarge(usize),
    /// The peer sent a message that does not belong at this point.
    #[error("unexpected message: {0}")]
    Unexpected(String),
    /// The peer is not a member: its device key has no live binding (§3.2).
    #[error("peer {0} has no live binding")]
    Untrusted(String),
    /// A trie node did not hash to the hash it was requested by (§5.2).
    ///
    /// This is a protocol violation, not a transient failure: the connection is
    /// dropped.
    #[error("peer served a trie node that does not hash to {expected}")]
    NodeHashMismatch {
        /// The hash the node was requested by.
        expected: Hash,
    },
    /// An out-of-line value did not hash to the hash it was requested by.
    #[error("peer served a trie value that does not hash to {expected}")]
    ValueHashMismatch {
        /// The hash the value was requested by.
        expected: Hash,
    },
    /// The store failed.
    #[error(transparent)]
    Store(#[from] synch_store::StoreError),
    /// A blocking store operation did not run to completion.
    ///
    /// Store work runs on tokio's blocking pool rather than on a runtime
    /// worker ([`crate::blocking`]); the pool reports only a panicked closure
    /// or a runtime shutting down under it.
    #[error("a blocking task did not complete: {0}")]
    Blocking(String),
    /// A trie operation failed.
    #[error(transparent)]
    Mpt(#[from] synch_mpt::MptError),
    /// The DNSSEC resolver failed or refused a response (§3.2, fail closed).
    #[error("dns: {0}")]
    Dns(String),
    /// A caller supplied an invalid argument.
    #[error("{0}")]
    Invalid(String),
}

impl From<iroh::endpoint::WriteError> for NetError {
    fn from(e: iroh::endpoint::WriteError) -> Self {
        NetError::Stream(e.to_string())
    }
}

impl From<iroh::endpoint::ReadExactError> for NetError {
    fn from(e: iroh::endpoint::ReadExactError) -> Self {
        NetError::Read(e.to_string())
    }
}

impl From<iroh::endpoint::ConnectionError> for NetError {
    fn from(e: iroh::endpoint::ConnectionError) -> Self {
        NetError::Stream(e.to_string())
    }
}

impl From<iroh::endpoint::ClosedStream> for NetError {
    fn from(e: iroh::endpoint::ClosedStream) -> Self {
        NetError::Stream(e.to_string())
    }
}
