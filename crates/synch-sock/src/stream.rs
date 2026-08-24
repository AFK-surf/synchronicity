//! The inbound stream, as the runtime sees it.
//!
//! A boxed reader and writer rather than an iroh type, so this crate depends on
//! no networking at all and the reactor can be tested over an in-memory duplex.
//! The network layer boxes a QUIC bidirectional stream into one of these; a
//! test boxes [`tokio::io::duplex`].

use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional byte stream: the guest's `SY_SELF`.
pub struct DuplexStream {
    /// Bytes from the caller.
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    /// Bytes to the caller.
    pub writer: Box<dyn AsyncWrite + Unpin + Send>,
}

impl std::fmt::Debug for DuplexStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DuplexStream")
    }
}

impl DuplexStream {
    /// Builds one from a reader and a writer.
    pub fn new(
        reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Self {
        DuplexStream {
            reader: Box::new(reader),
            writer: Box::new(writer),
        }
    }

    /// Splits a single duplex object — a TCP socket, a test pipe — into one.
    pub fn from_split<T>(stream: T) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (r, w) = tokio::io::split(stream);
        DuplexStream::new(r, w)
    }
}
