//! Length-framed postcard messages on QUIC streams (§5.1).
//!
//! Every message is a little-endian `u32` length followed by that many bytes of
//! postcard. The length is checked against [`MAX_FRAME_LEN`] before allocating.
//!
//! What that bounds, precisely: one *stream's* buffer, not a node's memory. The
//! buffer is sized from the declared length before the body is read, so a peer
//! that declares 16 MiB and sends nothing has named a 16 MiB allocation for
//! four bytes of traffic, on every stream it opens (`MAX_CONCURRENT_STREAMS`
//! of them per connection, and connections are not themselves capped). The
//! reason that
//! is not the amplification it looks like is `alloc_zeroed`: at this size it is
//! served by `mmap`, so the pages are not committed until they are written and
//! an attacker pays for only what it actually sends — measured at ~6 MB
//! resident for 1 600 such buffers. Reaching a peer at all requires a live
//! binding (`serve::serve_connection`), which is where §12 puts the answer to a
//! member behaving this way.
//!
//! The cap that matters for *work* rather than bytes is not here: it is the
//! per-field element cap on the decoded message, applied while decoding
//! ([`synch_core::MptMessage`]), because a frame this size is seconds of CPU to
//! deserialize.

use iroh::endpoint::{RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};
use synch_core::MAX_FRAME_LEN;

use crate::error::NetError;

/// Writes one length-framed postcard message.
pub async fn write_frame<T: Serialize>(send: &mut SendStream, msg: &T) -> Result<(), NetError> {
    let bytes = postcard::to_stdvec(msg).map_err(|e| NetError::Encode(e.to_string()))?;
    write_bytes(send, &bytes).await
}

/// Writes one length-framed raw payload (used for bao slice bodies, §6.4).
pub async fn write_bytes(send: &mut SendStream, bytes: &[u8]) -> Result<(), NetError> {
    if bytes.len() > MAX_FRAME_LEN {
        return Err(NetError::FrameTooLarge(bytes.len()));
    }
    send.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}

/// Reads one length-framed postcard message.
pub async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T, NetError> {
    let bytes = read_bytes(recv).await?;
    postcard::from_bytes(&bytes).map_err(|e| NetError::Decode(e.to_string()))
}

/// Reads one length-framed raw payload.
pub async fn read_bytes(recv: &mut RecvStream) -> Result<Vec<u8>, NetError> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header).await?;
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(NetError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        recv.read_exact(&mut buf).await?;
    }
    Ok(buf)
}
