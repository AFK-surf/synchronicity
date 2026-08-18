//! Length-framed postcard messages on QUIC streams (§5.1).
//!
//! Every message is a little-endian `u32` length followed by that many bytes of
//! postcard. The length is checked against [`MAX_FRAME_LEN`] before allocating,
//! so a hostile peer cannot make us reserve arbitrary memory (§12).

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

/// How long a frame read may go without a single byte arriving before the
/// peer is declared stalled.
///
/// This bounds silence, never duration: a slow provider trickling a large
/// slice over a long transfer re-arms the clock with every read, while a peer
/// that has stopped sending entirely is cut off in one bound however large
/// the frame. Sized above the serve side's own request budget (120 s in
/// `sync/blob/1`), so a provider still busy encoding a window never reads as
/// stalled.
#[cfg(not(test))]
pub const STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
/// The test build cannot wait minutes for a stall to be declared.
#[cfg(test)]
pub const STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(150);

/// Reads one length-framed postcard message, bounding silence (§12).
///
/// Same frame as [`read_frame`], except every read underneath it carries
/// [`STALL_TIMEOUT`]: a peer that sends a length prefix and then nothing
/// would otherwise hold the future — and the task and stream behind it —
/// indefinitely.
pub async fn read_frame_stalled<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T, NetError> {
    let bytes = read_bytes_stalled(recv).await?;
    postcard::from_bytes(&bytes).map_err(|e| NetError::Decode(e.to_string()))
}

/// Reads one length-framed raw payload, bounding silence (§12).
pub async fn read_bytes_stalled(recv: &mut RecvStream) -> Result<Vec<u8>, NetError> {
    let mut header = [0u8; 4];
    read_exact_stalled(recv, &mut header).await?;
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(NetError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        read_exact_stalled(recv, &mut buf).await?;
    }
    Ok(buf)
}

/// Fills `buf`, failing when no byte arrives for [`STALL_TIMEOUT`].
async fn read_exact_stalled(recv: &mut RecvStream, buf: &mut [u8]) -> Result<(), NetError> {
    let mut filled = 0;
    while filled < buf.len() {
        match tokio::time::timeout(STALL_TIMEOUT, recv.read(&mut buf[filled..])).await {
            Ok(Ok(Some(bytes))) => filled += bytes,
            Ok(Ok(None)) => {
                return Err(NetError::Read(format!(
                    "stream ended {filled} bytes into a {}-byte frame",
                    buf.len()
                )))
            }
            Ok(Err(e)) => return Err(NetError::Read(e.to_string())),
            Err(_) => {
                return Err(NetError::Read(format!(
                    "peer sent nothing for {}s mid-frame",
                    STALL_TIMEOUT.as_secs()
                )))
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use synch_core::{MptMessage, MAX_FRAME_LEN};

    /// The framing is `u32` length + postcard body; this reproduces the encoder
    /// and decoder over an in-memory buffer so the wire shape is pinned without
    /// needing a QUIC stream.
    fn round_trip(msg: &MptMessage) -> MptMessage {
        let body = postcard::to_stdvec(msg).unwrap();
        let mut framed = (body.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&body);

        let len = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        assert!(len <= MAX_FRAME_LEN);
        postcard::from_bytes(&framed[4..4 + len]).unwrap()
    }

    #[test]
    fn framing_round_trips() {
        let msg = MptMessage::GetNodes {
            hashes: vec![synch_core::Hash::new(b"a")],
        };
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn an_empty_body_frames_cleanly() {
        let msg = MptMessage::Heads { heads: Vec::new() };
        assert_eq!(round_trip(&msg), msg);
    }
}
