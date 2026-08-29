use std::borrow::BorrowMut;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::AsyncRead;

use super::{ChannelMsg, ChannelReadHalf};

#[derive(Debug)]
pub struct ChannelRx<R> {
    channel: R,
    buffer: Option<(ChannelMsg, usize)>,

    ext: Option<u32>,
}

impl<R> ChannelRx<R> {
    pub fn new(channel: R, ext: Option<u32>) -> Self {
        Self {
            channel,
            buffer: None,
            ext,
        }
    }
}

impl<R> AsyncRead for ChannelRx<R>
where
    R: BorrowMut<ChannelReadHalf> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A zero-byte `Ready(Ok(()))` is EOF to every Rust reader, so it must
        // only ever come from a genuine end of stream: a closed receiver or
        // `ChannelMsg::Eof`. A message that carries no readable bytes — an
        // empty `CHANNEL_DATA` payload, or a message this reader is not
        // attached to — is consumed and the poll continues to the next one.
        // Looping back to `poll_recv` is what keeps the waker registered.
        loop {
            let (msg, mut idx) = match self.buffer.take() {
                Some(msg) => msg,
                None => match ready!(self.channel.borrow_mut().receiver.poll_recv(cx)) {
                    Some(msg) => (msg, 0),
                    None => return Poll::Ready(Ok(())),
                },
            };

            match (&msg, self.ext) {
                (ChannelMsg::Data { data }, None) => {
                    let readable = buf.remaining().min(data.len() - idx);

                    // Clamped to maximum `buf.remaining()` and `data.len() - idx` with `.min`
                    #[allow(clippy::indexing_slicing)]
                    buf.put_slice(&data[idx..idx + readable]);
                    idx += readable;

                    if idx != data.len() {
                        // Partially consumed, either because `buf` is full or
                        // because it had no room at all: keep the remainder.
                        self.buffer = Some((msg, idx));
                    } else if readable == 0 {
                        // Fully consumed without producing a byte: the payload
                        // was empty. Not EOF.
                        continue;
                    }

                    return Poll::Ready(Ok(()));
                }
                (ChannelMsg::ExtendedData { data, ext }, Some(target)) if *ext == target => {
                    let readable = buf.remaining().min(data.len() - idx);

                    // Clamped to maximum `buf.remaining()` and `data.len() - idx` with `.min`
                    #[allow(clippy::indexing_slicing)]
                    buf.put_slice(&data[idx..idx + readable]);
                    idx += readable;

                    if idx != data.len() {
                        self.buffer = Some((msg, idx));
                    } else if readable == 0 {
                        continue;
                    }

                    return Poll::Ready(Ok(()));
                }
                (ChannelMsg::Eof, _) => {
                    self.channel.borrow_mut().receiver.close();

                    return Poll::Ready(Ok(()));
                }
                _ => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, ReadBuf};
    use tokio::sync::mpsc;

    use super::*;

    /// A reader over a fixed message sequence; dropping the sender makes the
    /// end of the sequence a genuine end of stream.
    fn rx(msgs: Vec<ChannelMsg>, ext: Option<u32>) -> ChannelRx<ChannelReadHalf> {
        let (sender, receiver) = mpsc::channel(msgs.len().max(1));
        for msg in msgs {
            sender.try_send(msg).unwrap();
        }
        ChannelRx::new(ChannelReadHalf { receiver }, ext)
    }

    fn data(payload: &'static [u8]) -> ChannelMsg {
        ChannelMsg::Data {
            data: Bytes::from_static(payload),
        }
    }

    /// F22: an empty `CHANNEL_DATA` payload must not surface as a zero-byte
    /// `Ready`. `tokio::io::copy` — and every other Rust reader — takes that
    /// for EOF, so one empty packet from the peer silently truncated the
    /// stream and stopped the reader from ever being polled again.
    #[tokio::test]
    async fn empty_data_message_is_not_read_as_eof() {
        let mut reader = rx(vec![data(b""), data(b"payload"), ChannelMsg::Eof], None);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();

        assert_eq!(out, b"payload", "an empty data payload was read as EOF");
    }

    /// The same for the extended-data stream a reader is attached to.
    #[tokio::test]
    async fn empty_extended_data_message_is_not_read_as_eof() {
        let extended = |payload: &'static [u8]| ChannelMsg::ExtendedData {
            data: Bytes::from_static(payload),
            ext: 1,
        };
        let mut reader = rx(
            vec![extended(b""), extended(b"stderr"), ChannelMsg::Eof],
            Some(1),
        );

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();

        assert_eq!(
            out, b"stderr",
            "an empty extended-data payload was read as EOF"
        );
    }

    /// `ChannelMsg::Eof` remains the only in-band end of stream.
    #[tokio::test]
    async fn eof_message_still_ends_the_stream() {
        let mut reader = rx(vec![ChannelMsg::Eof, data(b"after eof")], None);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();

        assert!(out.is_empty(), "data after EOF was delivered");
    }

    /// A payload larger than the caller's buffer is still resumed across
    /// polls rather than truncated.
    #[tokio::test]
    async fn payload_longer_than_the_read_buffer_is_resumed() {
        let mut reader = rx(vec![data(b"abcdef"), ChannelMsg::Eof], None);

        let mut buf = [0; 4];
        assert_eq!(reader.read(&mut buf).await.unwrap(), 4);
        assert_eq!(&buf[..4], b"abcd");
        assert_eq!(reader.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf[..2], b"ef");
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
    }

    /// A read into a full buffer must not consume the message, and must not
    /// be mistaken for the empty-payload case.
    #[tokio::test]
    async fn read_with_no_room_keeps_the_message_buffered() {
        let mut reader = rx(vec![data(b"kept"), ChannelMsg::Eof], None);

        let mut empty = [];
        let mut read_buf = ReadBuf::new(&mut empty);
        std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read(cx, &mut read_buf))
            .await
            .unwrap();
        assert_eq!(read_buf.filled().len(), 0);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"kept", "a full-buffer read dropped the message");
    }
}
