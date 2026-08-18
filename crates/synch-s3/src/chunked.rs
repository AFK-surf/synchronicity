//! Decoding `aws-chunked` request bodies (§9.4).
//!
//! An SDK that computes a checksum while it streams cannot put the result in a
//! header — the header is long gone by the time the last byte is hashed — so it
//! frames the body instead: each piece is preceded by its length in hex, and
//! the checksum arrives in a trailer after the final zero-length piece. The
//! client announces the shape in `x-amz-content-sha256` and the real payload
//! length in `x-amz-decoded-content-length`.
//!
//! This matters more than it looks. Mountpoint for Amazon S3 sends
//! `--upload-checksums crc32c` **by default**, so its every upload is framed
//! this way; a gateway that treats the body as opaque bytes stores the framing
//! as file content and reports success. The object is then corrupt in a way
//! nothing downstream can detect, because the corrupt bytes are what got
//! hashed.
//!
//! So the framing is stripped here, and the trailing checksum is *verified*
//! rather than skipped: the client asked for an end-to-end integrity check and
//! is entitled to be told when it fails. A failure surfaces as a stream error,
//! which is exactly what a truncated body surfaces as — the daemon aborts the
//! write and the staging file goes with it, so a body that fails its checksum
//! never becomes a published assertion.

use std::collections::BTreeMap;

use axum::body::Body;
use tokio_stream::StreamExt;

use crate::error::{S3Error, S3Result};

/// The longest a chunk-size or trailer line may be before it is refused.
///
/// A size line is a few bytes of hex plus extensions; a trailer line is a
/// header name and a base64 digest. Neither has any business being long, and
/// the cap is what stops a client from making the gateway buffer without bound
/// by never sending a newline.
const MAX_LINE: usize = 8 * 1024;

/// The most trailer bytes accepted after the final chunk, for the same reason.
const MAX_TRAILER: usize = 16 * 1024;

/// How a request body is framed, read from `x-amz-content-sha256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// The body is the payload.
    Plain,
    /// The body is `aws-chunked`, with no per-chunk signatures.
    Chunked,
}

/// Reads the framing a request declared.
///
/// The signed-chunk variants are refused rather than accepted-and-ignored:
/// verifying a per-chunk signature means carrying the rolling signing state
/// forward from the seed signature, and a gateway that skipped the check while
/// answering as though it had made one would be claiming an authentication it
/// never performed. `NotImplemented` makes a client fall back to a form this
/// gateway does check.
pub fn framing(payload_hash: &str) -> S3Result<Framing> {
    // The value is a hex digest, a sentinel, or one of the streaming forms;
    // only the streaming forms frame the body.
    if !payload_hash.starts_with("STREAMING-") {
        return Ok(Framing::Plain);
    }
    match payload_hash {
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => Ok(Framing::Chunked),
        other => Err(S3Error::not_implemented(&format!(
            "the {other} body encoding"
        ))),
    }
}

/// A checksum algorithm a trailer can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha256,
}

impl Algorithm {
    /// The algorithm a `x-amz-checksum-<name>` trailer names.
    fn parse(name: &str) -> Option<Algorithm> {
        match name {
            "crc32" => Some(Algorithm::Crc32),
            "crc32c" => Some(Algorithm::Crc32c),
            "crc64nvme" => Some(Algorithm::Crc64Nvme),
            "sha256" => Some(Algorithm::Sha256),
            _ => None,
        }
    }
}

/// Computes the checksums a trailer might ask about, one byte-stream at a time.
///
/// Every supported algorithm runs concurrently because which one the client
/// chose is only known from the trailer, which arrives last. They are all
/// cheap next to the write the bytes are on their way to.
struct Digests {
    crc32: crc::Digest<'static, u32>,
    crc32c: crc::Digest<'static, u32>,
    crc64nvme: crc::Digest<'static, u64>,
    sha256: sha2::Sha256,
}

static CRC32: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
static CRC32C: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
static CRC64NVME: crc::Crc<u64> = crc::Crc::<u64>::new(&crc::CRC_64_NVME);

/// The digest states are opaque and carry nothing worth printing; what a
/// caller wants to see is which algorithms are running, which is all of them.
impl std::fmt::Debug for Digests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Digests(crc32, crc32c, crc64nvme, sha256)")
    }
}

impl Digests {
    fn new() -> Digests {
        Digests {
            crc32: CRC32.digest(),
            crc32c: CRC32C.digest(),
            crc64nvme: CRC64NVME.digest(),
            sha256: <sha2::Sha256 as sha2::Digest>::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.crc32.update(bytes);
        self.crc32c.update(bytes);
        self.crc64nvme.update(bytes);
        sha2::Digest::update(&mut self.sha256, bytes);
    }

    /// The finished digest for one algorithm, as the raw bytes S3 base64s.
    fn finish(self, algorithm: Algorithm) -> Vec<u8> {
        match algorithm {
            Algorithm::Crc32 => self.crc32.finalize().to_be_bytes().to_vec(),
            Algorithm::Crc32c => self.crc32c.finalize().to_be_bytes().to_vec(),
            Algorithm::Crc64Nvme => self.crc64nvme.finalize().to_be_bytes().to_vec(),
            Algorithm::Sha256 => sha2::Digest::finalize(self.sha256).to_vec(),
        }
    }
}

/// Where the decoder is in the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Reading a `<hex-size>[;ext]\r\n` line.
    Size,
    /// Reading the payload of a chunk, with this many bytes still to come.
    Data(u64),
    /// Consuming the `\r\n` that closes a chunk's payload.
    DataEnd,
    /// Reading trailer lines, until a blank one ends them.
    Trailer,
    /// The final `\r\n` has been seen; nothing more is accepted.
    Done,
}

/// An incremental `aws-chunked` decoder.
///
/// Bytes go in in whatever pieces the network chose and payload comes out; the
/// framing never has to be whole in memory, so a 5 GiB part costs the same here
/// as a 5 KiB one.
#[derive(Debug)]
pub struct Decoder {
    state: State,
    line: Vec<u8>,
    trailer_bytes: usize,
    trailers: BTreeMap<String, String>,
    decoded: u64,
    /// What `x-amz-decoded-content-length` promised, if it said.
    expected: Option<u64>,
    digests: Option<Digests>,
}

impl Decoder {
    /// A decoder for a body whose payload length the client declared.
    pub fn new(expected: Option<u64>) -> Decoder {
        Decoder {
            state: State::Size,
            line: Vec::new(),
            trailer_bytes: 0,
            trailers: BTreeMap::new(),
            decoded: 0,
            expected,
            digests: Some(Digests::new()),
        }
    }

    /// How many payload bytes have been decoded so far.
    pub fn decoded(&self) -> u64 {
        self.decoded
    }

    /// Feeds one piece of the wire body, returning the payload it yielded.
    pub fn push(&mut self, mut input: &[u8]) -> S3Result<Vec<u8>> {
        let mut out = Vec::with_capacity(input.len());
        while !input.is_empty() {
            match self.state {
                State::Size => match self.take_line(&mut input)? {
                    None => break,
                    Some(line) => {
                        let size = parse_size(&line)?;
                        // A zero-length chunk is the end of the payload; what
                        // follows is the trailer section, which is present even
                        // when it is empty.
                        self.state = if size == 0 {
                            State::Trailer
                        } else {
                            State::Data(size)
                        };
                    }
                },
                State::Data(remaining) => {
                    let take = (remaining as usize).min(input.len());
                    let (payload, rest) = input.split_at(take);
                    if let Some(digests) = self.digests.as_mut() {
                        digests.update(payload);
                    }
                    self.decoded += take as u64;
                    // The declared length is checked as it is exceeded rather
                    // than only at the end: a client that lied about it must
                    // not first get to stream an unbounded body into a staging
                    // file on the strength of the lie.
                    if let Some(expected) = self.expected {
                        if self.decoded > expected {
                            return Err(S3Error::invalid(format!(
                                "the body carries more than the {expected} byte(s) \
                                 x-amz-decoded-content-length declared"
                            )));
                        }
                    }
                    out.extend_from_slice(payload);
                    input = rest;
                    self.state = match remaining - take as u64 {
                        0 => State::DataEnd,
                        left => State::Data(left),
                    };
                }
                State::DataEnd => match self.take_line(&mut input)? {
                    None => break,
                    Some(line) if line.is_empty() => self.state = State::Size,
                    Some(_) => {
                        return Err(S3Error::invalid("a chunk did not end where its size said"))
                    }
                },
                State::Trailer => match self.take_line(&mut input)? {
                    None => break,
                    // The blank line closes the trailer section, and with it
                    // the body.
                    Some(line) if line.is_empty() => self.state = State::Done,
                    Some(line) => {
                        self.trailer_bytes += line.len();
                        if self.trailer_bytes > MAX_TRAILER {
                            return Err(S3Error::invalid("the trailer section is too long"));
                        }
                        let text = String::from_utf8_lossy(&line);
                        if let Some((name, value)) = text.split_once(':') {
                            self.trailers
                                .insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
                        }
                    }
                },
                // Trailing garbage is a framing error, not something to skip:
                // whatever produced it disagrees with this decoder about where
                // the body ended.
                State::Done => {
                    return Err(S3Error::invalid("the body continued past its final chunk"))
                }
            }
        }
        Ok(out)
    }

    /// Accumulates up to the next `\r\n`, returning the line without it.
    ///
    /// `None` means the piece ran out first; the partial line is kept and the
    /// next piece continues it.
    fn take_line(&mut self, input: &mut &[u8]) -> S3Result<Option<Vec<u8>>> {
        match input.iter().position(|&b| b == b'\n') {
            Some(idx) => {
                self.line.extend_from_slice(&input[..idx]);
                *input = &input[idx + 1..];
                let mut line = std::mem::take(&mut self.line);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                Ok(Some(line))
            }
            None => {
                self.line.extend_from_slice(input);
                *input = &input[input.len()..];
                if self.line.len() > MAX_LINE {
                    return Err(S3Error::invalid("a chunk header ran on without a newline"));
                }
                Ok(None)
            }
        }
    }

    /// Checks that the body ended where it said it would, and that the payload
    /// matches whatever checksum the trailer carried.
    pub fn finish(mut self) -> S3Result<()> {
        if self.state != State::Done {
            return Err(S3Error::invalid(
                "the chunked body ended in the middle of a frame",
            ));
        }
        if let Some(expected) = self.expected {
            if self.decoded != expected {
                return Err(S3Error::invalid(format!(
                    "the body carried {} byte(s) against the {expected} \
                     x-amz-decoded-content-length declared",
                    self.decoded
                )));
            }
        }
        let Some((name, declared)) = self
            .trailers
            .iter()
            .find_map(|(k, v)| Some((k.strip_prefix("x-amz-checksum-")?, v.clone())))
        else {
            return Ok(());
        };
        // An algorithm this gateway cannot compute is refused rather than
        // waved through: the client asked to be told if the bytes changed in
        // flight, and answering 200 without having looked is the one response
        // that is worse than either checking or declining.
        let algorithm = Algorithm::parse(name)
            .ok_or_else(|| S3Error::not_implemented(&format!("the {name} checksum algorithm")))?;
        let digests = self
            .digests
            .take()
            .ok_or_else(|| S3Error::store("the digest state went missing"))?;
        let computed = digests.finish(algorithm);
        let expected = base64_decode(&declared)
            .ok_or_else(|| S3Error::invalid(format!("the {name} checksum is not base64")))?;
        if computed != expected {
            return Err(S3Error::new(
                axum::http::StatusCode::BAD_REQUEST,
                "BadDigest",
                format!("the body does not match the {name} checksum it carried"),
            ));
        }
        Ok(())
    }
}

/// Reads a chunk-size line: hex, then any number of `;name=value` extensions.
fn parse_size(line: &[u8]) -> S3Result<u64> {
    let text = std::str::from_utf8(line)
        .map_err(|_| S3Error::invalid("a chunk size line was not text"))?;
    let hex = text.split(';').next().unwrap_or("").trim();
    if hex.is_empty() {
        return Err(S3Error::invalid("a chunk carried no size"));
    }
    u64::from_str_radix(hex, 16)
        .map_err(|_| S3Error::invalid(format!("{hex:?} is not a chunk size")))
}

/// Decodes standard base64, which is what a checksum trailer carries.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// Wraps a framed request body so what comes out of it is the payload.
///
/// A `Plain` body is handed back untouched — the decoder is not in the path at
/// all — so the ordinary case pays nothing for this.
///
/// The decoded pieces travel over a short channel, the same shape a read takes
/// in the other direction: a stalled consumer stops the decoder within a piece
/// or two, so a slow daemon costs bounded memory rather than a buffered body.
pub fn decode(body: Body, framing: Framing, declared: Option<u64>) -> Body {
    if framing == Framing::Plain {
        return body;
    }
    let mut decoder = Decoder::new(declared);
    let mut stream = body.into_data_stream();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(2);
    tokio::spawn(async move {
        while let Some(piece) = stream.next().await {
            let piece = match piece {
                Ok(piece) => piece,
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    return;
                }
            };
            match decoder.push(&piece) {
                Ok(payload) if payload.is_empty() => continue,
                Ok(payload) => {
                    if tx.send(Ok(payload)).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    return;
                }
            }
        }
        // The trailer's verdict arrives after the last payload byte, so a
        // mismatch can only be reported by ending the body in an error — which
        // is the same thing a truncated body does, and the daemon treats it the
        // same way: the staging file goes, and nothing is published.
        if let Err(e) = decoder.finish() {
            let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
        }
    });
    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
}
