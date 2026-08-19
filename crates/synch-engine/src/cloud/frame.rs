//! The tunnel wire format: JSON control frames, binary content frames.
//!
//! Two shapes cross one WebSocket, multiplexed by request id. Control frames
//! are JSON text, tagged by `t`; content travels in binary frames behind an
//! eight-byte header, so file bytes are never JSON-encoded.
//!
//! **There is no frame that writes.** Nothing here encodes a put, an adopt, a
//! pin or a config append, so a control plane holding one end of this tunnel
//! cannot push bytes at a cluster whatever it sends — the read-only property
//! is a fact about this file, not a check somewhere else.

use serde::{Deserialize, Serialize};

/// The tunnel protocol version, carried in the hello and echoed on attach.
///
/// A mismatch is a refusal naming both versions, the same posture
/// `x-synch-control-version` takes on the local socket.
pub const PROTOCOL_VERSION: u32 = 1;

/// The domain-separation tag an attach proof signs under.
///
/// Distinct from `sync-head/1`, so a signature minted here can never be read
/// as a head signature, nor a head signature replayed as an attach proof.
pub const ATTACH_SIGNING_DOMAIN: &[u8] = b"synch-cloud-attach-v1";

/// How many bytes an attach nonce carries.
pub const NONCE_LEN: usize = 32;

/// The largest payload one binary content frame carries.
pub const MAX_CHUNK: usize = 64 * 1024;

/// The fixed header every binary content frame opens with: request id then
/// sequence, both big-endian `u32`.
pub const CHUNK_HEADER_LEN: usize = 8;

/// The exact bytes an attach proof covers:
///
/// ```text
/// "synch-cloud-attach-v1" || url || nonce
/// ```
///
/// The nonce is fixed-width and last, so no `(url, nonce)` pair produces the
/// same input as another — a length prefix would buy nothing a fixed-width
/// suffix does not already give. Binding the URL is what stops a proof minted
/// for one control plane being replayed at another: the daemon signs the
/// endpoint it actually dialed, and the endpoint checks against its own.
pub fn attach_signing_input(url: &str, nonce: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ATTACH_SIGNING_DOMAIN.len() + url.len() + nonce.len());
    buf.extend_from_slice(ATTACH_SIGNING_DOMAIN);
    buf.extend_from_slice(url.as_bytes());
    buf.extend_from_slice(nonce);
    buf
}

/// Wraps a payload in its content-frame header.
pub fn encode_chunk(id: u32, seq: u32, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CHUNK_HEADER_LEN + data.len());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Reads a content frame's header, returning the payload behind it.
pub fn decode_chunk(frame: &[u8]) -> Option<(u32, u32, &[u8])> {
    if frame.len() < CHUNK_HEADER_LEN {
        return None;
    }
    let id = u32::from_be_bytes(frame[0..4].try_into().ok()?);
    let seq = u32::from_be_bytes(frame[4..8].try_into().ok()?);
    Some((id, seq, &frame[CHUNK_HEADER_LEN..]))
}

/// What the control plane sends down the tunnel.
///
/// Every variant either asks a question about the unified tree or governs one
/// stream. None of them changes anything on the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum Down {
    /// The 32-byte nonce, hex, that the attach proof must cover.
    Challenge {
        /// The nonce, hex-encoded.
        nonce: String,
    },
    /// The proof was accepted and the session is live.
    Attached {
        /// The control plane's id for this session, for logs on both sides.
        session: String,
        /// The protocol version the control plane settled on.
        v: u32,
    },
    /// One page of a directory of the unified tree.
    Ls {
        /// The request id.
        id: u32,
        /// The space.
        space: String,
        /// The directory within the space, empty for its root.
        path: String,
        /// Resume after this path, exclusive.
        #[serde(default)]
        cursor: Option<String>,
        /// Inline every version of every entry, with its attestors.
        #[serde(default)]
        all: bool,
    },
    /// Every version of one path, with attestors.
    Stat {
        /// The request id.
        id: u32,
        /// The space.
        space: String,
        /// The path within the space.
        path: String,
    },
    /// The version a selector picks, its content root, and who holds it.
    Resolve {
        /// The request id.
        id: u32,
        /// The space.
        space: String,
        /// The path within the space.
        path: String,
        /// Pin one origin's version; unset takes the newest.
        #[serde(default)]
        from: Option<String>,
    },
    /// A byte range of a content root a [`Down::Resolve`] pinned.
    Read {
        /// The request id.
        id: u32,
        /// The content root, hex.
        root: String,
        /// The object's full size, as the resolve reported it.
        size: u64,
        /// The first byte to read.
        #[serde(default)]
        start: u64,
        /// How many bytes, or unset to the end of the object.
        #[serde(default)]
        len: Option<u64>,
        /// How many chunks may be sent before the first credit arrives.
        #[serde(default)]
        credit: u32,
    },
    /// More chunks may be sent on one stream.
    Credit {
        /// The stream's request id.
        id: u32,
        /// How many further chunks are allowed.
        n: u32,
    },
    /// Abandon one stream.
    Cancel {
        /// The stream's request id.
        id: u32,
    },
    /// Liveness, answered with [`Up::Pong`].
    Ping,
    /// The answer to a [`Up::Ping`].
    Pong,
    /// A coded refusal, of one request or of the connection.
    Err {
        /// The request it refuses, or unset for the connection itself.
        #[serde(default)]
        id: Option<u32>,
        /// The stable code.
        code: String,
        /// What went wrong, in the words a person reads.
        message: String,
    },
}

/// What the node sends up the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum Up {
    /// The opening frame: who is attaching, for what, and speaking what.
    Hello {
        /// The protocol version this daemon speaks.
        v: u32,
        /// The membership domain this attach is for.
        network: String,
        /// This node's origin, canonically rendered.
        origin: String,
        /// The active device key, z-base-32.
        device: String,
        /// The spaces this node holds, as they stood when the session opened.
        /// A routing claim, not a boundary: the daemon serves whatever the
        /// control plane asks of it.
        spaces: Vec<String>,
    },
    /// The signed challenge.
    Proof {
        /// The signature, hex.
        sig: String,
        /// The device key that produced it, z-base-32.
        key: String,
    },
    /// One page of a listing.
    Page {
        /// The request id.
        id: u32,
        /// The entries of this page.
        entries: Vec<EntryJson>,
        /// Where the next page resumes, or unset at the end of the listing.
        cursor: Option<String>,
    },
    /// Every version of one path.
    Versions {
        /// The request id.
        id: u32,
        /// The versions, newest-wins order last.
        versions: Vec<VersionJson>,
    },
    /// What a resolve settled on.
    Resolved {
        /// The request id.
        id: u32,
        /// The origin whose version was selected.
        origin: String,
        /// The content root, hex.
        root: String,
        /// The object's size.
        size: u64,
        /// The seq the version was published at.
        seq: u64,
        /// Origins currently advertising availability for that root.
        holders: Vec<String>,
    },
    /// The header of a content stream, before its first chunk.
    Meta {
        /// The stream's request id.
        id: u32,
        /// How many bytes this stream will carry.
        size: u64,
        /// The content root the bytes were verified against, hex.
        root: String,
    },
    /// A stream ended, having sent everything it was asked for.
    Done {
        /// The stream's request id.
        id: u32,
    },
    /// Liveness.
    Ping,
    /// The answer to a [`Down::Ping`].
    Pong,
    /// A coded refusal, carrying the daemon's own error codes verbatim.
    Err {
        /// The request it refuses, or unset for the connection itself.
        #[serde(default)]
        id: Option<u32>,
        /// The stable code.
        code: String,
        /// What went wrong.
        message: String,
    },
}

/// One entry of a directory of the unified tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryJson {
    /// The entry's name within the directory listed.
    pub name: String,
    /// The full path within the space.
    pub path: String,
    /// `dir`, `file`, `symlink` or `tombstone`.
    pub kind: String,
    /// The selected version's size.
    pub size: u64,
    /// The selected version's mtime, unix nanoseconds.
    pub mtime_ns: i64,
    /// How many versions the path carries: more than one is divergence.
    pub versions: u32,
    /// The origin the newest-wins policy selected.
    pub origin: String,
    /// The selected version's content root, hex, for files.
    pub root: Option<String>,
    /// Every version, when the request asked for them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<VersionJson>,
}

/// One version of one path, as a listing or the inspector renders it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionJson {
    /// The content root, hex, for content-carrying kinds.
    pub root: Option<String>,
    /// `file`, `dir`, `symlink` or `tombstone`.
    pub kind: String,
    /// The link target, for a symlink.
    pub symlink_target: Option<String>,
    /// The content length.
    pub size: u64,
    /// The greatest mtime any attestor published.
    pub mtime_ns: i64,
    /// The greatest seq any attestor published it at.
    pub seq: u64,
    /// Every origin asserting this version.
    pub attestors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_core::head_signing_input;

    /// The two contexts a device key signs under must not overlap. A head
    /// signature that verified as an attach proof would let anyone who has
    /// ever seen a published head attach as that node.
    #[test]
    fn an_attach_proof_is_not_a_head_signature() {
        let key = iroh_base::SecretKey::generate();
        let node_id = key.public();
        let origin = synch_core::OriginId::named("nas", "cluster.example").unwrap();
        let url = "https://sync.example/agent/v1/attach";
        let nonce = [7u8; NONCE_LEN];

        let attach = attach_signing_input(url, &nonce);
        let head = head_signing_input(&origin, 7, &synch_core::Hash::new(b"root"), 1234, &node_id);
        assert_ne!(attach, head);
        assert!(attach.starts_with(ATTACH_SIGNING_DOMAIN));
        assert!(!attach.starts_with(synch_core::HEAD_SIGNING_DOMAIN));
        assert!(!head.starts_with(ATTACH_SIGNING_DOMAIN));

        // And the signatures themselves do not cross over.
        let attach_sig = key.sign(&attach);
        let head_sig = key.sign(&head);
        assert!(node_id.verify(&attach, &attach_sig).is_ok());
        assert!(node_id.verify(&head, &attach_sig).is_err());
        assert!(node_id.verify(&attach, &head_sig).is_err());
    }

    /// The URL is part of what is signed, so a proof cannot be forwarded to a
    /// second control plane by whoever holds the first one's connection.
    #[test]
    fn an_attach_proof_is_bound_to_the_endpoint_it_was_minted_for() {
        let nonce = [1u8; NONCE_LEN];
        assert_ne!(
            attach_signing_input("https://a.example/agent/v1/attach", &nonce),
            attach_signing_input("https://b.example/agent/v1/attach", &nonce)
        );
        // The boundary cannot be shifted: the nonce is a fixed-width tail, so
        // a URL ending in the first nonce byte does not produce the input a
        // shorter URL with a longer nonce would.
        let shifted = [&[0x2fu8][..], &nonce[..NONCE_LEN - 1]].concat();
        assert_ne!(
            attach_signing_input("https://a.example", &nonce),
            attach_signing_input("https://a.example/", &shifted)
        );
    }

    #[test]
    fn content_frames_round_trip_through_their_header() {
        let payload = vec![9u8; 1024];
        let frame = encode_chunk(0x0102_0304, 7, &payload);
        assert_eq!(frame.len(), CHUNK_HEADER_LEN + payload.len());
        let (id, seq, data) = decode_chunk(&frame).unwrap();
        assert_eq!(id, 0x0102_0304);
        assert_eq!(seq, 7);
        assert_eq!(data, &payload[..]);

        // An empty payload is a legal frame; a truncated header is not.
        let empty = encode_chunk(1, 0, &[]);
        let (id, seq, data) = decode_chunk(&empty).unwrap();
        assert_eq!((id, seq, data.len()), (1, 0, 0));
        assert!(decode_chunk(&[0, 0, 0, 1, 0, 0, 0]).is_none());
    }

    #[test]
    fn control_frames_round_trip_through_json() {
        let cases = vec![
            Down::Challenge {
                nonce: "aa".repeat(NONCE_LEN),
            },
            Down::Ls {
                id: 4,
                space: "media".into(),
                // A colon in a path is exactly what a text reference cannot
                // carry, which is why these frames are structured.
                path: "uploads/2026:07".into(),
                cursor: None,
                all: true,
            },
            Down::Read {
                id: 9,
                root: "ff".repeat(32),
                size: 4096,
                start: 512,
                len: Some(1024),
                credit: 4,
            },
            Down::Credit { id: 9, n: 2 },
            Down::Cancel { id: 9 },
            Down::Ping,
            Down::Err {
                id: None,
                code: "browse-disabled".into(),
                message: "no".into(),
            },
        ];
        for frame in cases {
            let text = serde_json::to_string(&frame).unwrap();
            assert_eq!(serde_json::from_str::<Down>(&text).unwrap(), frame);
        }

        let up = Up::Resolved {
            id: 1,
            origin: "nas@cluster.example".into(),
            root: "ab".repeat(32),
            size: 7,
            seq: 3,
            holders: vec!["nas@cluster.example".into()],
        };
        let text = serde_json::to_string(&up).unwrap();
        assert_eq!(serde_json::from_str::<Up>(&text).unwrap(), up);
    }

    /// Absent optional fields decode: a control plane one release behind must
    /// not be a parse failure.
    #[test]
    fn optional_fields_default_when_a_peer_omits_them() {
        let frame: Down =
            serde_json::from_str(r#"{"t":"ls","id":1,"space":"m","path":""}"#).unwrap();
        assert_eq!(
            frame,
            Down::Ls {
                id: 1,
                space: "m".into(),
                path: String::new(),
                cursor: None,
                all: false,
            }
        );
        let frame: Down =
            serde_json::from_str(r#"{"t":"read","id":1,"root":"ab","size":9}"#).unwrap();
        assert_eq!(
            frame,
            Down::Read {
                id: 1,
                root: "ab".into(),
                size: 9,
                start: 0,
                len: None,
                credit: 0,
            }
        );
    }

    /// There is no opcode that writes, and this is where that stays true: a
    /// frame naming one is not a refusal at some later gate, it is a decode
    /// failure with nowhere to go.
    #[test]
    fn no_frame_encodes_a_write() {
        for attempt in [
            r#"{"t":"put","id":1,"space":"m","path":"a"}"#,
            r#"{"t":"take","id":1,"space":"m","path":"a"}"#,
            r#"{"t":"appendconfig","id":1,"key":"s3.x","record":"y"}"#,
        ] {
            assert!(serde_json::from_str::<Down>(attempt).is_err(), "{attempt}");
        }
    }
}
