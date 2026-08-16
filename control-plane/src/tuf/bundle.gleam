//// The `TufBundle` v1 record: Sigstore's TUF metadata, verbatim, framed
//// for the TXT record at `_synchronicity-tuf.<apex>`
//// (docs/REKOR-ZONE-KEY.md §10.1).
////
//// This is the mirror of crates/synch-net/src/tuf.rs, and the mirroring
//// stops at the framing on purpose. The client verifies the chain; this
//// service only relays it, so only the encoder lives here — and it is
//// checked against the same fixture the Rust decoder is
//// (test/fixtures/tuf), because two implementations of one format drift
//// silently unless something outside both of them holds the bytes still.
////
//// ```text
//// u8       version        = 1
//// u8       root_count       root.json versions, ascending
//// u32+[]   root_json[..]
//// u32+[]   timestamp_json   all files verbatim, exactly as the TUF
//// u32+[]   snapshot_json    repository serves them — signatures cover
//// u32+[]   targets_json     these bytes
//// u32+[]   trusted_root     the target the chain authenticates
//// ```

import gleam/bit_array
import gleam/list

/// The version this build writes.
pub const version = 1

pub type Bundle {
  Bundle(
    /// `root.json` at ascending versions, so a client embedded at version N
    /// can chain to the current one.
    roots: List(BitArray),
    timestamp: BitArray,
    snapshot: BitArray,
    targets: BitArray,
    trusted_root: BitArray,
  )
}

/// Encodes the bundle.
pub fn encode(bundle: Bundle) -> BitArray {
  bit_array.concat([
    <<version:int-size(8), list.length(bundle.roots):int-size(8)>>,
    join_roots(bundle.roots),
    blob32(bundle.timestamp),
    blob32(bundle.snapshot),
    blob32(bundle.targets),
    blob32(bundle.trusted_root),
  ])
}

/// The base64url form one TXT record carries. `zone/build` splits it into
/// ≤255-byte character-strings; the client concatenates before decoding.
pub fn to_txt(bundle: Bundle) -> String {
  bit_array.base64_url_encode(encode(bundle), False)
}

/// The stored form of a root chain: each file u32-length-prefixed, in the
/// order the bundle carries them. Storing the framing rather than the files
/// means serving is a copy, not a re-encode.
pub fn join_roots(roots: List(BitArray)) -> BitArray {
  bit_array.concat(list.map(roots, blob32))
}

/// Splits a stored root chain back into its files.
pub fn split_roots(blob: BitArray) -> Result(List(BitArray), Nil) {
  split_loop(blob, [])
}

fn split_loop(
  blob: BitArray,
  acc: List(BitArray),
) -> Result(List(BitArray), Nil) {
  case blob {
    <<>> -> Ok(list.reverse(acc))
    <<len:int-size(32), file:bytes-size(len), rest:bits>> ->
      split_loop(rest, [file, ..acc])
    _ -> Error(Nil)
  }
}

fn blob32(bytes: BitArray) -> BitArray {
  <<bit_array.byte_size(bytes):int-size(32), bytes:bits>>
}
