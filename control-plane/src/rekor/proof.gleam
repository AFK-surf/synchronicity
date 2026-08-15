//// The `RekorProof` v1 record: the compact binary blob that travels in the
//// zone at `_synchronicity-rekor.<apex>`, and the local verification of it.
////
//// This is the mirror of crates/synch-net/src/rekor.rs. Every client that
//// resolves a zone this service signs runs that decoder against these
//// bytes, so the two are one format with two implementations, checked
//// against a shared fixture (test/fixtures/rekor) rather than against each
//// other's good intentions:
////
//// ```text
//// u8       version        = 1
//// u16      key_tag
//// u8[32]   log_id           SHA-256 of the log's DER SubjectPublicKeyInfo
//// u64      log_index
//// u16+[]   dsse_payload     the in-toto Statement, byte-exact
//// u16+[]   dsse_signature   ECDSA P-256 over DSSE PAE(payload)
//// u16+[]   checkpoint       signed note: origin, tree size, root hash, sigs
//// u8+[32]* inclusion_path   Merkle audit path, leaf to root
//// ```
////
//// Two conventions are part of the format and not of either implementation:
//// the log entry is the DSSE envelope as canonical JSON (`payloadType`,
//// `payload`, `signatures` with a single `sig`, padded base64, no
//// whitespace), and the Merkle leaf is `SHA-256(0x00 || entry)` with
//// interior nodes `SHA-256(0x01 || left || right)` — RFC 6962 §2.1.

import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import rekor/statement

/// The version this build writes and accepts.
pub const version = 1

pub type Proof {
  Proof(
    key_tag: Int,
    log_id: BitArray,
    log_index: Int,
    dsse_payload: BitArray,
    dsse_signature: BitArray,
    checkpoint: BitArray,
    inclusion_path: List(BitArray),
  )
}

/// Why a proof was refused. The classes mirror the client's, because a
/// proof this service accepts and the client refuses is the failure mode
/// this whole verify-before-store step exists to prevent.
pub type ProofError {
  Malformed(String)
  Possession(String)
  Binding(String)
  Inclusion(String)
  CheckpointFailed(String)
  UnknownLog(String)
}

/// A parsed signed note.
pub type Checkpoint {
  Checkpoint(
    origin: String,
    tree_size: Int,
    root_hash: BitArray,
    /// The exact bytes the signature lines cover.
    signed: BitArray,
    /// `(name, signature)` per line; the four-byte key hint is a selector,
    /// never a credential, so it is dropped on the way in.
    signatures: List(#(String, BitArray)),
  )
}

/// Encodes the record.
pub fn encode(proof: Proof) -> BitArray {
  bit_array.concat([
    <<version:int-size(8), proof.key_tag:int-size(16)>>,
    proof.log_id,
    <<proof.log_index:int-size(64)>>,
    blob16(proof.dsse_payload),
    blob16(proof.dsse_signature),
    blob16(proof.checkpoint),
    <<list.length(proof.inclusion_path):int-size(8)>>,
    bit_array.concat(proof.inclusion_path),
  ])
}

fn blob16(bytes: BitArray) -> BitArray {
  <<bit_array.byte_size(bytes):int-size(16), bytes:bits>>
}

/// The base64url form one TXT record carries. `zone/build` splits it into
/// ≤255-byte character-strings; the client concatenates before decoding.
pub fn to_txt(proof: Proof) -> String {
  bit_array.base64_url_encode(encode(proof), False)
}

/// The log entry bytes: the DSSE envelope as canonical JSON.
pub fn entry_bytes(proof: Proof) -> BitArray {
  <<
    "{\"payloadType\":\"":utf8,
    statement.dsse_payload_type:utf8,
    "\",\"payload\":\"":utf8,
    bit_array.base64_encode(proof.dsse_payload, True):utf8,
    "\",\"signatures\":[{\"sig\":\"":utf8,
    bit_array.base64_encode(proof.dsse_signature, True):utf8,
    "\"}]}":utf8,
  >>
}

/// The RFC 6962 leaf hash of an entry.
pub fn leaf_hash(entry: BitArray) -> BitArray {
  crypto.hash(crypto.Sha256, bit_array.concat([<<0>>, entry]))
}

/// An RFC 6962 interior node hash.
pub fn node_hash(left: BitArray, right: BitArray) -> BitArray {
  crypto.hash(crypto.Sha256, bit_array.concat([<<1>>, left, right]))
}

/// Walks an audit path from a leaf to a root (RFC 6962 §2.1.1). The leaf's
/// index and the tree size decide which side each sibling sits on, which is
/// why both travel with the proof.
pub fn verify_inclusion(
  index: Int,
  tree_size: Int,
  leaf: BitArray,
  path: List(BitArray),
  root: BitArray,
) -> Result(Nil, ProofError) {
  case index >= tree_size {
    True ->
      Error(Inclusion(
        "entry "
        <> int.to_string(index)
        <> " is outside a tree of "
        <> int.to_string(tree_size),
      ))
    False -> {
      use hash <- result.try(walk(index, tree_size - 1, leaf, path))
      case hash == root {
        True -> Ok(Nil)
        False ->
          Error(Inclusion("the audit path does not reach the checkpoint's root"))
      }
    }
  }
}

fn walk(
  node: Int,
  last: Int,
  hash: BitArray,
  path: List(BitArray),
) -> Result(BitArray, ProofError) {
  case path, last {
    [], 0 -> Ok(hash)
    [], _ -> Error(Inclusion("the audit path is shorter than the tree is deep"))
    [_, ..], 0 ->
      Error(Inclusion("the audit path is longer than the tree is deep"))
    [sibling, ..rest], _ -> {
      let #(hashed, node, last) = case node % 2 == 1 || node == last {
        True -> {
          let #(node, last) = climb(node, last)
          #(node_hash(sibling, hash), node, last)
        }
        False -> #(node_hash(hash, sibling), node, last)
      }
      walk(node / 2, last / 2, hashed, rest)
    }
  }
}

fn climb(node: Int, last: Int) -> #(Int, Int) {
  case node != 0 && node % 2 == 0 {
    True -> climb(node / 2, last / 2)
    False -> #(node, last)
  }
}

/// Parses a signed note: text lines, a blank line, then signature lines.
/// The signature covers the text and its final newline, and nothing after.
pub fn parse_checkpoint(bytes: BitArray) -> Result(Checkpoint, ProofError) {
  let bad = fn(why: String) { Malformed("checkpoint: " <> why) }
  use text <- result.try(
    bit_array.to_string(bytes) |> result.replace_error(bad("not UTF-8")),
  )
  use #(body, sig_text) <- result.try(
    string.split_once(text, "\n\n")
    |> result.replace_error(bad(
      "no blank line between the note and its signatures",
    )),
  )
  let signed = body <> "\n"
  use #(origin, size, root) <- result.try(case string.split(body, "\n") {
    [origin, size, root, ..] -> Ok(#(origin, size, root))
    _ -> Error(bad("the note has fewer than three lines"))
  })
  use tree_size <- result.try(
    int.parse(size)
    |> result.replace_error(bad("the tree size is not a number")),
  )
  use root_hash <- result.try(
    bit_array.base64_decode(root)
    |> result.replace_error(bad("the root hash is not base64")),
  )
  use Nil <- result.try(case bit_array.byte_size(root_hash) == 32 {
    True -> Ok(Nil)
    False -> Error(bad("the root hash is not 32 bytes"))
  })
  use signatures <- result.try(
    string.split(sig_text, "\n")
    |> list.filter(fn(line) { line != "" })
    |> list.try_map(fn(line) {
      // U+2014 EM DASH, then the key name, then base64(keyhint || sig).
      use rest <- result.try(case string.split_once(line, "\u{2014} ") {
        Ok(#("", rest)) -> Ok(rest)
        _ -> Error(bad("a signature line does not start with an em dash"))
      })
      use #(name, encoded) <- result.try(
        string.split_once(rest, " ")
        |> result.replace_error(bad("a signature line has no signature")),
      )
      use blob <- result.try(
        bit_array.base64_decode(encoded)
        |> result.replace_error(bad("a signature is not base64")),
      )
      case bit_array.slice(blob, 4, bit_array.byte_size(blob) - 4) {
        Ok(signature) -> Ok(#(name, signature))
        Error(Nil) -> Error(bad("a signature is shorter than its key hint"))
      }
    }),
  )
  case signatures {
    [] -> Error(bad("no signature lines"))
    _ ->
      Ok(Checkpoint(origin, tree_size, root_hash, <<signed:utf8>>, signatures))
  }
}

@external(erlang, "cp_crypto_ffi", "ecdsa_verify_raw")
fn ecdsa_verify_raw(
  message: BitArray,
  signature: BitArray,
  public: BitArray,
) -> Bool

/// Verifies that the pinned log key signed this checkpoint.
///
/// ECDSA P-256 only: that is what Rekor's checkpoints and this service's
/// own verification use. The client additionally accepts Ed25519 log keys,
/// which no path here produces.
pub fn verify_checkpoint(
  checkpoint: Checkpoint,
  log_public: BitArray,
) -> Result(Nil, ProofError) {
  let signed =
    list.any(checkpoint.signatures, fn(pair) {
      ecdsa_verify_raw(checkpoint.signed, pair.1, log_public)
    })
  case signed {
    True -> Ok(Nil)
    False ->
      Error(CheckpointFailed(
        "no signature on the checkpoint from "
        <> checkpoint.origin
        <> " verifies under the pinned log key",
      ))
  }
}

/// The DER SubjectPublicKeyInfo prefix of an uncompressed P-256 key.
const p256_spki_prefix = <<
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  0x04,
>>

/// Wraps a raw 64-byte P-256 point in a DER SubjectPublicKeyInfo.
pub fn p256_spki(point: BitArray) -> BitArray {
  bit_array.concat([p256_spki_prefix, point])
}

/// The log id a proof names: SHA-256 over the DER SubjectPublicKeyInfo.
pub fn log_id(spki: BitArray) -> BitArray {
  crypto.hash(crypto.Sha256, spki)
}

/// Reads a pinned log key file: PEM `PUBLIC KEY` blocks or one base64
/// SubjectPublicKeyInfo per line, `#` starting a comment. Returns the DER
/// and the raw point, since verification needs one and the log id the
/// other.
pub fn parse_log_key(
  text: String,
) -> Result(#(BitArray, BitArray), ProofError) {
  let body =
    text
    |> string.split("\n")
    |> list.map(fn(line) {
      case string.split_once(line, "#") {
        Ok(#(before, _)) -> before
        Error(Nil) -> line
      }
    })
    |> list.map(string.trim)
    |> list.filter(fn(line) {
      line != ""
      && line != "-----BEGIN PUBLIC KEY-----"
      && line != "-----END PUBLIC KEY-----"
    })
    |> string.join("")
  use der <- result.try(
    bit_array.base64_decode(body)
    |> result.replace_error(UnknownLog("the log key file is not base64")),
  )
  case der {
    <<prefix:bytes-size(27), point:bytes-size(64)>>
      if prefix == p256_spki_prefix
    -> Ok(#(der, point))
    _ ->
      Error(UnknownLog("the log key is not an ECDSA P-256 SubjectPublicKeyInfo"))
  }
}

/// Verifies a proof the way the client will: the entry is in the tree the
/// checkpoint commits to, and the log signed that checkpoint.
///
/// Possession and binding are checked in `rekor/publish`, where the key and
/// the statement being logged are both in hand.
pub fn verify_against_log(
  proof: Proof,
  log_spki: BitArray,
  log_public: BitArray,
) -> Result(Checkpoint, ProofError) {
  use Nil <- result.try(case proof.log_id == log_id(log_spki) {
    True -> Ok(Nil)
    False ->
      Error(UnknownLog(
        "the proof names a log this service does not have the key for",
      ))
  })
  use checkpoint <- result.try(parse_checkpoint(proof.checkpoint))
  use Nil <- result.try(verify_inclusion(
    proof.log_index,
    checkpoint.tree_size,
    leaf_hash(entry_bytes(proof)),
    proof.inclusion_path,
    checkpoint.root_hash,
  ))
  use Nil <- result.try(verify_checkpoint(checkpoint, log_public))
  Ok(checkpoint)
}

/// Splits a stored audit path blob into its 32-byte hashes.
pub fn split_path(blob: BitArray) -> Result(List(BitArray), ProofError) {
  split_path_loop(blob, [])
}

fn split_path_loop(
  blob: BitArray,
  acc: List(BitArray),
) -> Result(List(BitArray), ProofError) {
  case blob {
    <<>> -> Ok(list.reverse(acc))
    <<hash:bytes-size(32), rest:bits>> -> split_path_loop(rest, [hash, ..acc])
    _ ->
      Error(Malformed("the stored audit path is not a run of 32-byte hashes"))
  }
}

/// The stored form of an audit path: the hashes, concatenated.
pub fn join_path(path: List(BitArray)) -> BitArray {
  bit_array.concat(path)
}
