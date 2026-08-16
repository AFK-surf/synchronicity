//// The `RekorProof` record: the compact binary blob that travels in the
//// zone at `_synchronicity-rekor.<apex>`, and the local verification of it.
////
//// This is the mirror of crates/synch-net/src/rekor.rs. Every client that
//// resolves a zone this service signs runs that decoder against these
//// bytes, so the two are one format with two implementations, checked
//// against a shared fixture (test/fixtures/rekor) rather than against each
//// other's good intentions:
////
//// ```text
//// u8       version            = 4
//// u8[32]   log_id               SHA-256 of the log's DER SubjectPublicKeyInfo
//// u64      log_index
//// u16+[]   statement            the in-toto Statement, byte-exact (PAE preimage)
//// u16+[]   canonicalized_body   the Rekor entry body, verbatim (leaf preimage)
//// u16+[]   checkpoint           signed note: origin, tree size, root hash, sigs
//// u8+[32]* inclusion_path       Merkle audit path, leaf to root
//// ```
////
//// The entry is the *real* Rekor v2 serialization, not a synchronicity
//// convention: Rekor accepts only `hashedrekord`, so a DSSE-signed Statement
//// is logged as a `hashedrekord` v0.0.2 over the DSSE PAE —
//// `data.digest = SHA-256(PAE)`, `signature.content` the DER ECDSA over that
//// digest. The log returns those bytes as `canonicalizedBody`; this record
//// carries them **verbatim** and the Merkle leaf is
//// `SHA-256(0x00 || canonicalized_body)`, with interior nodes
//// `SHA-256(0x01 || left || right)` — RFC 6962 §2.1. The Statement rides
//// alongside because the body commits only to its PAE *digest*.
////
//// The **verifier is an `x509Certificate`, never a raw public key**: a
//// raw-key entry names no zone anywhere in its leaf, so nobody can monitor
//// a zone for newly published keys — and the threat model has a
//// compromised DNS provider in it, so DNS cannot be the monitoring
//// channel. Rekor validates the certificate not at all and copies its DER
//// into the body verbatim, so the apex in its `dNSName` SAN lands inside
//// the Merkle leaf where a monitor sees it (`rekor/cert`). Any other
//// version byte is a malformed record and a `publicKey` verifier is a
//// refusal.

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string

/// The version this build writes and accepts. v4 is the key-set format:
/// no key-tag selector on the wire — a record's subject is a set, and a
/// client tries each record the zone serves.
pub const version = 4

/// The `hashedrekord` v0.0.2 digest algorithm and P-256 key-details tags a
/// body must declare.
const digest_algorithm = "SHA2_256"

/// The only entry kind Rekor v2 accepts, and the only one this design logs.
const entry_kind = "hashedrekord"

/// The entry API version a body must declare.
const entry_api_version = "0.0.2"

const key_details = "PKIX_ECDSA_P256_SHA_256"

pub type Proof {
  Proof(
    log_id: BitArray,
    log_index: Int,
    statement: BitArray,
    canonicalized_body: BitArray,
    checkpoint: BitArray,
    inclusion_path: List(BitArray),
  )
}

/// Why a proof was refused. The classes mirror the client's, because a
/// proof this service accepts and the client refuses is the failure mode
/// this whole verify-before-store step exists to prevent.
pub type ProofError {
  Malformed(String)
  Attribution(String)
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

/// Encodes the record, or refuses a record that does not fit the format.
///
/// `Error` for a blob past 65535 bytes or an audit path past 255 hops.
/// Refusing beats emitting *something*: the format exists so two
/// implementations agree byte for byte, and the two used to disagree about
/// the failure itself — this side wrapped the length modulo 65536 while the
/// Rust side clamped it and truncated the blob. Two different wrong answers
/// in a format whose whole point is agreement is worse than no answer.
pub fn encode(proof: Proof) -> Result(BitArray, String) {
  use Nil <- result.try(
    [proof.statement, proof.canonicalized_body, proof.checkpoint]
    |> list.try_each(fn(blob) {
      case bit_array.byte_size(blob) <= 65_535 {
        True -> Ok(Nil)
        False ->
          Error("a proof field is longer than the format's 16-bit length")
      }
    }),
  )
  use Nil <- result.try(case list.length(proof.inclusion_path) <= 255 {
    True -> Ok(Nil)
    False -> Error("the audit path is longer than the format's 255 hops")
  })
  Ok(
    bit_array.concat([
      <<version:int-size(8)>>,
      proof.log_id,
      <<proof.log_index:int-size(64)>>,
      blob16(proof.statement),
      blob16(proof.canonicalized_body),
      blob16(proof.checkpoint),
      <<list.length(proof.inclusion_path):int-size(8)>>,
      bit_array.concat(proof.inclusion_path),
    ]),
  )
}

fn blob16(bytes: BitArray) -> BitArray {
  <<bit_array.byte_size(bytes):int-size(16), bytes:bits>>
}

/// The base64url form one TXT record carries. `zone/build` splits it into
/// ≤255-byte character-strings; the client concatenates before decoding.
pub fn to_txt(proof: Proof) -> Result(String, String) {
  encode(proof)
  |> result.map(bit_array.base64_url_encode(_, False))
}

/// A real `hashedrekord` v0.0.2 body over a Statement's DSSE PAE.
///
/// The field order is the live log's, byte for byte — but nothing on the
/// serving path builds a body: the log returns `canonicalizedBody` and the
/// service carries it verbatim. This exists so a test log can mint a body
/// the way Sigstore does, mirroring `hashedrekord_body` on the client's sim
/// side (crates/synch-net/src/sim.rs). `digest` is the caller's; the fake
/// makes it the SHA-256 of the PAE it is logging.
pub fn hashedrekord_body(
  digest: BitArray,
  signature: BitArray,
  certificate: BitArray,
) -> BitArray {
  <<
    "{\"apiVersion\":\"0.0.2\",\"kind\":\"hashedrekord\",\"spec\":{\"hashedRekordV002\":{\"data\":{\"algorithm\":\"SHA2_256\",\"digest\":\"":utf8,
    bit_array.base64_encode(digest, True):utf8,
    "\"},\"signature\":{\"content\":\"":utf8,
    bit_array.base64_encode(signature, True):utf8,
    "\",\"verifier\":{\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\",\"x509Certificate\":{\"rawBytes\":\"":utf8,
    bit_array.base64_encode(certificate, True):utf8,
    "\"}}}}}}":utf8,
  >>
}

/// The digest, DER signature and verifier certificate a `hashedrekord`
/// v0.0.2 body carries. The service reads these back out of the log's own
/// `canonicalizedBody` to re-check attribution and the verifier binding
/// before storing — re-deriving nothing the log already serialized.
///
/// The `publicKey` arm of Rekor's verifier oneof is not handled: an entry
/// whose verifier is a bare key names no apex in its leaf, so no monitor
/// could ever have seen it. There is no branch to reach.
pub fn parse_body(
  bytes: BitArray,
) -> Result(#(BitArray, BitArray, BitArray), ProofError) {
  let bad = fn(why: String) { Malformed("entry body: " <> why) }
  use text <- result.try(
    bit_array.to_string(bytes) |> result.replace_error(bad("not UTF-8")),
  )
  let decoder = {
    use kind <- decode.field("kind", decode.string)
    use api_version <- decode.field("apiVersion", decode.string)
    use algorithm <- decode.subfield(
      ["spec", "hashedRekordV002", "data", "algorithm"],
      decode.string,
    )
    use digest <- decode.subfield(
      ["spec", "hashedRekordV002", "data", "digest"],
      decode.string,
    )
    use content <- decode.subfield(
      ["spec", "hashedRekordV002", "signature", "content"],
      decode.string,
    )
    use details <- decode.subfield(
      ["spec", "hashedRekordV002", "signature", "verifier", "keyDetails"],
      decode.string,
    )
    use raw_bytes <- decode.subfield(
      [
        "spec", "hashedRekordV002", "signature", "verifier", "x509Certificate",
        "rawBytes",
      ],
      decode.string,
    )
    decode.success(#(
      kind,
      api_version,
      algorithm,
      digest,
      content,
      details,
      raw_bytes,
    ))
  }
  use #(kind, api_version, algorithm, digest, content, details, raw_bytes) <- result.try(
    json.parse(text, decoder)
    |> result.replace_error(bad(
      "not a hashedrekord v0.0.2 entry with an x509Certificate verifier",
    )),
  )
  // Asserted here as well as in the client (crates/synch-net/src/rekor.rs),
  // because this module's stated job is to refuse anything the client would:
  // a body this side stores and the client rejects is the failure the
  // verify-before-store step exists to prevent.
  use Nil <- result.try(
    case kind == entry_kind && api_version == entry_api_version {
      True -> Ok(Nil)
      False -> Error(Binding("the entry is " <> kind <> " " <> api_version))
    },
  )
  use Nil <- result.try(case algorithm == digest_algorithm {
    True -> Ok(Nil)
    False -> Error(Binding("entry digest algorithm " <> algorithm))
  })
  use Nil <- result.try(case details == key_details {
    True -> Ok(Nil)
    False -> Error(Binding("entry key details " <> details))
  })
  use digest <- result.try(
    bit_array.base64_decode(digest)
    |> result.replace_error(bad("data.digest is not base64")),
  )
  use content <- result.try(
    bit_array.base64_decode(content)
    |> result.replace_error(bad("signature.content is not base64")),
  )
  use raw_bytes <- result.try(
    bit_array.base64_decode(raw_bytes)
    |> result.replace_error(bad(
      "verifier.x509Certificate.rawBytes is not base64",
    )),
  )
  Ok(#(digest, content, raw_bytes))
}

/// The RFC 6962 leaf hash of an entry body.
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

@external(erlang, "cp_crypto_ffi", "ed25519_verify")
fn ed25519_verify(
  message: BitArray,
  signature: BitArray,
  public: BitArray,
) -> Bool

/// Verifies that the pinned log key signed this checkpoint.
///
/// The algorithm follows the key: a 64-byte point is an uncompressed P-256
/// key whose checkpoint signatures are raw `r||s` (rekor.sigstore.dev and a
/// self-hosted or simulated log); a 32-byte point is Ed25519
/// (log2025-1.rekor.sigstore.dev, the default public log). One matching
/// signature line is enough — the other signature lines beside it are parsed
/// and simply not our key.
pub fn verify_checkpoint(
  checkpoint: Checkpoint,
  log_public: BitArray,
) -> Result(Nil, ProofError) {
  let signed =
    list.any(checkpoint.signatures, fn(pair) {
      case bit_array.byte_size(log_public) {
        64 -> ecdsa_verify_raw(checkpoint.signed, pair.1, log_public)
        32 -> ed25519_verify(checkpoint.signed, pair.1, log_public)
        _ -> False
      }
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

/// The DER SubjectPublicKeyInfo prefix of an Ed25519 key.
const ed25519_spki_prefix = <<
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
>>

/// Wraps a raw 64-byte P-256 point in a DER SubjectPublicKeyInfo.
pub fn p256_spki(point: BitArray) -> BitArray {
  bit_array.concat([p256_spki_prefix, point])
}

/// The log id a proof names: SHA-256 over the DER SubjectPublicKeyInfo.
///
/// **Do not substitute the `logId.keyId` the log returns.** Rekor's
/// `TransparencyLogEntry.logId.keyId` is the C2SP *note* key id —
/// `SHA-256(origin ‖ 0x0A ‖ 0x01 ‖ raw32)` — a different 32-byte value that
/// arrives in the same JSON response, a few fields from the checkpoint, and
/// looks every bit as much like the answer. A proof built with it matches no
/// client pin and fails as "unknown log", which reads like a bad pin set
/// rather than the mix-up it is. This function is the only place the
/// convention is decided, and `publish` calls it with the *pinned* key rather
/// than anything the server said.
pub fn log_id(spki: BitArray) -> BitArray {
  crypto.hash(crypto.Sha256, spki)
}

/// Reads a pinned log key file: PEM `PUBLIC KEY` blocks or one base64
/// SubjectPublicKeyInfo per line, `#` starting a comment. Returns the DER
/// and the raw point, since verification needs one and the log id the
/// other. Both an ECDSA P-256 (64-byte point) and an Ed25519 (32-byte
/// point) key are recognized; everything else is refused.
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
    <<prefix:bytes-size(12), point:bytes-size(32)>>
      if prefix == ed25519_spki_prefix
    -> Ok(#(der, point))
    _ ->
      Error(UnknownLog(
        "the log key is neither an ECDSA P-256 nor an Ed25519 SubjectPublicKeyInfo",
      ))
  }
}

/// Verifies a proof the way the client will: the leaf over the log's own
/// `canonicalizedBody` is in the tree the checkpoint commits to, and the log
/// signed that checkpoint.
///
/// Attribution and the verifier binding are checked in `rekor/publish`,
/// where the signer key and the Statement being logged are both in hand.
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
    leaf_hash(proof.canonicalized_body),
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
