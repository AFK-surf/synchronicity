//// The in-toto Statement a zone-key log entry carries (§2 of
//// docs/REKOR-ZONE-KEY.md), and the DSSE envelope around it.
////
//// The Statement claims a **key set**: the apex DNSKEY RRset the entry's
//// embedded chain proves. Its DSSE signature is *attribution* — it names
//// whoever built the entry, via the certificate's key — and authorizes
//// nothing: authorization is the chain, and only the chain. That is what
//// lets a provider-hosted zone (Cloudflare's keys, Bunny's keys) be logged
//// at all, and it costs nothing — an attacker able to forge an authorized
//// chain for a rogue key holds that key and could sign anything.
////
//// The rendering here is byte-exact and has no equivalent form. The DSSE
//// signature and the log's Merkle leaf both commit to these bytes, so
//// field order, the absence of whitespace, the escaping rules and the
//// canonical key order are part of the format — the client's decoder
//// (crates/synch-net/src/rekor.rs) re-derives nothing and compares
//// everything.

import dns/name.{type Name}
import dnssec/keys.{type Csk}
import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/list
import gleam/order
import gleam/string

/// The in-toto Statement type.
pub const statement_type = "https://in-toto.io/Statement/v1"

/// The predicate type carrying the zone-key claim.
///
/// v2 is the key-set claim: the subject is the apex DNSKEY RRset the chain
/// proves, and the DSSE signer is whoever published the entry.
pub const predicate_type = "https://synchronicity.sh/zone-key/v2"

/// The DSSE payload type of an in-toto Statement.
pub const dsse_payload_type = "application/vnd.in-toto+json"

/// One key of the claimed set. Every field is derived from the DNSKEY
/// rdata alone.
pub type StatementKey {
  StatementKey(key_tag: Int, algorithm: Int, flags: Int, sha256: String)
}

pub type Statement {
  Statement(apex: String, keys: List(StatementKey), action: String)
}

/// The Statement for a key set, from the DNSKEY rdatas themselves — tag,
/// algorithm, flags and digest all derived, and the canonical order applied:
/// ascending key tag, ties broken by the hex digest. One set, one rendering.
pub fn for_keys(
  apex: Name,
  rdatas: List(BitArray),
  action: String,
) -> Statement {
  let keys =
    rdatas
    |> list.map(statement_key)
    |> list.sort(fn(a, b) {
      case int.compare(a.key_tag, b.key_tag) {
        order.Eq -> string.compare(a.sha256, b.sha256)
        other -> other
      }
    })
  Statement(apex: name.to_string(apex), keys: keys, action: action)
}

/// One claimed key's fields, derived from the rdata alone.
///
/// A rdata too short to hold the four-byte DNSKEY header has `flags` and
/// `algorithm` **0**, both of them, rather than whatever partial values could
/// be read out of it: the two renderers commit to one byte string, so this
/// needs one rule, and "the header is unreadable" is one fact rather than two
/// or three. The collector refuses such a rdata before it can be claimed
/// (`rekor/chain`), so this is the answer to a question the wire cannot ask.
fn statement_key(rdata: BitArray) -> StatementKey {
  let #(flags, algorithm) = case rdata {
    <<flags:int-size(16), _protocol:int-size(8), algorithm:int-size(8), _:bits>> -> #(
      flags,
      algorithm,
    )
    _ -> #(0, 0)
  }
  StatementKey(
    key_tag: keys.key_tag(rdata),
    algorithm: algorithm,
    flags: flags,
    sha256: string.lowercase(
      bit_array.base16_encode(crypto.hash(crypto.Sha256, rdata)),
    ),
  )
}

/// The identity of a claimed set: SHA-256 over the concatenated hex digests
/// in canonical order. What `rekor_records` rows are keyed by — a key tag is
/// a 16-bit checksum and says nothing about which set an entry claims.
pub fn keyset_sha256(statement: Statement) -> BitArray {
  let joined =
    statement.keys |> list.map(fn(key) { key.sha256 }) |> string.join("")
  crypto.hash(crypto.Sha256, <<joined:utf8>>)
}

/// The canonical Statement bytes.
pub fn to_json(statement: Statement) -> BitArray {
  let subject =
    statement.keys
    |> list.map(fn(key) {
      "{\"name\":"
      <> quote(statement.apex)
      <> ",\"digest\":{\"sha256\":"
      <> quote(key.sha256)
      <> "}}"
    })
    |> string.join(",")
  let keys =
    statement.keys
    |> list.map(fn(key) {
      "{\"keyTag\":"
      <> int.to_string(key.key_tag)
      <> ",\"algorithm\":"
      <> int.to_string(key.algorithm)
      <> ",\"flags\":"
      <> int.to_string(key.flags)
      <> ",\"sha256\":"
      <> quote(key.sha256)
      <> "}"
    })
    |> string.join(",")
  let text =
    "{\"_type\":"
    <> quote(statement_type)
    <> ",\"subject\":["
    <> subject
    <> "],\"predicateType\":"
    <> quote(predicate_type)
    <> ",\"predicate\":{\"apex\":"
    <> quote(statement.apex)
    <> ",\"keys\":["
    <> keys
    <> "],\"action\":"
    <> quote(statement.action)
    <> "}}"
  <<text:utf8>>
}

/// A JSON string literal, escaped byte-for-byte the way the client's renderer
/// escapes one (`json_string`, crates/synch-net/src/rekor.rs): quote and
/// backslash, the three named control escapes, and `\u00xx` in lowercase hex
/// for every other character below U+0020.
///
/// Every field rendered here is a DNS name, a hex digest or one of three fixed
/// action words, so the control-character rule should be unreachable — but the
/// two renderers commit to one byte string through a Merkle leaf, so "should
/// be unreachable" is not a rule either of them may hold privately.
fn quote(value: String) -> String {
  let escaped =
    string.to_utf_codepoints(value)
    |> list.map(escape_codepoint)
    |> string.concat
  "\"" <> escaped <> "\""
}

fn escape_codepoint(codepoint: UtfCodepoint) -> String {
  case string.utf_codepoint_to_int(codepoint) {
    0x22 -> "\\\""
    0x5c -> "\\\\"
    0x0a -> "\\n"
    0x0d -> "\\r"
    0x09 -> "\\t"
    code if code < 0x20 ->
      "\\u00" <> string.pad_start(string.lowercase(int.to_base16(code)), 2, "0")
    _ -> string.from_utf_codepoints([codepoint])
  }
}

/// The DSSE Pre-Authentication Encoding (DSSE §2): the bytes actually
/// signed, so a payload can never be reinterpreted under another type.
pub fn pae(payload_type: String, payload: BitArray) -> BitArray {
  let type_bits = <<payload_type:utf8>>
  bit_array.concat([
    <<"DSSEv1 ":utf8>>,
    <<int.to_string(bit_array.byte_size(type_bits)):utf8>>,
    <<" ":utf8>>,
    type_bits,
    <<" ":utf8>>,
    <<int.to_string(bit_array.byte_size(payload)):utf8>>,
    <<" ":utf8>>,
    payload,
  ])
}

@external(erlang, "cp_crypto_ffi", "ecdsa_sign_der")
fn ecdsa_sign_der(message: BitArray, private: BitArray) -> BitArray

@external(erlang, "cp_crypto_ffi", "ecdsa_verify_der")
fn ecdsa_verify_der(
  message: BitArray,
  signature: BitArray,
  public: BitArray,
) -> Bool

/// Signs a Statement's DSSE PAE with the entry signer's key, DER/ASN.1
/// encoded. In serve mode the signer is the zone CSK; in external mode an
/// operational key the zone never carries. Either way it is the key the
/// entry's certificate names, and the client's attribution check verifies
/// the signature against exactly that certificate.
///
/// DER, not the raw `r||s` of a DNSSEC signature: this is the byte string a
/// Rekor entry's `signature.content` carries.
pub fn sign(signer: Csk, payload: BitArray) -> BitArray {
  ecdsa_sign_der(pae(dsse_payload_type, payload), signer.private)
}

/// Verifies a DER DSSE-PAE signature against the signer's public key — the
/// same attribution check the client performs, run here before anything is
/// stored.
pub fn verify(
  public: BitArray,
  payload: BitArray,
  signature: BitArray,
) -> Bool {
  ecdsa_verify_der(pae(dsse_payload_type, payload), signature, public)
}
