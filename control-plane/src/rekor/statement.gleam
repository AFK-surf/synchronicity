//// The in-toto Statement a zone-key log entry carries (§2 of
//// docs/REKOR-ZONE-KEY.md), and the DSSE envelope around it.
////
//// The Statement is signed by the zone key itself: possession of the CSK
//// is exactly the authority being made transparent, the client already
//// holds the public key from the validated DNSKEY RRset, and it keeps an
//// interactive identity provider out of a ceremony designed to run
//// offline.
////
//// The rendering here is byte-exact and has no equivalent form. The DSSE
//// signature and the log's Merkle leaf both commit to these bytes, so
//// field order, the absence of whitespace and the escaping rules are part
//// of the format — the client's decoder (crates/synch-net/src/rekor.rs)
//// re-derives nothing and compares everything.

import dns/name.{type Name}
import dns/rdata
import dnssec/keys.{type Csk}
import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/string

/// The in-toto Statement type.
pub const statement_type = "https://in-toto.io/Statement/v1"

/// The predicate type carrying the zone-key claim.
pub const predicate_type = "https://synchronicity.dev/zone-key/v1"

/// The DSSE payload type of an in-toto Statement.
pub const dsse_payload_type = "application/vnd.in-toto+json"

pub type Statement {
  Statement(
    subject_name: String,
    subject_sha256: String,
    apex: String,
    key_tag: Int,
    algorithm: Int,
    flags: Int,
    ds: String,
    action: String,
    replaces_key_tag: Option(Int),
  )
}

/// The Statement for a zone key: what this key is, for which zone, and why
/// it is being logged now.
pub fn for_key(
  apex: Name,
  public: BitArray,
  action: String,
  replaces: Option(Int),
) -> Statement {
  let rd = rdata.dnskey(keys.flags, keys.algorithm, public)
  Statement(
    subject_name: name.to_string(apex),
    subject_sha256: string.lowercase(
      bit_array.base16_encode(crypto.hash(crypto.Sha256, rd)),
    ),
    apex: name.to_string(apex),
    key_tag: keys.key_tag(rd),
    algorithm: keys.algorithm,
    flags: keys.flags,
    ds: keys.ds_fields(apex, public),
    action: action,
    replaces_key_tag: replaces,
  )
}

/// The canonical Statement bytes.
pub fn to_json(statement: Statement) -> BitArray {
  let text =
    "{\"_type\":"
    <> quote(statement_type)
    <> ",\"subject\":[{\"name\":"
    <> quote(statement.subject_name)
    <> ",\"digest\":{\"sha256\":"
    <> quote(statement.subject_sha256)
    <> "}}],\"predicateType\":"
    <> quote(predicate_type)
    <> ",\"predicate\":{\"apex\":"
    <> quote(statement.apex)
    <> ",\"keyTag\":"
    <> int.to_string(statement.key_tag)
    <> ",\"algorithm\":"
    <> int.to_string(statement.algorithm)
    <> ",\"flags\":"
    <> int.to_string(statement.flags)
    <> ",\"ds\":"
    <> quote(statement.ds)
    <> ",\"action\":"
    <> quote(statement.action)
    <> ",\"replacesKeyTag\":"
    <> case statement.replaces_key_tag {
      Some(tag) -> int.to_string(tag)
      None -> "null"
    }
    <> "}}"
  <<text:utf8>>
}

/// A JSON string literal. Every field rendered here is a DNS name, a hex
/// digest, or one of three fixed action words — no control characters can
/// reach this, and the two escapes below are what JSON needs for the rest.
fn quote(value: String) -> String {
  let escaped =
    value
    |> string.replace("\\", "\\\\")
    |> string.replace("\"", "\\\"")
  "\"" <> escaped <> "\""
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

@external(erlang, "cp_crypto_ffi", "ecdsa_sign_raw")
fn ecdsa_sign_raw(message: BitArray, private: BitArray) -> BitArray

@external(erlang, "cp_crypto_ffi", "ecdsa_verify_raw")
fn ecdsa_verify_raw(
  message: BitArray,
  signature: BitArray,
  public: BitArray,
) -> Bool

/// Signs a DSSE payload with the zone key.
pub fn sign(csk: Csk, payload: BitArray) -> BitArray {
  ecdsa_sign_raw(pae(dsse_payload_type, payload), csk.private)
}

/// Verifies a DSSE signature against a DNSKEY public key — the same check
/// the client performs, run here before anything is stored.
pub fn verify(
  public: BitArray,
  payload: BitArray,
  signature: BitArray,
) -> Bool {
  ecdsa_verify_raw(pae(dsse_payload_type, payload), signature, public)
}
