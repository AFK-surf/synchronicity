//// The zone-key certificate: how the apex gets inside a Merkle leaf
//// (docs/REKOR-ZONE-KEY.md §2).
////
//// Rekor v2 accepts exactly one entry type and gives it no room for a
//// payload, so a `hashedrekord` leaf holds a digest, a signature and a
//// verifier — and nothing that names a zone. That made the v2 entry
//// *apex-anonymous*: nobody could watch a zone for newly published keys,
//// which is the whole reason a transparency requirement is worth having.
////
//// Rekor's verifier is a oneof of a raw public key or an X.509 certificate,
//// and it performs **no certificate validation at all** — it parses, takes
//// the public key, and copies the certificate DER verbatim into the
//// canonicalized body the leaf commits to. So a self-signed certificate
//// carrying the apex as a `dNSName` SAN writes the zone name, in the clear,
//// into the log's own tree, where a monitor walking the tiles can index it.
////
//// What this produces is therefore a **key envelope, not a trust
//// assertion**. Nothing verifies its signature, its issuer or its validity
//// window, here or anywhere downstream. Three things inside it are
//// load-bearing and everything else is X.509 ceremony:
////
////   - the SubjectPublicKeyInfo — the zone CSK, which the client compares
////     against the DNSKEY it validated;
////   - the single `dNSName` SAN — the apex, which the client compares
////     against the RRSIG signer and a monitor indexes by;
////   - one custom extension — the DNSSEC chain, below.
////
//// There used to be a second extension here, `2.25.1138370866`, carrying a
//// succession countersignature: the previous zone key signing "this key
//// follows me". It is gone. A monitor cannot use it to tell a rotation from
//// a substitution — an attacker with the registrar holds the DS and so can
//// always build the chain — so the monitor stopped trying and now reports
//// every newly authorized key instead. **Do not reuse that arc**: a
//// permanently logged entry still carries it.
////
//// The mirror of this module is crates/synch-net/src/{x509,zonecert}.rs.
//// Both sides carry the same OID and the same DER, and the shared fixture
//// (test/fixtures/rekor) is what keeps them from drifting.

import gleam/bit_array
import gleam/bytes_tree
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string

/// The DNSSEC chain extension: `2.25.1555716359`.
///
/// We hold no IANA Private Enterprise Number, and inventing an arc under
/// somebody else's is how OID collisions happen. `2.25` is the UUID arc,
/// which needs no registration.
///
/// **The arc must stay inside 31 bits. Do not widen it.** Rekor is Go, its
/// certificate parser is `crypto/x509`, and Go's `encoding/asn1` rejects any
/// OID component that overflows `int32` — so a full 128-bit UUID arc fails
/// inside `x509.ParseCertificate` *before* Rekor looks at the extension, and
/// the submission comes back `400 invalid hashedrekord request` naming no
/// field. This version of the format did exactly that, and it was found by
/// live submission rather than by any test: Erlang's `public_key` (which
/// builds these certificates) and OpenSSL (which reads them back) both parse
/// the wide form without complaint, so everything here passed against a
/// certificate the log would refuse.
///
/// `1555716359` is `0xdcba5907` — the first four bytes of the original UUID
/// `dcba5907-a9a9-4de1-89fe-7b22794d9fbe` — masked into 31 bits.
///
/// **Provisional.** `2.25.<31-bit>` is a UUID with 97 leading zero bits, so
/// it carries a small collision risk against anyone else doing the same
/// trick; the long-term fix is an IANA Private Enterprise Number and OIDs
/// under `1.3.6.1.4.1.<PEN>` (docs/REKOR-ZONE-KEY.md §8.3). Duplicated with
/// the same warning in crates/synch-net/src/zonecert.rs, and pinned by the
/// crossval fixtures so the two cannot drift.
pub const oid_dnssec_chain = #(2, 25, 1_555_716_359)

/// The subject and issuer common name. Stable and descriptive: a
/// self-signed certificate's issuer is its subject, and this string is the
/// only human-readable hint an auditor reading the raw log entry gets.
pub const common_name = "synchronicity zone key"

/// One link of the carried DNSSEC chain: a zone, and the uncompressed
/// wire-format RRs it owns.
pub type Link {
  Link(zone: String, rrs: BitArray)
}

@external(erlang, "cp_crypto_ffi", "self_signed_cert")
fn ffi_self_signed_cert(
  common_name: BitArray,
  dns_name: BitArray,
  public: BitArray,
  private: BitArray,
  not_before: Int,
  not_after: Int,
  extensions: List(#(#(Int, Int, Int), BitArray)),
) -> BitArray

/// Builds the certificate a `hashedrekord` entry carries as its verifier.
///
/// `not_before` is the statement's own timestamp and `not_after` is a
/// century out. Both are **semantically meaningless**: no verifier in this
/// system reads them, because this is a key envelope and not a trust
/// assertion. They exist because X.509 has a mandatory field there, and
/// they are filled in with something honest rather than something clever.
///
/// A `create` or `rollover` certificate must carry a chain — the client
/// refuses one without it, on the monitors' behalf. A `retire` may not have
/// one to carry, because a retired zone can have no DS left; that asymmetry
/// is `chain: Option`, and it is enforced in `rekor/publish`.
pub fn build(
  apex: String,
  public: BitArray,
  private: BitArray,
  not_before: Int,
  not_after: Int,
  chain: Option(List(Link)),
) -> BitArray {
  let extensions =
    []
    |> prepend_option(chain, fn(links) {
      #(oid_dnssec_chain, encode_chain(links))
    })
    |> list.reverse
  ffi_self_signed_cert(
    <<common_name:utf8>>,
    <<{ san_name(apex) }:utf8>>,
    public,
    private,
    not_before,
    not_after,
    extensions,
  )
}

fn prepend_option(acc: List(b), value: Option(a), make: fn(a) -> b) -> List(b) {
  case value {
    Some(value) -> [make(value), ..acc]
    None -> acc
  }
}

/// The SAN spelling for an apex: **no trailing dot**.
///
/// A `dNSName` is a hostname, and readers parse it into a name before
/// comparing anything — so the dot is presentation, not identity. Writing it
/// one way keeps the fixtures stable.
///
/// Named `san_name` and not `fqdn` because it produces the opposite of an
/// FQDN, and the old name said so backwards.
pub fn san_name(apex: String) -> String {
  case string.ends_with(apex, ".") {
    True -> string.drop_end(apex, 1)
    False -> apex
  }
}

// -------------------------------------------------------------- the chain

/// `DnssecChain ::= SEQUENCE OF SEQUENCE { zone IA5String, rrs OCTET STRING }`,
/// apex link first, root link last.
pub fn encode_chain(links: List(Link)) -> BitArray {
  links
  |> list.map(fn(link) {
    der(
      0x30,
      bit_array.concat([
        der(0x16, <<{ link.zone }:utf8>>),
        der(0x04, link.rrs),
      ]),
    )
  })
  |> bit_array.concat
  |> der(0x30, _)
}

// ---------------------------------------------------------------- the DER

/// A DER tag-length-value, definite length, minimal encoding.
pub fn der(tag: Int, body: BitArray) -> BitArray {
  bit_array.concat([
    <<tag:int-size(8)>>,
    der_length(bit_array.byte_size(body)),
    body,
  ])
}

fn der_length(size: Int) -> BitArray {
  case size < 0x80 {
    True -> <<size:int-size(8)>>
    False -> {
      let bytes = big_endian(size, [])
      bit_array.concat([
        <<{ 0x80 + list.length(bytes) }:int-size(8)>>,
        bytes_of(bytes),
      ])
    }
  }
}

fn big_endian(value: Int, acc: List(Int)) -> List(Int) {
  case value {
    0 -> acc
    _ ->
      big_endian(int.bitwise_shift_right(value, 8), [
        int.bitwise_and(value, 0xff),
        ..acc
      ])
  }
}

fn bytes_of(values: List(Int)) -> BitArray {
  values
  |> list.fold(bytes_tree.new(), fn(acc, byte) {
    bytes_tree.append(acc, <<byte:int-size(8)>>)
  })
  |> bytes_tree.to_bit_array
}
