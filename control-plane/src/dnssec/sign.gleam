//// RRSIG construction (RFC 4034 §3.1.8.1): the signed data is the RRSIG
//// rdata with an empty signature, followed by every RR of the set in
//// canonical form — owner lowercase and uncompressed, RRs sorted by rdata
//// as left-justified byte strings, TTL replaced by the original TTL.
//// Names are canonical on entry everywhere in this codebase, so the bytes
//// assembled here are exactly the response bytes.

import dns/name.{type Name}
import dns/rdata
import dns/wire
import dnssec/keys.{type Csk}
import gleam/bit_array
import gleam/list

@external(erlang, "cp_crypto_ffi", "ecdsa_sign_raw")
fn ecdsa_sign_raw(message: BitArray, private: BitArray) -> BitArray

@external(erlang, "cp_crypto_ffi", "ecdsa_verify_raw")
fn ecdsa_verify_raw(
  message: BitArray,
  signature: BitArray,
  public: BitArray,
) -> Bool

/// Signs one RRset; returns the RRSIG RR in full wire form, ready to sit
/// beside the RRset in a response.
pub fn sign_rrset(
  csk: Csk,
  key_tag: Int,
  signer: Name,
  owner: Name,
  rtype: Int,
  ttl: Int,
  rdatas: List(BitArray),
  inception: Int,
  expiration: Int,
) -> BitArray {
  rdata.rr(
    owner,
    wire.type_rrsig,
    ttl,
    sign_rrset_rdata(
      csk,
      key_tag,
      signer,
      owner,
      rtype,
      ttl,
      rdatas,
      inception,
      expiration,
    ),
  )
}

/// The same, as the RRSIG *rdata* alone — what a resolver answer carries per
/// record rather than as a packed wire RR.
pub fn sign_rrset_rdata(
  csk: Csk,
  key_tag: Int,
  signer: Name,
  owner: Name,
  rtype: Int,
  ttl: Int,
  rdatas: List(BitArray),
  inception: Int,
  expiration: Int,
) -> BitArray {
  let signature =
    ecdsa_sign_raw(
      signing_input(
        key_tag,
        signer,
        owner,
        rtype,
        ttl,
        rdatas,
        inception,
        expiration,
      ),
      csk.private,
    )
  rdata.rrsig(
    rtype,
    keys.algorithm,
    list.length(owner),
    ttl,
    expiration,
    inception,
    key_tag,
    signer,
    signature,
  )
}

/// Verifies a raw signature over an RRset — test support: the real
/// verification story is delv and the synchronicity client's resolver.
pub fn verify_rrset(
  csk: Csk,
  key_tag: Int,
  signer: Name,
  owner: Name,
  rtype: Int,
  ttl: Int,
  rdatas: List(BitArray),
  inception: Int,
  expiration: Int,
  signature: BitArray,
) -> Bool {
  ecdsa_verify_raw(
    signing_input(
      key_tag,
      signer,
      owner,
      rtype,
      ttl,
      rdatas,
      inception,
      expiration,
    ),
    signature,
    csk.public,
  )
}

fn signing_input(
  key_tag: Int,
  signer: Name,
  owner: Name,
  rtype: Int,
  ttl: Int,
  rdatas: List(BitArray),
  inception: Int,
  expiration: Int,
) -> BitArray {
  let pre_rdata =
    rdata.rrsig(
      rtype,
      keys.algorithm,
      list.length(owner),
      ttl,
      expiration,
      inception,
      key_tag,
      signer,
      <<>>,
    )
  let owner_wire = name.encode(owner)
  let rrs =
    rdatas
    |> list.sort(bit_array.compare)
    |> list.map(fn(rd) {
      <<
        owner_wire:bits,
        rtype:int-size(16),
        wire.class_in:int-size(16),
        ttl:int-size(32),
        bit_array.byte_size(rd):int-size(16),
        rd:bits,
      >>
    })
  bit_array.concat([pre_rdata, ..rrs])
}
