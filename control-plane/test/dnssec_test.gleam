import dns/name
import dns/rdata
import dns/wire
import dnssec/keys
import dnssec/sign
import gleam/bit_array
import gleam/list
import gleam/string

@external(erlang, "test_ffi", "tmp_db")
fn tmp_path() -> String

pub fn generate_shapes_test() {
  let csk = keys.generate()
  assert bit_array.byte_size(csk.private) == 32
  assert bit_array.byte_size(csk.public) == 64
  let rd = keys.dnskey_rdata(csk)
  // flags 257, protocol 3, algorithm 13, then the 64-byte point.
  let assert <<1, 1, 3, 13, _:bytes-size(64)>> = rd
  let tag = keys.key_tag(rd)
  assert tag >= 0 && tag <= 0xffff
}

pub fn key_tag_known_vector_test() {
  // Fixed rdata so the fold + carry arithmetic has a pinned answer:
  // bytes 01 01 03 0d ab cd → words 0x0101 0x030d 0xabcd → 0xafdb.
  assert keys.key_tag(<<0x01, 0x01, 0x03, 0x0d, 0xab, 0xcd>>) == 0xafdb
  // Carry case: words 0xffff * 3 = 0x2fffd → + carry 2 → 0xffff.
  assert keys.key_tag(<<0xff, 0xff, 0xff, 0xff, 0xff, 0xff>>) == 0xffff
}

pub fn ds_and_anchor_render_test() {
  let csk = keys.Csk(<<1:size(256)>>, <<2:size(512)>>)
  let assert Ok(apex) = name.parse("sync.example.")
  let ds = keys.ds_line(apex, csk)
  assert string.starts_with(ds, "sync.example. IN DS ")
  assert string.contains(ds, " 13 2 ")
  // digest is 32 bytes → 64 hex chars at the end
  let assert Ok(#(_, hex)) = string.split_once(ds, " 13 2 ")
  assert string.length(hex) == 64
  let anchor = keys.anchor_line(apex, csk)
  assert string.starts_with(anchor, "sync.example. IN DNSKEY 257 3 13 ")
}

pub fn save_load_round_trip_test() {
  let path = tmp_path() <> ".key"
  let csk = keys.generate()
  let assert Ok(Nil) = keys.save(path, csk)
  let assert Ok(loaded) = keys.load(path)
  assert loaded == csk
  // Overwrite is refused: a zone key replacement is a ceremony.
  let assert Error(message) = keys.save(path, keys.generate())
  assert string.contains(message, "refusing")
}

pub fn load_rejects_garbage_test() {
  let assert Error(_) = keys.load("/definitely/not/here")
}

pub fn sign_verify_round_trip_test() {
  let csk = keys.generate()
  let tag = keys.key_tag(keys.dnskey_rdata(csk))
  let assert Ok(signer) = name.parse("sync.example.")
  let assert Ok(owner) = name.parse("_synchronicity.prod.acme.sync.example.")
  let rdatas = [
    rdata.txt("v=sync1 id=nas nk=aaaa"),
    rdata.txt("v=sync1 id=laptop nk=bbbb"),
  ]
  // Sign and verify 8 times: ECDSA signatures are randomized, so this
  // exercises the DER<->raw conversion's leading-zero and high-bit paths.
  list.each([1, 2, 3, 4, 5, 6, 7, 8], fn(_) {
    let rrsig_rr =
      sign.sign_rrset(
        csk,
        tag,
        signer,
        owner,
        wire.type_txt,
        300,
        rdatas,
        1_700_000_000,
        1_700_000_000 + 1_209_600,
      )
    // Pull the 64-byte signature back out of the RRSIG rdata.
    let assert Ok(msg) =
      wire.decode_message(<<
        0:int-size(32),
        0:int-size(16),
        1:int-size(16),
        0:int-size(32),
        rrsig_rr:bits,
      >>)
    let assert [wire.Rr(_, _, _, _, rrsig_rdata)] = msg.answers
    let rdata_size = bit_array.byte_size(rrsig_rdata)
    let assert Ok(signature) = bit_array.slice(rrsig_rdata, rdata_size - 64, 64)
    assert sign.verify_rrset(
      csk,
      tag,
      signer,
      owner,
      wire.type_txt,
      300,
      rdatas,
      1_700_000_000,
      1_700_000_000 + 1_209_600,
      signature,
    )
    // A perturbed message must not verify.
    assert !sign.verify_rrset(
      csk,
      tag,
      signer,
      owner,
      wire.type_txt,
      301,
      rdatas,
      1_700_000_000,
      1_700_000_000 + 1_209_600,
      signature,
    )
  })
}

pub fn rdata_order_independence_test() {
  // Signing input sorts rdatas canonically: the signature over [a, b]
  // verifies against [b, a].
  let csk = keys.generate()
  let tag = keys.key_tag(keys.dnskey_rdata(csk))
  let assert Ok(signer) = name.parse("z.example.")
  let assert Ok(owner) = name.parse("x.z.example.")
  let a = rdata.txt("aaa")
  let b = rdata.txt("bbb")
  let rrsig_rr =
    sign.sign_rrset(csk, tag, signer, owner, wire.type_txt, 60, [a, b], 0, 100)
  let size = bit_array.byte_size(rrsig_rr)
  let assert Ok(signature) = bit_array.slice(rrsig_rr, size - 64, 64)
  assert sign.verify_rrset(
    csk,
    tag,
    signer,
    owner,
    wire.type_txt,
    60,
    [b, a],
    0,
    100,
    signature,
  )
}
