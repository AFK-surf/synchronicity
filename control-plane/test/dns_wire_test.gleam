import dns/name
import dns/query
import dns/rdata
import dns/wire
import gleam/bit_array
import gleam/option.{None, Some}
import gleam/order

pub fn name_parse_and_encode_test() {
  let assert Ok(n) = name.parse("_synchronicity.Prod.ACME.example.COM.")
  assert n == ["_synchronicity", "prod", "acme", "example", "com"]
  assert name.to_string(n) == "_synchronicity.prod.acme.example.com."
  assert name.encode(["ab", "c"]) == <<2, "ab":utf8, 1, "c":utf8, 0>>
  assert name.encode([]) == <<0>>
  let assert Error(Nil) = name.parse("bad..name")
  let assert Error(Nil) = name.parse("no spaces")
}

pub fn canonical_name_order_test() {
  // RFC 4034 §6.1's example ordering.
  let assert Ok(example) = name.parse("example.")
  let assert Ok(a) = name.parse("a.example.")
  let assert Ok(yljkjljk) = name.parse("yljkjljk.a.example.")
  let assert Ok(z_a) = name.parse("z.a.example.")
  let assert Ok(zabc) = name.parse("zabc.a-domain.example.")
  let assert Ok(z_example) = name.parse("z.example.")
  assert name.compare(example, a) == order.Lt
  assert name.compare(a, yljkjljk) == order.Lt
  assert name.compare(yljkjljk, z_a) == order.Lt
  assert name.compare(z_a, zabc) == order.Lt
  assert name.compare(zabc, z_example) == order.Lt
  assert name.compare(z_example, z_example) == order.Eq
  assert name.compare(z_example, example) == order.Gt
}

pub fn in_zone_test() {
  let assert Ok(apex) = name.parse("acme.example.")
  let assert Ok(inside) = name.parse("_synchronicity.prod.acme.example.")
  let assert Ok(outside) = name.parse("other.example.")
  assert name.in_zone(apex, apex)
  assert name.in_zone(inside, apex)
  assert !name.in_zone(outside, apex)
  assert !name.in_zone(apex, inside)
}

pub fn decode_query_test() {
  // Hand-built query: id 0x1234, RD, one question TXT IN for a.bc.,
  // with an OPT advertising 1232 bytes and DO=1.
  let question = <<
    1,
    "a":utf8,
    2,
    "bc":utf8,
    0,
    16:int-size(16),
    1:int-size(16),
  >>
  let opt = <<
    0,
    41:int-size(16),
    1232:int-size(16),
    0,
    0,
    1:int-size(1),
    0:int-size(15),
    0:int-size(16),
  >>
  let msg = <<
    0x1234:int-size(16), 0x0100:int-size(16), 1:int-size(16), 0:int-size(16),
    0:int-size(16), 1:int-size(16), question:bits, opt:bits,
  >>
  let assert Ok(q) = wire.decode_query(msg)
  assert q.id == 0x1234
  assert q.rd == True
  assert q.qname == ["a", "bc"]
  assert q.qtype == wire.type_txt
  assert q.edns == Some(wire.Edns(1232, True))
}

pub fn decode_query_no_edns_test() {
  let question = <<1, "a":utf8, 0, 1:int-size(16), 1:int-size(16)>>
  let msg = <<
    7:int-size(16), 0:int-size(16), 1:int-size(16), 0:int-size(16),
    0:int-size(16), 0:int-size(16), question:bits,
  >>
  let assert Ok(q) = wire.decode_query(msg)
  assert q.edns == None
  assert q.rd == False
}

pub fn decode_query_rejects_response_test() {
  let question = <<1, "a":utf8, 0, 1:int-size(16), 1:int-size(16)>>
  let msg = <<
    7:int-size(16), 0x8000:int-size(16), 1:int-size(16), 0:int-size(16),
    0:int-size(16), 0:int-size(16), question:bits,
  >>
  let assert Error(wire.Unsupported(7)) = wire.decode_query(msg)
}

pub fn compressed_name_decode_test() {
  // "bc." at offset 12; at offset 16 the name "a." + pointer to 12.
  let msg = <<
    0:int-size(96),
    // offset 12: bc.
    2, "bc":utf8, 0,
    // offset 16: a + pointer -> 12
    1, "a":utf8, 3:int-size(2), 12:int-size(14),
  >>
  let assert Ok(#(labels, next)) = wire.decode_name(msg, 16, 0)
  assert labels == ["a", "bc"]
  assert next == 20
  // Forward pointers are refused (loop prevention).
  let bad = <<0:int-size(96), 3:int-size(2), 200:int-size(14)>>
  let assert Error(Nil) = wire.decode_name(bad, 12, 0)
}

pub fn uppercase_names_lowered_on_decode_test() {
  let msg = <<0:int-size(96), 2, "AB":utf8, 0>>
  let assert Ok(#(labels, _)) = wire.decode_name(msg, 12, 0)
  assert labels == ["ab"]
}

pub fn type_bitmap_test() {
  // TXT(16) RRSIG(46) NSEC(47): window 0, 6 bytes, per RFC 4034 §4.1.2.
  assert rdata.type_bitmap([wire.type_txt, wire.type_rrsig, wire.type_nsec])
    == <<0, 6, 0, 0, 0x80, 0, 0, 0x03>>
  // A(1) alone: window 0, 1 byte, bit 1 → 0x40.
  assert rdata.type_bitmap([wire.type_a]) == <<0, 1, 0x40>>
  // A high type (TYPE1234 = window 4, byte 26, 1234%8=2 → 0x20).
  assert rdata.type_bitmap([1234]) == <<4, 27, 0:size(208), 0x20>>
}

pub fn txt_chunking_test() {
  let short = rdata.txt("v=sync1 id=nas nk=abc")
  assert short == <<21, "v=sync1 id=nas nk=abc":utf8>>
  // A 300-byte string splits into 255 + 45.
  let long = string_repeat("x", 300)
  let assert <<255, _:bytes-size(255), 45, _:bytes-size(45)>> = rdata.txt(long)
}

fn string_repeat(s: String, times: Int) -> String {
  case times {
    0 -> ""
    _ -> s <> string_repeat(s, times - 1)
  }
}

pub fn rr_and_count_test() {
  let assert Ok(owner) = name.parse("a.example.")
  let one = rdata.rr(owner, wire.type_txt, 300, rdata.txt("hello"))
  let two = bit_array.concat([one, one])
  let assert Ok(1) = wire.count_rrs(one)
  let assert Ok(2) = wire.count_rrs(two)
  let assert Ok(0) = wire.count_rrs(<<>>)
  let assert Error(Nil) = wire.count_rrs(<<1, 2, 3>>)
}

pub fn response_round_trip_test() {
  let assert Ok(qname) = name.parse("_synchronicity.prod.acme.example.")
  let query =
    wire.Query(
      0xbeef,
      0,
      True,
      qname,
      wire.type_txt,
      wire.class_in,
      Some(wire.Edns(1400, True)),
    )
  let answer_rr = rdata.rr(qname, wire.type_txt, 300, rdata.txt("v=sync1"))
  let answers = wire.Section(answer_rr, 1)
  let resp =
    wire.encode_response(
      query,
      0,
      True,
      False,
      answers,
      wire.empty_section(),
      rdata.opt(query.advertised_udp_size, True),
    )
  let assert Ok(msg) = wire.decode_message(resp)
  assert msg.id == 0xbeef
  assert msg.questions == [#(qname, wire.type_txt, wire.class_in)]
  let assert [rr] = msg.answers
  assert rr.name == qname
  assert rr.rtype == wire.type_txt
  assert rr.ttl == 300
  let assert [opt_rr] = msg.additional
  assert opt_rr.rtype == wire.type_opt
  // AA bit set, QR set, rcode 0.
  assert msg.flags == 0x8500
}

pub fn address_parse_test() {
  let assert Ok(#(t4, <<192, 0, 2, 1>>)) = rdata.address("192.0.2.1")
  assert t4 == wire.type_a
  let assert Ok(#(t6, bytes)) = rdata.address("2001:db8::1")
  assert t6 == wire.type_aaaa
  assert bit_array.byte_size(bytes) == 16
  let assert Error(Nil) = rdata.address("not-an-ip")
}

pub fn sync1_text_test() {
  assert rdata.sync1_text("nas", "abc123", "", "") == "v=sync1 id=nas nk=abc123"
  assert rdata.sync1_text("nas", "abc123", "https://r.example", "1.2.3.4:5")
    == "v=sync1 id=nas nk=abc123 relay=https://r.example addr=1.2.3.4:5"
}
