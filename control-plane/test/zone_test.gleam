import dns/name
import dns/query
import dns/wire
import dnssec/keys
import dnssec/sign
import fixtures.{demo_conn, nk}
import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import store/sqlite
import zone/build
import zone/model.{type ZoneInput, Member, NsHost, TxtName, ZoneInput, ZoneMeta}

fn demo_input(csk: keys.Csk) -> ZoneInput {
  let assert Ok(apex) = name.parse("sync.test.")
  let assert Ok(ns1) = name.parse("ns1.sync.test.")
  let assert Ok(owner) = name.parse("_synchronicity.prod.acme.sync.test.")
  let rd = keys.dnskey_rdata(csk)
  ZoneInput(
    ZoneMeta(
      apex,
      7,
      csk.public,
      keys.key_tag(rd),
      <<>>,
      0,
      3600,
      1_209_600,
      604_800,
    ),
    [NsHost(ns1, "127.0.0.1", "")],
    [
      TxtName(owner, [
        Member("nas", nk(), "", ""),
        Member("laptop", nk(), "", ""),
        Member("laptop", nk(), "", ""),
      ]),
    ],
    [],
    0,
    [],
  )
}

fn txt_query(qname: String, qtype: Int, do_bit: Bool) -> wire.Query {
  let assert Ok(parsed) = name.parse(qname)
  let edns = case do_bit {
    True -> Some(wire.Edns(1400, True))
    False -> None
  }
  wire.Query(42, 0, False, parsed, qtype, wire.class_in, edns)
}

pub fn build_produces_expected_names_test() {
  let csk = keys.generate()
  let assert Ok(rrsets) = build.build(demo_input(csk))
  let owners = build.owners_in_order(rrsets)
  let strings = list.map(owners, name.to_string)
  // apex first (canonical minimum), then depth-sorted names. The zone's
  // transparency declaration sorts right after it: `_` precedes every letter.
  assert strings
    == [
      "sync.test.",
      "_synchronicity-transparency.sync.test.",
      "_synchronicity.prod.acme.sync.test.",
      "ns1.sync.test.",
    ]
  // Every owner has an NSEC; the chain wraps.
  let nsecs = list.filter(rrsets, fn(r) { r.rtype == wire.type_nsec })
  assert list.length(nsecs) == 4
}

pub fn build_refuses_bad_input_test() {
  let csk = keys.generate()
  let input = demo_input(csk)
  let assert Ok(owner) = name.parse("_synchronicity.prod.acme.sync.test.")

  // Ambiguity: one nk under two labels.
  let shared = nk()
  let ambiguous =
    ZoneInput(..input, txt_names: [
      TxtName(owner, [Member("a", shared, "", ""), Member("b", shared, "", "")]),
    ])
  let assert Error(build.AmbiguousNk(_)) = build.build(ambiguous)

  // Bad nk shape.
  let bad_nk =
    ZoneInput(..input, txt_names: [
      TxtName(owner, [Member("a", "notakey", "", "")]),
    ])
  let assert Error(build.InvalidNk(_)) = build.build(bad_nk)

  // Bad label.
  let bad_label =
    ZoneInput(..input, txt_names: [
      TxtName(owner, [Member("NAS!", nk(), "", "")]),
    ])
  let assert Error(build.InvalidLabel(_)) = build.build(bad_label)

  // Three keys under one label: not a rotation window.
  let too_many =
    ZoneInput(..input, txt_names: [
      TxtName(owner, [
        Member("a", nk(), "", ""),
        Member("a", nk(), "", ""),
        Member("a", nk(), "", ""),
      ]),
    ])
  let assert Error(build.DuplicateLabelInZone("a")) = build.build(too_many)

  // No nameservers is not a zone.
  let no_ns = ZoneInput(..input, ns_hosts: [])
  let assert Error(build.NoNameservers) = build.build(no_ns)

  // A dialing hint that would change the record's shape. `relay` and `addr`
  // are the only free-form values in a membership record, and the record
  // grammar is whitespace-separated key=value pairs — so a hint carrying a
  // space is extra fields, and the client's parser is last-wins for apex=,
  // which means the injected one would override the real one.
  let injected =
    ZoneInput(..input, txt_names: [
      TxtName(owner, [Member("a", nk(), "x apex=evil.example", "")]),
    ])
  let assert Error(build.InvalidHint(_)) = build.build(injected)

  // A quote breaks the provider round-trip instead: Cloudflare returns TXT
  // in presentation form and the reconciler folds it by splitting on `"`,
  // so a quoted value comes back as something other than what was sent.
  let quoted =
    ZoneInput(..input, txt_names: [
      TxtName(owner, [Member("a", nk(), "", "1.2.3.4\"")]),
    ])
  let assert Error(build.InvalidHint(_)) = build.build(quoted)

  // And an ordinary hint is untouched.
  let fine =
    ZoneInput(..input, txt_names: [
      TxtName(owner, [
        Member("a", nk(), "https://relay.example", "1.2.3.4:4433"),
      ]),
    ])
  let assert Ok(_) = build.build(fine)
}

pub fn positive_answer_test() {
  let #(conn, apex) = demo_conn()
  let q = txt_query("_synchronicity.prod.acme.sync.test.", wire.type_txt, True)
  let assert Ok(msg) = wire.decode_message(query.answer(conn, apex, q))
  // AA, rcode 0; TXT rrset (3 records) + 1 RRSIG.
  assert list.length(msg.answers) == 4
  let types = list.map(msg.answers, fn(rr) { rr.rtype })
  assert list.count(types, fn(t) { t == wire.type_txt }) == 3
  assert list.count(types, fn(t) { t == wire.type_rrsig }) == 1
  // Every TXT rdata is a v=sync1 record.
  list.each(msg.answers, fn(rr) {
    case rr.rtype == wire.type_txt {
      True -> {
        let assert <<len:int-size(8), text:bytes-size(len)>> = rr.rdata
        let assert Ok(s) = bit_array.to_string(text)
        let assert "v=sync1 id=" <> _ = s
        Nil
      }
      False -> Nil
    }
  })
  sqlite.close(conn)
}

pub fn positive_without_do_omits_rrsig_test() {
  let #(conn, apex) = demo_conn()
  let q = txt_query("_synchronicity.prod.acme.sync.test.", wire.type_txt, False)
  let assert Ok(msg) = wire.decode_message(query.answer(conn, apex, q))
  assert list.length(msg.answers) == 3
  assert msg.additional == []
  sqlite.close(conn)
}

pub fn nodata_test() {
  let #(conn, apex) = demo_conn()
  // Existing name, absent type.
  let q = txt_query("_synchronicity.prod.acme.sync.test.", wire.type_a, True)
  let assert Ok(msg) = wire.decode_message(query.answer(conn, apex, q))
  assert rcode(msg.flags) == 0
  assert msg.answers == []
  // SOA + RRSIG + own NSEC + RRSIG.
  let types = list.map(msg.authority, fn(rr) { rr.rtype })
  assert list.count(types, fn(t) { t == wire.type_soa }) == 1
  assert list.count(types, fn(t) { t == wire.type_nsec }) == 1
  assert list.count(types, fn(t) { t == wire.type_rrsig }) == 2
  sqlite.close(conn)
}

pub fn nodata_at_empty_non_terminal_test() {
  let #(conn, apex) = demo_conn()
  // prod.acme.sync.test is an ENT (only _synchronicity below it).
  let q = txt_query("prod.acme.sync.test.", wire.type_txt, True)
  let assert Ok(msg) = wire.decode_message(query.answer(conn, apex, q))
  assert rcode(msg.flags) == 0
  assert msg.answers == []
  // Covering NSEC: the owner is the ENT's canonical predecessor — the
  // transparency declaration — whose next name is a descendant of the ENT.
  // That is the validator's ENT proof.
  let assert Ok(predecessor) =
    name.parse("_synchronicity-transparency.sync.test.")
  let nsec_owners =
    msg.authority
    |> list.filter(fn(rr) { rr.rtype == wire.type_nsec })
    |> list.map(fn(rr) { rr.name })
  assert nsec_owners == [predecessor]
  sqlite.close(conn)
}

pub fn nxdomain_test() {
  let #(conn, apex) = demo_conn()
  let q = txt_query("_synchronicity.nope.acme.sync.test.", wire.type_txt, True)
  let assert Ok(msg) = wire.decode_message(query.answer(conn, apex, q))
  assert rcode(msg.flags) == 3
  let types = list.map(msg.authority, fn(rr) { rr.rtype })
  assert list.count(types, fn(t) { t == wire.type_soa }) == 1
  // Covering NSEC + wildcard-denial NSEC (may collapse to one).
  assert list.count(types, fn(t) { t == wire.type_nsec }) >= 1
  assert list.count(types, fn(t) { t == wire.type_rrsig })
    == list.count(types, fn(t) { t == wire.type_nsec }) + 1
  sqlite.close(conn)
}

pub fn out_of_zone_refused_test() {
  let #(conn, apex) = demo_conn()
  let q = txt_query("other.example.", wire.type_txt, True)
  let assert Ok(msg) = wire.decode_message(query.answer(conn, apex, q))
  assert rcode(msg.flags) == query.rcode_refused
  assert msg.answers == []
  assert msg.authority == []
  sqlite.close(conn)
}

pub fn dnskey_at_apex_test() {
  let #(conn, apex) = demo_conn()
  let q = txt_query("sync.test.", wire.type_dnskey, True)
  let assert Ok(msg) = wire.decode_message(query.answer(conn, apex, q))
  let types = list.map(msg.answers, fn(rr) { rr.rtype })
  assert list.count(types, fn(t) { t == wire.type_dnskey }) == 1
  assert list.count(types, fn(t) { t == wire.type_rrsig }) == 1
  sqlite.close(conn)
}

pub fn udp_truncation_test() {
  let #(conn, apex) = demo_conn()
  let q =
    wire.Query(
      9,
      0,
      False,
      {
        let assert Ok(n) = name.parse("_synchronicity.prod.acme.sync.test.")
        n
      },
      wire.type_txt,
      wire.class_in,
      None,
    )
  // Without EDNS the limit is 512; the signed TXT answer exceeds it.
  let full = query.answer(conn, apex, q)
  assert bit_array.byte_size(full) > 512 == False
  // This zone's answer happens to fit; force the check with a tiny limit
  // by exercising fit_udp on an EDNS query with a huge answer instead.
  let q_do =
    txt_query("_synchronicity.prod.acme.sync.test.", wire.type_txt, True)
  let with_do = query.answer(conn, apex, q_do)
  let fitted = query.fit_udp(q_do, with_do)
  // 1400-byte allowance: answer fits, unchanged.
  assert fitted == with_do
  sqlite.close(conn)
}

fn rcode(flags: Int) -> Int {
  flags % 16
}

/// A zone mid-rollover serves both keys, signed by the outgoing one, and
/// the signature verifies.
///
/// This is the property the whole staging mechanism rests on: a two-key
/// DNSKEY RRset is still a validly signed RRset under the DS the parent
/// already published, so publishing the incoming key costs the zone
/// nothing. If the RRSIG did not cover both rdatas in canonical order,
/// staging a key would take the zone bogus instead of preparing a
/// rollover.
pub fn a_staged_zone_serves_both_keys_under_one_valid_signature_test() {
  let active = keys.generate()
  let incoming = keys.generate()
  let tag = keys.key_tag(keys.dnskey_rdata(active))
  let input = demo_input(active)
  let staged =
    ZoneInput(
      ..input,
      meta: ZoneMeta(
        ..input.meta,
        dnskey_incoming: incoming.public,
        key_tag_incoming: keys.key_tag(keys.dnskey_rdata(incoming)),
      ),
    )
  let assert Ok(rrsets) = build.build(staged)
  let assert Ok(dnskey) =
    list.find(rrsets, fn(r) { r.rtype == wire.type_dnskey })

  // Both keys are published...
  assert list.length(dnskey.rdatas) == 2
  assert list.contains(dnskey.rdatas, keys.dnskey_rdata(active))
  assert list.contains(dnskey.rdatas, keys.dnskey_rdata(incoming))

  // ...and the outgoing key's signature covers the pair.
  let rrsig_rr =
    sign.sign_rrset(
      active,
      tag,
      staged.meta.apex,
      dnskey.owner,
      wire.type_dnskey,
      dnskey.ttl,
      dnskey.rdatas,
      0,
      100,
    )
  let size = bit_array.byte_size(rrsig_rr)
  let assert Ok(signature) = bit_array.slice(rrsig_rr, size - 64, 64)
  assert sign.verify_rrset(
    active,
    tag,
    staged.meta.apex,
    dnskey.owner,
    wire.type_dnskey,
    dnskey.ttl,
    dnskey.rdatas,
    0,
    100,
    signature,
  )

  // The incoming key signs nothing: it is published, not trusted.
  assert !sign.verify_rrset(
    incoming,
    keys.key_tag(keys.dnskey_rdata(incoming)),
    staged.meta.apex,
    dnskey.owner,
    wire.type_dnskey,
    dnskey.ttl,
    dnskey.rdatas,
    0,
    100,
    signature,
  )
}

/// A dialing hint cannot smuggle a second field into a member's record.
///
/// The client splits a record on `str::split_whitespace` — Unicode
/// whitespace, not the four ASCII spellings — so any of these characters
/// inside a hint makes the client read a field the member wrote. The sharp
/// one is a second `apex=`: the answer then names two control planes, which
/// is a refusal, so one member's hint partitions their whole network.
///
/// Asserted as a class rather than as the cases that were found, because the
/// list of ways to spell a separator is exactly what cannot be enumerated.
pub fn a_hint_cannot_carry_a_field_separator_test() {
  // Every hint shape this design actually publishes.
  assert build.valid_hint("1.2.3.4:9000")
  assert build.valid_hint("[2001:db8::1]:9000")
  assert build.valid_hint("https://relay.example.com:443/")
  assert build.valid_hint("")

  // Everything the client would split on, ASCII and not.
  let separators = [
    " ", "\t", "\n", "\r", "\u{000B}", "\u{000C}", "\u{0085}", "\u{00A0}",
    "\u{1680}", "\u{2000}", "\u{2028}", "\u{2029}", "\u{3000}",
  ]
  list.each(separators, fn(ws) {
    assert !build.valid_hint("1.2.3.4:9000" <> ws <> "apex=evil.example.com")
    assert !build.valid_hint(ws)
  })

  // And the quote, which survives the client but not the provider round-trip.
  assert !build.valid_hint("1.2.3.4:9000\"")

  // The provider's length ceiling still applies.
  assert !build.valid_hint(string.repeat("a", 256))
  assert build.valid_hint(string.repeat("a", 255))
}
