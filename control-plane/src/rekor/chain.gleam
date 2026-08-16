//// Collecting the DNSSEC chain a zone-key entry carries
//// (docs/REKOR-ZONE-KEY.md §2, §5.2).
////
//// The chain is what makes a log entry *classifiable*: from it alone, with
//// no DNS query and no cooperation from the zone, a monitor can decide
//// whether the key an entry names was actually delegated. That is why the
//// client refuses an entry without one — not for its own sake (it validated
//// the delegation natively long before) but so that an entry a monitor would
//// file as silent noise can never be an entry a client accepts.
////
//// Which forces the publish ordering (§5.2): a chain can only be built once
//// the **DS is live in the parent**, so logging moves to *after* the DS is
//// in place rather than before. The existing two-key rollover window covers
//// the gap — the old key keeps signing until the new one is logged.
////
//// The collection itself is ordinary recursive DNS work, done over DoH
//// against a configurable resolver, one RRset at a time:
////
////   link 0    _synchronicity-transparency.<apex>
////                       TXT + RRSIG           the zone's declaration,
////                                             signed by the apex
////   link 1    <apex>    DNSKEY + RRSIG        the claimed key set, proved
////                       DS + RRSIG            by the parent-signed DS
////   link i    <zone>    DNSKEY + RRSIG        self-signed
////                       DS + RRSIG            signed by *its* parent
////   link n    .         DNSKEY + RRSIG        the root, terminated by the
////                                             IANA trust anchor a reader
////                                             already holds
////
//// The apex link carries its own DNSKEY RRset because the RRset *is* the
//// claim: the walk proves DS → covered key → RRset, and a reader checks the
//// key that signed an answer for membership. A split-key zone's DS never
//// names the signing ZSK, and this is how DNSSEC itself authorizes it.
////
//// The chain starts one label *below* the apex, at the declaration, because
//// everything above it is public: any passer-by can read a zone's DNSKEY and
//// DS records out of an open resolver, so a chain that began at the apex
//// would be evidence anybody could assemble about anybody's zone. The
//// declaration is the part that takes write access to the zone, which is the
//// authority the entry claims to speak with — and it takes no *key* access,
//// so a zone whose DNSSEC keys live inside a managed provider publishes one
//// with an ordinary record write.
////
//// Nothing here validates anything. The resolver's answers are copied into
//// the certificate verbatim and every reader — client and monitor alike —
//// checks the signatures itself. A lying resolver therefore produces an
//// entry that fails validation everywhere, which is a publish that gets
//// refused, not a proof anybody accepts.

import dns/name.{type Name}
import dns/rdata
import dns/wire
import envoy
import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/list
import gleam/result
import gleam/string

/// DS is not among the types the serving path emits, so it is not in
/// `dns/wire`'s list; the chain is the one place this service reads one.
pub const type_ds = 43

/// The DoH resolver the chain is collected from (`CP_DNSSEC_CHAIN_RESOLVER`).
///
/// A public resolver by default, because this is not a trust decision: the
/// bytes it returns are signed by the zones that own them and are verified
/// by every reader of the resulting entry. Point it at your own validating
/// resolver if you would rather not tell Cloudflare when you rotate keys.
pub fn resolver_url() -> String {
  envoy.get("CP_DNSSEC_CHAIN_RESOLVER")
  |> result.unwrap("https://cloudflare-dns.com/dns-query")
}

/// A resolver, as the one operation this needs: ask for `<name> <type>`
/// with DNSSEC records, get the answer section's RRs back.
///
/// Injected rather than hardwired so the whole collector is testable with no
/// egress — and so no test run ever reaches out to a public resolver by
/// accident.
pub type Resolver {
  Resolver(query: fn(Name, Int) -> Result(List(wire.Rr), String))
}

/// One link of the chain, ready for `rekor/cert`.
pub type Link {
  Link(zone: String, rrs: BitArray)
}

/// Collects the chain for `apex`: the zone's declaration, then its own
/// DNSKEY RRset and DS, then up to the root — and returns the apex DNSKEY
/// rdatas beside the links, because that observed RRset is exactly the key
/// set the resulting entry claims.
///
/// Fails rather than returning a short chain: an entry with half a chain is
/// an entry every reader rejects, and finding that out at publish time —
/// where an operator is standing there reading the error — is worth much
/// more than finding it out later from a client that will not resolve. That
/// includes the declaration: a zone that has not published one yet cannot
/// log, and says so here rather than logging something no client accepts.
pub fn collect(
  resolver: Resolver,
  apex: Name,
) -> Result(#(List(Link), List(BitArray)), String) {
  let labels = name.to_string(apex) |> string.split(".") |> drop_empty
  use declaration <- result.try(declaration_link(resolver, apex))
  use #(apex_link, rdatas) <- result.try(apex_link(resolver, apex))
  use ancestors <- result.try(ancestor_links(resolver, labels, []))
  Ok(#([declaration, apex_link, ..ancestors], rdatas))
}

/// The bottom link: the apex's own `_synchronicity-transparency` TXT RRset
/// and the RRSIG it made over it.
fn declaration_link(resolver: Resolver, apex: Name) -> Result(Link, String) {
  let owner = [rdata.transparency_label, ..apex]
  use rrs <- result.try(rrset(resolver, owner, wire.type_txt))
  Ok(Link(name.to_string(owner), rrs))
}

/// Walks a chain's *shape*, the way a reader will walk its signatures.
///
/// This service cannot check the cryptography — the RRSIG walk lives in
/// crates/synch-net/src/chain.rs and every client and monitor runs it — but
/// it can check the thing that is cheap to get wrong and impossible to notice
/// afterwards: that the links form an unbroken ladder from the apex to the
/// **root**, and that each carries the RRsets its position requires.
///
/// It exists because a configuration knob once let this service publish a
/// chain that stopped at the TLD. Nothing here refused it — the code checked
/// only that the extension was *present* — so `rekor-publish` reported
/// success and then every client failed closed against an entry no reader
/// could anchor. A publish that cannot be verified is a publish that must
/// fail here, loudly, while an operator is still watching.
pub fn check_shape(links: List(Link), apex: Name) -> Result(Nil, String) {
  let declared_at = name.to_string([rdata.transparency_label, ..apex])
  let apex_text = name.to_string(apex)
  case links {
    [] | [_] ->
      Error("the chain is too short to carry a declaration and an apex")
    [declaration, ..ladder] ->
      case declaration.zone == declared_at, ladder {
        False, _ ->
          Error(
            "the chain starts at "
            <> declaration.zone
            <> ", not the declaration at "
            <> declared_at,
          )
        True, [first, ..] if first.zone != apex_text ->
          Error(
            "the chain's second link is "
            <> first.zone
            <> ", not the apex "
            <> apex_text,
          )
        True, _ -> check_ladder(ladder, apex)
      }
  }
}

fn check_ladder(links: List(Link), below: Name) -> Result(Nil, String) {
  case links {
    [] -> Error("the chain has no links")
    // The top of a well-formed chain is the root, whose DNSKEY the IANA
    // trust anchor terminates. Anything else is a chain that anchors nowhere.
    [last] ->
      case last.zone == "." {
        True -> Ok(Nil)
        False ->
          Error(
            "the chain stops at "
            <> last.zone
            <> " instead of the root, so no reader can anchor it",
          )
      }
    [_, next, ..rest] -> {
      let parent = parent_of(below)
      case next.zone == name.to_string(parent) {
        False ->
          Error(
            "the chain jumps from "
            <> name.to_string(below)
            <> " to "
            <> next.zone
            <> ", which is not its parent",
          )
        True -> check_ladder([next, ..rest], parent)
      }
    }
  }
}

fn parent_of(zone: Name) -> Name {
  case zone {
    [] -> []
    [_, ..rest] -> rest
  }
}

/// The apex's own link: its DNSKEY RRset (the claimed set) and its DS RRset,
/// each with the RRSIGs a reader's walk verifies. The DNSKEY rdatas come
/// back separately, so the publish path claims exactly what it observed.
fn apex_link(
  resolver: Resolver,
  apex: Name,
) -> Result(#(Link, List(BitArray)), String) {
  use keys_answers <- result.try(resolver.query(apex, wire.type_dnskey))
  use keys_rrs <- result.try(rrset_of(keys_answers, apex, wire.type_dnskey))
  let rdatas =
    keys_answers
    |> list.filter(fn(rr) {
      rr.rtype == wire.type_dnskey && rr.class == wire.class_in
    })
    |> list.map(fn(rr) { rr.rdata })
  use ds <- result.try(rrset(resolver, apex, type_ds))
  Ok(#(Link(name.to_string(apex), bit_array.concat([keys_rrs, ds])), rdatas))
}

fn ancestor_links(
  resolver: Resolver,
  labels: List(String),
  acc: List(Link),
) -> Result(List(Link), String) {
  case labels {
    [] | [_] -> {
      // The next zone up is the root: DNSKEY only, since the root has no DS.
      // Always included, and not worth making optional to save its ~1.1 KB:
      // a chain that stops below the root anchors against nothing a reader
      // holds, so every client would refuse the entry. A switch whose only
      // effect is to break verification is not a trade-off.
      use root <- result.try(name.parse(".") |> replace_error("."))
      use rrs <- result.try(rrset(resolver, root, wire.type_dnskey))
      Ok(list.reverse([Link(".", rrs), ..acc]))
    }
    [_, ..rest] -> {
      let text = string.join(rest, ".") <> "."
      use zone <- result.try(name.parse(text) |> replace_error(text))
      use keys <- result.try(rrset(resolver, zone, wire.type_dnskey))
      use ds <- result.try(rrset(resolver, zone, type_ds))
      ancestor_links(resolver, rest, [
        Link(text, bit_array.concat([keys, ds])),
        ..acc
      ])
    }
  }
}

/// One RRset plus its RRSIGs, re-emitted as uncompressed wire RRs.
///
/// Re-emitted rather than sliced out of the response: a resolver may
/// compress owner names against the question, and a Merkle leaf has no
/// message for a pointer to point into.
fn rrset(
  resolver: Resolver,
  zone: Name,
  rtype: Int,
) -> Result(BitArray, String) {
  use answers <- result.try(resolver.query(zone, rtype))
  rrset_of(answers, zone, rtype)
}

/// The filtering/validation/encoding half of `rrset`, over answers already
/// in hand — the apex link fetches DNSKEYs once and needs both the wire run
/// and the raw rdatas.
fn rrset_of(
  answers: List(wire.Rr),
  zone: Name,
  rtype: Int,
) -> Result(BitArray, String) {
  let wanted =
    list.filter(answers, fn(rr) {
      rr.class == wire.class_in
      && case rr.rtype {
        t if t == rtype -> True
        t if t == wire.type_rrsig -> covers(rr.rdata, rtype)
        _ -> False
      }
    })
  let has = fn(t) { list.any(wanted, fn(rr) { rr.rtype == t }) }
  case has(rtype), has(wire.type_rrsig) {
    False, _ ->
      Error(
        "no "
        <> type_name(rtype)
        <> " RRset at "
        <> name.to_string(zone)
        <> " — is the DS live in the parent yet?",
      )
    _, False ->
      Error(
        "the "
        <> type_name(rtype)
        <> " RRset at "
        <> name.to_string(zone)
        <> " carries no RRSIG",
      )
    True, True ->
      Ok(
        wanted
        |> list.map(fn(rr) { rdata.rr(rr.name, rr.rtype, rr.ttl, rr.rdata) })
        |> bit_array.concat,
      )
  }
}

fn covers(rrsig_rdata: BitArray, rtype: Int) -> Bool {
  case rrsig_rdata {
    <<covered:int-size(16), _:bits>> -> covered == rtype
    _ -> False
  }
}

fn type_name(rtype: Int) -> String {
  case rtype {
    48 -> "DNSKEY"
    43 -> "DS"
    other -> int.to_string(other)
  }
}

fn drop_empty(labels: List(String)) -> List(String) {
  list.filter(labels, fn(label) { label != "" })
}

fn replace_error(result: Result(a, Nil), what: String) -> Result(a, String) {
  result.replace_error(result, what <> " is not a DNS name")
}

// ------------------------------------------------------------------- DoH

/// The RFC 8484 resolver at `url`: `POST` a wire-format query with the DO
/// bit set, read the answer section back.
pub fn doh(url: String) -> Resolver {
  Resolver(query: fn(zone, rtype) { doh_query(url, zone, rtype) })
}

fn doh_query(
  url: String,
  zone: Name,
  rtype: Int,
) -> Result(List(wire.Rr), String) {
  let question =
    bit_array.concat([
      // id 0, RD set, one question, one additional (the OPT).
      <<
        0:int-size(16),
        0x0100:int-size(16),
        1:int-size(16),
        0:int-size(16),
        0:int-size(16),
        1:int-size(16),
      >>,
      name.encode(zone),
      <<rtype:int-size(16), { wire.class_in }:int-size(16)>>,
      { rdata.opt(4096, True) }.wire,
    ])
  use req <- result.try(
    request.to(url) |> result.replace_error("bad resolver URL " <> url),
  )
  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/dns-message")
    |> request.set_header("accept", "application/dns-message")
    |> request.set_body(question)
  use resp <- result.try(
    httpc.send_bits(req)
    |> result.map_error(fn(e) { url <> " unreachable: " <> string.inspect(e) }),
  )
  case resp.status {
    200 ->
      case wire.decode_message(resp.body) {
        Ok(message) -> Ok(message.answers)
        Error(Nil) -> Error(url <> " returned a message that does not decode")
      }
    status -> Error(url <> " answered " <> int.to_string(status))
  }
}
