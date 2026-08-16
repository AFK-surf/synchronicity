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
////   link 0    <apex>    DS + RRSIG            signed by the parent
////   link i    <zone>    DNSKEY + RRSIG        self-signed
////                       DS + RRSIG            signed by *its* parent
////   link n    .         DNSKEY + RRSIG        the root, terminated by the
////                                             IANA trust anchor a reader
////                                             already holds
////
//// Nothing here validates anything, and nothing here encodes anything. The
//// resolver's answers are handed to the `synch-rekor` port program as they
//// arrived, and it walks them — the same cryptographic walk every client and
//// every monitor runs, against the same trust anchor — *before* it builds a
//// certificate around them. So a lying resolver produces a publish that
//// fails at the terminal rather than an entry nobody can anchor: this used
//// to be a shape check that could only see whether the ladder reached the
//// root, and a chain that stopped at the TLD once got past it into the log.

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
import rekor/port

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

/// The trust anchor a collected chain is walked against
/// (`CP_DNSSEC_ANCHOR`), or `""` for the IANA root.
///
/// The root is what a public zone is delegated under and therefore what every
/// monitor will use, so overriding it is a claim that your readers live in a
/// different universe — the same semantics, and the same file syntax, as the
/// client's `--dnssec-anchor`. It exists for a privately rooted deployment
/// and for tests; a zone under the real DNS wants it unset.
pub fn anchor_file() -> String {
  envoy.get("CP_DNSSEC_ANCHOR") |> result.unwrap("")
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

/// Collects the chain for `apex`, from its own DS up to the root.
///
/// Fails rather than returning a short chain: an entry with half a chain is
/// an entry every reader rejects, and finding that out at publish time —
/// where an operator is standing there reading the error — is worth much
/// more than finding it out later from a client that will not resolve.
pub fn collect(
  resolver: Resolver,
  apex: Name,
) -> Result(List(port.ChainLink), String) {
  let labels = name.to_string(apex) |> string.split(".") |> drop_empty
  use apex_link <- result.try(ds_link(resolver, apex))
  use ancestors <- result.try(ancestor_links(resolver, labels, []))
  Ok([apex_link, ..ancestors])
}

/// The apex's own link: its DS RRset and the parent's signature over it.
///
/// No DNSKEY: a reader derives the key it is asking about from the
/// certificate's own SubjectPublicKeyInfo, so a copy of the DNSKEY here
/// would be a copy of something nobody is willing to believe.
fn ds_link(resolver: Resolver, apex: Name) -> Result(port.ChainLink, String) {
  use rrs <- result.try(rrset(resolver, apex, type_ds))
  Ok(port.ChainLink(name.to_string(apex), rrs))
}

fn ancestor_links(
  resolver: Resolver,
  labels: List(String),
  acc: List(port.ChainLink),
) -> Result(List(port.ChainLink), String) {
  case labels {
    [] | [_] -> {
      // The next zone up is the root: DNSKEY only, since the root has no DS.
      // Always included. An earlier version made this optional to save ~1.1 KB
      // and the saving was illusory: a chain that stops below the root anchors
      // against nothing a reader holds, so every client refuses the entry. A
      // switch whose only effect is to break verification is not a trade-off.
      use root <- result.try(name.parse(".") |> replace_error("."))
      use rrs <- result.try(rrset(resolver, root, wire.type_dnskey))
      Ok(list.reverse([port.ChainLink(".", rrs), ..acc]))
    }
    [_, ..rest] -> {
      let text = string.join(rest, ".") <> "."
      use zone <- result.try(name.parse(text) |> replace_error(text))
      use keys <- result.try(rrset(resolver, zone, wire.type_dnskey))
      use ds <- result.try(rrset(resolver, zone, type_ds))
      ancestor_links(resolver, rest, [
        port.ChainLink(text, bit_array.concat([keys, ds])),
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
