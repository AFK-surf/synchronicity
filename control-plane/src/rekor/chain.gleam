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
//// in place rather than before. The two-key rollover window covers the gap
//// — `zone-key stage` publishes the incoming key in the DNSKEY RRset
//// without making it a signer, so the old key keeps signing until the new
//// one is logged, and the claim this module collects names both.
////
//// The collection itself is ordinary recursive DNS work, done over DoH
//// against a configurable resolver, one RRset at a time:
////
////   link 0    _synchronicity-transparency.<apex>
////                       TXT + RRSIG           the zone's declaration,
////                                             signed by the signing zone
////   link 1    <signing zone>
////                       DNSKEY + RRSIG        the claimed key set, proved
////                       DS + RRSIG            by the parent-signed DS
////   link i    <zone>    DNSKEY + RRSIG        self-signed
////                       DS + RRSIG            signed by *its* parent
////   link n    .         DNSKEY + RRSIG        the root, terminated by the
////                                             IANA trust anchor a reader
////                                             already holds
////
//// The signing zone's link carries its own DNSKEY RRset because the RRset
//// *is* the claim: the walk proves DS → covered key → RRset, and a reader
//// checks the key that signed an answer for membership. A split-key zone's
//// DS never names the signing ZSK, and this is how DNSSEC itself authorizes
//// it.
////
//// The links above it are the **zone cuts** between the signing zone and the
//// root — not one link per label. A delegation may cross several labels at
//// once (`example.com` delegating `cp.acme.example.com` directly), and the
//// names in between are empty non-terminals with neither DNSKEY nor DS: a
//// link for one of those carries no RRsets, and every reader refuses a chain
//// containing it. So the walk asks each name above the signing zone whether
//// it is a zone at all — a DS is what its parent's delegation looks like —
//// and includes only the ones that are, root last.
////
//// The chain starts one label *below* the signing zone, at the declaration,
//// because a bare delegation ladder is public data: any passer-by can read a
//// zone's DNSKEY and DS records out of an open resolver, so a chain that
//// began at the signing zone would be evidence anybody could assemble about
//// anybody's zone. The declaration narrows that to zones which have opted
//// into publishing — control planes — and no further: the TXT RRset and its
//// RRSIG are public DNS the moment they are served, this collector reads
//// them from a public resolver itself, and so can anyone. It is not
//// attribution, and nothing downstream may be written as though it were.
////
//// **No signature is verified here, and that is a real limit rather than a
//// formality.** RRsets are copied into the certificate verbatim and every
//// reader — client and monitor alike — verifies them itself; the RRSIG walk
//// lives in `crates/synch-net/src/chain.rs` and this service does not
//// duplicate it. So a resolver that returns *well-formed but wrong* bytes
//// produces an entry that verifies nowhere — and a Merkle leaf cannot be
//// withdrawn, so the cost of noticing late is permanent and public.
////
//// What is checked here is therefore everything that can be checked without
//// a signature, chosen to match what a reader turns on:
////
////   - owner names, class and type on every record copied into a link;
////   - the ladder's shape: declaration below a signing zone that contains
////     the apex, proper-ancestor steps, terminating at the root;
////   - the declaration's *text*, its RRSIG label count (wildcard) and its
////     signer;
////   - reconstructible DNSKEY rdata, and a claimed set that excludes
////     non-zone-key and REVOKE'd keys;
////   - that each link's DNSKEY RRset is actually covered by the DS its
////     parent published, by recomputing the digest.
////
//// What remains unchecked is exactly the signatures, and the failure it
//// leaves reachable is a resolver that serves individually valid RRsets
//// which do not verify under one another. Do not read the list above as
//// "the entry is valid"; read it as "the entry is not obviously invalid".

import dns/name.{type Name}
import dns/rdata
import dns/wire
import dnssec/keys
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
  signing_zone: Name,
) -> Result(#(List(Link), List(BitArray)), String) {
  use declaration <- result.try(declaration_link(resolver, apex, signing_zone))
  use #(zone_link, rdatas) <- result.try(zone_link(resolver, signing_zone))
  use ancestors <- result.try(ancestor_links(resolver, signing_zone, []))
  Ok(#([declaration, zone_link, ..ancestors], rdatas))
}

/// The bottom link: the apex's own `_synchronicity-transparency` TXT RRset
/// and the RRSIG the signing zone made over it.
///
/// Three rules a reader enforces are enforced here as well, because a
/// declaration that breaks any of them makes the whole entry unverifiable
/// (`crates/synch-net/src/chain.rs`, `verify_declaration`) — and *that* is a
/// permanent, public, irreversible write to an append-only log, so the place
/// to notice is here, while an operator is still watching:
///
/// - the TXT RRset must actually read `v=sync1 transparency`. A reader checks
///   the text rather than counting records, so an unrelated TXT sitting at
///   this name is not consent — and a zone that has not published its
///   declaration yet answers with something, not nothing;
/// - an RRSIG covering fewer labels than its owner has was expanded from a
///   wildcard, so the zone never published a declaration of its own;
/// - an RRSIG whose signer is not the signing zone was made by somebody the
///   chain does not claim holds the record.
fn declaration_link(
  resolver: Resolver,
  apex: Name,
  signing_zone: Name,
) -> Result(Link, String) {
  let owner = [rdata.transparency_label, ..apex]
  use answers <- result.try(resolver.query(owner, wire.type_txt))
  use rrs <- result.try(rrset_of(answers, owner, wire.type_txt))
  use Nil <- result.try(check_declares(answers, owner))
  use Nil <- result.try(check_declaration_sigs(answers, owner, signing_zone))
  Ok(Link(name.to_string(owner), rrs))
}

/// Whether some TXT at `owner` carries the declaration text.
///
/// A TXT record is a sequence of character-strings and its text is their
/// concatenation, so a declaration a provider split across chunks still reads
/// as one — the same reading `chain.rs`'s `declares` gives it.
fn check_declares(answers: List(wire.Rr), owner: Name) -> Result(Nil, String) {
  let declared =
    answers
    |> list.filter(fn(rr) { owned(rr, owner, wire.type_txt) })
    |> list.any(fn(rr) { txt_text(rr.rdata) == rdata.transparency_text })
  case declared {
    True -> Ok(Nil)
    False ->
      Error(
        "the TXT RRset at "
        <> name.to_string(owner)
        <> " does not read \""
        <> rdata.transparency_text
        <> "\" — has the zone published its declaration yet? Every reader "
        <> "checks this text, so an entry carrying anything else verifies nowhere",
      )
  }
}

/// The text of a TXT rdata: its character-strings, concatenated.
fn txt_text(rd: BitArray) -> String {
  txt_chunks(rd, <<>>) |> bit_array.to_string |> result.unwrap("")
}

fn txt_chunks(rd: BitArray, acc: BitArray) -> BitArray {
  case rd {
    <<len:int-size(8), rest:bits>> -> {
      let bytes = bit_array.slice(rest, 0, len)
      let tail = bit_array.slice(rest, len, bit_array.byte_size(rest) - len)
      case bytes, tail {
        Ok(bytes), Ok(tail) -> txt_chunks(tail, bit_array.concat([acc, bytes]))
        _, _ -> acc
      }
    }
    _ -> acc
  }
}

fn check_declaration_sigs(
  answers: List(wire.Rr),
  owner: Name,
  signing_zone: Name,
) -> Result(Nil, String) {
  answers
  |> list.filter(fn(rr) { rrsig_for(rr, owner, wire.type_txt) })
  |> list.try_each(fn(rr) {
    use #(labels, signer) <- result.try(
      rrsig_labels_and_signer(rr.rdata)
      |> result.replace_error(
        "the RRSIG over the declaration at "
        <> name.to_string(owner)
        <> " does not decode",
      ),
    )
    case labels >= list.length(owner), signer == signing_zone {
      False, _ ->
        Error(
          "the declaration at "
          <> name.to_string(owner)
          <> " was expanded from a wildcard, so the zone never published one",
        )
      _, False ->
        Error(
          "the declaration at "
          <> name.to_string(owner)
          <> " names "
          <> name.to_string(signer)
          <> " as its signer, not the signing zone "
          <> name.to_string(signing_zone),
        )
      True, True -> Ok(Nil)
    }
  })
}

/// The label count and signer name out of an RRSIG rdata (RFC 4034 §3.1).
/// The signer name starts at byte 18 and is never compressed in RRSIG rdata.
fn rrsig_labels_and_signer(rrsig_rdata: BitArray) -> Result(#(Int, Name), Nil) {
  case rrsig_rdata {
    <<
      _covered:int-size(16),
      _algorithm:int-size(8),
      labels:int-size(8),
      _:bits,
    >> -> {
      use #(signer, _end) <- result.try(wire.decode_name(rrsig_rdata, 18, 0))
      Ok(#(labels, signer))
    }
    _ -> Error(Nil)
  }
}

/// Walks a chain's *shape*, the way a reader will walk its signatures.
///
/// This service cannot check the cryptography — the RRSIG walk lives in
/// crates/synch-net/src/chain.rs and every client and monitor runs it — but
/// it can check the things that are cheap to get wrong and impossible to
/// notice afterwards: that the declaration sits below a signing zone that
/// contains the apex, that the ladder climbs from that zone to the **root**,
/// and that each link carries the RRsets its position requires.
///
/// **This is the shape half only.** The content rules a reader also applies —
/// the declaration's text, and the DS actually covering a key in the RRset —
/// are enforced where the records are collected (`declaration_link`,
/// `check_ds_covers`), because they need the answers rather than the encoded
/// links. Between them they cover every non-cryptographic rule a reader
/// turns on; the signatures remain this service's blind spot, and the module
/// docs say what that leaves reachable.
///
/// A ladder link's parent is a *proper ancestor* of the link below it, not
/// its one-label parent name: zone cuts cross as many labels as a delegation
/// says they do, and the DS digest is computed over each link's own name, so
/// every link is pinned cryptographically whatever the label count is.
pub fn check_shape(
  links: List(Link),
  apex: Name,
  signing_zone: Name,
) -> Result(Nil, String) {
  let declared_at = name.to_string([rdata.transparency_label, ..apex])
  let zone_text = name.to_string(signing_zone)
  use Nil <- result.try(case name.in_zone(apex, signing_zone) {
    True -> Ok(Nil)
    False ->
      Error(
        "the signing zone "
        <> zone_text
        <> " does not contain the apex "
        <> name.to_string(apex)
        <> ", so it is not the authority for that name",
      )
  })
  case links {
    [] | [_] ->
      Error("the chain is too short to carry a declaration and a signing zone")
    [declaration, ..ladder] ->
      case declaration.zone == declared_at, ladder {
        False, _ ->
          Error(
            "the chain starts at "
            <> declaration.zone
            <> ", not the declaration at "
            <> declared_at,
          )
        True, [first, ..] if first.zone != zone_text ->
          Error(
            "the chain's second link is "
            <> first.zone
            <> ", not the signing zone "
            <> zone_text,
          )
        True, _ -> check_ladder(ladder, signing_zone)
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
      use above <- result.try(name.parse(next.zone) |> replace_error(next.zone))
      case name.in_zone(below, above) && above != below {
        False ->
          Error(
            "the chain jumps from "
            <> name.to_string(below)
            <> " to "
            <> next.zone
            <> ", which is not an ancestor of it",
          )
        True -> check_ladder([next, ..rest], above)
      }
    }
  }
}

/// The signing zone's own link: its DNSKEY RRset (the claimed set) and its
/// DS RRset, each with the RRSIGs a reader's walk verifies. The DNSKEY rdatas
/// come back separately, so the publish path claims exactly what it observed.
fn zone_link(
  resolver: Resolver,
  zone: Name,
) -> Result(#(Link, List(BitArray)), String) {
  use keys_answers <- result.try(resolver.query(zone, wire.type_dnskey))
  use keys_rrs <- result.try(rrset_of(keys_answers, zone, wire.type_dnskey))
  let observed =
    keys_answers
    |> list.filter(fn(rr) { owned(rr, zone, wire.type_dnskey) })
    |> list.map(fn(rr) { rr.rdata })
  use Nil <- result.try(
    list.try_each(observed, fn(rd) { check_dnskey_rdata(rd, zone) }),
  )
  // The claim names the keys the RRset actually authorizes, which is what a
  // reader's walk proves: a key without the Zone Key flag, or one carrying
  // RFC 5011's REVOKE bit, signs nothing and is not part of the authorized
  // set. The link still carries the whole RRset, because the RRSIG covers it.
  let rdatas = list.filter(observed, claimable)
  use Nil <- result.try(case rdatas {
    [] ->
      Error(
        "no DNSKEY at "
        <> name.to_string(zone)
        <> " is a usable zone key, so there is no authorized set to claim",
      )
    _ -> Ok(Nil)
  })
  use ds_answers <- result.try(resolver.query(zone, type_ds))
  use ds <- result.try(rrset_of(ds_answers, zone, type_ds))
  use Nil <- result.try(check_ds_covers(zone, keys_answers, ds_answers))
  Ok(#(Link(name.to_string(zone), bit_array.concat([keys_rrs, ds])), rdatas))
}

/// Whether a DNSKEY rdata belongs to the set its RRset authorizes.
///
/// RFC 4034 §2.1.1: without the Zone Key flag a key may not verify an RRSIG
/// over zone data. RFC 5011 §2.1: a key carrying REVOKE is one its owner has
/// withdrawn. Neither is part of the authorized set, and a reader's chain walk
/// excludes both — so a claim naming one would describe a set no client
/// derives.
pub fn claimable(rd: BitArray) -> Bool {
  case rd {
    <<flags:int-size(16), _:bits>> ->
      int.bitwise_and(flags, zone_key_flag) != 0
      && int.bitwise_and(flags, revoke_flag) == 0
    _ -> False
  }
}

/// The DNSKEY Zone Key flag (RFC 4034 §2.1.1).
const zone_key_flag = 0x0100

/// The DNSKEY REVOKE flag (RFC 5011 §2.1).
const revoke_flag = 0x0080

/// A DNSKEY rdata this side is willing to claim: a full four-byte header
/// whose protocol byte is 3.
///
/// The claim's digests are computed over these bytes verbatim, and the
/// client's chain walk reconstructs rdata as `flags ‖ 3 ‖ algorithm ‖ key`
/// — refusing protocol 3's alternatives here (RFC 4034 §2.1.2 permits no
/// others) is what keeps the two byte-identical, and it makes a rdata too
/// short to hold flags and an algorithm unreachable from the wire.
fn check_dnskey_rdata(rd: BitArray, zone: Name) -> Result(Nil, String) {
  case rd {
    <<_flags:int-size(16), 3:int-size(8), _algorithm:int-size(8), _:bits>> ->
      Ok(Nil)
    _ ->
      Error(
        "a DNSKEY at "
        <> name.to_string(zone)
        <> " is not flags, protocol 3, algorithm and a key, so no reader"
        <> " could reconstruct the rdata this claim would name",
      )
  }
}

/// The links above the signing zone: every genuine zone cut between it and
/// the root, and the root itself.
fn ancestor_links(
  resolver: Resolver,
  below: Name,
  acc: List(Link),
) -> Result(List(Link), String) {
  case below {
    // The next name up is the root: DNSKEY only, since the root has no DS.
    // Always included, and not worth making optional to save its ~1.1 KB:
    // a chain that stops below the root anchors against nothing a reader
    // holds, so every client would refuse the entry. A switch whose only
    // effect is to break verification is not a trade-off.
    [] | [_] -> {
      use rrs <- result.try(rrset(resolver, [], wire.type_dnskey))
      Ok(list.reverse([Link(".", rrs), ..acc]))
    }
    [_, ..above] -> {
      use link <- result.try(zone_cut_link(resolver, above))
      case link {
        Ok(link) -> ancestor_links(resolver, above, [link, ..acc])
        // An empty non-terminal: no zone, no link, and the link below it is
        // proved by the DS held in the next real zone up.
        Error(Nil) -> ancestor_links(resolver, above, acc)
      }
    }
  }
}

/// One name on the way up as a link, or `Error(Nil)` when that name is not a
/// zone at all.
///
/// A DS is what a secure delegation looks like from the child's side, so a
/// name with one is a zone and a name with neither DS nor DNSKEY is an empty
/// non-terminal to be skipped. The two mixed answers are chains that cannot
/// be built and are refused here rather than published: a DS with no DNSKEY
/// is a delegation to an unsigned zone, and a DNSKEY with no DS is a signed
/// zone its parent delegates insecurely — either way the walk stops there and
/// no reader can anchor what is below.
fn zone_cut_link(
  resolver: Resolver,
  zone: Name,
) -> Result(Result(Link, Nil), String) {
  use ds_answers <- result.try(resolver.query(zone, type_ds))
  use key_answers <- result.try(resolver.query(zone, wire.type_dnskey))
  use ds <- result.try(maybe_rrset_of(ds_answers, zone, type_ds))
  use keys <- result.try(maybe_rrset_of(key_answers, zone, wire.type_dnskey))
  case ds, keys {
    Ok(ds), Ok(keys) -> {
      use Nil <- result.try(check_ds_covers(zone, key_answers, ds_answers))
      Ok(Ok(Link(name.to_string(zone), bit_array.concat([keys, ds]))))
    }
    Error(Nil), Error(Nil) -> Ok(Error(Nil))
    Ok(_), Error(Nil) ->
      Error(
        name.to_string(zone)
        <> " has a DS but answers no DNSKEY RRset: the zone it delegates to"
        <> " is unsigned, so the chain cannot be walked past it",
      )
    Error(Nil), Ok(_) ->
      Error(
        name.to_string(zone)
        <> " answers a DNSKEY RRset but its parent holds no DS for it, so"
        <> " the delegation is insecure and the chain breaks there",
      )
  }
}

/// Whether some claimable DNSKEY at `zone` is covered by a DS in the same
/// link — the check `chain.rs`'s `covers` makes of every ladder link below
/// the top, made here before anything is written to a public log.
///
/// This is the rule a resolver breaks by *answering incompletely*: a DS RRset
/// from before a rollover, a DNSKEY RRset from after it, and the two describe
/// different keys. Both RRsets are individually signed and individually
/// valid, so nothing else in this collector notices — and the entry that
/// results is one every client refuses and every monitor files as tier B,
/// permanently, because a Merkle leaf cannot be withdrawn.
///
/// SHA-256 and SHA-384 only, matching the reader: a chain that can only be
/// followed through SHA-1 is one it declines to follow.
fn check_ds_covers(
  zone: Name,
  key_answers: List(wire.Rr),
  ds_answers: List(wire.Rr),
) -> Result(Nil, String) {
  let digests =
    ds_answers
    |> list.filter(fn(rr) { owned(rr, zone, type_ds) })
    |> list.filter_map(fn(rr) {
      case rr.rdata {
        <<_tag:int-size(16), _alg:int-size(8), 2:int-size(8), digest:bits>> ->
          Ok(digest)
        <<_tag:int-size(16), _alg:int-size(8), 4:int-size(8), digest:bits>> ->
          Ok(digest)
        _ -> Error(Nil)
      }
    })
  let covered =
    key_answers
    |> list.filter(fn(rr) { owned(rr, zone, wire.type_dnskey) })
    |> list.map(fn(rr) { rr.rdata })
    |> list.filter(claimable)
    |> list.any(fn(rd) {
      let want = keys.ds_digest(zone, rd)
      list.any(digests, fn(got) { got == want })
    })
  case covered {
    True -> Ok(Nil)
    False ->
      Error(
        "no usable DNSKEY at "
        <> name.to_string(zone)
        <> " is covered by a DS its parent published (SHA-256 or SHA-384) — "
        <> "the DS and DNSKEY RRsets this resolver answered describe different "
        <> "keys, so the chain would not walk at any reader. Is a rollover in "
        <> "flight, or has the new DS finished propagating?",
      )
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

/// `rrset`, but absence is an answer: `Error(Nil)` for a name that has no
/// RRset of this type at all. An RRset that is *there* and unsigned is still
/// a failure, because a link cannot carry it.
fn maybe_rrset_of(
  answers: List(wire.Rr),
  zone: Name,
  rtype: Int,
) -> Result(Result(BitArray, Nil), String) {
  case list.any(answers, fn(rr) { owned(rr, zone, rtype) }) {
    False -> Ok(Error(Nil))
    True -> rrset_of(answers, zone, rtype) |> result.map(Ok)
  }
}

/// Whether an RR is the wanted type at the wanted owner.
fn owned(rr: wire.Rr, zone: Name, rtype: Int) -> Bool {
  rr.class == wire.class_in && rr.rtype == rtype && rr.name == zone
}

/// Whether an RR is an RRSIG at `zone` covering `rtype`.
fn rrsig_for(rr: wire.Rr, zone: Name, rtype: Int) -> Bool {
  rr.class == wire.class_in
  && rr.rtype == wire.type_rrsig
  && rr.name == zone
  && covers(rr.rdata, rtype)
}

/// The filtering/validation/encoding half of `rrset`, over answers already
/// in hand — the signing zone's link fetches DNSKEYs once and needs both the
/// wire run and the raw rdatas.
///
/// Filtered by owner name as well as by class and type: a resolver may put
/// anything it likes in an answer section, and a reader refuses a link
/// holding a record the link's own name does not own
/// (`ParsedLink::parse` in crates/synch-net/src/chain.rs). Copying such a
/// record in would make the whole entry unverifiable.
fn rrset_of(
  answers: List(wire.Rr),
  zone: Name,
  rtype: Int,
) -> Result(BitArray, String) {
  let wanted =
    list.filter(answers, fn(rr) {
      owned(rr, zone, rtype) || rrsig_for(rr, zone, rtype)
    })
  let has = fn(t) { list.any(wanted, fn(rr) { rr.rtype == t }) }
  case has(rtype), has(wire.type_rrsig) {
    False, _ ->
      Error(
        "no "
        <> type_name(rtype)
        <> " RRset at "
        <> name.to_string(zone)
        <> case rtype {
          // Each absence has one likely cause, and they are different
          // enough that a single hint sends an operator the wrong way.
          t if t == wire.type_txt ->
            " — has the zone published its declaration yet?"
          _ -> " — is the DS live in the parent yet?"
        },
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
    16 -> "TXT"
    other -> int.to_string(other)
  }
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
        Ok(message) -> response_answers(url, message)
        Error(Nil) -> Error(url <> " returned a message that does not decode")
      }
    status -> Error(url <> " answered " <> int.to_string(status))
  }
}

/// The answer section of a decoded response, or why the response is no
/// answer at all.
///
/// NOERROR and NXDOMAIN both *are* answers: an empty section is what a
/// genuine absence looks like, and each caller has its own words for that
/// (the collector's "has the zone published its declaration yet?", the
/// key watch's quiet wait). Any other rcode — SERVFAIL above all, a
/// validating resolver's verdict, e.g. while a provider re-signs — is the
/// resolver declining to answer, and must never be read as the RRset being
/// absent: that reading reports a publish problem that does not exist.
pub fn response_answers(
  url: String,
  message: wire.Message,
) -> Result(List(wire.Rr), String) {
  case rcode(message.flags) {
    // NOERROR or NXDOMAIN.
    0 | 3 -> Ok(message.answers)
    code -> Error(url <> " answered " <> rcode_name(code))
  }
}

/// The rcode is the low nibble of the flags word (RFC 1035 §4.1.1).
fn rcode(flags: Int) -> Int {
  int.bitwise_and(flags, 0b1111)
}

fn rcode_name(code: Int) -> String {
  case code {
    1 -> "FORMERR"
    2 -> "SERVFAIL"
    4 -> "NOTIMP"
    5 -> "REFUSED"
    other -> "rcode " <> int.to_string(other)
  }
}
