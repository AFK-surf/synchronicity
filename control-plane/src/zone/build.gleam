//// Turns a ZoneInput into the complete RRset list, NSEC chain included.
//// This is also the last line of defense: every invariant the product
//// layer enforces is re-checked here, and a violation refuses the whole
//// publish — an ambiguous or malformed zone is never emitted.

import dns/name.{type Name}
import dns/rdata
import dns/wire
import dnssec/keys
import gleam/dict
import gleam/int
import gleam/list
import gleam/order
import gleam/result
import zone/model.{type ZoneInput}

/// Data records: TXT, NSEC, SOA — the values clients clamp around.
pub const ttl_data = 300

/// Infrastructure records: NS, DNSKEY, glue.
pub const ttl_infra = 3600

pub type Rrset {
  Rrset(owner: Name, rtype: Int, ttl: Int, rdatas: List(BitArray))
}

pub type BuildError {
  NoNameservers
  OwnerOutsideZone(String)
  DuplicateLabelInZone(String)
  InvalidLabel(String)
  InvalidNk(String)
  /// One nk under two different labels in one zone — the §3.2 ambiguity.
  /// The schema makes this unrepresentable; refusing here is fail-closed
  /// defense in depth.
  AmbiguousNk(String)
  BadGlueAddress(String)
}

/// All RRsets for the zone, NSEC chain included, ready to sign.
pub fn build(input: ZoneInput) -> Result(List(Rrset), BuildError) {
  let apex = input.meta.apex
  use Nil <- result.try(validate(input))
  use first_ns <- result.try(case input.ns_hosts {
    [first, ..] -> Ok(first.host)
    [] -> Error(NoNameservers)
  })

  let soa =
    Rrset(apex, wire.type_soa, ttl_data, [
      rdata.soa(
        first_ns,
        ["hostmaster", ..apex],
        input.meta.soa_serial,
        86_400,
        7200,
        1_209_600,
        ttl_data,
      ),
    ])
  let ns =
    Rrset(
      apex,
      wire.type_ns,
      ttl_infra,
      list.map(input.ns_hosts, fn(h) { rdata.ns(h.host) }),
    )
  let dnskey =
    Rrset(apex, wire.type_dnskey, ttl_infra, [
      rdata.dnskey(keys.flags, keys.algorithm, input.meta.dnskey_public),
    ])

  use glue <- result.try(glue_rrsets(input, apex))

  let txt =
    list.map(input.txt_names, fn(txt_name) {
      Rrset(
        txt_name.owner,
        wire.type_txt,
        ttl_data,
        list.map(txt_name.members, fn(m) {
          rdata.txt(rdata.sync1_text(m.label, m.nk_z32, m.relay, m.addr))
        }),
      )
    })

  let data = list.flatten([[soa, ns, dnskey], glue, txt])
  Ok(list.append(data, nsec_chain(data)))
}

/// The canonical owner order and the NSEC records it induces — exposed for
/// the publish step to persist the chain.
pub fn owners_in_order(rrsets: List(Rrset)) -> List(Name) {
  rrsets
  |> list.map(fn(r) { r.owner })
  |> list.unique
  |> list.sort(name.compare)
}

fn nsec_chain(data: List(Rrset)) -> List(Rrset) {
  let owners = owners_in_order(data)
  let next_of = case owners {
    [first, ..rest] -> list.zip(owners, list.append(rest, [first]))
    [] -> []
  }
  list.map(next_of, fn(pair) {
    let #(owner, next) = pair
    let types_here =
      data
      |> list.filter(fn(r) { r.owner == owner })
      |> list.map(fn(r) { r.rtype })
    let types = [wire.type_rrsig, wire.type_nsec, ..types_here]
    Rrset(owner, wire.type_nsec, ttl_data, [rdata.nsec(next, types)])
  })
}

fn glue_rrsets(
  input: ZoneInput,
  apex: Name,
) -> Result(List(Rrset), BuildError) {
  input.ns_hosts
  |> list.filter(fn(h) { name.in_zone(h.host, apex) })
  |> list.try_map(fn(h) {
    let addresses =
      [h.ipv4, h.ipv6]
      |> list.filter(fn(a) { a != "" })
    use parsed <- result.try(
      list.try_map(addresses, fn(a) {
        rdata.address(a)
        |> result.replace_error(BadGlueAddress(a))
      }),
    )
    let groups = list.group(parsed, fn(p) { p.0 })
    Ok(
      [wire.type_a, wire.type_aaaa]
      |> list.filter_map(fn(rtype) {
        case dict.get(groups, rtype) {
          Ok(pairs) ->
            Ok(Rrset(h.host, rtype, ttl_infra, list.map(pairs, fn(p) { p.1 })))
          Error(Nil) -> Error(Nil)
        }
      }),
    )
  })
  |> result.map(list.flatten)
}

fn validate(input: ZoneInput) -> Result(Nil, BuildError) {
  let apex = input.meta.apex
  use Nil <- result.try(
    list.try_fold(input.txt_names, Nil, fn(_, txt_name) {
      case name.in_zone(txt_name.owner, apex) {
        False -> Error(OwnerOutsideZone(name.to_string(txt_name.owner)))
        True -> validate_members(txt_name.members)
      }
    }),
  )
  Ok(Nil)
}

fn validate_members(members: List(model.Member)) -> Result(Nil, BuildError) {
  // Label grammar and nk shape.
  use Nil <- result.try(
    list.try_fold(members, Nil, fn(_, m) {
      case name.valid_device_label(m.label) {
        False -> Error(InvalidLabel(m.label))
        True ->
          case model.validate_nk(m.nk_z32) {
            Ok(_) -> Ok(Nil)
            Error(Nil) -> Error(InvalidNk(m.nk_z32))
          }
      }
    }),
  )
  // One nk may appear under exactly one label (rotation shares the label).
  let by_nk = dict.to_list(list.group(members, fn(m) { m.nk_z32 }))
  use Nil <- result.try(
    list.try_fold(by_nk, Nil, fn(_, pair) {
      let #(nk, with_nk) = pair
      case list.unique(list.map(with_nk, fn(m) { m.label })) {
        [_] -> Ok(Nil)
        _ -> Error(AmbiguousNk(nk))
      }
    }),
  )
  // A label belongs to one device: >2 records under a label means the
  // rotation-window bound broke upstream; two is the legal window.
  let by_label = dict.to_list(list.group(members, fn(m) { m.label }))
  list.try_fold(by_label, Nil, fn(_, pair) {
    let #(label, with_label) = pair
    case list.length(with_label) <= 2 {
      True -> Ok(Nil)
      False -> Error(DuplicateLabelInZone(label))
    }
  })
}

/// Sorts full RRsets canonically — publish stores them in chain order.
pub fn sort_rrsets(rrsets: List(Rrset)) -> List(Rrset) {
  list.sort(rrsets, fn(a, b) {
    case name.compare(a.owner, b.owner) {
      order.Eq -> int.compare(a.rtype, b.rtype)
      other -> other
    }
  })
}
