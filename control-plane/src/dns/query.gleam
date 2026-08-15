//// The pure answer engine: one snapshot + one query in, one wire-format
//// response out. Positive answers, NODATA and NXDOMAIN with their NSEC
//// proofs, REFUSED outside the zone. Authoritative answers only — RA is
//// never set, recursion never happens.

import dns/name.{type Name}
import dns/rdata
import dns/wire.{type Query, Section}
import gleam/bit_array
import gleam/dict
import gleam/list
import gleam/option.{None, Some}
import gleam/order
import zone/snapshot.{type Snapshot, type Stored}

pub const rcode_noerror = 0

pub const rcode_nxdomain = 3

pub const rcode_notimp = 4

pub const rcode_refused = 5

/// Our advertised EDNS0 payload size: under common MTUs, no fragmentation.
pub const advertised_udp_size = 1400

/// Answers a query from the snapshot. The result is transport-agnostic;
/// UDP callers apply `fit_udp` afterwards.
pub fn answer(snap: Snapshot, q: Query) -> BitArray {
  let do_bit = case q.edns {
    Some(wire.Edns(_, do_bit)) -> do_bit
    None -> False
  }
  let additional = case q.edns {
    Some(_) -> rdata.opt(advertised_udp_size, do_bit)
    None -> wire.empty_section()
  }
  case
    q.opcode == 0,
    q.qclass == wire.class_in && q.qtype != 255,
    name.in_zone(q.qname, snap.apex)
  {
    False, _, _ ->
      wire.encode_response(
        q,
        rcode_notimp,
        False,
        False,
        wire.empty_section(),
        wire.empty_section(),
        additional,
      )
    _, False, _ ->
      wire.encode_response(
        q,
        rcode_refused,
        False,
        False,
        wire.empty_section(),
        wire.empty_section(),
        additional,
      )
    _, _, False ->
      wire.encode_response(
        q,
        rcode_refused,
        False,
        False,
        wire.empty_section(),
        wire.empty_section(),
        additional,
      )
    True, True, True -> in_zone_answer(snap, q, do_bit, additional)
  }
}

fn in_zone_answer(
  snap: Snapshot,
  q: Query,
  do_bit: Bool,
  additional: wire.Section,
) -> BitArray {
  let qname_str = name.to_string(q.qname)
  case dict.get(snap.rrsets, #(qname_str, q.qtype)) {
    Ok(stored) ->
      wire.encode_response(
        q,
        rcode_noerror,
        True,
        False,
        with_sig(stored, do_bit),
        wire.empty_section(),
        additional,
      )
    Error(Nil) ->
      case name_exists(snap, q.qname, qname_str) {
        True ->
          wire.encode_response(
            q,
            rcode_noerror,
            True,
            False,
            wire.empty_section(),
            nodata_authority(snap, q.qname, qname_str, do_bit),
            additional,
          )
        False ->
          wire.encode_response(
            q,
            rcode_nxdomain,
            True,
            False,
            wire.empty_section(),
            nxdomain_authority(snap, q.qname, do_bit),
            additional,
          )
      }
  }
}

fn with_sig(stored: Stored, do_bit: Bool) -> wire.Section {
  let base = Section(stored.rrset_wire, stored.rrset_count)
  case do_bit {
    True -> wire.append(base, Section(stored.rrsig_wire, 1))
    False -> base
  }
}

/// A name exists if it owns RRsets or is an empty non-terminal (some owner
/// lies strictly below it).
fn name_exists(snap: Snapshot, qname: Name, qname_str: String) -> Bool {
  is_owner(snap, qname_str)
  || list.any(snap.owners, fn(owner) {
    owner != qname && name.in_zone(owner, qname)
  })
}

fn is_owner(snap: Snapshot, name_str: String) -> Bool {
  dict.has_key(snap.rrsets, #(name_str, wire.type_nsec))
}

fn soa_section(snap: Snapshot, do_bit: Bool) -> wire.Section {
  case dict.get(snap.rrsets, #(name.to_string(snap.apex), wire.type_soa)) {
    Ok(stored) -> with_sig(stored, do_bit)
    Error(Nil) -> wire.empty_section()
  }
}

fn nsec_section_for(snap: Snapshot, owner: Name, do_bit: Bool) -> wire.Section {
  case dict.get(snap.rrsets, #(name.to_string(owner), wire.type_nsec)) {
    Ok(stored) -> with_sig(stored, do_bit)
    Error(Nil) -> wire.empty_section()
  }
}

/// NODATA: SOA, plus (with DO) the NSEC proving the type absent — the
/// qname's own NSEC when qname owns records, else the covering NSEC whose
/// next name is a descendant (the empty-non-terminal proof).
fn nodata_authority(
  snap: Snapshot,
  qname: Name,
  qname_str: String,
  do_bit: Bool,
) -> wire.Section {
  let soa = soa_section(snap, do_bit)
  case do_bit {
    False -> soa
    True -> {
      let nsec_owner = case is_owner(snap, qname_str) {
        True -> qname
        False -> predecessor(snap, qname)
      }
      wire.append(soa, nsec_section_for(snap, nsec_owner, do_bit))
    }
  }
}

/// NXDOMAIN: SOA, the NSEC covering qname, and the NSEC denying a
/// wildcard at the closest encloser (deduplicated when identical).
fn nxdomain_authority(
  snap: Snapshot,
  qname: Name,
  do_bit: Bool,
) -> wire.Section {
  let soa = soa_section(snap, do_bit)
  case do_bit {
    False -> soa
    True -> {
      let covering = predecessor(snap, qname)
      let ce = closest_encloser(snap, qname)
      let wildcard = ["*", ..ce]
      let wildcard_cover = predecessor(snap, wildcard)
      let nsecs = case covering == wildcard_cover {
        True -> nsec_section_for(snap, covering, do_bit)
        False ->
          wire.append(
            nsec_section_for(snap, covering, do_bit),
            nsec_section_for(snap, wildcard_cover, do_bit),
          )
      }
      wire.append(soa, nsecs)
    }
  }
}

/// The canonically largest owner strictly before `target`. The apex is
/// canonically first among in-zone names, so in-zone targets always have
/// one.
fn predecessor(snap: Snapshot, target: Name) -> Name {
  list.fold(snap.owners, snap.apex, fn(best, owner) {
    case name.compare(owner, target) {
      order.Lt ->
        case name.compare(owner, best) {
          order.Gt -> owner
          _ -> best
        }
      _ -> best
    }
  })
}

/// The longest existing (owner or empty-non-terminal) ancestor of qname.
fn closest_encloser(snap: Snapshot, qname: Name) -> Name {
  case qname {
    [] -> []
    [_, ..parent] -> {
      let parent_str = name.to_string(parent)
      case
        is_owner(snap, parent_str)
        || list.any(snap.owners, fn(o) {
          o != parent && name.in_zone(o, parent)
        })
      {
        True -> parent
        False -> closest_encloser(snap, parent)
      }
    }
  }
}

/// The UDP payload limit a query allows (RFC 6891; 512 without EDNS).
pub fn udp_limit(q: Query) -> Int {
  case q.edns {
    Some(wire.Edns(size, _)) -> {
      let clamped = case size < 512 {
        True -> 512
        False -> size
      }
      case clamped > advertised_udp_size {
        True -> advertised_udp_size
        False -> clamped
      }
    }
    None -> 512
  }
}

/// Shrinks an oversize UDP response to a TC=1 stub (header + question +
/// OPT); the client retries over TCP.
pub fn fit_udp(q: Query, response: BitArray) -> BitArray {
  case bit_array.byte_size(response) <= udp_limit(q) {
    True -> response
    False -> {
      let additional = case q.edns {
        Some(wire.Edns(_, do_bit)) -> rdata.opt(advertised_udp_size, do_bit)
        None -> wire.empty_section()
      }
      wire.encode_response(
        q,
        rcode_noerror,
        True,
        True,
        wire.empty_section(),
        wire.empty_section(),
        additional,
      )
    }
  }
}

/// A minimal FORMERR/NOTIMP for queries we could not fully parse.
pub fn error_stub(id: Int, rcode: Int) -> BitArray {
  <<
    id:int-size(16),
    1:int-size(1),
    0:int-size(4),
    0:int-size(1),
    0:int-size(1),
    0:int-size(1),
    0:int-size(1),
    0:int-size(3),
    rcode:int-size(4),
    0:int-size(64),
  >>
}
