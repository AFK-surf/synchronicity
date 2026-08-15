//// The answer engine: one query in, one wire-format response out,
//// straight from SQLite. Every answer's reads run inside one read
//// transaction, so an answer can never straddle a publish — the RRset
//// and its RRSIG are always from the same zone version. Positive
//// answers, NODATA and NXDOMAIN with their NSEC proofs, REFUSED outside
//// the zone, SERVFAIL when the database cannot answer. Authoritative
//// only — RA is never set, recursion never happens.
////
//// Canonical-order lookups (NSEC predecessors, empty-non-terminal
//// checks) ride on `sort_key`: a byte encoding whose BLOB order equals
//// RFC 4034 §6.1 order, indexed in presigned_rrsets.

import dns/name.{type Name}
import dns/rdata
import dns/wire.{type Query, Section}
import gleam/bit_array

import gleam/option.{None, Some}
import gleam/result
import store/sqlite.{type Connection, Blob, Int as VInt, Text}

pub const rcode_noerror = 0

pub const rcode_servfail = 2

pub const rcode_nxdomain = 3

pub const rcode_notimp = 4

pub const rcode_refused = 5

/// Our advertised EDNS0 payload size: under common MTUs, no fragmentation.
pub const advertised_udp_size = 1400

/// One stored RRset with its signature, answer-section-ready.
type Stored {
  Stored(rrset_wire: BitArray, rrset_count: Int, rrsig_wire: BitArray)
}

/// Answers a query from the database. The result is transport-agnostic;
/// UDP callers apply `fit_udp` afterwards. The connection comes reset
/// from the pool — no transaction or statement state can linger.
pub fn answer(conn: Connection, apex: Name, q: Query) -> BitArray {
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
    name.in_zone(q.qname, apex)
  {
    False, _, _ -> refusal(q, rcode_notimp, additional)
    _, False, _ -> refusal(q, rcode_refused, additional)
    _, _, False -> refusal(q, rcode_refused, additional)
    True, True, True -> {
      // One read transaction per answer: WAL pins the zone version for
      // the handful of lookups below.
      let _ = sqlite.exec(conn, "BEGIN", [])
      let outcome = in_zone_answer(conn, apex, q, do_bit, additional)
      let _ = sqlite.exec(conn, "COMMIT", [])
      case outcome {
        Ok(response) -> response
        // Database unavailable or corrupt row: no answer beats a wrong
        // or unsigned one.
        Error(_) -> refusal(q, rcode_servfail, additional)
      }
    }
  }
}

fn refusal(q: Query, rcode: Int, additional: wire.Section) -> BitArray {
  wire.encode_response(
    q,
    rcode,
    False,
    False,
    wire.empty_section(),
    wire.empty_section(),
    additional,
  )
}

fn in_zone_answer(
  conn: Connection,
  apex: Name,
  q: Query,
  do_bit: Bool,
  additional: wire.Section,
) -> Result(BitArray, sqlite.Error) {
  let qname_str = name.to_string(q.qname)
  use exact <- result.try(lookup(conn, qname_str, q.qtype))
  case exact {
    Some(stored) ->
      Ok(wire.encode_response(
        q,
        rcode_noerror,
        True,
        False,
        with_sig(stored, do_bit),
        wire.empty_section(),
        additional,
      ))
    None -> {
      use exists <- result.try(exists_at_or_below(conn, q.qname))
      case exists {
        True -> {
          use authority <- result.try(nodata_authority(
            conn,
            apex,
            q.qname,
            qname_str,
            do_bit,
          ))
          Ok(wire.encode_response(
            q,
            rcode_noerror,
            True,
            False,
            wire.empty_section(),
            authority,
            additional,
          ))
        }
        False -> {
          use authority <- result.try(nxdomain_authority(
            conn,
            apex,
            q.qname,
            do_bit,
          ))
          Ok(wire.encode_response(
            q,
            rcode_nxdomain,
            True,
            False,
            wire.empty_section(),
            authority,
            additional,
          ))
        }
      }
    }
  }
}

// -- storage lookups ---------------------------------------------------------

fn lookup(
  conn: Connection,
  name_str: String,
  rtype: Int,
) -> Result(option.Option(Stored), sqlite.Error) {
  let rows =
    sqlite.query(
      conn,
      "SELECT rrset_wire, rrsig_wire FROM presigned_rrsets
       WHERE name = ? AND rtype = ?",
      [Text(name_str), VInt(rtype)],
    )
  case rows {
    Ok([[Blob(rrset_wire), Blob(rrsig_wire)]]) -> stored(rrset_wire, rrsig_wire)
    Ok(_) -> Ok(None)
    Error(e) -> Error(e)
  }
}

fn stored(
  rrset_wire: BitArray,
  rrsig_wire: BitArray,
) -> Result(option.Option(Stored), sqlite.Error) {
  case wire.count_rrs(rrset_wire) {
    Ok(count) -> Ok(Some(Stored(rrset_wire, count, rrsig_wire)))
    // A row we cannot parse is corruption; answering would serve garbage.
    Error(Nil) -> Error(sqlite.Protocol)
  }
}

/// Does any owner exist at or below `target`? Covers both "target owns
/// records" and "target is an empty non-terminal" in one indexed range
/// probe over sort_key.
fn exists_at_or_below(
  conn: Connection,
  target: Name,
) -> Result(Bool, sqlite.Error) {
  let rows =
    sqlite.query(
      conn,
      "SELECT 1 FROM presigned_rrsets
       WHERE sort_key >= ? AND sort_key < ? LIMIT 1",
      [Blob(name.sort_key(target)), Blob(name.sort_key_upper(target))],
    )
  case rows {
    Ok([]) -> Ok(False)
    Ok(_) -> Ok(True)
    Error(e) -> Error(e)
  }
}

fn is_owner(conn: Connection, name_str: String) -> Result(Bool, sqlite.Error) {
  let rows =
    sqlite.query(conn, "SELECT 1 FROM presigned_rrsets WHERE name = ? LIMIT 1", [
      Text(name_str),
    ])
  case rows {
    Ok([]) -> Ok(False)
    Ok(_) -> Ok(True)
    Error(e) -> Error(e)
  }
}

/// The NSEC RRset of the canonically largest owner strictly before
/// `target_key`. The apex is canonically first among in-zone names, so
/// every in-zone target has one.
fn covering_nsec(
  conn: Connection,
  target_key: BitArray,
) -> Result(option.Option(Stored), sqlite.Error) {
  let rows =
    sqlite.query(
      conn,
      "SELECT rrset_wire, rrsig_wire FROM presigned_rrsets
       WHERE rtype = ? AND sort_key < ?
       ORDER BY sort_key DESC LIMIT 1",
      [VInt(wire.type_nsec), Blob(target_key)],
    )
  case rows {
    Ok([[Blob(rrset_wire), Blob(rrsig_wire)]]) -> stored(rrset_wire, rrsig_wire)
    Ok(_) -> Ok(None)
    Error(e) -> Error(e)
  }
}

// -- authority sections ------------------------------------------------------

fn with_sig(stored: Stored, do_bit: Bool) -> wire.Section {
  let base = Section(stored.rrset_wire, stored.rrset_count)
  case do_bit {
    True -> wire.append(base, Section(stored.rrsig_wire, 1))
    False -> base
  }
}

fn section_of(found: option.Option(Stored), do_bit: Bool) -> wire.Section {
  case found {
    Some(stored) -> with_sig(stored, do_bit)
    None -> wire.empty_section()
  }
}

fn soa_section(
  conn: Connection,
  apex: Name,
  do_bit: Bool,
) -> Result(wire.Section, sqlite.Error) {
  use found <- result.try(lookup(conn, name.to_string(apex), wire.type_soa))
  Ok(section_of(found, do_bit))
}

/// NODATA: SOA, plus (with DO) the NSEC proving the type absent — the
/// qname's own NSEC when qname owns records, else the covering NSEC whose
/// next name is a descendant (the empty-non-terminal proof).
fn nodata_authority(
  conn: Connection,
  apex: Name,
  qname: Name,
  qname_str: String,
  do_bit: Bool,
) -> Result(wire.Section, sqlite.Error) {
  use soa <- result.try(soa_section(conn, apex, do_bit))
  case do_bit {
    False -> Ok(soa)
    True -> {
      use owner <- result.try(is_owner(conn, qname_str))
      use nsec <- result.try(case owner {
        True -> lookup(conn, qname_str, wire.type_nsec)
        False -> covering_nsec(conn, name.sort_key(qname))
      })
      Ok(wire.append(soa, section_of(nsec, do_bit)))
    }
  }
}

/// NXDOMAIN: SOA, the NSEC covering qname, and the NSEC denying a
/// wildcard at the closest encloser (deduplicated when identical).
fn nxdomain_authority(
  conn: Connection,
  apex: Name,
  qname: Name,
  do_bit: Bool,
) -> Result(wire.Section, sqlite.Error) {
  use soa <- result.try(soa_section(conn, apex, do_bit))
  case do_bit {
    False -> Ok(soa)
    True -> {
      use covering <- result.try(covering_nsec(conn, name.sort_key(qname)))
      use ce <- result.try(closest_encloser(conn, qname))
      let wildcard_key = name.sort_key(["*", ..ce])
      use wildcard_cover <- result.try(covering_nsec(conn, wildcard_key))
      let nsecs = case covering == wildcard_cover {
        True -> section_of(covering, do_bit)
        False ->
          wire.append(
            section_of(covering, do_bit),
            section_of(wildcard_cover, do_bit),
          )
      }
      Ok(wire.append(soa, nsecs))
    }
  }
}

/// The longest existing (owner or empty-non-terminal) ancestor of qname.
fn closest_encloser(
  conn: Connection,
  qname: Name,
) -> Result(Name, sqlite.Error) {
  case qname {
    [] -> Ok([])
    [_, ..parent] -> {
      use exists <- result.try(exists_at_or_below(conn, parent))
      case exists {
        True -> Ok(parent)
        False -> closest_encloser(conn, parent)
      }
    }
  }
}

// -- transport helpers -------------------------------------------------------

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
