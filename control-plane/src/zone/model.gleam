//// Reads the database into a pure description of the zone: who the
//// nameservers are and which membership records each network publishes.
//// Everything downstream (build, sign, serve) is pure functions of this.

import dns/name.{type Name}
import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Text}
import thirtytwo

pub type ZoneMeta {
  ZoneMeta(
    apex: Name,
    soa_serial: Int,
    dnskey_public: BitArray,
    key_tag: Int,
    sig_inception_skew: Int,
    sig_validity: Int,
    sig_refresh_before: Int,
  )
}

pub type NsHost {
  NsHost(host: Name, ipv4: String, ipv6: String)
}

/// One published member: a device's label and one of its live keys.
pub type Member {
  Member(label: String, nk_z32: String, relay: String, addr: String)
}

/// One `_synchronicity.<network>.<org>.<apex>` owner and its members.
pub type TxtName {
  TxtName(owner: Name, members: List(Member))
}

pub type ZoneInput {
  ZoneInput(meta: ZoneMeta, ns_hosts: List(NsHost), txt_names: List(TxtName))
}

pub type ModelError {
  NoZoneMeta
  BadStoredName(String)
  Db(sqlite.Error)
}

/// Validates an nk in z-base-32: exactly a 32-byte key. Curve-point
/// validity is not checked — byte identity is what the record grammar
/// operates on, and the client re-parses fail-closed.
pub fn validate_nk(nk_z32: String) -> Result(BitArray, Nil) {
  use bytes <- result.try(thirtytwo.z_base_32_decode(nk_z32))
  case bit_array.byte_size(bytes) == 32 && string.length(nk_z32) == 52 {
    True -> Ok(bytes)
    False -> Error(Nil)
  }
}

pub fn read(conn: Connection) -> Result(ZoneInput, ModelError) {
  use meta <- result.try(read_meta(conn))
  use ns_hosts <- result.try(read_ns(conn, meta.apex))
  use txt_names <- result.try(read_txt_names(conn, meta.apex))
  Ok(ZoneInput(meta, ns_hosts, txt_names))
}

pub fn read_meta(conn: Connection) -> Result(ZoneMeta, ModelError) {
  let sql =
    "SELECT base_domain, soa_serial, dnskey_public, key_tag,
            sig_inception_skew, sig_validity, sig_refresh_before
     FROM zone_meta WHERE id = 1"
  case sqlite.query(conn, sql, []) {
    Ok([
      [
        Text(base),
        sqlite.Int(serial),
        sqlite.Blob(dnskey),
        sqlite.Int(tag),
        sqlite.Int(skew),
        sqlite.Int(validity),
        sqlite.Int(refresh),
      ],
    ]) ->
      case name.parse(base) {
        Ok(apex) ->
          Ok(ZoneMeta(apex, serial, dnskey, tag, skew, validity, refresh))
        Error(Nil) -> Error(BadStoredName(base))
      }
    Ok([]) -> Error(NoZoneMeta)
    Ok(_) -> Error(Db(sqlite.Protocol))
    Error(e) -> Error(Db(e))
  }
}

fn read_ns(conn: Connection, apex: Name) -> Result(List(NsHost), ModelError) {
  let sql =
    "SELECT hostname, coalesce(ipv4, ''), coalesce(ipv6, '')
             FROM zone_ns ORDER BY hostname"
  use rows <- result.try(sqlite.query(conn, sql, []) |> result.map_error(Db))
  list.try_map(rows, fn(row) {
    case row {
      [Text(hostname), Text(ipv4), Text(ipv6)] -> {
        // A bare label is relative to the apex; dots make it absolute.
        let full = case string.contains(hostname, ".") {
          True -> hostname
          False -> hostname <> "." <> name.to_string(apex)
        }
        case name.parse(full) {
          Ok(host) -> Ok(NsHost(host, ipv4, ipv6))
          Error(Nil) -> Error(BadStoredName(hostname))
        }
      }
      _ -> Error(Db(sqlite.Protocol))
    }
  })
}

fn read_txt_names(
  conn: Connection,
  apex: Name,
) -> Result(List(TxtName), ModelError) {
  let sql =
    "SELECT n.name, o.slug, d.label, k.nk_z32,
            coalesce(d.relay, ''), coalesce(d.addr, '')
     FROM networks n
     JOIN orgs o ON o.id = n.org_id
     JOIN network_devices nd ON nd.network_id = n.id
     JOIN devices d ON d.id = nd.device_id
     JOIN device_keys k ON k.device_id = d.id
     WHERE k.state != 'revoked'
     ORDER BY o.slug, n.name, d.label, k.added_at"
  use rows <- result.try(sqlite.query(conn, sql, []) |> result.map_error(Db))
  use flat <- result.try(
    list.try_map(rows, fn(row) {
      case row {
        [
          Text(network),
          Text(slug),
          Text(label),
          Text(nk),
          Text(relay),
          Text(addr),
        ] -> {
          let full =
            "_synchronicity."
            <> network
            <> "."
            <> slug
            <> "."
            <> name.to_string(apex)
          case name.parse(full) {
            Ok(owner) -> Ok(#(owner, Member(label, nk, relay, addr)))
            Error(Nil) -> Error(BadStoredName(full))
          }
        }
        _ -> Error(Db(sqlite.Protocol))
      }
    }),
  )
  // Group members per owner, preserving order.
  let owners =
    list.fold(flat, [], fn(acc, pair) {
      let #(owner, member) = pair
      case list.key_find(acc, owner) {
        Ok(members) -> list.key_set(acc, owner, [member, ..members])
        Error(Nil) -> [#(owner, [member]), ..acc]
      }
    })
  Ok(
    owners
    |> list.reverse
    |> list.map(fn(pair) { TxtName(pair.0, list.reverse(pair.1)) }),
  )
}
