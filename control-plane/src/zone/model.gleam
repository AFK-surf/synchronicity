//// Reads the database into a pure description of the zone: who the
//// nameservers are and which membership records each network publishes.
//// Everything downstream (build, sign, serve) is pure functions of this.

import dns/name.{type Name}
import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import rekor/proof
import rekor/publish as rekor_publish
import rekor/store as rekor_store
import store/sqlite.{type Connection, Text}
import thirtytwo
import tuf/bundle
import tuf/store as tuf_store

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
  ZoneInput(
    meta: ZoneMeta,
    ns_hosts: List(NsHost),
    txt_names: List(TxtName),
    /// Zone-key transparency proofs for the key the zone publishes, in the
    /// base64url form one TXT record carries. Empty until `rekor-publish`
    /// has run — phase 0 of the rollout serves a zone without them.
    /// The proof records, each with the part number that decides its owner
    /// name: part 1 at `_synchronicity-rekor`, part n at
    /// `_synchronicity-rekor-<n>`.
    rekor_proofs: List(#(Int, String)),
    /// The relayed Sigstore TUF bundle (§10.1), base64url. Empty until
    /// `tuf-refresh` has run, which is a zone whose clients keep the pins
    /// they already have — a non-event, not a fault.
    tuf_bundle: String,
  )
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
  use rekor_proofs <- result.try(read_rekor_proofs(conn))
  use tuf_bundle <- result.try(read_tuf_bundle(conn))
  Ok(ZoneInput(meta, ns_hosts, txt_names, rekor_proofs, tuf_bundle))
}

/// The relayed TUF bundle, or the empty string when nothing is stored.
///
/// A database error here would be an odd way to stop serving a zone over
/// material the client is free to ignore, so it is reported like any other
/// read; what is *not* an error is having no material at all.
fn read_tuf_bundle(conn: Connection) -> Result(String, ModelError) {
  use stored <- result.try(tuf_store.get(conn) |> result.map_error(Db))
  case stored {
    Ok(material) -> Ok(bundle.to_txt(tuf_store.to_bundle(material)))
    Error(Nil) -> Ok("")
  }
}

/// The proof records this zone serves — every verified non-retire record;
/// with key-set claims there is no per-tag selection, a client tries each.
///
/// A stored row that cannot be turned back into a proof is dropped rather
/// than served: a malformed record would make every client refuse the whole
/// zone, which is a worse outcome than the one the row was meant to fix.
fn read_rekor_proofs(
  conn: Connection,
) -> Result(List(#(Int, String)), ModelError) {
  use records <- result.try(rekor_store.servable(conn) |> result.map_error(Db))
  Ok(
    records
    |> list.filter_map(fn(record) {
      // A row that will not encode is dropped for the same reason a
      // malformed one is: serving it would make every client refuse the
      // whole zone, which is worse than the gap the row was meant to close.
      case rekor_publish.to_proof(record) {
        Ok(built) -> proof.to_txt(built) |> result.replace_error(Nil)
        Error(_) -> Error(Nil)
      }
    })
    // One proof is several records, and they go to *different* owner names:
    // part 1 at the base, part n one label along. Providers cap the combined
    // content of a single name — Cloudflare at 8192 wire bytes, which one
    // ICANN-rooted proof exceeds by itself — so the parts have to spread.
    |> list.flatten
    |> list.map(fn(text) { #(proof.part_index_of(text), text) }),
  )
}

/// The health probe's view of the zone: current serial and the soonest
/// RRSIG expiry. Error(Nil) covers every unhealthy shape — no zone_meta,
/// nothing presigned, database unavailable.
pub fn health(conn: Connection) -> Result(#(Int, Int), Nil) {
  case
    sqlite.query(
      conn,
      "SELECT m.soa_serial, min(p.sig_expires_at)
       FROM zone_meta m, presigned_rrsets p",
      [],
    )
  {
    Ok([[sqlite.Int(serial), sqlite.Int(expires)]]) -> Ok(#(serial, expires))
    _ -> Error(Nil)
  }
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
