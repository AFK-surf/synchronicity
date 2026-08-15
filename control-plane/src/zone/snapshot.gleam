//// The in-memory zone every DNS answer is served from. Loaded from
//// presigned_rrsets, installed in persistent_term (zero-copy reads from
//// any process, writes only on publish/reload), swapped atomically —
//// in-flight queries finish on the snapshot they started with. SQLite is
//// never touched per-query.

import dns/name.{type Name}
import dns/wire
import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import store/sqlite.{type Connection, Blob, Int as VInt, Text}
import zone/model

pub type Stored {
  Stored(ttl: Int, rrset_wire: BitArray, rrset_count: Int, rrsig_wire: BitArray)
}

pub type Snapshot {
  Snapshot(
    apex: Name,
    serial: Int,
    /// Keyed by (canonical owner string, rtype).
    rrsets: Dict(#(String, Int), Stored),
    /// Owners with RRsets, canonical order — the NSEC chain's spine.
    owners: List(Name),
    min_sig_expires: Int,
    loaded_at: Int,
  )
}

@external(erlang, "cp_sys_ffi", "snapshot_put")
fn snapshot_put(snapshot: Snapshot) -> Nil

@external(erlang, "cp_sys_ffi", "snapshot_get")
fn snapshot_get() -> Result(Snapshot, Nil)

pub fn install(snapshot: Snapshot) -> Nil {
  snapshot_put(snapshot)
}

pub fn current() -> Result(Snapshot, Nil) {
  snapshot_get()
}

pub fn load(conn: Connection, now: Int) -> Result(Snapshot, String) {
  use meta <- result.try(
    model.read_meta(conn)
    |> result.map_error(fn(_) { "zone_meta unreadable — not initialized?" }),
  )
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT name, rtype, ttl, rrset_wire, rrsig_wire, sig_expires_at
       FROM presigned_rrsets",
      [],
    )
    |> result.map_error(fn(_) { "presigned_rrsets unreadable" }),
  )
  use entries <- result.try(
    list.try_map(rows, fn(row) {
      case row {
        [
          Text(owner),
          VInt(rtype),
          VInt(ttl),
          Blob(rrset_wire),
          Blob(rrsig_wire),
          VInt(expires),
        ] ->
          case wire.count_rrs(rrset_wire) {
            Ok(count) ->
              Ok(#(
                #(owner, rtype),
                Stored(ttl, rrset_wire, count, rrsig_wire),
                expires,
              ))
            Error(Nil) -> Error("unparseable rrset_wire for " <> owner)
          }
        _ -> Error("bad presigned_rrsets row shape")
      }
    }),
  )
  use owner_rows <- result.try(
    sqlite.query(conn, "SELECT owner FROM nsec_chain ORDER BY ord", [])
    |> result.map_error(fn(_) { "nsec_chain unreadable" }),
  )
  use owners <- result.try(
    list.try_map(owner_rows, fn(row) {
      case row {
        [Text(owner)] ->
          name.parse(owner)
          |> result.map_error(fn(_) { "bad owner name " <> owner })
        _ -> Error("bad nsec_chain row shape")
      }
    }),
  )
  let rrsets =
    list.fold(entries, dict.new(), fn(acc, entry) {
      dict.insert(acc, entry.0, entry.1)
    })
  let min_expires =
    list.fold(entries, 0, fn(acc, entry) {
      case acc == 0 || entry.2 < acc {
        True -> entry.2
        False -> acc
      }
    })
  Ok(Snapshot(meta.apex, meta.soa_serial, rrsets, owners, min_expires, now))
}
