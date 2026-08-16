//// The `tuf_material` table: the Sigstore metadata this zone relays, and
//// the versions that decide whether a refetch is an update or a regression
//// (docs/REKOR-ZONE-KEY.md §10.3).
////
//// One row, because there is one Sigstore repository and one current view
//// of it. Replicas need nothing beyond the row: relayed TUF material is
//// public, self-authenticating data and rides the existing operator-owned
//// replication like everything else.

import gleam/list
import gleam/result
import store/sqlite.{type Connection, Blob, Int as VInt, Text}
import tuf/bundle.{type Bundle, Bundle}

/// The stored material, with everything the refetch decision needs.
pub type Material {
  Material(
    source: String,
    roots: List(BitArray),
    root_version: Int,
    timestamp_json: BitArray,
    timestamp_version: Int,
    timestamp_expires: Int,
    snapshot_json: BitArray,
    snapshot_version: Int,
    targets_json: BitArray,
    targets_version: Int,
    trusted_root: BitArray,
    fetched_at: Int,
  )
}

/// The bundle this material serves as.
pub fn to_bundle(material: Material) -> Bundle {
  Bundle(
    roots: material.roots,
    timestamp: material.timestamp_json,
    snapshot: material.snapshot_json,
    targets: material.targets_json,
    trusted_root: material.trusted_root,
  )
}

/// Replaces the stored material. The single row is the whole state: a
/// partial update would leave a chain whose files disagree, which is
/// exactly the material a client is going to ignore.
pub fn put(conn: Connection, material: Material) -> Result(Nil, sqlite.Error) {
  sqlite.exec(
    conn,
    "INSERT INTO tuf_material
       (id, source, root_json, root_count, root_version, timestamp_json,
        timestamp_version, timestamp_expires, snapshot_json, snapshot_version,
        targets_json, targets_version, trusted_root, fetched_at)
     VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (id) DO UPDATE SET
       source = excluded.source,
       root_json = excluded.root_json,
       root_count = excluded.root_count,
       root_version = excluded.root_version,
       timestamp_json = excluded.timestamp_json,
       timestamp_version = excluded.timestamp_version,
       timestamp_expires = excluded.timestamp_expires,
       snapshot_json = excluded.snapshot_json,
       snapshot_version = excluded.snapshot_version,
       targets_json = excluded.targets_json,
       targets_version = excluded.targets_version,
       trusted_root = excluded.trusted_root,
       fetched_at = excluded.fetched_at",
    [
      Text(material.source),
      Blob(bundle.join_roots(material.roots)),
      VInt(list.length(material.roots)),
      VInt(material.root_version),
      Blob(material.timestamp_json),
      VInt(material.timestamp_version),
      VInt(material.timestamp_expires),
      Blob(material.snapshot_json),
      VInt(material.snapshot_version),
      Blob(material.targets_json),
      VInt(material.targets_version),
      Blob(material.trusted_root),
      VInt(material.fetched_at),
    ],
  )
  |> result.replace(Nil)
}

/// The stored material, if any has ever been fetched.
pub fn get(conn: Connection) -> Result(Result(Material, Nil), sqlite.Error) {
  let sql =
    "SELECT source, root_json, root_version, timestamp_json, timestamp_version,
            timestamp_expires, snapshot_json, snapshot_version, targets_json,
            targets_version, trusted_root, fetched_at
     FROM tuf_material WHERE id = 1"
  use rows <- result.try(sqlite.query(conn, sql, []))
  case rows {
    [row] -> Ok(decode(row))
    _ -> Ok(Error(Nil))
  }
}

fn decode(row: List(sqlite.Value)) -> Result(Material, Nil) {
  case row {
    [
      Text(source),
      Blob(roots),
      VInt(root_version),
      Blob(timestamp_json),
      VInt(timestamp_version),
      VInt(timestamp_expires),
      Blob(snapshot_json),
      VInt(snapshot_version),
      Blob(targets_json),
      VInt(targets_version),
      Blob(trusted_root),
      VInt(fetched_at),
    ] -> {
      use roots <- result.try(bundle.split_roots(roots))
      Ok(Material(
        source,
        roots,
        root_version,
        timestamp_json,
        timestamp_version,
        timestamp_expires,
        snapshot_json,
        snapshot_version,
        targets_json,
        targets_version,
        trusted_root,
        fetched_at,
      ))
    }
    _ -> Error(Nil)
  }
}
