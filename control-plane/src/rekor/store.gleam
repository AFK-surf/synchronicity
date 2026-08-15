//// The `rekor_records` table: the proofs this zone serves, and the only
//// thing the publish gate consults.
////
//// A row is written only after the proof has been verified locally by the
//// same rules the client applies (`rekor/publish`), so `verified_at` means
//// *this service checked it*, not *the log said so*. Replicas need nothing
//// beyond the row itself: a proof is public data and rides the existing
//// operator-owned replication.

import gleam/list
import gleam/result
import store/sqlite.{type Connection, Blob, Int as VInt, Text}

pub type Record {
  Record(
    key_tag: Int,
    apex: String,
    action: String,
    dsse_payload: BitArray,
    dsse_signature: BitArray,
    log_id: BitArray,
    log_index: Int,
    checkpoint: BitArray,
    inclusion_path: BitArray,
    integrated_at: Int,
    verified_at: Int,
  )
}

/// Writes a record, replacing the one for this key tag and action.
///
/// Re-publishing is a refresh, not a second entry: the tree has grown, so
/// the checkpoint and audit path change while the entry — payload,
/// signature, index — stays exactly what it was.
pub fn put(conn: Connection, record: Record) -> Result(Nil, sqlite.Error) {
  sqlite.exec(
    conn,
    "INSERT INTO rekor_records
       (key_tag, apex, action, dsse_payload, dsse_signature, log_id,
        log_index, checkpoint, inclusion_path, integrated_at, verified_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (key_tag, action) DO UPDATE SET
       apex = excluded.apex,
       dsse_payload = excluded.dsse_payload,
       dsse_signature = excluded.dsse_signature,
       log_id = excluded.log_id,
       log_index = excluded.log_index,
       checkpoint = excluded.checkpoint,
       inclusion_path = excluded.inclusion_path,
       integrated_at = excluded.integrated_at,
       verified_at = excluded.verified_at",
    [
      VInt(record.key_tag),
      Text(record.apex),
      Text(record.action),
      Blob(record.dsse_payload),
      Blob(record.dsse_signature),
      Blob(record.log_id),
      VInt(record.log_index),
      Blob(record.checkpoint),
      Blob(record.inclusion_path),
      VInt(record.integrated_at),
      VInt(record.verified_at),
    ],
  )
  |> result.replace(Nil)
}

/// One key tag's records, newest verification first.
pub fn for_key_tag(
  conn: Connection,
  key_tag: Int,
) -> Result(List(Record), sqlite.Error) {
  let sql =
    "SELECT key_tag, apex, action, dsse_payload, dsse_signature, log_id,
            log_index, checkpoint, inclusion_path, integrated_at, verified_at
     FROM rekor_records WHERE key_tag = ?
     ORDER BY verified_at DESC, action"
  use rows <- result.try(sqlite.query(conn, sql, [VInt(key_tag)]))
  Ok(list.filter_map(rows, decode))
}

/// One record by key tag and action, for the idempotent republish path.
pub fn get(
  conn: Connection,
  key_tag: Int,
  action: String,
) -> Result(Result(Record, Nil), sqlite.Error) {
  use records <- result.try(for_key_tag(conn, key_tag))
  Ok(list.find(records, fn(record) { record.action == action }))
}

/// Every key tag with a verified record, for the dashboard and `/healthz`.
pub fn verified_key_tags(conn: Connection) -> Result(List(Int), sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT DISTINCT key_tag FROM rekor_records WHERE action != 'retire'",
      [],
    ),
  )
  Ok(
    list.filter_map(rows, fn(row) {
      case row {
        [sqlite.Int(tag)] -> Ok(tag)
        _ -> Error(Nil)
      }
    }),
  )
}

/// The proof blobs a zone serves for one key tag.
///
/// `retire` entries are monitor breadcrumbs (§2): they are never served,
/// because a client that enforced them would be treating the log as a
/// revocation channel, which it is not.
pub fn servable(
  conn: Connection,
  key_tag: Int,
) -> Result(List(Record), sqlite.Error) {
  use records <- result.try(for_key_tag(conn, key_tag))
  Ok(list.filter(records, fn(record) { record.action != "retire" }))
}

fn decode(row: List(sqlite.Value)) -> Result(Record, Nil) {
  case row {
    [
      VInt(key_tag),
      Text(apex),
      Text(action),
      Blob(payload),
      Blob(signature),
      Blob(log_id),
      VInt(log_index),
      Blob(checkpoint),
      Blob(path),
      VInt(integrated_at),
      VInt(verified_at),
    ] ->
      Ok(Record(
        key_tag,
        apex,
        action,
        payload,
        signature,
        log_id,
        log_index,
        checkpoint,
        path,
        integrated_at,
        verified_at,
      ))
    _ -> Error(Nil)
  }
}
