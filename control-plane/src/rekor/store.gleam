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
    /// SHA-256 of the key's DER SubjectPublicKeyInfo — the identity. A key
    /// tag is a 16-bit checksum and two keys can share one, so the tag
    /// selects and this identifies.
    spki_sha256: BitArray,
    key_tag: Int,
    apex: String,
    action: String,
    /// The in-toto Statement, byte-exact — the DSSE PAE preimage.
    statement: BitArray,
    /// The log's `canonicalizedBody`, verbatim — the Merkle leaf preimage,
    /// carrying the entry signature and the signer's key.
    canonicalized_body: BitArray,
    log_id: BitArray,
    log_index: Int,
    checkpoint: BitArray,
    inclusion_path: BitArray,
    /// Whether this entry carries no DNSSEC chain. Only ever a `retire`: a
    /// retired zone may have no DS left to build one from, and clients
    /// refuse a retire as authorization outright, so the exception cannot be
    /// turned into an evasion (§5.2).
    chainless: Bool,
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
       (spki_sha256, key_tag, apex, action, statement, canonicalized_body,
        log_id, log_index, checkpoint, inclusion_path, chainless,
        integrated_at, verified_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (spki_sha256, action) DO UPDATE SET
       key_tag = excluded.key_tag,
       apex = excluded.apex,
       statement = excluded.statement,
       canonicalized_body = excluded.canonicalized_body,
       log_id = excluded.log_id,
       log_index = excluded.log_index,
       checkpoint = excluded.checkpoint,
       inclusion_path = excluded.inclusion_path,
       chainless = excluded.chainless,
       integrated_at = excluded.integrated_at,
       verified_at = excluded.verified_at",
    [
      Blob(record.spki_sha256),
      VInt(record.key_tag),
      Text(record.apex),
      Text(record.action),
      Blob(record.statement),
      Blob(record.canonicalized_body),
      Blob(record.log_id),
      VInt(record.log_index),
      Blob(record.checkpoint),
      Blob(record.inclusion_path),
      VInt(case record.chainless {
        True -> 1
        False -> 0
      }),
      VInt(record.integrated_at),
      VInt(record.verified_at),
    ],
  )
  |> result.replace(Nil)
}

/// One key tag's records, newest verification first.
///
/// A *list*, and a tag can legitimately select more than one key: the tag is
/// a 16-bit checksum, so two keys can share it. The caller tries each.
pub fn for_key_tag(
  conn: Connection,
  key_tag: Int,
) -> Result(List(Record), sqlite.Error) {
  let sql =
    "SELECT spki_sha256, key_tag, apex, action, statement, canonicalized_body,
            log_id, log_index, checkpoint, inclusion_path, chainless,
            integrated_at, verified_at
     FROM rekor_records WHERE key_tag = ?
     ORDER BY verified_at DESC, action"
  use rows <- result.try(sqlite.query(conn, sql, [VInt(key_tag)]))
  Ok(list.filter_map(rows, decode))
}

/// One record by key identity and action, for the idempotent republish path.
///
/// Keyed on the SPKI digest rather than the key tag: two keys sharing a tag
/// must not be able to read each other's row and conclude "already
/// published".
pub fn get(
  conn: Connection,
  spki_sha256: BitArray,
  key_tag: Int,
  action: String,
) -> Result(Result(Record, Nil), sqlite.Error) {
  use records <- result.try(for_key_tag(conn, key_tag))
  Ok(
    list.find(records, fn(record) {
      record.action == action && record.spki_sha256 == spki_sha256
    }),
  )
}

/// Every key tag with a verified record.
///
/// Its one caller is `rekor/publish`, which asks whether the key it is about
/// to publish already has a record. Neither the dashboard nor `/healthz`
/// reads it, despite what an earlier version of this comment claimed.
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
      Blob(spki_sha256),
      VInt(key_tag),
      Text(apex),
      Text(action),
      Blob(statement),
      Blob(canonicalized_body),
      Blob(log_id),
      VInt(log_index),
      Blob(checkpoint),
      Blob(path),
      VInt(chainless),
      VInt(integrated_at),
      VInt(verified_at),
    ] ->
      Ok(Record(
        spki_sha256,
        key_tag,
        apex,
        action,
        statement,
        canonicalized_body,
        log_id,
        log_index,
        checkpoint,
        path,
        chainless != 0,
        integrated_at,
        verified_at,
      ))
    _ -> Error(Nil)
  }
}
