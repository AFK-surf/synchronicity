//// The `rekor_records` table: the proofs this zone serves, and the only
//// thing the publish gate consults.
////
//// A row is written only after the proof has been verified locally by the
//// same rules the client applies (`rekor/publish`), so `verified_at` means
//// *this service checked it*, not *the log said so*. Replicas need nothing
//// beyond the row itself: a proof is public data and rides the existing
//// operator-owned replication.
////
//// A row's identity is `(keyset_sha256, action)` — the SHA-256 over the
//// claimed set's canonical digests, because an entry claims a *set* of
//// keys, not one. The keys themselves live in `rekor_record_keys`, one row
//// per claimed key, which is what the publish gate joins against: "is the
//// active CSK covered by a verified record" is a lookup by key digest, and
//// a key tag is a 16-bit checksum two keys can share.

import gleam/list
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Blob, Int as VInt, Text}

pub type Record {
  Record(
    /// SHA-256 over the claimed set's canonical hex digests — the identity.
    keyset_sha256: BitArray,
    apex: String,
    action: String,
    /// The in-toto Statement, byte-exact — the DSSE PAE preimage.
    statement: BitArray,
    /// The log's `canonicalizedBody`, verbatim — the Merkle leaf preimage,
    /// carrying the entry signature and the signer's certificate.
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
    /// The claimed keys: `#(sha256(dnskey_rdata), key_tag)` per key.
    keys: List(#(BitArray, Int)),
  )
}

/// Writes a record, replacing the one for this key set and action.
///
/// Re-publishing is a refresh, not a second entry: the tree has grown, so
/// the checkpoint and audit path change while the entry — payload,
/// signature, index — stays exactly what it was.
pub fn put(conn: Connection, record: Record) -> Result(Nil, sqlite.Error) {
  // One transaction, because this is an INSERT, a DELETE and one INSERT per
  // claimed key, and the states in between are not merely stale — they are
  // *wrong in a way that reads as fact*. A crash after the DELETE leaves a
  // record with no key rows, and both questions the rest of the service asks
  // then answer "this key was never logged": `covered` refuses every publish
  // the gate guards, and `servable` quietly stops serving the proof at
  // `_synchronicity-rekor.<apex>` while the row explaining it still exists.
  use <- sqlite.transaction(conn, fn(e) { e })

  use _ <- result.try(
    sqlite.exec(
      conn,
      "INSERT INTO rekor_records
       (keyset_sha256, apex, action, statement, canonicalized_body,
        log_id, log_index, checkpoint, inclusion_path, chainless,
        integrated_at, verified_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (keyset_sha256, action) DO UPDATE SET
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
        Blob(record.keyset_sha256),
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
    ),
  )
  use _ <- result.try(
    sqlite.exec(
      conn,
      "DELETE FROM rekor_record_keys WHERE keyset_sha256 = ? AND action = ?",
      [Blob(record.keyset_sha256), Text(record.action)],
    ),
  )
  record.keys
  |> list.try_each(fn(key) {
    sqlite.exec(
      conn,
      "INSERT INTO rekor_record_keys (keyset_sha256, action, key_sha256, key_tag)
       VALUES (?, ?, ?, ?)",
      [
        Blob(record.keyset_sha256),
        Text(record.action),
        Blob(key.0),
        VInt(key.1),
      ],
    )
    |> result.replace(Nil)
  })
}

/// One record by key-set identity and action, for the idempotent republish
/// path.
pub fn get(
  conn: Connection,
  keyset_sha256: BitArray,
  action: String,
) -> Result(Result(Record, Nil), sqlite.Error) {
  use records <- result.try(
    select(conn, "WHERE r.keyset_sha256 = ? AND r.action = ?", [
      Blob(keyset_sha256),
      Text(action),
    ]),
  )
  Ok(case records {
    [record, ..] -> Ok(record)
    [] -> Error(Nil)
  })
}

/// Whether any non-retire record has been verified — a zone's first logged
/// set is a `create`, any later one a `rollover`.
pub fn any_verified(conn: Connection) -> Result(Bool, sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT 1 FROM rekor_records WHERE action != 'retire' LIMIT 1",
      [],
    ),
  )
  Ok(!list.is_empty(rows))
}

/// Whether a key (by rdata digest) is claimed by any verified, non-retire
/// record — the publish gate's whole question.
pub fn covered(
  conn: Connection,
  key_sha256: BitArray,
) -> Result(Bool, sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT 1 FROM rekor_record_keys k
     JOIN rekor_records r
       ON r.keyset_sha256 = k.keyset_sha256 AND r.action = k.action
     WHERE k.key_sha256 = ? AND r.action != 'retire'
     LIMIT 1",
      [Blob(key_sha256)],
    ),
  )
  Ok(!list.is_empty(rows))
}

/// The proof records a zone serves: every verified record that could
/// authorize an answer the zone is capable of giving, newest first.
///
/// Two filters, for two different reasons.
///
/// `retire` entries are monitor breadcrumbs (§2) and are never served,
/// because a client that enforced them would be treating the log as a
/// revocation channel, which it is not.
///
/// The rest are held to `live_keys` — the digests of the DNSKEY rdata the
/// zone currently publishes. A proof authorizes an answer when the key that
/// signed it is a member of the proof's key set, so a claim covering no
/// live key can never authorize anything: it is history. Keeping it in the
/// table is how an operator compares monitor reports against what they
/// published; serving it would cost every client a chain walk it can only
/// reject, and cost the zone bytes at an owner name a provider caps.
///
/// An empty `live_keys` means "the caller does not know yet" — an external
/// deployment that has booted but not yet observed the provider's keys — and
/// serves everything, so a boot never blanks the proofs it already has.
pub fn servable(
  conn: Connection,
  live_keys: List(BitArray),
) -> Result(List(Record), sqlite.Error) {
  case live_keys {
    [] -> select(conn, "WHERE r.action != 'retire'", [])
    _ -> {
      let placeholders =
        live_keys |> list.map(fn(_) { "?" }) |> string.join(",")
      let where_clause = "WHERE r.action != 'retire'
           AND EXISTS (SELECT 1 FROM rekor_record_keys k
                        WHERE k.keyset_sha256 = r.keyset_sha256
                          AND k.action = r.action
                          AND k.key_sha256 IN (" <> placeholders <> "))"
      select(conn, where_clause, list.map(live_keys, Blob))
    }
  }
}

fn select(
  conn: Connection,
  where_clause: String,
  values: List(sqlite.Value),
) -> Result(List(Record), sqlite.Error) {
  let sql = "SELECT r.keyset_sha256, r.apex, r.action, r.statement,
            r.canonicalized_body, r.log_id, r.log_index, r.checkpoint,
            r.inclusion_path, r.chainless, r.integrated_at, r.verified_at
     FROM rekor_records r " <> where_clause <> " ORDER BY r.verified_at DESC, r.action"
  use rows <- result.try(sqlite.query(conn, sql, values))
  rows
  |> list.filter_map(decode)
  |> list.try_map(fn(record) {
    use keys <- result.try(keys_of(conn, record.keyset_sha256, record.action))
    Ok(Record(..record, keys: keys))
  })
}

fn keys_of(
  conn: Connection,
  keyset_sha256: BitArray,
  action: String,
) -> Result(List(#(BitArray, Int)), sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT key_sha256, key_tag FROM rekor_record_keys
     WHERE keyset_sha256 = ? AND action = ?
     ORDER BY key_tag, key_sha256",
      [Blob(keyset_sha256), Text(action)],
    ),
  )
  Ok(
    list.filter_map(rows, fn(row) {
      case row {
        [Blob(sha256), VInt(tag)] -> Ok(#(sha256, tag))
        _ -> Error(Nil)
      }
    }),
  )
}

fn decode(row: List(sqlite.Value)) -> Result(Record, Nil) {
  case row {
    [
      Blob(keyset_sha256),
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
      Ok(
        Record(
          keyset_sha256,
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
          [],
        ),
      )
    _ -> Error(Nil)
  }
}
