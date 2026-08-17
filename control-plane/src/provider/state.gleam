//// The `provider_sync_state` and `observed_zone_keys` tables: what the
//// reconciler last did, and which provider keys the watcher has seen.
////
//// One row of sync state per deployment. Desired state is never stored —
//// it is a pure function of the product tables — so there is nothing here
//// to replay or drift from; `applied_hash` is the identity of the set last
//// confirmed applied, which is `/healthz`'s cheap "in sync?" answer.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Blob, Int as VInt, Null, Text}

fn string_join(parts: List(String), with: String) -> String {
  string.join(parts, with)
}

pub type SyncState {
  SyncState(
    provider: String,
    provider_zone_id: String,
    applied_hash: Option(BitArray),
    last_synced_serial: Option(Int),
    last_ok_at: Option(Int),
    last_attempt_at: Int,
    last_error: Option(String),
    last_error_at: Option(Int),
  )
}

pub fn get(conn: Connection) -> Result(Result(SyncState, Nil), sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT provider, provider_zone_id, applied_hash, last_synced_serial,
            last_ok_at, last_attempt_at, last_error, last_error_at
     FROM provider_sync_state WHERE id = 1",
      [],
    ),
  )
  Ok(case rows {
    [
      [
        Text(provider),
        Text(zone_id),
        hash,
        serial,
        ok_at,
        VInt(attempt_at),
        error,
        error_at,
      ],
    ] ->
      Ok(SyncState(
        provider,
        zone_id,
        optional_blob(hash),
        optional_int(serial),
        optional_int(ok_at),
        attempt_at,
        optional_text(error),
        optional_int(error_at),
      ))
    _ -> Error(Nil)
  })
}

/// Records a successful sync: the hash and serial applied, the error
/// cleared.
pub fn record_ok(
  conn: Connection,
  provider: String,
  zone_id: String,
  applied_hash: BitArray,
  serial: Int,
  now: Int,
) -> Result(Nil, sqlite.Error) {
  upsert(conn, provider, zone_id, [
    Blob(applied_hash),
    VInt(serial),
    VInt(now),
    VInt(now),
    Null,
    Null,
  ])
}

/// Records a failed attempt; the last applied hash and serial stand — the
/// provider still holds whatever was last applied.
pub fn record_error(
  conn: Connection,
  provider: String,
  zone_id: String,
  message: String,
  now: Int,
) -> Result(Nil, sqlite.Error) {
  use current <- result.try(get(conn))
  let #(hash, serial, ok_at) = case current {
    Ok(state) -> #(
      blob_or_null(state.applied_hash),
      int_or_null(state.last_synced_serial),
      int_or_null(state.last_ok_at),
    )
    Error(Nil) -> #(Null, Null, Null)
  }
  upsert(conn, provider, zone_id, [
    hash,
    serial,
    ok_at,
    VInt(now),
    Text(message),
    VInt(now),
  ])
}

fn upsert(
  conn: Connection,
  provider: String,
  zone_id: String,
  values: List(sqlite.Value),
) -> Result(Nil, sqlite.Error) {
  sqlite.exec(
    conn,
    "INSERT INTO provider_sync_state
       (id, provider, provider_zone_id, applied_hash, last_synced_serial,
        last_ok_at, last_attempt_at, last_error, last_error_at)
     VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (id) DO UPDATE SET
       provider = excluded.provider,
       provider_zone_id = excluded.provider_zone_id,
       applied_hash = excluded.applied_hash,
       last_synced_serial = excluded.last_synced_serial,
       last_ok_at = excluded.last_ok_at,
       last_attempt_at = excluded.last_attempt_at,
       last_error = excluded.last_error,
       last_error_at = excluded.last_error_at",
    [Text(provider), Text(zone_id), ..values],
  )
  |> result.replace(Nil)
}

// ------------------------------------------------- observed provider keys

pub type ObservedKey {
  ObservedKey(
    key_sha256: BitArray,
    key_tag: Int,
    dnskey_rdata: BitArray,
    first_seen: Int,
    last_seen: Int,
    logged_at: Option(Int),
  )
}

pub fn observed_keys(
  conn: Connection,
) -> Result(List(ObservedKey), sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT key_sha256, key_tag, dnskey_rdata, first_seen, last_seen,
            logged_at
     FROM observed_zone_keys ORDER BY key_tag, key_sha256",
      [],
    ),
  )
  Ok(
    list.filter_map(rows, fn(row) {
      case row {
        [Blob(sha256), VInt(tag), Blob(rdata), VInt(first), VInt(last), logged] ->
          Ok(ObservedKey(sha256, tag, rdata, first, last, optional_int(logged)))
        _ -> Error(Nil)
      }
    }),
  )
}

/// Replaces the observed set with what the wire answered just now: rows for
/// keys no longer served are dropped, surviving rows keep `first_seen` and
/// `logged_at`, new rows start unlogged.
pub fn record_observed(
  conn: Connection,
  keys: List(#(BitArray, Int, BitArray)),
  now: Int,
) -> Result(Nil, sqlite.Error) {
  use _ <- result.try(case keys {
    [] -> sqlite.exec(conn, "DELETE FROM observed_zone_keys", [])
    _ -> {
      let placeholders = keys |> list.map(fn(_) { "?" }) |> string_join(",")
      sqlite.exec(
        conn,
        "DELETE FROM observed_zone_keys WHERE key_sha256 NOT IN ("
          <> placeholders
          <> ")",
        list.map(keys, fn(key) { Blob(key.0) }),
      )
    }
  })
  keys
  |> list.try_each(fn(key) {
    let #(sha256, tag, rdata) = key
    sqlite.exec(
      conn,
      "INSERT INTO observed_zone_keys
         (key_sha256, key_tag, dnskey_rdata, first_seen, last_seen, logged_at)
       VALUES (?, ?, ?, ?, ?, NULL)
       ON CONFLICT (key_sha256) DO UPDATE SET last_seen = excluded.last_seen",
      [Blob(sha256), VInt(tag), Blob(rdata), VInt(now), VInt(now)],
    )
    |> result.replace(Nil)
  })
}

/// Stamps every currently observed key as covered by a logged claim.
pub fn record_logged(conn: Connection, now: Int) -> Result(Nil, sqlite.Error) {
  sqlite.exec(conn, "UPDATE observed_zone_keys SET logged_at = ?", [VInt(now)])
  |> result.replace(Nil)
}

fn optional_int(value: sqlite.Value) -> Option(Int) {
  case value {
    VInt(v) -> Some(v)
    _ -> None
  }
}

fn optional_blob(value: sqlite.Value) -> Option(BitArray) {
  case value {
    Blob(v) -> Some(v)
    _ -> None
  }
}

fn optional_text(value: sqlite.Value) -> Option(String) {
  case value {
    Text(v) -> Some(v)
    _ -> None
  }
}

fn blob_or_null(value: Option(BitArray)) -> sqlite.Value {
  case value {
    Some(v) -> Blob(v)
    None -> Null
  }
}

fn int_or_null(value: Option(Int)) -> sqlite.Value {
  case value {
    Some(v) -> VInt(v)
    None -> Null
  }
}
