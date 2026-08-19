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
    /// The records the provider refused on the last pass that reached it,
    /// rendered for an operator to read. A pass can now succeed for most of
    /// a change set and be refused for part of it, and this is the only
    /// place that difference is visible.
    last_failures: Option(String),
    last_partial_at: Option(Int),
  )
}

pub fn get(conn: Connection) -> Result(Result(SyncState, Nil), sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT provider, provider_zone_id, applied_hash, last_synced_serial,
            last_ok_at, last_attempt_at, last_error, last_error_at,
            last_failures, last_partial_at
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
        failures,
        partial_at,
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
        optional_text(failures),
        optional_int(partial_at),
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
    Null,
    Null,
  ])
}

/// Records a pass the provider partly refused: the change set went out, some
/// records did not take. The applied hash and serial deliberately do *not*
/// advance — the zone is not the set we rendered — so the next sweep
/// recomputes the diff and retries exactly what is still missing.
pub fn record_partial(
  conn: Connection,
  provider: String,
  zone_id: String,
  failures: String,
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
    Null,
    Null,
    Text(failures),
    VInt(now),
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
    Null,
    Null,
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
        last_ok_at, last_attempt_at, last_error, last_error_at,
        last_failures, last_partial_at)
     VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (id) DO UPDATE SET
       provider = excluded.provider,
       provider_zone_id = excluded.provider_zone_id,
       applied_hash = excluded.applied_hash,
       last_synced_serial = excluded.last_synced_serial,
       last_ok_at = excluded.last_ok_at,
       last_attempt_at = excluded.last_attempt_at,
       last_error = excluded.last_error,
       last_error_at = excluded.last_error_at,
       last_failures = excluded.last_failures,
       last_partial_at = excluded.last_partial_at",
    [Text(provider), Text(zone_id), ..values],
  )
  |> result.replace(Nil)
}

/// How long the oldest key the watcher has seen but not yet logged has been
/// waiting, in seconds — `None` when every observed key is covered.
///
/// The one number that says whether the watch loop is keeping up with the
/// provider's rotations: a key that has been unlogged for longer than a
/// couple of intervals is a zone whose next answer may fail closed.
pub fn oldest_unlogged_age(
  conn: Connection,
  now: Int,
) -> Result(Option(Int), sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT min(first_seen) FROM observed_zone_keys WHERE logged_at IS NULL",
      [],
    ),
  )
  Ok(case rows {
    [[VInt(first_seen)]] -> Some(now - first_seen)
    _ -> None
  })
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
/// One transaction, for the reason `rekor/store.put` states about its own
/// DELETE-then-INSERT: the states in between are not merely stale, they are
/// wrong in a way that reads as fact. Two different readers act on this table
/// — the reconciler's gate arms when it is empty, and `zone/model.live_keys`
/// falls through to serving every non-retire proof record when it is — so a
/// crash between the delete and the inserts publishes a decision nobody made.
pub fn record_observed(
  conn: Connection,
  keys: List(#(BitArray, Int, BitArray)),
  now: Int,
) -> Result(Nil, sqlite.Error) {
  use <- sqlite.transaction(conn, fn(e) { e })
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

/// Stamps only the observed keys whose rdata digest is in `key_sha256s`.
/// Extra keys stay unlogged so the next watch tick retries them.
pub fn record_logged(
  conn: Connection,
  key_sha256s: List(BitArray),
  now: Int,
) -> Result(Nil, sqlite.Error) {
  case key_sha256s {
    [] -> Ok(Nil)
    _ -> {
      let placeholders =
        key_sha256s |> list.map(fn(_) { "?" }) |> string_join(",")
      sqlite.exec(
        conn,
        "UPDATE observed_zone_keys SET logged_at = ? WHERE key_sha256 IN ("
          <> placeholders
          <> ")",
        [VInt(now), ..list.map(key_sha256s, Blob)],
      )
      |> result.replace(Nil)
    }
  }
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
