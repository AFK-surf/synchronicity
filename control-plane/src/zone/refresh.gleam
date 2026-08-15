//// The replica refresh contract: an external process (litestream
//// restore, rsync, anything) replaces the database file via write-new +
//// atomic rename. We notice by polling the file's mtime (and accept a
//// loopback /reload poke for immediacy), reopen read-only, and swap the
//// in-memory snapshot atomically. Failures keep the last good snapshot —
//// signatures are valid for days, staleness shows in /healthz, and a
//// database from a newer build is refused, never probed.

import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/result
import simplifile
import store/db
import store/migrate
import store/sqlite
import zone/snapshot

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

const poll_interval_ms = 10_000

/// Loads the zone from the database file and installs it. Every failure
/// leaves the current snapshot serving.
pub fn reload(db_path: String) -> Result(Int, String) {
  use conn <- result.try(
    db.open_read(db_path)
    |> result.map_error(fn(_) { "could not open " <> db_path }),
  )
  let outcome = {
    use version <- result.try(
      migrate.current_version(conn)
      |> result.map_error(fn(_) { "could not read schema version" }),
    )
    use Nil <- result.try(case version > migrate.build_version() {
      True ->
        Error(
          "database is schema v"
          <> int.to_string(version)
          <> " but this build knows v"
          <> int.to_string(migrate.build_version())
          <> " — refusing; keeping the current snapshot",
        )
      False -> Ok(Nil)
    })
    use snap <- result.try(snapshot.load(conn, now_unix()))
    snapshot.install(snap)
    Ok(snap.serial)
  }
  sqlite.close(conn)
  outcome
}

/// Starts the poll loop: reload whenever the file's mtime changes.
pub fn start_poll(db_path: String) -> Nil {
  process.spawn(fn() { loop(db_path, mtime_of(db_path)) })
  Nil
}

fn loop(db_path: String, last_mtime: Int) -> Nil {
  process.sleep(poll_interval_ms)
  let current = mtime_of(db_path)
  case current != last_mtime && current != 0 {
    True ->
      case reload(db_path) {
        Ok(serial) -> {
          io.println("replica: reloaded zone, serial " <> int.to_string(serial))
          loop(db_path, current)
        }
        Error(message) -> {
          io.println_error("replica: reload failed: " <> message)
          loop(db_path, current)
        }
      }
    False -> loop(db_path, last_mtime)
  }
}

fn mtime_of(path: String) -> Int {
  case simplifile.file_info(path) {
    Ok(info) -> info.mtime_seconds
    Error(_) -> 0
  }
}
