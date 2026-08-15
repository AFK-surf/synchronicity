//// Primary-only signature freshness: hourly, republish the zone when the
//// soonest RRSIG expiry is inside the refresh window (default 7 days of a
//// 14-day validity). Replicas therefore have days of slack, not minutes.

import dnssec/keys.{type Csk}
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/string
import store/db
import store/sqlite
import zone/publish
import zone/snapshot

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

const check_interval_ms = 3_600_000

pub fn start(db_path: String, csk: Csk) -> Nil {
  process.spawn(fn() { loop(db_path, csk) })
  Nil
}

fn loop(db_path: String, csk: Csk) -> Nil {
  process.sleep(check_interval_ms)
  run_once(db_path, csk)
  loop(db_path, csk)
}

/// One check; exposed so tests can drive it without the timer.
pub fn run_once(db_path: String, csk: Csk) -> Nil {
  case db.open_primary(db_path) {
    Error(_) -> io.println_error("resign: database unavailable")
    Ok(conn) -> {
      let now = now_unix()
      let due =
        sqlite.query(
          conn,
          "SELECT min(p.sig_expires_at) - m.sig_refresh_before
           FROM presigned_rrsets p, zone_meta m",
          [],
        )
      case due {
        Ok([[sqlite.Int(threshold)]]) if now >= threshold -> {
          case publish.publish(conn, csk, now, "system:resign") {
            Ok(serial) -> {
              case snapshot.load(conn, now) {
                Ok(snap) -> snapshot.install(snap)
                Error(_) -> Nil
              }
              io.println(
                "resign: republished, serial " <> int.to_string(serial),
              )
            }
            Error(e) ->
              io.println_error("resign: publish failed: " <> string.inspect(e))
          }
        }
        Ok(_) -> Nil
        Error(e) ->
          io.println_error("resign: query failed: " <> string.inspect(e))
      }
      sqlite.close(conn)
    }
  }
}
