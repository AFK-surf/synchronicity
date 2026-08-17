//// Primary-only signature freshness: hourly, republish the zone when the
//// soonest RRSIG expiry is inside the refresh window (default 7 days of a
//// 14-day validity). Replicas therefore have days of slack, not minutes.
////
//// The other half of what §10.3 asks of a primary — keeping this service's
//// own TUF material young — is `jobs/tuf_refresh`, a sibling rather than a
//// leg of this job, because the external-mode tree has no re-sign job for
//// it to ride along with.

import dnssec/keys.{type Csk}
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/io
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import gleam/string
import store/db
import store/sqlite
import zone/publish

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

const check_interval_ms = 3_600_000

pub type Msg {
  Tick
}

type State {
  State(db_path: String, csk: Csk, subject: Subject(Msg))
}

/// The re-sign job as a supervised child: an hourly self-timer. A crash
/// mid-check is contained and restarted by the supervisor — DNS serving
/// never goes down with it.
pub fn supervised(
  db_path: String,
  csk: Csk,
) -> supervision.ChildSpecification(Nil) {
  supervision.worker(fn() {
    let builder =
      actor.new_with_initialiser(1000, fn(subject) {
        let _ = process.send_after(subject, check_interval_ms, Tick)
        actor.initialised(State(db_path, csk, subject))
        |> Ok
      })
      |> actor.on_message(handle)
    use started <- result.try(actor.start(builder))
    Ok(actor.Started(started.pid, Nil))
  })
}

fn handle(state: State, msg: Msg) -> actor.Next(State, Msg) {
  let Tick = msg
  run_once(state.db_path, state.csk)
  let _ = process.send_after(state.subject, check_interval_ms, Tick)
  actor.continue(state)
}

/// One check; exposed so tests can drive it without the timer.
pub fn run_once(db_path: String, csk: Csk) -> Nil {
  // Deliberately not pooled: this hourly job needs a writer, and the API
  // pool's workers are sized for request traffic — an owned short-lived
  // connection cannot starve it. Pools are for request/serving paths.
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
          // The re-sign path, which the transparency gate does not apply
          // to: this emits records clients already accept, and refusing it
          // would let the zone go bogus in `sig_validity` days — turning a
          // transparency gap into a DNSSEC outage.
          case publish.publish_resign(conn, csk, now, "system:resign") {
            Ok(serial) -> {
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
