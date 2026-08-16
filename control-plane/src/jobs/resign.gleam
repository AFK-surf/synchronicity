//// Primary-only signature freshness: hourly, republish the zone when the
//// soonest RRSIG expiry is inside the refresh window (default 7 days of a
//// 14-day validity). Replicas therefore have days of slack, not minutes.
////
//// The same hour also keeps the relayed TUF material young
//// (docs/REKOR-ZONE-KEY.md §10.3): when the stored timestamp is within
//// three days of expiring, refetch it. A failed refetch is logged and
//// nothing else — clients keep the pins they have, and a control plane
//// that stops fetching degrades to a frozen pin set rather than a failed
//// cluster (§10.2).

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
import tuf/fetch
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
  run_once_at(db_path, csk, fetch.http(fetch.url()), now_unix())
}

/// The same check against an injected TUF repository, so the suite can
/// exercise the refetch leg without egress — and so no test run ever
/// reaches out to Sigstore by accident.
pub fn run_once_with(db_path: String, csk: Csk, repo: fetch.Repo) -> Nil {
  run_once_at(db_path, csk, repo, now_unix())
}

/// The same check at an injected moment, so a test can walk the checked-in
/// TUF fixture chain at the time it was fetched instead of expiring with it.
pub fn run_once_at(
  db_path: String,
  csk: Csk,
  repo: fetch.Repo,
  now: Int,
) -> Nil {
  // Deliberately not pooled: this hourly job needs a writer, and the API
  // pool's workers are sized for request traffic — an owned short-lived
  // connection cannot starve it. Pools are for request/serving paths.
  case db.open_primary(db_path) {
    Error(_) -> io.println_error("resign: database unavailable")
    Ok(conn) -> {
      // Refetch first, so a republish this hour carries the fresher bundle
      // rather than waiting an hour to serve it.
      refresh_tuf(conn, csk, repo, now)
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

/// Refetches Sigstore's TUF metadata when the stored timestamp is within
/// three days of expiring (§10.3), and republishes when it changed — the
/// zone is presigned, so stored material a client can see only exists after
/// a publish, and waiting for the next RRSIG-due republish could sit on a
/// fresher bundle for days.
///
/// Every failure is a log line and nothing more: the zone keeps relaying
/// whatever it had, and clients keep the pins they have. A control plane
/// that stops fetching degrades to a frozen pin set, never to a failed
/// cluster.
fn refresh_tuf(
  conn: sqlite.Connection,
  csk: Csk,
  repo: fetch.Repo,
  now: Int,
) -> Nil {
  case fetch.due(conn, now) {
    False -> Nil
    True ->
      case fetch.refresh(conn, repo, fetch.url(), now) {
        Ok(outcome) ->
          case outcome.changed {
            True -> {
              io.println(
                "resign: tuf refreshed, root "
                <> int.to_string(outcome.root_version)
                <> " timestamp "
                <> int.to_string(outcome.timestamp_version),
              )
              case publish.publish(conn, csk, now, "system:tuf-refresh") {
                Ok(serial) ->
                  io.println(
                    "resign: republished for tuf, serial "
                    <> int.to_string(serial),
                  )
                Error(e) ->
                  io.println_error(
                    "resign: publish after tuf refresh failed: "
                    <> string.inspect(e),
                  )
              }
            }
            False -> Nil
          }
        Error(why) -> io.println_error("resign: tuf refresh failed: " <> why)
      }
  }
}
