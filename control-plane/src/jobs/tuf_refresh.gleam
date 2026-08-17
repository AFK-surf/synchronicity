//// Sigstore TUF freshness, in both primary modes
//// (docs/REKOR-ZONE-KEY.md §10.3): what is stored decides which
//// transparency-log shard this service submits to, and nothing else —
//// clients walk Sigstore's repository themselves. So the fetch needs no
//// command and has none: this job runs once at boot (a fresh control plane
//// holds no material at all, and absent material is always due) and then
//// hourly, refetching when the stored timestamp is within three days of
//// expiring.
////
//// It is a job of its own, not a leg of the re-sign job, because the
//// external-mode tree has no re-sign job to ride along with — and the key
//// watcher there reads the stored material on every tick while deliberately
//// never fetching, so a quarter-hourly loop never turns into a
//// quarter-hourly fetch.
////
//// Every failure is a log line and nothing more: the stored material
//// stands, and a control plane that stops fetching degrades to submitting
//// into the shard it last knew about, never to a failed cluster (§10.2).

import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/io
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import store/db
import store/sqlite
import tuf/fetch

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

const check_interval_ms = 3_600_000

pub type Msg {
  Tick
}

type State {
  State(db_path: String, subject: Subject(Msg))
}

/// The refresh job as a supervised child: an hourly self-timer after a
/// first tick at boot. A crash mid-fetch is contained and restarted by the
/// supervisor — DNS serving never goes down with it.
pub fn supervised(db_path: String) -> supervision.ChildSpecification(Nil) {
  supervision.worker(fn() {
    let builder =
      actor.new_with_initialiser(1000, fn(subject) {
        // Immediately, not one interval from now: a fresh control plane
        // holds no material, and absent material is always due. Waiting out
        // the first hour would leave `rekor/client.discover` without an
        // answer for exactly the window a deployment is being set up in.
        process.send(subject, Tick)
        actor.initialised(State(db_path, subject))
        |> Ok
      })
      |> actor.on_message(handle)
    use started <- result.try(actor.start(builder))
    Ok(actor.Started(started.pid, Nil))
  })
}

fn handle(state: State, msg: Msg) -> actor.Next(State, Msg) {
  let Tick = msg
  run_once(state.db_path)
  let _ = process.send_after(state.subject, check_interval_ms, Tick)
  actor.continue(state)
}

/// One check; exposed so tests can drive it without the timer.
pub fn run_once(db_path: String) -> Nil {
  run_once_at(db_path, fetch.http(fetch.url()), now_unix())
}

/// The same check against an injected TUF repository at an injected moment,
/// so the suite walks the checked-in fixture chain at the time it was
/// fetched instead of expiring with it — and so no test run ever reaches
/// out to Sigstore by accident.
pub fn run_once_at(db_path: String, repo: fetch.Repo, now: Int) -> Nil {
  // Deliberately not pooled, exactly as `resign`: this hourly job needs a
  // writer, and an owned short-lived connection cannot starve the API pool.
  case db.open_primary(db_path) {
    Error(_) -> io.println_error("tuf-refresh: database unavailable")
    Ok(conn) -> {
      case fetch.due(conn, now) {
        False -> Nil
        True ->
          case fetch.refresh(conn, repo, fetch.url(), now) {
            Ok(outcome) ->
              case outcome.changed {
                True ->
                  io.println(
                    "tuf-refresh: root "
                    <> int.to_string(outcome.root_version)
                    <> " timestamp "
                    <> int.to_string(outcome.timestamp_version),
                  )
                False -> Nil
              }
            Error(why) -> io.println_error("tuf-refresh: fetch failed: " <> why)
          }
      }
      sqlite.close(conn)
    }
  }
}
