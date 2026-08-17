//// External-mode reconciliation: converge the provider-hosted zone on the
//// record set the database implies (docs/EXTERNAL-DNS-PROVIDER.md).
////
//// Modeled on `jobs/resign`: a supervised actor with a self-rescheduling
//// hourly sweep and an owned short-lived connection per pass. Two additions
//// to that template: the actor registers a name so a committed product
//// mutation can `poke` it — convergence in seconds instead of an hour —
//// and the pass short-circuits on a stored hash of the last applied set,
//// which makes the sweep's common case one SELECT and no provider traffic.
////
//// There is deliberately no outbox. Desired state is a pure function of
//// the current tables (the property `zone/build` exploits), so
//// desired-plus-sweep is simpler than any queue and, unlike one,
//// self-heals drift introduced behind our back in the provider's console.
////
//// Failure posture matches the codebase: a provider outage degrades to a
//// stale-but-serving zone — the provider keeps answering with whatever was
//// last applied — never to a failed control plane. Staleness is recorded
//// in `provider_sync_state` where `/healthz` reports it, and a conflict
//// (a record below the apex we did not render, with no ownership marker)
//// stops the pass without touching anything: the reconciler must be
//// incapable of eating a zone it does not own.
////
//// A pass can also *partly* apply. Records go out independently and a
//// refused one is reported rather than aborting the rest, because the
//// records this zone publishes are not equally urgent and the big ones are
//// not the important ones: a transparency proof the provider refuses on
//// size must never be the reason a device revocation failed to land. A
//// partial pass does not advance `applied_hash`, so the next sweep
//// recomputes the diff and retries exactly what is still missing.

import gleam/erlang/process.{type Name, type Subject}
import gleam/int
import gleam/io
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import gleam/string
import provider/diff
import provider/provider.{type Provider}
import provider/state
import rekor/gate
import rekor/store as rekor_store
import store/db
import store/sqlite.{type Connection}
import zone/model
import zone/render_external

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

/// The repair sweep. Short enough that drift — a record edited by hand at
/// the provider, a change lost to a failed apply — is corrected in minutes
/// rather than hours, and cheap when nothing has moved: the hash
/// short-circuit makes an unchanged pass one SELECT and no provider call.
const sweep_interval_ms = 300_000

pub type Msg {
  Tick
}

type State {
  State(
    db_path: String,
    provider: Provider,
    provider_name: String,
    zone_id: String,
    subject: Subject(Msg),
  )
}

/// Nudges a running reconciler by its registered name — sent by
/// `zone_mutation` after its transaction commits, and by anything else
/// that changed what the zone should say. Falling on the floor is fine:
/// the hourly sweep repairs a missed poke.
pub fn poke(name: Name(Msg)) -> Nil {
  case process.named_subject(name) {
    subject -> process.send(subject, Tick)
  }
}

pub fn supervised(
  name: Name(Msg),
  db_path: String,
  prov: Provider,
  provider_name: String,
  zone_id: String,
) -> supervision.ChildSpecification(Nil) {
  supervision.worker(fn() {
    let builder =
      actor.new_with_initialiser(1000, fn(subject) {
        // Immediately, not one interval from now: a primary that has just
        // booted has a provider zone of unknown freshness, and on a *first*
        // boot it has no records out there at all. Waiting out a sweep
        // before the first pass would leave the zone unpublished for that
        // long, which is the one window where nothing else pokes.
        //
        // This tick and nothing else: `handle` re-arms after every pass, so
        // also scheduling one here would start a second, permanent timer
        // chain beside the first and sweep at twice the stated interval.
        process.send(subject, Tick)
        actor.initialised(State(db_path, prov, provider_name, zone_id, subject))
        |> actor.returning(subject)
        |> Ok
      })
      |> actor.on_message(handle)
      |> actor.named(name)
    use started <- result.try(actor.start(builder))
    Ok(actor.Started(started.pid, Nil))
  })
}

fn handle(state: State, msg: Msg) -> actor.Next(State, Msg) {
  let Tick = msg
  run_once(state.db_path, state.provider, state.provider_name, state.zone_id)
  let _ = process.send_after(state.subject, sweep_interval_ms, Tick)
  actor.continue(state)
}

/// One pass; exposed so tests and the CLI drive it without the timer.
pub fn run_once(
  db_path: String,
  prov: Provider,
  provider_name: String,
  zone_id: String,
) -> Nil {
  // Deliberately not pooled, exactly as `resign`: this job needs a writer
  // for its state row, and an owned short-lived connection cannot starve
  // the API pool.
  case db.open_primary(db_path) {
    Error(_) -> io.println_error("provider-sync: database unavailable")
    Ok(conn) -> {
      run_once_with(conn, prov, provider_name, zone_id, now_unix())
      sqlite.close(conn)
    }
  }
}

/// The pass body over an open connection and an injected clock — what the
/// suite drives with a fake provider.
pub fn run_once_with(
  conn: Connection,
  prov: Provider,
  provider_name: String,
  zone_id: String,
  now: Int,
) -> Nil {
  case pass(conn, prov, zone_id, now) {
    Ok(Fresh) -> Nil
    Ok(Converged(serial, hash, changes, shed)) -> {
      let _ = state.record_ok(conn, provider_name, zone_id, hash, serial, now)
      let _ = audit_sync(conn, now, serial, changes, shed, [])
      io.println(
        "provider-sync: applied serial "
        <> int.to_string(serial)
        <> " ("
        <> describe_changes(changes)
        <> describe_shed(shed)
        <> ")",
      )
    }
    Ok(Partial(serial, changes, failures)) -> {
      let rendered = render_failures(failures)
      let _ = state.record_partial(conn, provider_name, zone_id, rendered, now)
      let _ = audit_sync(conn, now, serial, changes, 0, failures)
      io.println_error(
        "provider-sync: serial "
        <> int.to_string(serial)
        <> " partly applied — the provider refused "
        <> rendered,
      )
    }
    Error(why) -> {
      let _ = state.record_error(conn, provider_name, zone_id, why, now)
      io.println_error("provider-sync: " <> why)
    }
  }
}

type Outcome {
  /// The stored hash already matches the desired set — nothing to do, no
  /// provider traffic. The sweep's common case.
  Fresh
  Converged(serial: Int, hash: BitArray, changes: provider.Changes, shed: Int)
  /// The change set went out and the provider refused part of it. The hash
  /// is deliberately absent: the zone is not the set we rendered, so nothing
  /// may record it as applied, and the next sweep recomputes the diff and
  /// retries what is still missing.
  Partial(
    serial: Int,
    changes: provider.Changes,
    failures: List(provider.Failure),
  )
}

fn pass(
  conn: Connection,
  prov: Provider,
  _zone_id: String,
  _now: Int,
) -> Result(Outcome, String) {
  use input <- result.try(
    model.read(conn)
    |> result.map_error(fn(e) { "reading zone: " <> string.inspect(e) }),
  )
  use omit_members <- result.try(omit_members(conn))
  use desired <- result.try(
    render_external.render_gated(input, omit_members)
    |> result.map_error(fn(e) { "rendering: " <> string.inspect(e) }),
  )
  let hash = render_external.desired_hash(desired)
  use stored <- result.try(
    state.get(conn)
    |> result.map_error(fn(e) { "reading sync state: " <> string.inspect(e) }),
  )
  let fresh = case stored {
    Ok(s) ->
      s.applied_hash == Some(hash)
      && s.last_synced_serial == Some(input.meta.soa_serial)
      && s.last_error == option.None
      // A pass the provider partly refused left records missing, so the
      // short-circuit must not fire until a later pass gets them out.
      && s.last_failures == option.None
    Error(Nil) -> False
  }
  use <- fresh_guard(fresh)
  use existing <- result.try(
    prov.list() |> result.map_error(fn(e) { "provider list: " <> e }),
  )
  use changes <- result.try(
    diff.diff(desired, existing) |> result.map_error(describe_conflict),
  )
  use applied <- result.try(case provider.no_changes(changes) {
    True -> Ok(provider.Applied(0, []))
    False ->
      prov.apply(changes) |> result.map_error(fn(e) { "provider apply: " <> e })
  })
  case applied.failed {
    [] -> Ok(Converged(input.meta.soa_serial, hash, changes, input.rekor_shed))
    failures -> Ok(Partial(input.meta.soa_serial, changes, failures))
  }
}

/// Armed gate and no verified record: omit membership TXT. A store error
/// fails the pass rather than guessing. The declaration still renders.
fn omit_members(conn: Connection) -> Result(Bool, String) {
  case gate.required() {
    False -> Ok(False)
    True ->
      rekor_store.any_verified(conn)
      |> result.map(fn(any) { !any })
      |> result.map_error(fn(e) {
        "reading rekor records: " <> string.inspect(e)
      })
  }
}

fn fresh_guard(
  fresh: Bool,
  next: fn() -> Result(Outcome, String),
) -> Result(Outcome, String) {
  case fresh {
    True -> Ok(Fresh)
    False -> next()
  }
}

/// Each conflict with the remedy that actually applies to it. The apex is
/// this deployment's alone, so a record below it either belongs on a sibling
/// name or is a marker somebody else wrote.
fn describe_conflict(conflict: diff.Conflict) -> String {
  case conflict {
    diff.Foreign(name, value) ->
      "conflict: "
      <> name
      <> " holds a record this zone did not render ("
      <> value
      <> ") and no ownership marker — refusing to touch it. The apex is this"
      <> " deployment's alone: move that record to a sibling name"
    diff.MarkerMismatch(name, value) ->
      "conflict: "
      <> name
      <> " holds an ownership marker this deployment did not write ("
      <> value
      <> "). Another control plane is publishing into this apex, or an older"
      <> " build left a marker of a narrower scope — delete the record and"
      <> " this deployment will write its own"
  }
}

fn describe_changes(changes: provider.Changes) -> String {
  "+"
  <> int.to_string(list.length(changes.create))
  <> " ~"
  <> int.to_string(list.length(changes.replace))
  <> " -"
  <> int.to_string(list.length(changes.delete))
}

/// A dropped proof is said out loud. A cap nobody is told about reads as
/// "everything is published" when it is not.
fn describe_shed(shed: Int) -> String {
  case shed {
    0 -> ""
    n -> ", " <> int.to_string(n) <> " older proof(s) over budget"
  }
}

fn render_failures(failures: List(provider.Failure)) -> String {
  failures
  |> list.map(fn(failure) { failure.name <> " (" <> failure.reason <> ")" })
  |> string.join("; ")
}

fn audit_sync(
  conn: Connection,
  now: Int,
  serial: Int,
  changes: provider.Changes,
  shed: Int,
  failures: List(provider.Failure),
) -> Result(Nil, sqlite.Error) {
  sqlite.exec(
    conn,
    "INSERT INTO audit_log (at, actor, org_id, action, detail)
     VALUES (?, 'system:provider-sync', NULL, 'provider.sync', ?)",
    [
      sqlite.Int(now),
      sqlite.Text(
        json.to_string(
          json.object([
            #("serial", json.int(serial)),
            #("create", json.int(list.length(changes.create))),
            #("replace", json.int(list.length(changes.replace))),
            #("delete", json.int(list.length(changes.delete))),
            #("proofs_shed", json.int(shed)),
            #("refused", json.int(list.length(failures))),
          ]),
        ),
      ),
    ],
  )
  |> result.replace(Nil)
}
