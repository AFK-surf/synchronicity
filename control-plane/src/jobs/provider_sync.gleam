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
//// That short-circuit is *time-bounded*, and has to be. Every input to it —
//// the applied hash, the SOA serial, the last error — is our own state, so
//// on its own it only ever asks "did we change anything", and a pass that
//// never lists the provider cannot see what the provider was told by
//// somebody else. The reconciler holds delete authority below the apex, and
//// that authority is the only thing standing between an API token and a
//// forged record in a zone this deployment owns; coupling it to our own
//// write traffic means the quietest tenant is repaired least often, which
//// is backwards. So the hash may skip a pass, but not indefinitely:
//// `reconcile_interval` is the longest a record nobody here wrote can sit
//// in the zone unseen.
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
import gleam/option.{type Option, Some}
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
/// the provider, a change lost to a failed apply — is corrected in minutes,
/// and cheap when nothing has moved: the hash short-circuit makes most passes
/// one SELECT and no provider call. Every `reconcile_interval` one of them
/// lists anyway, so "minutes" is the sweep and `reconcile_interval` is the
/// worst case.
const sweep_interval_ms = 300_000

/// How long the hash short-circuit may go on skipping the provider.
///
/// Seconds, against `last_ok_at`. Past this, a sweep lists and diffs even
/// when nothing on our side moved, which is what makes the "self-heals drift
/// introduced behind our back" claim above true rather than conditional on
/// the tenant happening to be busy.
///
/// The number is set by what a forged record has to outlive to be worth
/// planting: a client that reads one holds it for `render_external.ttl_data`
/// (300) plus the client's own trust grace (900, `DEFAULT_TRUST_GRACE` in
/// `crates/synch-net/src/dns.rs`), so 1200 seconds is the point past which
/// this sweep stops being the thing that bounds the exposure. 900 sits inside
/// that with a sweep to spare — three `sweep_interval_ms` ticks — and costs
/// four list calls per zone per hour in the steady state, which is nothing
/// against either provider's budget (Cloudflare's is per-account per-5-min
/// and a zone this size lists in one request).
const reconcile_interval = 900

pub type Msg {
  /// The sweep timer firing. **The only message that re-arms the timer.**
  Tick
  /// A product mutation asking for a pass now. Deliberately a separate
  /// constructor: `handle` re-arms after a `Tick`, so a poke handled as one
  /// would start a second, permanent timer chain beside the first — once per
  /// mutation, never cancelled, for the life of the process. The steady-state
  /// sweep rate would be one pass per interval per poke ever received, which
  /// any authenticated member can drive up by editing a device in a loop, and
  /// a revocation's own poke would then queue behind that backlog.
  Poke
}

type State {
  State(
    db_path: String,
    provider: Provider,
    provider_name: String,
    zone_id: String,
    subject: Subject(Msg),
    interval_ms: Int,
  )
}

/// Nudges a running reconciler by its registered name — sent by
/// `zone_mutation` after its transaction commits, and by anything else
/// that changed what the zone should say. Falling on the floor is fine:
/// the sweep repairs a missed poke.
///
/// **Checked, because `process.send` to an unregistered name raises.** It is
/// `let assert Ok(pid) = named(name) as "Sending to unregistered name"`, so
/// "falling on the floor" is not what an absent reconciler gets: the caller
/// dies. The window is real in both directions — the supervisor registers
/// this name inside the actor's own init, and any restart of the reconciler
/// leaves it unregistered until that completes. The caller is
/// `zone_mutation`, *after* its transaction has committed and *before* the
/// 200 is built, so a raise there turns a committed revocation into a 500
/// whose follow-up work (dropping the revoked key's live tunnels) never runs
/// and whose retry answers 404, the row already being revoked.
pub fn poke(name: Name(Msg)) -> Nil {
  case process.named(name) {
    Ok(_) -> process.send(process.named_subject(name), Poke)
    Error(Nil) -> Nil
  }
}

pub fn supervised(
  name: Name(Msg),
  db_path: String,
  prov: Provider,
  provider_name: String,
  zone_id: String,
) -> supervision.ChildSpecification(Nil) {
  supervised_every(
    name,
    db_path,
    prov,
    provider_name,
    zone_id,
    sweep_interval_ms,
  )
}

/// The same with the sweep interval named, so a test can watch the timer
/// chain without waiting five minutes for it.
pub fn supervised_every(
  name: Name(Msg),
  db_path: String,
  prov: Provider,
  provider_name: String,
  zone_id: String,
  interval_ms: Int,
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
        // This tick and nothing else: `handle` re-arms after every `Tick`,
        // so also scheduling one here would start a second, permanent timer
        // chain beside the first and sweep at twice the stated interval.
        process.send(subject, Tick)
        actor.initialised(State(
          db_path,
          prov,
          provider_name,
          zone_id,
          subject,
          interval_ms,
        ))
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
  run_once(state.db_path, state.provider, state.provider_name, state.zone_id)
  // Exactly one timer chain, started by the initialiser's first `Tick` and
  // continued here. A `Poke` runs its pass and re-arms nothing — see `Msg`.
  case msg {
    Tick -> {
      let _ = process.send_after(state.subject, state.interval_ms, Tick)
      Nil
    }
    Poke -> Nil
  }
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
  case pass(conn, prov, provider_name, zone_id, now) {
    Ok(Fresh) -> Nil
    Ok(Converged(serial, hash, changes, shed)) -> {
      note(state.record_ok(conn, provider_name, zone_id, hash, serial, now))
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
      note(state.record_partial(conn, provider_name, zone_id, rendered, now))
      let _ = audit_sync(conn, now, serial, changes, 0, failures)
      io.println_error(
        "provider-sync: serial "
        <> int.to_string(serial)
        <> " partly applied — the provider refused "
        <> rendered,
      )
    }
    Error(why) -> {
      note(state.record_error(conn, provider_name, zone_id, why, now))
      io.println_error("provider-sync: " <> why)
    }
  }
}

/// Reports a sync-state write that did not happen.
///
/// These were discarded. The consequence is not cosmetic: `fresh` requires
/// `last_error == None`, so an error row that fails to land leaves the
/// previous success row standing and the very next pass short-circuits past a
/// provider it just failed to reach. A write that fails is a fact about this
/// deployment that nothing else records, so it goes to stderr like every other
/// failure here.
fn note(written: Result(Nil, sqlite.Error)) -> Nil {
  case written {
    Ok(Nil) -> Nil
    Error(e) ->
      io.println_error(
        "provider-sync: could not record sync state: " <> string.inspect(e),
      )
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
  provider_name: String,
  zone_id: String,
  now: Int,
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
      // And only while the last confirmed read of the provider is recent.
      // Everything above is our own state; this is the one term that makes
      // the skip expire, so drift nobody here wrote is still found.
      && recently_listed(s.last_ok_at, now)
    Error(Nil) -> False
  }
  // Whether this deployment has already applied a set to *this* provider and
  // zone. It is what lets `diff_gated` treat a marker that no longer matches
  // as drift rather than as somebody else's apex — see `diff.diff_gated`.
  // Read from our own row, which only `record_ok` writes and only after an
  // apply that was itself gated on ownership, so it cannot be conjured by
  // anything at the provider. A zone id or provider name that changed makes
  // it false again, which is right: that is a first sync somewhere new.
  let adopted = case stored {
    Ok(s) ->
      s.applied_hash != option.None
      && s.provider == provider_name
      && s.provider_zone_id == zone_id
    Error(Nil) -> False
  }
  use <- fresh_guard(fresh)
  use existing <- result.try(
    prov.list() |> result.map_error(fn(e) { "provider list: " <> e }),
  )
  // What the gate held back, as records rather than as a flag. A flag can
  // only say "membership", which downstream has to turn into a predicate over
  // names — and a revoked device's record carries a membership-shaped name
  // too, as does one an attacker planted. Rendering the ungated set says
  // exactly which records this pass would have published, so the shield
  // covers those and nothing else.
  use withheld <- result.try(case omit_members {
    False -> Ok([])
    True ->
      render_external.render(input)
      |> result.map(fn(ungated) {
        // The *difference*, not the whole ungated set: `withheld` means "what
        // the gate dropped", and handing the shield every record this pass
        // rendered would silently widen it to whatever the renderer starts
        // gating next.
        list.filter(ungated, fn(r) { !list.contains(desired, r) })
      })
      |> result.map_error(fn(e) { "rendering: " <> string.inspect(e) })
  })
  use changes <- result.try(
    diff.diff_gated(desired, existing, withheld, adopted: adopted)
    |> result.map_error(describe_conflict),
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
/// fails the pass rather than guessing. The declaration still renders — the
/// watcher needs it on the wire to build a chain at all.
fn omit_members(conn: Connection) -> Result(Bool, String) {
  case gate.required() {
    False -> Ok(False)
    True ->
      // **The live keys, not "has anything ever been logged".** Serve mode's
      // gate asks whether the *active CSK* is claimed by a verified record
      // (`gate.check` → `store.covered`, by rdata digest); this is the
      // external-mode analogue and asks the same question. A gate that asked
      // only whether *some* record existed would arm once, at the first
      // publish, and never again — so a provider that later rotated to an
      // unlogged key would keep getting membership TXT published while every
      // `require` client failed closed on it.
      //
      // Every observed key, because in external mode the provider holds the
      // keys and this service cannot tell which of them signs a given answer:
      // whichever one does, a client demands a proof for *that* one. This is
      // the same bar `zonekey_watch` uses to decide it has nothing to do, so
      // the two cannot disagree about whether a zone is covered.
      //
      // No observed keys at all is the bootstrap case and still holds
      // membership back: nothing is known to be logged yet.
      case state.observed_keys(conn) {
        Error(e) -> Error("reading observed zone keys: " <> string.inspect(e))
        Ok([]) -> Ok(True)
        Ok(observed) ->
          observed
          |> list.try_map(fn(key) { rekor_store.covered(conn, key.key_sha256) })
          |> result.map(fn(flags) { !list.all(flags, fn(ok) { ok }) })
          |> result.map_error(fn(e) {
            "reading rekor records: " <> string.inspect(e)
          })
      }
  }
}

/// Whether the provider was last read recently enough to skip reading it.
///
/// A state with no `last_ok_at` has never confirmed a read, so it is never
/// recent. A stamp in the future — a clock stepped back since it was written
/// — reads as due rather than as valid forever, the same direction the
/// resolver's pin-refresh clock is bounded in.
fn recently_listed(last_ok_at: Option(Int), now: Int) -> Bool {
  case last_ok_at {
    option.None -> False
    Some(at) -> at <= now && now - at < reconcile_interval
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
