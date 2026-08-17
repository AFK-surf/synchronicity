//// A pool of csqlite workers. Connections are handed to borrowers by
//// port ownership transfer, so call sites keep the direct `store/sqlite`
//// interface with no per-statement message copying. Every checkout
//// RESETs the worker — closing and reopening the SQLite handle — so a
//// borrower can never observe a previous borrower's state, and an
//// atomically renamed replacement database file (the replica refresh
//// contract) is picked up on the very next use.
////
//// Failure posture: a worker that cannot be reset is killed and
//// replaced; a borrower that dies holding a connection is detected by
//// monitor and its worker killed (SQLite discards any open transaction
//// on worker exit). The dispatcher traps exits so an idle worker dying
//// cannot take the pool down.

import exception
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import store/migrate
import store/sqlite.{type Connection}

/// A stable handle: the dispatcher is addressed by registered name, so
/// the handle keeps working across supervisor restarts of the pool.
pub opaque type Pool {
  Pool(subject: Subject(Msg), pragmas: String)
}

pub opaque type Msg {
  Checkout(caller: Pid, reply: Subject(Connection))
  /// Both carry the connection rather than the borrower: one process may
  /// hold more than one lease at a time (a request that resolves a session
  /// on one connection and does its work on another), so returning a
  /// connection must retire that connection's lease and no other.
  Checkin(conn: Connection)
  Discard(conn: Connection)
  BorrowerDown(process.Down)
  PortExit(process.ExitMessage)
}

type Lease {
  Lease(pid: Pid, monitor: process.Monitor, conn: Connection)
}

type Waiter =
  #(Pid, Subject(Connection))

type State {
  State(
    path: String,
    mode: sqlite.Mode,
    size: Int,
    idle: List(Connection),
    leases: List(Lease),
    waiters: List(Waiter),
  )
}

/// The pool as a supervised child: the dispatcher registers under `name`
/// and `handle(name, pragmas)` addresses it before, during, and after any
/// restart. `pragmas` are re-applied after every checkout reset
/// (per-connection pragmas do not survive a handle reopen).
pub fn supervised(
  name: process.Name(Msg),
  path: String,
  mode: sqlite.Mode,
  pragmas: String,
  size: Int,
) -> supervision.ChildSpecification(Pool) {
  supervision.worker(fn() {
    use started <- result.try(actor.start(builder(name, path, mode, size)))
    Ok(actor.Started(started.pid, handle(name, pragmas)))
  })
}

/// The stable client handle for a (possibly not yet started) named pool.
pub fn handle(name: process.Name(Msg), pragmas: String) -> Pool {
  Pool(process.named_subject(name), pragmas)
}

/// Starts an unsupervised pool (tests, one-shot tools).
pub fn start(
  path: String,
  mode: sqlite.Mode,
  pragmas: String,
  size: Int,
) -> Result(Pool, actor.StartError) {
  let name = process.new_name("cp_pool")
  use _started <- result.try(actor.start(builder(name, path, mode, size)))
  Ok(handle(name, pragmas))
}

fn builder(
  name: process.Name(Msg),
  path: String,
  mode: sqlite.Mode,
  size: Int,
) -> actor.Builder(State, Msg, Subject(Msg)) {
  actor.new_with_initialiser(10_000, fn(subject) {
    // Trapped exits: an idle worker dying must not be a pool-killing
    // signal — but a shutdown request must still be honored (see the
    // PortExit handling).
    process.trap_exits(True)
    let idle = open_workers(path, mode, size, [])
    let selector =
      process.new_selector()
      |> process.select(subject)
      |> process.select_monitors(BorrowerDown)
      |> process.select_trapped_exits(PortExit)
    actor.initialised(State(path, mode, size, idle, [], []))
    |> actor.selecting(selector)
    |> actor.returning(subject)
    |> Ok
  })
  |> actor.named(name)
  |> actor.on_message(handle_msg)
}

fn open_workers(
  path: String,
  mode: sqlite.Mode,
  remaining: Int,
  acc: List(Connection),
) -> List(Connection) {
  case remaining {
    0 -> acc
    _ ->
      case sqlite.open(path, mode) {
        Ok(conn) -> open_workers(path, mode, remaining - 1, [conn, ..acc])
        Error(_) -> acc
      }
  }
}

/// Checks a connection out, resets it to pristine, runs `work`, and
/// returns it — on every exit path, panics included.
pub fn with_connection(
  pool: Pool,
  work: fn(Connection) -> a,
) -> Result(a, sqlite.Error) {
  use conn <- result.try(acquire(pool, 3))
  use <- exception.defer(fn() { release(pool, conn) })
  Ok(work(conn))
}

fn acquire(pool: Pool, attempts: Int) -> Result(Connection, sqlite.Error) {
  case attempts {
    0 -> Error(sqlite.ConnectionClosed)
    _ -> {
      let self = process.self()
      let conn =
        process.call(pool.subject, waiting: 10_000, sending: Checkout(self, _))
      sqlite.take(conn)
      // The checkout contract: pristine state, current file — and never a
      // file from a newer build (replicas may have one swapped in by
      // external tooling before their binary is upgraded; refuse, never
      // probe).
      let fresh = {
        use Nil <- result.try(sqlite.reset(conn))
        use Nil <- result.try(sqlite.script(conn, pool.pragmas))
        use version <- result.try(migrate.current_version(conn))
        let build = migrate.build_version()
        case version > build {
          True ->
            Error(sqlite.Sqlite(
              0,
              "database schema v"
                <> int.to_string(version)
                <> " is newer than this build's v"
                <> int.to_string(build)
                <> " — refusing",
            ))
          False -> Ok(Nil)
        }
      }
      case fresh {
        Ok(Nil) -> Ok(conn)
        Error(sqlite.ConnectionClosed) | Error(sqlite.RpcTimeout) -> {
          // Dead worker in the pool: kill, report, try again.
          sqlite.kill(conn)
          process.send(pool.subject, Discard(conn))
          acquire(pool, attempts - 1)
        }
        Error(e) -> {
          // The worker is alive but the database refused (e.g. replica
          // file mid-replacement): hand it back and surface the error.
          release(pool, conn)
          Error(e)
        }
      }
    }
  }
}

fn release(pool: Pool, conn: Connection) -> Nil {
  // A borrower that panicked mid-transaction returns a connection still
  // holding the write lock; left idle, it would wedge every other writer
  // until this worker's next checkout reset. Drop any open transaction
  // now — a no-op error on a clean connection, deliberate on a dirty one.
  let _ = sqlite.exec(conn, "ROLLBACK", [])
  // Owner is resolved through the registered name so a checkin lands in
  // the restarted dispatcher, not a dead pid.
  let returned = case process.subject_owner(pool.subject) {
    Ok(owner) -> sqlite.give(conn, owner)
    Error(Nil) -> Error(Nil)
  }
  case returned {
    Ok(Nil) -> process.send(pool.subject, Checkin(conn))
    Error(Nil) -> {
      // Dispatcher gone (mid-restart) or worker dead: this connection is
      // an orphan of the old generation — discard it.
      sqlite.kill(conn)
      process.send(pool.subject, Discard(conn))
    }
  }
}

fn handle_msg(state: State, msg: Msg) -> actor.Next(State, Msg) {
  case msg {
    Checkout(caller, reply) -> actor.continue(lend(state, caller, reply))
    Checkin(conn) -> {
      sqlite.take(conn)
      let state = drop_lease(state, conn)
      actor.continue(place(state, conn))
    }
    Discard(conn) -> actor.continue(drop_lease(state, conn))
    BorrowerDown(process.ProcessDown(monitor: monitor, pid: pid, ..)) -> {
      // The borrower died holding a connection: its worker is unreachable
      // (ports deliver to the dead owner) and may hold the write lock —
      // kill it; SQLite rolls the open transaction back on worker exit.
      process.demonitor_process(monitor)
      let #(gone, kept) = list.partition(state.leases, fn(l) { l.pid == pid })
      list.each(gone, fn(l) { sqlite.kill(l.conn) })
      let state =
        State(
          ..state,
          leases: kept,
          waiters: list.filter(state.waiters, fn(w) { w.0 != pid }),
        )
      actor.continue(state)
    }
    BorrowerDown(_) -> actor.continue(state)
    PortExit(exit_message) ->
      case exit_message.reason {
        // A port detaching cleanly (transfer-window race): noise. Dead
        // connections are culled at lend time.
        process.Normal -> actor.continue(state)
        // Anything else is either a supervisor shutdown request or an
        // abnormal linked death — terminate; the supervisor decides what
        // happens next. Live workers die with us via their janitors.
        _ -> actor.stop()
      }
  }
}

/// Hands an idle (or freshly opened) connection to `caller`, culling dead
/// ports along the way; queues the caller when at capacity.
fn lend(state: State, caller: Pid, reply: Subject(Connection)) -> State {
  case state.idle {
    [conn, ..rest] ->
      case sqlite.give(conn, caller) {
        Ok(Nil) -> {
          process.send(reply, conn)
          State(..state, idle: rest, leases: [
            Lease(caller, process.monitor(caller), conn),
            ..state.leases
          ])
        }
        Error(Nil) -> {
          sqlite.kill(conn)
          lend(State(..state, idle: rest), caller, reply)
        }
      }
    [] -> {
      let live = list.length(state.leases)
      case live < state.size {
        True ->
          case sqlite.open(state.path, state.mode) {
            Ok(conn) -> lend(State(..state, idle: [conn]), caller, reply)
            Error(_) ->
              // Cannot open (database gone?): queue; the caller's call
              // timeout is the backstop.
              State(..state, waiters: [#(caller, reply), ..state.waiters])
          }
        False -> State(..state, waiters: [#(caller, reply), ..state.waiters])
      }
    }
  }
}

/// Returns a connection to the pool: straight to the longest waiter if
/// one is queued, else to the idle list.
fn place(state: State, conn: Connection) -> State {
  case list.reverse(state.waiters) {
    [#(pid, reply), ..rest] -> {
      let state = State(..state, waiters: list.reverse(rest))
      case sqlite.give(conn, pid) {
        Ok(Nil) -> {
          process.send(reply, conn)
          State(..state, leases: [
            Lease(pid, process.monitor(pid), conn),
            ..state.leases
          ])
        }
        // Waiter died while queued: try the next one.
        Error(Nil) -> place(state, conn)
      }
    }
    [] -> State(..state, idle: [conn, ..state.idle])
  }
}

/// Retires the lease on one connection. Keyed on the connection, never on
/// the borrower: a process holding two leases returns them one at a time,
/// and dropping both on the first checkin would lose the pool's record of a
/// connection still out on loan — undercounting `size` and, worse, leaving
/// `BorrowerDown` with nothing to kill if that borrower then died holding
/// the write lock. Monitors are per-lease, so demonitoring this one leaves
/// any other lease of the same pid still watched.
fn drop_lease(state: State, conn: Connection) -> State {
  let #(gone, kept) = list.partition(state.leases, fn(l) { l.conn == conn })
  list.each(gone, fn(l) { process.demonitor_process(l.monitor) })
  State(..state, leases: kept)
}
