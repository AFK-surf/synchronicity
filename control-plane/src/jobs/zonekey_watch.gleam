//// External-mode key watching: keep the transparency claim covering the
//// keys the provider actually signs with (docs/EXTERNAL-DNS-PROVIDER.md).
////
//// The provider holds the zone's private keys and rotates them on its own
//// schedule, so the claim cannot be a ceremony an operator runs — it has
//// to follow the wire. Every fifteen minutes this actor resolves the apex
//// DNSKEY RRset over DoH; when the set differs from what the last logged
//// claim covered, it collects the chain, logs a fresh claim signed by the
//// operational key, and pokes the reconciler so the `_synchronicity-rekor`
//// record follows into the provider zone.
////
//// The failure direction is closed: a provider that cuts to a
//// never-pre-published key strands `Require` clients until this loop
//// re-logs — at most one watch interval plus propagation. Providers
//// pre-publish rotations in the RRset as standard practice, and the
//// key-set claim covers a pre-published key before it ever signs, which
//// makes the gap theoretical in the ordinary case. Every failure here is a
//// log line and a `/healthz` count, never a crash: clients keep verifying
//// against the last logged set for as long as it keeps signing.

import dns/name as dns_name
import dns/wire
import dnssec/keys.{type Csk}
import gleam/bit_array
import gleam/crypto
import gleam/erlang/process.{type Name, type Subject}
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{None}
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import gleam/string
import jobs/provider_sync
import provider/state
import rekor/chain
import rekor/client.{type Log}
import rekor/publish as rekor
import store/db
import store/sqlite.{type Connection}

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

const watch_interval_ms = 900_000

pub type Msg {
  Tick
}

type State {
  State(
    db_path: String,
    apex: dns_name.Name,
    signer: Csk,
    resolver: chain.Resolver,
    log: Log,
    log_key: #(BitArray, BitArray),
    reconciler: Name(provider_sync.Msg),
    subject: Subject(Msg),
  )
}

pub fn supervised(
  db_path: String,
  apex: dns_name.Name,
  signer: Csk,
  resolver: chain.Resolver,
  log: Log,
  log_key: #(BitArray, BitArray),
  reconciler: Name(provider_sync.Msg),
) -> supervision.ChildSpecification(Nil) {
  supervision.worker(fn() {
    let builder =
      actor.new_with_initialiser(1000, fn(subject) {
        // First look right away: a fresh boot should observe and log before
        // the first quarter hour, not after it.
        process.send(subject, Tick)
        actor.initialised(State(
          db_path,
          apex,
          signer,
          resolver,
          log,
          log_key,
          reconciler,
          subject,
        ))
        |> Ok
      })
      |> actor.on_message(handle)
    use started <- result.try(actor.start(builder))
    Ok(actor.Started(started.pid, Nil))
  })
}

fn handle(state: State, msg: Msg) -> actor.Next(State, Msg) {
  let Tick = msg
  case db.open_primary(state.db_path) {
    Error(_) -> io.println_error("zonekey-watch: database unavailable")
    Ok(conn) -> {
      let poked =
        run_once_with(
          conn,
          state.apex,
          state.signer,
          state.resolver,
          state.log,
          state.log_key,
          now_unix(),
        )
      sqlite.close(conn)
      case poked {
        True -> provider_sync.poke(state.reconciler)
        False -> Nil
      }
    }
  }
  let _ = process.send_after(state.subject, watch_interval_ms, Tick)
  actor.continue(state)
}

/// One look at the wire; exposed for tests and the CLI. Returns whether a
/// new claim was logged — the caller's cue to poke the reconciler.
pub fn run_once_with(
  conn: Connection,
  apex: dns_name.Name,
  signer: Csk,
  resolver: chain.Resolver,
  log: Log,
  log_key: #(BitArray, BitArray),
  now: Int,
) -> Bool {
  case observe(resolver, apex) {
    Error(why) -> {
      io.println_error("zonekey-watch: " <> why)
      False
    }
    Ok(observed) -> {
      let covered = case state.observed_keys(conn) {
        Ok(stored) ->
          same_keys(observed, stored)
          && list.all(stored, fn(key) { key.logged_at != None })
        Error(_) -> False
      }
      let _ = state.record_observed(conn, observed, now)
      case covered {
        True -> False
        False ->
          case
            rekor.run(
              conn,
              apex,
              signer,
              log,
              log_key,
              now,
              resolver,
              rekor.Current,
            )
          {
            Ok(outcome) -> {
              let _ = state.record_logged(conn, now)
              io.println(
                "zonekey-watch: logged key set "
                <> string.join(list.map(outcome.key_tags, int.to_string), ",")
                <> " ("
                <> outcome.action
                <> ", log index "
                <> int.to_string(outcome.log_index)
                <> ")",
              )
              True
            }
            Error(e) -> {
              io.println_error(
                "zonekey-watch: logging failed: " <> string.inspect(e),
              )
              False
            }
          }
      }
    }
  }
}

/// The apex DNSKEY RRset as `#(sha256, tag, rdata)` per key, or why not.
fn observe(
  resolver: chain.Resolver,
  apex: dns_name.Name,
) -> Result(List(#(BitArray, Int, BitArray)), String) {
  use answers <- result.try(resolver.query(apex, wire.type_dnskey))
  let rdatas =
    answers
    |> list.filter(fn(rr) {
      rr.rtype == wire.type_dnskey && rr.class == wire.class_in
    })
    |> list.map(fn(rr) { rr.rdata })
  case rdatas {
    [] ->
      Error(
        "no DNSKEY RRset at "
        <> dns_name.to_string(apex)
        <> " — is the provider zone signed and delegated yet?",
      )
    _ ->
      Ok(
        list.map(rdatas, fn(rd) {
          #(crypto.hash(crypto.Sha256, rd), keys.key_tag(rd), rd)
        }),
      )
  }
}

fn same_keys(
  observed: List(#(BitArray, Int, BitArray)),
  stored: List(state.ObservedKey),
) -> Bool {
  let observed_ids =
    observed |> list.map(fn(key) { key.0 }) |> list.sort(bit_compare)
  let stored_ids =
    stored |> list.map(fn(key) { key.key_sha256 }) |> list.sort(bit_compare)
  observed_ids == stored_ids
}

fn bit_compare(a: BitArray, b: BitArray) {
  bit_array.compare(a, b)
}
