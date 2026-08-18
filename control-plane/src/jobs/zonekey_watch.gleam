//// External-mode key watching: keep the transparency claim covering the
//// keys the provider actually signs with (docs/EXTERNAL-DNS-PROVIDER.md).
////
//// The provider holds the zone's private keys and rotates them on its own
//// schedule, so the claim cannot be a ceremony an operator runs — it has
//// to follow the wire. Every five minutes this actor resolves the signing
//// zone's DNSKEY RRset over DoH — twice, and acts only on two reads that
//// agree, because the observation is what prunes the stored key set and one
//// bad answer must not delete a live key's proof. When the set differs from
//// what the last logged claim covered, it collects the chain, logs a fresh
//// claim (signed by an ephemeral key `rekor/publish` mints and discards —
//// attribution is not authorization), and pokes the reconciler so the
//// `_synchronicity-rekor` record follows into the provider zone.
////
//// A provider that pre-publishes — the standard rotation dance, and what
//// Cloudflare does — puts its next key in the RRset days before it signs
//// with it. That changes the set, so this loop logs a claim covering *both*
//// keys while the old one is still signing, and the cut happens with the
//// incoming key already on the public record. The claim's subject being a
//// key set rather than one key is what lets a single entry span both sides
//// of the cut.
////
//// A provider that cuts to a key it never published strands `Require`
//// clients until this loop re-logs, and the cadence is set so that window
//// fits inside the lifetime of the membership a client already holds
//// (`zone/render_external.ttl_proof`). Every failure here is a log line and
//// a `/healthz` count, never a crash: clients keep verifying against the
//// last logged set for as long as it keeps signing.

import dns/name as dns_name
import dns/rdata
import dns/wire
import dnssec/keys
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
import rekor/store as rekor_store
import store/db
import store/sqlite.{type Connection}

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

/// How often the wire is re-read. Not a knob: it is one term of the timing
/// relation in `zone/render_external.ttl_proof`, and moving it alone would
/// silently widen the window a rotation can strand clients for.
const watch_interval_ms = 300_000

/// How soon to look again when the declaration is not on the wire yet.
/// The reconciler and this watcher both start at boot; five minutes is
/// the wrong wait for a record the other half publishes in seconds.
const declaration_retry_ms = 30_000

pub type Msg {
  Tick
}

/// What one look at the wire decided, so `handle` can pick the next wait
/// and whether to poke the reconciler.
pub type WatchResult {
  /// A new claim was logged.
  Logged
  /// The declaration is not published yet — try again soon.
  WaitingForDeclaration
  /// Nothing to do, or a failure already logged.
  Quiet
}

type State {
  State(
    db_path: String,
    apex: dns_name.Name,
    signing_zone: dns_name.Name,
    resolver: chain.Resolver,
    reconciler: Name(provider_sync.Msg),
    subject: Subject(Msg),
  )
}

pub fn supervised(
  db_path: String,
  apex: dns_name.Name,
  signing_zone: dns_name.Name,
  resolver: chain.Resolver,
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
          signing_zone,
          resolver,
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
  let result = case db.open_primary(state.db_path) {
    Error(_) -> {
      io.println_error("zonekey-watch: database unavailable")
      Quiet
    }
    Ok(conn) -> {
      let now = now_unix()
      // The log is resolved on every tick rather than captured at boot: this
      // process is meant to run for months, and Sigstore opening the next
      // shard should cost a TUF refresh, not a restart. Failing to resolve
      // is a log line like every other failure here — the claim already in
      // the zone keeps verifying while it is unresolvable.
      let result = case client.discover(conn, now) {
        Error(why) -> {
          io.println_error("zonekey-watch: no transparency log: " <> why)
          Quiet
        }
        Ok(target) ->
          run_once_with(
            conn,
            state.apex,
            state.signing_zone,
            state.resolver,
            client.http(target.url),
            target.key,
            now,
          )
      }
      sqlite.close(conn)
      result
    }
  }
  case result {
    Logged -> provider_sync.poke(state.reconciler)
    WaitingForDeclaration | Quiet -> Nil
  }
  let next_ms = case result {
    WaitingForDeclaration -> declaration_retry_ms
    Logged | Quiet -> watch_interval_ms
  }
  let _ = process.send_after(state.subject, next_ms, Tick)
  actor.continue(state)
}

/// One look at the wire; exposed for tests and the CLI.
pub fn run_once_with(
  conn: Connection,
  apex: dns_name.Name,
  signing_zone: dns_name.Name,
  resolver: chain.Resolver,
  log: Log,
  log_key: #(BitArray, BitArray),
  now: Int,
) -> WatchResult {
  // The chain's bottom link is the declaration, and the reconciler is what
  // puts it in the provider zone. Both actors start at boot, so on a first
  // boot this one can reach the log before that record exists — and then
  // logs nothing, loudly, every quarter hour until it does. Checking first
  // turns that into a quiet wait for the other half of the boot. A lookup
  // that *fails* is a different event: reported, never narrated as absence.
  case declaration_live(resolver, apex) {
    Ok(True) ->
      log_if_new(conn, apex, signing_zone, resolver, log, log_key, now)
    Ok(False) -> {
      io.println(
        "zonekey-watch: waiting for the declaration at "
        <> dns_name.to_string([rdata.transparency_label, ..apex])
        <> " to be published",
      )
      WaitingForDeclaration
    }
    Error(why) -> {
      io.println_error("zonekey-watch: declaration lookup failed: " <> why)
      Quiet
    }
  }
}

/// Whether the apex's declaration resolves yet. Absence is the ordinary
/// state of a control plane that has booted but not yet reconciled, so it is
/// a reason to wait rather than a fault to report. A failed lookup is not
/// absence — it says nothing about the record, and reading it as "not
/// published" would report a regression that may never have happened — so it
/// comes back as an error for the caller to log, as every failure here is.
fn declaration_live(
  resolver: chain.Resolver,
  apex: dns_name.Name,
) -> Result(Bool, String) {
  let owner = [rdata.transparency_label, ..apex]
  use answers <- result.try(resolver.query(owner, wire.type_txt))
  Ok(
    list.any(answers, fn(rr) {
      rr.rtype == wire.type_txt && rr.class == wire.class_in
    }),
  )
}

fn log_if_new(
  conn: Connection,
  apex: dns_name.Name,
  signing_zone: dns_name.Name,
  resolver: chain.Resolver,
  log: Log,
  log_key: #(BitArray, BitArray),
  now: Int,
) -> WatchResult {
  case observe(resolver, signing_zone) {
    Error(why) -> {
      io.println_error("zonekey-watch: " <> why)
      Quiet
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
        True -> Quiet
        False ->
          case
            rekor.run(
              conn,
              apex,
              signing_zone,
              log,
              log_key,
              now,
              resolver,
              rekor.Current,
            )
          {
            Ok(outcome) -> {
              let _ = stamp_covered(conn, now)
              io.println(
                "zonekey-watch: logged key set "
                <> string.join(list.map(outcome.key_tags, int.to_string), ",")
                <> " ("
                <> outcome.action
                <> ", log index "
                <> int.to_string(outcome.log_index)
                <> ")",
              )
              Logged
            }
            Error(e) -> {
              io.println_error(
                "zonekey-watch: logging failed: " <> string.inspect(e),
              )
              Quiet
            }
          }
      }
    }
  }
}

/// Stamps only keys a verified non-retire row actually covers. Observe and
/// collect are two DNSKEY queries; extra keys the first saw stay unlogged
/// so the next tick retries.
fn stamp_covered(conn: Connection, now: Int) -> Result(Nil, sqlite.Error) {
  use observed <- result.try(state.observed_keys(conn))
  let digests =
    list.filter_map(observed, fn(key) {
      case rekor_store.covered(conn, key.key_sha256) {
        Ok(True) -> Ok(key.key_sha256)
        _ -> Error(Nil)
      }
    })
  state.record_logged(conn, digests, now)
}

/// The signing zone's DNSKEY RRset as `#(sha256, tag, rdata)` per key, read
/// **twice**, and only believed when the two reads agree.
///
/// What this observation feeds is `state.record_observed`, which *deletes* the
/// rows for keys the answer does not contain — and those rows are what
/// `zone/model` holds the served proofs to, so a single bad answer would
/// delete the zone's proof records for keys that never went away. One answer
/// is not enough to act on that. Two disagreeing reads leave the stored set
/// alone: nothing is logged, nothing is deleted, and the next tick asks again.
fn observe(
  resolver: chain.Resolver,
  zone: dns_name.Name,
) -> Result(List(#(BitArray, Int, BitArray)), String) {
  use first <- result.try(observe_once(resolver, zone))
  use second <- result.try(observe_once(resolver, zone))
  case same_answer(first, second) {
    True -> Ok(first)
    False ->
      Error(
        "two reads of the DNSKEY RRset at "
        <> dns_name.to_string(zone)
        <> " disagree; acting on an unconfirmed answer would delete proofs"
        <> " for keys that may still be live",
      )
  }
}

fn observe_once(
  resolver: chain.Resolver,
  zone: dns_name.Name,
) -> Result(List(#(BitArray, Int, BitArray)), String) {
  use answers <- result.try(resolver.query(zone, wire.type_dnskey))
  let rdatas =
    answers
    |> list.filter(fn(rr) {
      rr.rtype == wire.type_dnskey
      && rr.class == wire.class_in
      && rr.name == zone
    })
    |> list.map(fn(rr) { rr.rdata })
  case rdatas {
    [] ->
      Error(
        "no DNSKEY RRset at "
        <> dns_name.to_string(zone)
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

fn same_answer(
  a: List(#(BitArray, Int, BitArray)),
  b: List(#(BitArray, Int, BitArray)),
) -> Bool {
  let digests = fn(keys: List(#(BitArray, Int, BitArray))) {
    keys |> list.map(fn(key) { key.0 }) |> list.sort(bit_compare)
  }
  digests(a) == digests(b)
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
