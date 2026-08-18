//// Attached daemons: the registry, the attach endpoint, and the tunnel
//// frames that cross it.
////
//// A node behind NAT cannot be dialed, so the only connection that can exist
//// is one it opens. `/agent/v1/attach` is where it lands: a WebSocket, no
//// cookies and no CSRF, authenticated by challenge-response against the
//// device keys this service already publishes into the zone.
////
//// Live state lives here and nowhere else. A table of open connections is a
//// lie after any restart, and a registry rebuilt from reconnects is truthful
//// within one backoff interval — so sessions are actor state, and the only
//// durable half of the feature is `networks.browse_enabled` and the audit
//// trail.
////
//// Nothing in this module writes to a cluster. The frames it can encode ask
//// for a listing, a version set, a resolution or a byte range; there is no
//// opcode for anything else, which is where the read-only property lives.

import api/middleware.{now_unix}
import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode.{type Decoder}
import gleam/erlang/process.{type Name, type Subject}
import gleam/http/request.{type Request as HttpRequest}
import gleam/http/response.{type Response as HttpResponse}
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import gleam/string
import mist
import store/pool.{type Pool}
import store/sqlite.{type Connection, Int as VInt, Text}
import thirtytwo
import util/id

/// Whether an Ed25519 signature verifies, guarded so malformed key material
/// answers `False` rather than raising.
@external(erlang, "cp_crypto_ffi", "ed25519_verify_safe")
fn ed25519_verify(message: BitArray, signature: BitArray, key: BitArray) -> Bool

/// The tunnel protocol version this build speaks.
///
/// A mismatch is a refusal naming both versions, not a negotiation: protobuf
/// keeps a field addition readable, but nothing makes a control plane that has
/// not learnt a frame out of one that has.
pub const protocol_version = 1

/// How long an attach nonce stays redeemable.
const nonce_ttl = 60

/// The most outstanding nonces the registry holds at once.
///
/// An unauthenticated `hello` mints one, so without a ceiling a flood grows
/// the list to rate×`nonce_ttl` and turns every mint and redeem into an O(n)
/// scan of it — an O(n²) stall on the single actor that also answers every
/// browse and download call. Capping the list keeps every operation O(cap):
/// past the cap the oldest-expiring nonces are dropped, which at worst makes
/// one in-flight attach re-challenge, while single-use and the 60s expiry are
/// untouched. At the default heartbeat cadence a legitimate fleet is nowhere
/// near this.
const nonce_cap = 4096

/// How many chunks an attached daemon may send before it must wait for
/// credit, and the window the relay keeps open.
///
/// Four times the 64 KiB chunk ceiling: enough that the tunnel is never idle
/// waiting for an acknowledgement, small enough that a stalled browser costs
/// a quarter of a megabyte here and stalls the read at its source.
pub const credit_window = 4

/// How long a browse call waits for an attached daemon to answer.
const query_timeout = 15_000

/// How long a download waits for the next frame before giving up.
const stream_timeout = 60_000

/// How long a one-shot question may sit unanswered before the session
/// reclaims it. Longer than `query_timeout` so the caller's own timeout
/// reports first; this is the backstop that frees the leaked entry after.
const waiting_lease = 30

/// How many downloads one user may have open at once.
///
/// Reads are same-origin GETs with cookies and need no CSRF token, so a
/// hostile page can start one with an `img` tag. The cap is what stops it
/// quietly draining an operator's upstream with a hundred of them.
const stream_cap = 4

/// How long a claimed stream slot may go unreleased before it is reclaimed.
///
/// Every path through the relay releases its slot, so this only catches a
/// relay process that died without running either of them — a bound on a leak
/// rather than a mechanism anything relies on.
const stream_lease = 3600

// -- what an attached daemon is ---------------------------------------------

/// One attached daemon, as everything outside this module sees it.
pub type Session {
  Session(
    id: String,
    network_id: String,
    org_id: String,
    /// The device's label in the zone, which is how a person names it.
    label: String,
    /// The origin the daemon publishes under.
    origin: String,
    /// The `device_keys` row the proof verified against.
    key_id: String,
    /// The spaces the operator exposed, and no others.
    spaces: List(String),
    version: Int,
    attached_at: Int,
    /// How to ask this daemon something.
    inbox: Subject(Ask),
  )
}

/// What a browse handler asks an attached daemon.
pub type Ask {
  /// A question about the unified tree, answered once.
  Query(query: Question, reply: Subject(Result(Answer, Refusal)))
  /// A byte range of a pinned content root, answered as a stream.
  Fetch(root: String, size: Int, start: Int, length: Int, sink: Subject(Event))
  /// More chunks may be sent on one stream.
  Grant(id: Int, n: Int)
  /// Abandon one stream.
  Abort(id: Int)
  /// The heartbeat tick this session schedules for itself.
  Beat
}

/// The three questions the tunnel can carry.
pub type Question {
  Ls(space: String, path: String, cursor: String, all: Bool)
  Stat(space: String, path: String)
  Resolve(space: String, path: String, from: String)
}

/// What a question is answered with.
pub type Answer {
  Listing(entries: List(Entry), cursor: String)
  Versions(versions: List(Version))
  Resolved(
    origin: String,
    root: String,
    size: Int,
    seq: Int,
    holders: List(String),
  )
}

/// A coded refusal, carrying the daemon's own error codes verbatim.
pub type Refusal {
  Refusal(code: String, message: String)
}

/// One entry of a directory of the unified tree.
pub type Entry {
  Entry(
    name: String,
    path: String,
    kind: String,
    size: Int,
    mtime_ns: Int,
    versions: Int,
    origin: String,
    root: String,
    all: List(Version),
  )
}

/// One version of one path, with the origins asserting it.
pub type Version {
  Version(
    root: String,
    kind: String,
    symlink_target: String,
    size: Int,
    mtime_ns: Int,
    seq: Int,
    attestors: List(String),
  )
}

/// What a download receives from the session serving it.
pub type Event {
  /// The stream's id, so the relay can return credit and cancel it.
  Started(id: Int)
  /// How many bytes are coming, and the root they were verified against.
  Header(size: Int, root: String)
  /// One chunk of content, in order.
  Body(seq: Int, data: BitArray)
  /// The stream sent everything it was asked for.
  Complete
  /// The stream ended early.
  Broken(code: String, message: String)
  /// The relay's own watchdog: no frame has arrived for a while.
  ///
  /// A tunnel that has stopped producing looks exactly like a slow one from
  /// here, and a download that hangs forever is worse for whoever is waiting
  /// than one that fails.
  Idle
}

// -- the registry ------------------------------------------------------------

/// What the registry is asked.
pub type Msg {
  /// Mint a single-use nonce for an attach in progress.
  Mint(reply: Subject(String))
  /// Spend one, if it is still live.
  Redeem(nonce: String, reply: Subject(Bool))
  /// A daemon finished its handshake.
  Join(session: Session)
  /// A daemon's connection ended.
  Leave(id: String)
  /// Every session attached for one network.
  Attached(network_id: String, reply: Subject(List(Session)))
  /// Browsing was turned off for a network: its sessions go now, not at the
  /// next heartbeat.
  DropNetwork(network_id: String)
  /// A device key was revoked: any session standing on it goes with it.
  DropKey(key_id: String)
  /// One user is opening a download; answered `False` at the cap.
  ClaimStream(user_id: String, reply: Subject(Bool))
  /// One user's download ended, however it ended.
  ReleaseStream(user_id: String)
}

type Registry {
  Registry(
    sessions: List(Session),
    nonces: List(#(String, Int)),
    /// One entry per download in flight: whose it is, and when it started.
    streams: List(#(String, Int)),
  )
}

/// A supervised registry, addressed by name so a browse handler can reach it
/// across a restart of the tree.
pub fn supervised(name: Name(Msg)) -> supervision.ChildSpecification(Nil) {
  supervision.worker(fn() {
    use started <- result.try(start(name))
    Ok(actor.Started(started.pid, Nil))
  })
}

/// Starts a registry under a name; exposed so a test drives one without a
/// supervision tree, the way `provider_sync.run_once` is.
pub fn start(
  name: Name(Msg),
) -> Result(actor.Started(Subject(Msg)), actor.StartError) {
  actor.new(Registry([], [], []))
  |> actor.on_message(handle_registry)
  |> actor.named(name)
  |> actor.start
}

fn handle_registry(state: Registry, message: Msg) -> actor.Next(Registry, Msg) {
  let now = now_unix()
  case message {
    Mint(reply) -> {
      // Hex, because the proof covers the 32 raw bytes and both ends have to
      // agree on how they were written down.
      let nonce =
        crypto.strong_random_bytes(32)
        |> bit_array.base16_encode
        |> string.lowercase
      process.send(reply, nonce)
      // Sweep the expired, then cap. The list is capped on every insert, so
      // `live` only ever scans at most `nonce_cap` entries — the flood cannot
      // make this or `Redeem` grow unbounded. Newest-first, so `take` keeps the
      // freshest and drops the oldest-expiring, which is the right one to lose.
      let kept =
        [#(nonce, now + nonce_ttl), ..live(state.nonces, now)]
        |> list.take(nonce_cap)
      actor.continue(Registry(..state, nonces: kept))
    }
    Redeem(nonce, reply) -> {
      let fresh = live(state.nonces, now)
      let found = list.any(fresh, fn(pair) { pair.0 == nonce })
      process.send(reply, found)
      // Single use: spent whether or not the proof that follows verifies, so
      // a wrong signature cannot be retried against the same challenge.
      actor.continue(
        Registry(
          ..state,
          nonces: list.filter(fresh, fn(pair) { pair.0 != nonce }),
        ),
      )
    }
    Join(session) ->
      actor.continue(Registry(..state, sessions: [session, ..state.sessions]))
    Leave(id) ->
      actor.continue(
        Registry(
          ..state,
          sessions: list.filter(state.sessions, fn(s) { s.id != id }),
        ),
      )
    Attached(network_id, reply) -> {
      process.send(
        reply,
        list.filter(state.sessions, fn(s) { s.network_id == network_id }),
      )
      actor.continue(state)
    }
    DropNetwork(network_id) -> {
      let #(going, staying) =
        list.partition(state.sessions, fn(s) { s.network_id == network_id })
      list.each(going, close)
      actor.continue(Registry(..state, sessions: staying))
    }
    DropKey(key_id) -> {
      let #(going, staying) =
        list.partition(state.sessions, fn(s) { s.key_id == key_id })
      list.each(going, close)
      actor.continue(Registry(..state, sessions: staying))
    }
    ClaimStream(user_id, reply) -> {
      let held =
        list.filter(state.streams, fn(pair) { pair.1 + stream_lease > now })
      let mine = list.filter(held, fn(pair) { pair.0 == user_id })
      case list.length(mine) < stream_cap {
        True -> {
          process.send(reply, True)
          actor.continue(Registry(..state, streams: [#(user_id, now), ..held]))
        }
        False -> {
          process.send(reply, False)
          actor.continue(Registry(..state, streams: held))
        }
      }
    }
    ReleaseStream(user_id) ->
      actor.continue(
        Registry(..state, streams: release(state.streams, user_id)),
      )
  }
}

/// Drops one of a user's slots, keeping their others.
fn release(
  streams: List(#(String, Int)),
  user_id: String,
) -> List(#(String, Int)) {
  case list.split_while(streams, fn(pair) { pair.0 != user_id }) {
    #(before, [_, ..after]) -> list.append(before, after)
    #(all, []) -> all
  }
}

fn live(nonces: List(#(String, Int)), now: Int) -> List(#(String, Int)) {
  list.filter(nonces, fn(pair) { pair.1 > now })
}

/// Ends a session by aborting the connection that owns it. The socket's own
/// process notices and unregisters; this is the eviction, not the bookkeeping.
fn close(session: Session) -> Nil {
  process.send(session.inbox, Abort(0))
}

/// The sessions attached for one network, or `[]` if the registry is not
/// answering — which reads the same way to a caller as "nothing is attached".
pub fn sessions_for(
  registry: Subject(Msg),
  network_id: String,
) -> List(Session) {
  let reply = process.new_subject()
  process.send(registry, Attached(network_id, reply))
  process.receive(reply, 2000) |> result.unwrap([])
}

/// Drops every session for a network, used when an admin turns browsing off.
pub fn drop_network(registry: Subject(Msg), network_id: String) -> Nil {
  process.send(registry, DropNetwork(network_id))
}

/// Drops every session standing on one device key, used when it is revoked.
pub fn drop_key(registry: Subject(Msg), key_id: String) -> Nil {
  process.send(registry, DropKey(key_id))
}

/// Takes one of a user's download slots, or says the cap is reached.
pub fn claim_stream(registry: Subject(Msg), user_id: String) -> Bool {
  let reply = process.new_subject()
  process.send(registry, ClaimStream(user_id, reply))
  process.receive(reply, 2000) |> result.unwrap(False)
}

/// Gives one back. Every path out of a relay calls this.
pub fn release_stream(registry: Subject(Msg), user_id: String) -> Nil {
  process.send(registry, ReleaseStream(user_id))
}

/// How many downloads one user may have open at once.
pub fn streams_per_user() -> Int {
  stream_cap
}

/// Asks one attached daemon a question and waits for its answer.
pub fn ask(session: Session, question: Question) -> Result(Answer, Refusal) {
  let reply = process.new_subject()
  process.send(session.inbox, Query(question, reply))
  case process.receive(reply, query_timeout) {
    Ok(answer) -> answer
    Error(Nil) ->
      Error(Refusal("unavailable", "the attached daemon did not answer in time"))
  }
}

// -- the attach endpoint -----------------------------------------------------

/// What the attach endpoint needs to do its work.
pub type Attach {
  Attach(registry: Subject(Msg), pool: Pool, attach_url: String)
}

/// The URL a proof is signed over: the endpoint the daemon actually dialed.
pub fn attach_url(public_url: String) -> String {
  string.trim(public_url) |> trim_slash <> "/agent/v1/attach"
}

fn trim_slash(url: String) -> String {
  case string.ends_with(url, "/") {
    True -> trim_slash(string.drop_end(url, 1))
    False -> url
  }
}

type Phase {
  /// Nothing has been claimed yet.
  Opening
  /// A claim is on the table and a nonce is out for it.
  Challenged(claim: Claim, nonce: String)
  /// The proof verified and the registry knows about this connection.
  Live(session: Session)
}

type Claim {
  Claim(
    network: String,
    origin: String,
    device: String,
    spaces: List(String),
    version: Int,
  )
}

type Waiting {
  /// A one-shot question, with the unix second past which it is abandoned. A
  /// daemon that answers a wrong-shaped frame or never answers at all would
  /// otherwise leave the entry — and the caller's reply subject — here forever;
  /// the heartbeat sweep replies an error and drops it once the deadline passes.
  ForAnswer(reply: Subject(Result(Answer, Refusal)), deadline: Int)
  /// A stream. No deadline: a large download over a slow link is legitimately
  /// long, and its liveness is the relay watchdog's job — it aborts on 60s of
  /// no progress, which removes this entry via `Abort`.
  ForStream(sink: Subject(Event))
}

type Conn {
  Conn(
    attach: Attach,
    inbox: Subject(Ask),
    phase: Phase,
    next_id: Int,
    waiting: List(#(Int, Waiting)),
    /// Heartbeats sent with no traffic back. Two is dead.
    misses: Int,
  )
}

/// Upgrades an attach request to the tunnel.
pub fn handle(
  req: HttpRequest(mist.Connection),
  attach: Attach,
) -> HttpResponse(mist.ResponseData) {
  mist.websocket(
    request: req,
    on_init: fn(_) {
      let inbox = process.new_subject()
      process.send_after(inbox, 30_000, Beat)
      #(
        Conn(attach, inbox, Opening, 1, [], 0),
        Some(process.new_selector() |> process.select(inbox)),
      )
    },
    on_close: fn(state: Conn) {
      case state.phase {
        Live(session) -> process.send(attach.registry, Leave(session.id))
        _ -> Nil
      }
    },
    handler: socket,
  )
}

fn socket(
  state: Conn,
  message: mist.WebsocketMessage(Ask),
  conn: mist.WebsocketConnection,
) -> mist.Next(Conn, Ask) {
  case message {
    mist.Text(body) -> incoming(state, body, conn)
    mist.Binary(frame) -> content(state, frame)
    mist.Custom(ask) -> outgoing(state, ask, conn)
    mist.Closed | mist.Shutdown -> mist.stop()
  }
}

/// One control frame from the daemon.
fn incoming(
  state: Conn,
  body: String,
  conn: mist.WebsocketConnection,
) -> mist.Next(Conn, Ask) {
  let state = Conn(..state, misses: 0)
  case tag_of(body), state.phase {
    Ok("hello"), Opening -> hello(state, body, conn)
    Ok("proof"), Challenged(claim, nonce) ->
      proof(state, body, claim, nonce, conn)
    Ok("ping"), _ -> {
      let _ = send(conn, json.object([#("t", json.string("pong"))]))
      mist.continue(state)
    }
    Ok("pong"), _ -> mist.continue(state)
    Ok("page"), Live(_) -> answered(state, body, page_decoder())
    Ok("versions"), Live(_) -> answered(state, body, versions_decoder())
    Ok("resolved"), Live(_) -> answered(state, body, resolved_decoder())
    Ok("meta"), Live(_) -> streamed(state, body, meta_decoder())
    Ok("done"), Live(_) -> streamed(state, body, done_decoder())
    Ok("err"), Live(_) -> streamed(state, body, error_decoder())
    // A frame out of its phase is a protocol violation, not something to
    // interpret: refusing the connection is cheaper for both sides than
    // guessing what a daemon meant by it.
    _, _ -> refuse(conn, "invalid", "unexpected frame for this phase")
  }
}

fn hello(
  state: Conn,
  body: String,
  conn: mist.WebsocketConnection,
) -> mist.Next(Conn, Ask) {
  case json.parse(body, hello_decoder()) {
    Error(_) -> refuse(conn, "invalid", "malformed hello")
    Ok(claim) ->
      case claim.version == protocol_version {
        False ->
          refuse(
            conn,
            "version-mismatch",
            "this control plane speaks tunnel v"
              <> int.to_string(protocol_version)
              <> ", the daemon speaks v"
              <> int.to_string(claim.version),
          )
        True -> {
          let reply = process.new_subject()
          process.send(state.attach.registry, Mint(reply))
          case process.receive(reply, 2000) {
            Error(Nil) -> refuse(conn, "internal", "no challenge available")
            Ok(nonce) -> {
              let _ =
                send(
                  conn,
                  json.object([
                    #("t", json.string("challenge")),
                    #("nonce", json.string(nonce)),
                  ]),
                )
              mist.continue(Conn(..state, phase: Challenged(claim, nonce)))
            }
          }
        }
      }
  }
}

fn proof(
  state: Conn,
  body: String,
  claim: Claim,
  nonce: String,
  conn: mist.WebsocketConnection,
) -> mist.Next(Conn, Ask) {
  let spent = {
    let reply = process.new_subject()
    process.send(state.attach.registry, Redeem(nonce, reply))
    process.receive(reply, 2000) |> result.unwrap(False)
  }
  case spent, json.parse(body, proof_decoder()) {
    False, _ ->
      refuse(conn, "unauthorized", "that challenge is spent or expired")
    _, Error(_) -> refuse(conn, "invalid", "malformed proof")
    True, Ok(#(signature_hex, key_z32)) ->
      case
        verified(
          state.attach,
          state.inbox,
          claim,
          nonce,
          signature_hex,
          key_z32,
        )
      {
        Error(Refusal(code, message)) -> refuse(conn, code, message)
        Ok(session) -> {
          process.send(state.attach.registry, Join(session))
          let _ =
            send(
              conn,
              json.object([
                #("t", json.string("attached")),
                #("session", json.string(session.id)),
                #("v", json.int(protocol_version)),
              ]),
            )
          mist.continue(Conn(..state, phase: Live(session)))
        }
      }
  }
}

/// Checks the proof against the keys this service publishes, and the network
/// against the org's own switch.
///
/// Nothing new is enrolled: the key that signs is a `device_keys` row in state
/// `active` for a device assigned to the claimed network, which is exactly the
/// material the zone already carries.
fn verified(
  attach: Attach,
  inbox: Subject(Ask),
  claim: Claim,
  nonce: String,
  signature_hex: String,
  key_z32: String,
) -> Result(Session, Refusal) {
  use signature <- result.try(
    bit_array.base16_decode(string.uppercase(signature_hex))
    |> result.replace_error(Refusal("invalid", "the signature is not hex")),
  )
  use key <- result.try(
    thirtytwo.z_base_32_decode(key_z32)
    |> result.replace_error(Refusal("invalid", "the key is not z-base-32")),
  )
  use nonce_bytes <- result.try(
    bit_array.base16_decode(string.uppercase(nonce))
    |> result.replace_error(Refusal("internal", "the challenge is unusable")),
  )
  let covered = signing_input(attach.attach_url, nonce_bytes)
  use Nil <- result.try(case ed25519_verify(covered, signature, key) {
    True -> Ok(Nil)
    False -> Error(Refusal("unauthorized", "the attach proof does not verify"))
  })
  case
    pool.with_connection(attach.pool, fn(conn) {
      lookup(conn, inbox, claim, key_z32)
    })
  {
    Ok(found) -> found
    Error(_) -> Error(Refusal("internal", "the directory is unavailable"))
  }
}

/// The exact bytes an attach proof covers, matching the daemon's own
/// `synch-cloud-attach-v1 || url || nonce`.
///
/// Domain-separated from every other signature a device key makes, and bound
/// to this endpoint's URL so a proof minted here cannot be replayed at another
/// control plane.
pub fn signing_input(url: String, nonce: BitArray) -> BitArray {
  <<"synch-cloud-attach-v1":utf8, url:utf8, nonce:bits>>
}

/// Resolves the claim against the tables: an active key, a device in the
/// claimed network, and an org that has turned browsing on for it.
fn lookup(
  conn: Connection,
  inbox: Subject(Ask),
  claim: Claim,
  key_z32: String,
) -> Result(Session, Refusal) {
  let found =
    sqlite.query(
      conn,
      "SELECT k.id, d.id, d.label, n.id, n.org_id, n.browse_enabled
         FROM device_keys k
         JOIN devices d ON d.id = k.device_id
         JOIN network_devices nd ON nd.device_id = d.id
         JOIN networks n ON n.id = nd.network_id
         JOIN orgs o ON o.id = n.org_id
        WHERE k.nk_z32 = ? AND k.state = 'active'
          AND n.name || '.' || o.slug = ?",
      [Text(key_z32), Text(network_prefix(claim.network))],
    )
  case found {
    Ok([
      [
        Text(key_id),
        Text(_device),
        Text(label),
        Text(network_id),
        Text(org_id),
        VInt(enabled),
      ],
    ]) ->
      case enabled {
        0 ->
          Error(Refusal(
            "browse-disabled",
            "file browsing is not enabled for "
              <> claim.network
              <> "; an org admin turns it on",
          ))
        _ ->
          Ok(Session(
            id: id.new(),
            network_id: network_id,
            org_id: org_id,
            label: label,
            origin: claim.origin,
            key_id: key_id,
            spaces: claim.spaces,
            version: claim.version,
            attached_at: now_unix(),
            inbox: inbox,
          ))
      }
    // An unknown key, a retired one, and a device that is not in the claimed
    // network are one fact to whoever is attaching: this connection is not
    // recognised. Distinguishing them would enumerate the directory.
    Ok(_) ->
      Error(Refusal(
        "unauthorized",
        "no active device key attaches for that network",
      ))
    Error(_) -> Error(Refusal("internal", "the directory is unavailable"))
  }
}

/// The `<network>.<org>` prefix of a membership domain, which is what the
/// tables name.
fn network_prefix(domain: String) -> String {
  case string.split(domain, ".") {
    [network, org, ..] -> network <> "." <> org
    _ -> domain
  }
}

fn refuse(
  conn: mist.WebsocketConnection,
  code: String,
  message: String,
) -> mist.Next(Conn, Ask) {
  let _ =
    send(
      conn,
      json.object([
        #("t", json.string("err")),
        #("code", json.string(code)),
        #("message", json.string(message)),
      ]),
    )
  mist.stop()
}

fn send(conn: mist.WebsocketConnection, payload: Json) -> Result(Nil, Nil) {
  mist.send_text_frame(conn, json.to_string(payload))
  |> result.replace_error(Nil)
}

// -- routing answers back to their callers ----------------------------------

fn answered(
  state: Conn,
  body: String,
  decoder: Decoder(#(Int, Answer)),
) -> mist.Next(Conn, Ask) {
  case json.parse(body, decoder) {
    Error(_) -> mist.continue(state)
    Ok(#(id, answer)) -> {
      case list.key_find(state.waiting, id) {
        Ok(ForAnswer(reply, _)) -> process.send(reply, Ok(answer))
        _ -> Nil
      }
      mist.continue(Conn(..state, waiting: without(state.waiting, id)))
    }
  }
}

/// Every waiting request but one.
fn without(waiting: List(#(Int, Waiting)), id: Int) -> List(#(Int, Waiting)) {
  list.filter(waiting, fn(pair) { pair.0 != id })
}

/// Drops one-shot questions whose deadline has passed, replying an error to
/// each so its caller is not left waiting on a subject nobody will answer.
/// Streams are exempt: they carry no deadline and are reclaimed by the relay.
fn sweep_waiting(state: Conn, now: Int) -> Conn {
  let #(expired, kept) =
    list.partition(state.waiting, fn(entry) {
      case entry.1 {
        ForAnswer(_, deadline) -> deadline <= now
        ForStream(_) -> False
      }
    })
  list.each(expired, fn(entry) {
    case entry.1 {
      ForAnswer(reply, _) ->
        process.send(
          reply,
          Error(Refusal("unavailable", "the attached daemon did not answer")),
        )
      ForStream(_) -> Nil
    }
  })
  Conn(..state, waiting: kept)
}

fn streamed(
  state: Conn,
  body: String,
  decoder: Decoder(#(Int, Event)),
) -> mist.Next(Conn, Ask) {
  case json.parse(body, decoder) {
    Error(_) -> mist.continue(state)
    Ok(#(id, event)) -> {
      let ended = case event {
        Header(..) | Body(..) | Started(..) | Idle -> False
        Complete | Broken(..) -> True
      }
      case list.key_find(state.waiting, id) {
        Ok(ForStream(sink)) -> process.send(sink, event)
        // An error frame for a one-shot question is that question's refusal.
        Ok(ForAnswer(reply, _)) ->
          case event {
            Broken(code, message) ->
              process.send(reply, Error(Refusal(code, message)))
            _ -> Nil
          }
        Error(Nil) -> Nil
      }
      case ended {
        True ->
          mist.continue(Conn(..state, waiting: without(state.waiting, id)))
        False -> mist.continue(state)
      }
    }
  }
}

/// One binary content frame: an eight-byte header, then payload.
fn content(state: Conn, frame: BitArray) -> mist.Next(Conn, Ask) {
  case frame {
    <<id:big-size(32), seq:big-size(32), data:bits>> -> {
      case list.key_find(state.waiting, id) {
        Ok(ForStream(sink)) -> process.send(sink, Body(seq, data))
        _ -> Nil
      }
      mist.continue(Conn(..state, misses: 0))
    }
    _ -> mist.continue(state)
  }
}

// -- asking the daemon things ------------------------------------------------

fn outgoing(
  state: Conn,
  ask: Ask,
  conn: mist.WebsocketConnection,
) -> mist.Next(Conn, Ask) {
  case ask, state.phase {
    Beat, _ ->
      case state.misses >= 2 {
        True -> mist.stop()
        False -> {
          // Reclaim one-shot questions the daemon abandoned before sending a
          // ping — the leak `answered` cannot plug on a malformed frame, since
          // a frame it could not decode carries no id to key on.
          let state = sweep_waiting(state, now_unix())
          let _ = send(conn, json.object([#("t", json.string("ping"))]))
          process.send_after(state.inbox, 30_000, Beat)
          mist.continue(Conn(..state, misses: state.misses + 1))
        }
      }
    Query(question, reply), Live(_) -> {
      let id = state.next_id
      let _ = send(conn, question_json(id, question))
      mist.continue(
        Conn(..state, next_id: id + 1, waiting: [
          #(id, ForAnswer(reply, now_unix() + waiting_lease)),
          ..state.waiting
        ]),
      )
    }
    Query(_, reply), _ -> {
      process.send(
        reply,
        Error(Refusal("unavailable", "the session is not live")),
      )
      mist.continue(state)
    }
    Fetch(root, size, start, length, sink), Live(_) -> {
      let id = state.next_id
      process.send(sink, Started(id))
      let _ =
        send(
          conn,
          json.object([
            #("t", json.string("read")),
            #("id", json.int(id)),
            #("root", json.string(root)),
            #("size", json.int(size)),
            #("start", json.int(start)),
            #("len", json.int(length)),
            #("credit", json.int(credit_window)),
          ]),
        )
      mist.continue(
        Conn(..state, next_id: id + 1, waiting: [
          #(id, ForStream(sink)),
          ..state.waiting
        ]),
      )
    }
    Fetch(_, _, _, _, sink), _ -> {
      process.send(sink, Broken("unavailable", "the session is not live"))
      mist.continue(state)
    }
    Grant(id, n), _ -> {
      let _ =
        send(
          conn,
          json.object([
            #("t", json.string("credit")),
            #("id", json.int(id)),
            #("n", json.int(n)),
          ]),
        )
      mist.continue(state)
    }
    // Id zero is the registry's eviction: there is no such stream, and the
    // connection itself is what is being taken down.
    Abort(0), _ -> mist.stop()
    Abort(id), _ -> {
      let _ =
        send(
          conn,
          json.object([
            #("t", json.string("cancel")),
            #("id", json.int(id)),
          ]),
        )
      mist.continue(Conn(..state, waiting: without(state.waiting, id)))
    }
  }
}

fn question_json(id: Int, question: Question) -> Json {
  case question {
    Ls(space, path, cursor, all) ->
      json.object([
        #("t", json.string("ls")),
        #("id", json.int(id)),
        #("space", json.string(space)),
        #("path", json.string(path)),
        #("cursor", case cursor {
          "" -> json.null()
          value -> json.string(value)
        }),
        #("all", json.bool(all)),
      ])
    Stat(space, path) ->
      json.object([
        #("t", json.string("stat")),
        #("id", json.int(id)),
        #("space", json.string(space)),
        #("path", json.string(path)),
      ])
    Resolve(space, path, from) ->
      json.object([
        #("t", json.string("resolve")),
        #("id", json.int(id)),
        #("space", json.string(space)),
        #("path", json.string(path)),
        #("from", case from {
          "" -> json.null()
          value -> json.string(value)
        }),
      ])
  }
}

// -- decoders ----------------------------------------------------------------

fn tag_of(body: String) -> Result(String, Nil) {
  json.parse(body, {
    use tag <- decode.field("t", decode.string)
    decode.success(tag)
  })
  |> result.replace_error(Nil)
}

fn hello_decoder() -> Decoder(Claim) {
  use version <- decode.field("v", decode.int)
  use network <- decode.field("network", decode.string)
  use origin <- decode.field("origin", decode.string)
  use device <- decode.field("device", decode.string)
  use spaces <- decode.field("spaces", decode.list(decode.string))
  decode.success(Claim(network, origin, device, spaces, version))
}

fn proof_decoder() -> Decoder(#(String, String)) {
  use signature <- decode.field("sig", decode.string)
  use key <- decode.field("key", decode.string)
  decode.success(#(signature, key))
}

fn version_decoder() -> Decoder(Version) {
  use root <- decode.optional_field("root", "", nullable_string())
  use kind <- decode.field("kind", decode.string)
  use target <- decode.optional_field("symlink_target", "", nullable_string())
  use size <- decode.field("size", decode.int)
  use mtime <- decode.field("mtime_ns", decode.int)
  use seq <- decode.field("seq", decode.int)
  use attestors <- decode.field("attestors", decode.list(decode.string))
  decode.success(Version(root, kind, target, size, mtime, seq, attestors))
}

fn entry_decoder() -> Decoder(Entry) {
  use name <- decode.field("name", decode.string)
  use path <- decode.field("path", decode.string)
  use kind <- decode.field("kind", decode.string)
  use size <- decode.field("size", decode.int)
  use mtime <- decode.field("mtime_ns", decode.int)
  use versions <- decode.field("versions", decode.int)
  use origin <- decode.field("origin", decode.string)
  use root <- decode.optional_field("root", "", nullable_string())
  use all <- decode.optional_field("all", [], decode.list(version_decoder()))
  decode.success(Entry(
    name,
    path,
    kind,
    size,
    mtime,
    versions,
    origin,
    root,
    all,
  ))
}

fn page_decoder() -> Decoder(#(Int, Answer)) {
  use id <- decode.field("id", decode.int)
  use entries <- decode.field("entries", decode.list(entry_decoder()))
  use cursor <- decode.optional_field("cursor", "", nullable_string())
  decode.success(#(id, Listing(entries, cursor)))
}

fn versions_decoder() -> Decoder(#(Int, Answer)) {
  use id <- decode.field("id", decode.int)
  use versions <- decode.field("versions", decode.list(version_decoder()))
  decode.success(#(id, Versions(versions)))
}

fn resolved_decoder() -> Decoder(#(Int, Answer)) {
  use id <- decode.field("id", decode.int)
  use origin <- decode.field("origin", decode.string)
  use root <- decode.field("root", decode.string)
  use size <- decode.field("size", decode.int)
  use seq <- decode.field("seq", decode.int)
  use holders <- decode.field("holders", decode.list(decode.string))
  decode.success(#(id, Resolved(origin, root, size, seq, holders)))
}

fn meta_decoder() -> Decoder(#(Int, Event)) {
  use id <- decode.field("id", decode.int)
  use size <- decode.field("size", decode.int)
  use root <- decode.field("root", decode.string)
  decode.success(#(id, Header(size, root)))
}

fn done_decoder() -> Decoder(#(Int, Event)) {
  use id <- decode.field("id", decode.int)
  decode.success(#(id, Complete))
}

fn error_decoder() -> Decoder(#(Int, Event)) {
  use id <- decode.field("id", decode.int)
  use code <- decode.field("code", decode.string)
  use message <- decode.field("message", decode.string)
  decode.success(#(id, Broken(code, message)))
}

/// A field the daemon may send as `null` rather than omit.
fn nullable_string() -> Decoder(String) {
  decode.one_of(decode.string, [decode.success("")])
}

// -- streaming a download ----------------------------------------------------

/// Relays one content stream to a chunked HTTP response.
///
/// The relay never holds more than the credit window: one chunk goes to the
/// socket and one credit goes back, so a slow browser stalls the read at the
/// daemon rather than filling memory here.
pub type Relay {
  Relay(session: Session, id: Int, sent: Int, root: String, moved: Bool)
}

/// A fresh relay, before the daemon has said anything.
pub fn relay(session: Session) -> Relay {
  Relay(session, 0, 0, "", False)
}

/// What one relayed event leaves behind.
pub type Relayed {
  /// Keep going.
  Relaying(Relay)
  /// The stream ended having sent everything.
  Finished(Relay)
  /// The stream ended early, and why.
  Failed(Relay, String)
}

/// Acts on one event from the session serving a download.
pub fn relay_step(
  state: Relay,
  event: Event,
  conn: mist.Connection,
) -> Relayed {
  case event {
    Started(id) -> Relaying(Relay(..state, id: id, moved: True))
    Header(_, root) -> Relaying(Relay(..state, root: root, moved: True))
    Body(_, data) ->
      case mist.send_chunk(conn, data) {
        Ok(_) -> {
          // One chunk out, one credit back: the window is the whole of what
          // this process is allowed to be holding.
          process.send(state.session.inbox, Grant(state.id, 1))
          Relaying(
            Relay(
              ..state,
              sent: state.sent + bit_array.byte_size(data),
              moved: True,
            ),
          )
        }
        // The browser hung up: cancel at the source rather than let the daemon
        // keep producing for a socket nobody is reading.
        Error(_) -> {
          process.send(state.session.inbox, Abort(state.id))
          Failed(state, "the client stopped reading")
        }
      }
    Complete -> Finished(state)
    Broken(code, message) -> Failed(state, code <> ": " <> message)
    Idle ->
      case state.moved {
        True -> Relaying(Relay(..state, moved: False))
        False -> {
          process.send(state.session.inbox, Abort(state.id))
          Failed(state, "the daemon stopped producing")
        }
      }
  }
}

/// How long a relay waits between frames before giving up on the daemon.
///
/// A stall with no progress at all is a dead tunnel dressed as a slow one, and
/// a download that hangs forever is worse for whoever is waiting than one that
/// fails.
pub fn relay_timeout() -> Int {
  stream_timeout
}

/// Cancels one relay's stream at the daemon.
pub fn relay_cancel(state: Relay) -> Nil {
  process.send(state.session.inbox, Abort(state.id))
}

/// The root a relay served, for the audit row.
pub fn relay_root(state: Relay) -> String {
  state.root
}

/// How many bytes a relay put on the wire, for the audit row.
pub fn relay_sent(state: Relay) -> Int {
  state.sent
}

/// A session's own account of itself, for the browse status endpoint.
pub fn session_json(session: Session) -> Json {
  json.object([
    #("session", json.string(session.id)),
    #("device", json.string(session.label)),
    #("origin", json.string(session.origin)),
    #("spaces", json.array(session.spaces, json.string)),
    #("protocol", json.int(session.version)),
    #("attached_at", json.int(session.attached_at)),
  ])
}

/// Picks the session to send a request to.
///
/// Preferring a holder is the whole of the routing: the bytes then cross the
/// operator's network once instead of hopping peer, serving node, cloud. When
/// no holder is attached any session still answers correctly — its blob
/// fetcher pulls the missing ranges from peers, bao-verified — so this is a
/// hint, never a correctness input.
pub fn route(
  sessions: List(Session),
  holders: List(String),
) -> Option(Session) {
  let holding =
    list.filter(sessions, fn(s) { list.contains(holders, s.origin) })
  case holding, sessions {
    [first, ..], _ -> Some(first)
    [], [first, ..] -> Some(first)
    [], [] -> None
  }
}

/// Whether a session exposes a space, which the control plane checks as well
/// as the daemon: both ends enforce the allowlist, so neither has to trust
/// the other to have done it.
pub fn exposes(session: Session, space: String) -> Bool {
  list.contains(session.spaces, space)
}
