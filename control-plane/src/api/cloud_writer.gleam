//// The write tunnel: hosted replicas attached to take the file API's writes
//// (docs/CLOUD-WRITES.md §5), and the registry that holds them.
////
//// A second tunnel beside the browse one, and deliberately not a fifth
//// version of it. The browse tunnel's read-only property is a fact about the
//// daemon's frame decoder — no write opcode decodes — and it stays one: the
//// frames here are decoded by the cloud data plane alone, which the daemon
//// binary never links. What crosses this tunnel is the mirror image of a
//// download: `put`, then content frames *downward* under credit, then
//// `commit`; the hosted node stages the bytes and publishes them as
//// `cloud-1`'s own version of the path.
////
//// Two credentials attach here (§5.2). The data-plane key rides the upgrade
//// request and proves *which fleet member* this is, which is what lets the
//// lookup check the assignment; the device-key challenge proves the
//// connection is held by the process that holds `cloud-1`'s secret, which is
//// the key that will sign the head. Neither alone attaches anything.
////
//// Live state lives here and nowhere else, as for the browse tunnel. The
//// control plane writes nothing to its database on a file write — no audit
//// row, no status row (§4.4) — so a replica takes writes as well as the
//// primary, and the data plane opens one of these tunnels to every node of
//// the deployment.

import api/agent
import api/middleware.{now_unix}
import auth/dataplane_key
import auth/principal
import gleam/bit_array
import gleam/bytes_tree
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

@external(erlang, "cp_crypto_ffi", "ed25519_verify_safe")
fn ed25519_verify(message: BitArray, signature: BitArray, key: BitArray) -> Bool

/// The newest write-tunnel protocol version this build speaks. Its own
/// counter, unrelated to the browse tunnel's.
pub const protocol_version = 1

/// The oldest version this build still serves.
pub const min_protocol_version = 1

/// How many content frames the relay may send ahead of the credit the node
/// returns for each one it has staged. The browse tunnel's window, in the
/// other direction.
pub const credit_window = 4

/// How long a write waits for the node to open it, and for a delete to be
/// answered.
const query_timeout = 15_000

/// How long a write waits for credit, or for the commit to land. Long,
/// because a commit uploads the object to the tenant's prefix and pushes a
/// head, and a client that has streamed a gigabyte is owed the wait.
const commit_timeout = 600_000

/// How many writes one credential may have open at once. Its own pool beside
/// the download cap, because an upload is longer.
const write_cap = 4

/// How long a claimed write slot may go unreleased before it is reclaimed.
const write_lease = 3600

/// How long a one-shot question may sit unanswered before the session
/// reclaims it, after the caller's own timeout has reported.
const waiting_lease = 30

// -- what an attached writer is ---------------------------------------------

/// One hosted node attached to take writes, as everything outside this
/// module sees it.
pub type Session {
  Session(
    id: String,
    network_id: String,
    org_id: String,
    /// The slot label, `cloud-1`.
    label: String,
    /// The origin the node publishes under.
    origin: String,
    /// The `device_keys` row the proof verified against.
    key_id: String,
    /// The data plane the credential names.
    dp: String,
    /// The hosting slot this node serves.
    slot: Int,
    version: Int,
    attached_at: Int,
    /// How to ask this node something.
    inbox: Subject(Ask),
  )
}

/// What the file API asks an attached writer.
pub type Ask {
  /// Open a write; the node answers `Opened` or `Failed` on `reply`, and
  /// every later event for the write goes there too.
  Open(
    space: String,
    path: String,
    size: Int,
    from: String,
    if_match: String,
    if_none_match: Bool,
    reply: Subject(Event),
  )
  /// One content frame of an open write, in order.
  Chunk(id: Int, seq: Int, data: BitArray)
  /// Every byte of a write was sent.
  Commit(id: Int)
  /// Withdraw the node's version of a path.
  Remove(
    space: String,
    path: String,
    from: String,
    if_match: String,
    reply: Subject(Event),
  )
  /// Abandon a write.
  Cancel(id: Int)
  /// The heartbeat tick this session schedules for itself.
  Beat
}

/// What a caller receives from the session serving its request.
pub type Event {
  /// The write may begin: its id on the tunnel, and how many frames may be
  /// sent before the first credit.
  Opened(id: Int, credit: Int)
  /// More frames may be sent.
  Credit(id: Int, n: Int)
  /// The version now exists.
  Committed(root: String, size: Int, seq: Int, mtime_ns: Int, origin: String)
  /// The tombstone was published, or there was nothing to withdraw.
  Deleted(still_published: Bool, withdrawn: Bool)
  /// A coded refusal, in the node's own vocabulary.
  Failed(code: String, message: String)
}

// -- the registry -------------------------------------------------------------

/// What the registry is asked.
pub type Msg {
  /// A node finished its handshake.
  Join(session: Session)
  /// A node's connection ended.
  Leave(id: String)
  /// Every session attached for one network.
  Attached(network_id: String, reply: Subject(List(Session)))
  /// Hosting was turned off for a network: its sessions go now.
  DropNetwork(network_id: String)
  /// A device key was revoked: any session standing on it goes with it.
  DropKey(key_id: String)
  /// One credential is opening a write; answered `False` at the cap.
  ClaimSlot(holder: String, reply: Subject(Bool))
  /// One credential's write ended, however it ended.
  ReleaseSlot(holder: String)
}

type Registry {
  Registry(sessions: List(Session), slots: List(#(String, Int)))
}

/// A supervised registry, addressed by name.
pub fn supervised(name: Name(Msg)) -> supervision.ChildSpecification(Nil) {
  supervision.worker(fn() {
    use started <- result.try(start(name))
    Ok(actor.Started(started.pid, Nil))
  })
}

/// Starts a registry under a name; exposed so a test drives one.
pub fn start(
  name: Name(Msg),
) -> Result(actor.Started(Subject(Msg)), actor.StartError) {
  actor.new(Registry([], []))
  |> actor.on_message(handle_registry)
  |> actor.named(name)
  |> actor.start
}

fn handle_registry(state: Registry, message: Msg) -> actor.Next(Registry, Msg) {
  let now = now_unix()
  case message {
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
    ClaimSlot(holder, reply) -> {
      let held =
        list.filter(state.slots, fn(pair) { pair.1 + write_lease > now })
      let mine = list.filter(held, fn(pair) { pair.0 == holder })
      case list.length(mine) < write_cap {
        True -> {
          process.send(reply, True)
          actor.continue(Registry(..state, slots: [#(holder, now), ..held]))
        }
        False -> {
          process.send(reply, False)
          actor.continue(Registry(..state, slots: held))
        }
      }
    }
    ReleaseSlot(holder) ->
      actor.continue(Registry(..state, slots: release(state.slots, holder)))
  }
}

fn release(
  slots: List(#(String, Int)),
  holder: String,
) -> List(#(String, Int)) {
  case list.split_while(slots, fn(pair) { pair.0 != holder }) {
    #(before, [_, ..after]) -> list.append(before, after)
    #(all, []) -> all
  }
}

/// Ends a session by aborting the connection that owns it.
fn close(session: Session) -> Nil {
  process.send(session.inbox, Cancel(0))
}

/// The sessions attached for one network, or `[]` if the registry is not
/// answering.
pub fn sessions_for(
  registry: Subject(Msg),
  network_id: String,
) -> List(Session) {
  let reply = process.new_subject()
  process.send(registry, Attached(network_id, reply))
  process.receive(reply, 2000) |> result.unwrap([])
}

/// Drops every session for a network, used when hosting is turned off.
pub fn drop_network(registry: Subject(Msg), network_id: String) -> Nil {
  process.send(registry, DropNetwork(network_id))
}

/// Drops every session standing on one device key.
pub fn drop_key(registry: Subject(Msg), key_id: String) -> Nil {
  process.send(registry, DropKey(key_id))
}

/// Takes one of a credential's write slots, or says the cap is reached.
pub fn claim_slot(registry: Subject(Msg), holder: String) -> Bool {
  let reply = process.new_subject()
  process.send(registry, ClaimSlot(holder, reply))
  process.receive(reply, 2000) |> result.unwrap(False)
}

/// Gives one back. Every path out of a write calls this.
pub fn release_slot(registry: Subject(Msg), holder: String) -> Nil {
  process.send(registry, ReleaseSlot(holder))
}

/// How many writes one credential may have open at once.
pub fn writes_per_user() -> Int {
  write_cap
}

/// The session that takes a network's writes: the one serving slot 1, the
/// only slot v1 hosts (docs/CLOUD-WRITES.md §4.5).
pub fn pick(sessions: List(Session)) -> Result(Session, Nil) {
  list.find(sessions, fn(s) { s.slot == 1 })
}

// -- asking the node things ---------------------------------------------------

/// Opens a write and waits for the node to accept it.
pub fn open(
  session: Session,
  space: String,
  path: String,
  size: Int,
  from: String,
  if_match: String,
  if_none_match: Bool,
) -> #(Subject(Event), Result(#(Int, Int), Event)) {
  let reply = process.new_subject()
  process.send(
    session.inbox,
    Open(space, path, size, from, if_match, if_none_match, reply),
  )
  let answer = case process.receive(reply, query_timeout) {
    Ok(Opened(id, credit)) -> Ok(#(id, credit))
    Ok(other) -> Error(other)
    Error(Nil) ->
      Error(Failed(
        "unavailable",
        "the hosted node did not open the write in time",
      ))
  }
  #(reply, answer)
}

/// Waits for the next credit on a write.
pub fn await_credit(reply: Subject(Event)) -> Result(Int, Event) {
  case process.receive(reply, commit_timeout) {
    Ok(Credit(_, n)) -> Ok(n)
    Ok(other) -> Error(other)
    Error(Nil) ->
      Error(Failed("unavailable", "the hosted node stopped taking the write"))
  }
}

/// Waits for a commit to land, skipping the credits still arriving.
pub fn await_commit(reply: Subject(Event)) -> Event {
  case process.receive(reply, commit_timeout) {
    Ok(Credit(..)) -> await_commit(reply)
    Ok(event) -> event
    Error(Nil) ->
      Failed("unavailable", "the hosted node did not commit in time")
  }
}

/// Withdraws the node's version of a path and waits for the answer.
pub fn remove(
  session: Session,
  space: String,
  path: String,
  from: String,
  if_match: String,
) -> Event {
  let reply = process.new_subject()
  process.send(session.inbox, Remove(space, path, from, if_match, reply))
  case process.receive(reply, commit_timeout) {
    Ok(event) -> event
    Error(Nil) ->
      Failed("unavailable", "the hosted node did not answer in time")
  }
}

// -- the attach endpoint -----------------------------------------------------

/// What the attach endpoint needs to do its work.
pub type Attach {
  Attach(
    registry: Subject(Msg),
    /// The browse registry, for its single-use nonces: a nonce is a nonce,
    /// and the two endpoints sharing one pool costs nothing.
    nonces: Subject(agent.Msg),
    pool: Pool,
    attach_url: String,
  )
}

/// The URL a write-tunnel proof is signed over: the endpoint the node dialed.
pub fn attach_url(public_url: String) -> String {
  string.trim(public_url) |> trim_slash <> "/dp/v1/attach"
}

fn trim_slash(url: String) -> String {
  case string.ends_with(url, "/") {
    True -> trim_slash(string.drop_end(url, 1))
    False -> url
  }
}

/// The exact bytes a write-tunnel attach proof covers, matching the node's
/// `synch-cloud-write-v1 || url || nonce`.
///
/// A distinct tag from the browse tunnel's, so a browse proof cannot be
/// replayed at this endpoint — a statement about the signature rather than
/// about two URLs happening to differ.
pub fn signing_input(url: String, nonce: BitArray) -> BitArray {
  <<"synch-cloud-write-v1":utf8, url:utf8, nonce:bits>>
}

type Phase {
  Opening
  Challenged(claim: Claim, nonce: String)
  Live(session: Session)
}

/// What the node claimed in its hello.
pub type Claim {
  Claim(
    network: String,
    origin: String,
    device: String,
    slot: Int,
    version: Int,
  )
}

type Waiting {
  /// A request whose events go to one caller; one-shots carry the second
  /// past which they are abandoned, writes none — a stalled write is the
  /// caller's own timeout to notice.
  Waiting(reply: Subject(Event), deadline: Option(Int))
}

type Conn {
  Conn(
    attach: Attach,
    dp: String,
    inbox: Subject(Ask),
    phase: Phase,
    next_id: Int,
    waiting: List(#(Int, Waiting)),
    misses: Int,
  )
}

/// Upgrades an attach request to the write tunnel.
///
/// The data-plane credential is checked here, before the upgrade: a request
/// without one is refused as `dataplane_only`, the answer every `/dp/v1`
/// route gives a credential that is not the fleet's.
pub fn handle(
  req: HttpRequest(mist.Connection),
  attach: Attach,
) -> HttpResponse(mist.ResponseData) {
  case dataplane_of(req, attach.pool) {
    Error(response) -> response
    Ok(dp) ->
      mist.websocket(
        request: req,
        on_init: fn(_) {
          let inbox = process.new_subject()
          process.send_after(inbox, 30_000, Beat)
          #(
            Conn(attach, dp, inbox, Opening, 1, [], 0),
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
}

/// The data plane the upgrade request's bearer token names.
fn dataplane_of(
  req: HttpRequest(mist.Connection),
  db: Pool,
) -> Result(String, HttpResponse(mist.ResponseData)) {
  case middleware.presented(req.headers) {
    middleware.Bearer(token) ->
      case
        pool.with_connection(db, fn(conn) {
          dataplane_key.authenticate(conn, token, now_unix())
        })
      {
        Ok(Ok(who)) ->
          case who.credential {
            principal.Dataplane(_, dp) -> Ok(dp)
            _ -> Error(refused_http(403, "dataplane_only"))
          }
        Ok(Error(Nil)) -> Error(refused_http(401, "unauthorized"))
        Error(_) -> Error(refused_http(500, "internal"))
      }
    middleware.Foreign -> Error(refused_http(401, "unauthorized"))
    middleware.Absent -> Error(refused_http(403, "dataplane_only"))
  }
}

fn refused_http(status: Int, code: String) -> HttpResponse(mist.ResponseData) {
  response.new(status)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_tree.from_string(
        json.to_string(
          json.object([
            #(
              "error",
              json.object([
                #("code", json.string(code)),
                #(
                  "message",
                  json.string(
                    "this endpoint answers the hosting service's own credential "
                    <> "(Authorization: Bearer synchdp_…) and no other",
                  ),
                ),
              ]),
            ),
          ]),
        ),
      ),
    ),
  )
}

fn socket(
  state: Conn,
  message: mist.WebsocketMessage(Ask),
  conn: mist.WebsocketConnection,
) -> mist.Next(Conn, Ask) {
  case message {
    mist.Text(body) -> incoming(state, body, conn)
    // Content only ever travels downward on this tunnel.
    mist.Binary(_) ->
      refuse(
        conn,
        "invalid",
        "nothing travels up this tunnel but control frames",
      )
    mist.Custom(ask) -> outgoing(state, ask, conn)
    mist.Closed | mist.Shutdown -> mist.stop()
  }
}

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
    Ok("opened"), Live(_) -> forward(state, body, opened_decoder(), False)
    Ok("credit"), Live(_) -> forward(state, body, credit_decoder(), False)
    Ok("committed"), Live(_) -> forward(state, body, committed_decoder(), True)
    Ok("deleted"), Live(_) -> forward(state, body, deleted_decoder(), True)
    Ok("err"), Live(_) -> forward(state, body, error_decoder(), True)
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
      case claim.version >= min_protocol_version {
        False ->
          refuse(
            conn,
            "version-mismatch",
            "this control plane speaks write tunnel v"
              <> int.to_string(min_protocol_version)
              <> " and later, the node speaks v"
              <> int.to_string(claim.version),
          )
        True -> {
          let reply = process.new_subject()
          process.send(state.attach.nonces, agent.Mint(reply))
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
    process.send(state.attach.nonces, agent.Redeem(nonce, reply))
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
          state.dp,
          state.inbox,
          claim,
          nonce,
          signature_hex,
          key_z32,
        )
      {
        Error(#(code, message)) -> refuse(conn, code, message)
        Ok(session) -> {
          process.send(state.attach.registry, Join(session))
          let _ =
            send(
              conn,
              json.object([
                #("t", json.string("attached")),
                #("session", json.string(session.id)),
                #("v", json.int(session.version)),
              ]),
            )
          mist.continue(Conn(..state, phase: Live(session)))
        }
      }
  }
}

/// Checks the proof against the keys this service publishes, and the claim
/// against the assignment and the hosting switch.
fn verified(
  attach: Attach,
  dp: String,
  inbox: Subject(Ask),
  claim: Claim,
  nonce: String,
  signature_hex: String,
  key_z32: String,
) -> Result(Session, #(String, String)) {
  use signature <- result.try(
    bit_array.base16_decode(string.uppercase(signature_hex))
    |> result.replace_error(#("invalid", "the signature is not hex")),
  )
  use key <- result.try(
    thirtytwo.z_base_32_decode(key_z32)
    |> result.replace_error(#("invalid", "the key is not z-base-32")),
  )
  use nonce_bytes <- result.try(
    bit_array.base16_decode(string.uppercase(nonce))
    |> result.replace_error(#("internal", "the challenge is unusable")),
  )
  let covered = signing_input(attach.attach_url, nonce_bytes)
  use Nil <- result.try(case ed25519_verify(covered, signature, key) {
    True -> Ok(Nil)
    False -> Error(#("unauthorized", "the attach proof does not verify"))
  })
  case
    pool.with_connection(attach.pool, fn(conn) {
      lookup(conn, dp, inbox, claim, key_z32, now_unix())
    })
  {
    Ok(found) -> found
    Error(_) -> Error(#("internal", "the directory is unavailable"))
  }
}

/// Resolves the claim against the tables: an active key, of a device this
/// service registered, in the claimed network, hosted, and assigned to the
/// data plane the credential names (docs/CLOUD-WRITES.md §5.2).
///
/// Every part of this is a read, so a replica performs it as well as the
/// primary. Public so a test can hold it to its refusals without a socket.
pub fn lookup(
  conn: Connection,
  dp: String,
  inbox: Subject(Ask),
  claim: Claim,
  key_z32: String,
  now: Int,
) -> Result(Session, #(String, String)) {
  let found =
    sqlite.query(
      conn,
      "SELECT k.id, d.label, n.id, n.org_id, n.cloud_hosted,
              coalesce(n.cloud_dp_id, '')
         FROM device_keys k
         JOIN devices d ON d.id = k.device_id
         JOIN network_devices nd ON nd.device_id = d.id
         JOIN networks n ON n.id = nd.network_id
         JOIN orgs o ON o.id = n.org_id
        WHERE k.nk_z32 = ? AND k.state = 'active'
          AND d.created_by = 'system-dataplane'
          AND n.name || '.' || o.slug = ?",
      [Text(key_z32), Text(network_prefix(claim.network))],
    )
  case found {
    Ok([
      [
        Text(key_id),
        Text(label),
        Text(network_id),
        Text(org_id),
        VInt(hosted),
        Text(assigned),
      ],
    ]) ->
      case assigned == dp, hosted {
        // "Not yours" is "not there" on a surface scoped by assignment.
        False, _ -> Error(#("not_found", "no such network on this data plane"))
        True, 0 ->
          Error(#(
            "hosting-disabled",
            "cloud hosting is off for " <> claim.network,
          ))
        True, _ ->
          Ok(Session(
            id: id.new(),
            network_id: network_id,
            org_id: org_id,
            label: label,
            origin: claim.origin,
            key_id: key_id,
            dp: dp,
            slot: claim.slot,
            version: int.min(claim.version, protocol_version),
            attached_at: now,
            inbox: inbox,
          ))
      }
    // An unknown key, a retired one, a customer's device, and a device that
    // is not in the claimed network are one fact to whoever is attaching.
    Ok(_) ->
      Error(#("unauthorized", "no hosted device key attaches for that network"))
    Error(_) -> Error(#("internal", "the directory is unavailable"))
  }
}

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

/// Delivers one answer frame to the caller waiting on its id, dropping the
/// wait when the frame is terminal.
fn forward(
  state: Conn,
  body: String,
  decoder: Decoder(#(Int, Event)),
  terminal: Bool,
) -> mist.Next(Conn, Ask) {
  case json.parse(body, decoder) {
    Error(_) -> mist.continue(state)
    Ok(#(id, event)) -> {
      case list.key_find(state.waiting, id) {
        Ok(Waiting(reply, _)) -> process.send(reply, event)
        Error(Nil) -> Nil
      }
      // A refusal ends a request whichever kind it was; a write that was
      // never opened is over too.
      let ended =
        terminal
        || case event {
          Failed(..) -> True
          _ -> False
        }
      case ended {
        True ->
          mist.continue(Conn(..state, waiting: without(state.waiting, id)))
        False -> mist.continue(state)
      }
    }
  }
}

fn without(waiting: List(#(Int, Waiting)), id: Int) -> List(#(Int, Waiting)) {
  list.filter(waiting, fn(pair) { pair.0 != id })
}

/// Drops one-shot requests whose deadline has passed, replying an error to
/// each so its caller is not left waiting.
fn sweep_waiting(state: Conn, now: Int) -> Conn {
  let #(expired, kept) =
    list.partition(state.waiting, fn(entry) {
      case entry.1 {
        Waiting(_, Some(deadline)) -> deadline <= now
        Waiting(_, None) -> False
      }
    })
  list.each(expired, fn(entry) {
    let Waiting(reply, _) = entry.1
    process.send(reply, Failed("unavailable", "the hosted node did not answer"))
  })
  Conn(..state, waiting: kept)
}

// -- asking the node things ---------------------------------------------------

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
          let state = sweep_waiting(state, now_unix())
          let _ = send(conn, json.object([#("t", json.string("ping"))]))
          process.send_after(state.inbox, 30_000, Beat)
          mist.continue(Conn(..state, misses: state.misses + 1))
        }
      }
    Open(space, path, size, from, if_match, if_none_match, reply), Live(_) -> {
      let id = state.next_id
      let _ =
        send(
          conn,
          json.object([
            #("t", json.string("put")),
            #("id", json.int(id)),
            #("space", json.string(space)),
            #("path", json.string(path)),
            #("size", json.int(size)),
            #("from", nullable(from)),
            #("if_match", nullable(if_match)),
            #("if_none_match", json.bool(if_none_match)),
          ]),
        )
      mist.continue(
        Conn(..state, next_id: id + 1, waiting: [
          #(id, Waiting(reply, None)),
          ..state.waiting
        ]),
      )
    }
    Remove(space, path, from, if_match, reply), Live(_) -> {
      let id = state.next_id
      let _ =
        send(
          conn,
          json.object([
            #("t", json.string("delete")),
            #("id", json.int(id)),
            #("space", json.string(space)),
            #("path", json.string(path)),
            #("from", nullable(from)),
            #("if_match", nullable(if_match)),
          ]),
        )
      mist.continue(
        Conn(..state, next_id: id + 1, waiting: [
          #(id, Waiting(reply, Some(now_unix() + waiting_lease))),
          ..state.waiting
        ]),
      )
    }
    Open(_, _, _, _, _, _, reply), _ | Remove(_, _, _, _, reply), _ -> {
      process.send(reply, Failed("unavailable", "the session is not live"))
      mist.continue(state)
    }
    Chunk(id, seq, data), Live(_) -> {
      let _ =
        mist.send_binary_frame(conn, <<
          id:big-size(32),
          seq:big-size(32),
          data:bits,
        >>)
      mist.continue(state)
    }
    Commit(id), Live(_) -> {
      let _ =
        send(
          conn,
          json.object([#("t", json.string("commit")), #("id", json.int(id))]),
        )
      mist.continue(state)
    }
    // Id zero is the registry's eviction: the connection itself goes.
    Cancel(0), _ -> mist.stop()
    Cancel(id), _ -> {
      let _ =
        send(
          conn,
          json.object([#("t", json.string("cancel")), #("id", json.int(id))]),
        )
      mist.continue(Conn(..state, waiting: without(state.waiting, id)))
    }
    Chunk(..), _ | Commit(_), _ -> mist.continue(state)
  }
}

fn nullable(value: String) -> Json {
  case value {
    "" -> json.null()
    text -> json.string(text)
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
  use slot <- decode.optional_field("slot", 1, decode.int)
  decode.success(Claim(network, origin, device, slot, version))
}

fn proof_decoder() -> Decoder(#(String, String)) {
  use signature <- decode.field("sig", decode.string)
  use key <- decode.field("key", decode.string)
  decode.success(#(signature, key))
}

fn opened_decoder() -> Decoder(#(Int, Event)) {
  use id <- decode.field("id", decode.int)
  use credit <- decode.field("credit", decode.int)
  decode.success(#(id, Opened(id, credit)))
}

fn credit_decoder() -> Decoder(#(Int, Event)) {
  use id <- decode.field("id", decode.int)
  use n <- decode.field("n", decode.int)
  decode.success(#(id, Credit(id, n)))
}

fn committed_decoder() -> Decoder(#(Int, Event)) {
  use id <- decode.field("id", decode.int)
  use root <- decode.field("root", decode.string)
  use size <- decode.field("size", decode.int)
  use seq <- decode.field("seq", decode.int)
  use mtime_ns <- decode.field("mtime_ns", decode.int)
  use origin <- decode.field("origin", decode.string)
  decode.success(#(id, Committed(root, size, seq, mtime_ns, origin)))
}

fn deleted_decoder() -> Decoder(#(Int, Event)) {
  use id <- decode.field("id", decode.int)
  use still_published <- decode.field("still_published", decode.bool)
  use withdrawn <- decode.field("withdrawn", decode.bool)
  decode.success(#(id, Deleted(still_published, withdrawn)))
}

fn error_decoder() -> Decoder(#(Int, Event)) {
  use id <- decode.field("id", decode.int)
  use code <- decode.field("code", decode.string)
  use message <- decode.field("message", decode.string)
  decode.success(#(id, Failed(code, message)))
}

/// A session's own account of itself, for the browse status endpoint.
pub fn session_json(session: Session) -> Json {
  json.object([
    #("session", json.string(session.id)),
    #("device", json.string(session.label)),
    #("origin", json.string(session.origin)),
    #("slot", json.int(session.slot)),
    #("protocol", json.int(session.version)),
    #("attached_at", json.int(session.attached_at)),
  ])
}
