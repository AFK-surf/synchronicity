//// The browse API: what a dashboard reads, relayed from an attached daemon.
////
//// Primary only, GET only, and never a byte of file content stored here.
//// Every route resolves its org and network on a pooled connection, hands
//// that connection back, and only then talks to a daemon — a round trip to
//// somebody's LAN is far too long to hold a connection across.
////
//// Space and path travel as query parameters, never path segments: a file
//// path may contain anything, which is the same lesson the S3 gateway learnt
//// when it stopped putting keys through the CLI's text parser.
////
//// Reads are not recorded. A browse call is a read of an operator's own
//// files through a tunnel their own daemon opened, and the durable half of
//// the feature is the switch that permits it — `networks.browse_enabled`,
//// whose every flip *is* audited. A per-download row would be a log of
//// ordinary use, written on whichever node happened to serve it.

import api/agent.{type Session}
import api/auth_api.{type AuthContext}
import api/common.{Admin, Member, audit, check_org, db_error, ok_json}
import api/middleware.{error_json}
import api/reads.{type Reads}
import auth/principal.{type Principal}
import gleam/dynamic/decode
import gleam/erlang/process.{type Name}
import gleam/json.{type Json}
import gleam/list
import gleam/result
import store/pool
import store/sqlite.{type Connection, Int as VInt, Text}
import wisp.{type Request, type Response}

/// What a browse route needs beyond the ordinary API context: where the live
/// sessions are.
pub type Browse {
  Browse(registry: Name(agent.Msg), attach_url: String)
}

/// The durable facts a browse call turns on.
type Network {
  Network(org_id: String, network_id: String, enabled: Bool)
}

// -- status ------------------------------------------------------------------

/// Whether browsing is on for this network, and which daemons are attached.
///
/// The observability surface for the feature: attach count, per-session
/// spaces, protocol version, attach time.
pub fn status(
  reads: Reads,
  browse: Browse,
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  use net <- with_network(reads, who, slug, network, Member)
  let sessions = attached(browse, net)
  ok_json(
    json.object([
      #("enabled", json.bool(net.enabled)),
      #("devices", json.array(sessions, agent.session_json)),
      #("attach_url", json.string(browse.attach_url)),
    ]),
  )
}

// -- delegated trust ---------------------------------------------------------

/// Who the cluster admits on a delegation (DESIGN.md 3.5).
///
/// A membership question rather than a file one, and the only grant no remote
/// surface reported: an operator could see every space and every version in
/// the network and not who was admitted to read them.
///
/// Any attached daemon answers. Delegations are `d:` records replicated to
/// every member, so there is no space to route on and no origin to pick — the
/// first session serves, and its label travels with the answer so the reader
/// knows who was asked.
///
/// Gated on the same switch as the rest of this module. The toggle is what
/// decides whether this service asks an org's daemons questions at all, and
/// answering one it is switched off for would make the switch mean two
/// different things.
pub fn delegations(
  reads: Reads,
  browse: Browse,
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  use net <- with_network(reads, who, slug, network, Member)
  case net.enabled, attached(browse, net) {
    False, _ ->
      error_json(
        409,
        "browse-disabled",
        "this network does not answer control-plane questions",
      )
    True, [] ->
      error_json(
        503,
        "no-device-attached",
        "no daemon of this network is attached",
      )
    True, [session, ..] ->
      case agent.ask(session, agent.Delegations) {
        Ok(agent.Delegated(rows)) ->
          ok_json(
            json.object([
              #("device", json.string(session.label)),
              #("origin", json.string(session.origin)),
              #("delegations", json.array(rows, delegation_json)),
            ]),
          )
        Ok(_) ->
          error_json(502, "internal", "the daemon answered the wrong question")
        Error(refusal) -> relayed(refusal)
      }
  }
}

fn delegation_json(row: agent.Delegation) -> Json {
  json.object([
    #("key", json.string(row.key)),
    #("issuer", json.string(row.issuer)),
    #("spaces", json.array(row.spaces, json.string)),
    #("live", json.bool(row.live)),
    #("not_after", json.int(row.not_after)),
    #("added_at", json.int(row.added_at)),
    #("note", json.string(row.note)),
  ])
}

// -- listing -----------------------------------------------------------------

/// One directory of the unified tree.
pub fn ls(
  req: Request,
  reads: Reads,
  browse: Browse,
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  use net <- with_network(reads, who, slug, network, Member)
  let space = query(req, "space")
  let path = query(req, "path")
  let origin = query(req, "origin")
  use session <- serving(browse, net, space, origin)
  let question =
    agent.Ls(space, path, query(req, "cursor"), query(req, "all") == "1")
  case agent.ask(session, question) {
    Ok(agent.Listing(entries, cursor)) ->
      ok_json(
        json.object([
          #("device", json.string(session.label)),
          #("origin", json.string(session.origin)),
          #("space", json.string(space)),
          #("path", json.string(path)),
          #("entries", json.array(entries, entry_json)),
          #("cursor", json.string(cursor)),
        ]),
      )
    Ok(_) ->
      error_json(502, "internal", "the daemon answered the wrong question")
    Error(refusal) -> relayed(refusal)
  }
}

/// Every version of one path, with its attestors — the version inspector.
pub fn stat(
  req: Request,
  reads: Reads,
  browse: Browse,
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  use net <- with_network(reads, who, slug, network, Member)
  let space = query(req, "space")
  let path = query(req, "path")
  let origin = query(req, "origin")
  use session <- serving(browse, net, space, origin)
  case agent.ask(session, agent.Stat(space, path)) {
    Ok(agent.Versions(versions)) ->
      ok_json(
        json.object([
          #("device", json.string(session.label)),
          #("origin", json.string(session.origin)),
          #("space", json.string(space)),
          #("path", json.string(path)),
          #("versions", json.array(versions, version_json)),
        ]),
      )
    Ok(_) ->
      error_json(502, "internal", "the daemon answered the wrong question")
    Error(refusal) -> relayed(refusal)
  }
}

// -- the org's switch --------------------------------------------------------

/// Turns browsing on or off for one network.
///
/// Not a zone change: the apex record is deployment-wide, and this is a
/// serving-side decision the control plane enforces the instant it changes —
/// which is why turning it off drops the network's live sessions in the same
/// request rather than waiting out a TTL.
pub fn set_enabled(
  req: Request,
  ctx: AuthContext,
  browse: Browse,
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  let decoder = {
    use enabled <- decode.field("enabled", decode.bool)
    decode.success(enabled)
  }
  use enabled <- common.body_decoder(req, decoder)
  use net <- with_network(ctx.reads, who, slug, network, Admin)
  let written =
    pool.with_connection(ctx.reads.pool, fn(conn) {
      common.transaction(conn, fn() {
        case
          sqlite.exec(
            conn,
            "UPDATE networks SET browse_enabled = ? WHERE id = ?",
            [
              VInt(case enabled {
                True -> 1
                False -> 0
              }),
              Text(net.network_id),
            ],
          )
        {
          Ok(_) ->
            audit(
              conn,
              who,
              net.org_id,
              case enabled {
                True -> "browse.enable"
                False -> "browse.disable"
              },
              json.object([#("network", json.string(network))]),
            )
            |> result.replace(Nil)
            |> result.map_error(fn(_) { db_error() })
          Error(e) -> Error(common.constraint_response(e))
        }
      })
    })
  case written {
    Ok(Ok(Nil)) -> {
      // After the commit, and unconditionally on the off path: a session that
      // outlived the switch would keep answering for a network the org has
      // just said may not be browsed.
      case enabled {
        False ->
          agent.drop_network(
            process.named_subject(browse.registry),
            net.network_id,
          )
        True -> Nil
      }
      ok_json(
        json.object([
          #("ok", json.bool(True)),
          #("enabled", json.bool(enabled)),
        ]),
      )
    }
    Ok(Error(refusal)) -> refusal
    Error(_) -> db_error()
  }
}

// -- plumbing ----------------------------------------------------------------

/// Resolves the org, the role floor and the network, giving the connection
/// back before `next` runs.
fn with_network(
  reads: Reads,
  who: Principal,
  slug: String,
  network: String,
  minimum: common.Role,
  next: fn(Network) -> Response,
) -> Response {
  let looked =
    pool.with_connection(reads.pool, fn(conn) {
      resolve(conn, slug, network, who, minimum)
    })
  case looked {
    Ok(Ok(net)) -> next(net)
    Ok(Error(refusal)) -> refusal
    Error(_) -> db_error()
  }
}

fn resolve(
  conn: Connection,
  slug: String,
  network: String,
  who: Principal,
  minimum: common.Role,
) -> Result(Network, Response) {
  use #(org_id, _role) <- result.try(check_org(conn, slug, who, minimum))
  case
    sqlite.query(
      conn,
      "SELECT id, browse_enabled FROM networks WHERE org_id = ? AND name = ?",
      [Text(org_id), Text(network)],
    )
  {
    Ok([[Text(network_id), VInt(enabled)]]) ->
      Ok(Network(org_id, network_id, enabled != 0))
    Ok(_) -> Error(error_json(404, "not_found", "no such network"))
    Error(_) -> Error(db_error())
  }
}

/// The sessions attached for a network, or none when browsing is off — a
/// disabled network has nothing attached to it as far as this API is
/// concerned, whatever a stale connection might still be holding open.
fn attached(browse: Browse, net: Network) -> List(Session) {
  case net.enabled {
    False -> []
    True ->
      agent.sessions_for(process.named_subject(browse.registry), net.network_id)
  }
}

/// Picks the daemon that will answer, and refuses honestly when none can.
///
/// What may be browsed is this service's question alone — the admin toggle
/// above and the RBAC around the route — because the daemon enforces no local
/// list of its own. This only routes: a space no attached daemon holds has
/// nobody to ask, which is a 503 rather than a policy statement.
fn serving(
  browse: Browse,
  net: Network,
  space: String,
  origin: String,
  next: fn(Session) -> Response,
) -> Response {
  case net.enabled, space {
    False, _ ->
      error_json(
        409,
        "browse-disabled",
        "file browsing is not enabled for this network",
      )
    _, "" -> error_json(400, "bad_request", "space= is required")
    True, _ ->
      case pick(space, attached(browse, net), origin) {
        Ok(session) -> next(session)
        Error(message) -> error_json(503, "no-device-attached", message)
      }
  }
}

/// The session a request asked for: the one publishing `origin` when the
/// request names one, any holder of the space when it does not.
///
/// The origin, not the label, is the selector — labels are for people and
/// need not be unique, while an origin names one node for as long as it
/// exists. A named node that is not attached, and one that is attached but
/// does not hold the space, are different facts and say so.
pub fn pick(
  space: String,
  attached: List(Session),
  origin: String,
) -> Result(Session, String) {
  let holders = list.filter(attached, agent.holds(_, space))
  case origin {
    "" ->
      list.first(holders)
      |> result.map_error(fn(_) { "no attached daemon holds " <> space })
    origin ->
      case list.find(holders, fn(s) { s.origin == origin }) {
        Ok(session) -> Ok(session)
        Error(Nil) ->
          case list.any(attached, fn(s) { s.origin == origin }) {
            True -> Error(origin <> " does not hold " <> space)
            False -> Error(origin <> " is not attached")
          }
      }
  }
}

/// The facts a download needs, resolved the same way every other route
/// resolves them: the same RBAC, the same 404 for a network the caller cannot
/// see, and the same connection handed back before anything slow happens.
///
/// It exists because the download route lives below wisp — it streams, and
/// wisp has no streaming body — so it cannot use the continuation form above.
pub fn for_download(
  db: pool.Pool,
  who: Principal,
  slug: String,
  network: String,
) -> Result(#(String, String, Bool), Nil) {
  case
    pool.with_connection(db, fn(conn) {
      resolve(conn, slug, network, who, Member)
    })
  {
    Ok(Ok(net)) -> Ok(#(net.org_id, net.network_id, net.enabled))
    _ -> Error(Nil)
  }
}

/// The registry a browse context addresses.
pub fn registry(browse: Browse) -> process.Subject(agent.Msg) {
  process.named_subject(browse.registry)
}

/// A daemon's coded refusal, as an HTTP status a browser can act on.
fn relayed(refusal: agent.Refusal) -> Response {
  let status = case refusal.code {
    "not-found" -> 404
    "invalid" -> 400
    "divergent" -> 409
    "unavailable" -> 503
    _ -> 502
  }
  error_json(status, refusal.code, refusal.message)
}

fn query(req: Request, key: String) -> String {
  wisp.get_query(req) |> list.key_find(key) |> result.unwrap("")
}

fn entry_json(entry: agent.Entry) -> Json {
  json.object([
    #("name", json.string(entry.name)),
    #("path", json.string(entry.path)),
    #("kind", json.string(entry.kind)),
    #("size", json.int(entry.size)),
    #("mtime_ns", json.int(entry.mtime_ns)),
    #("versions", json.int(entry.versions)),
    #("origin", json.string(entry.origin)),
    #("root", json.string(entry.root)),
    #("all", json.array(entry.all, version_json)),
  ])
}

fn version_json(version: agent.Version) -> Json {
  json.object([
    #("root", json.string(version.root)),
    #("kind", json.string(version.kind)),
    #("symlink_target", json.string(version.symlink_target)),
    #("size", json.int(version.size)),
    #("mtime_ns", json.int(version.mtime_ns)),
    #("seq", json.int(version.seq)),
    #("attestors", json.array(version.attestors, json.string)),
  ])
}
