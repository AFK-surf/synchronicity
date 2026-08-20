//// Streamed downloads, below wisp because wisp has no streaming body.
////
//// A download ties an HTTP response to a tunnel stream. The registry grants
//// the attached daemon a small credit window; each chunk relayed to the
//// browser and flushed returns one credit, so a slow browser stalls the read
//// at its source and this process never holds more than the window.
////
//// Every response is `Content-Disposition: attachment`, `application/octet-
//// stream`, `X-Content-Type-Options: nosniff`. Stored files are hostile
//// content, and one HTML file rendered on the origin that holds the session
//// cookie is a stored-XSS machine — so nothing here is ever served inline.
//// The SPA's preview fetches these bytes and renders them as text or as an
//// image only, never as HTML, which keeps that boundary intact.

import api/agent.{type Session}
import api/browse_api.{type Browse}
import api/middleware
import auth/api_key
import auth/principal.{type Principal, ApiKey, Cookie, Principal}
import auth/session
import gleam/bit_array
import gleam/bytes_tree
import gleam/crypto
import gleam/erlang/process.{type Subject}
import gleam/http/request.{type Request as HttpRequest}
import gleam/http/response.{type Response as HttpResponse}
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri
import mist
import store/pool.{type Pool}

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

/// How often the relay's watchdog fires. A stream that has produced nothing
/// between two ticks is a dead tunnel dressed as a slow one.
const watchdog_ms = 60_000

/// What one download needs to know about itself: the concurrency slot it has
/// to give back and who to give it back for, plus the path the filename in
/// `Content-Disposition` comes from.
type Download {
  Download(registry: Subject(agent.Msg), holder: String, path: String)
}

/// `GET /api/orgs/:slug/networks/:net/browse/file?space=&path=&from=&origin=`
pub fn handle(
  req: HttpRequest(mist.Connection),
  browse: Browse,
  db: Pool,
  secret: String,
  slug: String,
  network: String,
) -> HttpResponse(mist.ResponseData) {
  let params =
    uri.parse_query(req.query |> option.unwrap("")) |> result.unwrap([])
  let space = param(params, "space")
  let path = param(params, "path")
  let from = param(params, "from")
  let origin = param(params, "origin")

  use who <- require_principal(req, db, secret)
  // The concurrency slot is claimed against the credential, not the person
  // behind it: a key gets its own budget rather than spending the budget of
  // whoever minted it.
  let holder = principal.actor(who)
  use #(_org_id, network_id, enabled) <- require_network(db, who, slug, network)
  use Nil <- require(enabled, 409, "file browsing is not enabled")
  use Nil <- require(
    space != "" && path != "",
    400,
    "space= and path= are required",
  )

  let registry = browse_api.registry(browse)
  let download = Download(registry, holder, path)
  let sessions = agent.sessions_for(registry, network_id)
  case browse_api.pick(space, sessions, origin) {
    Error(message) -> deny(503, message)
    Ok(first) ->
      // A read is a same-origin GET with cookies and needs no CSRF token, so a
      // hostile page can start one from an `img` tag. The cap is what stops it
      // starting a hundred.
      case agent.claim_stream(registry, holder) {
        False ->
          deny(
            429,
            "too many downloads open at once (limit "
              <> int.to_string(agent.streams_per_user())
              <> ")",
          )
        True ->
          // Two tunnel steps. The resolve pins the version to its content root
          // and names the origins currently holding it; the read is then
          // addressed *by root*, so a publish landing in between cannot swap
          // the bytes mid-download.
          case agent.ask(first, agent.Resolve(space, path, from)) {
            Error(refusal) -> {
              agent.release_stream(registry, holder)
              deny(status_of(refusal.code), refusal.message)
            }
            Ok(agent.Resolved(_origin, root, size, _seq, holders)) -> {
              // A named node serves the bytes it resolved — its blob fetcher
              // pulls missing ranges from peers, bao-verified. Unnamed, holders
              // first and then anyone: one extra internal hop, the same bytes.
              let session = case origin {
                "" ->
                  case
                    agent.route(
                      list.filter(sessions, agent.holds(_, space)),
                      holders,
                    )
                  {
                    Some(session) -> session
                    None -> first
                  }
                _ -> first
              }
              case wanted_range(req, size) {
                Error(Nil) -> {
                  agent.release_stream(registry, holder)
                  deny_range(size)
                }
                Ok(#(start, length, partial)) ->
                  stream(
                    req,
                    session,
                    download,
                    root,
                    size,
                    start,
                    length,
                    partial,
                  )
              }
            }
            Ok(_) -> {
              agent.release_stream(registry, holder)
              deny(502, "the daemon answered the wrong question")
            }
          }
      }
  }
}

/// The plain-text refusal a download ends on.
fn deny(status: Int, message: String) -> HttpResponse(mist.ResponseData) {
  refused(status, message)
}

/// A 416 carries `Content-Range: bytes */<size>` (RFC 7233 §4.2), so a client
/// learns the object's real length rather than only that its range was wrong.
fn deny_range(size: Int) -> HttpResponse(mist.ResponseData) {
  refused(
    416,
    "that Range is not satisfiable for a "
      <> int.to_string(size)
      <> "-byte object",
  )
  |> response.set_header("content-range", "bytes */" <> int.to_string(size))
}

/// Opens the chunked response and relays the stream into it.
fn stream(
  req: HttpRequest(mist.Connection),
  session: Session,
  download: Download,
  root: String,
  size: Int,
  start: Int,
  length: Int,
  partial: Bool,
) -> HttpResponse(mist.ResponseData) {
  let status = case partial {
    True -> 206
    False -> 200
  }
  let headers = [
    #("content-type", "application/octet-stream"),
    #(
      "content-disposition",
      "attachment; filename=\"" <> filename(download.path) <> "\"",
    ),
    #("x-content-type-options", "nosniff"),
    #("accept-ranges", "bytes"),
    // Forwarded from the daemon's resolve, not recomputed: the daemon is the
    // data authority (it bao-verifies every byte it serves), so the control
    // plane relays its BLAKE3 root rather than re-hashing a stream it only
    // passes through. A client that wants to check runs `b3sum` itself.
    #("x-synch-root", root),
    #("x-synch-device", session.label),
    ..case partial {
      True -> [
        #(
          "content-range",
          "bytes "
            <> int.to_string(start)
            <> "-"
            <> int.to_string(start + length - 1)
            <> "/"
            <> int.to_string(size),
        ),
      ]
      False -> []
    }
  ]
  let head =
    list.fold(headers, response.new(status), fn(acc, pair) {
      response.set_header(acc, pair.0, pair.1)
    })
  mist.chunked(
    request: req,
    response: head,
    init: fn(sink: Subject(agent.Event)) {
      process.send(session.inbox, agent.Fetch(root, size, start, length, sink))
      let _ = process.send_after(sink, watchdog_ms, agent.Idle)
      #(agent.relay(session), sink)
    },
    loop: fn(state, event, conn) {
      let #(relay, sink) = state
      case event {
        agent.Idle -> {
          let _ = process.send_after(sink, watchdog_ms, agent.Idle)
          Nil
        }
        _ -> Nil
      }
      case agent.relay_step(relay, event, conn) {
        agent.Relaying(next) -> mist.ChunkContinue(#(next, sink))
        agent.Finished(_next) -> {
          record(download)
          mist.ChunkStop
        }
        agent.Failed(_next, why) -> {
          record(download)
          // Aborted rather than closed cleanly: a truncated body must never
          // reach a browser as a complete file.
          mist.ChunkAbort(why)
        }
      }
    },
  )
}

/// Gives the download's concurrency slot back, however the stream ended.
fn record(download: Download) -> Nil {
  agent.release_stream(download.registry, download.holder)
}

// -- request plumbing --------------------------------------------------------

/// Resolves whichever credential the request carries, without wisp, which
/// cannot reach here.
///
/// The same two credentials the wisp routes take and the same order:
/// an `Authorization` header wins outright and never falls back, for the
/// reason `middleware.check_principal` spells out. That function cannot be
/// reused verbatim — it speaks wisp's Request and produces wisp's Response,
/// and this route is below both — so what is shared is everything that
/// decides the answer: the header parser and the two credential modules.
fn require_principal(
  req: HttpRequest(mist.Connection),
  db: Pool,
  secret: String,
  next: fn(Principal) -> HttpResponse(mist.ResponseData),
) -> HttpResponse(mist.ResponseData) {
  case middleware.presented(req.headers) {
    middleware.Bearer(token) ->
      case
        pool.with_connection(db, fn(conn) {
          api_key.authenticate(conn, token, now_unix())
        })
      {
        Ok(Ok(key)) ->
          next(Principal(
            key.created_by,
            ApiKey(key.key_id, key.org_id, key.role),
          ))
        Ok(Error(Nil)) -> refused(401, middleware.bad_key_message)
        Error(_) -> refused(500, "database unavailable")
      }
    // Terminal, exactly as above the wisp line: a header naming a credential
    // this service cannot read is refused, not downgraded to the cookie.
    middleware.Foreign -> refused(401, middleware.foreign_credential_message)
    middleware.Absent -> require_session(req, db, secret, next)
  }
}

/// The cookie half, which is what a browser download arrives with.
///
/// The same signed value wisp writes and the same secret it signs with, so a
/// cookie minted by the ordinary sign-in works unchanged; the database is then
/// what says whether the session is live, exactly as `middleware.check_session`
/// does. No CSRF: this is a GET, and a read needs none.
fn require_session(
  req: HttpRequest(mist.Connection),
  db: Pool,
  secret: String,
  next: fn(Principal) -> HttpResponse(mist.ResponseData),
) -> HttpResponse(mist.ResponseData) {
  let token =
    request.get_cookies(req)
    |> list.key_find(session.cookie_name)
    |> result.try(fn(value) {
      crypto.verify_signed_message(value, <<secret:utf8>>)
    })
    |> result.try(bit_array.to_string)
  case token {
    Error(Nil) -> refused(401, "sign in first")
    Ok(token) ->
      case
        pool.with_connection(db, fn(conn) {
          session.get(conn, token, now_unix())
        })
      {
        Ok(Ok(live)) -> next(Principal(live.user_id, Cookie(live.csrf)))
        Ok(Error(Nil)) -> refused(401, "session expired")
        Error(_) -> refused(500, "database unavailable")
      }
  }
}

fn require_network(
  db: Pool,
  who: Principal,
  slug: String,
  network: String,
  next: fn(#(String, String, Bool)) -> HttpResponse(mist.ResponseData),
) -> HttpResponse(mist.ResponseData) {
  case browse_api.for_download(db, who, slug, network) {
    Ok(facts) -> next(facts)
    Error(Nil) -> refused(404, "no such network")
  }
}

fn require(
  condition: Bool,
  status: Int,
  message: String,
  next: fn(Nil) -> HttpResponse(mist.ResponseData),
) -> HttpResponse(mist.ResponseData) {
  case condition {
    True -> next(Nil)
    False -> refused(status, message)
  }
}

/// The byte window a request asked for.
///
/// One range only. A multi-range request needs a multipart body, which this
/// relay does not build, so it is refused rather than answered with the first
/// range and a 206 that lies about what it contains.
fn wanted_range(
  req: HttpRequest(mist.Connection),
  size: Int,
) -> Result(#(Int, Int, Bool), Nil) {
  case request.get_header(req, "range") {
    Error(Nil) -> Ok(#(0, size, False))
    Ok(header) ->
      case string.split(string.trim(header), "=") {
        ["bytes", spec] ->
          case string.contains(spec, ",") {
            True -> Error(Nil)
            False ->
              case string.split(spec, "-") {
                // bytes=-N: the last N bytes.
                ["", last] ->
                  case int.parse(last) {
                    Ok(n) if n > 0 && n <= size -> Ok(#(size - n, n, True))
                    _ -> Error(Nil)
                  }
                [first, ""] ->
                  case int.parse(first) {
                    Ok(start) if start < size -> Ok(#(start, size - start, True))
                    _ -> Error(Nil)
                  }
                [first, last] ->
                  case int.parse(first), int.parse(last) {
                    Ok(start), Ok(end) if start <= end && start < size ->
                      Ok(#(start, int.min(end, size - 1) - start + 1, True))
                    _, _ -> Error(Nil)
                  }
                _ -> Error(Nil)
              }
          }
        _ -> Error(Nil)
      }
  }
}

/// The name a browser saves the file under: the path's last segment, with
/// anything that could break out of the quoted header removed.
fn filename(path: String) -> String {
  let base = case string.split(path, "/") |> list.last {
    Ok(name) -> name
    Error(Nil) -> path
  }
  base
  |> string.to_utf_codepoints
  |> list.filter(fn(point) {
    let code = string.utf_codepoint_to_int(point)
    code >= 0x20 && code < 0x7F && code != 0x22 && code != 0x5C
  })
  |> string.from_utf_codepoints
  |> fn(name) {
    case name {
      "" -> "download"
      other -> other
    }
  }
}

fn param(params: List(#(String, String)), key: String) -> String {
  list.key_find(params, key) |> result.unwrap("")
}

fn status_of(code: String) -> Int {
  case code {
    "not-found" -> 404
    "invalid" -> 400
    "divergent" -> 409
    "unavailable" -> 503
    _ -> 502
  }
}

/// A refusal, as plain text: this route's success is a byte stream, so its
/// failures are not dressed as the JSON API's.
fn refused(status: Int, message: String) -> HttpResponse(mist.ResponseData) {
  response.new(status)
  |> response.set_header("content-type", "text/plain; charset=utf-8")
  |> response.set_header("x-content-type-options", "nosniff")
  |> response.set_body(mist.Bytes(bytes_tree.from_string(message <> "\n")))
}
