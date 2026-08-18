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
//// cookie is a stored-XSS machine — which is also why there is no preview.

import api/agent.{type Relay, type Session}
import api/browse_api.{type Browse}
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

/// What one download needs to know about itself: the audit row it will write,
/// and the slot it has to give back.
type Download {
  Download(
    db: Pool,
    registry: Subject(agent.Msg),
    user_id: String,
    org_id: String,
    network: String,
    space: String,
    path: String,
  )
}

/// `GET /api/orgs/:slug/networks/:net/browse/file?space=&path=&from=`
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

  use user_id <- require_user(req, db, secret)
  use #(org_id, network_id, enabled) <- require_network(
    db,
    user_id,
    slug,
    network,
  )
  use Nil <- require(enabled, 409, "file browsing is not enabled")
  use Nil <- require(
    space != "" && path != "",
    400,
    "space= and path= are required",
  )

  let registry = browse_api.registry(browse)
  let attached =
    agent.sessions_for(registry, network_id)
    |> list.filter(agent.exposes(_, space))
  use first <- pick(attached)

  // A read is a same-origin GET with cookies and needs no CSRF token, so a
  // hostile page can start one from an `img` tag. The cap is what stops it
  // starting a hundred.
  use Nil <- require(
    agent.claim_stream(registry, user_id),
    429,
    "too many downloads open at once (limit "
      <> int.to_string(agent.streams_per_user())
      <> ")",
  )

  // Two tunnel steps. The resolve pins the version to its content root and
  // names the origins currently holding it; the read is then addressed *by
  // root*, so a publish landing in between cannot swap the bytes mid-download.
  let download = Download(db, registry, user_id, org_id, network, space, path)
  case agent.ask(first, agent.Resolve(space, path, from)) {
    Error(refusal) -> {
      agent.release_stream(registry, user_id)
      refused(status_of(refusal.code), refusal.message)
    }
    Ok(agent.Resolved(_origin, root, size, _seq, holders)) -> {
      // Holders first, then anyone: a non-holder still answers correctly, its
      // blob fetcher pulling the missing ranges from peers bao-verified. One
      // extra internal hop, the same bytes.
      let session = case agent.route(attached, holders) {
        Some(session) -> session
        None -> first
      }
      case wanted_range(req, size) {
        Error(Nil) -> {
          agent.release_stream(registry, user_id)
          refused(
            416,
            "that Range is not satisfiable for a "
              <> int.to_string(size)
              <> "-byte object",
          )
        }
        Ok(#(start, length, partial)) ->
          stream(req, session, download, root, size, start, length, partial)
      }
    }
    Ok(_) -> {
      agent.release_stream(registry, user_id)
      refused(502, "the daemon answered the wrong question")
    }
  }
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
        agent.Finished(next) -> {
          record(download, next, "ok")
          mist.ChunkStop
        }
        agent.Failed(next, why) -> {
          record(download, next, why)
          // Aborted rather than closed cleanly: a truncated body must never
          // reach a browser as a complete file.
          mist.ChunkAbort(why)
        }
      }
    },
  )
}

fn record(download: Download, relay: Relay, outcome: String) -> Nil {
  agent.release_stream(download.registry, download.user_id)
  browse_api.audit_download(
    download.db,
    download.user_id,
    download.org_id,
    download.network,
    download.space,
    download.path,
    agent.relay_root(relay),
    agent.relay_sent(relay),
    outcome,
  )
}

// -- request plumbing --------------------------------------------------------

/// Resolves the session cookie without wisp, which cannot reach here.
///
/// The same signed value wisp writes and the same secret it signs with, so a
/// cookie minted by the ordinary sign-in works unchanged; the database is then
/// what says whether the session is live, exactly as `middleware.check_session`
/// does. No CSRF: this is a GET, and a read needs none.
fn require_user(
  req: HttpRequest(mist.Connection),
  db: Pool,
  secret: String,
  next: fn(String) -> HttpResponse(mist.ResponseData),
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
        Ok(Ok(live)) -> next(live.user_id)
        Ok(Error(Nil)) -> refused(401, "session expired")
        Error(_) -> refused(500, "database unavailable")
      }
  }
}

fn require_network(
  db: Pool,
  user_id: String,
  slug: String,
  network: String,
  next: fn(#(String, String, Bool)) -> HttpResponse(mist.ResponseData),
) -> HttpResponse(mist.ResponseData) {
  case browse_api.for_download(db, user_id, slug, network) {
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

fn pick(
  sessions: List(Session),
  next: fn(Session) -> HttpResponse(mist.ResponseData),
) -> HttpResponse(mist.ResponseData) {
  case sessions {
    [first, ..] -> next(first)
    [] -> refused(503, "no attached daemon exposes that space")
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
