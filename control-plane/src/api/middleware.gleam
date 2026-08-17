//// Session + CSRF middleware for the product API.

import auth/session.{type Session}
import gleam/http.{Get, Head, Options}
import gleam/json
import gleam/list
import store/sqlite.{type Connection}
import wisp.{type Request, type Response}

@external(erlang, "cp_sys_ffi", "now_unix")
pub fn now_unix() -> Int

pub fn error_json(status: Int, code: String, message: String) -> Response {
  json.object([
    #(
      "error",
      json.object([
        #("code", json.string(code)),
        #("message", json.string(message)),
      ]),
    ),
  ])
  |> json.to_string
  |> wisp.json_response(status)
}

/// Resolves the session cookie; mutating methods must echo the session's
/// CSRF token in an `x-csrf` header (double submit).
///
/// Returns the refusal rather than taking a continuation, so a caller may
/// hand the connection back before running the request's own work. That is
/// what keeps a request from holding two pooled connections at once: with a
/// pool of `size`, `size` concurrent requests would each hold one and queue
/// for a second, and every one of them would sit there until
/// `pool.acquire`'s call timeout killed it.
pub fn check_session(
  req: Request,
  conn: Connection,
) -> Result(Session, Response) {
  case wisp.get_cookie(req, session.cookie_name, wisp.Signed) {
    Error(Nil) -> Error(error_json(401, "unauthenticated", "sign in first"))
    Ok(token) ->
      case session.get(conn, token, now_unix()) {
        Error(Nil) ->
          Error(error_json(401, "unauthenticated", "session expired"))
        Ok(live) ->
          case req.method {
            Get | Head | Options -> Ok(live)
            _ ->
              case list.key_find(req.headers, "x-csrf") {
                Ok(header) if header == live.csrf -> Ok(live)
                _ ->
                  Error(error_json(
                    403,
                    "csrf",
                    "missing or wrong x-csrf header",
                  ))
              }
          }
      }
  }
}

/// `check_session` for a caller that already holds the connection it wants
/// to keep using, and so has nothing to hand back first.
pub fn require_session(
  req: Request,
  conn: Connection,
  next: fn(Session) -> Response,
) -> Response {
  case check_session(req, conn) {
    Ok(live) -> next(live)
    Error(response) -> response
  }
}
