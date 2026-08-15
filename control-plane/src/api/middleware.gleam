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
pub fn require_session(
  req: Request,
  conn: Connection,
  next: fn(Session) -> Response,
) -> Response {
  case wisp.get_cookie(req, session.cookie_name, wisp.Signed) {
    Error(Nil) -> error_json(401, "unauthenticated", "sign in first")
    Ok(token) ->
      case session.get(conn, token, now_unix()) {
        Error(Nil) -> error_json(401, "unauthenticated", "session expired")
        Ok(live) ->
          case req.method {
            Get | Head | Options -> next(live)
            _ ->
              case list.key_find(req.headers, "x-csrf") {
                Ok(header) if header == live.csrf -> next(live)
                _ -> error_json(403, "csrf", "missing or wrong x-csrf header")
              }
          }
      }
  }
}
