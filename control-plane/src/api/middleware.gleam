//// Credential resolution for the product API: the session cookie and its
//// CSRF double submit, and the bearer token an org-scoped API key is
//// presented as.

import auth/api_key
import auth/principal.{type Principal, ApiKey, Cookie, Principal}
import auth/session.{type Session}
import gleam/http.{Get, Head, Options}
import gleam/json
import gleam/list
import gleam/string
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

/// Resolves whichever credential the request carries.
///
/// **An `Authorization` header wins, and never falls back.** A bearer token
/// is a caller saying which credential it means to use; treating a bad one as
/// "no credential" and reaching for the cookie instead would let a page the
/// browser holds a session for be driven by a request that named something
/// else entirely. A malformed or unknown token is a 401, not a downgrade.
///
/// **A key needs no CSRF token, and that is not an omission.** CSRF exists
/// because a cookie is *ambient*: the browser attaches it to a cross-site
/// request nobody at the keyboard asked for. Nothing attaches an
/// `Authorization` header on its own — a cross-origin page cannot set one and
/// have it sent — so there is no ambient authority to defend, and demanding a
/// token that only a session has would simply make keys unusable.
pub fn check_principal(
  req: Request,
  conn: Connection,
) -> Result(Principal, Response) {
  case bearer(req) {
    Ok(token) ->
      case api_key.authenticate(conn, token, now_unix()) {
        Ok(key) ->
          Ok(Principal(key.created_by, ApiKey(key.key_id, key.org_id, key.role)))
        Error(Nil) ->
          Error(error_json(
            401,
            "unauthenticated",
            "unknown, expired or revoked API key",
          ))
      }
    Error(Nil) ->
      case check_session(req, conn) {
        Ok(live) -> Ok(Principal(live.user_id, Cookie(live.csrf)))
        Error(refusal) -> Error(refusal)
      }
  }
}

fn bearer(req: Request) -> Result(String, Nil) {
  bearer_token(req.headers)
}

/// The token of an `Authorization: Bearer …` header, if there is one.
///
/// The scheme is matched case-insensitively (RFC 7235 §2.1 says it is), the
/// header name is already lowercase by the time wisp or mist hands it over,
/// and an empty token is the same as no header — a caller that sent `Bearer `
/// sent no credential, and should be told to sign in rather than that its key
/// is unknown.
///
/// Takes the header list rather than a request so the streaming download
/// route, which lives below wisp and holds a mist request, reads the header
/// the same way every other route does.
pub fn bearer_token(headers: List(#(String, String))) -> Result(String, Nil) {
  case list.key_find(headers, "authorization") {
    Error(Nil) -> Error(Nil)
    Ok(value) ->
      case string.split_once(string.trim(value), " ") {
        Ok(#(scheme, rest)) ->
          case string.lowercase(scheme) == "bearer", string.trim(rest) {
            True, "" -> Error(Nil)
            True, token -> Ok(token)
            False, _ -> Error(Nil)
          }
        Error(Nil) -> Error(Nil)
      }
  }
}

/// The refusal for a route an API key may not take.
///
/// Three kinds of endpoint carry it, and they have one thing in common: each
/// would let a key reach past the org and role it was minted with.
///
///   * **Account endpoints** — creating an org, accepting an invitation,
///     signing in or out. These are about a *person*; a key has no account
///     to act on, and an org it created would answer to nobody's membership.
///   * **Membership endpoints** — invitations, role changes, removals. An
///     admin key that can invite an admin can hand out standing human access
///     that outlives the key, which is exactly the escalation a scoped
///     credential is supposed to make impossible.
///   * **Key management itself** — a key that can mint keys can mint one
///     that never expires, and revoking the one you know about would not end
///     the access.
///
/// Everything else an org owns — its networks, its devices and their keys,
/// the browse surface, the audit trail — is open to a key at the role floor
/// the route already carries. Those are the machine-facing acts a key exists
/// for.
pub fn api_key_refused() -> Response {
  error_json(
    403,
    "api_key_forbidden",
    "this endpoint is for signed-in users: an API key may not manage "
      <> "accounts, membership or other API keys",
  )
}

/// Runs `next` only for a request made by a person.
pub fn require_user(who: Principal, next: fn() -> Response) -> Response {
  case who.credential {
    Cookie(_) -> next()
    ApiKey(..) -> api_key_refused()
  }
}
