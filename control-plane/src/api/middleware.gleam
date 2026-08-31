//// Credential resolution for the product API: the session cookie and its
//// CSRF double submit, and the bearer token an API key — org-scoped,
//// network-scoped, or the deployment-wide data-plane key — is presented as.

import auth/api_key
import auth/dataplane_key
import auth/principal.{type Principal, Cookie, Principal}

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

/// What the request said about which credential it means to be judged on.
pub type Presented {
  /// A well-formed `Authorization: Bearer <token>`.
  Bearer(token: String)
  /// An `authorization` header this service cannot read as one of its keys:
  /// another scheme, an empty token, a separator that is not a space.
  Foreign
  /// No `authorization` header at all — the cookie's turn.
  Absent
}

/// Resolves whichever credential the request carries.
///
/// **An `Authorization` header is terminal.** Its presence is a caller saying
/// which credential it means to be judged on, so a header this service cannot
/// turn into a live key is a 401 — never a quiet fall-through to the cookie.
/// Two reasons, and the second is the one that bites in practice:
///
///   * A request that names a credential and is then answered as *somebody
///     else* is a request answered on authority it did not ask for. (Not
///     reachable across origins today — this service sets no CORS headers, so
///     a foreign page cannot get the header sent at all, and the cookie path
///     still demands `x-csrf` — but the rule should not depend on that.)
///   * A script whose `$TOKEN` is unset sends `Authorization: Bearer `. If the
///     machine also holds a session cookie, falling back would run the whole
///     job as the *person*, silently, instead of failing on the first call.
///
/// **A key needs no CSRF token, and that is not an omission.** CSRF exists
/// because a cookie is *ambient*: the browser attaches it to a cross-site
/// request nobody at the keyboard asked for. Nothing attaches an
/// `Authorization` header on its own, so there is no ambient authority to
/// defend, and demanding a token that only a session has would simply make
/// keys unusable.
pub fn check_principal(
  req: Request,
  conn: Connection,
) -> Result(Principal, Response) {
  case presented(req.headers) {
    Bearer(token) ->
      case api_key.authenticate(conn, token, now_unix()) {
        Ok(who) -> Ok(who)
        // The two families are told apart by prefix before either touches the
        // database — `synchdp_` does not start with `synch_` — so this is not
        // a second lookup for a well-formed token of either kind. It costs one
        // extra round trip only for a token that is going to be refused, which
        // is the request we are least interested in making fast.
        Error(Nil) ->
          case dataplane_key.authenticate(conn, token, now_unix()) {
            Ok(who) -> Ok(who)
            Error(Nil) -> Error(bad_key())
          }
      }
    Foreign -> Error(foreign_credential())
    Absent ->
      case check_session(req, conn) {
        Ok(live) -> Ok(Principal(live.user_id, Cookie(live.csrf)))
        Error(refusal) -> Error(refusal)
      }
  }
}

/// What a bearer token that resolves to no live key is told. It does not say
/// which of the three it was: `api_key.authenticate` folds expiry into the
/// lookup precisely so an expired key and one that never existed are the same
/// answer.
///
/// A constant rather than a literal because the streaming download route
/// refuses the same two things in plain text, below wisp, and one credential
/// should not explain itself two ways depending on which route heard it.
pub const bad_key_message = "unknown, expired or revoked API key"

pub const foreign_credential_message = "the Authorization header is not a synchronicity API key: send `Authorization: Bearer synch_…`, or omit the header to use a session cookie"

fn bad_key() -> Response {
  error_json(401, "unauthenticated", bad_key_message)
}

fn foreign_credential() -> Response {
  error_json(401, "unauthenticated", foreign_credential_message)
}

/// Reads the `authorization` header, if any.
///
/// The scheme is matched case-insensitively (RFC 7235 §2.1 says it is) and the
/// header name is already lowercase by the time wisp or mist hands it over.
/// Everything that is not a bearer token with a non-empty value is `Foreign`
/// rather than `Absent`, which is what makes the header terminal.
///
/// Takes the header list rather than a request so the streaming download
/// route, which lives below wisp and holds a mist request, reads the header
/// the same way every other route does.
pub fn presented(headers: List(#(String, String))) -> Presented {
  case list.key_find(headers, "authorization") {
    Error(Nil) -> Absent
    Ok(value) ->
      case string.split_once(string.trim(value), " ") {
        Ok(#(scheme, rest)) ->
          case string.lowercase(scheme) == "bearer", string.trim(rest) {
            True, "" -> Foreign
            True, token -> Bearer(token)
            False, _ -> Foreign
          }
        Error(Nil) -> Foreign
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
///   * **Membership endpoints** — invitations, role changes, removals, the
///     roster read, and the audit trail. An admin key that can invite an
///     admin can hand out standing human access that outlives the key, which
///     is exactly the escalation a scoped credential is supposed to make
///     impossible; and the roster is people's names and addresses, plus the
///     very `user_id` values the mutations take. The trail carries both of
///     those *and* an inventory of the org's other credentials, so closing
///     the roster while leaving it open would have closed nothing.
///   * **Key management itself** — a key that can mint keys can mint one
///     that never expires, and revoking the one you know about would not end
///     the access. Not an absolute: an admin key that deletes a network takes
///     that network's join keys with it, since a scope whose network is gone
///     is a token that can never be used again. What it cannot do is mint,
///     rename, re-scope or enumerate one.
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
    principal.ApiKey(..) -> api_key_refused()
    // A join key gets the refusal that names the one thing it *can* do,
    // rather than a list of things no key may.
    principal.JoinKey(..) -> join_key_refused()
    principal.Dataplane(..) -> dataplane_refused()
  }
}

/// The refusal every route but one gives a join key. Defined here rather than
/// taken from `api/common`, which imports this module.
pub fn join_key_refused() -> Response {
  error_json(
    403,
    "join_key_forbidden",
    "a join key may only add a device to the network it was minted for: "
      <> "POST /api/orgs/<org>/networks/<network>/devices",
  )
}

/// The refusal every route outside `/dp/v1` gives a data-plane key.
///
/// Named rather than folded into `api_key_refused`, for the reason the join
/// key's refusal is named: a credential should be told what it *is* for, and a
/// message about managing accounts and other API keys would send whoever is
/// reading the log looking for the wrong mistake. The one mistake this refusal
/// covers is pointing the data plane's own key at the org API — which the
/// design says can never work, and this is where it does not.
pub fn dataplane_refused() -> Response {
  error_json(
    403,
    "dataplane_forbidden",
    "a data-plane key reaches the hosted-replica API and nothing else: "
      <> "/dp/v1/networks and the routes below it",
  )
}
