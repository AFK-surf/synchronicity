//// The auth HTTP surface: OAuth start/callback for Google and GitHub,
//// magic-link request/redeem, logout, and /api/me.

import api/middleware.{error_json, now_unix}
import api/reads.{type Reads}
import auth/github
import auth/google
import auth/identity
import auth/magic
import auth/oauth.{type Provider}
import auth/oidc
import auth/principal.{type Principal}
import auth/session
import config.{type CueProvisioning}
import email/mailer.{type Mailer}
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import store/sqlite.{type Connection, Text}
import util/id
import wisp.{type Request, type Response}
import zone/publish

pub type AuthContext {
  AuthContext(
    /// Request-scoped connections come from here; every checkout is
    /// reset to pristine. Held as `Reads` rather than a bare pool so a
    /// write handler can hand the read half straight to a read handler,
    /// which is the same half a replica mounts on its own.
    reads: Reads,
    /// Where a link mailed to a person comes back to — the balanced entry
    /// name, not this node's own (`CP_ENTRY_URL`).
    entry_url: String,
    mail: Mailer,
    google: Option(Provider),
    github: Option(Provider),
    /// How a product mutation publishes the zone, injected per mode: serve
    /// mode re-signs in-transaction with the CSK; external mode bumps the
    /// serial and re-validates, and the wire follows via the reconciler. The
    /// `Change` says whether the mutation widens what the zone claims, which
    /// is what the transparency gate turns on.
    publish_in_tx: fn(Connection, Int, String, publish.Change) ->
      Result(Int, publish.PublishError),
    /// Runs after a zone mutation commits — a no-op in serve mode (commit
    /// is publication), the reconciler poke in external mode. Never inside
    /// the transaction: provider calls must not hold the write lock.
    published: fn() -> Nil,
    /// Cue's S2S provisioning configuration, or `None` when the integration
    /// is off. Only the primary carries a writable AuthContext, which is also
    /// the only node that may provision.
    cue_provisioning: Option(CueProvisioning),
  )
}

/// Runs `next` with a pooled, freshly reset connection. The pool returns
/// the worker on every exit path — panics included — and a borrower that
/// dies holding one is reclaimed by monitor, so a crashed handler can
/// never wedge the database write lock.
pub fn with_db(ctx: AuthContext, next: fn(Connection) -> Response) -> Response {
  reads.with_db(ctx.reads, next)
}

fn provider_for(ctx: AuthContext, key: String) -> Result(Provider, Nil) {
  case key {
    "google" -> option.to_result(ctx.google, Nil)
    "github" -> option.to_result(ctx.github, Nil)
    _ -> Error(Nil)
  }
}

fn redirect_uri(ctx: AuthContext, key: String) -> String {
  ctx.entry_url <> "/auth/callback/" <> key
}

/// The cookie a sessionless flow binds itself with. The flow sets it on the
/// authorize redirect and the callback requires it back, so a
/// state/authorize URL handed to a victim cannot complete in a browser that
/// never held the initiating side of the flow (login CSRF).
const oauth_flow_cookie = "cp_oauth_flow"

/// A live session in this request's cookie, if any, as `#(user_id, hash)`
/// where the hash is the cookie token's SHA-256 — the sessions table's key.
fn live_session(req: Request, conn: Connection) -> Option(#(String, BitArray)) {
  case wisp.get_cookie(req, session.cookie_name, wisp.Signed) {
    Ok(token) ->
      case session.get(conn, token, now_unix()) {
        Ok(live) -> option.Some(#(live.user_id, id.hash_token(token)))
        Error(Nil) -> None
      }
    Error(Nil) -> None
  }
}

/// What a start URL asks for and binds:
/// `#(link_user_id, binding_token_hash, browser_token_to_set)`.
///
/// `?link=1` from a live session records that the resulting identity should
/// be linked to the session's user instead of logging anyone in — the
/// sanctioned path for custom-OIDC identities. Every flow is bound to the
/// browser that started it — the session's token hash when there is a
/// session, otherwise a fresh per-flow token the caller sets as a cookie on
/// the redirect — which is what the callback checks the completing browser
/// against: a state/authorize URL handed to a victim cannot complete in the
/// victim's browser, with or without a session on either side.
fn flow_session(
  req: Request,
  conn: Connection,
) -> #(Option(String), Option(BitArray), Option(String)) {
  case live_session(req, conn) {
    option.Some(#(user_id, hash)) -> {
      let link_user_id = case list.key_find(wisp.get_query(req), "link") {
        Ok("1") -> option.Some(user_id)
        _ -> None
      }
      #(link_user_id, option.Some(hash), None)
    }
    None -> {
      // No session: bind the flow to a fresh token carried by a cookie only
      // the initiating browser receives. Absence of a session is not a
      // browser identity — without this, an attacker's sessionless flow
      // would complete in any other sessionless browser (login CSRF).
      let token = id.secret()
      #(None, option.Some(id.hash_token(token)), option.Some(token))
    }
  }
}

/// The authorize redirect, plus the per-flow cookie a sessionless flow
/// binds itself with (10 minutes, the flow's own lifetime).
fn redirect_with_flow_cookie(
  req: Request,
  url: String,
  browser_token: Option(String),
) -> Response {
  case browser_token {
    None -> wisp.redirect(url)
    Some(token) ->
      wisp.redirect(url)
      |> wisp.set_cookie(req, oauth_flow_cookie, token, wisp.Signed, 600)
  }
}

pub fn start(req: Request, ctx: AuthContext, key: String) -> Response {
  case provider_for(ctx, key) {
    Error(Nil) -> error_json(404, "unknown_provider", "provider not configured")
    Ok(provider) ->
      with_db(ctx, fn(conn) {
        let #(link_user_id, binding_hash, browser_token) =
          flow_session(req, conn)
        case
          oauth.start(
            conn,
            provider,
            redirect_uri(ctx, key),
            None,
            link_user_id,
            binding_hash,
            now_unix(),
          )
        {
          Ok(url) -> redirect_with_flow_cookie(req, url, browser_token)
          Error(_) -> error_json(500, "internal", "could not start flow")
        }
      })
  }
}

/// Sign-in (or link) with an org's custom OIDC provider, by org slug.
pub fn oidc_start(
  req: Request,
  ctx: AuthContext,
  org_slug: String,
) -> Response {
  with_db(ctx, fn(conn) {
    case oidc.for_org_slug(conn, org_slug) {
      Error(Nil) ->
        error_json(404, "no_oidc", "this org has no OIDC provider configured")
      Ok(org) -> {
        let #(link_user_id, binding_hash, browser_token) =
          flow_session(req, conn)
        case
          oauth.start(
            conn,
            org.provider,
            redirect_uri(ctx, "oidc"),
            option.Some(org.provider_id),
            link_user_id,
            binding_hash,
            now_unix(),
          )
        {
          Ok(url) -> redirect_with_flow_cookie(req, url, browser_token)
          Error(_) -> error_json(500, "internal", "could not start flow")
        }
      }
    }
  })
}

pub fn oidc_callback(req: Request, ctx: AuthContext) -> Response {
  let params = wisp.get_query(req)
  case list.key_find(params, "code"), list.key_find(params, "state") {
    Ok(code), Ok(state) ->
      with_db(ctx, fn(conn) {
        case oauth.take_state(conn, state, now_unix()) {
          Error(Nil) ->
            error_json(400, "bad_state", "expired or replayed OAuth state")
          Ok(flow) ->
            case flow.provider, flow.oidc_provider_id {
              "oidc", option.Some(provider_id) ->
                case oidc.by_id(conn, provider_id) {
                  Error(Nil) ->
                    error_json(404, "no_oidc", "provider was removed mid-flow")
                  Ok(org) -> {
                    let outcome = {
                      use tokens <- result.try(oauth.exchange(
                        org.provider,
                        code,
                        redirect_uri(ctx, "oidc"),
                        flow.pkce_verifier,
                      ))
                      oidc.identity_from_tokens(
                        org,
                        tokens,
                        flow.nonce,
                        now_unix(),
                      )
                    }
                    case outcome {
                      Error(message) ->
                        error_json(502, "identity_failed", message)
                      Ok(who) ->
                        conclude(
                          req,
                          conn,
                          "oidc",
                          option.Some(provider_id),
                          who,
                          flow.binding_token_hash,
                          flow.link_user_id,
                        )
                    }
                  }
                }
              _, _ -> error_json(400, "bad_state", "state is not an OIDC flow")
            }
        }
      })
    _, _ -> error_json(400, "bad_callback", "missing code or state")
  }
}

/// Shared tail of every callback: link to the session's user when the
/// flow was started with ?link=1, otherwise log in under the policy.
///
/// Every flow is bound to the session it was started from, and the callback
/// refuses a browser that is not that session (or, for a sessionless flow,
/// a browser that has one): a state/authorize URL carried to a victim would
/// otherwise link the victim's provider identity to the attacker's account
/// (account-linking CSRF, OAuth Security BCP §4.7) or silently replace the
/// victim's session with the attacker's (login CSRF).
fn conclude(
  req: Request,
  conn: Connection,
  provider_key: String,
  oidc_provider_id: Option(String),
  who: oauth.ProviderIdentity,
  flow_session_hash: Option(BitArray),
  link_user_id: Option(String),
) -> Response {
  case link_user_id {
    option.Some(user_id) ->
      case flow_session_hash {
        None ->
          error_json(
            400,
            "bad_state",
            "this linking flow was not started from a session",
          )
        Some(expected) ->
          case wisp.get_cookie(req, session.cookie_name, wisp.Signed) {
            Ok(token) ->
              case session.get(conn, token, now_unix()) {
                Ok(live) -> {
                  let same_session =
                    live.user_id == user_id && id.hash_token(token) == expected
                  case same_session {
                    True ->
                      case
                        identity.link(
                          conn,
                          user_id,
                          provider_key,
                          oidc_provider_id,
                          who.subject,
                          now_unix(),
                        )
                      {
                        Ok(_) ->
                          wisp.redirect("/settings?linked=" <> provider_key)
                        Error(_) ->
                          error_json(409, "conflict", "identity already linked")
                      }
                    False ->
                      error_json(
                        403,
                        "session_mismatch",
                        "this flow belongs to a different session",
                      )
                  }
                }
                _ ->
                  error_json(
                    403,
                    "session_mismatch",
                    "this flow belongs to a different session",
                  )
              }
            Error(Nil) ->
              error_json(
                403,
                "session_mismatch",
                "this flow belongs to a different session",
              )
          }
      }
    None ->
      case flow_browser_matches(req, flow_session_hash) {
        False ->
          error_json(
            403,
            "session_mismatch",
            "this flow belongs to a different browser",
          )
        True ->
          case
            identity.login(
              conn,
              provider_key,
              oidc_provider_id,
              who.subject,
              who.email,
              who.email_trusted,
              who.name,
              now_unix(),
            )
          {
            Ok(user_id) -> sign_in(req, conn, user_id)
            Error(identity.NeedsExplicitLink(_)) ->
              wisp.redirect("/login?error=needs-link")
            Error(identity.Db(_)) ->
              error_json(500, "internal", "could not record identity")
          }
      }
  }
}

/// Whether the browser completing the flow is the one that started it.
///
/// Every flow is bound to a token the initiating browser holds — the session
/// cookie's token when there was a session, the per-flow cookie otherwise —
/// and the callback requires the stored binding to match one of this
/// browser's cookies. Completing the flow from any other browser, including
/// one with no session at all, is refused: the alternative would be an
/// attacker's flow signing a victim into the attacker's account (login
/// CSRF) or replacing the victim's session with the flow's outcome.
fn flow_browser_matches(req: Request, flow_binding: Option(BitArray)) -> Bool {
  case flow_binding {
    option.Some(expected) ->
      case current_binding_hash(req) {
        option.Some(got) -> got == expected
        None -> False
      }
    // Every flow this build starts stores a binding; a row without one is a
    // flow this build cannot vouch for, and it must not complete either.
    None -> False
  }
}

/// The hash of whichever flow-binding token this browser holds: the session
/// cookie's, or the per-flow cookie's.
fn current_binding_hash(req: Request) -> Option(BitArray) {
  case wisp.get_cookie(req, session.cookie_name, wisp.Signed) {
    Ok(token) -> option.Some(id.hash_token(token))
    Error(Nil) ->
      case wisp.get_cookie(req, oauth_flow_cookie, wisp.Signed) {
        Ok(token) -> option.Some(id.hash_token(token))
        Error(Nil) -> None
      }
  }
}

pub fn callback(req: Request, ctx: AuthContext, key: String) -> Response {
  let params = wisp.get_query(req)
  case
    list.key_find(params, "code"),
    list.key_find(params, "state"),
    provider_for(ctx, key)
  {
    Ok(code), Ok(state), Ok(provider) ->
      with_db(ctx, fn(conn) {
        case oauth.take_state(conn, state, now_unix()) {
          Error(Nil) ->
            error_json(400, "bad_state", "expired or replayed OAuth state")
          Ok(flow) ->
            case flow.provider == key {
              False ->
                error_json(
                  400,
                  "bad_state",
                  "state belongs to another provider",
                )
              True -> finish_oauth(req, ctx, conn, provider, key, flow, code)
            }
        }
      })
    _, _, Error(Nil) ->
      error_json(404, "unknown_provider", "provider not configured")
    _, _, _ -> error_json(400, "bad_callback", "missing code or state")
  }
}

fn finish_oauth(
  req: Request,
  ctx: AuthContext,
  conn: Connection,
  provider: Provider,
  key: String,
  flow: oauth.FlowState,
  code: String,
) -> Response {
  let exchanged =
    oauth.exchange(provider, code, redirect_uri(ctx, key), flow.pkce_verifier)
  case exchanged {
    Error(message) -> error_json(502, "exchange_failed", message)
    Ok(tokens) -> {
      let fetched = case key {
        "google" ->
          google.fetch_identity(
            tokens,
            provider.client_id,
            flow.nonce,
            now_unix(),
          )
        _ ->
          github.fetch_identity(tokens.access_token, "https://api.github.com")
      }
      case fetched {
        Error(message) -> error_json(502, "identity_failed", message)
        Ok(who) ->
          conclude(
            req,
            conn,
            key,
            None,
            who,
            flow.binding_token_hash,
            flow.link_user_id,
          )
      }
    }
  }
}

/// Creates the session and sets the signed cookie.
///
/// Host-only, which is what a browser does with no `Domain` attribute and
/// what this deployment shape wants: the dashboard is reached through one
/// entry name that a load balancer points at whichever node is serving, so
/// the cookie set there is sent back there. Nodes' own names carry the
/// attach endpoints (`CP_ENDPOINTS`), which is a daemon's business and
/// involves no cookie at all.
pub fn sign_in(req: Request, conn: Connection, user_id: String) -> Response {
  case session.create(conn, user_id, now_unix()) {
    Ok(#(token, _session)) ->
      wisp.redirect("/")
      |> wisp.set_cookie(
        req,
        session.cookie_name,
        token,
        wisp.Signed,
        session.ttl_seconds,
      )
    Error(_) -> error_json(500, "internal", "could not create session")
  }
}

pub fn magic_request(req: Request, ctx: AuthContext) -> Response {
  use body <- wisp.require_string_body(req)
  let decoder = {
    use email <- decode.field("email", decode.string)
    decode.success(email)
  }
  case json.parse(body, decoder) {
    Error(_) -> error_json(400, "bad_request", "body must be {\"email\": ...}")
    Ok(email) ->
      with_db(ctx, fn(conn) {
        // Always 200: no account enumeration through this endpoint.
        let _ = magic.request(conn, email, now_unix(), ctx.entry_url, ctx.mail)
        json.object([#("ok", json.bool(True))])
        |> json.to_string
        |> wisp.json_response(200)
      })
  }
}

pub fn magic_redeem(req: Request, ctx: AuthContext) -> Response {
  case list.key_find(wisp.get_query(req), "token") {
    Error(Nil) -> error_json(400, "bad_request", "missing token")
    Ok(token) ->
      with_db(ctx, fn(conn) {
        case magic.redeem(conn, token, now_unix()) {
          Ok(user_id) -> sign_in(req, conn, user_id)
          Error(magic.BadToken) -> wisp.redirect("/login?error=bad-magic-link")
          Error(_) -> error_json(500, "internal", "could not redeem")
        }
      })
  }
}

pub fn logout(req: Request, ctx: AuthContext) -> Response {
  with_db(ctx, fn(conn) {
    case wisp.get_cookie(req, session.cookie_name, wisp.Signed) {
      Ok(token) -> session.delete(conn, token)
      Error(Nil) -> Nil
    }
    json.object([#("ok", json.bool(True))])
    |> json.to_string
    |> wisp.json_response(200)
    |> wisp.set_cookie(req, session.cookie_name, "", wisp.Signed, 0)
  })
}

/// Which sign-in methods this deployment can actually complete, so the
/// login and settings screens offer only those. Answered without a
/// session — the login page asks before anyone has one — and so it
/// carries booleans and nothing else: no client ids, no org slugs,
/// nothing that says who has an account here.
/// Which sign-in methods this deployment has configured, and — on a node
/// that cannot mint a session — where they are offered instead.
///
/// `primary` is empty on the primary, which is that place. On a replica it
/// is the primary's URL and every method reads false: the flows are not
/// mounted here, so offering them would be offering a 404, and the login
/// screen turns the one non-empty field into a link.
pub fn methods(ctx: Option(AuthContext), primary_url: String) -> Response {
  case ctx {
    None ->
      json.object([
        #("google", json.bool(False)),
        #("github", json.bool(False)),
        #("magic_link", json.bool(False)),
        #("oidc", json.bool(False)),
        #("primary", json.string(primary_url)),
      ])
      |> json.to_string
      |> wisp.json_response(200)
    Some(ctx) -> configured_methods(ctx)
  }
}

fn configured_methods(ctx: AuthContext) -> Response {
  with_db(ctx, fn(conn) {
    let google_on = option.is_some(ctx.google)
    let github_on = option.is_some(ctx.github)
    let oidc_on = oidc.any_configured(conn)
    // Log-only mail takes the address and sends nothing, so it is not a
    // method to offer beside working ones. Left alone on the page it is
    // still the way in: the operator reads the link off the service log,
    // which beats a login screen with nothing on it.
    let magic_on =
      mailer.delivers(ctx.mail) || !{ google_on || github_on || oidc_on }
    json.object([
      #("google", json.bool(google_on)),
      #("github", json.bool(github_on)),
      #("magic_link", json.bool(magic_on)),
      #("oidc", json.bool(oidc_on)),
      #("primary", json.string("")),
    ])
    |> json.to_string
    |> wisp.json_response(200)
  })
}

/// The signed-in person, their CSRF token and their orgs — what the SPA
/// bootstraps from.
///
/// Refused for an API key rather than answered: every field here is about an
/// account, and a key does not have one. Its own reach is not a secret it
/// needs an endpoint for — the org it may act in is the org it was minted in,
/// and `GET /api/orgs/<slug>` says whether it still can.
pub fn me(reads_ctx: Reads, who: Principal) -> Response {
  case who.credential {
    principal.Cookie(csrf) -> me_for(reads_ctx, who.user_id, csrf)
    principal.ApiKey(..) -> middleware.api_key_refused()
    principal.JoinKey(..) -> middleware.join_key_refused()
  }
}

fn me_for(db: Reads, user_id: String, csrf: String) -> Response {
  reads.with_db(db, fn(conn) {
    let user =
      sqlite.query(
        conn,
        "SELECT email, coalesce(name, '') FROM users WHERE id = ?",
        [Text(user_id)],
      )
    let orgs =
      sqlite.query(
        conn,
        "SELECT o.id, o.slug, o.name, m.role
         FROM org_members m JOIN orgs o ON o.id = m.org_id
         WHERE m.user_id = ? ORDER BY o.slug",
        [Text(user_id)],
      )
    case user, orgs {
      Ok([[Text(email), Text(display)]]), Ok(org_rows) ->
        json.object([
          #(
            "user",
            json.object([
              #("id", json.string(user_id)),
              #("email", json.string(email)),
              #("name", json.string(display)),
            ]),
          ),
          #("csrf", json.string(csrf)),
          #(
            "orgs",
            json.array(org_rows, fn(row) {
              case row {
                [Text(org_id), Text(slug), Text(org_name), Text(role)] ->
                  json.object([
                    #("id", json.string(org_id)),
                    #("slug", json.string(slug)),
                    #("name", json.string(org_name)),
                    #("role", json.string(role)),
                  ])
                _ -> json.null()
              }
            }),
          ),
        ])
        |> json.to_string
        |> wisp.json_response(200)
      _, _ -> error_json(500, "internal", "could not load user")
    }
  })
}
