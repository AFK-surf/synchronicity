//// The auth HTTP surface: OAuth start/callback for Google and GitHub,
//// magic-link request/redeem, logout, and /api/me.

import api/middleware.{error_json, now_unix}
import auth/github
import auth/google
import auth/identity
import auth/magic
import auth/oauth.{type Provider}
import auth/oidc
import auth/session
import dnssec/keys
import email/mailer.{type Mailer}
import exception
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None}
import store/db
import store/sqlite.{type Connection, Text}
import wisp.{type Request, type Response}

pub type AuthContext {
  AuthContext(
    db_path: String,
    public_url: String,
    mail: Mailer,
    google: Option(Provider),
    github: Option(Provider),
    /// The zone key — product mutations re-sign the zone in-transaction.
    csk: keys.Csk,
  )
}

/// Opens a request-scoped connection (csqlite processes are cheap and the
/// dashboard's write rate is tiny; WAL + busy_timeout serialize writers).
///
/// The close is deferred, not sequential: a panic anywhere in `next` must
/// still tear the connection down. Wisp rescues crashes, so the process
/// survives — without the defer, a panic inside an open BEGIN IMMEDIATE
/// would leave a csqlite process holding the database write lock for the
/// life of the HTTP connection, wedging every subsequent write. Closing
/// the port makes SQLite discard any open transaction.
pub fn with_db(ctx: AuthContext, next: fn(Connection) -> Response) -> Response {
  case db.open_primary(ctx.db_path) {
    Ok(conn) -> {
      use <- exception.defer(fn() { sqlite.close(conn) })
      next(conn)
    }
    Error(_) -> error_json(500, "internal", "database unavailable")
  }
}

fn provider_for(ctx: AuthContext, key: String) -> Result(Provider, Nil) {
  case key {
    "google" -> option.to_result(ctx.google, Nil)
    "github" -> option.to_result(ctx.github, Nil)
    _ -> Error(Nil)
  }
}

fn redirect_uri(ctx: AuthContext, key: String) -> String {
  ctx.public_url <> "/auth/callback/" <> key
}

/// `?link=1` on a start URL, from a live session, records that the
/// resulting identity should be linked to the session's user instead of
/// logging anyone in — the sanctioned path for custom-OIDC identities.
fn maybe_link_user(req: Request, conn: Connection) -> Option(String) {
  case list.key_find(wisp.get_query(req), "link") {
    Ok("1") ->
      case wisp.get_cookie(req, session.cookie_name, wisp.Signed) {
        Ok(token) ->
          case session.get(conn, token, now_unix()) {
            Ok(live) -> option.Some(live.user_id)
            Error(Nil) -> None
          }
        Error(Nil) -> None
      }
    _ -> None
  }
}

pub fn start(req: Request, ctx: AuthContext, key: String) -> Response {
  case provider_for(ctx, key) {
    Error(Nil) -> error_json(404, "unknown_provider", "provider not configured")
    Ok(provider) ->
      with_db(ctx, fn(conn) {
        case
          oauth.start(
            conn,
            provider,
            redirect_uri(ctx, key),
            None,
            maybe_link_user(req, conn),
            now_unix(),
          )
        {
          Ok(url) -> wisp.redirect(url)
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
      Ok(org) ->
        case
          oauth.start(
            conn,
            org.provider,
            redirect_uri(ctx, "oidc"),
            option.Some(org.provider_id),
            maybe_link_user(req, conn),
            now_unix(),
          )
        {
          Ok(url) -> wisp.redirect(url)
          Error(_) -> error_json(500, "internal", "could not start flow")
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
                      use tokens <- gleam_result_try(oauth.exchange(
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

fn gleam_result_try(
  result: Result(a, e),
  next: fn(a) -> Result(b, e),
) -> Result(b, e) {
  case result {
    Ok(value) -> next(value)
    Error(e) -> Error(e)
  }
}

/// Shared tail of every callback: link to the session's user when the
/// flow was started with ?link=1, otherwise log in under the policy.
fn conclude(
  req: Request,
  conn: Connection,
  provider_key: String,
  oidc_provider_id: Option(String),
  who: oauth.ProviderIdentity,
  link_user_id: Option(String),
) -> Response {
  case link_user_id {
    option.Some(user_id) ->
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
        Ok(_) -> wisp.redirect("/settings?linked=" <> provider_key)
        Error(_) -> error_json(409, "conflict", "identity already linked")
      }
    None ->
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
        Ok(who) -> conclude(req, conn, key, None, who, flow.link_user_id)
      }
    }
  }
}

/// Creates the session and sets the signed cookie.
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
        let _ = magic.request(conn, email, now_unix(), ctx.public_url, ctx.mail)
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

pub fn me(req: Request, ctx: AuthContext) -> Response {
  with_db(ctx, fn(conn) {
    use live <- middleware.require_session(req, conn)
    let user =
      sqlite.query(
        conn,
        "SELECT email, coalesce(name, '') FROM users WHERE id = ?",
        [Text(live.user_id)],
      )
    let orgs =
      sqlite.query(
        conn,
        "SELECT o.id, o.slug, o.name, m.role
         FROM org_members m JOIN orgs o ON o.id = m.org_id
         WHERE m.user_id = ? ORDER BY o.slug",
        [Text(live.user_id)],
      )
    case user, orgs {
      Ok([[Text(email), Text(display)]]), Ok(org_rows) ->
        json.object([
          #(
            "user",
            json.object([
              #("id", json.string(live.user_id)),
              #("email", json.string(email)),
              #("name", json.string(display)),
            ]),
          ),
          #("csrf", json.string(live.csrf)),
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
