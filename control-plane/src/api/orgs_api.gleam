//// Orgs, memberships and invites.

import api/auth_api.{type AuthContext, with_db}
import api/common.{
  Admin, Member, Owner, audit, constraint_response, ok_json, require_org,
  text_at, transaction, valid_dns_label,
}
import api/middleware.{error_json, now_unix}
import auth/oidc
import auth/session.{type Session}
import email/mailer
import gleam/crypto
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import store/sqlite.{type Connection, Blob, Int as VInt, Text}
import util/id
import wisp.{type Request, type Response}

fn body_decoder(
  req: Request,
  decoder: decode.Decoder(a),
  next: fn(a) -> Response,
) -> Response {
  use body <- wisp.require_string_body(req)
  case json.parse(body, decoder) {
    Ok(value) -> next(value)
    Error(_) -> error_json(400, "bad_request", "malformed JSON body")
  }
}

pub fn create_org(req: Request, ctx: AuthContext, live: Session) -> Response {
  let decoder = {
    use slug <- decode.field("slug", decode.string)
    use org_name <- decode.field("name", decode.string)
    decode.success(#(slug, org_name))
  }
  use #(slug, org_name) <- body_decoder(req, decoder)
  case valid_dns_label(slug) {
    False ->
      error_json(
        400,
        "bad_slug",
        "slug must be a DNS label: [a-z0-9-]{1,63}, no leading/trailing hyphen",
      )
    True ->
      with_db(ctx, fn(conn) {
        let org_id = id.new()
        // One transaction: an org must never exist without its owner.
        case
          transaction(conn, fn() {
            {
              use _ <- result.try(
                sqlite.exec(conn, "INSERT INTO orgs VALUES (?, ?, ?, ?)", [
                  Text(org_id),
                  Text(slug),
                  Text(org_name),
                  VInt(now_unix()),
                ]),
              )
              use _ <- result.try(
                sqlite.exec(
                  conn,
                  "INSERT INTO org_members VALUES (?, ?, 'owner', ?)",
                  [
                    Text(org_id),
                    Text(live.user_id),
                    VInt(now_unix()),
                  ],
                ),
              )
              audit(
                conn,
                live.user_id,
                org_id,
                "org.create",
                json.object([#("slug", json.string(slug))]),
              )
            }
            |> result.map_error(constraint_response)
          })
        {
          Ok(Nil) ->
            ok_json(
              json.object([
                #("id", json.string(org_id)),
                #("slug", json.string(slug)),
              ]),
            )
          Error(response) -> response
        }
      })
  }
}

pub fn get_org(ctx: AuthContext, live: Session, slug: String) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, role <- require_org(conn, slug, live.user_id, Member)
    let networks =
      sqlite.query(
        conn,
        "SELECT name FROM networks WHERE org_id = ? ORDER BY name",
        [Text(org_id)],
      )
    let devices =
      sqlite.query(conn, "SELECT count(*) FROM devices WHERE org_id = ?", [
        Text(org_id),
      ])
    case networks, devices {
      Ok(network_rows), Ok([[VInt(device_count)]]) ->
        ok_json(
          json.object([
            #("id", json.string(org_id)),
            #("slug", json.string(slug)),
            #("role", json.string(common.role_to_string(role))),
            #(
              "networks",
              json.array(network_rows, fn(row) { json.string(text_at(row, 0)) }),
            ),
            #("device_count", json.int(device_count)),
          ]),
        )
      _, _ -> error_json(500, "internal", "database error")
    }
  })
}

pub fn list_members(ctx: AuthContext, live: Session, slug: String) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _role <- require_org(conn, slug, live.user_id, Member)
    let rows =
      sqlite.query(
        conn,
        "SELECT u.id, u.email, coalesce(u.name, ''), m.role
         FROM org_members m JOIN users u ON u.id = m.user_id
         WHERE m.org_id = ? ORDER BY u.email",
        [Text(org_id)],
      )
    common.rows_json(rows, fn(row) {
      json.object([
        #("user_id", json.string(text_at(row, 0))),
        #("email", json.string(text_at(row, 1))),
        #("name", json.string(text_at(row, 2))),
        #("role", json.string(text_at(row, 3))),
      ])
    })
  })
}

pub fn change_role(
  req: Request,
  ctx: AuthContext,
  live: Session,
  slug: String,
  target_user: String,
) -> Response {
  let decoder = {
    use role <- decode.field("role", decode.string)
    decode.success(role)
  }
  use role_text <- body_decoder(req, decoder)
  case common.role_from_string(role_text) {
    Error(Nil) -> error_json(400, "bad_role", "role must be owner|admin|member")
    Ok(_) ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, live.user_id, Owner)
        case would_lose_last_owner(conn, org_id, target_user, role_text) {
          True ->
            error_json(409, "last_owner", "an org must keep at least one owner")
          False -> {
            let update =
              sqlite.exec(
                conn,
                "UPDATE org_members SET role = ? WHERE org_id = ? AND user_id = ?",
                [Text(role_text), Text(org_id), Text(target_user)],
              )
            case update {
              Ok(sqlite.Done(1, _)) -> {
                let _ =
                  audit(
                    conn,
                    live.user_id,
                    org_id,
                    "member.role",
                    json.object([
                      #("user", json.string(target_user)),
                      #("role", json.string(role_text)),
                    ]),
                  )
                ok_json(json.object([#("ok", json.bool(True))]))
              }
              Ok(_) -> error_json(404, "not_found", "no such member")
              Error(e) -> constraint_response(e)
            }
          }
        }
      })
  }
}

pub fn remove_member(
  ctx: AuthContext,
  live: Session,
  slug: String,
  target_user: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, my_role <- require_org(conn, slug, live.user_id, Admin)
    let target_role =
      sqlite.query(
        conn,
        "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
        [Text(org_id), Text(target_user)],
      )
    case target_role {
      Ok([[Text("owner")]]) if my_role != Owner ->
        error_json(403, "forbidden", "only owners may remove owners")
      Ok([[Text(role_text)]]) ->
        case role_text == "owner" && last_owner(conn, org_id, target_user) {
          True ->
            error_json(409, "last_owner", "an org must keep at least one owner")
          False -> {
            let _ =
              sqlite.exec(
                conn,
                "DELETE FROM org_members WHERE org_id = ? AND user_id = ?",
                [Text(org_id), Text(target_user)],
              )
            let _ =
              audit(
                conn,
                live.user_id,
                org_id,
                "member.remove",
                json.object([#("user", json.string(target_user))]),
              )
            ok_json(json.object([#("ok", json.bool(True))]))
          }
        }
      Ok(_) -> error_json(404, "not_found", "no such member")
      Error(_) -> error_json(500, "internal", "database error")
    }
  })
}

fn last_owner(conn: Connection, org_id: String, user_id: String) -> Bool {
  case
    sqlite.query(
      conn,
      "SELECT count(*) FROM org_members
       WHERE org_id = ? AND role = 'owner' AND user_id != ?",
      [Text(org_id), Text(user_id)],
    )
  {
    Ok([[VInt(0)]]) -> True
    _ -> False
  }
}

fn would_lose_last_owner(
  conn: Connection,
  org_id: String,
  target_user: String,
  new_role: String,
) -> Bool {
  new_role != "owner" && last_owner(conn, org_id, target_user)
}

pub fn create_invite(
  req: Request,
  ctx: AuthContext,
  live: Session,
  slug: String,
) -> Response {
  let decoder = {
    use email <- decode.field("email", decode.string)
    use role <- decode.optional_field("role", "member", decode.string)
    decode.success(#(email, role))
  }
  use #(email, role) <- body_decoder(req, decoder)
  case role == "member" || role == "admin" {
    False -> error_json(400, "bad_role", "invite role must be member or admin")
    True ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, live.user_id, Admin)
        let token = id.secret()
        let token_hash = crypto.hash(crypto.Sha256, <<token:utf8>>)
        let insert =
          sqlite.exec(
            conn,
            "INSERT INTO invites VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
            [
              Text(id.new()),
              Text(org_id),
              Text(email),
              Text(role),
              Blob(token_hash),
              Text(live.user_id),
              VInt(now_unix()),
              VInt(now_unix() + 604_800),
            ],
          )
        case insert {
          Error(e) -> constraint_response(e)
          Ok(_) -> {
            let link = ctx.public_url <> "/invite?token=" <> token
            let _ =
              mailer.send(
                ctx.mail,
                email,
                "You have been invited to " <> slug <> " on synchronicity",
                "Accept the invitation (valid for 7 days):\n\n" <> link <> "\n",
              )
            let _ =
              audit(
                conn,
                live.user_id,
                org_id,
                "invite.create",
                json.object([
                  #("email", json.string(email)),
                  #("role", json.string(role)),
                ]),
              )
            ok_json(json.object([#("ok", json.bool(True))]))
          }
        }
      })
  }
}

pub fn accept_invite(
  req: Request,
  ctx: AuthContext,
  live: Session,
) -> Response {
  let decoder = {
    use token <- decode.field("token", decode.string)
    decode.success(token)
  }
  use token <- body_decoder(req, decoder)
  with_db(ctx, fn(conn) {
    let token_hash = crypto.hash(crypto.Sha256, <<token:utf8>>)
    let lookup =
      sqlite.query(
        conn,
        "SELECT id, org_id, role FROM invites
         WHERE token_hash = ? AND accepted_at IS NULL AND expires_at > ?",
        [Blob(token_hash), VInt(now_unix())],
      )
    case lookup {
      Ok([[Text(invite_id), Text(org_id), Text(role)]]) -> {
        // Membership + invite consumption move together or not at all.
        let applied =
          transaction(conn, fn() {
            {
              use _ <- result.try(
                sqlite.exec(
                  conn,
                  "INSERT OR IGNORE INTO org_members VALUES (?, ?, ?, ?)",
                  [
                    Text(org_id),
                    Text(live.user_id),
                    Text(role),
                    VInt(now_unix()),
                  ],
                ),
              )
              use _ <- result.try(
                sqlite.exec(
                  conn,
                  "UPDATE invites SET accepted_at = ? WHERE id = ?",
                  [VInt(now_unix()), Text(invite_id)],
                ),
              )
              audit(
                conn,
                live.user_id,
                org_id,
                "invite.accept",
                json.object([#("invite", json.string(invite_id))]),
              )
            }
            |> result.map_error(constraint_response)
          })
        case applied {
          Ok(Nil) -> {
            let slug =
              sqlite.query(conn, "SELECT slug FROM orgs WHERE id = ?", [
                Text(org_id),
              ])
            let slug_text = case slug {
              Ok([row]) -> text_at(row, 0)
              _ -> ""
            }
            ok_json(json.object([#("org", json.string(slug_text))]))
          }
          Error(response) -> response
        }
      }
      Ok(_) -> error_json(404, "bad_invite", "invalid or expired invite")
      Error(_) -> error_json(500, "internal", "database error")
    }
  })
}

/// OIDC configuration is owner-only in both directions: it is
/// takeover-adjacent (it decides who can sign in under the org's issuer).
pub fn get_oidc(ctx: AuthContext, live: Session, slug: String) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Owner)
    let rows =
      sqlite.query(
        conn,
        "SELECT issuer, client_id, authorization_endpoint, token_endpoint,
                discovered_at
         FROM oidc_providers WHERE org_id = ?",
        [Text(org_id)],
      )
    case rows {
      Ok([row]) ->
        ok_json(
          json.object([
            #("issuer", json.string(text_at(row, 0))),
            #("client_id", json.string(text_at(row, 1))),
            #("authorization_endpoint", json.string(text_at(row, 2))),
            #("token_endpoint", json.string(text_at(row, 3))),
            #("discovered_at", json.int(common.int_at(row, 4))),
          ]),
        )
      Ok(_) -> ok_json(json.null())
      Error(_) -> error_json(500, "internal", "database error")
    }
  })
}

pub fn put_oidc(
  req: Request,
  ctx: AuthContext,
  live: Session,
  slug: String,
) -> Response {
  let decoder = {
    use issuer <- decode.field("issuer", decode.string)
    use client_id <- decode.field("client_id", decode.string)
    use client_secret <- decode.field("client_secret", decode.string)
    decode.success(#(issuer, client_id, client_secret))
  }
  use #(issuer, client_id, client_secret) <- body_decoder(req, decoder)
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Owner)
    // Discovery runs now, over verified TLS; a mismatched or unreachable
    // issuer refuses the whole save.
    case oidc.save(conn, org_id, issuer, client_id, client_secret, now_unix()) {
      Ok(found) -> {
        let _ =
          audit(
            conn,
            live.user_id,
            org_id,
            "oidc.configure",
            json.object([#("issuer", json.string(issuer))]),
          )
        ok_json(
          json.object([
            #("issuer", json.string(issuer)),
            #(
              "authorization_endpoint",
              json.string(found.authorization_endpoint),
            ),
            #("token_endpoint", json.string(found.token_endpoint)),
          ]),
        )
      }
      Error(message) -> error_json(502, "discovery_failed", message)
    }
  })
}

pub fn delete_oidc(ctx: AuthContext, live: Session, slug: String) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Owner)
    // Identities and their provider row go together: a provider without
    // its identities is fine, identities without their provider are not.
    let removed =
      transaction(conn, fn() {
        {
          use _ <- result.try(
            sqlite.exec(
              conn,
              "DELETE FROM auth_identities WHERE oidc_provider_id IN
               (SELECT id FROM oidc_providers WHERE org_id = ?)",
              [Text(org_id)],
            ),
          )
          use _ <- result.try(
            sqlite.exec(conn, "DELETE FROM oidc_providers WHERE org_id = ?", [
              Text(org_id),
            ]),
          )
          audit(conn, live.user_id, org_id, "oidc.remove", json.object([]))
        }
        |> result.map_error(constraint_response)
      })
    case removed {
      Ok(Nil) -> ok_json(json.object([#("ok", json.bool(True))]))
      Error(response) -> response
    }
  })
}

pub fn audit_log(
  req: Request,
  ctx: AuthContext,
  live: Session,
  slug: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Admin)
    let cursor =
      wisp.get_query(req)
      |> list.key_find("before")
      |> result.try(int.parse)
      |> result.unwrap(9_223_372_036_854_775_807)
    let rows =
      sqlite.query(
        conn,
        "SELECT id, at, coalesce(actor, ''), action, detail FROM audit_log
         WHERE org_id = ? AND id < ? ORDER BY id DESC LIMIT 50",
        [Text(org_id), VInt(cursor)],
      )
    common.rows_json(rows, fn(row) {
      json.object([
        #("id", json.int(common.int_at(row, 0))),
        #("at", json.int(common.int_at(row, 1))),
        #("actor", json.string(text_at(row, 2))),
        #("action", json.string(text_at(row, 3))),
        #("detail", json.string(text_at(row, 4))),
      ])
    })
  })
}
