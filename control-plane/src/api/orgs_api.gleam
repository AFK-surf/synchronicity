//// Orgs, memberships and invites.

import api/auth_api.{type AuthContext, with_db}
import api/common.{
  Admin, Member, Owner, audit, body_decoder, constraint_response, db_error,
  ok_json, require_org, text_at, transaction, zone_mutation,
}
import api/middleware.{error_json, now_unix, require_user}
import api/reads.{type Reads}
import auth/oidc
import auth/principal.{type Principal}
import dns/name
import email/mailer
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Blob, Int as VInt, Text}
import util/id
import wisp.{type Request, type Response}
import zone/publish

/// Creating an org is a person's act: the creator becomes its owner, and a
/// key has no account to be one with. `require_user` here is also what keeps
/// an org-scoped credential from making an org it would not be scoped to.
pub fn create_org(req: Request, ctx: AuthContext, who: Principal) -> Response {
  use <- require_user(who)
  let decoder = {
    use slug <- decode.field("slug", decode.string)
    use org_name <- decode.field("name", decode.string)
    decode.success(#(slug, org_name))
  }
  use #(slug, org_name) <- body_decoder(req, decoder)
  case name.valid_dns_label(slug) {
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
                    Text(who.user_id),
                    VInt(now_unix()),
                  ],
                ),
              )
              audit(conn, who, org_id, "org.create", [
                #("slug", json.string(slug)),
              ])
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

pub fn get_org(reads: Reads, who: Principal, slug: String) -> Response {
  reads.with_db(reads, fn(conn) {
    use org_id, role <- require_org(conn, slug, who, Member)
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
      _, _ -> db_error()
    }
  })
}

/// Org deletion. Everything the org owns goes in one transaction beside a
/// zone republish — the same contract every zone-shaping mutation carries,
/// so DNS and the tables can never disagree about what existed. The typed
/// confirmation mirrors `delete_network`'s: the slug is the name the zone
/// answered to, and it is what the operator must retype.
pub fn delete_org(
  req: Request,
  ctx: AuthContext,
  who: Principal,
  slug: String,
) -> Response {
  let decoder = {
    use confirm <- decode.field("confirm", decode.string)
    decode.success(confirm)
  }
  use <- require_user(who)
  use confirm <- body_decoder(req, decoder)
  case confirm == slug {
    False -> error_json(400, "confirm", "body confirm must equal the org slug")
    True ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, who, Owner)
        zone_mutation(conn, ctx, who, publish.Narrowing, fn() {
          // Foreign keys are ON, so children leave before parents. The two
          // IN-clauses on network_devices cover both halves of the join —
          // assignment is org-scoped in the API, but the delete should not
          // have to trust that.
          let work = {
            // The org's own credentials go first, before the networks a join
            // key names: nothing cascades them, and an API key outliving its
            // org would be a token that authenticates to a 404 forever.
            use _ <- result.try(
              sqlite.exec(conn, "DELETE FROM api_keys WHERE org_id = ?", [
                Text(org_id),
              ]),
            )
            use _ <- result.try(
              sqlite.exec(
                conn,
                "DELETE FROM network_devices
                 WHERE network_id IN (SELECT id FROM networks WHERE org_id = ?)
                    OR device_id IN (SELECT id FROM devices WHERE org_id = ?)",
                [Text(org_id), Text(org_id)],
              ),
            )
            use _ <- result.try(
              sqlite.exec(
                conn,
                "DELETE FROM device_keys
                 WHERE device_id IN (SELECT id FROM devices WHERE org_id = ?)",
                [Text(org_id)],
              ),
            )
            // Children before parents, and foreign keys are on: the
            // metering heartbeat's row points at a network.
            use _ <- result.try(
              sqlite.exec(
                conn,
                "DELETE FROM network_hosting_status
                 WHERE network_id IN (SELECT id FROM networks WHERE org_id = ?)",
                [Text(org_id)],
              ),
            )
            // Deleting an org that still hosts networks is an offboarding for
            // each of them: the bytes in the bucket outlive every row here, so
            // the instruction to collect them is written before the rows go.
            // `DO NOTHING` leaves a clock that is already running alone.
            use _ <- result.try(
              sqlite.exec(
                conn,
                "INSERT INTO cloud_collect_queue
                   (org_slug, network_name, disabled_at)
                 SELECT ?1, n.name, ?2 FROM networks n
                 WHERE n.org_id = ?3 AND n.cloud_hosted = 1
                 ON CONFLICT (org_slug, network_name) DO NOTHING",
                [Text(slug), VInt(now_unix()), Text(org_id)],
              ),
            )
            use _ <- result.try(
              sqlite.exec(conn, "DELETE FROM networks WHERE org_id = ?", [
                Text(org_id),
              ]),
            )
            use _ <- result.try(
              sqlite.exec(conn, "DELETE FROM devices WHERE org_id = ?", [
                Text(org_id),
              ]),
            )
            // A sign-in state pointing at a provider that is about to exist
            // no more: the state can never be redeemed, so it goes too.
            use _ <- result.try(
              sqlite.exec(
                conn,
                "DELETE FROM oauth_states WHERE oidc_provider_id IN
                 (SELECT id FROM oidc_providers WHERE org_id = ?)",
                [Text(org_id)],
              ),
            )
            // Identities and their provider row go together: identities
            // without their provider are not (see delete_oidc).
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
            use _ <- result.try(
              sqlite.exec(conn, "DELETE FROM invites WHERE org_id = ?", [
                Text(org_id),
              ]),
            )
            use _ <- result.try(
              sqlite.exec(conn, "DELETE FROM org_members WHERE org_id = ?", [
                Text(org_id),
              ]),
            )
            // The audit trail outlives the org it describes — org_id carries
            // no foreign key precisely so history is not cascade-deleted.
            // The slug rides in the detail because the row naming it is next.
            use _ <- result.try(
              audit(conn, who, org_id, "org.delete", [
                #("slug", json.string(slug)),
              ]),
            )
            sqlite.exec(conn, "DELETE FROM orgs WHERE id = ?", [Text(org_id)])
            |> result.replace(Nil)
          }
          case work {
            Ok(Nil) -> Ok(json.object([#("deleted", json.string(slug))]))
            Error(e) -> Error(constraint_response(e))
          }
        })
      })
  }
}

/// The org's roster.
///
/// A person's endpoint, though it only reads. The row it returns is a
/// person's name, email and id, and the org's machine credentials have no
/// business carrying that: an API key exists to drive networks, devices and
/// keys, and a leaked one should not also hand over the address book — nor
/// the `user_id` values that the membership *mutations* take. Reading the
/// roster is a thing the dashboard does, so the dashboard's credential is
/// what may do it.
pub fn list_members(reads: Reads, who: Principal, slug: String) -> Response {
  use <- require_user(who)
  reads.with_db(reads, fn(conn) {
    use org_id, _role <- require_org(conn, slug, who, Member)
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
  who: Principal,
  slug: String,
  target_user: String,
) -> Response {
  let decoder = {
    use role <- decode.field("role", decode.string)
    decode.success(role)
  }
  use <- require_user(who)
  use role_text <- body_decoder(req, decoder)
  case common.role_from_string(role_text) {
    Error(Nil) -> error_json(400, "bad_role", "role must be owner|admin|member")
    Ok(_) ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, who, Owner)
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
                  audit(conn, who, org_id, "member.role", [
                    #("user", json.string(target_user)),
                    #("role", json.string(role_text)),
                  ])
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

/// Removing a member — and the case where the member is the caller, which
/// is leaving.
///
/// **The role floor depends on whose row it is.** Removing somebody else is
/// an administrative act and needs `Admin`; removing your own is not, and
/// needs only the membership being given up. A plain member held in an org
/// with no way out has to ask an admin to be let go, which is not a
/// permission model — it is a lock on the wrong side of the door.
///
/// Nothing below the floor moves. Only owners may remove *other* owners, and
/// the last owner may not go by anyone's hand, their own included: an org
/// with no owner can never be given one again, since every path to `owner`
/// (`change_role`, `transfer_ownership`) is owner-gated. A sole owner
/// transfers ownership or deletes the org, and the refusal says so.
pub fn remove_member(
  ctx: AuthContext,
  who: Principal,
  slug: String,
  target_user: String,
) -> Response {
  use <- require_user(who)
  let leaving = target_user == who.user_id
  let removing_other = !leaving
  let minimum = case leaving {
    True -> Member
    False -> Admin
  }
  with_db(ctx, fn(conn) {
    use org_id, my_role <- require_org(conn, slug, who, minimum)
    let target_role =
      sqlite.query(
        conn,
        "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
        [Text(org_id), Text(target_user)],
      )
    case target_role {
      Ok([[Text("owner")]]) if removing_other && my_role != Owner ->
        error_json(403, "forbidden", "only owners may remove owners")
      Ok([[Text(role_text)]]) ->
        case role_text == "owner" && last_owner(conn, org_id, target_user) {
          True if leaving ->
            error_json(
              409,
              "last_owner",
              "you are the last owner of this org: transfer ownership or "
                <> "delete the org before leaving",
            )
          True ->
            error_json(409, "last_owner", "an org must keep at least one owner")
          False -> {
            let removal =
              sqlite.exec(
                conn,
                "DELETE FROM org_members WHERE org_id = ? AND user_id = ?",
                [Text(org_id), Text(target_user)],
              )
            case removal {
              Ok(_) -> {
                let _ =
                  audit(
                    conn,
                    who,
                    org_id,
                    case leaving {
                      True -> "member.leave"
                      False -> "member.remove"
                    },
                    [#("user", json.string(target_user))],
                  )
                ok_json(
                  json.object([
                    #("ok", json.bool(True)),
                    // What the caller's own access just became, which a bare
                    // `ok` does not say: a leaver's next request to this org
                    // is a 404, and the SPA needs to know that before it
                    // makes one.
                    #("left", json.bool(leaving)),
                  ]),
                )
              }
              Error(e) -> constraint_response(e)
            }
          }
        }
      Ok(_) -> error_json(404, "not_found", "no such member")
      Error(_) -> db_error()
    }
  })
}

/// Ownership transfer as one step: the named member becomes an owner, the
/// acting owner steps down to admin. Promotion and demotion share a
/// transaction, so the org is never between owners — the invariant
/// `change_role` and `remove_member` defend one member at a time.
///
/// Not a zone mutation: roles never reach DNS, the same reason `change_role`
/// is not one. Both updates count their rows: the promote's count is the
/// member existence check, and the demote's `role = 'owner'` condition is
/// what happened to the actor re-checked inside the transaction — an actor
/// demoted or removed between the role check and `BEGIN` must fail the
/// transfer, not be quietly re-elevated by it.
pub fn transfer_ownership(
  req: Request,
  ctx: AuthContext,
  who: Principal,
  slug: String,
) -> Response {
  let decoder = {
    use to <- decode.field("to", decode.string)
    decode.success(to)
  }
  use <- require_user(who)
  use to <- body_decoder(req, decoder)
  case to == who.user_id {
    True ->
      error_json(
        400,
        "bad_target",
        "ownership cannot be transferred to yourself",
      )
    False ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, who, Owner)
        let applied =
          transaction(conn, fn() {
            {
              use _ <- result.try(
                case
                  sqlite.exec(
                    conn,
                    "UPDATE org_members SET role = 'owner'
                     WHERE org_id = ? AND user_id = ?",
                    [Text(org_id), Text(to)],
                  )
                {
                  Ok(sqlite.Done(1, _)) -> Ok(Nil)
                  Ok(_) -> Error(error_json(404, "not_found", "no such member"))
                  Error(e) -> Error(constraint_response(e))
                },
              )
              use _ <- result.try(
                case
                  sqlite.exec(
                    conn,
                    "UPDATE org_members SET role = 'admin'
                     WHERE org_id = ? AND user_id = ? AND role = 'owner'",
                    [Text(org_id), Text(who.user_id)],
                  )
                {
                  Ok(sqlite.Done(1, _)) -> Ok(Nil)
                  // The promote above rolls back with this refusal: the
                  // actor stopped being an owner after the role check read
                  // otherwise, and a transfer may not re-elevate its actor.
                  Ok(_) ->
                    Error(error_json(
                      403,
                      "forbidden",
                      "you are no longer an owner of this org",
                    ))
                  Error(e) -> Error(constraint_response(e))
                },
              )
              audit(conn, who, org_id, "org.transfer", [
                #("to", json.string(to)),
              ])
              |> result.map_error(constraint_response)
            }
          })
        case applied {
          Ok(Nil) ->
            ok_json(
              json.object([
                #("owner", json.string(to)),
                #("your_role", json.string("admin")),
              ]),
            )
          Error(response) -> response
        }
      })
  }
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
  who: Principal,
  slug: String,
) -> Response {
  let decoder = {
    use email <- decode.field("email", decode.string)
    use role <- decode.optional_field("role", "member", decode.string)
    decode.success(#(email, role))
  }
  use <- require_user(who)
  use #(email_input, role) <- body_decoder(req, decoder)
  // Normalised the way the magic-link path normalises: the address is
  // about to be an SMTP recipient, and a pasted `  Name@Example.COM  `
  // is one the relay would refuse.
  let email = string.lowercase(string.trim(email_input))
  let addressable =
    string.contains(email, "@") && string.byte_size(email) <= 254
  case role == "member" || role == "admin", addressable {
    False, _ ->
      error_json(400, "bad_role", "invite role must be member or admin")
    _, False -> error_json(400, "bad_email", "invite needs an email address")
    True, True ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, who, Admin)
        let token = id.secret()
        let token_hash = id.hash_token(token)
        let insert =
          sqlite.exec(
            conn,
            "INSERT INTO invites VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            [
              Text(id.new()),
              Text(org_id),
              Text(email),
              Text(role),
              Blob(token_hash),
              Text(who.user_id),
              VInt(now_unix()),
              VInt(now_unix() + 604_800),
            ],
          )
        case insert {
          Error(e) -> constraint_response(e)
          Ok(_) -> {
            let link = ctx.entry_url <> "/invite?token=" <> token
            let _ =
              mailer.send(
                ctx.mail,
                email,
                "You have been invited to " <> slug <> " on synchronicity",
                "Accept the invitation (valid for 7 days):\n\n" <> link <> "\n",
              )
            let _ =
              audit(conn, who, org_id, "invite.create", [
                #("email", json.string(email)),
                #("role", json.string(role)),
              ])
            ok_json(json.object([#("ok", json.bool(True))]))
          }
        }
      })
  }
}

/// What an invitation link may say about itself before any session exists:
/// the token is the credential — a holder could accept the invite outright,
/// so showing them what they would be joining reveals nothing acceptance
/// would not.
pub fn preview_invite(req: Request, reads: Reads) -> Response {
  // Absent and empty are the same omission; only a real token earns a lookup.
  case list.key_find(wisp.get_query(req), "token") {
    Error(Nil) | Ok("") ->
      error_json(400, "bad_request", "token query parameter required")
    Ok(token) ->
      reads.with_db(reads, fn(conn) {
        let rows =
          sqlite.query(
            conn,
            "SELECT o.slug, o.name, i.email, i.role, i.expires_at,
                    i.accepted_at IS NOT NULL
             FROM invites i JOIN orgs o ON o.id = i.org_id
             WHERE i.token_hash = ?",
            [Blob(id.hash_token(token))],
          )
        case rows {
          Ok([
            [
              Text(slug),
              Text(org_name),
              Text(email),
              Text(role),
              VInt(expires_at),
              VInt(accepted),
            ],
          ]) -> {
            // Status over bare existence: an expired or already-accepted
            // invite is still identifiable to its holder, and the page can
            // say which it is rather than answering "invalid" for all three.
            let status = case accepted == 1, expires_at > now_unix() {
              True, _ -> "accepted"
              False, False -> "expired"
              False, True -> "valid"
            }
            ok_json(
              json.object([
                #("org", json.string(slug)),
                #("org_name", json.string(org_name)),
                #("email", json.string(email)),
                #("role", json.string(role)),
                #("expires_at", json.int(expires_at)),
                #("status", json.string(status)),
              ]),
            )
          }
          Ok(_) -> error_json(404, "bad_invite", "invalid invitation link")
          Error(_) -> db_error()
        }
      })
  }
}

pub fn accept_invite(
  req: Request,
  ctx: AuthContext,
  who: Principal,
) -> Response {
  let decoder = {
    use token <- decode.field("token", decode.string)
    decode.success(token)
  }
  use <- require_user(who)
  use token <- body_decoder(req, decoder)
  with_db(ctx, fn(conn) {
    let token_hash = id.hash_token(token)
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
                    Text(who.user_id),
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
              audit(conn, who, org_id, "invite.accept", [
                #("invite", json.string(invite_id)),
              ])
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
      Error(_) -> db_error()
    }
  })
}

/// OIDC configuration is owner-only in both directions: it is
/// takeover-adjacent (it decides who can sign in under the org's issuer).
pub fn get_oidc(reads: Reads, who: Principal, slug: String) -> Response {
  reads.with_db(reads, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Owner)
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
      Error(_) -> db_error()
    }
  })
}

pub fn put_oidc(
  req: Request,
  ctx: AuthContext,
  who: Principal,
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
    use org_id, _ <- require_org(conn, slug, who, Owner)
    // Discovery runs now, over verified TLS; a mismatched or unreachable
    // issuer refuses the whole save.
    case oidc.save(conn, org_id, issuer, client_id, client_secret, now_unix()) {
      Ok(found) -> {
        let _ =
          audit(conn, who, org_id, "oidc.configure", [
            #("issuer", json.string(issuer)),
          ])
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

pub fn delete_oidc(ctx: AuthContext, who: Principal, slug: String) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Owner)
    // Identities and their provider row go together: a provider without
    // its identities is fine, identities without their provider are not.
    let removed =
      transaction(conn, fn() {
        {
          use _ <- result.try(
            sqlite.exec(
              conn,
              "DELETE FROM oauth_states WHERE oidc_provider_id IN
               (SELECT id FROM oidc_providers WHERE org_id = ?)",
              [Text(org_id)],
            ),
          )
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
          audit(conn, who, org_id, "oidc.remove", [])
        }
        |> result.map_error(constraint_response)
      })
    case removed {
      Ok(Nil) -> ok_json(json.object([#("ok", json.bool(True))]))
      Error(response) -> response
    }
  })
}

/// The org's trail.
///
/// A person's endpoint, for the same reason the roster is. The trail carries
/// exactly the two things the rest of this module closes to keys: members'
/// email addresses and `user_id`s, in the `actor` column and in the details of
/// `invite.create`, `member.role`, `member.remove` and `org.transfer`; and the
/// full inventory of the org's other credentials, from `apikey.create` —
/// including which network each join key is scoped to. A leaked CI key that
/// could read this would recover the address book and a map of what else to go
/// looking for, which is precisely what refusing it the roster and the key
/// listing was meant to prevent.
pub fn audit_log(
  req: Request,
  reads: Reads,
  who: Principal,
  slug: String,
) -> Response {
  use <- require_user(who)
  reads.with_db(reads, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Admin)
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
