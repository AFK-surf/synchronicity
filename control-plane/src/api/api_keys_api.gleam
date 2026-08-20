//// Org-scoped API keys: the management surface an org admin uses.
////
//// Admin-gated in all four directions, and closed to keys themselves —
//// `middleware.require_user` is the first thing every handler here runs, and
//// `middleware.api_key_refused` says why. A key that could mint keys could
//// mint one that never expires, and revoking the key you knew about would
//// not have ended the access.
////
//// Not a zone mutation: a credential is not a membership record and never
//// reaches DNS. The mutations are single statements, so they need no
//// transaction either — what they do need is the audit row beside them,
//// which is the whole trail an operator has for a credential that is
//// invisible by design.

import api/auth_api.{type AuthContext, with_db}
import api/common.{
  Admin, audit, body_decoder, constraint_response, ok_json, require_org, text_at,
}
import api/middleware.{error_json, now_unix, require_user}
import api/reads.{type Reads}
import auth/api_key
import auth/principal.{type Principal}
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/string
import store/sqlite.{Int as VInt, Text}
import util/id
import wisp.{type Request, type Response}

/// The longest a key may be named. The column carries the same ceiling, so a
/// name past it is refused here with a sentence rather than there with a
/// constraint failure.
const name_limit = 64

/// Every key the org holds — never a token, which exists once, in the reply
/// to the request that minted it.
///
/// A read, so a replica answers it: an operator looking at the list wants to
/// know which keys exist and when each was last used, and neither fact needs
/// the node that holds the pen.
pub fn list_keys(reads: Reads, who: Principal, slug: String) -> Response {
  use <- require_user(who)
  reads.with_db(reads, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Admin)
    let rows =
      sqlite.query(
        conn,
        "SELECT k.id, k.name, k.prefix, k.role, k.created_at,
                coalesce(k.expires_at, 0), coalesce(k.last_used_at, 0),
                coalesce(u.email, '')
         FROM api_keys k LEFT JOIN users u ON u.id = k.created_by
         WHERE k.org_id = ? ORDER BY k.created_at, k.id",
        [Text(org_id)],
      )
    common.rows_json(rows, fn(row) {
      json.object([
        #("id", json.string(text_at(row, 0))),
        #("name", json.string(text_at(row, 1))),
        #("prefix", json.string(text_at(row, 2))),
        #("role", json.string(text_at(row, 3))),
        #("created_at", json.int(common.int_at(row, 4))),
        // Zero for "no expiry" and "never used": the JSON says absent with a
        // number the SPA can test, rather than a null it would have to.
        #("expires_at", json.int(common.int_at(row, 5))),
        #("last_used_at", json.int(common.int_at(row, 6))),
        #("created_by", json.string(text_at(row, 7))),
      ])
    })
  })
}

/// Mints a key. The token comes back exactly once.
///
/// `role` is `admin` or `member` and nothing else — an org can only be handed
/// away by an owner, and a credential that could be one would be a way to
/// hand an org away by copying a string.
pub fn create_key(
  req: Request,
  ctx: AuthContext,
  who: Principal,
  slug: String,
) -> Response {
  use <- require_user(who)
  let decoder = {
    use name <- decode.field("name", decode.string)
    use role <- decode.optional_field("role", "member", decode.string)
    use expires_in <- decode.optional_field("expires_in", 0, decode.int)
    decode.success(#(name, role, expires_in))
  }
  use #(name_input, role, expires_in) <- body_decoder(req, decoder)
  let name = string.trim(name_input)
  case check_name(name), check_role(role), check_expiry(expires_in) {
    Error(refusal), _, _ | _, Error(refusal), _ | _, _, Error(refusal) ->
      refusal
    Ok(Nil), Ok(Nil), Ok(expires_at) ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, who, Admin)
        let key_id = id.new()
        case
          api_key.create(
            conn,
            key_id,
            org_id,
            name,
            role,
            who.user_id,
            expires_at,
            now_unix(),
          )
        {
          Error(e) -> constraint_response(e)
          Ok(#(token, prefix)) -> {
            let _ =
              audit(
                conn,
                who,
                org_id,
                "apikey.create",
                json.object([
                  #("key", json.string(key_id)),
                  #("name", json.string(name)),
                  #("role", json.string(role)),
                ]),
              )
            ok_json(
              json.object([
                #("id", json.string(key_id)),
                #("name", json.string(name)),
                #("role", json.string(role)),
                #("prefix", json.string(prefix)),
                #("expires_at", json.int(option.unwrap(expires_at, 0))),
                // The one and only time this value exists anywhere but the
                // holder's hands: the row keeps its SHA-256, and nothing
                // stored can produce the token again.
                #("token", json.string(token)),
              ]),
            )
          }
        }
      })
  }
}

/// Renames a key, changes its role, or moves its expiry. Every field is
/// optional and an absent one is left alone.
///
/// What cannot be updated is the secret: rotating a credential is minting a
/// new one and deleting the old, which is two audited acts rather than one
/// that silently invalidates whatever is deployed.
pub fn update_key(
  req: Request,
  ctx: AuthContext,
  who: Principal,
  slug: String,
  key_id: String,
) -> Response {
  use <- require_user(who)
  let decoder = {
    use name <- decode.optional_field(
      "name",
      None,
      decode.optional(decode.string),
    )
    use role <- decode.optional_field(
      "role",
      None,
      decode.optional(decode.string),
    )
    use expires_in <- decode.optional_field(
      "expires_in",
      None,
      decode.optional(decode.int),
    )
    decode.success(#(name, role, expires_in))
  }
  use #(name_field, role_field, expiry_field) <- body_decoder(req, decoder)
  let name = option.map(name_field, string.trim)
  case validate_update(name, role_field, expiry_field) {
    Error(refusal) -> refusal
    Ok(expires_at) ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, who, Admin)
        // `org_id` in the WHERE and not merely in the lookup: it is what
        // makes another org's key id a miss rather than an edit.
        let update =
          sqlite.exec(
            conn,
            "UPDATE api_keys
             SET name = coalesce(?1, name),
                 role = coalesce(?2, role),
                 expires_at = CASE WHEN ?3 IS NULL THEN expires_at
                                   WHEN ?3 = 0 THEN NULL
                                   ELSE ?3 END
             WHERE id = ?4 AND org_id = ?5",
            [
              nullable_text(name),
              nullable_text(role_field),
              expiry_argument(expiry_field, expires_at),
              Text(key_id),
              Text(org_id),
            ],
          )
        case update {
          Ok(sqlite.Done(1, _)) -> {
            let _ =
              audit(
                conn,
                who,
                org_id,
                "apikey.update",
                json.object([
                  #("key", json.string(key_id)),
                  #("name", json.nullable(name, json.string)),
                  #("role", json.nullable(role_field, json.string)),
                  #("expires_at", json.nullable(expires_at, json.int)),
                ]),
              )
            ok_json(json.object([#("ok", json.bool(True))]))
          }
          Ok(_) -> error_json(404, "not_found", "no such API key")
          Error(e) -> constraint_response(e)
        }
      })
  }
}

/// Deletes a key, which is what revoking one is.
///
/// The row goes rather than being tombstoned: the token authenticates by the
/// hash in that row, so removing it is what ends the access, and a tombstone
/// would only be a second place for the same fact to be wrong. What survives
/// is the audit trail, which names the key by id in both the row that minted
/// it and the row that ended it.
pub fn delete_key(
  ctx: AuthContext,
  who: Principal,
  slug: String,
  key_id: String,
) -> Response {
  use <- require_user(who)
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Admin)
    case
      sqlite.exec(conn, "DELETE FROM api_keys WHERE id = ? AND org_id = ?", [
        Text(key_id),
        Text(org_id),
      ])
    {
      Ok(sqlite.Done(1, _)) -> {
        let _ =
          audit(
            conn,
            who,
            org_id,
            "apikey.delete",
            json.object([#("key", json.string(key_id))]),
          )
        ok_json(json.object([#("ok", json.bool(True))]))
      }
      Ok(_) -> error_json(404, "not_found", "no such API key")
      Error(e) -> constraint_response(e)
    }
  })
}

// -- validation --------------------------------------------------------------

fn check_name(name: String) -> Result(Nil, Response) {
  case string.byte_size(name) >= 1 && string.byte_size(name) <= name_limit {
    True -> Ok(Nil)
    False ->
      Error(error_json(
        400,
        "bad_name",
        "an API key needs a name of 1 to "
          <> int.to_string(name_limit)
          <> " bytes, so the list can say which key this is",
      ))
  }
}

/// A key is `admin` or `member`. Never `owner`: see the module note, and
/// `store/migrate`'s v10, where the same rule is a CHECK.
fn check_role(role: String) -> Result(Nil, Response) {
  case role {
    "admin" | "member" -> Ok(Nil)
    _ ->
      Error(error_json(
        400,
        "bad_role",
        "an API key's role is admin or member: an org is only ever handed "
          <> "away by an owner, and no key is one",
      ))
  }
}

/// `expires_in` is seconds from now, and `0` is "no expiry" — a duration
/// rather than a timestamp, because the caller's clock is not this service's
/// and a key that expired on arrival is a support ticket.
fn check_expiry(expires_in: Int) -> Result(Option(Int), Response) {
  case expires_in {
    0 -> Ok(None)
    seconds if seconds > 0 -> Ok(Some(now_unix() + seconds))
    _ ->
      Error(error_json(
        400,
        "bad_expiry",
        "expires_in is a number of seconds from now, or 0 for no expiry",
      ))
  }
}

fn validate_update(
  name: Option(String),
  role: Option(String),
  expires_in: Option(Int),
) -> Result(Option(Int), Response) {
  case name {
    Some(text) ->
      case check_name(text) {
        Error(refusal) -> Error(refusal)
        Ok(Nil) -> validate_update_role(role, expires_in)
      }
    None -> validate_update_role(role, expires_in)
  }
}

fn validate_update_role(
  role: Option(String),
  expires_in: Option(Int),
) -> Result(Option(Int), Response) {
  case role {
    Some(text) ->
      case check_role(text) {
        Error(refusal) -> Error(refusal)
        Ok(Nil) -> validate_update_expiry(expires_in)
      }
    None -> validate_update_expiry(expires_in)
  }
}

fn validate_update_expiry(
  expires_in: Option(Int),
) -> Result(Option(Int), Response) {
  case expires_in {
    Some(seconds) -> check_expiry(seconds)
    None -> Ok(None)
  }
}

/// The `expires_at` argument, where three cases have to stay distinct: the
/// field was absent (NULL — leave the column alone), it was `0` (0 — clear
/// the column), or it named a duration (the resulting timestamp).
fn expiry_argument(
  field: Option(Int),
  expires_at: Option(Int),
) -> sqlite.Value {
  case field {
    None -> sqlite.Null
    Some(_) ->
      case expires_at {
        Some(at) -> VInt(at)
        None -> VInt(0)
      }
  }
}

fn nullable_text(value: Option(String)) -> sqlite.Value {
  case value {
    Some(text) -> Text(text)
    None -> sqlite.Null
  }
}
