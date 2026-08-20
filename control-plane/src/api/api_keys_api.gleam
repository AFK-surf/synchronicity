//// Org-scoped API keys: the management surface an org admin uses.
////
//// Admin-gated in all four directions, and closed to keys themselves —
//// `middleware.require_user` is the first thing every handler here runs, and
//// `middleware.api_key_refused` says why. A key that could mint keys could
//// mint one that never expires, and revoking the key you knew about would
//// not have ended the access.
////
//// Not a zone mutation: a credential is not a membership record and never
//// reaches DNS. Each mutation is one statement followed by its audit row,
//// which is the whole trail an operator has for a credential that is
//// invisible by design. The two are not one transaction — the same shape
//// every other mutation in this API has, `orgs_api.change_role` included —
//// so a crash between them loses the row and not the change. Worth knowing
//// when reading the trail; not worth a transaction the rest of the API does
//// not take.

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
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import store/sqlite.{Int as VInt, Text}
import util/id
import wisp.{type Request, type Response}

/// The longest a key may be named, in bytes.
///
/// The column carries a ceiling too — `length(name) BETWEEN 1 AND 64` — but
/// SQLite's `length()` counts *characters* on TEXT, so this check is the
/// stricter of the two for any name that is not pure ASCII. That is the right
/// way round: a name is refused here with a sentence, never there with a
/// constraint failure.
const name_limit = 64

/// The longest life a key may be given: ten years.
///
/// Less a policy than a guard. `now + expires_in` is arithmetic on the BEAM,
/// whose integers are unbounded, and the storage layer truncates to 64 bits —
/// so an absurd duration would silently mint a key that has *already* expired.
/// A bound turns that into a sentence.
const max_expires_in = 315_360_000

/// What a request says about a key's expiry. Three cases, kept apart because
/// two of them carry no timestamp and mean opposite things: `Leave` is "the
/// field was absent", `Clear` is "this key stops expiring". Collapsing them
/// into one `Option(Int)` is what made an audit row unable to say which had
/// happened.
type Expiry {
  Leave
  Clear
  SetAt(at: Int)
}

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
        // The minter's email, not their id: this list is read by a person
        // deciding whether a key is still wanted, and "who made this" is a
        // question an id does not answer. It is also the column to look down
        // when somebody leaves the org — a key outlives its minter's
        // membership by design, so nothing else surfaces what they left
        // behind.
        #("created_by_email", json.string(text_at(row, 7))),
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
    Ok(Nil), Ok(Nil), Ok(expiry) ->
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
            expires_at_of(expiry),
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
                #(
                  "expires_at",
                  json.int(option.unwrap(expires_at_of(expiry), 0)),
                ),
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

/// Renames a key, changes its role, or moves its expiry.
///
/// Every field is optional and an **absent** one is left alone. An explicit
/// `null` is not the same thing and is refused: `{"role": null}` is a client
/// that meant something it has not said, and guessing which — leave it, or
/// clear it — is how a credential quietly ends up with the wrong reach.
/// `POST` refuses a null in the same field for the same reason.
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
    use name <- decode.optional_field("name", None, some(decode.string))
    use role <- decode.optional_field("role", None, some(decode.string))
    use expires_in <- decode.optional_field(
      "expires_in",
      None,
      some(decode.int),
    )
    decode.success(#(name, role, expires_in))
  }
  use #(name_field, role_field, expiry_field) <- body_decoder(req, decoder)
  let name = option.map(name_field, string.trim)
  case validate_update(name, role_field, expiry_field) {
    Error(refusal) -> refusal
    Ok(expiry) ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, who, Admin)
        // `org_id` in the WHERE and not merely in the lookup: it is what
        // makes another org's key id a miss rather than an edit.
        //
        // `?3` carries all three expiry cases because SQL has no third state
        // to bind: NULL leaves the column, 0 clears it, anything else sets
        // it. `expiry_argument` is the only thing that produces it, and
        // `check_expiry` is what guarantees a real timestamp is never 0.
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
              expiry_argument(expiry),
              Text(key_id),
              Text(org_id),
            ],
          )
        case update {
          Ok(sqlite.Done(1, _)) -> {
            // Only what moved. A field the request did not carry is absent
            // from the row rather than present as null, so `expires_at: null`
            // can mean the one thing it should: this key stopped expiring.
            // An update that changed nothing writes nothing — the value of
            // this trail is that it is short.
            let changed =
              list.flatten([
                case name {
                  Some(text) -> [#("name", json.string(text))]
                  None -> []
                },
                case role_field {
                  Some(text) -> [#("role", json.string(text))]
                  None -> []
                },
                case expiry {
                  Leave -> []
                  Clear -> [#("expires_at", json.null())]
                  SetAt(at) -> [#("expires_at", json.int(at))]
                },
              ])
            case changed {
              [] -> Nil
              fields -> {
                let _ =
                  audit(
                    conn,
                    who,
                    org_id,
                    "apikey.update",
                    json.object([#("key", json.string(key_id)), ..fields]),
                  )
                Nil
              }
            }
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
  let size = string.byte_size(name)
  case size >= 1 && size <= name_limit {
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
fn check_expiry(expires_in: Int) -> Result(Expiry, Response) {
  case expires_in {
    0 -> Ok(Clear)
    seconds if seconds > 0 && seconds <= max_expires_in ->
      Ok(SetAt(now_unix() + seconds))
    _ ->
      Error(error_json(
        400,
        "bad_expiry",
        "expires_in is a number of seconds from now, at most "
          <> int.to_string(max_expires_in)
          <> " of them, or 0 for no expiry",
      ))
  }
}

/// The three optional fields of a PATCH, checked in the order they are
/// written. The expiry is the only one that produces a value, so it is what
/// comes back.
fn validate_update(
  name: Option(String),
  role: Option(String),
  expires_in: Option(Int),
) -> Result(Expiry, Response) {
  use _ <- result.try(optionally(name, check_name))
  use _ <- result.try(optionally(role, check_role))
  case expires_in {
    Some(seconds) -> check_expiry(seconds)
    None -> Ok(Leave)
  }
}

/// Runs a check over a field that may not have been sent. An absent field is
/// nothing to complain about.
fn optionally(
  field: Option(a),
  check: fn(a) -> Result(Nil, Response),
) -> Result(Nil, Response) {
  case field {
    Some(value) -> check(value)
    None -> Ok(Nil)
  }
}

/// `Some(at)` for a key that expires, `None` for one that does not — the
/// shape `api_key.create` takes, where there is no column to leave alone
/// because the row does not exist yet.
fn expires_at_of(expiry: Expiry) -> Option(Int) {
  case expiry {
    SetAt(at) -> Some(at)
    Clear | Leave -> None
  }
}

/// The `?3` argument of the update: NULL leaves the column, `0` clears it,
/// anything else sets it. `check_expiry` is what keeps a real timestamp from
/// ever being `0` and colliding with the clear sentinel.
fn expiry_argument(expiry: Expiry) -> sqlite.Value {
  case expiry {
    Leave -> sqlite.Null
    Clear -> VInt(0)
    SetAt(at) -> VInt(at)
  }
}

fn nullable_text(value: Option(String)) -> sqlite.Value {
  case value {
    Some(text) -> Text(text)
    None -> sqlite.Null
  }
}

/// A decoder that wraps its value in `Some`, so `optional_field`'s default of
/// `None` means "absent" and an explicit `null` fails the inner decoder
/// rather than being read as absent. `decode.optional` would swallow it.
fn some(inner: decode.Decoder(a)) -> decode.Decoder(Option(a)) {
  decode.map(inner, Some)
}
