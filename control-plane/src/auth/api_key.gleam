//// Org-scoped API keys: the credential for a caller that is a program.
////
//// The same storage shape sessions, invites and magic links use — the row
//// holds the SHA-256 of the token and never the token — with two additions
//// a long-lived credential needs and a session does not:
////
//// * **`prefix`**, the leading characters kept in clear. A key is meant to
////   outlive the browser tab it was minted in, so the one question a list
////   has to answer is "which of these is the token in my CI settings?" — and
////   answering it must not require storing enough to *be* the token.
//// * **`expires_at`**, optional. A key that cannot expire is fine while
////   somebody is watching the list; a key handed out for a fortnight should
////   stop working on its own.
////
//// Two kinds share the table, because everything about *being* a credential
//// is the same for both. An **org key** names an org and carries a role. A
//// **join key** names one network and carries no role at all: the only thing
//// it can do is put a device into that network. Which one a row is, is
//// `role = 'join'`, and the schema ties that to `network_id` with a CHECK so
//// neither half can be wrong on its own.
////
//// Authorisation is not here. What a token resolves to travels in the
//// `auth/principal` value this module hands back, and `api/common` is where
//// that value becomes a permission.

import auth/principal.{type Principal, ApiKey, JoinKey, Principal}
import gleam/option.{type Option, None, Some}
import gleam/string
import store/sqlite.{type Connection, Blob, Int as VInt, Null, Text}
import util/id

/// The leading text of every token.
///
/// Not decoration: a credential that announces what it is can be recognised
/// on sight in a paste, a log line or a CI variable, and by the secret
/// scanners that look for exactly this shape. It is also what lets an
/// `Authorization` header carrying somebody else's scheme be refused without
/// a database round trip.
pub const token_prefix = "synch_"

/// How much of the token's random half is kept in clear, beside the prefix.
///
/// Eight base64url characters is 48 bits — plenty to tell one of an org's
/// keys from another, nowhere near enough to shorten a search for the
/// remaining 208 bits of a 256-bit secret.
const display_length = 8

/// How stale `last_used_at` may get before a use writes it back. The same
/// hour `auth/session` slides expiry on, and for the same reason: the fact
/// is worth far less than a write lock on every request.
const use_stamp_interval = 3600

/// The role string that marks a join key. Not a rank — see `auth/principal`.
pub const join_role = "join"

/// Mints a key. Returns the token and the display prefix; the row's id is an
/// argument, because the caller needs it for the audit row either way.
///
/// `network_id` is `Some` exactly when `role` is `join`; the schema's CHECK
/// says the same thing, so a caller that gets it wrong is refused rather than
/// stored.
///
/// The token is the only copy — nothing stored can reproduce it, so a caller
/// that loses it mints another.
pub fn create(
  conn: Connection,
  key_id: String,
  org_id: String,
  network_id: Option(String),
  name: String,
  role: String,
  created_by: String,
  expires_at: Option(Int),
  now: Int,
) -> Result(#(String, String), sqlite.Error) {
  let secret = id.secret()
  let token = token_prefix <> secret
  let prefix = token_prefix <> string.slice(secret, 0, display_length)
  let insert =
    sqlite.exec(
      conn,
      // Columns named rather than positional: this table has been rebuilt
      // once already, and a VALUES list is the thing that silently shifts
      // when it is rebuilt again.
      "INSERT INTO api_keys
         (id, org_id, network_id, name, prefix, token_hash, role, created_by,
          created_at, expires_at, last_used_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
      [
        Text(key_id),
        Text(org_id),
        nullable_text(network_id),
        Text(name),
        Text(prefix),
        Blob(id.hash_token(token)),
        Text(role),
        Text(created_by),
        VInt(now),
        nullable_int(expires_at),
      ],
    )
  case insert {
    Ok(_) -> Ok(#(token, prefix))
    Error(e) -> Error(e)
  }
}

/// Resolves a bearer token, or refuses.
///
/// Expiry is part of the lookup rather than a check after it, so an expired
/// key is indistinguishable from one that never existed — the stance
/// `session.get` takes for the same reason.
///
/// The `last_used_at` stamp is advisory and its failure ignored, which is
/// what lets a node holding a read-only copy of the database authenticate at
/// all: a replica reads the row the primary wrote, and its `UPDATE` comes
/// back `SQLITE_READONLY` without disturbing the connection. The consequence
/// is the one `session.get` names — the column records the last use *against
/// the primary*, which is what an operator deciding whether a key is still in
/// service wants from it anyway. The cost of getting nothing back is one
/// doomed round trip per request on a replica, since the stamp it reads never
/// moves; at the rate a replica serves reads that is not worth a second
/// mechanism to avoid.
pub fn authenticate(
  conn: Connection,
  token: String,
  now: Int,
) -> Result(Principal, Nil) {
  case string.starts_with(token, token_prefix) {
    False -> Error(Nil)
    True -> {
      let hash = id.hash_token(token)
      let sql =
        "SELECT id, org_id, coalesce(network_id, ''), role, created_by,
                coalesce(last_used_at, 0)
         FROM api_keys
         WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?)"
      case sqlite.query(conn, sql, [Blob(hash), VInt(now)]) {
        Ok([
          [
            Text(key_id),
            Text(org_id),
            Text(network_id),
            Text(role),
            Text(created_by),
            VInt(last_used),
          ],
        ]) -> {
          case now - last_used > use_stamp_interval {
            True -> {
              let _ =
                sqlite.exec(
                  conn,
                  "UPDATE api_keys SET last_used_at = ? WHERE token_hash = ?",
                  [VInt(now), Blob(hash)],
                )
              Nil
            }
            False -> Nil
          }
          // The schema's CHECK is what makes this exhaustive: `join` without
          // a network, or a network without `join`, is a row that cannot be
          // written. The empty-string arm is unreachable and answers `Error`
          // rather than inventing a credential out of a broken row.
          case role, network_id {
            "join", "" -> Error(Nil)
            "join", network ->
              Ok(Principal(created_by, JoinKey(key_id, org_id, network)))
            _, _ -> Ok(Principal(created_by, ApiKey(key_id, org_id, role)))
          }
        }
        _ -> Error(Nil)
      }
    }
  }
}

fn nullable_text(value: Option(String)) -> sqlite.Value {
  case value {
    Some(text) -> Text(text)
    None -> Null
  }
}

/// `Some(n)` as a bound integer, `None` as SQL NULL — the shape `expires_at`
/// is stored in, where "never expires" is the absence of a time rather than
/// a sentinel one.
pub fn nullable_int(value: Option(Int)) -> sqlite.Value {
  case value {
    Some(n) -> VInt(n)
    None -> Null
  }
}
