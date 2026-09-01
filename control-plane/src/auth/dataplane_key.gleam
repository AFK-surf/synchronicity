//// The data-plane credential: the one key in this service that names no org.
////
//// Everything about *being* a credential is `auth/api_key`'s, deliberately
//// and line for line — the row holds the SHA-256 of the token and never the
//// token, `prefix` is the leading characters kept in clear so a list can say
//// which key a leaked token is, `expires_at` is optional, and `last_used_at`
//// is stamped at most hourly and its failure ignored so a read replica can
//// authenticate at all. Two long-lived program credentials that stored
//// themselves differently would be two things for an operator to learn and
//// two places for a mistake about hashing to hide.
////
//// Everything about *scope* is absent, and that is the whole point of the
//// separate table. An `api_keys` row names one org and carries a role; this
//// one names the deployment and carries neither. What it may do is not
//// written down in a column — it is the set of routes that accept
//// `principal.Dataplane`, which is `/dp/v1/*` and nothing else
//// (docs/CLOUD-DATAPLANE.md §3.2).
////
//// **Minted only from the operator CLI** (`controlplane dataplane-key mint`).
//// There is no HTTP route that mints, renames, lists or revokes one, and that
//// asymmetry with `api_keys` is on purpose: a credential that can enumerate
//// every org on the deployment must never be reachable *through* the API it
//// authorizes, or a single leak compounds into the ability to mint a
//// replacement that outlives the revocation.

import auth/api_key.{nullable_int}
import auth/principal.{type Principal, Dataplane, Principal}
import gleam/option.{type Option}
import gleam/string
import store/sqlite.{type Connection, Blob, Int as VInt, Text}
import util/id

/// The leading text of every data-plane token.
///
/// A namespace of its own rather than a suffix inside `synch_`, so the two
/// bearer families can never be confused in a log line, a paste or the
/// middleware: `synchdp_…` does not start with `synch_` (the character after
/// `synch` is `d`, not `_`), so `api_key.authenticate` refuses it without a
/// database round trip and this one refuses an org key the same way. Neither
/// resolver can ever answer for the other's token by accident.
pub const token_prefix = "synchdp_"

/// How much of the token's random half is kept in clear, beside the prefix.
/// `auth/api_key`'s eight base64url characters, for its reasons.
const display_length = 8

/// How stale `last_used_at` may get before a use writes it back — the hour
/// `auth/api_key` and `auth/session` both slide on.
const use_stamp_interval = 3600

/// The user the rows a data-plane key writes are attributed to.
///
/// Seeded by migration v12, unaddressable by construction (its `email` carries
/// no `@`, so no sign-in path can ever reach it), and referenced here because
/// `devices.created_by` is `NOT NULL REFERENCES users(id)` — a hosted device
/// has to name a user, and it should be the service rather than whichever
/// operator happened to run the mint.
pub const system_user_id = "system-dataplane"

/// Mints a key for one data plane. Returns the token and the display prefix;
/// the row's id is an argument, because the caller needs it for the audit row
/// either way.
///
/// The token is the only copy — nothing stored can reproduce it, so an
/// operator who loses it mints another and deletes this row.
///
/// `dp_id` is required, and that is the whole of what makes a data plane's
/// identity unforgeable (migration v14). The rejected alternative was a
/// fleet-wide key plus an id in the pod's environment, and its failure mode
/// is what settled it: a typo there authenticates perfectly and hosts
/// nothing, or hosts another pod's networks, and neither is an error anybody
/// sees. A key that names its data plane cannot be mistyped into naming a
/// different one. It can be *copied*, which is an operator deliberately
/// sharing a secret rather than fumbling a variable — and one this service
/// cannot tell from the legitimate case of a pod being replaced.
pub fn create(
  conn: Connection,
  key_id: String,
  name: String,
  dp_id: String,
  expires_at: Option(Int),
  now: Int,
) -> Result(#(String, String), sqlite.Error) {
  let secret = id.secret()
  let token = token_prefix <> secret
  let prefix = token_prefix <> string.slice(secret, 0, display_length)
  let insert =
    sqlite.exec(
      conn,
      // Columns named rather than positional, for the reason `api_key.create`
      // names them: a VALUES list is the thing that silently shifts when a
      // table is rebuilt.
      "INSERT INTO dataplane_keys
         (id, name, prefix, token_hash, created_at, expires_at, last_used_at,
          dp_id)
       VALUES (?, ?, ?, ?, ?, ?, NULL, ?)",
      [
        Text(key_id),
        Text(name),
        Text(prefix),
        Blob(id.hash_token(token)),
        VInt(now),
        nullable_int(expires_at),
        Text(dp_id),
      ],
    )
  case insert {
    Ok(_) -> Ok(#(token, prefix))
    Error(e) -> Error(e)
  }
}

/// Resolves a bearer token, or refuses.
///
/// Expiry is folded into the lookup rather than checked after it, so an
/// expired key is indistinguishable from one that never existed — the stance
/// `api_key.authenticate` and `session.get` both take.
///
/// The `last_used_at` stamp is advisory and its failure ignored, which is what
/// lets the `/dp/v1` reads be served by a read replica: the `UPDATE` comes back
/// `SQLITE_READONLY` and the connection is undisturbed. The column therefore
/// records the last use *against the primary*, which is what an operator asking
/// "is this key still in service" wants from it — the data plane registers
/// devices and posts heartbeats against the primary on its ordinary cadence,
/// so a key genuinely in use moves the column whatever a replica saw.
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
        "SELECT id, coalesce(last_used_at, 0), dp_id
         FROM dataplane_keys
         WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?)"
      case sqlite.query(conn, sql, [Blob(hash), VInt(now)]) {
        Ok([[Text(key_id), VInt(last_used), Text(dp)]]) -> {
          case now - last_used > use_stamp_interval {
            True -> {
              let _ =
                sqlite.exec(
                  conn,
                  "UPDATE dataplane_keys SET last_used_at = ?
                   WHERE token_hash = ?",
                  [VInt(now), Blob(hash)],
                )
              Nil
            }
            False -> Nil
          }
          Ok(Principal(system_user_id, Dataplane(key_id, dp)))
        }
        _ -> Error(Nil)
      }
    }
  }
}
