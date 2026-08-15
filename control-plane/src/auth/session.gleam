//// DB-backed sessions: revocable and listable, which stateless cookies
//// are not. The signed cookie carries only a random token; the database
//// stores its SHA-256. CSRF is a per-session secret the SPA echoes in a
//// header on every mutation.

import store/sqlite.{type Connection, Blob, Int as VInt, Text}
import util/id

pub const cookie_name = "cp_session"

/// 30 days, refreshed on activity.
pub const ttl_seconds = 2_592_000

pub type Session {
  Session(user_id: String, csrf: String)
}

fn hash(token: String) -> BitArray {
  id.hash_token(token)
}

/// Creates a session; returns the bearer token for the cookie.
pub fn create(
  conn: Connection,
  user_id: String,
  now: Int,
) -> Result(#(String, Session), sqlite.Error) {
  let token = id.secret()
  let csrf = id.secret()
  case
    sqlite.exec(conn, "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)", [
      Blob(hash(token)),
      Text(user_id),
      Text(csrf),
      VInt(now),
      VInt(now + ttl_seconds),
      VInt(now),
    ])
  {
    Ok(_) -> Ok(#(token, Session(user_id, csrf)))
    Error(e) -> Error(e)
  }
}

/// Resolves a bearer token; slides expiry at most once an hour.
pub fn get(conn: Connection, token: String, now: Int) -> Result(Session, Nil) {
  let sql =
    "SELECT user_id, csrf_token, last_seen_at FROM sessions
     WHERE token_hash = ? AND expires_at > ?"
  case sqlite.query(conn, sql, [Blob(hash(token)), VInt(now)]) {
    Ok([[Text(user_id), Text(csrf), VInt(last_seen)]]) -> {
      case now - last_seen > 3600 {
        True -> {
          let _ =
            sqlite.exec(
              conn,
              "UPDATE sessions SET last_seen_at = ?, expires_at = ?
               WHERE token_hash = ?",
              [VInt(now), VInt(now + ttl_seconds), Blob(hash(token))],
            )
          Nil
        }
        False -> Nil
      }
      Ok(Session(user_id, csrf))
    }
    _ -> Error(Nil)
  }
}

pub fn delete(conn: Connection, token: String) -> Nil {
  let _ =
    sqlite.exec(conn, "DELETE FROM sessions WHERE token_hash = ?", [
      Blob(hash(token)),
    ])
  Nil
}
