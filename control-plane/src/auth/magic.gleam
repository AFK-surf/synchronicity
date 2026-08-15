//// Email magic links. Enumeration-safe (the request path always
//// succeeds), rate-limited per address, tokens stored as SHA-256,
//// single-use, 15-minute expiry.

import auth/identity
import email/mailer.{type Mailer}
import gleam/option.{None}
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Blob, Int as VInt, Text}
import util/id

const token_ttl = 900

const max_per_hour = 3

pub type RedeemError {
  BadToken
  Db(sqlite.Error)
  Login(identity.LoginError)
}

fn hash(token: String) -> BitArray {
  id.hash_token(token)
}

/// Requests a magic link. Always Ok for the caller — whether the address
/// exists, is rate limited, or is malformed is never observable.
pub fn request(
  conn: Connection,
  email_input: String,
  now: Int,
  public_url: String,
  mail: Mailer,
) -> Result(Nil, sqlite.Error) {
  let email = string.lowercase(string.trim(email_input))
  case string.contains(email, "@") && string.byte_size(email) <= 254 {
    False -> Ok(Nil)
    True -> {
      use count <- result.try(recent_count(conn, email, now))
      case count >= max_per_hour {
        True -> Ok(Nil)
        False -> {
          use token <- result.try(create_token(conn, email, now))
          let link = public_url <> "/auth/magic/redeem?token=" <> token
          let _ =
            mailer.send(
              mail,
              email,
              "Sign in to the synchronicity control plane",
              "Follow this link to sign in (valid for 15 minutes):\n\n"
                <> link
                <> "\n\nIf you did not request this, ignore this message.\n",
            )
          Ok(Nil)
        }
      }
    }
  }
}

/// Token creation, separate from `request` because that path never
/// reveals the token: tests and the `seed-admin` bootstrap call this
/// directly to get a usable link.
pub fn create_token(
  conn: Connection,
  email: String,
  now: Int,
) -> Result(String, sqlite.Error) {
  let token = id.secret()
  use _ <- result.try(
    sqlite.exec(
      conn,
      "INSERT INTO magic_link_tokens VALUES (?, ?, ?, ?, NULL)",
      [
        Blob(hash(token)),
        Text(email),
        VInt(now),
        VInt(now + token_ttl),
      ],
    ),
  )
  Ok(token)
}

fn recent_count(
  conn: Connection,
  email: String,
  now: Int,
) -> Result(Int, sqlite.Error) {
  case
    sqlite.query(
      conn,
      "SELECT count(*) FROM magic_link_tokens WHERE email = ? AND created_at > ?",
      [Text(email), VInt(now - 3600)],
    )
  {
    Ok([[sqlite.Int(n)]]) -> Ok(n)
    Ok(_) -> Ok(0)
    Error(e) -> Error(e)
  }
}

/// Redeems a token: single use, then logs the email in (creating the
/// account on first use — possession of the inbox is the verification).
pub fn redeem(
  conn: Connection,
  token: String,
  now: Int,
) -> Result(String, RedeemError) {
  let token_hash = hash(token)
  // Consume atomically: the guarded UPDATE is the check. Two concurrent
  // redeems of one token race SELECT-then-UPDATE; only one can win a
  // single statement.
  let consumed =
    sqlite.query(
      conn,
      "UPDATE magic_link_tokens SET consumed_at = ?
       WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?
       RETURNING email",
      [VInt(now), Blob(token_hash), VInt(now)],
    )
  case consumed {
    Ok([[Text(email)]]) ->
      identity.login(conn, "magic", None, email, email, True, None, now)
      |> result.map_error(Login)
    Ok(_) -> Error(BadToken)
    Error(e) -> Error(Db(e))
  }
}
