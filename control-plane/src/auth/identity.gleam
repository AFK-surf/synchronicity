//// Identity resolution and the linking policy.
////
//// Invariant: an identity auto-links to an existing account ONLY when the
//// asserting party is trusted to have verified the email — Google
//// (email_verified), GitHub (verified primary), magic link (possession).
//// Custom OIDC issuers are org-controlled and could mint any email claim,
//// so they NEVER auto-link; the user signs in with an existing method and
//// links explicitly from a live session.

import gleam/option.{type Option, None, Some}
import gleam/string
import store/sqlite.{type Connection, Int as VInt, Text}
import util/id

pub type LoginError {
  /// An account with this email exists; this untrusted identity must be
  /// linked explicitly from a logged-in session.
  NeedsExplicitLink(email: String)
  Db(sqlite.Error)
}

/// Finds or creates the user for an authenticated external identity.
pub fn login(
  conn: Connection,
  provider: String,
  oidc_provider_id: Option(String),
  subject: String,
  email: String,
  email_trusted: Bool,
  display_name: Option(String),
  now: Int,
) -> Result(String, LoginError) {
  let email = string.lowercase(string.trim(email))
  case find_identity(conn, provider, oidc_provider_id, subject) {
    Ok(Some(user_id)) -> Ok(user_id)
    Ok(None) ->
      case find_user_by_email(conn, email) {
        Ok(Some(user_id)) ->
          case email_trusted {
            True ->
              insert_identity(
                conn,
                user_id,
                provider,
                oidc_provider_id,
                subject,
                now,
              )
            False -> Error(NeedsExplicitLink(email))
          }
        Ok(None) -> {
          let user_id = id.new()
          case
            sqlite.exec(conn, "INSERT INTO users VALUES (?, ?, ?, ?)", [
              Text(user_id),
              Text(email),
              sqlite.optional_text(display_name),
              VInt(now),
            ])
          {
            Ok(_) ->
              insert_identity(
                conn,
                user_id,
                provider,
                oidc_provider_id,
                subject,
                now,
              )
            Error(e) -> Error(Db(e))
          }
        }
        Error(e) -> Error(Db(e))
      }
    Error(e) -> Error(Db(e))
  }
}

/// Explicit link from a logged-in session (the custom-OIDC path).
pub fn link(
  conn: Connection,
  user_id: String,
  provider: String,
  oidc_provider_id: Option(String),
  subject: String,
  now: Int,
) -> Result(String, LoginError) {
  insert_identity(conn, user_id, provider, oidc_provider_id, subject, now)
}

fn find_identity(
  conn: Connection,
  provider: String,
  oidc_provider_id: Option(String),
  subject: String,
) -> Result(Option(String), sqlite.Error) {
  let sql =
    "SELECT user_id FROM auth_identities
     WHERE provider = ? AND coalesce(oidc_provider_id, '') = ? AND subject = ?"
  case
    sqlite.query(conn, sql, [
      Text(provider),
      Text(option.unwrap(oidc_provider_id, "")),
      Text(subject),
    ])
  {
    Ok([[Text(user_id)]]) -> Ok(Some(user_id))
    Ok(_) -> Ok(None)
    Error(e) -> Error(e)
  }
}

fn find_user_by_email(
  conn: Connection,
  email: String,
) -> Result(Option(String), sqlite.Error) {
  case
    sqlite.query(conn, "SELECT id FROM users WHERE email = ?", [Text(email)])
  {
    Ok([[Text(user_id)]]) -> Ok(Some(user_id))
    Ok(_) -> Ok(None)
    Error(e) -> Error(e)
  }
}

fn insert_identity(
  conn: Connection,
  user_id: String,
  provider: String,
  oidc_provider_id: Option(String),
  subject: String,
  now: Int,
) -> Result(String, LoginError) {
  case
    sqlite.exec(conn, "INSERT INTO auth_identities VALUES (?, ?, ?, ?, ?, ?)", [
      Text(id.new()),
      Text(user_id),
      Text(provider),
      sqlite.optional_text(oidc_provider_id),
      Text(subject),
      VInt(now),
    ])
  {
    Ok(_) -> Ok(user_id)
    Error(e) -> Error(Db(e))
  }
}
