//// Outbound mail. SMTP relay in production; LogOnly when no relay is
//// configured, so development and tests never accidentally send mail.

import gleam/int
import gleam/io
import gleam/string

pub type Mailer {
  Smtp(
    host: String,
    port: Int,
    username: String,
    password: String,
    from: String,
  )
  LogOnly
}

@external(erlang, "cp_smtp_ffi", "send")
fn smtp_send(
  envelope: String,
  from: String,
  to: String,
  subject: String,
  body: String,
  host: String,
  port: Int,
  username: String,
  password: String,
) -> Result(Nil, String)

/// The bare address inside a From header. `CP_SMTP_FROM` is normally
/// written for the reader — `Synchronicity <sync@example.com>` — but the
/// SMTP envelope carries the address alone, and a relay handed the
/// display name too rejects the transaction outright.
pub fn envelope_address(from: String) -> String {
  case string.split_once(from, "<") {
    Ok(#(_, rest)) ->
      case string.split_once(rest, ">") {
        Ok(#(address, _)) -> string.trim(address)
        Error(Nil) -> string.trim(rest)
      }
    Error(Nil) -> string.trim(from)
  }
}

/// Failures are logged here rather than left to the caller: mail is sent
/// on paths that have nothing useful to tell the requester — an invite is
/// created whether or not its notification lands — so an unlogged error
/// would be an invitation that silently never arrives.
pub fn send(
  mailer: Mailer,
  to: String,
  subject: String,
  body: String,
) -> Result(Nil, String) {
  case mailer {
    Smtp(host, port, username, password, from) ->
      case
        smtp_send(
          envelope_address(from),
          from,
          to,
          subject,
          body,
          host,
          port,
          username,
          password,
        )
      {
        Ok(Nil) -> Ok(Nil)
        Error(why) -> {
          io.println_error("mail: to=" <> to <> " not sent: " <> why)
          Error(why)
        }
      }
    LogOnly -> {
      io.println(
        "mail (log-only) to=" <> to <> " subject=" <> subject <> "\n" <> body,
      )
      Ok(Nil)
    }
  }
}

/// Whether mail actually leaves the building. Log-only mail is a
/// development convenience — the message goes to the service's stdout —
/// so a feature that depends on the user receiving it is not on offer.
pub fn delivers(mailer: Mailer) -> Bool {
  case mailer {
    Smtp(..) -> True
    LogOnly -> False
  }
}

pub fn describe(mailer: Mailer) -> String {
  case mailer {
    Smtp(host, port, _, _, from) ->
      "smtp " <> host <> ":" <> int.to_string(port) <> " from " <> from
    LogOnly -> "log-only (no CP_SMTP_HOST configured)"
  }
}
