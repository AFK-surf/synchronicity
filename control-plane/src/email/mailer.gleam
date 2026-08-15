//// Outbound mail. SMTP relay in production; LogOnly when no relay is
//// configured, so development and tests never accidentally send mail.

import gleam/int
import gleam/io

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
  from: String,
  to: String,
  subject: String,
  body: String,
  host: String,
  port: Int,
  username: String,
  password: String,
) -> Result(Nil, String)

pub fn send(
  mailer: Mailer,
  to: String,
  subject: String,
  body: String,
) -> Result(Nil, String) {
  case mailer {
    Smtp(host, port, username, password, from) ->
      smtp_send(from, to, subject, body, host, port, username, password)
    LogOnly -> {
      io.println(
        "mail (log-only) to=" <> to <> " subject=" <> subject <> "\n" <> body,
      )
      Ok(Nil)
    }
  }
}

pub fn describe(mailer: Mailer) -> String {
  case mailer {
    Smtp(host, port, _, _, from) ->
      "smtp " <> host <> ":" <> int.to_string(port) <> " from " <> from
    LogOnly -> "log-only (no CP_SMTP_HOST configured)"
  }
}
