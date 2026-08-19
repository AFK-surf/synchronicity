import email/mailer
import gleam/string

pub fn envelope_strips_the_display_name_test() {
  assert mailer.envelope_address("Synchronicity <sync@cue.surf>")
    == "sync@cue.surf"
}

pub fn envelope_keeps_a_bare_address_test() {
  assert mailer.envelope_address("sync@cue.surf") == "sync@cue.surf"
  assert mailer.envelope_address("  sync@cue.surf  ") == "sync@cue.surf"
}

pub fn envelope_survives_a_missing_bracket_test() {
  assert mailer.envelope_address("<sync@cue.surf>") == "sync@cue.surf"
  assert mailer.envelope_address("Synchronicity <sync@cue.surf")
    == "sync@cue.surf"
}

@external(erlang, "test_ffi", "smtp_listen")
fn smtp_listen() -> Int

@external(erlang, "test_ffi", "smtp_transcript")
fn smtp_transcript() -> String

/// What actually goes over the wire: the display name belongs in the
/// header and nowhere near `MAIL FROM`, which a relay reads as an address
/// and rejects the whole transaction over — invisibly, since the invite
/// is created either way.
pub fn smtp_envelope_carries_the_address_alone_test() {
  let port = smtp_listen()
  let sent =
    mailer.send(
      mailer.Smtp("127.0.0.1", port, "", "", "Synchronicity <sync@cue.surf>"),
      "invitee@example.com",
      "You have been invited to acme on synchronicity",
      "Accept the invitation:\n\nhttps://cp.test/invite?token=t\n",
    )
  assert sent == Ok(Nil)
  let said = smtp_transcript()
  assert string.contains(said, "MAIL FROM:<sync@cue.surf>")
  assert string.contains(said, "RCPT TO:<invitee@example.com>")
  assert string.contains(said, "From: Synchronicity <sync@cue.surf>")
  // Dateless, id-less mail is mail spam filters distrust.
  assert string.contains(said, "Message-ID: <")
  assert string.contains(said, "Date: ")
}

/// A relay that is not there is an error the caller can log, not an
/// exception that takes the request down with it.
pub fn unreachable_relay_is_an_error_test() {
  let sent =
    mailer.send(
      // Port 1: nothing is listening, and nothing is allowed to.
      mailer.Smtp("127.0.0.1", 1, "", "", "sync@cue.surf"),
      "invitee@example.com",
      "You have been invited to acme on synchronicity",
      "Accept the invitation:\n\nhttps://cp.test/invite?token=t\n",
    )
  let assert Error(_) = sent
}
