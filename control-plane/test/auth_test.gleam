import auth/identity
import auth/magic
import auth/oauth
import auth/session
import email/mailer
import fixtures.{fresh_conn}
import gleam/bit_array
import gleam/json
import gleam/option.{None, Some}
import gleam/string
import store/sqlite.{Text}

pub fn session_lifecycle_test() {
  let conn = fresh_conn()
  let assert Ok(_) =
    sqlite.exec(conn, "INSERT INTO users VALUES ('u1', 'a@x.com', NULL, 0)", [])
  let assert Ok(#(token, made)) = session.create(conn, "u1", 1000)
  let assert Ok(live) = session.get(conn, token, 2000)
  assert live.user_id == "u1"
  assert live.csrf == made.csrf
  // Wrong token: no session.
  let assert Error(Nil) = session.get(conn, "not-the-token", 2000)
  // Expired: no session.
  let assert Error(Nil) =
    session.get(conn, token, 1000 + session.ttl_seconds + 1)
  session.delete(conn, token)
  let assert Error(Nil) = session.get(conn, token, 2000)
  sqlite.close(conn)
}

pub fn magic_round_trip_test() {
  let conn = fresh_conn()
  let assert Ok(token) = magic.create_token(conn, "new@example.com", 1000)
  let assert Ok(user_id) = magic.redeem(conn, token, 1200)
  // The account was created with the email as identity.
  let assert Ok([[Text(email)]]) =
    sqlite.query(conn, "SELECT email FROM users WHERE id = ?", [Text(user_id)])
  assert email == "new@example.com"
  // Single use.
  let assert Error(magic.BadToken) = magic.redeem(conn, token, 1300)
  // Expired tokens don't redeem.
  let assert Ok(stale) = magic.create_token(conn, "other@example.com", 1000)
  let assert Error(magic.BadToken) = magic.redeem(conn, stale, 1000 + 901)
  // Redeeming again for the same email reuses the account.
  let assert Ok(again) = magic.create_token(conn, "new@example.com", 2000)
  let assert Ok(same_user) = magic.redeem(conn, again, 2100)
  assert same_user == user_id
  sqlite.close(conn)
}

pub fn magic_rate_limit_test() {
  let conn = fresh_conn()
  let send = fn() {
    magic.request(
      conn,
      "burst@example.com",
      5000,
      "http://cp.test",
      mailer.LogOnly,
    )
  }
  let assert Ok(Nil) = send()
  let assert Ok(Nil) = send()
  let assert Ok(Nil) = send()
  let assert Ok(Nil) = send()
  let assert Ok(Nil) = send()
  let assert Ok([[sqlite.Int(count)]]) =
    sqlite.query(
      conn,
      "SELECT count(*) FROM magic_link_tokens WHERE email = 'burst@example.com'",
      [],
    )
  assert count == 3
  sqlite.close(conn)
}

pub fn identity_linking_policy_test() {
  let conn = fresh_conn()
  // First login creates the user.
  let assert Ok(user_id) =
    identity.login(
      conn,
      "google",
      None,
      "sub-1",
      "person@example.com",
      True,
      Some("Person"),
      100,
    )
  // Same identity again: same user.
  let assert Ok(same) =
    identity.login(
      conn,
      "google",
      None,
      "sub-1",
      "person@example.com",
      True,
      None,
      200,
    )
  assert same == user_id
  // Different trusted provider, same verified email: auto-links.
  let assert Ok(linked) =
    identity.login(
      conn,
      "github",
      None,
      "999",
      "person@example.com",
      True,
      None,
      300,
    )
  assert linked == user_id
  // Custom OIDC asserting the same email: NEVER auto-links.
  let assert Ok(_) =
    sqlite.exec(conn, "INSERT INTO orgs VALUES ('o1', 'acme', 'Acme', 0)", [])
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO oidc_providers VALUES ('op1', 'o1', 'https://evil.example',
       'cid', 'sec', 'https://evil.example/auth', 'https://evil.example/token',
       NULL, 0)",
      [],
    )
  let assert Error(identity.NeedsExplicitLink("person@example.com")) =
    identity.login(
      conn,
      "oidc",
      Some("op1"),
      "victim-sub",
      "person@example.com",
      False,
      None,
      400,
    )
  // Explicit link from a live session is the sanctioned path.
  let assert Ok(explicitly) =
    identity.link(conn, user_id, "oidc", Some("op1"), "victim-sub", 500)
  assert explicitly == user_id
  let assert Ok(now_logged) =
    identity.login(
      conn,
      "oidc",
      Some("op1"),
      "victim-sub",
      "person@example.com",
      False,
      None,
      600,
    )
  assert now_logged == user_id
  sqlite.close(conn)
}

pub fn oauth_state_single_use_test() {
  let conn = fresh_conn()
  let provider =
    oauth.Provider(
      "google",
      "https://auth.example/authorize",
      "https://auth.example/token",
      "cid",
      "secret",
      "openid email",
    )
  let assert Ok(url) =
    oauth.start(
      conn,
      provider,
      "http://cp.test/auth/callback/google",
      None,
      None,
      100,
    )
  assert string.starts_with(url, "https://auth.example/authorize?")
  assert string.contains(url, "code_challenge_method=S256")
  assert string.contains(url, "client_id=cid")
  // Extract state from the URL.
  let assert Ok(#(_, tail)) = string.split_once(url, "state=")
  let assert [state, ..] = string.split(tail, "&")
  let assert Ok(flow) = oauth.take_state(conn, state, 200)
  assert flow.provider == "google"
  assert flow.link_user_id == None
  // Single use.
  let assert Error(Nil) = oauth.take_state(conn, state, 300)
  // Expired states never match.
  let assert Ok(url2) =
    oauth.start(
      conn,
      provider,
      "http://cp.test/auth/callback/google",
      None,
      None,
      100,
    )
  let assert Ok(#(_, tail2)) = string.split_once(url2, "state=")
  let assert [state2, ..] = string.split(tail2, "&")
  let assert Error(Nil) = oauth.take_state(conn, state2, 100 + 601)
  sqlite.close(conn)
}

pub fn id_token_claims_test() {
  let payload =
    json.object([
      #("iss", json.string("https://accounts.google.com")),
      #("aud", json.string("cid")),
      #("sub", json.string("sub-9")),
      #("exp", json.int(2000)),
      #("email", json.string("a@b.c")),
      #("email_verified", json.bool(True)),
      #("nonce", json.string("n1")),
    ])
    |> json.to_string
  let jwt =
    "eyJhbGciOiJSUzI1NiJ9."
    <> bit_array.base64_url_encode(<<payload:utf8>>, False)
    <> ".sig"
  let assert Ok(claims) = oauth.decode_id_token(jwt)
  assert claims.sub == "sub-9"
  assert claims.email == Some("a@b.c")
  let assert Ok(Nil) =
    oauth.validate_claims(
      claims,
      ["https://accounts.google.com"],
      "cid",
      "n1",
      1000,
    )
  // Expired.
  let assert Error(_) =
    oauth.validate_claims(
      claims,
      ["https://accounts.google.com"],
      "cid",
      "n1",
      3000,
    )
  // Wrong nonce.
  let assert Error(_) =
    oauth.validate_claims(
      claims,
      ["https://accounts.google.com"],
      "cid",
      "other",
      1000,
    )
  // Wrong audience.
  let assert Error(_) =
    oauth.validate_claims(
      claims,
      ["https://accounts.google.com"],
      "other-cid",
      "n1",
      1000,
    )
  // Wrong issuer.
  let assert Error(_) =
    oauth.validate_claims(claims, ["https://evil.example"], "cid", "n1", 1000)
}
