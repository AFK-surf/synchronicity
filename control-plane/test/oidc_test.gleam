import auth/oauth
import auth/oidc
import fixtures.{fresh_conn}
import gleam/bit_array
import gleam/json
import gleam/option.{None, Some}
import gleam/string
import store/sqlite

fn discovery_doc(issuer: String) -> String {
  json.object([
    #("issuer", json.string(issuer)),
    #("authorization_endpoint", json.string(issuer <> "/authorize")),
    #("token_endpoint", json.string(issuer <> "/token")),
    #("userinfo_endpoint", json.string(issuer <> "/userinfo")),
  ])
  |> json.to_string
}

fn test_org() -> oidc.OrgProvider {
  oidc.OrgProvider(
    "op1",
    "https://id.example.com",
    oauth.Provider(
      "oidc",
      "https://id.example.com/authorize",
      "https://id.example.com/token",
      "client-1",
      "secret",
      "openid email profile",
    ),
  )
}

pub fn parse_discovery_test() {
  let assert Ok(found) =
    oidc.parse_discovery(
      discovery_doc("https://id.example.com"),
      "https://id.example.com",
    )
  assert found.authorization_endpoint == "https://id.example.com/authorize"
  assert found.token_endpoint == "https://id.example.com/token"
  assert found.userinfo_endpoint == Some("https://id.example.com/userinfo")
  // Trailing-slash tolerance.
  let assert Ok(_) =
    oidc.parse_discovery(
      discovery_doc("https://id.example.com"),
      "https://id.example.com/",
    )
}

pub fn parse_discovery_rejects_issuer_mismatch_test() {
  // Fail closed: a document claiming a different issuer is a
  // misconfiguration or an attack, never accepted.
  let assert Error(message) =
    oidc.parse_discovery(
      discovery_doc("https://evil.example.com"),
      "https://id.example.com",
    )
  assert string.contains(message, "refusing")
}

pub fn parse_discovery_rejects_garbage_test() {
  let assert Error(_) = oidc.parse_discovery("not json", "https://x.example")
  let assert Error(_) =
    oidc.parse_discovery(
      "{\"issuer\": \"https://x.example\"}",
      "https://x.example",
    )
}

pub fn identity_requires_id_token_test() {
  let assert Error(message) =
    oidc.identity_from_tokens(test_org(), oauth.Tokens("access", None), "n", 0)
  assert string.contains(message, "id_token")
}

pub fn identity_from_tokens_validates_and_distrusts_email_test() {
  let payload =
    json.object([
      #("iss", json.string("https://id.example.com")),
      #("aud", json.string("client-1")),
      #("sub", json.string("emp-7")),
      #("exp", json.int(2000)),
      #("email", json.string("someone@corp.example")),
      // Even an asserted-verified email stays untrusted for auto-linking:
      #("email_verified", json.bool(True)),
      #("nonce", json.string("n1")),
    ])
    |> json.to_string
  let jwt = "e30." <> json_b64(payload) <> ".sig"
  let tokens = oauth.Tokens("access", Some(jwt))
  let assert Ok(who) = oidc.identity_from_tokens(test_org(), tokens, "n1", 1000)
  assert who.subject == "emp-7"
  assert who.email == "someone@corp.example"
  assert who.email_trusted == False
  // Wrong nonce fails.
  let assert Error(_) =
    oidc.identity_from_tokens(test_org(), tokens, "other", 1000)
  // Wrong audience fails.
  let other_org =
    oidc.OrgProvider(
      "op1",
      "https://id.example.com",
      oauth.Provider(
        "oidc",
        "https://id.example.com/authorize",
        "https://id.example.com/token",
        "different-client",
        "secret",
        "openid email profile",
      ),
    )
  let assert Error(_) = oidc.identity_from_tokens(other_org, tokens, "n1", 1000)
}

fn json_b64(payload: String) -> String {
  bit_array.base64_url_encode(<<payload:utf8>>, False)
}

/// The login screen asks whether to draw the org sign-in box at all.
pub fn any_configured_test() {
  let conn = fresh_conn()
  assert oidc.any_configured(conn) == False
  let assert Ok(_) =
    sqlite.script(
      conn,
      "INSERT INTO orgs VALUES ('o1', 'acme', 'Acme', 0);
       INSERT INTO oidc_providers VALUES ('p1', 'o1', 'https://id.example.com',
         'client-1', 'secret', 'https://id.example.com/authorize',
         'https://id.example.com/token', NULL, 0);",
    )
  assert oidc.any_configured(conn) == True
  sqlite.close(conn)
}
