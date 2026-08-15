//// Per-org custom OIDC. Discovery runs once, at configuration save time,
//// over verified TLS, and the document's `issuer` must equal the
//// configured issuer — fail closed on mismatch. ID tokens from these
//// issuers are validated (iss/aud/exp/nonce) but their email claims are
//// NEVER trusted for auto-linking: the issuer is org-controlled.

import auth/oauth.{type Provider, Provider}
import gleam/dynamic/decode
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Int as VInt, Null, Text}
import util/id

pub type Discovered {
  Discovered(
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option(String),
  )
}

/// Fetches and validates <issuer>/.well-known/openid-configuration.
pub fn discover(issuer: String) -> Result(Discovered, String) {
  let url = normalize(issuer) <> "/.well-known/openid-configuration"
  use req <- result.try(
    request.to(url) |> result.replace_error("bad issuer URL"),
  )
  use resp <- result.try(
    httpc.send(request.set_header(req, "accept", "application/json"))
    |> result.map_error(fn(e) { "discovery failed: " <> string.inspect(e) }),
  )
  case resp.status {
    200 -> parse_discovery(resp.body, issuer)
    status -> Error("discovery returned " <> int.to_string(status))
  }
}

/// Pure parse + the fail-closed issuer check (unit-tested directly).
pub fn parse_discovery(
  body: String,
  expected_issuer: String,
) -> Result(Discovered, String) {
  let decoder = {
    use doc_issuer <- decode.field("issuer", decode.string)
    use authorization <- decode.field("authorization_endpoint", decode.string)
    use token <- decode.field("token_endpoint", decode.string)
    use userinfo <- decode.optional_field(
      "userinfo_endpoint",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(doc_issuer, authorization, token, userinfo))
  }
  use #(doc_issuer, authorization, token, userinfo) <- result.try(
    json.parse(body, decoder)
    |> result.replace_error("unparseable discovery document"),
  )
  case normalize(doc_issuer) == normalize(expected_issuer) {
    True -> Ok(Discovered(authorization, token, userinfo))
    False ->
      Error(
        "discovery document says issuer "
        <> doc_issuer
        <> " but "
        <> expected_issuer
        <> " was configured — refusing",
      )
  }
}

fn normalize(issuer: String) -> String {
  case string.ends_with(issuer, "/") {
    True -> normalize(string.drop_end(issuer, 1))
    False -> issuer
  }
}

/// Saves (or replaces) an org's OIDC configuration after live discovery.
pub fn save(
  conn: Connection,
  org_id: String,
  issuer: String,
  client_id: String,
  client_secret: String,
  now: Int,
) -> Result(Discovered, String) {
  use found <- result.try(discover(issuer))
  let userinfo = case found.userinfo_endpoint {
    Some(url) -> Text(url)
    None -> Null
  }
  let write = {
    use _ <- result.try(
      sqlite.exec(conn, "DELETE FROM oidc_providers WHERE org_id = ?", [
        Text(org_id),
      ]),
    )
    sqlite.exec(
      conn,
      "INSERT INTO oidc_providers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        Text(id.new()),
        Text(org_id),
        Text(normalize(issuer)),
        Text(client_id),
        Text(client_secret),
        Text(found.authorization_endpoint),
        Text(found.token_endpoint),
        userinfo,
        VInt(now),
      ],
    )
  }
  case write {
    Ok(_) -> Ok(found)
    Error(_) -> Error("could not store OIDC configuration")
  }
}

pub type OrgProvider {
  OrgProvider(provider_id: String, issuer: String, provider: Provider)
}

/// Loads the provider for an org slug (login path).
pub fn for_org_slug(
  conn: Connection,
  slug: String,
) -> Result(OrgProvider, Nil) {
  let lookup =
    sqlite.query(
      conn,
      "SELECT p.id, p.issuer, p.client_id, p.client_secret,
              p.authorization_endpoint, p.token_endpoint
       FROM oidc_providers p JOIN orgs o ON o.id = p.org_id
       WHERE o.slug = ?",
      [Text(slug)],
    )
  from_row(lookup)
}

/// Loads a provider by its id (callback path).
pub fn by_id(
  conn: Connection,
  provider_id: String,
) -> Result(OrgProvider, Nil) {
  let lookup =
    sqlite.query(
      conn,
      "SELECT id, issuer, client_id, client_secret,
              authorization_endpoint, token_endpoint
       FROM oidc_providers WHERE id = ?",
      [Text(provider_id)],
    )
  from_row(lookup)
}

fn from_row(
  lookup: Result(List(List(sqlite.Value)), sqlite.Error),
) -> Result(OrgProvider, Nil) {
  case lookup {
    Ok([
      [
        Text(provider_id),
        Text(issuer),
        Text(client_id),
        Text(client_secret),
        Text(authorization),
        Text(token),
      ],
    ]) ->
      Ok(OrgProvider(
        provider_id,
        issuer,
        Provider(
          "oidc",
          authorization,
          token,
          client_id,
          client_secret,
          "openid email profile",
        ),
      ))
    _ -> Error(Nil)
  }
}

/// Extracts and validates the identity from an OIDC token response.
/// email_trusted is always False for custom issuers.
pub fn identity_from_tokens(
  org: OrgProvider,
  tokens: oauth.Tokens,
  expected_nonce: String,
  now: Int,
) -> Result(oauth.ProviderIdentity, String) {
  use id_token <- result.try(case tokens.id_token {
    Some(token) -> Ok(token)
    None -> Error("issuer did not return an id_token")
  })
  use claims <- result.try(oauth.decode_id_token(id_token))
  use Nil <- result.try(oauth.validate_claims(
    claims,
    [org.issuer, org.issuer <> "/"],
    org.provider.client_id,
    expected_nonce,
    now,
  ))
  use email <- result.try(case claims.email {
    Some(email) -> Ok(email)
    None -> Error("id_token carries no email claim")
  })
  Ok(oauth.ProviderIdentity(claims.sub, email, claims.name, False))
}
