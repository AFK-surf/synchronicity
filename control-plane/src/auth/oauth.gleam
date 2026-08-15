//// The generic OAuth 2 authorization-code flow: state + PKCE (S256) +
//// nonce, single-use state rows, token exchange over verified TLS
//// (gleam_httpc verifies certificates by default — that verification is
//// load-bearing for the ID-token trust model, see auth/oidc).

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import store/sqlite.{type Connection, Int as VInt, Null, Text}
import util/id

pub type Provider {
  Provider(
    key: String,
    authorization_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    scopes: String,
  )
}

/// An in-flight flow, as persisted in oauth_states.
pub type FlowState {
  FlowState(
    provider: String,
    oidc_provider_id: Option(String),
    pkce_verifier: String,
    nonce: String,
    link_user_id: Option(String),
  )
}

/// What the token endpoint returned.
pub type Tokens {
  Tokens(access_token: String, id_token: Option(String))
}

/// An authenticated external identity, provider-agnostic.
pub type ProviderIdentity {
  ProviderIdentity(
    subject: String,
    email: String,
    name: Option(String),
    /// Whether the provider verified the email — the auto-link gate.
    email_trusted: Bool,
  )
}

/// Builds the authorize redirect and records the flow state (10 min).
pub fn start(
  conn: Connection,
  provider: Provider,
  redirect_uri: String,
  oidc_provider_id: Option(String),
  link_user_id: Option(String),
  now: Int,
) -> Result(String, sqlite.Error) {
  let state = id.secret()
  let verifier = id.secret() <> id.secret()
  let challenge =
    bit_array.base64_url_encode(
      crypto.hash(crypto.Sha256, <<verifier:utf8>>),
      False,
    )
  let nonce = id.secret()
  use _ <- result.try(
    sqlite.exec(
      conn,
      "INSERT INTO oauth_states VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        Text(state),
        Text(provider.key),
        option_text(oidc_provider_id),
        Text(verifier),
        Text(nonce),
        Null,
        option_text(link_user_id),
        VInt(now),
        VInt(now + 600),
      ],
    ),
  )
  let query =
    uri.query_to_string([
      #("response_type", "code"),
      #("client_id", provider.client_id),
      #("redirect_uri", redirect_uri),
      #("scope", provider.scopes),
      #("state", state),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("nonce", nonce),
    ])
  Ok(provider.authorization_endpoint <> "?" <> query)
}

fn option_text(value: Option(String)) -> sqlite.Value {
  case value {
    Some(text) -> Text(text)
    None -> Null
  }
}

/// Consumes a state row — single use, expired rows never match.
pub fn take_state(
  conn: Connection,
  state: String,
  now: Int,
) -> Result(FlowState, Nil) {
  let lookup =
    sqlite.query(
      conn,
      "SELECT provider, coalesce(oidc_provider_id, ''), pkce_verifier,
              coalesce(nonce, ''), coalesce(link_user_id, '')
       FROM oauth_states WHERE state = ? AND expires_at > ?",
      [Text(state), VInt(now)],
    )
  let _ =
    sqlite.exec(conn, "DELETE FROM oauth_states WHERE state = ?", [Text(state)])
  case lookup {
    Ok([[Text(provider), Text(oidc), Text(verifier), Text(nonce), Text(link)]]) ->
      Ok(FlowState(provider, non_empty(oidc), verifier, nonce, non_empty(link)))
    _ -> Error(Nil)
  }
}

fn non_empty(text: String) -> Option(String) {
  case text {
    "" -> None
    _ -> Some(text)
  }
}

/// Exchanges the code at the token endpoint. TLS verification on: the
/// response's authenticity is exactly what the ID-token trust rests on.
pub fn exchange(
  provider: Provider,
  code: String,
  redirect_uri: String,
  pkce_verifier: String,
) -> Result(Tokens, String) {
  let body =
    uri.query_to_string([
      #("grant_type", "authorization_code"),
      #("code", code),
      #("redirect_uri", redirect_uri),
      #("client_id", provider.client_id),
      #("client_secret", provider.client_secret),
      #("code_verifier", pkce_verifier),
    ])
  use req <- result.try(
    request.to(provider.token_endpoint)
    |> result.replace_error("bad token endpoint " <> provider.token_endpoint),
  )
  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_header("accept", "application/json")
    |> request.set_body(body)
  use resp <- result.try(
    httpc.send(req)
    |> result.map_error(fn(e) {
      "token endpoint unreachable: " <> string.inspect(e)
    }),
  )
  case resp.status {
    200 -> parse_tokens(resp.body)
    status ->
      Error(
        "token endpoint returned "
        <> string.inspect(status)
        <> ": "
        <> string.slice(resp.body, 0, 200),
      )
  }
}

fn parse_tokens(body: String) -> Result(Tokens, String) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use id_token <- decode.optional_field(
      "id_token",
      None,
      decode.optional(decode.string),
    )
    decode.success(Tokens(access_token, id_token))
  }
  json.parse(body, decoder)
  |> result.replace_error("unparseable token response")
}

/// ID-token claims we validate. No JWS verification — the token arrived on
/// the TLS-verified, client-authenticated token-endpoint channel (OIDC
/// Core §3.1.3.7 sanctions TLS server validation in this exact case); we
/// validate iss, aud, exp and nonce instead.
pub type Claims {
  Claims(
    iss: String,
    aud: String,
    sub: String,
    exp: Int,
    email: Option(String),
    email_verified: Bool,
    name: Option(String),
    nonce: Option(String),
  )
}

pub fn decode_id_token(id_token: String) -> Result(Claims, String) {
  case string.split(id_token, ".") {
    [_header, payload, ..] -> {
      use bytes <- result.try(
        base64url(payload) |> result.replace_error("bad id_token encoding"),
      )
      use text <- result.try(
        bit_array.to_string(bytes) |> result.replace_error("bad id_token utf8"),
      )
      let decoder = {
        use iss <- decode.field("iss", decode.string)
        use aud <- decode.field("aud", decode.string)
        use sub <- decode.field("sub", decode.string)
        use exp <- decode.field("exp", decode.int)
        use email <- decode.optional_field(
          "email",
          None,
          decode.optional(decode.string),
        )
        use verified <- decode.optional_field(
          "email_verified",
          False,
          decode.bool,
        )
        use claim_name <- decode.optional_field(
          "name",
          None,
          decode.optional(decode.string),
        )
        use nonce <- decode.optional_field(
          "nonce",
          None,
          decode.optional(decode.string),
        )
        decode.success(Claims(
          iss,
          aud,
          sub,
          exp,
          email,
          verified,
          claim_name,
          nonce,
        ))
      }
      json.parse(text, decoder)
      |> result.replace_error("unparseable id_token claims")
    }
    _ -> Error("id_token is not a JWT")
  }
}

fn base64url(text: String) -> Result(BitArray, Nil) {
  bit_array.base64_url_decode(text)
  |> result.lazy_or(fn() { bit_array.base64_url_decode(text <> "=") })
  |> result.lazy_or(fn() { bit_array.base64_url_decode(text <> "==") })
}

/// Shared claim validation: issuer, audience, expiry, nonce.
pub fn validate_claims(
  claims: Claims,
  expected_issuers: List(String),
  client_id: String,
  expected_nonce: String,
  now: Int,
) -> Result(Nil, String) {
  use Nil <- result.try(case list_contains(expected_issuers, claims.iss) {
    True -> Ok(Nil)
    False -> Error("id_token issuer mismatch: " <> claims.iss)
  })
  use Nil <- result.try(case claims.aud == client_id {
    True -> Ok(Nil)
    False -> Error("id_token audience mismatch")
  })
  use Nil <- result.try(case claims.exp > now {
    True -> Ok(Nil)
    False -> Error("id_token expired")
  })
  case claims.nonce {
    Some(nonce) if nonce == expected_nonce -> Ok(Nil)
    _ -> Error("id_token nonce mismatch")
  }
}

fn list_contains(items: List(String), needle: String) -> Bool {
  case items {
    [] -> False
    [first, ..rest] -> first == needle || list_contains(rest, needle)
  }
}
