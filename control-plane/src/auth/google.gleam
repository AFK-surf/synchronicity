//// Google sign-in: standard code flow; identity comes from the ID token
//// (TLS-direct from the token endpoint), and only verified emails count.

import auth/oauth.{
  type Provider, type ProviderIdentity, type Tokens, Provider, ProviderIdentity,
}
import gleam/option.{None, Some}
import gleam/result

pub fn provider(client_id: String, client_secret: String) -> Provider {
  Provider(
    "google",
    "https://accounts.google.com/o/oauth2/v2/auth",
    "https://oauth2.googleapis.com/token",
    client_id,
    client_secret,
    "openid email profile",
  )
}

pub fn fetch_identity(
  tokens: Tokens,
  client_id: String,
  expected_nonce: String,
  now: Int,
) -> Result(ProviderIdentity, String) {
  use id_token <- result.try(case tokens.id_token {
    Some(token) -> Ok(token)
    None -> Error("google did not return an id_token")
  })
  use claims <- result.try(oauth.decode_id_token(id_token))
  use Nil <- result.try(oauth.validate_claims(
    claims,
    ["https://accounts.google.com", "accounts.google.com"],
    client_id,
    expected_nonce,
    now,
  ))
  use email <- result.try(case claims.email {
    Some(email) -> Ok(email)
    None -> Error("google id_token carries no email")
  })
  case claims.email_verified {
    True -> Ok(ProviderIdentity(claims.sub, email, claims.name, True))
    False -> Error("google email is unverified")
  }
}
