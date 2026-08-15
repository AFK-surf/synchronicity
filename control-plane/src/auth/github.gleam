//// GitHub sign-in: plain OAuth 2 (no OIDC), so identity comes from the
//// API — /user for the stable numeric id, /user/emails for the verified
//// primary address.

import auth/oauth.{
  type Provider, type ProviderIdentity, Provider, ProviderIdentity,
}
import gleam/dynamic/decode
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None}
import gleam/result
import gleam/string

pub fn provider(client_id: String, client_secret: String) -> Provider {
  Provider(
    "github",
    "https://github.com/login/oauth/authorize",
    "https://github.com/login/oauth/access_token",
    client_id,
    client_secret,
    "read:user user:email",
  )
}

/// `api_base` is https://api.github.com in production; tests point it at
/// a stub.
pub fn fetch_identity(
  access_token: String,
  api_base: String,
) -> Result(ProviderIdentity, String) {
  use user_body <- result.try(get(api_base <> "/user", access_token))
  let user_decoder = {
    use github_id <- decode.field("id", decode.int)
    use display <- decode.optional_field(
      "name",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(github_id, display))
  }
  use #(github_id, display) <- result.try(
    json.parse(user_body, user_decoder)
    |> result.replace_error("unparseable /user response"),
  )

  use emails_body <- result.try(get(api_base <> "/user/emails", access_token))
  let email_decoder = {
    use email <- decode.field("email", decode.string)
    use verified <- decode.field("verified", decode.bool)
    use primary <- decode.field("primary", decode.bool)
    decode.success(#(email, verified, primary))
  }
  use emails <- result.try(
    json.parse(emails_body, decode.list(email_decoder))
    |> result.replace_error("unparseable /user/emails response"),
  )
  case
    list.find(emails, fn(e) { e.1 && e.2 })
    |> result.lazy_or(fn() { list.find(emails, fn(e) { e.1 }) })
  {
    Ok(#(email, _, _)) ->
      Ok(ProviderIdentity(int.to_string(github_id), email, display, True))
    Error(Nil) -> Error("github account has no verified email")
  }
}

fn get(url: String, access_token: String) -> Result(String, String) {
  use req <- result.try(
    request.to(url) |> result.replace_error("bad url " <> url),
  )
  let req =
    req
    |> request.set_header("authorization", "Bearer " <> access_token)
    |> request.set_header("accept", "application/vnd.github+json")
    |> request.set_header("user-agent", "synchronicity-control-plane")
  use resp <- result.try(
    httpc.send(req)
    |> result.map_error(fn(e) { "github unreachable: " <> string.inspect(e) }),
  )
  case resp.status {
    200 -> Ok(resp.body)
    status -> Error("github returned " <> int.to_string(status))
  }
}
