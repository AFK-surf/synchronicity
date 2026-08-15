//// HTTP routing. The DNS endpoints and health/anchor are role-agnostic;
//// the product API mounts on the primary only (a replica has no sessions
//// and no writes, by construction).

import api/auth_api.{type AuthContext}
import dns/doh
import gleam/http.{Get, Post}
import gleam/json
import gleam/option.{type Option, None, Some}
import wisp.{type Request, type Response}
import zone/snapshot

pub type Context {
  Context(
    /// Trust-anchor line + DS record, prebuilt at boot (public data).
    anchor: String,
    ds: String,
    /// Present on the primary only; replicas serve DNS and health alone.
    auth: Option(AuthContext),
  )
}

pub fn handle(req: Request, ctx: Context) -> Response {
  case wisp.path_segments(req) {
    ["dns-query"] -> doh.handle(req)
    ["healthz"] -> healthz()
    ["api", "zone", "anchor"] -> anchor(ctx)
    ["auth", ..] | ["api", ..] ->
      case ctx.auth {
        Some(auth) -> primary_routes(req, auth)
        None -> wisp.not_found()
      }
    _ -> wisp.not_found()
  }
}

fn primary_routes(req: Request, auth: AuthContext) -> Response {
  case wisp.path_segments(req), req.method {
    ["auth", "start", provider], Get -> auth_api.start(req, auth, provider)
    ["auth", "callback", provider], Get ->
      auth_api.callback(req, auth, provider)
    ["auth", "magic"], Post -> auth_api.magic_request(req, auth)
    ["auth", "magic", "redeem"], Get -> auth_api.magic_redeem(req, auth)
    ["api", "logout"], Post -> auth_api.logout(req, auth)
    ["api", "me"], Get -> auth_api.me(req, auth)
    _, _ -> wisp.not_found()
  }
}

fn healthz() -> Response {
  case snapshot.current() {
    Ok(snap) ->
      json.object([
        #("status", json.string("ok")),
        #("soa_serial", json.int(snap.serial)),
        #("sig_expires_at", json.int(snap.min_sig_expires)),
        #("loaded_at", json.int(snap.loaded_at)),
      ])
      |> json.to_string
      |> wisp.json_response(200)
    Error(Nil) ->
      json.object([#("status", json.string("no zone loaded"))])
      |> json.to_string
      |> wisp.json_response(503)
  }
}

fn anchor(ctx: Context) -> Response {
  let body =
    "; trust anchor for --dnssec-anchor\n"
    <> ctx.anchor
    <> "\n; DS record for the parent zone\n; "
    <> ctx.ds
    <> "\n"
  wisp.response(200)
  |> wisp.set_header("content-type", "text/plain; charset=utf-8")
  |> wisp.set_body(wisp.Text(body))
}
