//// HTTP routing. The DNS endpoints and health/anchor are role-agnostic;
//// the product API mounts on the primary only (a replica has no sessions
//// and no writes, by construction).

import dns/doh
import gleam/json
import wisp.{type Request, type Response}
import zone/snapshot

pub type Context {
  Context(
    /// Trust-anchor line + DS record, prebuilt at boot (public data).
    anchor: String,
    ds: String,
  )
}

pub fn handle(req: Request, ctx: Context) -> Response {
  case wisp.path_segments(req) {
    ["dns-query"] -> doh.handle(req)
    ["healthz"] -> healthz()
    ["api", "zone", "anchor"] -> anchor(ctx)
    _ -> wisp.not_found()
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
