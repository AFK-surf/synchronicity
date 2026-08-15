//// HTTP routing. The DNS endpoints and health/anchor are role-agnostic;
//// the product API mounts on the primary only (a replica has no sessions
//// and no writes, by construction).

import api/auth_api.{type AuthContext}
import api/middleware
import api/networks_api
import api/orgs_api
import api/static
import auth/session.{type Session}
import dns/doh
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/json
import gleam/option.{type Option, None, Some}
import wisp.{type Request, type Response}
import zone/refresh
import zone/snapshot

pub type Context {
  Context(
    /// Trust-anchor line + DS record, prebuilt at boot (public data).
    anchor: String,
    ds: String,
    /// Present on the primary only; replicas serve DNS and health alone.
    auth: Option(AuthContext),
    /// Replica only: the database path POST /reload refreshes from — the
    /// immediate-pickup half of the external refresh contract.
    reload_db: Option(String),
  )
}

pub fn handle(req: Request, ctx: Context) -> Response {
  case wisp.path_segments(req) {
    ["dns-query"] -> doh.handle(req)
    ["healthz"] -> healthz()
    ["api", "zone", "anchor"] -> anchor(ctx)
    ["reload"] ->
      case req.method, ctx.reload_db {
        Post, Some(db_path) -> reload(db_path)
        _, _ -> wisp.not_found()
      }
    ["auth", ..] | ["api", ..] ->
      case ctx.auth {
        Some(auth) -> primary_routes(req, auth)
        None -> wisp.not_found()
      }
    _ ->
      case ctx.auth {
        // The dashboard ships with the primary; replicas serve DNS only.
        Some(_) -> static.serve(req, wisp.not_found)
        None -> wisp.not_found()
      }
  }
}

fn primary_routes(req: Request, auth: AuthContext) -> Response {
  case wisp.path_segments(req), req.method {
    ["auth", "oidc", org_slug], Get -> auth_api.oidc_start(req, auth, org_slug)
    ["auth", "callback", "oidc"], Get -> auth_api.oidc_callback(req, auth)
    ["auth", "start", provider], Get -> auth_api.start(req, auth, provider)
    ["auth", "callback", provider], Get ->
      auth_api.callback(req, auth, provider)
    ["auth", "magic"], Post -> auth_api.magic_request(req, auth)
    ["auth", "magic", "redeem"], Get -> auth_api.magic_redeem(req, auth)
    ["api", "logout"], Post -> auth_api.logout(req, auth)
    ["api", "me"], Get -> auth_api.me(req, auth)

    ["api", "orgs"], Post -> {
      use live <- with_session(req, auth)
      orgs_api.create_org(req, auth, live)
    }
    ["api", "orgs", slug], Get -> {
      use live <- with_session(req, auth)
      orgs_api.get_org(auth, live, slug)
    }
    ["api", "orgs", slug, "members"], Get -> {
      use live <- with_session(req, auth)
      orgs_api.list_members(auth, live, slug)
    }
    ["api", "orgs", slug, "members", user], Patch -> {
      use live <- with_session(req, auth)
      orgs_api.change_role(req, auth, live, slug, user)
    }
    ["api", "orgs", slug, "members", user], Delete -> {
      use live <- with_session(req, auth)
      orgs_api.remove_member(auth, live, slug, user)
    }
    ["api", "orgs", slug, "invites"], Post -> {
      use live <- with_session(req, auth)
      orgs_api.create_invite(req, auth, live, slug)
    }
    ["api", "invites", "accept"], Post -> {
      use live <- with_session(req, auth)
      orgs_api.accept_invite(req, auth, live)
    }
    ["api", "orgs", slug, "audit"], Get -> {
      use live <- with_session(req, auth)
      orgs_api.audit_log(req, auth, live, slug)
    }
    ["api", "orgs", slug, "oidc"], Get -> {
      use live <- with_session(req, auth)
      orgs_api.get_oidc(auth, live, slug)
    }
    ["api", "orgs", slug, "oidc"], Put -> {
      use live <- with_session(req, auth)
      orgs_api.put_oidc(req, auth, live, slug)
    }
    ["api", "orgs", slug, "oidc"], Delete -> {
      use live <- with_session(req, auth)
      orgs_api.delete_oidc(auth, live, slug)
    }

    ["api", "orgs", slug, "networks"], Get -> {
      use live <- with_session(req, auth)
      networks_api.list_networks(auth, live, slug)
    }
    ["api", "orgs", slug, "networks"], Post -> {
      use live <- with_session(req, auth)
      networks_api.create_network(req, auth, live, slug)
    }
    ["api", "orgs", slug, "networks", net], Get -> {
      use live <- with_session(req, auth)
      networks_api.network_detail(auth, live, slug, net)
    }
    ["api", "orgs", slug, "networks", net], Delete -> {
      use live <- with_session(req, auth)
      networks_api.delete_network(req, auth, live, slug, net)
    }
    ["api", "orgs", slug, "networks", net, "devices", dev], Put -> {
      use live <- with_session(req, auth)
      networks_api.assign_device(auth, live, slug, net, dev)
    }
    ["api", "orgs", slug, "networks", net, "devices", dev], Delete -> {
      use live <- with_session(req, auth)
      networks_api.unassign_device(auth, live, slug, net, dev)
    }

    ["api", "orgs", slug, "devices"], Get -> {
      use live <- with_session(req, auth)
      networks_api.list_devices(auth, live, slug)
    }
    ["api", "orgs", slug, "devices"], Post -> {
      use live <- with_session(req, auth)
      networks_api.create_device(req, auth, live, slug)
    }
    ["api", "orgs", slug, "devices", dev], Patch -> {
      use live <- with_session(req, auth)
      networks_api.patch_device(req, auth, live, slug, dev)
    }
    ["api", "orgs", slug, "devices", dev], Delete -> {
      use live <- with_session(req, auth)
      networks_api.delete_device(auth, live, slug, dev)
    }
    ["api", "orgs", slug, "devices", dev, "keys"], Post -> {
      use live <- with_session(req, auth)
      networks_api.add_key(req, auth, live, slug, dev)
    }
    ["api", "orgs", slug, "devices", dev, "keys", key, "retire"], Post -> {
      use live <- with_session(req, auth)
      networks_api.retire_key(auth, live, slug, dev, key)
    }
    ["api", "orgs", slug, "devices", dev, "keys", key, "revoke"], Post -> {
      use live <- with_session(req, auth)
      networks_api.revoke_key(auth, live, slug, dev, key)
    }

    _, _ -> wisp.not_found()
  }
}

fn with_session(
  req: Request,
  auth: AuthContext,
  next: fn(Session) -> Response,
) -> Response {
  auth_api.with_db(auth, fn(conn) {
    middleware.require_session(req, conn, next)
  })
}

fn reload(db_path: String) -> Response {
  case refresh.reload(db_path) {
    Ok(serial) ->
      json.object([#("soa_serial", json.int(serial))])
      |> json.to_string
      |> wisp.json_response(200)
    Error(message) ->
      json.object([#("error", json.string(message))])
      |> json.to_string
      |> wisp.json_response(500)
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
