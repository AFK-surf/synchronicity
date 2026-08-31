//// HTTP routing. The DNS endpoints and health/anchor are role-agnostic;
//// the product API mounts in one of two shapes.
////
//// **The split is reads against writes, not primary against replica.** A
//// replica holds a read-only copy of the same database, so every GET the
//// primary answers it answers identically — the dashboard, the org and
//// network listings, and the browse surface, whose daemons attach to it
//// directly. What it cannot do is mint a session or mutate a row, so those
//// routes are not mounted at all: they answer with a refusal that names the
//// primary, which is the one fact a read-only node holds that a 404 does
//// not carry.
////
//// **Three credentials reach the product API**, and the split above is the
//// reason all of them are resolved in one place: a session cookie (a
//// person), a bearer org key, and a bearer join key. `with_principal`
//// resolves whichever the request carries, `api/common.check_org` decides
//// what it permits, and no route below has to know which arrived — except
//// the handful that are a person's alone, which say so with
//// `middleware.require_user`, and the one join route, which asks
//// `api/common.check_join_target` instead.
////
//// **A fourth reaches `/dp/v1` and only `/dp/v1`** — the cloud data plane's
//// key (docs/CLOUD-DATAPLANE.md §3.2). It is resolved by the same
//// `with_principal`, because there must be exactly one place a bearer token
//// becomes a principal, and it is then kept apart by two refusals rather than
//// by a second router: `api/common.check_org` turns it away, so no org-scoped
//// route can be reached with it, and `api/dataplane_api` admits nothing else,
//// so no other credential can be reached *through* it. The `/dp/v1` prefix
//// sits under the same reads/writes split as everything else — the
//// desired-state GET is a read of litestream-fed state and a replica serves
//// it; the registration, the retirement and the heartbeat are writes and are
//// the primary's.
////
//// Naming convention in api/: endpoint modules carry the `_api` suffix
//// (auth_api, orgs_api, networks_api, devices_api); plumbing does not
//// (router, middleware, common, static — static serves files, not an API;
//// skill serves one file, likewise).

import api/api_keys_api
import api/auth_api.{type AuthContext}
import api/browse_api.{type Browse}
import api/dataplane_api
import api/devices_api
import api/middleware
import api/networks_api
import api/orgs_api
import api/reads.{type Reads}
import api/skill
import api/static
import auth/principal.{type Principal}
import dns/doh
import dns/serve.{type Serving}
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import provider/state as provider_state
import store/pool
import wisp.{type Request, type Response}
import zone/model

/// How this deployment's zone reaches the wire, as routing needs to know
/// it: a serving node answers DoH and reports RRSIG health; an external
/// node has no DNS surface at all and reports reconciler health instead.
pub type ZoneSurface {
  ServingZone(serving: Serving)
  ExternalZone(pool: pool.Pool)
}

pub type Context {
  Context(
    /// Trust-anchor line + DS record, prebuilt at boot (public data).
    /// Empty in external mode — there is no zone key of ours to anchor.
    anchor: String,
    ds: String,
    /// The product API this node mounts. Every node mounts one; which half
    /// is the only question.
    api: Api,
    /// Read-only serving context (pool + apex) on serving roles. A replica
    /// needs no reload signal: every checkout reopens the database file,
    /// so an atomically renamed replacement is picked up on next use.
    zone: ZoneSurface,
    /// Where this node's attached daemons are. Every node has a registry:
    /// the apex names every node, and a daemon opens a tunnel to each.
    browse: Browse,
  )
}

/// Which half of the product API is mounted here.
pub type Api {
  /// Everything: the reads, the writes, and the sign-in flows that mint the
  /// sessions both halves are gated on.
  Writable(auth: AuthContext)
  /// The read half alone, and the primary's URL to send the rest to.
  ///
  /// `primary_url` is not decoration: a node that refuses a write without
  /// naming where the write is taken is a dead end, and a replica cannot
  /// derive it — the database records the fleet's zone, not which of its
  /// nodes holds the pen.
  ReadOnly(reads: Reads, primary_url: String)
}

/// The read half's context, whichever surface is mounted.
fn readable(api: Api) -> Reads {
  case api {
    Writable(auth) -> auth.reads
    ReadOnly(reads, _) -> reads
  }
}

pub fn handle(req: Request, ctx: Context) -> Response {
  case wisp.path_segments(req) {
    ["dns-query"] ->
      case ctx.zone {
        ServingZone(serving) -> doh.handle(req, serving)
        ExternalZone(_) -> wisp.not_found()
      }
    ["healthz"] ->
      case ctx.zone {
        ServingZone(serving) -> healthz(serving)
        ExternalZone(pool) -> healthz_external(pool)
      }
    // Role-agnostic like the two above, and for the same reason: public text
    // about the `synch` client, needing no session, no database and no zone.
    // Whichever node of a deployment you reach, this URL answers.
    ["SKILL.md"] -> skill.serve(req)
    ["api", "zone", "anchor"] ->
      case ctx.anchor {
        "" -> wisp.not_found()
        _ -> anchor(ctx)
      }
    // Anonymous by necessity: the login screen asks it before a session
    // exists, to draw only the methods this deployment has configured. It
    // sits outside both route tables because it is the one answer that
    // differs between the surfaces rather than being shared or absent — a
    // read-only node offers no method and names the node that does.
    ["api", "auth", "methods"] ->
      case ctx.api, req.method {
        Writable(auth), Get -> auth_api.methods(Some(auth), "")
        ReadOnly(_, primary_url), Get -> auth_api.methods(None, primary_url)
        _, _ -> wisp.not_found()
      }
    // `/dp/v1` joins the same two tables rather than getting a mount of its
    // own: it has the same reads-on-a-replica, writes-on-the-primary property
    // as everything else, and a second dispatch would be a second place for
    // that property to be got wrong. A write reaching a replica therefore gets
    // `elsewhere`'s 409 naming the primary, which is the answer a reconciler
    // behind a load balancer can act on.
    ["auth", ..] | ["api", ..] | ["dp", ..] ->
      // Reads first, whichever surface this is: the two mount the same
      // handlers over the same tables, so a route that appears in both is
      // written once and cannot drift between them.
      case read_routes(req, readable(ctx.api), ctx.browse) {
        Some(response) -> response
        None ->
          case ctx.api {
            Writable(auth) -> write_routes(req, auth, ctx.browse)
            ReadOnly(_, primary_url) -> elsewhere(req, primary_url)
          }
      }
    // The dashboard ships with the API, on either surface: a node that
    // answers the reads serves the pages that make them.
    _ -> static.serve(req, wisp.not_found)
  }
}

/// What a read-only node answers for a route it does not mount.
///
/// Three answers, and the difference between them is what the caller can do
/// about it:
///
/// * **`/auth/...` under `GET` is a redirect.** These are the sign-in flows,
///   and every one of them is a browser navigation rather than a `fetch` — so
///   the browser follows the redirect to the primary, signs in there, and
///   gets a cookie set on the host that can set one. A 404 for a stale
///   bookmark or a second tab would be a dead end for no reason.
/// * **Any other non-GET is a 409 naming the primary.** The request is
///   well-formed and this node simply is not where it is taken. The SPA turns
///   the `primary` field into a link rather than a stack trace. Not a
///   redirect: these are `fetch` calls with `credentials: 'same-origin'`, so
///   a cross-origin redirect arrives without the cookie and is refused by
///   CORS besides — the SPA has to decide, and this is what it decides on.
/// * **Anything else is the 404 it would be anywhere**: a path that exists on
///   no node, and there is nowhere to send a typo.
///
/// The `GET`/non-`GET` test is deliberately not a second copy of the
/// primary's route table — a table listing every write here would be a table
/// to forget to update. The property that actually holds is that every route
/// a read-only node mounts is a `GET`, so a non-GET under `/api` or `/auth`
/// is by construction a route it does not have.
fn elsewhere(req: Request, primary_url: String) -> Response {
  case req.method, wisp.path_segments(req) {
    Get, ["auth", ..] -> wisp.redirect(primary_url <> auth_path(req))
    Get, _ -> wisp.not_found()
    _, _ ->
      json.object([
        #(
          "error",
          json.object([
            #("code", json.string("read-only-replica")),
            #(
              "message",
              json.string(
                "this control-plane node serves a read-only copy of the "
                <> "database; changes are made at "
                <> primary_url,
              ),
            ),
            #("primary", json.string(primary_url)),
          ]),
        ),
      ])
      |> json.to_string
      |> wisp.json_response(409)
  }
}

/// The path and query to hand the primary, rebuilt from the parsed segments
/// rather than echoed from the request line.
///
/// The value lands in a `Location` header prefixed with an operator-supplied
/// origin, so what it must not do is change which origin that is.
/// `path_segments` has already decoded, split and dropped the empty segments,
/// which is what makes the rebuilt path start with exactly one `/` — an
/// echoed `//evil.example` would still be a path under the primary's
/// authority rather than a new one, but a normalized path is the version that
/// does not need the argument.
fn auth_path(req: Request) -> String {
  let path = "/" <> string.join(wisp.path_segments(req), "/")
  case req.query {
    Some(query) -> path <> "?" <> query
    None -> path
  }
}

/// The routes a node with a read-only copy of the database can answer, and
/// therefore the routes *both* surfaces answer: they are mounted once, here,
/// so a primary and a replica cannot come to disagree about what a GET
/// returns.
///
/// `None` means "not one of mine", which is a different fact from a 404 —
/// the caller decides whether the request falls through to the write table
/// or to a refusal.
fn read_routes(req: Request, reads: Reads, browse: Browse) -> Option(Response) {
  case wisp.path_segments(req), req.method {
    ["api", "me"], Get ->
      Some({
        use who <- with_principal(req, reads)
        auth_api.me(reads, who)
      })
    // Anonymous by the same reasoning as /api/auth/methods: the invite page
    // asks it before a session exists, and the token in the query string is
    // the credential the invitation email already carried.
    ["api", "invites", "preview"], Get ->
      Some(orgs_api.preview_invite(req, reads))

    ["api", "orgs", slug], Get ->
      Some({
        use who <- with_principal(req, reads)
        orgs_api.get_org(reads, who, slug)
      })
    ["api", "orgs", slug, "members"], Get ->
      Some({
        use who <- with_principal(req, reads)
        orgs_api.list_members(reads, who, slug)
      })
    ["api", "orgs", slug, "audit"], Get ->
      Some({
        use who <- with_principal(req, reads)
        orgs_api.audit_log(req, reads, who, slug)
      })
    ["api", "orgs", slug, "oidc"], Get ->
      Some({
        use who <- with_principal(req, reads)
        orgs_api.get_oidc(reads, who, slug)
      })
    // The listing is a read like any other, so a replica answers it. The
    // three mutations are not, and land in the write table below.
    ["api", "orgs", slug, "api-keys"], Get ->
      Some({
        use who <- with_principal(req, reads)
        api_keys_api.list_keys(reads, who, slug)
      })

    ["api", "orgs", slug, "networks"], Get ->
      Some({
        use who <- with_principal(req, reads)
        networks_api.list_networks(reads, who, slug)
      })
    ["api", "orgs", slug, "networks", net], Get ->
      Some({
        use who <- with_principal(req, reads)
        networks_api.network_detail(reads, who, slug, net)
      })

    // The browse surface is a read surface end to end: the tunnel encodes no
    // write opcode, and every route below resolves its org on a pooled
    // connection and then asks a daemon on the operator's own network. A
    // replica with daemons attached answers all of it.
    ["api", "orgs", slug, "networks", net, "browse"], Get ->
      Some({
        use who <- with_principal(req, reads)
        browse_api.status(reads, browse, who, slug, net)
      })
    ["api", "orgs", slug, "networks", net, "delegations"], Get ->
      Some({
        use who <- with_principal(req, reads)
        browse_api.delegations(reads, browse, who, slug, net)
      })
    ["api", "orgs", slug, "networks", net, "replication"], Get ->
      Some({
        use who <- with_principal(req, reads)
        browse_api.replication(reads, browse, who, slug, net)
      })
    ["api", "orgs", slug, "networks", net, "browse", "ls"], Get ->
      Some({
        use who <- with_principal(req, reads)
        browse_api.ls(req, reads, browse, who, slug, net)
      })
    ["api", "orgs", slug, "networks", net, "browse", "stat"], Get ->
      Some({
        use who <- with_principal(req, reads)
        browse_api.stat(req, reads, browse, who, slug, net)
      })

    ["api", "orgs", slug, "devices"], Get ->
      Some({
        use who <- with_principal(req, reads)
        devices_api.list_devices(reads, who, slug)
      })

    // The data plane's desired-state document. A read like any other, so a
    // replica answers it — which is what lets the fleet's every-60s poll be
    // load-balanced away from the node that takes the writes.
    ["dp", "v1", "networks"], Get ->
      Some({
        use who <- with_principal(req, reads)
        dataplane_api.desired_state(req, reads, who)
      })

    _, _ -> None
  }
}

/// The routes that mutate, and the sign-in flows that mint the sessions the
/// rest are gated on. Mounted on the primary alone, because a replica's
/// database is opened read-only and every one of these would fail at the
/// sqlite layer with a message about a file rather than about a topology.
fn write_routes(req: Request, auth: AuthContext, browse: Browse) -> Response {
  case wisp.path_segments(req), req.method {
    ["auth", "oidc", org_slug], Get -> auth_api.oidc_start(req, auth, org_slug)
    ["auth", "callback", "oidc"], Get -> auth_api.oidc_callback(req, auth)
    ["auth", "start", provider], Get -> auth_api.start(req, auth, provider)
    ["auth", "callback", provider], Get ->
      auth_api.callback(req, auth, provider)
    ["auth", "magic"], Post -> auth_api.magic_request(req, auth)
    ["auth", "magic", "redeem"], Get -> auth_api.magic_redeem(req, auth)
    ["api", "logout"], Post -> auth_api.logout(req, auth)
    ["api", "orgs"], Post -> {
      use who <- with_principal(req, auth.reads)
      orgs_api.create_org(req, auth, who)
    }
    ["api", "orgs", slug], Delete -> {
      use who <- with_principal(req, auth.reads)
      orgs_api.delete_org(req, auth, who, slug)
    }
    ["api", "orgs", slug, "members", user], Patch -> {
      use who <- with_principal(req, auth.reads)
      orgs_api.change_role(req, auth, who, slug, user)
    }
    ["api", "orgs", slug, "members", user], Delete -> {
      use who <- with_principal(req, auth.reads)
      orgs_api.remove_member(auth, who, slug, user)
    }
    ["api", "orgs", slug, "transfer"], Post -> {
      use who <- with_principal(req, auth.reads)
      orgs_api.transfer_ownership(req, auth, who, slug)
    }
    ["api", "orgs", slug, "invites"], Post -> {
      use who <- with_principal(req, auth.reads)
      orgs_api.create_invite(req, auth, who, slug)
    }
    ["api", "invites", "accept"], Post -> {
      use who <- with_principal(req, auth.reads)
      orgs_api.accept_invite(req, auth, who)
    }
    ["api", "orgs", slug, "oidc"], Put -> {
      use who <- with_principal(req, auth.reads)
      orgs_api.put_oidc(req, auth, who, slug)
    }
    ["api", "orgs", slug, "oidc"], Delete -> {
      use who <- with_principal(req, auth.reads)
      orgs_api.delete_oidc(auth, who, slug)
    }

    ["api", "orgs", slug, "api-keys"], Post -> {
      use who <- with_principal(req, auth.reads)
      api_keys_api.create_key(req, auth, who, slug)
    }
    ["api", "orgs", slug, "api-keys", key], Patch -> {
      use who <- with_principal(req, auth.reads)
      api_keys_api.update_key(req, auth, who, slug, key)
    }
    ["api", "orgs", slug, "api-keys", key], Delete -> {
      use who <- with_principal(req, auth.reads)
      api_keys_api.delete_key(auth, who, slug, key)
    }

    ["api", "orgs", slug, "networks"], Post -> {
      use who <- with_principal(req, auth.reads)
      networks_api.create_network(req, auth, who, slug)
    }
    ["api", "orgs", slug, "networks", net], Delete -> {
      use who <- with_principal(req, auth.reads)
      networks_api.delete_network(req, auth, who, slug, net)
    }
    // A node joins a network: one call, and the only one a join key can
    // make. Everyone else reaches it too, at the Member floor the two
    // older routes below carry.
    ["api", "orgs", slug, "networks", net, "devices"], Post -> {
      use who <- with_principal(req, auth.reads)
      networks_api.join_device(req, auth, who, slug, net)
    }
    ["api", "orgs", slug, "networks", net, "devices", dev], Put -> {
      use who <- with_principal(req, auth.reads)
      networks_api.assign_device(auth, who, slug, net, dev)
    }
    ["api", "orgs", slug, "networks", net, "devices", dev], Delete -> {
      use who <- with_principal(req, auth.reads)
      networks_api.unassign_device(auth, who, slug, net, dev)
    }

    ["api", "orgs", slug, "networks", net, "browse", "enabled"], Put -> {
      use who <- with_principal(req, auth.reads)
      browse_api.set_enabled(req, auth, browse, who, slug, net)
    }
    // The hosting switch, beside the browse switch it is modelled on. The two
    // are independent and independently fail-closed: hosting replicates,
    // browsing observes, and neither implies the other.
    ["api", "orgs", slug, "networks", net, "cloud-hosting", "enabled"], Put -> {
      use who <- with_principal(req, auth.reads)
      networks_api.set_cloud_hosting(req, auth, who, slug, net)
    }

    ["api", "orgs", slug, "devices"], Post -> {
      use who <- with_principal(req, auth.reads)
      devices_api.create_device(req, auth, who, slug)
    }
    ["api", "orgs", slug, "devices", dev], Patch -> {
      use who <- with_principal(req, auth.reads)
      devices_api.patch_device(req, auth, who, slug, dev)
    }
    ["api", "orgs", slug, "devices", dev], Delete -> {
      use who <- with_principal(req, auth.reads)
      devices_api.delete_device(auth, who, slug, dev)
    }
    ["api", "orgs", slug, "devices", dev, "keys"], Post -> {
      use who <- with_principal(req, auth.reads)
      devices_api.add_key(req, auth, who, slug, dev)
    }
    ["api", "orgs", slug, "devices", dev, "keys", key, "retire"], Post -> {
      use who <- with_principal(req, auth.reads)
      devices_api.retire_key(auth, who, slug, dev, key)
    }
    ["api", "orgs", slug, "devices", dev, "keys", key, "revoke"], Post -> {
      use who <- with_principal(req, auth.reads)
      devices_api.revoke_key(auth, browse, who, slug, dev, key)
    }

    // The data plane's four writes. They are here rather than in a table of
    // their own because they are writes, and everything true of a write on
    // this service is true of them: the primary takes them, they publish the
    // zone where they shape it, and a replica answers `elsewhere`'s 409.
    ["dp", "v1", "networks", org, net, "device"], Put -> {
      use who <- with_principal(req, auth.reads)
      dataplane_api.register_device(req, auth, who, org, net)
    }
    ["dp", "v1", "networks", org, net, "device", "keys", nk], Delete -> {
      use who <- with_principal(req, auth.reads)
      dataplane_api.retire_key(req, auth, who, org, net, nk)
    }
    ["dp", "v1", "networks", org, net, "status"], Post -> {
      use who <- with_principal(req, auth.reads)
      dataplane_api.post_status(req, auth, who, org, net)
    }
    // Reporting a collection, not asking for one: the fleet has already
    // deleted the tenant's prefixes when it calls this, and what it is
    // writing here is the record that it did.
    ["dp", "v1", "networks", org, net, "storage"], Delete -> {
      use who <- with_principal(req, auth.reads)
      dataplane_api.collect_storage(auth, who, org, net)
    }

    _, _ -> wisp.not_found()
  }
}

/// Resolves the request's credential — session cookie or API key — on a
/// connection borrowed only for that lookup, and gives it back before the
/// handler runs; the handler checks out its own.
///
/// The connection must not still be held here: every handler below opens one
/// of its own, so holding this one across `next` would put two of a pool of
/// four in one request's hands. At four concurrent authenticated requests
/// the pool is then empty with every borrower queued for a second
/// connection, and none of them can release the first until they get it —
/// a deadlock broken only by `pool.acquire`'s 10s call timeout killing all
/// four callers. The bound is the pool size, so no pool is large enough to
/// avoid it.
fn with_principal(
  req: Request,
  reads: Reads,
  next: fn(Principal) -> Response,
) -> Response {
  // pool.with_connection rather than auth_api.with_db: the latter is
  // Response-typed, and this needs the principal out of the closure so the
  // connection can be released before `next` runs.
  case pool.with_connection(reads.pool, middleware.check_principal(req, _)) {
    Ok(Ok(who)) -> next(who)
    Ok(Error(refusal)) -> refusal
    Error(_) -> middleware.error_json(500, "internal", "database unavailable")
  }
}

/// Serve-mode health.
///
/// **The signature expiry is compared to the clock, not merely reported.** A
/// primary whose `resign` job has been failing serves a zone whose RRSIGs have
/// run out: every validating resolver reads it as `Bogus` and every client
/// fails closed, while this endpoint answered 200 `"status":"ok"` with
/// `sig_expires_at` in the past. The HTTP status is the only thing an
/// orchestrator, a load balancer or the image's own HEALTHCHECK reads, so a
/// field nobody reads is not a signal. A day of headroom, which is far more
/// than the resign cadence needs and far less than the signature lifetime.
/// How much life a zone's signatures must have left for serve mode to call
/// itself healthy. Far more than the resign cadence needs, far less than a
/// signature's lifetime — so it fires on a resign job that has stopped, and
/// never on one that is merely between runs.
pub const zone_health_headroom = 86_400

/// Whether a zone with signatures expiring at `expires` is servable at `now`.
pub fn zone_is_servable(expires: Int, now: Int) -> Bool {
  expires > now + zone_health_headroom
}

fn healthz(serving: Serving) -> Response {
  let now = middleware.now_unix()
  let looked =
    pool.with_connection(serving.pool, fn(conn) { model.health(conn) })
  case looked {
    Ok(Ok(#(serial, expires))) if expires > now + zone_health_headroom ->
      json.object([
        #("status", json.string("ok")),
        #("soa_serial", json.int(serial)),
        #("sig_expires_at", json.int(expires)),
      ])
      |> json.to_string
      |> wisp.json_response(200)
    Ok(Ok(#(serial, expires))) ->
      json.object([
        #("status", json.string("zone signatures are expiring or expired")),
        #("soa_serial", json.int(serial)),
        #("sig_expires_at", json.int(expires)),
      ])
      |> json.to_string
      |> wisp.json_response(503)
    _ ->
      json.object([#("status", json.string("no zone available"))])
      |> json.to_string
      |> wisp.json_response(503)
  }
}

/// External-mode health: the reconciler's view, with no provider
/// round-trip. Staleness is reported, never fatal — the provider keeps
/// serving whatever was last applied, the same stance `healthz` takes on
/// absent TUF material in serve mode.
fn healthz_external(zone_pool: pool.Pool) -> Response {
  let now = middleware.now_unix()
  let looked =
    pool.with_connection(zone_pool, fn(conn) {
      #(
        model.read_meta(conn),
        provider_state.get(conn),
        provider_state.observed_keys(conn),
        provider_state.oldest_unlogged_age(conn, now),
      )
    })
  case looked {
    Ok(#(Ok(meta), Ok(state), Ok(keys), unlogged_age)) -> {
      let synced = case state {
        Ok(s) ->
          s.last_synced_serial == option.Some(meta.soa_serial)
          && s.last_error == option.None
          && s.last_failures == option.None
        Error(Nil) -> False
      }
      let logged = list.filter(keys, fn(key) { key.logged_at != option.None })
      let provider_fields = case state {
        Ok(s) -> [
          #("provider", json.string(s.provider)),
          #("provider_zone_id", json.string(s.provider_zone_id)),
          #(
            "provider_last_synced_serial",
            json.nullable(s.last_synced_serial, json.int),
          ),
          #("provider_last_ok_at", json.nullable(s.last_ok_at, json.int)),
          #("provider_last_error", json.nullable(s.last_error, json.string)),
          #("provider_last_error_at", json.nullable(s.last_error_at, json.int)),
          #(
            "provider_last_failures",
            json.nullable(s.last_failures, json.string),
          ),
          #(
            "provider_last_partial_at",
            json.nullable(s.last_partial_at, json.int),
          ),
        ]
        Error(Nil) -> [#("provider", json.string("never synced"))]
      }
      json.object([
        #("status", json.string("ok")),
        #("mode", json.string("external")),
        #("soa_serial", json.int(meta.soa_serial)),
        #("provider_in_sync", json.bool(synced)),
        #("keys_observed", json.int(list.length(keys))),
        #("keys_logged", json.int(list.length(logged))),
        // How long the watch loop has been behind the wire, which is the
        // one number that says whether the next answer may fail closed.
        #(
          "oldest_unlogged_age",
          json.nullable(
            option.from_result(unlogged_age) |> option.flatten,
            json.int,
          ),
        ),
        ..provider_fields
      ])
      |> json.to_string
      |> wisp.json_response(200)
    }
    _ ->
      json.object([#("status", json.string("no zone available"))])
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
