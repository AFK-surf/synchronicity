import api/auth_api
import api/router
import auth/session
import dns/name as dns_name
import dns/serve
import dns/wire
import email/mailer
import exception
import fixtures.{nk, now_unix, tmp_db}
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import store/db
import store/migrate
import store/sqlite
import util/id
import wisp
import wisp/simulate
import zone/model
import zone/publish

type Harness {
  Harness(ctx: router.Context, db_path: String, token: String, csrf: String)
}

/// Fresh database with zone bootstrap and one signed-in user.
fn harness() -> Harness {
  harness_sized(2)
}

/// `harness` with the primary pool's size named, so a test can pin how many
/// connections one request is allowed to need.
fn harness_sized(pool_size: Int) -> Harness {
  let db_path = tmp_db()
  let assert Ok(conn) = db.open_primary(db_path)
  let assert Ok(_) = migrate.migrate(conn)
  let csk = fixtures.zone_boot(conn)
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO users VALUES ('u-admin', 'admin@example.com', 'Admin', 0)",
      [],
    )
  let assert Ok(#(token, live)) = session.create(conn, "u-admin", now_unix())
  let assert Ok(_) = publish.publish(conn, csk, now_unix(), "test:boot")
  sqlite.close(conn)
  let assert Ok(api_pool) = db.start_primary_pool(db_path, pool_size)
  let assert Ok(dns_pool) = db.start_read_pool(db_path, 2)
  let assert Ok(apex) = dns_name.parse("sync.test.")
  let auth =
    auth_api.AuthContext(
      api_pool,
      "http://cp.test",
      mailer.LogOnly,
      None,
      None,
      fn(conn, now, actor) { publish.publish_in_tx(conn, csk, now, actor) },
      fn() { Nil },
    )
  Harness(
    router.Context(
      "anchor",
      "ds",
      Some(auth),
      router.ServingZone(serve.Serving(dns_pool, apex)),
    ),
    db_path,
    token,
    live.csrf,
  )
}

fn authed(h: Harness, method: http.Method, path: String) -> wisp.Request {
  simulate.request(method, path)
  |> simulate.cookie(session.cookie_name, h.token, wisp.Signed)
  |> simulate.header("x-csrf", h.csrf)
}

fn call(h: Harness, req: wisp.Request) -> wisp.Response {
  router.handle(req, h.ctx)
}

fn call_json(
  h: Harness,
  method: http.Method,
  path: String,
  body: json.Json,
) -> wisp.Response {
  call(h, authed(h, method, path) |> simulate.json_body(body))
}

fn read_db(h: Harness) -> sqlite.Connection {
  let assert Ok(conn) = db.open_read(h.db_path)
  conn
}

/// The z32 keys currently published for a network, straight from the model.
fn published_nks(h: Harness) -> List(String) {
  let conn = read_db(h)
  let assert Ok(input) = model.read(conn)
  sqlite.close(conn)
  input.txt_names
  |> list.flat_map(fn(t) { t.members })
  |> list.map(fn(m) { m.nk_z32 })
}

pub fn unauthenticated_api_test() {
  let h = harness()
  let resp = call(h, simulate.request(Get, "/api/orgs/acme"))
  assert resp.status == 401
}

pub fn csrf_required_test() {
  let h = harness()
  let req =
    simulate.request(Post, "/api/orgs")
    |> simulate.cookie(session.cookie_name, h.token, wisp.Signed)
    |> simulate.json_body(
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    )
  assert call(h, req).status == 403
}

pub fn org_and_network_flow_test() {
  let h = harness()
  // Create org.
  let resp =
    call_json(
      h,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    )
  assert resp.status == 200
  // Bad slug refused.
  let bad =
    call_json(
      h,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("-bad-")),
        #("name", json.string("Bad")),
      ]),
    )
  assert bad.status == 400
  // Create network (creator is owner).
  let net =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    )
  assert net.status == 200
  assert string.contains(simulate.read_body(net), "soa_serial")
  // Detail exists.
  let detail = call(h, authed(h, Get, "/api/orgs/acme/networks/prod"))
  assert detail.status == 200
  assert string.contains(simulate.read_body(detail), "prod.acme.sync.test")
  // A non-member sees a 404, not the org.
  let conn = {
    let assert Ok(conn) = db.open_primary(h.db_path)
    conn
  }
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO users VALUES ('u-outsider', 'out@example.com', NULL, 0)",
      [],
    )
  let assert Ok(#(out_token, out_live)) =
    session.create(conn, "u-outsider", now_unix())
  sqlite.close(conn)
  let outsider_req =
    simulate.request(Get, "/api/orgs/acme")
    |> simulate.cookie(session.cookie_name, out_token, wisp.Signed)
    |> simulate.header("x-csrf", out_live.csrf)
  assert call(h, outsider_req).status == 404
}

pub fn device_lifecycle_and_invariants_test() {
  let h = harness()
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    ).status
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status

  // Bad nk refused.
  let bad_nk =
    call_json(
      h,
      Post,
      "/api/orgs/acme/devices",
      json.object([
        #("label", json.string("nas")),
        #("nk", json.string("not-a-key")),
      ]),
    )
  assert bad_nk.status == 400

  // Create + assign nas.
  let nas_nk = nk()
  let created =
    call_json(
      h,
      Post,
      "/api/orgs/acme/devices",
      json.object([
        #("label", json.string("nas")),
        #("nk", json.string(nas_nk)),
      ]),
    )
  assert created.status == 200
  let assert Ok(#(_, tail)) =
    string.split_once(simulate.read_body(created), "device_id\":\"")
  let assert [nas_id, ..] = string.split(tail, "\"")
  let assert 200 =
    call(h, authed(h, Put, "/api/orgs/acme/networks/prod/devices/" <> nas_id)).status
  assert published_nks(h) == [nas_nk]

  // The same nk on a second device: §3.2 ambiguity, 409.
  let dup =
    call_json(
      h,
      Post,
      "/api/orgs/acme/devices",
      json.object([
        #("label", json.string("other")),
        #("nk", json.string(nas_nk)),
      ]),
    )
  assert dup.status == 409
  assert string.contains(simulate.read_body(dup), "ambiguity")

  // A second device with the same label in the same network: 409.
  let clash_nk = nk()
  let clash_created =
    call_json(
      h,
      Post,
      "/api/orgs/acme/devices",
      json.object([
        #("label", json.string("nas")),
        #("nk", json.string(clash_nk)),
      ]),
    )
  assert clash_created.status == 200
  let assert Ok(#(_, tail2)) =
    string.split_once(simulate.read_body(clash_created), "device_id\":\"")
  let assert [clash_id, ..] = string.split(tail2, "\"")
  let clash =
    call(h, authed(h, Put, "/api/orgs/acme/networks/prod/devices/" <> clash_id))
  assert clash.status == 409

  // Rotation: add a second key — both published, same label.
  let new_nk = nk()
  let rotate =
    call_json(
      h,
      Post,
      "/api/orgs/acme/devices/" <> nas_id <> "/keys",
      json.object([#("nk", json.string(new_nk))]),
    )
  assert rotate.status == 200
  let published = published_nks(h)
  assert list.contains(published, nas_nk)
  assert list.contains(published, new_nk)

  // A second rotation while one is open: 409.
  let again =
    call_json(
      h,
      Post,
      "/api/orgs/acme/devices/" <> nas_id <> "/keys",
      json.object([#("nk", json.string(nk()))]),
    )
  assert again.status == 409

  // Retire the old (retiring) key: it leaves the RRset.
  let conn = read_db(h)
  let assert Ok([[sqlite.Text(old_key_id)]]) =
    sqlite.query(
      conn,
      "SELECT id FROM device_keys WHERE state = 'retiring'",
      [],
    )
  sqlite.close(conn)
  let retire =
    call(
      h,
      authed(
        h,
        Post,
        "/api/orgs/acme/devices/"
          <> nas_id
          <> "/keys/"
          <> old_key_id
          <> "/retire",
      ),
    )
  assert retire.status == 200
  assert published_nks(h) == [new_nk]

  // Revoke the active key (admin): device disappears from the zone.
  let conn2 = read_db(h)
  let assert Ok([[sqlite.Text(active_id)]]) =
    sqlite.query(
      conn2,
      "SELECT id FROM device_keys WHERE state = 'active' AND device_id = ?",
      [sqlite.Text(nas_id)],
    )
  sqlite.close(conn2)
  let revoke =
    call(
      h,
      authed(
        h,
        Post,
        "/api/orgs/acme/devices/"
          <> nas_id
          <> "/keys/"
          <> active_id
          <> "/revoke",
      ),
    )
  assert revoke.status == 200
  assert published_nks(h) == []
}

pub fn last_owner_protected_test() {
  let h = harness()
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    ).status
  let demote =
    call_json(
      h,
      Patch,
      "/api/orgs/acme/members/u-admin",
      json.object([#("role", json.string("member"))]),
    )
  assert demote.status == 409
  let remove = call(h, authed(h, Delete, "/api/orgs/acme/members/u-admin"))
  assert remove.status == 409
}

pub fn member_role_cannot_admin_test() {
  let h = harness()
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    ).status
  // Add a plain member directly.
  let conn = {
    let assert Ok(conn) = db.open_primary(h.db_path)
    conn
  }
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO users VALUES ('u-member', 'm@example.com', NULL, 0)",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO org_members VALUES
       ((SELECT id FROM orgs WHERE slug = 'acme'), 'u-member', 'member', 0)",
      [],
    )
  let assert Ok(#(member_token, member_live)) =
    session.create(conn, "u-member", now_unix())
  sqlite.close(conn)
  let as_member = fn(method, path, body) {
    simulate.request(method, path)
    |> simulate.cookie(session.cookie_name, member_token, wisp.Signed)
    |> simulate.header("x-csrf", member_live.csrf)
    |> simulate.json_body(body)
  }
  // member cannot create networks (admin required)...
  let net =
    call(
      h,
      as_member(
        Post,
        "/api/orgs/acme/networks",
        json.object([#("name", json.string("prod"))]),
      ),
    )
  assert net.status == 403
  // ...but can add devices.
  let dev =
    call(
      h,
      as_member(
        Post,
        "/api/orgs/acme/devices",
        json.object([
          #("label", json.string("laptop")),
          #("nk", json.string(nk())),
        ]),
      ),
    )
  assert dev.status == 200
}

pub fn invite_accept_test() {
  let h = harness()
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    ).status
  // Issue the invite (mail goes to the log), then accept with a token we
  // planted directly.
  let conn = {
    let assert Ok(conn) = db.open_primary(h.db_path)
    conn
  }
  let token = "test-invite-token"
  let token_hash = id.hash_token(token)
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO invites VALUES ('inv1',
        (SELECT id FROM orgs WHERE slug = 'acme'),
        'newbie@example.com', 'member', ?, 'u-admin', ?, ?, NULL)",
      [
        sqlite.Blob(token_hash),
        sqlite.Int(now_unix()),
        sqlite.Int(now_unix() + 3600),
      ],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO users VALUES ('u-newbie', 'newbie@example.com', NULL, 0)",
      [],
    )
  let assert Ok(#(new_token, new_live)) =
    session.create(conn, "u-newbie", now_unix())
  sqlite.close(conn)
  let accept =
    simulate.request(Post, "/api/invites/accept")
    |> simulate.cookie(session.cookie_name, new_token, wisp.Signed)
    |> simulate.header("x-csrf", new_live.csrf)
    |> simulate.json_body(json.object([#("token", json.string(token))]))
  let resp = call(h, accept)
  assert resp.status == 200
  assert string.contains(simulate.read_body(resp), "acme")
  // Membership exists now.
  let conn2 = read_db(h)
  let assert Ok([[sqlite.Text("member")]]) =
    sqlite.query(
      conn2,
      "SELECT role FROM org_members WHERE user_id = 'u-newbie'",
      [],
    )
  sqlite.close(conn2)
}

pub fn mutation_visible_to_dns_immediately_test() {
  // Guards the core visibility promise: a committed mutation is what the
  // DNS serving path answers with — there is no cache to go stale.
  let h = harness()
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("snaporg")),
        #("name", json.string("Snap")),
      ]),
    ).status
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/snaporg/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  let created =
    call_json(
      h,
      Post,
      "/api/orgs/snaporg/devices",
      json.object([#("label", json.string("nas")), #("nk", json.string(nk()))]),
    )
  assert created.status == 200
  let assert Ok(#(_, rest)) =
    string.split_once(simulate.read_body(created), "device_id\":\"")
  let assert Ok(#(device_id, _)) = string.split_once(rest, "\"")
  let assert 200 =
    call(
      h,
      authed(h, Put, "/api/orgs/snaporg/networks/prod/devices/" <> device_id),
    ).status
  // The DNS path reads the same database the mutation committed to: the
  // device's membership record resolves on the very next query, through
  // the same pooled serving path the real servers use.
  let assert router.Context(_, _, _, router.ServingZone(serving)) = h.ctx
  let assert Ok(qname) =
    dns_name.parse("_synchronicity.prod.snaporg.sync.test.")
  let question = <<
    9:int-size(16),
    0:int-size(16),
    1:int-size(16),
    0:int-size(48),
    dns_name.encode(qname):bits,
    16:int-size(16),
    1:int-size(16),
  >>
  let assert Ok(response) = serve.handle_packet(serving, question, serve.Stream)
  let assert Ok(msg) = wire.decode_message(response)
  // NOERROR with exactly the freshly published TXT record.
  assert msg.flags % 16 == 0
  let assert [rr] = msg.answers
  assert rr.rtype == wire.type_txt
}

pub fn one_request_needs_one_connection_test() {
  // A pool of exactly one, and an authenticated request that must complete on
  // it. Resolving the session on a connection held across the handler would
  // make every such request need two: with a pool of `size`, `size`
  // concurrent requests would each hold one and queue for a second, and none
  // could release the first until it arrived. This asserts the request needs
  // one connection, which is what makes that unreachable at any pool size.
  // Not /api/me, which resolves its session on the connection it goes on to
  // use: this must be a route reached through the router's session wrapper,
  // where the handler opens its own.
  let h = harness_sized(1)
  let resp =
    call_json(
      h,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    )
  assert resp.status == 200
}

pub fn with_db_discards_conn_on_panic_test() {
  // A panic inside a request handler must not leak the connection: wisp
  // rescues crashes, so the process survives — only with_db's deferred
  // close stands between a panicking handler and a csqlite process
  // holding the write lock for the life of the HTTP connection.
  let h = harness()
  let assert router.Context(_, _, Some(auth), _) = h.ctx
  let _ =
    exception.rescue(fn() {
      auth_api.with_db(auth, fn(conn) {
        let assert Ok(_) = sqlite.exec(conn, "BEGIN IMMEDIATE", [])
        panic as "handler crashed mid-transaction"
      })
    })
  // The write lock must be free immediately; a leaked connection would
  // make this block for busy_timeout and fail with SQLITE_BUSY.
  let assert Ok(conn) = db.open_primary(h.db_path)
  let assert Ok(_) = sqlite.exec(conn, "BEGIN IMMEDIATE", [])
  let assert Ok(_) = sqlite.exec(conn, "ROLLBACK", [])
  sqlite.close(conn)
}
