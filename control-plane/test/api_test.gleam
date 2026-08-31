import api/agent
import api/auth_api
import api/browse_api
import api/reads
import api/router
import api/skill
import auth/dataplane_key
import auth/google
import auth/session
import dns/name as dns_name
import dns/serve
import dns/wire
import email/mailer
import exception
import fixtures.{nk, now_unix, tmp_db}
import gleam/erlang/process
import gleam/http.{Delete, Get, Patch, Post, Put}
import gleam/int
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
      reads.Reads(api_pool),
      "http://cp.test",
      mailer.LogOnly,
      None,
      None,
      fn(conn, now, actor, change) {
        publish.publish_in_tx(conn, csk, now, actor, change)
      },
      fn() { Nil },
      None,
    )
  let agents = process.new_name("cp_agents_test_" <> id.new())
  let assert Ok(_) = agent.start(agents)
  Harness(
    router.Context(
      "anchor",
      "ds",
      router.Writable(auth),
      router.ServingZone(serve.Serving(dns_pool, apex)),
      browse_api.Browse(agents, "https://cp.test/agent/v1/attach"),
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

/// The same harness with different sign-in configuration, which is all
/// `/api/auth/methods` reports on.
fn with_auth(
  h: Harness,
  change: fn(auth_api.AuthContext) -> auth_api.AuthContext,
) -> Harness {
  let assert router.Writable(auth) = h.ctx.api
  Harness(..h, ctx: router.Context(..h.ctx, api: router.Writable(change(auth))))
}

pub fn auth_methods_lists_only_configured_test() {
  let h = harness()
  let read = fn(h) {
    simulate.read_body(call(h, simulate.request(Get, "/api/auth/methods")))
  }
  // Nothing configured: no OAuth client, no org SSO, log-only mail — and
  // magic links offered regardless, because they are the only way in.
  let bare = read(h)
  assert string.contains(bare, "\"google\":false")
  assert string.contains(bare, "\"github\":false")
  assert string.contains(bare, "\"oidc\":false")
  assert string.contains(bare, "\"magic_link\":true")
  // With a provider that works, log-only mail stops being offered: it
  // would take the address and send nothing.
  let with_google =
    with_auth(h, fn(auth) {
      auth_api.AuthContext(..auth, google: Some(google.provider("gid", "gsec")))
    })
  let oauth_only = read(with_google)
  assert string.contains(oauth_only, "\"google\":true")
  assert string.contains(oauth_only, "\"github\":false")
  assert string.contains(oauth_only, "\"magic_link\":false")
  // Configured mail is offered beside it.
  let mailing =
    with_auth(with_google, fn(auth) {
      auth_api.AuthContext(
        ..auth,
        mail: mailer.Smtp("smtp.test", 587, "u", "p", "cp@test"),
      )
    })
  let both = read(mailing)
  assert string.contains(both, "\"google\":true")
  assert string.contains(both, "\"magic_link\":true")
}

/// The org's switch is off until an admin flips it, flipping it is audited,
/// and a network nobody has attached to answers honestly rather than emptily.
///
/// The deployment always offers the surface — the apex names this node and
/// daemons dial it — so this switch is the whole of the gate, and it is the
/// org's to hold.
pub fn the_org_switch_gates_browsing_test() {
  let h = harness()
  let browsing = h
  let assert Ok(_) =
    call_json(
      browsing,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    )
    |> fn(r) {
      case r.status {
        200 -> Ok(Nil)
        _ -> Error(Nil)
      }
    }
  let assert Ok(_) =
    call_json(
      browsing,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    )
    |> fn(r) {
      case r.status {
        200 -> Ok(Nil)
        _ -> Error(Nil)
      }
    }

  // Off by default, and a listing against a disabled network says so rather
  // than answering empty.
  let status =
    call(browsing, authed(browsing, Get, "/api/orgs/acme/networks/prod/browse"))
  assert status.status == 200
  assert string.contains(simulate.read_body(status), "\"enabled\":false")
  let listing =
    call(
      browsing,
      authed(
        browsing,
        Get,
        "/api/orgs/acme/networks/prod/browse/ls?space=media&path=",
      ),
    )
  assert listing.status == 409

  // The admin flips it. Not a zone change: no soa_serial in the answer.
  let flipped =
    call_json(
      browsing,
      Put,
      "/api/orgs/acme/networks/prod/browse/enabled",
      json.object([#("enabled", json.bool(True))]),
    )
  assert flipped.status == 200
  assert !string.contains(simulate.read_body(flipped), "soa_serial")

  // Enabled but with nothing attached yet, which reads differently from
  // "disabled".
  let listing =
    call(
      browsing,
      authed(
        browsing,
        Get,
        "/api/orgs/acme/networks/prod/browse/ls?space=media&path=",
      ),
    )
  assert listing.status == 503
  assert string.contains(simulate.read_body(listing), "no-device-attached")

  // And the flip is in the audit trail the org already reads.
  let conn = read_db(browsing)
  let assert Ok([[sqlite.Text(action)]]) =
    sqlite.query(
      conn,
      "SELECT action FROM audit_log WHERE action LIKE 'browse.%'",
      [],
    )
  sqlite.close(conn)
  assert action == "browse.enable"
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

/// An armed gate must not keep a revoked key resolvable.
///
/// The gate holds back *new* claims under a key no transparency log has seen.
/// A revocation is the opposite: it takes a key out of the zone, and refusing
/// it leaves the key live in the database while the exempt hourly re-sign keeps
/// renewing the RRSIGs over it — so the key never ages out either. Removals go
/// through; additions wait.
pub fn an_armed_gate_still_lets_a_revocation_through_test() {
  let h = harness()
  // Disarm during setup because each setup mutation widens the published zone.
  use <- fixtures.with_gate_armed
  fixtures.gate_disarmed()
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
  let device_nk = nk()
  let created =
    call_json(
      h,
      Post,
      "/api/orgs/acme/devices",
      json.object([
        #("label", json.string("nas")),
        #("nk", json.string(device_nk)),
      ]),
    )
  assert created.status == 200
  let assert Ok(#(_, tail)) =
    string.split_once(simulate.read_body(created), "device_id\":\"")
  let assert [device_id, ..] = string.split(tail, "\"")
  let assert 200 =
    call(
      h,
      authed(h, Put, "/api/orgs/acme/networks/prod/devices/" <> device_id),
    ).status
  assert published_nks(h) == [device_nk]
  let conn = read_db(h)
  let assert Ok([[sqlite.Text(key_id)]]) =
    sqlite.query(conn, "SELECT id FROM device_keys WHERE device_id = ?", [
      sqlite.Text(device_id),
    ])
  sqlite.close(conn)

  // Now arm it. The zone key has no log record, so a mutation that adds to
  // what the zone claims is refused — and says which step is missing.
  fixtures.gate_armed()
  let widening =
    call_json(
      h,
      Post,
      "/api/orgs/acme/devices",
      json.object([
        #("label", json.string("laptop")),
        #("nk", json.string(nk())),
      ]),
    )
  assert widening.status == 409
  assert string.contains(simulate.read_body(widening), "rekor-publish")

  // The revocation of the key already serving goes through, and the key
  // actually leaves the zone.
  let revoke =
    call(
      h,
      authed(
        h,
        Post,
        "/api/orgs/acme/devices/"
          <> device_id
          <> "/keys/"
          <> key_id
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

/// Leaving is removing your own row, and it needs only the membership being
/// given up — a plain member who can only be let go by an admin is held, not
/// governed. Removing somebody *else's* row still needs admin.
pub fn member_can_leave_org_test() {
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
      "INSERT INTO users VALUES ('u-other', 'o@example.com', NULL, 0)",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO org_members VALUES
       ((SELECT id FROM orgs WHERE slug = 'acme'), 'u-member', 'member', 0),
       ((SELECT id FROM orgs WHERE slug = 'acme'), 'u-other', 'member', 0)",
      [],
    )
  let assert Ok(#(member_token, member_live)) =
    session.create(conn, "u-member", now_unix())
  sqlite.close(conn)
  let as_member = fn(method, path) {
    simulate.request(method, path)
    |> simulate.cookie(session.cookie_name, member_token, wisp.Signed)
    |> simulate.header("x-csrf", member_live.csrf)
  }

  // Somebody else's row is still an administrative act...
  let other = call(h, as_member(Delete, "/api/orgs/acme/members/u-other"))
  assert other.status == 403

  // ...their own is not, and the answer says the caller is the one who left.
  let left = call(h, as_member(Delete, "/api/orgs/acme/members/u-member"))
  assert left.status == 200
  assert string.contains(simulate.read_body(left), "\"left\":true")

  let conn2 = read_db(h)
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(
      conn2,
      "SELECT count(*) FROM org_members WHERE user_id = 'u-member'",
      [],
    )
  // Recorded as leaving, not as being removed: the actor and the subject are
  // the same person, and the log is where that distinction survives.
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(
      conn2,
      "SELECT count(*) FROM audit_log WHERE action = 'member.leave'",
      [],
    )
  // The org and everyone else in it are untouched.
  let assert Ok([[sqlite.Int(2)]]) =
    sqlite.query(conn2, "SELECT count(*) FROM org_members", [])
  sqlite.close(conn2)

  // A former member sees the org the way a stranger does, and has nothing
  // left to leave.
  let stranger = call(h, as_member(Get, "/api/orgs/acme"))
  assert stranger.status == 404
  let again = call(h, as_member(Delete, "/api/orgs/acme/members/u-member"))
  assert again.status == 404
}

/// The last owner is the one member who cannot leave: every path back to
/// `owner` is owner-gated, so an org they walked out of could never be given
/// one again. The refusal names the two ways out.
pub fn last_owner_cannot_leave_test() {
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
  let stuck = call(h, authed(h, Delete, "/api/orgs/acme/members/u-admin"))
  assert stuck.status == 409
  assert string.contains(simulate.read_body(stuck), "transfer ownership")

  // Hand the org over and the way out opens: the stepped-down admin leaves
  // their own row like anybody else.
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
  sqlite.close(conn)
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/transfer",
      json.object([#("to", json.string("u-member"))]),
    ).status
  let gone = call(h, authed(h, Delete, "/api/orgs/acme/members/u-admin"))
  assert gone.status == 200
  let conn2 = read_db(h)
  let assert Ok([[sqlite.Text("u-member")]]) =
    sqlite.query(conn2, "SELECT user_id FROM org_members", [])
  sqlite.close(conn2)
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

pub fn invite_creation_test() {
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
  // The invite grammar: member or admin, never owner — owners are made by
  // transfer or promotion, not by self-service token.
  let bad =
    call_json(
      h,
      Post,
      "/api/orgs/acme/invites",
      json.object([
        #("email", json.string("newbie@example.com")),
        #("role", json.string("owner")),
      ]),
    )
  assert bad.status == 400
  let resp =
    call_json(
      h,
      Post,
      "/api/orgs/acme/invites",
      json.object([
        #("email", json.string("newbie@example.com")),
        #("role", json.string("admin")),
      ]),
    )
  assert resp.status == 200
  // An address is stored the way it will be sent to: trimmed and folded,
  // since a relay takes neither the surrounding spaces nor the case.
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/invites",
      json.object([#("email", json.string("  Second@Example.COM  "))]),
    ).status
  // And an address that is not one at all never reaches the relay.
  let unaddressed =
    call_json(
      h,
      Post,
      "/api/orgs/acme/invites",
      json.object([#("email", json.string("nobody"))]),
    )
  assert unaddressed.status == 400
  let conn = read_db(h)
  let assert Ok([[sqlite.Text("admin"), sqlite.Int(1)]]) =
    sqlite.query(
      conn,
      "SELECT role, accepted_at IS NULL FROM invites
       WHERE email = 'newbie@example.com'",
      [],
    )
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(
      conn,
      "SELECT count(*) FROM invites WHERE email = 'second@example.com'",
      [],
    )
  sqlite.close(conn)
}

/// The invite page's lookup: a token holder sees the org, the role and the
/// state of the invite they hold — including the two states that can no
/// longer be accepted, which the page must tell apart from an unknown token.
pub fn invite_preview_test() {
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
  let conn = {
    let assert Ok(conn) = db.open_primary(h.db_path)
    conn
  }
  let plant = fn(id, token, expires, accepted) {
    let assert Ok(_) =
      sqlite.exec(
        conn,
        "INSERT INTO invites VALUES (?, (SELECT id FROM orgs WHERE slug = 'acme'),
           'newbie@example.com', 'admin', ?, 'u-admin', ?, ?, ?)",
        [
          sqlite.Text(id),
          sqlite.Blob(id.hash_token(token)),
          sqlite.Int(now_unix()),
          sqlite.Int(expires),
          accepted,
        ],
      )
    Nil
  }
  let now = now_unix()
  plant("inv-valid", "valid-token", now + 3600, sqlite.Null)
  plant("inv-expired", "expired-token", now - 10, sqlite.Null)
  plant("inv-accepted", "accepted-token", now + 3600, sqlite.Int(now))
  // Both expired and accepted: accepted is what the holder must hear, since
  // expiry alone would suggest a resend that cannot fix it.
  plant("inv-both", "both-token", now - 10, sqlite.Int(now))
  sqlite.close(conn)

  let preview = fn(token) {
    simulate.read_body(call(
      h,
      simulate.request(Get, "/api/invites/preview?token=" <> token),
    ))
  }
  let valid = preview("valid-token")
  assert string.contains(valid, "\"org\":\"acme\"")
  assert string.contains(valid, "\"org_name\":\"Acme\"")
  assert string.contains(valid, "\"email\":\"newbie@example.com\"")
  assert string.contains(valid, "\"role\":\"admin\"")
  assert string.contains(valid, "\"status\":\"valid\"")
  // Unix seconds, not a formatted date: the page renders it itself.
  assert string.contains(valid, "\"expires_at\":" <> int.to_string(now + 3600))
  assert string.contains(preview("expired-token"), "\"status\":\"expired\"")
  assert string.contains(preview("accepted-token"), "\"status\":\"accepted\"")
  assert string.contains(preview("both-token"), "\"status\":\"accepted\"")
  // A token that is nobody's invite is a 404, not a guess; an omitted one is
  // the request's own fault.
  let unknown =
    call(h, simulate.request(Get, "/api/invites/preview?token=nope"))
  assert unknown.status == 404
  let bare = call(h, simulate.request(Get, "/api/invites/preview"))
  assert bare.status == 400
  let empty = call(h, simulate.request(Get, "/api/invites/preview?token="))
  assert empty.status == 400
}

/// Deleting a network: the typed confirmation is the guard, the zone shrinks
/// in the same transaction, and the devices live on unassigned.
pub fn network_deletion_test() {
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

  // A confirm that is not the network's name changes nothing.
  let wrong =
    call_json(
      h,
      Delete,
      "/api/orgs/acme/networks/prod",
      json.object([#("confirm", json.string("nope"))]),
    )
  assert wrong.status == 400
  assert published_nks(h) == [nas_nk]

  let gone =
    call_json(
      h,
      Delete,
      "/api/orgs/acme/networks/prod",
      json.object([#("confirm", json.string("prod"))]),
    )
  assert gone.status == 200
  assert published_nks(h) == []
  assert call(h, authed(h, Get, "/api/orgs/acme/networks/prod")).status == 404
  // Devices are unassigned by the delete, not deleted by it.
  let conn = read_db(h)
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(conn, "SELECT count(*) FROM devices WHERE label = 'nas'", [])
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn, "SELECT count(*) FROM network_devices", [])
  sqlite.close(conn)
}

/// Deleting an org takes everything it owns — and only what it owns: a
/// sibling org's devices keep resolving, the audit trail outlives the org,
/// and an admin who is not the owner cannot do it at all.
/// Removing an org's OIDC provider takes the identities linked through it
/// and the sign-in states pointing at it — with foreign keys ON, a state
/// left behind would refuse the removal itself.
pub fn delete_oidc_takes_its_children_test() {
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
  let conn = {
    let assert Ok(conn) = db.open_primary(h.db_path)
    conn
  }
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO oidc_providers VALUES ('oidc1',
        (SELECT id FROM orgs WHERE slug = 'acme'), 'https://issuer.test',
        'cid', 'csec', 'https://issuer.test/auth',
        'https://issuer.test/token', NULL, 0)",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO auth_identities VALUES
        ('ident1', 'u-admin', 'oidc', 'oidc1', 'sub-1', 0)",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO oauth_states VALUES
        ('state1', 'oidc', 'oidc1', 'verifier', NULL, NULL, NULL, 0, 0, NULL)",
      [],
    )
  sqlite.close(conn)
  let resp = call(h, authed(h, Delete, "/api/orgs/acme/oidc"))
  assert resp.status == 200
  let conn2 = read_db(h)
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn2, "SELECT count(*) FROM oidc_providers", [])
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn2, "SELECT count(*) FROM auth_identities", [])
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn2, "SELECT count(*) FROM oauth_states", [])
  sqlite.close(conn2)
}

pub fn org_deletion_test() {
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
      "/api/orgs",
      json.object([
        #("slug", json.string("keep")),
        #("name", json.string("Keep")),
      ]),
    ).status
  list.each(["acme", "keep"], fn(org) {
    let assert 200 =
      call_json(
        h,
        Post,
        "/api/orgs/" <> org <> "/networks",
        json.object([#("name", json.string("prod"))]),
      ).status
  })
  let acme_nk = nk()
  let keep_nk = nk()
  let label_nk = [
    #("acme", "nas", acme_nk),
    #("keep", "laptop", keep_nk),
  ]
  list.each(label_nk, fn(entry) {
    let #(org, label, key) = entry
    let created =
      call_json(
        h,
        Post,
        "/api/orgs/" <> org <> "/devices",
        json.object([
          #("label", json.string(label)),
          #("nk", json.string(key)),
        ]),
      )
    assert created.status == 200
    let assert Ok(#(_, tail)) =
      string.split_once(simulate.read_body(created), "device_id\":\"")
    let assert [device_id, ..] = string.split(tail, "\"")
    let assert 200 =
      call(
        h,
        authed(
          h,
          Put,
          "/api/orgs/" <> org <> "/networks/prod/devices/" <> device_id,
        ),
      ).status
  })
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/invites",
      json.object([
        #("email", json.string("newbie@example.com")),
        #("role", json.string("member")),
      ]),
    ).status

  // A fellow admin cannot delete the org, whatever they confirm.
  let conn = {
    let assert Ok(conn) = db.open_primary(h.db_path)
    conn
  }
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO users VALUES ('u-helper', 'helper@example.com', NULL, 0)",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO org_members VALUES
       ((SELECT id FROM orgs WHERE slug = 'acme'), 'u-helper', 'admin', 0)",
      [],
    )
  let assert Ok(#(helper_token, helper_live)) =
    session.create(conn, "u-helper", now_unix())
  // A configured provider with a linked identity and a sign-in state in
  // flight: the delete must take all three, in an order the foreign keys
  // permit.
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO oidc_providers VALUES ('oidc1',
        (SELECT id FROM orgs WHERE slug = 'acme'), 'https://issuer.test',
        'cid', 'csec', 'https://issuer.test/auth',
        'https://issuer.test/token', NULL, 0)",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO auth_identities VALUES
        ('ident1', 'u-admin', 'oidc', 'oidc1', 'sub-1', 0)",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO oauth_states VALUES
        ('state1', 'oidc', 'oidc1', 'verifier', NULL, NULL, NULL, 0, 0, NULL)",
      [],
    )
  sqlite.close(conn)
  let as_helper =
    simulate.request(Delete, "/api/orgs/acme")
    |> simulate.cookie(session.cookie_name, helper_token, wisp.Signed)
    |> simulate.header("x-csrf", helper_live.csrf)
    |> simulate.json_body(json.object([#("confirm", json.string("acme"))]))
  assert call(h, as_helper).status == 403

  // The slug is the confirmation: anything else is refused.
  let wrong =
    call_json(
      h,
      Delete,
      "/api/orgs/acme",
      json.object([#("confirm", json.string("wrong"))]),
    )
  assert wrong.status == 400

  let gone =
    call_json(
      h,
      Delete,
      "/api/orgs/acme",
      json.object([#("confirm", json.string("acme"))]),
    )
  assert gone.status == 200
  assert call(h, authed(h, Get, "/api/orgs/acme")).status == 404

  // Everything acme owned is gone; everything keep owns is intact.
  let conn2 = read_db(h)
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn2, "SELECT count(*) FROM orgs WHERE slug = 'acme'", [])
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(
      conn2,
      "SELECT count(*) FROM org_members WHERE org_id NOT IN (SELECT id FROM orgs)",
      [],
    )
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(
      conn2,
      "SELECT count(*) FROM devices WHERE label = 'nas'
       OR id IN (SELECT device_id FROM network_devices WHERE network_id NOT IN (SELECT id FROM networks))",
      [],
    )
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn2, "SELECT count(*) FROM invites", [])
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn2, "SELECT count(*) FROM oidc_providers", [])
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn2, "SELECT count(*) FROM auth_identities", [])
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn2, "SELECT count(*) FROM oauth_states", [])
  let assert Ok([[sqlite.Text(detail)]]) =
    sqlite.query(
      conn2,
      "SELECT detail FROM audit_log WHERE action = 'org.delete'",
      [],
    )
  assert string.contains(detail, "acme")
  sqlite.close(conn2)
  // Only keep's device is still published — and it is.
  assert published_nks(h) == [keep_nk]
  let survivor = call(h, authed(h, Get, "/api/orgs/keep"))
  assert survivor.status == 200
}

/// Ownership transfer is one atomic step: the member becomes the owner, the
/// owner steps down to admin, and the org is never between owners.
pub fn ownership_transfer_test() {
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
  sqlite.close(conn)

  // To yourself is a no-op dressed as a transfer; to a non-member, a 404.
  let to_self =
    call_json(
      h,
      Post,
      "/api/orgs/acme/transfer",
      json.object([#("to", json.string("u-admin"))]),
    )
  assert to_self.status == 400
  let to_nobody =
    call_json(
      h,
      Post,
      "/api/orgs/acme/transfer",
      json.object([#("to", json.string("u-nobody"))]),
    )
  assert to_nobody.status == 404

  let transferred =
    call_json(
      h,
      Post,
      "/api/orgs/acme/transfer",
      json.object([#("to", json.string("u-member"))]),
    )
  assert transferred.status == 200
  assert string.contains(
    simulate.read_body(transferred),
    "\"your_role\":\"admin\"",
  )
  let conn2 = read_db(h)
  let assert Ok([[sqlite.Text("admin")]]) =
    sqlite.query(
      conn2,
      "SELECT role FROM org_members WHERE user_id = 'u-admin'",
      [],
    )
  let assert Ok([[sqlite.Text("owner")]]) =
    sqlite.query(
      conn2,
      "SELECT role FROM org_members WHERE user_id = 'u-member'",
      [],
    )
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(
      conn2,
      "SELECT count(*) FROM audit_log WHERE action = 'org.transfer'",
      [],
    )
  sqlite.close(conn2)

  // The stepped-down admin no longer holds the transfer — not even back to
  // the owner who took their place.
  let again =
    call_json(
      h,
      Post,
      "/api/orgs/acme/transfer",
      json.object([#("to", json.string("u-member"))]),
    )
  assert again.status == 403
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
  let assert router.Context(_, _, _, router.ServingZone(serving), _) = h.ctx
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

// -- the read-only surface ---------------------------------------------------

/// The same harness reading through a replica's surface: the read half of
/// the API over the same tables, and the primary's URL for the other half.
///
/// The database is the primary's own file rather than a copy, which is the
/// point — a replica's copy is byte-identical, so what the surface answers is
/// exactly what the primary would, and any difference is the router's doing
/// rather than the data's.
fn read_only(h: Harness, primary_url: String) -> Harness {
  let assert router.Writable(auth) = h.ctx.api
  Harness(
    ..h,
    ctx: router.Context(..h.ctx, api: router.ReadOnly(auth.reads, primary_url)),
  )
}

/// Every GET the primary answers, a read-only node answers identically:
/// the tables are the same and the handlers are mounted once.
pub fn a_read_only_node_answers_every_read_test() {
  let h = harness()
  let replica = read_only(h, "https://sync.test")
  let reads = [
    "/api/me",
    "/api/orgs/acme",
    "/api/orgs/acme/members",
    "/api/orgs/acme/networks",
    "/api/orgs/acme/devices",
    "/api/orgs/acme/audit",
  ]
  // An org to read, created through the surface that can create one.
  let created =
    call_json(
      h,
      http.Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    )
  assert created.status == 200

  list.each(reads, fn(path) {
    let from_primary = call(h, authed(h, http.Get, path))
    let from_replica = call(replica, authed(replica, http.Get, path))
    assert from_replica.status == from_primary.status
    assert simulate.read_body(from_replica) == simulate.read_body(from_primary)
  })

  // There is no built SPA in a test tree, so compare the primary and replica
  // responses rather than expecting a successful static response.
  let spa = call(replica, simulate.request(http.Get, "/orgs/acme"))
  assert spa.status == call(h, simulate.request(http.Get, "/orgs/acme")).status
}

/// A write is refused with the address of the node that takes it — not a
/// 404, which tells an operator nothing, and not a 500 from sqlite about a
/// read-only file, which tells them about the wrong layer.
pub fn a_read_only_node_names_where_the_writes_go_test() {
  let replica = read_only(harness(), "https://sync.test")
  let refused =
    call_json(
      replica,
      http.Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    )
  assert refused.status == 409
  let body = simulate.read_body(refused)
  assert string.contains(body, "read-only-replica")
  assert string.contains(body, "\"primary\":\"https://sync.test\"")

  // The sign-in flows are writes too — they mint the session everything else
  // is gated on — so they are refused by the same rule.
  let magic =
    call_json(
      replica,
      http.Post,
      "/auth/magic",
      json.object([#("email", json.string("someone@example.com"))]),
    )
  assert magic.status == 409

  // A path that exists on no node is still the 404 it would be anywhere: the
  // refusal names a place to go, and there is nowhere to send a typo.
  let nonsense = call(replica, authed(replica, http.Get, "/api/nope"))
  assert nonsense.status == 404

  // The sign-in flows under GET are browser navigations, not fetches, so a
  // stale bookmark or a second tab is redirected to the node that can
  // complete it rather than dead-ended — query and all, since `?link=1` is
  // what makes a start URL a linking flow rather than a sign-in.
  let start =
    call(replica, simulate.request(http.Get, "/auth/start/google?link=1"))
  assert start.status == 303
  assert list.key_find(start.headers, "location")
    == Ok("https://sync.test/auth/start/google?link=1")
}

/// The login screen asks what it may offer before a session exists. On a
/// read-only node the honest answer is "nothing here, and here is where":
/// every method false, and the primary named.
pub fn a_read_only_node_offers_no_sign_in_but_names_one_test() {
  let replica = read_only(harness(), "https://sync.test")
  let body =
    simulate.read_body(call(
      replica,
      simulate.request(http.Get, "/api/auth/methods"),
    ))
  assert string.contains(body, "\"magic_link\":false")
  assert string.contains(body, "\"google\":false")
  assert string.contains(body, "\"primary\":\"https://sync.test\"")

  // The primary names no one else: it is the place.
  let here =
    simulate.read_body(call(
      harness(),
      simulate.request(http.Get, "/api/auth/methods"),
    ))
  assert string.contains(here, "\"primary\":\"\"")
}

/// The browse surface is a read surface, so a read-only node serves it — and
/// must, since the registry of attached daemons is one node's memory and a
/// node no daemon attached to answers nothing.
///
/// The one write in the surface is the org's own switch, and that goes where
/// every other write goes.
pub fn a_read_only_node_serves_the_browse_surface_test() {
  let h = harness()
  let name = process.new_name("cp_agents_replica_test")
  let assert Ok(_) = agent.start(name)
  let browsing =
    Harness(
      ..h,
      ctx: router.Context(
        ..h.ctx,
        browse: browse_api.Browse(name, "https://cp1.test/agent/v1/attach"),
      ),
    )
  let assert 200 =
    call_json(
      browsing,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string("acme")),
        #("name", json.string("Acme")),
      ]),
    ).status
  let assert 200 =
    call_json(
      browsing,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  let assert 200 =
    call_json(
      browsing,
      Put,
      "/api/orgs/acme/networks/prod/browse/enabled",
      json.object([#("enabled", json.bool(True))]),
    ).status

  let replica = read_only(browsing, "https://sync.test")

  // Status reads, and names *this* node's attach URL — the one its own
  // daemons dialled, not the primary's.
  let status =
    call(replica, authed(replica, Get, "/api/orgs/acme/networks/prod/browse"))
  assert status.status == 200
  let body = simulate.read_body(status)
  assert string.contains(body, "\"enabled\":true")
  assert string.contains(body, "https://cp1.test/agent/v1/attach")

  // A listing reaches the same refusal the primary gives with nothing
  // attached, which is what says the route ran rather than 404ing.
  let listing =
    call(
      replica,
      authed(
        replica,
        Get,
        "/api/orgs/acme/networks/prod/browse/ls?space=media&path=",
      ),
    )
  assert listing.status == 503
  assert string.contains(simulate.read_body(listing), "no-device-attached")

  // The org's switch is a write like any other.
  let flip =
    call_json(
      replica,
      Put,
      "/api/orgs/acme/networks/prod/browse/enabled",
      json.object([#("enabled", json.bool(False))]),
    )
  assert flip.status == 409
  assert string.contains(simulate.read_body(flip), "read-only-replica")
}

pub fn with_db_discards_conn_on_panic_test() {
  // A panic inside a request handler must not leak the connection: wisp
  // rescues crashes, so the process survives — only with_db's deferred
  // close stands between a panicking handler and a csqlite process
  // holding the write lock for the life of the HTTP connection.
  let h = harness()
  let assert router.Context(_, _, router.Writable(auth), _, _) = h.ctx
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

/// `/healthz` in serve mode reports the zone's signature expiry as a status,
/// not only as a field.
///
/// A primary whose `resign` job has been failing serves a zone every
/// validating resolver reads as `Bogus`. The endpoint answered 200
/// `"status":"ok"` with `sig_expires_at` in the past, and the HTTP status is
/// the only thing the image's HEALTHCHECK, a load balancer or an orchestrator
/// reads.
pub fn healthz_fails_when_the_zone_signatures_have_run_out_test() {
  let now = now_unix()
  // A freshly signed zone has a fortnight of life and is servable.
  assert router.zone_is_servable(now + 14 * 86_400, now)
  assert router.zone_is_servable(now + router.zone_health_headroom + 1, now)

  // Expired, and about to expire, are both refusals — the first is a zone
  // every validating resolver already reads as Bogus, the second is a resign
  // job that has stopped rather than one merely between runs.
  assert !router.zone_is_servable(now - 60, now)
  assert !router.zone_is_servable(now + 60, now)
}

/// `/SKILL.md` is public, role-agnostic, and actually in the shipment.
///
/// Role-agnostic is the whole point of the route existing at all: the `synch`
/// guide needs no session, no database and no zone, so a replica — which
/// answers 404 for every product route and has no SPA to fall back to — must
/// still serve it. A URL that only works on the primary is not one worth
/// publishing.
///
/// The shipment assertion is the other half. `priv/skill/SKILL.md` is a
/// tracked source file that a packaging change can silently drop, and a build
/// that dropped it boots, serves, and passes every other check while this one
/// route answers 404.
pub fn skill_md_is_served_by_every_role_test() {
  let h = harness()
  let body = fn(res) { simulate.read_body(res) }

  let served = call(h, simulate.request(Get, "/SKILL.md"))
  assert served.status == 200
  assert list.contains(served.headers, #(
    "content-type",
    "text/markdown; charset=utf-8",
  ))
  // Enough of the document to know it is the guide and not, say, index.html.
  assert string.contains(body(served), "synch daemon run")
  // The served guide includes the socket lifecycle, not only file operations.
  assert string.contains(body(served), "synch socket activate")
  // And that it still carries this service's own API, which is the half an
  // agent holding nothing but this URL cannot get anywhere else: the node
  // that answers /SKILL.md is the node that answers /api.
  assert string.contains(body(served), "Authorization: Bearer")

  // Role-agnostic, so a read-only node serves the same document: it needs no
  // session, no writable database and no zone key, and an operator pointed at
  // any node of a deployment gets the same guide from the same URL. That is
  // the only property that makes the URL worth handing out.
  let replica = read_only(h, "https://sync.test")
  let elsewhere = call(replica, simulate.request(Get, "/SKILL.md"))
  assert elsewhere.status == 200
  assert body(elsewhere) == body(served)

  // Read-only: anything but a GET is a refusal, not a fallthrough.
  assert call(h, authed(h, Post, "/SKILL.md")).status == 405

  // And the file really is where the shipment puts it.
  assert skill.read() != Error(Nil)
}

// -- org-scoped API keys -----------------------------------------------------

/// An org for the harness's user to hold keys in.
fn org_named(h: Harness, slug: String) -> Nil {
  let created =
    call_json(
      h,
      Post,
      "/api/orgs",
      json.object([
        #("slug", json.string(slug)),
        #("name", json.string(string.uppercase(slug))),
      ]),
    )
  assert created.status == 200
  Nil
}

/// A request carrying a bearer token and no cookie — which is what a program
/// sends, and the shape every claim about keys below has to hold for.
fn keyed(token: String, method: http.Method, path: String) -> wisp.Request {
  simulate.request(method, path)
  |> simulate.header("authorization", "Bearer " <> token)
}

/// Mints an org key through the API and returns its token.
fn mint(h: Harness, slug: String, name: String, role: String) -> String {
  let created =
    call_json(
      h,
      Post,
      "/api/orgs/" <> slug <> "/api-keys",
      json.object([
        #("name", json.string(name)),
        #("role", json.string(role)),
      ]),
    )
  assert created.status == 200
  token_of(simulate.read_body(created))
}

/// Mints a join key scoped to one network.
fn mint_join(
  h: Harness,
  slug: String,
  network: String,
  name: String,
) -> String {
  let created =
    call_json(
      h,
      Post,
      "/api/orgs/" <> slug <> "/api-keys",
      json.object([
        #("name", json.string(name)),
        #("role", json.string("join")),
        #("network", json.string(network)),
        // Not optional on a join key, and the helper says so by carrying one.
        #("expires_in", json.int(2_592_000)),
      ]),
    )
  assert created.status == 200
  token_of(simulate.read_body(created))
}

/// An org with one network, which is what a join key needs to exist at all.
fn org_with_network(h: Harness, slug: String, network: String) -> Nil {
  org_named(h, slug)
  let made =
    call_json(
      h,
      Post,
      "/api/orgs/" <> slug <> "/networks",
      json.object([#("name", json.string(network))]),
    )
  assert made.status == 200
  Nil
}

/// The body a node sends to join, with a fresh key each time.
fn joining(label: String) -> json.Json {
  json.object([#("label", json.string(label)), #("nk", json.string(nk()))])
}

/// The `token` field of a mint response.
///
/// The split is enough wherever it is in the body: `"token":"` appears once,
/// and base64url has no `"` to escape one into the value. A decoder here
/// would only restate the encoder.
fn token_of(body: String) -> String {
  let assert Ok(#(_, after)) = string.split_once(body, "\"token\":\"")
  let assert Ok(#(token, _)) = string.split_once(after, "\"")
  token
}

/// The one property the whole feature rests on: a key reaches its own org
/// and nothing else, whatever its minter can reach.
pub fn api_key_is_scoped_to_one_org_test() {
  let h = harness()
  org_named(h, "acme")
  org_named(h, "other")
  let token = mint(h, "acme", "ci", "admin")

  // The org it was minted in.
  assert call(h, keyed(token, Get, "/api/orgs/acme")).status == 200

  // Another org the *minter* owns, and the key does not: the same 404 a
  // stranger gets, because an org is not enumerable by whoever cannot see it.
  let elsewhere = call(h, keyed(token, Get, "/api/orgs/other"))
  assert elsewhere.status == 404
  assert string.contains(simulate.read_body(elsewhere), "no such org")

  // A token nobody minted is a 401 and not a 404: the credential is what
  // failed, and saying so is not saying which orgs exist.
  let unknown = call(h, keyed("synch_nope", Get, "/api/orgs/acme"))
  assert unknown.status == 401
  // And a token that is not one of ours at all fails the same way, without
  // a lookup: the scheme is right, the prefix is not.
  assert call(h, keyed("ghp_something", Get, "/api/orgs/acme")).status == 401
}

/// A key's role is the key's, not its minter's — the reason the role lives on
/// the row rather than being read from `org_members`.
pub fn api_key_carries_its_own_role_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status

  // Minted by the org's owner, and still only a member: the member floor
  // opens, the admin floor does not.
  let member = mint(h, "acme", "read-mostly", "member")
  assert call(h, keyed(member, Get, "/api/orgs/acme/networks")).status == 200
  let refused = call(h, keyed(member, Delete, "/api/orgs/acme/devices/nope"))
  assert refused.status == 403
  assert string.contains(simulate.read_body(refused), "requires admin role")

  // An admin key clears the same floor: a miss, not a refusal.
  let admin = mint(h, "acme", "deployer", "admin")
  assert call(h, keyed(admin, Delete, "/api/orgs/acme/devices/nope")).status
    == 404

  // No key is ever an owner, in either direction: the role cannot be asked
  // for, and the owner-gated routes refuse the keys that do exist.
  let owner_key =
    call_json(
      h,
      Post,
      "/api/orgs/acme/api-keys",
      json.object([
        #("name", json.string("too much")),
        #("role", json.string("owner")),
      ]),
    )
  assert owner_key.status == 400
  assert string.contains(simulate.read_body(owner_key), "admin, member or join")
  assert call(h, keyed(admin, Get, "/api/orgs/acme/oidc")).status == 403
}

/// What a key may never do, and why each one is on the list: every entry is
/// a way a scoped credential could reach past its scope.
pub fn api_key_may_not_manage_accounts_membership_or_keys_test() {
  let h = harness()
  org_named(h, "acme")
  let token = mint(h, "acme", "ci", "admin")
  let forbidden = fn(res: wisp.Response) {
    assert res.status == 403
    assert string.contains(simulate.read_body(res), "api_key_forbidden")
    Nil
  }
  let post = fn(path, body) {
    call(h, keyed(token, Post, path) |> simulate.json_body(body))
  }

  // An account is a person's, and so is the org a person creates.
  forbidden(post(
    "/api/orgs",
    json.object([
      #("slug", json.string("mine")),
      #("name", json.string("Mine")),
    ]),
  ))
  forbidden(call(h, keyed(token, Get, "/api/me")))

  // Membership: an admin key that could invite an admin would be handing out
  // standing human access that outlives the key.
  forbidden(post(
    "/api/orgs/acme/invites",
    json.object([#("email", json.string("someone@example.com"))]),
  ))
  forbidden(call(h, keyed(token, Delete, "/api/orgs/acme/members/u-admin")))

  // The audit trail, which carries both of the things above: members'
  // addresses and ids in its actor column and its invite and role details,
  // and an inventory of the org's other keys from every apikey.create row.
  forbidden(call(h, keyed(token, Get, "/api/orgs/acme/audit")))

  // And keys themselves, in all four directions — including the listing,
  // which would otherwise tell a key what else to go looking for.
  forbidden(call(h, keyed(token, Get, "/api/orgs/acme/api-keys")))
  forbidden(post(
    "/api/orgs/acme/api-keys",
    json.object([#("name", json.string("another"))]),
  ))
  forbidden(call(
    h,
    keyed(token, Patch, "/api/orgs/acme/api-keys/whatever")
      |> simulate.json_body(json.object([#("name", json.string("mine"))])),
  ))
  forbidden(call(h, keyed(token, Delete, "/api/orgs/acme/api-keys/whatever")))
}

/// The org roster is a person's to read. A key drives networks, devices and
/// keys; the address book is not part of that, and the `user_id` values it
/// carries are what the membership mutations take.
pub fn api_key_may_not_read_the_member_roster_test() {
  let h = harness()
  org_named(h, "acme")
  let token = mint(h, "acme", "ci", "admin")
  let refused = call(h, keyed(token, Get, "/api/orgs/acme/members"))
  assert refused.status == 403
  assert string.contains(simulate.read_body(refused), "api_key_forbidden")
  // Still the dashboard's to read, on the same org.
  assert call(h, authed(h, Get, "/api/orgs/acme/members")).status == 200
}

/// A bearer token needs no CSRF header, and never falls back to the cookie.
pub fn api_key_mutations_need_no_csrf_and_never_fall_back_test() {
  let h = harness()
  org_named(h, "acme")
  let token = mint(h, "acme", "ci", "admin")

  // No cookie, no `x-csrf`, and a mutation goes through: nothing attaches an
  // Authorization header on its own, so there is no ambient authority to
  // defend against.
  let made =
    call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks")
        |> simulate.json_body(json.object([#("name", json.string("prod"))])),
    )
  assert made.status == 200

  // A request that names a credential is judged on that credential. A junk
  // token beside a good cookie is a 401, not a signed-in request — the
  // fallback would be a way to make a cross-site request look deliberate.
  let mixed =
    authed(h, Get, "/api/orgs/acme")
    |> simulate.header("authorization", "Bearer synch_junk")
  assert call(h, mixed).status == 401

  // Every shape of Authorization header is terminal, cookie or no cookie.
  // The one that matters in practice is `Bearer ` with an unset variable
  // behind it: falling back would run a whole CI job as the person whose
  // cookie happened to be on the machine.
  let shapes = ["Bearer ", "Bearer", "Basic dXNlcjpwYXNz", "Bearer\tsynch_x"]
  list.each(shapes, fn(header) {
    let alone =
      simulate.request(Get, "/api/orgs/acme")
      |> simulate.header("authorization", header)
    assert call(h, alone).status == 401
    // And beside a good cookie, which is the case a fallback would answer.
    let beside =
      authed(h, Get, "/api/orgs/acme")
      |> simulate.header("authorization", header)
    assert call(h, beside).status == 401
  })
}

/// The management surface end to end: mint, list, update, delete — and what
/// each step does to the credential itself.
pub fn api_keys_are_created_listed_updated_and_deleted_test() {
  let h = harness()
  org_named(h, "acme")

  let created =
    call_json(
      h,
      Post,
      "/api/orgs/acme/api-keys",
      json.object([
        #("name", json.string("ci")),
        #("role", json.string("member")),
        #("expires_in", json.int(3600)),
      ]),
    )
  assert created.status == 200
  let minted = simulate.read_body(created)
  let token = token_of(minted)
  assert string.starts_with(token, "synch_")
  assert string.contains(minted, "\"role\":\"member\"")

  // The list identifies the key by its prefix and never carries the token.
  let listed =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  assert string.contains(listed, "\"name\":\"ci\"")
  assert string.contains(listed, "\"prefix\":\"synch_")
  assert !string.contains(listed, token)
  assert string.contains(listed, "\"created_by_email\":\"admin@example.com\"")

  let assert Ok(#(_, after_id)) = string.split_once(listed, "\"id\":\"")
  let assert Ok(#(key_id, _)) = string.split_once(after_id, "\"")

  // An update renames, re-roles and clears the expiry, leaving the token
  // it was minted with working: rotating a secret is minting a new key.
  let updated =
    call_json(
      h,
      Patch,
      "/api/orgs/acme/api-keys/" <> key_id,
      json.object([
        #("name", json.string("deployer")),
        #("role", json.string("admin")),
        #("expires_in", json.int(0)),
      ]),
    )
  assert updated.status == 200
  let after_update =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  assert string.contains(after_update, "\"name\":\"deployer\"")
  assert string.contains(after_update, "\"role\":\"admin\"")
  assert string.contains(after_update, "\"expires_at\":0")

  // The new role is in force on the next request, not on the next mint.
  assert call(
      h,
      keyed(token, Post, "/api/orgs/acme/devices")
        |> simulate.json_body(
          json.object([
            #("label", json.string("nas")),
            #("nk", json.string(nk())),
          ]),
        ),
    ).status
    == 200

  // A key id from another org — or one that never existed — is a miss, not
  // an edit. The cross-org half is what `org_id` in the WHERE is for, and it
  // is the half worth asserting: the caller owns both orgs, so only the
  // statement's own scoping stands between them.
  assert call_json(
      h,
      Patch,
      "/api/orgs/acme/api-keys/nosuchkey",
      json.object([#("name", json.string("x"))]),
    ).status
    == 404
  org_named(h, "other")
  let other_token = mint(h, "other", "theirs", "member")
  let other_listing =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/other/api-keys")))
  let assert Ok(#(_, after_other)) =
    string.split_once(other_listing, "\"id\":\"")
  let assert Ok(#(other_id, _)) = string.split_once(after_other, "\"")
  assert call_json(
      h,
      Patch,
      "/api/orgs/acme/api-keys/" <> other_id,
      json.object([#("role", json.string("admin"))]),
    ).status
    == 404
  // Untouched, not merely unreported: the other org's key still authenticates
  // and is still a member.
  assert call(h, keyed(other_token, Get, "/api/orgs/other")).status == 200
  assert call(h, keyed(other_token, Get, "/api/orgs/other/audit")).status == 403

  // Deleting the row is what ends the access: the token authenticates by the
  // hash that row held.
  assert call(h, authed(h, Delete, "/api/orgs/acme/api-keys/" <> key_id)).status
    == 200
  assert call(h, keyed(token, Get, "/api/orgs/acme")).status == 401
  assert call(h, authed(h, Delete, "/api/orgs/acme/api-keys/" <> key_id)).status
    == 404

  // Three acts, three audit rows, all naming the key by id.
  let conn = read_db(h)
  let assert Ok(rows) =
    sqlite.query(
      conn,
      "SELECT action FROM audit_log
       WHERE action LIKE 'apikey.%'
         AND org_id = (SELECT id FROM orgs WHERE slug = 'acme')
       ORDER BY id",
      [],
    )
  sqlite.close(conn)
  assert list.map(rows, fn(row) {
      let assert [sqlite.Text(action)] = row
      action
    })
    == ["apikey.create", "apikey.update", "apikey.delete"]
}

/// One field at a time, the empty body, and the explicit null — the cases the
/// `coalesce`/`CASE` update exists for, and the ones nothing else sends.
///
/// The audit row is what these turn on: two of the three expiry inputs carry
/// no timestamp and mean opposite things, so a row that cannot tell "stopped
/// expiring" from "changed nothing" is a trail that cannot answer the one
/// question it is kept for.
pub fn api_key_updates_record_only_what_moved_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/api-keys",
      json.object([
        #("name", json.string("ci")),
        #("expires_in", json.int(3600)),
      ]),
    ).status
  let listed =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  let assert Ok(#(_, after_id)) = string.split_once(listed, "\"id\":\"")
  let assert Ok(#(key_id, _)) = string.split_once(after_id, "\"")
  let path = "/api/orgs/acme/api-keys/" <> key_id
  let patch = fn(body) { call_json(h, Patch, path, body).status }
  let row = fn() {
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  }

  // Name only: the other two columns are untouched, expiry included.
  assert patch(json.object([#("name", json.string("renamed"))])) == 200
  assert string.contains(row(), "\"name\":\"renamed\"")
  assert string.contains(row(), "\"role\":\"member\"")
  assert !string.contains(row(), "\"expires_at\":0")

  // Expiry only, cleared. The name survives.
  assert patch(json.object([#("expires_in", json.int(0))])) == 200
  assert string.contains(row(), "\"expires_at\":0")
  assert string.contains(row(), "\"name\":\"renamed\"")

  // An empty body changes nothing and is not a 404 — the statement still had
  // to find the row.
  assert patch(json.object([])) == 200
  // An explicit null is refused rather than guessed at, the same as on POST.
  assert patch(json.object([#("role", json.null())])) == 400

  let conn = read_db(h)
  let assert Ok(rows) =
    sqlite.query(
      conn,
      "SELECT detail FROM audit_log WHERE action = 'apikey.update' ORDER BY id",
      [],
    )
  sqlite.close(conn)
  let details =
    list.map(rows, fn(row) {
      let assert [sqlite.Text(detail)] = row
      detail
    })
  // Two rows for the two updates that moved something, and none for the
  // empty body or the refusal.
  assert list.length(details) == 2
  let assert [renamed, cleared] = details
  assert string.contains(renamed, "\"name\":\"renamed\"")
  // Absent, not null: the request did not carry an expiry.
  assert !string.contains(renamed, "expires_at")
  // Null, and it can only mean the one thing.
  assert string.contains(cleared, "\"expires_at\":null")
  assert !string.contains(cleared, "name")
}

/// `expires_in` is bounded, because `now + expires_in` is arithmetic on the
/// BEAM and the storage layer is not: an unbounded duration wraps and mints a
/// key that has already expired.
pub fn absurd_expiry_is_refused_rather_than_wrapped_test() {
  let h = harness()
  org_named(h, "acme")
  let asked =
    call_json(
      h,
      Post,
      "/api/orgs/acme/api-keys",
      json.object([
        #("name", json.string("forever")),
        #("expires_in", json.int(999_999_999_999_999_999_999)),
      ]),
    )
  assert asked.status == 400
  assert string.contains(simulate.read_body(asked), "bad_expiry")
  // And a negative one, which was never a duration forward.
  assert call_json(
      h,
      Post,
      "/api/orgs/acme/api-keys",
      json.object([
        #("name", json.string("past")),
        #("expires_in", json.int(-1)),
      ]),
    ).status
    == 400
}

/// The listing records when each key was last used, which is how an operator
/// tells a key still in service from one to clean up.
pub fn a_keys_use_is_stamped_test() {
  let h = harness()
  org_named(h, "acme")
  let token = mint(h, "acme", "ci", "member")
  // Never used: the listing says so with the zero the SPA tests for.
  let before =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  assert string.contains(before, "\"last_used_at\":0")

  assert call(h, keyed(token, Get, "/api/orgs/acme")).status == 200
  let after =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  assert !string.contains(after, "\"last_used_at\":0")
}

/// The audit trail names the credential that acted, not the person who
/// minted it — which stays true after that person's membership changes.
pub fn a_keys_work_is_audited_as_the_key_test() {
  let h = harness()
  org_named(h, "acme")
  let token = mint(h, "acme", "ci", "admin")
  assert call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks")
        |> simulate.json_body(json.object([#("name", json.string("prod"))])),
    ).status
    == 200

  let conn = read_db(h)
  let assert Ok([[sqlite.Text(actor)]]) =
    sqlite.query(
      conn,
      "SELECT actor FROM audit_log WHERE action = 'network.create'",
      [],
    )
  sqlite.close(conn)
  assert string.starts_with(actor, "key:")
}

/// An expired key is refused, and refused the way an unknown one is: the
/// expiry is part of the lookup, so there is nothing for a caller to learn
/// from the difference.
pub fn expired_api_key_is_refused_test() {
  let h = harness()
  org_named(h, "acme")
  let token = mint(h, "acme", "fortnight", "member")
  assert call(h, keyed(token, Get, "/api/orgs/acme")).status == 200

  // Reach past the API to age the key: the surface deliberately takes a
  // duration forward, and there is no way to ask it for the past. Named in
  // the WHERE, so this still ages one key once a second is minted.
  let assert Ok(conn) = db.open_primary(h.db_path)
  let assert Ok(_) =
    sqlite.exec(conn, "UPDATE api_keys SET expires_at = ? WHERE name = ?", [
      sqlite.Int(now_unix() - 1),
      sqlite.Text("fortnight"),
    ])
  sqlite.close(conn)

  // The 200-then-401 sandwich around that one write is the whole evidence:
  // the body deliberately says nothing about *why*, since expiry is folded
  // into the lookup so an expired key and one that never existed are the
  // same answer.
  assert call(h, keyed(token, Get, "/api/orgs/acme")).status == 401

  // It is still listed, so an operator can see what stopped working and
  // clean it up rather than wondering.
  let listed =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  assert string.contains(listed, "\"name\":\"fortnight\"")
}

/// A key does not outlive the org it is scoped to.
pub fn deleting_an_org_takes_its_keys_test() {
  let h = harness()
  org_named(h, "acme")
  let token = mint(h, "acme", "ci", "admin")
  assert call_json(
      h,
      Delete,
      "/api/orgs/acme",
      json.object([#("confirm", json.string("acme"))]),
    ).status
    == 200
  // Not a token that authenticates to a 404 forever: the row is gone with
  // the org, so the credential is gone too.
  assert call(h, keyed(token, Get, "/api/orgs/acme")).status == 401
}

// -- join keys ---------------------------------------------------------------

/// The one thing a join key can do, and that it really does it: the device
/// exists, it is in the network, and the zone was republished — which is what
/// separates a node that resolves from a row in a table.
pub fn a_join_key_adds_a_device_to_its_network_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let token = mint_join(h, "acme", "prod", "rack-1 provisioning")

  let joined =
    call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks/prod/devices")
        |> simulate.json_body(joining("nas")),
    )
  assert joined.status == 200
  let body = simulate.read_body(joined)
  assert string.contains(body, "\"label\":\"nas\"")
  // A zone mutation, so the answer carries the serial the publish produced.
  assert string.contains(body, "soa_serial")

  // In the network, not merely in the org: a device in no network appears in
  // no zone, and enrolling something invisible would be enrolling nothing.
  let detail =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/networks/prod")))
  assert string.contains(detail, "\"label\":\"nas\"")

  // And the trail names the credential, not the person who minted it.
  let conn = read_db(h)
  let assert Ok([[sqlite.Text(actor)]]) =
    sqlite.query(
      conn,
      "SELECT actor FROM audit_log WHERE action = 'network.join'",
      [],
    )
  sqlite.close(conn)
  assert string.starts_with(actor, "key:")
}

/// It is *one* network, and the refusal for any other is the refusal a
/// stranger gets: a leaked provisioning key must not be a way to find out
/// what else the org runs.
pub fn a_join_key_reaches_one_network_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("lab"))]),
    ).status
  org_with_network(h, "other", "prod")
  let token = mint_join(h, "acme", "prod", "rack-1")

  // Its own network: yes.
  assert call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks/prod/devices")
        |> simulate.json_body(joining("nas")),
    ).status
    == 200

  // A sibling network in the same org, and the same network name in another
  // org — both 404, neither 403: the key learns nothing either way.
  assert call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks/lab/devices")
        |> simulate.json_body(joining("nas")),
    ).status
    == 404
  assert call(
      h,
      keyed(token, Post, "/api/orgs/other/networks/prod/devices")
        |> simulate.json_body(joining("nas")),
    ).status
    == 404
}

/// Adding a device is the *only* thing it can do. Everything else in the
/// service goes through `check_org`, which refuses the whole family before it
/// reads a rank — so this is a sample of a closed set, not a list to keep up
/// to date.
pub fn a_join_key_can_do_nothing_else_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let token = mint_join(h, "acme", "prod", "rack-1")
  let refused = fn(res: wisp.Response) {
    assert res.status == 403
    assert string.contains(simulate.read_body(res), "join_key_forbidden")
    Nil
  }

  // Reads of the org it is scoped inside, including the network it may add
  // to: it may enrol, it may not look.
  refused(call(h, keyed(token, Get, "/api/orgs/acme")))
  refused(call(h, keyed(token, Get, "/api/orgs/acme/networks")))
  refused(call(h, keyed(token, Get, "/api/orgs/acme/networks/prod")))
  refused(call(h, keyed(token, Get, "/api/orgs/acme/devices")))
  refused(call(h, keyed(token, Get, "/api/me")))

  // The two older device routes, which between them are what this one route
  // replaced: neither is reachable, so a join key cannot attach a device it
  // did not create or leave one lying in the org attached to nothing.
  refused(call(
    h,
    keyed(token, Post, "/api/orgs/acme/devices")
      |> simulate.json_body(joining("stray")),
  ))
  refused(call(h, keyed(token, Put, "/api/orgs/acme/networks/prod/devices/d1")))
  refused(call(
    h,
    keyed(token, Delete, "/api/orgs/acme/networks/prod/devices/d1"),
  ))

  // Mutations of the network itself, and of credentials.
  refused(call(
    h,
    keyed(token, Post, "/api/orgs/acme/networks")
      |> simulate.json_body(json.object([#("name", json.string("mine"))])),
  ))
  refused(call(
    h,
    keyed(token, Delete, "/api/orgs/acme/networks/prod")
      |> simulate.json_body(json.object([#("confirm", json.string("prod"))])),
  ))
  refused(call(h, keyed(token, Get, "/api/orgs/acme/api-keys")))
  refused(call(
    h,
    keyed(token, Post, "/api/orgs/acme/api-keys")
      |> simulate.json_body(json.object([#("name", json.string("more"))])),
  ))
}

/// A person and an org key take the same route, at the floor the older device
/// routes carry — it is the same act, and a person should not need two calls
/// to do what a machine does in one.
pub fn everyone_else_joins_through_the_same_route_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")

  assert call_json(
      h,
      Post,
      "/api/orgs/acme/networks/prod/devices",
      joining("by-person"),
    ).status
    == 200

  let member = mint(h, "acme", "ci", "member")
  assert call(
      h,
      keyed(member, Post, "/api/orgs/acme/networks/prod/devices")
        |> simulate.json_body(joining("by-key")),
    ).status
    == 200

  // Two devices in the network, and a third that reuses a label is refused
  // rather than published as an ambiguity.
  let clash =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks/prod/devices",
      joining("by-person"),
    )
  assert clash.status == 409
  assert string.contains(simulate.read_body(clash), "already in this network")
}

/// The scope and the kind are one fact, in both directions and at both ends.
pub fn a_join_keys_scope_is_not_optional_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let ask = fn(body) { call_json(h, Post, "/api/orgs/acme/api-keys", body) }

  // `join` without a network is not a scope.
  let unscoped =
    ask(
      json.object([
        #("name", json.string("k")),
        #("role", json.string("join")),
      ]),
    )
  assert unscoped.status == 400
  assert string.contains(simulate.read_body(unscoped), "bad_scope")

  // A network on an org key would be a bound nothing enforces.
  let overscoped =
    ask(
      json.object([
        #("name", json.string("k")),
        #("role", json.string("member")),
        #("network", json.string("prod")),
      ]),
    )
  assert overscoped.status == 400
  assert string.contains(simulate.read_body(overscoped), "bad_scope")

  // A network the org does not have is a 404, not a scope.
  assert ask(
      json.object([
        #("name", json.string("k")),
        #("role", json.string("join")),
        #("network", json.string("nope")),
        #("expires_in", json.int(3600)),
      ]),
    ).status
    == 404

  // And a join key must say how long it lives. Nothing bounds how many
  // devices one enrols, so its lifetime is the only bound it has — and the
  // default of "no expiry" is right for a key in a secret store and wrong
  // for one in a provisioning image.
  let forever =
    ask(
      json.object([
        #("name", json.string("k")),
        #("role", json.string("join")),
        #("network", json.string("prod")),
      ]),
    )
  assert forever.status == 400
  assert string.contains(simulate.read_body(forever), "bad_expiry")
  // An org key is still allowed to be permanent.
  assert ask(
      json.object([
        #("name", json.string("ci")),
        #("role", json.string("member")),
      ]),
    ).status
    == 200

  // The listing says which network a join key is for, and says nothing for
  // an org key.
  let _ = mint_join(h, "acme", "prod", "scoped")
  let listed =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  assert string.contains(listed, "\"role\":\"join\"")
  assert string.contains(listed, "\"network\":\"prod\"")
}

/// A key's kind is settled when it is minted. Crossing the boundary would
/// need a network the key was never given, or would hand an already-deployed
/// secret a reach nobody audited it for.
pub fn a_keys_kind_cannot_be_patched_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let token = mint_join(h, "acme", "prod", "rack-1")
  let listed =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  let assert Ok(#(_, after_id)) = string.split_once(listed, "\"id\":\"")
  let assert Ok(#(key_id, _)) = string.split_once(after_id, "\"")
  let path = "/api/orgs/acme/api-keys/" <> key_id

  let promoted =
    call_json(h, Patch, path, json.object([#("role", json.string("admin"))]))
  assert promoted.status == 400
  assert string.contains(
    simulate.read_body(promoted),
    "fixed when it is minted",
  )

  // Still a join key, and still only that.
  assert call(h, keyed(token, Get, "/api/orgs/acme")).status == 403
  assert call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks/prod/devices")
        |> simulate.json_body(joining("nas")),
    ).status
    == 200

  // The parts that are not the kind still move.
  assert call_json(h, Patch, path, json.object([#("name", json.string("r2"))])).status
    == 200
}

/// Whose key was it? A row a key wrote answers on its own.
///
/// `key:<id>` alone is resolvable only by finding the `apikey.create` row
/// that named it — which survives revocation, but sits an unbounded number of
/// pages back in a log served fifty at a time. The provenance an incident
/// actually needs is on the row in front of you, and it is still there after
/// the key it describes has been revoked.
pub fn a_row_a_key_wrote_names_the_key_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let token = mint_join(h, "acme", "prod", "rack-1 provisioning")
  assert call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks/prod/devices")
        |> simulate.json_body(joining("nas")),
    ).status
    == 200

  // Revoke it, which is what you do when a provisioning image leaks — and
  // which takes the row that would otherwise have answered this.
  let listed =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  let assert Ok(#(_, after_id)) = string.split_once(listed, "\"id\":\"")
  let assert Ok(#(key_id, _)) = string.split_once(after_id, "\"")
  assert call(h, authed(h, Delete, "/api/orgs/acme/api-keys/" <> key_id)).status
    == 200

  let conn = read_db(h)
  let assert Ok([[sqlite.Text(actor), sqlite.Text(detail)]]) =
    sqlite.query(
      conn,
      "SELECT actor, detail FROM audit_log WHERE action = 'network.join'",
      [],
    )
  // Nothing is left to look the key up in.
  let assert Ok([[sqlite.Int(0)]]) =
    sqlite.query(conn, "SELECT count(*) FROM api_keys", [])
  sqlite.close(conn)

  // Which key, what it was called, and who minted it — all on the one row.
  assert actor == "key:" <> key_id
  assert string.contains(detail, "\"key_name\":\"rack-1 provisioning\"")
  assert string.contains(detail, "\"key_minted_by\":\"admin@example.com\"")
  // And what it did.
  assert string.contains(detail, "\"label\":\"nas\"")
  assert string.contains(detail, "\"network\":\"prod\"")
}

/// A person's row carries no credential fields: the actor column already
/// names them, and there is nothing else to say.
pub fn a_row_a_person_wrote_stays_bare_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let conn = read_db(h)
  let assert Ok([[sqlite.Text(detail)]]) =
    sqlite.query(
      conn,
      "SELECT detail FROM audit_log WHERE action = 'network.create'",
      [],
    )
  sqlite.close(conn)
  assert detail == "{\"name\":\"prod\"}"
}

/// The join route is one act or none.
///
/// Three inserts share a transaction, and that is what makes the route safe
/// to hand a credential whose only power is this: a half-done enrolment would
/// leave a device in the org, attached to nothing, that the join key can
/// neither see nor remove. The second insert is the one to fail — a key
/// already bound to another device trips the global live-key index — so the
/// first has already written by the time it does.
pub fn a_failed_join_leaves_nothing_behind_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let token = mint_join(h, "acme", "prod", "rack-1")
  let shared = nk()
  let joining_with = fn(label) {
    json.object([
      #("label", json.string(label)),
      #("nk", json.string(shared)),
    ])
  }
  assert call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks/prod/devices")
        |> simulate.json_body(joining_with("first")),
    ).status
    == 200

  // Same key, different label: the device row goes in, the key row is
  // refused, and the whole thing has to come back out.
  let second =
    call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks/prod/devices")
        |> simulate.json_body(joining_with("second")),
    )
  assert second.status == 409

  let conn = read_db(h)
  let assert Ok([[sqlite.Int(orphans)]]) =
    sqlite.query(conn, "SELECT count(*) FROM devices WHERE label = ?", [
      sqlite.Text("second"),
    ])
  let assert Ok([[sqlite.Int(devices)]]) =
    sqlite.query(conn, "SELECT count(*) FROM devices", [])
  sqlite.close(conn)
  assert orphans == 0
  assert devices == 1
}

/// The join route re-checks what the older device route checks, because it is
/// the route a machine uses and the older one is not.
pub fn the_join_route_validates_what_it_stores_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let token = mint_join(h, "acme", "prod", "rack-1")
  let post = fn(body) {
    call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks/prod/devices")
        |> simulate.json_body(body),
    )
  }
  let bad = fn(body, code) {
    let answer = post(body)
    assert answer.status == 400
    assert string.contains(simulate.read_body(answer), code)
    Nil
  }

  bad(
    json.object([
      #("label", json.string("Not A Label")),
      #("nk", json.string(nk())),
    ]),
    "invalid_label",
  )
  bad(
    json.object([
      #("label", json.string("nas")),
      #("nk", json.string("not-a-key")),
    ]),
    "invalid_nk",
  )
  // A hint carrying whitespace is extra fields in a membership record, not
  // one value — which is what makes a client refuse the whole record.
  bad(
    json.object([
      #("label", json.string("nas")),
      #("nk", json.string(nk())),
      #("relay", json.string("one two")),
    ]),
    "bad_hint",
  )

  // And the hints it accepts are the hints it stores.
  assert post(
      json.object([
        #("label", json.string("nas")),
        #("nk", json.string(nk())),
        #("relay", json.string("relay.example")),
        #("addr", json.string("203.0.113.7:1234")),
      ]),
    ).status
    == 200
  let conn = read_db(h)
  let assert Ok([[sqlite.Text(relay), sqlite.Text(addr)]]) =
    sqlite.query(conn, "SELECT relay, addr FROM devices WHERE label = ?", [
      sqlite.Text("nas"),
    ])
  sqlite.close(conn)
  assert relay == "relay.example"
  assert addr == "203.0.113.7:1234"
}

/// A join key does not outlive the network it names.
pub fn deleting_a_network_takes_its_join_keys_test() {
  let h = harness()
  org_with_network(h, "acme", "prod")
  let token = mint_join(h, "acme", "prod", "rack-1")
  assert call_json(
      h,
      Delete,
      "/api/orgs/acme/networks/prod",
      json.object([#("confirm", json.string("prod"))]),
    ).status
    == 200
  // Not a narrower credential — a token that can never be used again, so the
  // row goes with the network rather than dangling past it.
  assert call(
      h,
      keyed(token, Post, "/api/orgs/acme/networks/prod/devices")
        |> simulate.json_body(joining("nas")),
    ).status
    == 401
  let listed =
    simulate.read_body(call(h, authed(h, Get, "/api/orgs/acme/api-keys")))
  assert !string.contains(listed, "rack-1")
}

// ---- the cloud data plane ---------------------------------------------------

/// Mints a data-plane key the way the operator CLI does, straight against the
/// table: there is deliberately no HTTP route that mints one, so a test cannot
/// go through the API to get it either.
fn mint_dataplane(h: Harness, name: String) -> String {
  let assert Ok(conn) = db.open_primary(h.db_path)
  let assert Ok(#(token, _prefix)) =
    dataplane_key.create(conn, id.new(), name, None, now_unix())
  sqlite.close(conn)
  token
}

/// Turns hosting on for a network, as an org admin.
fn host_network(h: Harness, slug: String, network: String, on: Bool) -> Int {
  call_json(
    h,
    Put,
    "/api/orgs/" <> slug <> "/networks/" <> network <> "/cloud-hosting/enabled",
    json.object([#("enabled", json.bool(on))]),
  ).status
}

/// The gate the whole credential rests on: a data-plane key sees every org's
/// hosted networks, and *only* through `/dp/v1`. Against the org API it is
/// refused outright rather than being treated as a member of anything — so a
/// leaked one cannot read a file, a roster, or another credential.
pub fn dataplane_key_reaches_only_the_dp_api_test() {
  let h = harness()
  org_named(h, "acme")
  let token = mint_dataplane(h, "fleet")

  // The one surface it has.
  assert call(h, keyed(token, Get, "/dp/v1/networks")).status == 200

  // And nothing else, including an org that exists and one that does not.
  assert call(h, keyed(token, Get, "/api/orgs/acme")).status == 403
  assert call(h, keyed(token, Get, "/api/orgs/nope")).status == 403
  assert call(h, keyed(token, Get, "/api/orgs/acme/networks")).status == 403
  assert call(h, keyed(token, Get, "/api/orgs/acme/api-keys")).status == 403
  assert call(h, keyed(token, Get, "/api/me")).status == 403

  // The converse: an org key is not a data-plane key, however privileged.
  let org_token = mint(h, "acme", "ci", "admin")
  assert call(h, keyed(org_token, Get, "/dp/v1/networks")).status == 403
  // Nor is a session, which is a person and not a fleet.
  assert call(h, authed(h, Get, "/dp/v1/networks")).status == 403
}

/// Hosting is off until an org admin turns it on, and the document the fleet
/// polls is what carries that decision.
pub fn hosting_is_off_until_an_admin_enables_it_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  let token = mint_dataplane(h, "fleet")

  // Default off: the network exists and the fleet is not told to host it.
  let before = simulate.read_body(call(h, keyed(token, Get, "/dp/v1/networks")))
  assert !string.contains(before, "prod")

  assert host_network(h, "acme", "prod", True) == 200
  let after = simulate.read_body(call(h, keyed(token, Get, "/dp/v1/networks")))
  assert string.contains(after, "prod")
  // The membership domain, verbatim what the node is configured with.
  assert string.contains(after, "prod.acme.sync.test")

  // And off again removes it, which is what starts a teardown.
  assert host_network(h, "acme", "prod", False) == 200
  let disabled =
    simulate.read_body(call(h, keyed(token, Get, "/dp/v1/networks")))
  assert !string.contains(disabled, "prod.acme.sync.test")
}

/// Registration is idempotent and publishes: the zone names the key on the
/// commit, which is what closes the window a restarted pod waits in.
pub fn registering_a_hosted_device_publishes_and_is_idempotent_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  assert host_network(h, "acme", "prod", True) == 200
  let token = mint_dataplane(h, "fleet")
  let key = nk()
  let body =
    json.object([#("label", json.string("cloud-1")), #("nk", json.string(key))])

  let registered =
    call(
      h,
      keyed(token, Put, "/dp/v1/networks/acme/prod/device")
        |> simulate.json_body(body),
    )
  assert registered.status == 200

  // The zone carries it now — no second step, and no TTL to wait out.
  let conn = read_db(h)
  let assert Ok(rows) =
    sqlite.query(conn, "SELECT count(*) FROM presigned_rrsets WHERE name = ?", [
      sqlite.Text("_synchronicity.prod.acme.sync.test."),
    ])
  sqlite.close(conn)
  // Present at all is the claim: the membership name is signed and served
  // the moment the registration commits, which is what the reconciler's
  // next open depends on. How many rows that is (the RRset and its RRSIG)
  // is the signer's business, not this test's.
  assert rows != [[sqlite.Int(0)]]

  // The same key again is a no-op, because a reconciler re-registers on every
  // provisioning and must not churn the zone by doing so.
  let again =
    call(
      h,
      keyed(token, Put, "/dp/v1/networks/acme/prod/device")
        |> simulate.json_body(body),
    )
  assert again.status == 200

  // And the document now reports the device, which is how a disk-less pod
  // tells "never joined" from "identity to recover".
  let listed = simulate.read_body(call(h, keyed(token, Get, "/dp/v1/networks")))
  assert string.contains(listed, "cloud-1")
  assert string.contains(listed, key)
}

/// The reserved namespace, in both directions: customers cannot mint a device
/// that impersonates the fleet, and the fleet cannot register anything else.
pub fn the_cloud_label_namespace_is_reserved_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  assert host_network(h, "acme", "prod", True) == 200

  // A customer cannot take a slot label.
  let taken =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks/prod/devices",
      json.object([
        #("label", json.string("cloud-1")),
        #("nk", json.string(nk())),
      ]),
    )
  assert taken.status == 409
  assert string.contains(simulate.read_body(taken), "reserved-label")

  // A label that merely looks like one is not reserved: the rule is
  // `cloud-<digits>`, and a customer's `cloud-nine` is their own business.
  assert call_json(
      h,
      Post,
      "/api/orgs/acme/networks/prod/devices",
      json.object([
        #("label", json.string("cloud-nine")),
        #("nk", json.string(nk())),
      ]),
    ).status
    == 200

  // And the fleet cannot register outside it.
  let token = mint_dataplane(h, "fleet")
  let refused =
    call(
      h,
      keyed(token, Put, "/dp/v1/networks/acme/prod/device")
        |> simulate.json_body(
          json.object([
            #("label", json.string("nas")),
            #("nk", json.string(nk())),
          ]),
        ),
    )
  assert refused.status == 400
}

/// A network nobody enabled is not registrable, however good the credential —
/// the toggle is the gate, not just a listing filter.
pub fn registering_into_an_unhosted_network_is_refused_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  let token = mint_dataplane(h, "fleet")
  let refused =
    call(
      h,
      keyed(token, Put, "/dp/v1/networks/acme/prod/device")
        |> simulate.json_body(
          json.object([
            #("label", json.string("cloud-1")),
            #("nk", json.string(nk())),
          ]),
        ),
    )
  assert refused.status != 200
}

/// Disabling takes the hosted device out of the zone in the same commit, so a
/// customer who turns hosting off stops publishing the fleet's key at once.
pub fn disabling_hosting_removes_the_hosted_device_from_the_zone_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  assert host_network(h, "acme", "prod", True) == 200
  let token = mint_dataplane(h, "fleet")
  let assert 200 =
    call(
      h,
      keyed(token, Put, "/dp/v1/networks/acme/prod/device")
        |> simulate.json_body(
          json.object([
            #("label", json.string("cloud-1")),
            #("nk", json.string(nk())),
          ]),
        ),
    ).status

  assert host_network(h, "acme", "prod", False) == 200

  let conn = read_db(h)
  let assert Ok(devices) =
    sqlite.query(conn, "SELECT count(*) FROM devices WHERE label = ?", [
      sqlite.Text("cloud-1"),
    ])
  let assert Ok(stamped) =
    sqlite.query(
      conn,
      "SELECT count(*) FROM cloud_collect_queue WHERE network_name = ?",
      [sqlite.Text("prod")],
    )
  sqlite.close(conn)
  // Gone, not merely unpublished: the retention hold is over storage, and the
  // device row is what the zone is built from.
  assert devices == [[sqlite.Int(0)]]
  // And the clock the retention hold runs on has started.
  assert stamped == [[sqlite.Int(1)]]
}

/// The steady-state poll is a 304, which is what makes a 60-second fleet-wide
/// cadence cheap.
pub fn the_desired_document_is_conditional_test() {
  let h = harness()
  org_named(h, "acme")
  let token = mint_dataplane(h, "fleet")
  let first = call(h, keyed(token, Get, "/dp/v1/networks"))
  assert first.status == 200
  let assert Ok(tag) = list.key_find(first.headers, "etag")

  let again =
    call(
      h,
      keyed(token, Get, "/dp/v1/networks")
        |> simulate.header("if-none-match", tag),
    )
  assert again.status == 304
}

// ---- the retention hold ------------------------------------------------------

/// A network that was hosted and has since been switched off — the state the
/// retention hold runs over, and the only state the `collect` list is about.
fn offboarded(h: Harness, slug: String, network: String) -> Nil {
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/" <> slug <> "/networks",
      json.object([#("name", json.string(network))]),
    ).status
  assert host_network(h, slug, network, True) == 200
  assert host_network(h, slug, network, False) == 200
  Nil
}

/// Backdates the retention stamp, which is the only way a test reaches the far
/// side of a thirty-day hold: the API takes a *decision* and stamps the clock
/// itself, and there is deliberately no way to ask it for a date in the past.
fn age_hold(h: Harness, network: String, seconds: Int) -> Nil {
  let assert Ok(conn) = db.open_primary(h.db_path)
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "UPDATE cloud_collect_queue SET disabled_at = ? WHERE network_name = ?",
      [sqlite.Int(now_unix() - seconds), sqlite.Text(network)],
    )
  sqlite.close(conn)
}

/// The desired-state document, as the fleet reads it.
fn dp_document(h: Harness, token: String) -> String {
  simulate.read_body(call(h, keyed(token, Get, "/dp/v1/networks")))
}

/// The document under an `If-None-Match`, which is how the fleet actually
/// polls it.
fn dp_poll(h: Harness, token: String, tag: String) -> wisp.Response {
  call(
    h,
    keyed(token, Get, "/dp/v1/networks")
      |> simulate.header("if-none-match", tag),
  )
}

fn soa_serial(h: Harness) -> Int {
  let conn = read_db(h)
  let assert Ok(meta) = model.read_meta(conn)
  sqlite.close(conn)
  meta.soa_serial
}

/// How many networks are queued for collection — the instruction itself,
/// as distinct from `collect_rows`, which counts the history of collections
/// that already happened.
fn queued_rows(h: Harness) -> List(List(sqlite.Value)) {
  let conn = read_db(h)
  let assert Ok(rows) =
    sqlite.query(conn, "SELECT count(*) FROM cloud_collect_queue", [])
  sqlite.close(conn)
  rows
}

fn collect_rows(h: Harness) -> List(List(sqlite.Value)) {
  let conn = read_db(h)
  let assert Ok(rows) =
    sqlite.query(conn, "SELECT count(*) FROM audit_log WHERE action = ?", [
      sqlite.Text("cloud-hosting.storage.collect"),
    ])
  sqlite.close(conn)
  rows
}

/// The hold is a hold. An offboarded network's storage is not offered for
/// collection until thirty days have run, and then it is — which is the whole
/// of the promise §6 makes and the thing that was missing.
pub fn storage_is_collectable_only_after_the_retention_hold_test() {
  let h = harness()
  org_named(h, "acme")
  offboarded(h, "acme", "prod")
  let token = mint_dataplane(h, "fleet")

  // Switched off a moment ago. It has already left `networks` — that is the
  // teardown — and it has not joined `collect`, so the name appears nowhere in
  // the document at all, which makes its absence checkable as one claim.
  assert !string.contains(dp_document(h, token), "prod")

  // Twenty-nine days is still inside the hold, and that is the point of
  // having one: re-enabling here is a cheap re-provision, and the bytes have
  // to still be there for it.
  age_hold(h, "prod", 29 * 86_400)
  assert !string.contains(dp_document(h, token), "prod")

  // Thirty-one days is not.
  age_hold(h, "prod", 31 * 86_400)
  let due = dp_document(h, token)
  assert string.contains(
    due,
    "\"collect\":[{\"org\":\"acme\",\"network\":\"prod\"}]",
  )
}

/// The hole a serial-only generation would leave, and the reason the `ETag`
/// carries the due set too.
///
/// A hold elapses because a *clock* passed, not because anything committed:
/// no zone fact changes, so the SOA serial sits exactly where it was. A fleet
/// polling with `If-None-Match` against a tag built from the serial alone
/// would be handed 304s for ever and never learn that a tenant's storage fell
/// due — the collection would not be late, it would never happen.
pub fn a_hold_falling_due_moves_the_etag_test() {
  let h = harness()
  org_named(h, "acme")
  offboarded(h, "acme", "prod")
  let token = mint_dataplane(h, "fleet")

  let first = call(h, keyed(token, Get, "/dp/v1/networks"))
  assert first.status == 200
  let assert Ok(tag) = list.key_find(first.headers, "etag")
  // Nothing has changed, so the steady-state poll is the cheap 304 it is meant
  // to be. That is the behaviour the rest of this test has to survive.
  assert dp_poll(h, token, tag).status == 304

  let serial = soa_serial(h)
  age_hold(h, "prod", 31 * 86_400)
  // The evidence that this is a real hole and not a hypothetical one: the
  // serial — the document's `generation` — is untouched by a hold elapsing.
  assert soa_serial(h) == serial

  let after = dp_poll(h, token, tag)
  assert after.status == 200
  assert string.contains(simulate.read_body(after), "prod")
}

/// The other half of the loop: the data plane reports the deletion, and the
/// network stops being offered. Without this the list would repeat the same
/// instruction on every poll for the rest of the deployment's life.
pub fn collecting_storage_clears_the_network_from_the_list_test() {
  let h = harness()
  org_named(h, "acme")
  offboarded(h, "acme", "prod")
  age_hold(h, "prod", 31 * 86_400)
  let token = mint_dataplane(h, "fleet")
  assert string.contains(dp_document(h, token), "prod")

  let done = call(h, keyed(token, Delete, "/dp/v1/networks/acme/prod/storage"))
  assert done.status == 200
  assert string.contains(simulate.read_body(done), "\"collected\":true")

  assert !string.contains(dp_document(h, token), "prod")

  // The retry a partially-failed collection makes — the pod died between the
  // last object and the call, and has no way to know which — is a 200 no-op
  // rather than a 404, and does not write a second page of history.
  let again = call(h, keyed(token, Delete, "/dp/v1/networks/acme/prod/storage"))
  assert again.status == 200
  assert string.contains(simulate.read_body(again), "\"collected\":false")

  assert collect_rows(h) == [[sqlite.Int(1)]]
}

/// The hold is enforced on the *write*, not only in the list.
///
/// The `collect` list withholding a network is a hint; this is the call that
/// destroys the bytes. A replayed instruction, a fleet bug, or a leaked
/// `synchdp_` token must not be able to collect inside the customer's window
/// to change their mind — the authority that owns the clock checks it here.
pub fn collecting_inside_the_retention_hold_is_refused_test() {
  let h = harness()
  org_named(h, "acme")
  offboarded(h, "acme", "prod")
  let token = mint_dataplane(h, "fleet")

  // One second in: the list correctly offers nothing...
  assert !string.contains(dp_document(h, token), "prod")
  // ...and the write refuses too, which is the half that was missing.
  let early = call(h, keyed(token, Delete, "/dp/v1/networks/acme/prod/storage"))
  assert early.status == 409
  assert string.contains(simulate.read_body(early), "retention-hold")
  // The clock is untouched, so the collection still happens on time.
  assert queued_rows(h) == [[sqlite.Int(1)]]

  age_hold(h, "prod", 31 * 86_400)
  assert call(h, keyed(token, Delete, "/dp/v1/networks/acme/prod/storage")).status
    == 200
}

/// Deleting a network does not delete the instruction to collect its bytes.
///
/// The clock used to live on the network row, so the ordinary delete button
/// took it — and the fleet then held that customer's storage for ever, which
/// is the exact bug the collect list exists to fix. The queue outlives the
/// row because the bytes do.
pub fn deleting_a_hosted_network_still_queues_its_storage_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  assert host_network(h, "acme", "prod", True) == 200

  // A heartbeat first: its row is a child of the network, and an un-cascaded
  // foreign key used to make every hosted network permanently undeletable.
  let token = mint_dataplane(h, "fleet")
  assert call_json(
      h,
      Put,
      "/api/orgs/acme/networks/prod/cloud-hosting/enabled",
      json.object([#("enabled", json.bool(True))]),
    ).status
    == 200

  let deleted =
    call_json(
      h,
      Delete,
      "/api/orgs/acme/networks/prod",
      json.object([#("confirm", json.string("prod"))]),
    )
  assert deleted.status == 200

  // The network is gone and the instruction is not.
  assert queued_rows(h) == [[sqlite.Int(1)]]
  age_hold(h, "prod", 31 * 86_400)
  assert string.contains(dp_document(h, token), "prod")
}

/// Disabling hosting on a network that never had it starts no clock.
///
/// Otherwise a dashboard syncing its initial state, or an IaC provider
/// writing `cloud_hosted = false` explicitly, has the fleet delete prefixes
/// thirty days later for a network that was never hosted.
pub fn disabling_a_never_hosted_network_queues_nothing_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  assert host_network(h, "acme", "prod", False) == 200
  assert queued_rows(h) == [[sqlite.Int(0)]]
}

/// The reserved namespace is guarded on every route that touches an existing
/// device, not only on creation.
///
/// Guarding creation alone guarded nothing: a member who can add a key to the
/// hosted device seizes the identity an operator-run pod holds the customer's
/// replica under, and an admin who can delete it destroys that identity —
/// both just as thoroughly as one who could have created the label.
pub fn a_customer_cannot_touch_the_hosted_slots_device_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  assert host_network(h, "acme", "prod", True) == 200

  let token = mint_dataplane(h, "fleet")
  let registered =
    call(
      h,
      keyed(token, Put, "/dp/v1/networks/acme/prod/device")
        |> simulate.json_body(
          json.object([
            #("label", json.string("cloud-1")),
            #("nk", json.string(nk())),
          ]),
        ),
    )
  assert registered.status == 200

  let conn = read_db(h)
  let assert Ok([[sqlite.Text(device_id)]]) =
    sqlite.query(conn, "SELECT id FROM devices WHERE label = ?", [
      sqlite.Text("cloud-1"),
    ])
  sqlite.close(conn)

  // Adding a key to it: the takeover.
  let seized =
    call_json(
      h,
      Post,
      "/api/orgs/acme/devices/" <> device_id <> "/keys",
      json.object([#("nk", json.string(nk()))]),
    )
  assert seized.status == 409
  assert string.contains(simulate.read_body(seized), "reserved-label")

  // Deleting it: the destruction.
  let removed =
    call_json(
      h,
      Delete,
      "/api/orgs/acme/devices/" <> device_id,
      json.object([#("confirm", json.string("cloud-1"))]),
    )
  assert removed.status == 409
  assert string.contains(simulate.read_body(removed), "reserved-label")
}

/// Collecting a live tenant's storage is the catastrophic operation in this
/// design, so the API must not be able to *say* it happened — whatever the
/// fleet believes it did.
pub fn collecting_a_hosted_networks_storage_is_refused_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  assert host_network(h, "acme", "prod", True) == 200
  let token = mint_dataplane(h, "fleet")

  let refused =
    call(h, keyed(token, Delete, "/dp/v1/networks/acme/prod/storage"))
  assert refused.status == 409
  assert string.contains(simulate.read_body(refused), "cloud-hosting-enabled")
  // Nothing recorded: the refusal is about the audit row as much as the write,
  // since a row claiming a hosted tenant's bytes were collected is a claim
  // somebody would have to disprove later.
  assert collect_rows(h) == [[sqlite.Int(0)]]

  // And the route is the fleet's, like the rest of `/dp/v1`: a signed-in
  // admin of the very org that owns the network cannot record a collection.
  assert call(h, authed(h, Delete, "/dp/v1/networks/acme/prod/storage")).status
    == 403
}

/// An expired data-plane key is refused like any other credential.
pub fn expired_dataplane_key_is_refused_test() {
  let h = harness()
  let token = mint_dataplane(h, "fleet")
  let assert Ok(conn) = db.open_primary(h.db_path)
  let assert Ok(_) =
    sqlite.exec(conn, "UPDATE dataplane_keys SET expires_at = ?", [
      sqlite.Int(now_unix() - 1),
    ])
  sqlite.close(conn)
  assert call(h, keyed(token, Get, "/dp/v1/networks")).status == 401
}

/// Disabling twice must not restart the retention clock: a reconciler that
/// re-sends the same state is ordinary, and each restamp would push the
/// collection another hold out — storage retained, and billed, for ever.
pub fn disabling_twice_does_not_restart_the_retention_clock_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  assert host_network(h, "acme", "prod", True) == 200
  assert host_network(h, "acme", "prod", False) == 200

  // Backdate the stamp, then disable again as a retrying caller would.
  let assert Ok(conn) = db.open_primary(h.db_path)
  let long_ago = now_unix() - 1_000_000
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "UPDATE cloud_collect_queue SET disabled_at = ? WHERE network_name = ?",
      [
        sqlite.Int(long_ago),
        sqlite.Text("prod"),
      ],
    )
  sqlite.close(conn)
  assert host_network(h, "acme", "prod", False) == 200

  let conn = read_db(h)
  let assert Ok(rows) =
    sqlite.query(
      conn,
      "SELECT disabled_at FROM cloud_collect_queue WHERE network_name = ?",
      [sqlite.Text("prod")],
    )
  sqlite.close(conn)
  assert rows == [[sqlite.Int(long_ago)]]
}

/// And re-enabling clears it, so a network that comes back is not carrying a
/// deadline from its last life.
pub fn re_enabling_clears_the_retention_clock_test() {
  let h = harness()
  org_named(h, "acme")
  let assert 200 =
    call_json(
      h,
      Post,
      "/api/orgs/acme/networks",
      json.object([#("name", json.string("prod"))]),
    ).status
  assert host_network(h, "acme", "prod", True) == 200
  assert host_network(h, "acme", "prod", False) == 200
  assert host_network(h, "acme", "prod", True) == 200

  // Re-enabling removes the queue row outright rather than nulling a column:
  // the instruction to delete this tenant's bytes must not survive the
  // decision to keep hosting them.
  let conn = read_db(h)
  let assert Ok(rows) =
    sqlite.query(
      conn,
      "SELECT count(*) FROM cloud_collect_queue WHERE network_name = ?",
      [sqlite.Text("prod")],
    )
  sqlite.close(conn)
  assert rows == [[sqlite.Int(0)]]
}
