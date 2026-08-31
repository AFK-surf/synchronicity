//// Cue per-Workspace provisioning:
//// `PUT /internal/v1/integrations/cue/workspaces/<cue_workspace_id>`.

import api/auth_api
import api/browse_api
import api/reads
import api/router
import config
import email/mailer
import fixtures.{tmp_db}
import gleam/erlang/process
import gleam/http.{Post, Put}
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/string
import store/db
import store/migrate
import store/sqlite
import util/id
import wisp
import wisp/simulate
import zone/publish

const secret = "cue-provisioning-shared-secret-0123456789"

const hub_org = "org-hub"

const hub_provider = "oidcp-hub"

fn cue_cfg() -> config.CueProvisioning {
  config.CueProvisioning(secret, hub_provider)
}

type Env {
  Env(ctx: router.Context, db_path: String)
}

fn setup() -> Env {
  setup_full(
    Some(cue_cfg()),
    fn(_conn) { Nil },
    fn(_conn, _now, _actor, _change) { Ok(1) },
  )
}

fn setup_seeded(seed: fn(sqlite.Connection) -> Nil) -> Env {
  setup_full(Some(cue_cfg()), seed, fn(_conn, _now, _actor, _change) { Ok(1) })
}

/// A migrated database carrying the shared hub org + its OIDC provider (every
/// Cue identity anchors to this one provider); `seed` adds any extra rows,
/// before the pool opens so no second writer contends for the file.
fn setup_full(
  cue: Option(config.CueProvisioning),
  seed: fn(sqlite.Connection) -> Nil,
  publish_in_tx: fn(sqlite.Connection, Int, String, publish.Change) ->
    Result(Int, publish.PublishError),
) -> Env {
  let db_path = tmp_db()
  let assert Ok(conn) = db.open_primary(db_path)
  let assert Ok(_) = migrate.migrate(conn)
  // The zone identity (zone_meta + a CSK), so the create/enroll paths can build
  // a device domain from the apex. The publish itself stays stubbed below.
  let _ = fixtures.zone_boot(conn)
  let assert Ok(_) =
    sqlite.exec(conn, "INSERT INTO orgs VALUES (?, 'hub', 'Hub', 0)", [
      sqlite.Text(hub_org),
    ])
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO oidc_providers
       VALUES (?, ?, 'https://cue.test', 'cid', 'csec',
               'https://cue.test/authorize', 'https://cue.test/token', NULL, 0)",
      [sqlite.Text(hub_provider), sqlite.Text(hub_org)],
    )
  seed(conn)
  sqlite.close(conn)
  let assert Ok(api_pool) = db.start_primary_pool(db_path, 2)
  let auth =
    auth_api.AuthContext(
      reads.Reads(api_pool),
      "http://cp.test",
      mailer.LogOnly,
      None,
      None,
      // The network write publishes the zone; stub the publish (returns a
      // serial) so the create path exercises the whole transaction.
      publish_in_tx,
      fn() { Nil },
      cue,
    )
  let browse =
    browse_api.Browse(
      process.new_name("cue_test_agents_" <> id.new()),
      "https://cp.test/agent/v1/attach",
    )
  let ctx =
    router.Context(
      "anchor",
      "ds",
      router.Writable(auth),
      router.ExternalZone(api_pool),
      browse,
    )
  Env(ctx, db_path)
}

fn body(ws_name: String, subject: String, email: String) -> json.Json {
  json.object([
    #("name", json.string(ws_name)),
    #(
      "owner",
      json.object([
        #("subject", json.string(subject)),
        #("email", json.string(email)),
        #("name", json.string("Owner")),
      ]),
    ),
  ])
}

fn put(
  env: Env,
  workspace_id: String,
  token: Option(String),
  payload: json.Json,
) -> wisp.Response {
  let base =
    simulate.request(
      Put,
      "/internal/v1/integrations/cue/workspaces/" <> workspace_id,
    )
    |> simulate.json_body(payload)
  let req = case token {
    Some(t) -> simulate.header(base, "authorization", "Bearer " <> t)
    None -> base
  }
  router.handle(req, env.ctx)
}

fn count(env: Env, sql: String, params: List(sqlite.Value)) -> Int {
  let assert Ok(conn) = db.open_read(env.db_path)
  let assert Ok([[sqlite.Int(n)]]) = sqlite.query(conn, sql, params)
  sqlite.close(conn)
  n
}

fn workspace_mapping(env: Env, workspace_id: String) -> #(String, String) {
  let assert Ok(conn) = db.open_read(env.db_path)
  let assert Ok([[sqlite.Text(org_id), sqlite.Text(network_id)]]) =
    sqlite.query(
      conn,
      "SELECT org_id, network_id FROM cue_workspace_orgs
       WHERE cue_workspace_id = ?",
      [sqlite.Text(workspace_id)],
    )
  sqlite.close(conn)
  #(org_id, network_id)
}

pub fn create_provisions_org_network_identity_membership_test() {
  let env = setup()
  let resp =
    put(env, "wsp_1", Some(secret), body("WS One", "usr_alice", "a@cue.test"))
  assert resp.status == 200
  let out = simulate.read_body(resp)
  assert string.contains(out, "\"created\":true")

  // One workspace mapping, one workspace org (hub is the only other), one
  // default network, one identity under the hub provider, one owner membership.
  assert count(
      env,
      "SELECT count(*) FROM cue_workspace_orgs WHERE cue_workspace_id = ?",
      [
        sqlite.Text("wsp_1"),
      ],
    )
    == 1
  assert count(env, "SELECT count(*) FROM networks WHERE name = 'default'", [])
    == 1
  assert count(env, "SELECT count(*) FROM auth_identities WHERE subject = ?", [
      sqlite.Text("usr_alice"),
    ])
    == 1
  assert count(
      env,
      "SELECT count(*) FROM org_members m
       JOIN cue_workspace_orgs w ON w.org_id = m.org_id
       WHERE w.cue_workspace_id = ? AND m.role = 'owner'",
      [sqlite.Text("wsp_1")],
    )
    == 1
}

pub fn provision_is_idempotent_test() {
  let env = setup()
  let first =
    put(env, "wsp_2", Some(secret), body("WS Two", "usr_bob", "b@cue.test"))
  assert first.status == 200
  assert string.contains(simulate.read_body(first), "\"created\":true")

  let second =
    put(env, "wsp_2", Some(secret), body("WS Two", "usr_bob", "b@cue.test"))
  assert second.status == 200
  assert string.contains(simulate.read_body(second), "\"created\":false")

  // No duplicates on repeat.
  assert count(env, "SELECT count(*) FROM cue_workspace_orgs", []) == 1
  assert count(env, "SELECT count(*) FROM networks", []) == 1
  assert count(env, "SELECT count(*) FROM auth_identities WHERE subject = ?", [
      sqlite.Text("usr_bob"),
    ])
    == 1
  assert count(env, "SELECT count(*) FROM org_members", []) == 1
}

pub fn same_owner_two_workspaces_reuses_identity_test() {
  let env = setup()
  let a = put(env, "wsp_a", Some(secret), body("A", "usr_carol", "c@cue.test"))
  assert a.status == 200
  let b = put(env, "wsp_b", Some(secret), body("B", "usr_carol", "c@cue.test"))
  assert b.status == 200

  // Two workspace orgs + networks, but ONE identity/user reused across both,
  // with a membership in each org.
  assert count(env, "SELECT count(*) FROM cue_workspace_orgs", []) == 2
  assert count(env, "SELECT count(*) FROM networks", []) == 2
  assert count(env, "SELECT count(*) FROM users WHERE email = ?", [
      sqlite.Text("c@cue.test"),
    ])
    == 1
  assert count(env, "SELECT count(*) FROM auth_identities WHERE subject = ?", [
      sqlite.Text("usr_carol"),
    ])
    == 1
  assert count(env, "SELECT count(*) FROM org_members", []) == 2
}

pub fn email_conflict_requires_explicit_link_test() {
  let env =
    setup_seeded(fn(conn) {
      let assert Ok(_) =
        sqlite.exec(
          conn,
          "INSERT INTO users VALUES ('seed-dave', 'dave@cue.test', 'D', 0)",
          [],
        )
      Nil
    })
  // A workspace whose owner's email belongs to a different, unlinked user.
  let resp =
    put(env, "wsp_d", Some(secret), body("D", "usr_dave", "dave@cue.test"))
  assert resp.status == 409
  assert string.contains(simulate.read_body(resp), "explicit_link_required")
  // Nothing partial: no workspace org, no identity for the subject.
  assert count(env, "SELECT count(*) FROM cue_workspace_orgs", []) == 0
  assert count(env, "SELECT count(*) FROM auth_identities WHERE subject = ?", [
      sqlite.Text("usr_dave"),
    ])
    == 0
}

pub fn wrong_secret_is_unauthenticated_test() {
  let env = setup()
  let resp =
    put(
      env,
      "wsp_e",
      Some("not-the-secret"),
      body("E", "usr_eve", "e@cue.test"),
    )
  assert resp.status == 401
  assert count(env, "SELECT count(*) FROM cue_workspace_orgs", []) == 0
}

pub fn absent_secret_is_unauthenticated_test() {
  let env = setup()
  let resp = put(env, "wsp_f", None, body("F", "usr_frank", "f@cue.test"))
  assert resp.status == 401
}

pub fn disabled_provisioning_is_unavailable_test() {
  let env =
    setup_full(None, fn(_conn) { Nil }, fn(_conn, _now, _actor, _change) {
      Ok(1)
    })
  let resp =
    put(env, "wsp_g", Some(secret), body("G", "usr_grace", "g@cue.test"))
  assert resp.status == 503
  assert string.contains(
    simulate.read_body(resp),
    "provisioning_not_configured",
  )
}

pub fn unknown_hub_provider_is_unavailable_test() {
  let env =
    setup_full(
      Some(config.CueProvisioning(secret, "no-such-provider")),
      fn(_conn) { Nil },
      fn(_conn, _now, _actor, _change) { Ok(1) },
    )
  let resp =
    put(env, "wsp_h", Some(secret), body("H", "usr_ivan", "i@cue.test"))
  assert resp.status == 503
  assert string.contains(
    simulate.read_body(resp),
    "provisioning_not_configured",
  )
}

pub fn invalid_email_is_rejected_test() {
  let env = setup()
  let resp =
    put(env, "wsp_j", Some(secret), body("J", "usr_judy", "not-an-email"))
  assert resp.status == 400
  assert string.contains(simulate.read_body(resp), "invalid_email")
}

// --- Device enrollment -----------------------------------------------------

fn device_body(
  nk: String,
  label: String,
  subject: String,
  email: String,
) -> json.Json {
  json.object([
    #("nk", json.string(nk)),
    #("label", json.string(label)),
    #(
      "owner",
      json.object([
        #("subject", json.string(subject)),
        #("email", json.string(email)),
        #("name", json.string("Owner")),
      ]),
    ),
  ])
}

fn post_device(
  env: Env,
  workspace_id: String,
  token: Option(String),
  payload: json.Json,
) -> wisp.Response {
  let base =
    simulate.request(
      Post,
      "/internal/v1/integrations/cue/workspaces/" <> workspace_id <> "/devices",
    )
    |> simulate.json_body(payload)
  let req = case token {
    Some(t) -> simulate.header(base, "authorization", "Bearer " <> t)
    None -> base
  }
  router.handle(req, env.ctx)
}

/// Provisions a workspace and returns its owner subject/email, ready to enroll.
fn provisioned_workspace(env: Env, workspace_id: String) -> #(String, String) {
  let subject = "usr_" <> id.new()
  let email = id.new() <> "@cue.test"
  let resp = put(env, workspace_id, Some(secret), body("WS", subject, email))
  assert resp.status == 200
  #(subject, email)
}

pub fn enroll_device_creates_device_key_membership_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_dev")
  let nk = fixtures.nk()

  let resp =
    post_device(
      env,
      "wsp_dev",
      Some(secret),
      device_body(nk, "laptop", subject, email),
    )
  assert resp.status == 200
  let out = simulate.read_body(resp)
  assert string.contains(out, "\"created\":true")
  assert string.contains(out, "\"device_id\"")
  // The domain is <network>.<org-slug>.<apex>; the apex is the booted zone.
  assert string.contains(out, "default.cue-")
  assert string.contains(out, ".sync.test")

  // One device, one active key, one membership of the workspace's network.
  assert count(env, "SELECT count(*) FROM devices", []) == 1
  assert count(
      env,
      "SELECT count(*) FROM device_keys WHERE state = 'active'",
      [],
    )
    == 1
  assert count(
      env,
      "SELECT count(*) FROM network_devices nd
       JOIN cue_workspace_orgs w ON w.network_id = nd.network_id
       WHERE w.cue_workspace_id = ?",
      [sqlite.Text("wsp_dev")],
    )
    == 1
}

pub fn enroll_device_is_idempotent_by_nk_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_idem")
  let nk = fixtures.nk()

  let first =
    post_device(
      env,
      "wsp_idem",
      Some(secret),
      device_body(nk, "laptop", subject, email),
    )
  assert first.status == 200
  assert string.contains(simulate.read_body(first), "\"created\":true")

  // A repeat with the same nk (a retry) converges on the one device.
  let second =
    post_device(
      env,
      "wsp_idem",
      Some(secret),
      device_body(nk, "laptop", subject, email),
    )
  assert second.status == 200
  assert string.contains(simulate.read_body(second), "\"created\":false")

  assert count(env, "SELECT count(*) FROM devices", []) == 1
  assert count(env, "SELECT count(*) FROM device_keys", []) == 1
  assert count(env, "SELECT count(*) FROM network_devices", []) == 1
}

pub fn concurrent_provisioning_reuses_the_winning_mapping_test() {
  let publish_entered = process.new_subject()
  let responses = process.new_subject()

  let env =
    setup_full(
      Some(cue_cfg()),
      fn(_conn) { Nil },
      fn(_conn, _now, _actor, _change) {
        // A subject can only be received by the process that created it. Each
        // publisher therefore makes its own gate and hands the sending half to
        // the test process.
        let release = process.new_subject()
        process.send(publish_entered, release)
        let assert Ok(Nil) = process.receive(release, 5000)
        Ok(1)
      },
    )
  let payload = body("Concurrent", "usr_race", "race@cue.test")

  process.spawn_unlinked(fn() {
    process.send(responses, put(env, "wsp_race", Some(secret), payload))
  })
  let assert Ok(first_release) = process.receive(publish_entered, 1000)

  // The second request observes the still-uncommitted mapping as absent, then
  // waits for the first writer. Releasing after it has reached that window
  // reproduces the uniqueness race deterministically on the two-connection
  // pool used by this fixture.
  process.spawn_unlinked(fn() {
    process.send(responses, put(env, "wsp_race", Some(secret), payload))
  })
  process.sleep(100)
  process.send(first_release, Nil)

  // After the repair, the losing request rechecks inside `zone_mutation` and
  // reaches the publisher too. Before the repair it fails at the mapping's
  // unique constraint, so there is no second gate to release.
  case process.receive(publish_entered, 500) {
    Ok(second_release) -> process.send(second_release, Nil)
    Error(Nil) -> Nil
  }

  let assert Ok(first) = process.receive(responses, 5000)
  let assert Ok(second) = process.receive(responses, 5000)
  assert first.status == 200
  assert second.status == 200
  let #(org_id, network_id) = workspace_mapping(env, "wsp_race")
  let first_body = simulate.read_body(first)
  let second_body = simulate.read_body(second)
  assert string.contains(first_body, "\"org_id\":\"" <> org_id <> "\"")
  assert string.contains(first_body, "\"network_id\":\"" <> network_id <> "\"")
  assert string.contains(second_body, "\"org_id\":\"" <> org_id <> "\"")
  assert string.contains(second_body, "\"network_id\":\"" <> network_id <> "\"")
  assert count(env, "SELECT count(*) FROM cue_workspace_orgs", []) == 1
  assert count(env, "SELECT count(*) FROM networks", []) == 1
}

pub fn existing_device_key_cannot_cross_workspace_orgs_test() {
  let env = setup()
  let subject = "usr_cross_org"
  let email = "cross-org@cue.test"
  let a = put(env, "wsp_org_a", Some(secret), body("A", subject, email))
  let b = put(env, "wsp_org_b", Some(secret), body("B", subject, email))
  assert a.status == 200
  assert b.status == 200
  let nk = fixtures.nk()

  let first =
    post_device(
      env,
      "wsp_org_a",
      Some(secret),
      device_body(nk, "laptop", subject, email),
    )
  assert first.status == 200

  let second =
    post_device(
      env,
      "wsp_org_b",
      Some(secret),
      device_body(nk, "laptop", subject, email),
    )
  assert second.status == 409
  assert string.contains(simulate.read_body(second), "device_org_conflict")
  assert count(env, "SELECT count(*) FROM devices", []) == 1
  assert count(env, "SELECT count(*) FROM network_devices", []) == 1
}

pub fn enroll_unprovisioned_workspace_is_not_found_test() {
  let env = setup()
  let nk = fixtures.nk()
  let resp =
    post_device(
      env,
      "wsp_absent",
      Some(secret),
      device_body(nk, "laptop", "usr_k", "k@cue.test"),
    )
  assert resp.status == 404
  assert string.contains(simulate.read_body(resp), "workspace_not_provisioned")
  assert count(env, "SELECT count(*) FROM devices", []) == 0
}

pub fn enroll_device_wrong_secret_is_unauthenticated_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_authz")
  let nk = fixtures.nk()
  let resp =
    post_device(
      env,
      "wsp_authz",
      Some("not-the-secret"),
      device_body(nk, "laptop", subject, email),
    )
  assert resp.status == 401
  assert count(env, "SELECT count(*) FROM devices", []) == 0
}

pub fn enroll_invalid_nk_is_rejected_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_badnk")
  let resp =
    post_device(
      env,
      "wsp_badnk",
      Some(secret),
      device_body("not-a-valid-key", "laptop", subject, email),
    )
  assert resp.status == 400
  assert string.contains(simulate.read_body(resp), "invalid_nk")
  assert count(env, "SELECT count(*) FROM devices", []) == 0
}
