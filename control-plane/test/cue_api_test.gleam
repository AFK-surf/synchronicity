//// Cue per-Workspace provisioning:
//// `PUT /internal/v1/integrations/cue/workspaces/<cue_workspace_id>`.

import api/auth_api
import api/browse_api
import api/reads
import api/router
import config
import email/mailer
import fixtures.{tmp_db}
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http.{Delete, Get, Post, Put}
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
      process.new_name("cue_test_writers_" <> id.new()),
      "https://cp.test/dp/v1/attach",
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

pub fn trusted_cue_email_links_existing_account_idempotently_test() {
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
  // The trusted Cue request binds its identity to the existing account.
  let resp =
    put(env, "wsp_d", Some(secret), body("D", "usr_dave", "dave@cue.test"))
  assert resp.status == 200
  let retry =
    put(env, "wsp_d", Some(secret), body("D", "usr_dave", "dave@cue.test"))
  assert retry.status == 200
  assert count(env, "SELECT count(*) FROM cue_workspace_orgs", []) == 1
  assert count(env, "SELECT count(*) FROM users WHERE email = ?", [
      sqlite.Text("dave@cue.test"),
    ])
    == 1
  assert count(
      env,
      "SELECT count(*) FROM auth_identities WHERE subject = ? AND user_id = ? AND oidc_provider_id = ?",
      [
        sqlite.Text("usr_dave"),
        sqlite.Text("seed-dave"),
        sqlite.Text(hub_provider),
      ],
    )
    == 1
  assert count(env, "SELECT count(*) FROM org_members WHERE user_id = ?", [
      sqlite.Text("seed-dave"),
    ])
    == 1
  // A later email change must not move the already-bound Cue subject.
  let changed_email =
    put(env, "wsp_d", Some(secret), body("D", "usr_dave", "changed@cue.test"))
  assert changed_email.status == 200
  assert count(
      env,
      "SELECT count(*) FROM auth_identities WHERE subject = ? AND user_id = ?",
      [
        sqlite.Text("usr_dave"),
        sqlite.Text("seed-dave"),
      ],
    )
    == 1
  assert count(env, "SELECT count(*) FROM users WHERE email = ?", [
      sqlite.Text("changed@cue.test"),
    ])
    == 0
}

pub fn untrusted_cue_request_cannot_link_existing_account_test() {
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
  let resp =
    put(
      env,
      "wsp_d",
      Some("wrong-secret"),
      body("D", "usr_dave", "dave@cue.test"),
    )
  assert resp.status == 401
  assert count(env, "SELECT count(*) FROM auth_identities WHERE subject = ?", [
      sqlite.Text("usr_dave"),
    ])
    == 0
  assert count(env, "SELECT count(*) FROM cue_workspace_orgs", []) == 0
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

pub fn provisioning_enables_cloud_features_and_places_new_network_test() {
  let env =
    setup_seeded(fn(conn) {
      let assert Ok(_) =
        sqlite.exec(
          conn,
          "INSERT INTO data_planes (id, created_at) VALUES ('dp-cue', 0)",
          [],
        )
      Nil
    })
  let resp =
    put(
      env,
      "wsp_cloud",
      Some(secret),
      body("Cloud", "usr_cloud", "cloud@cue.test"),
    )
  assert resp.status == 200
  assert count(
      env,
      "SELECT count(*) FROM networks WHERE browse_enabled = 1 AND cloud_hosted = 1 AND cloud_dp_id = 'dp-cue'",
      [],
    )
    == 1
}

pub fn backfill_reenables_features_preserves_placement_and_cancels_collection_test() {
  let env =
    setup_seeded(fn(conn) {
      let assert Ok(_) =
        sqlite.exec(
          conn,
          "INSERT INTO data_planes (id, created_at) VALUES ('dp-cue', 0)",
          [],
        )
      Nil
    })
  let payload = body("Cloud", "usr_cloud", "cloud@cue.test")
  assert put(env, "wsp_cloud", Some(secret), payload).status == 200
  let assert Ok(conn) = db.open_primary(env.db_path)
  // Represent a previously provisioned network whose admin disabled both flags.
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "UPDATE networks SET browse_enabled = 0, cloud_hosted = 0, cloud_dp_id = 'dp-cue'",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO cloud_collect_queue (org_slug, network_name, disabled_at, dp_id) SELECT o.slug, n.name, 0, 'dp-cue' FROM networks n JOIN orgs o ON o.id = n.org_id",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO data_planes (id, created_at) VALUES ('dp-empty', 0)",
      [],
    )
  sqlite.close(conn)
  assert put(env, "wsp_cloud", Some(secret), payload).status == 200
  assert put(env, "wsp_cloud", Some(secret), payload).status == 200
  assert count(
      env,
      "SELECT count(*) FROM networks WHERE browse_enabled = 1 AND cloud_hosted = 1 AND cloud_dp_id = 'dp-cue'",
      [],
    )
    == 1
  assert count(env, "SELECT count(*) FROM cloud_collect_queue", []) == 0
  assert count(env, "SELECT count(*) FROM cue_workspace_orgs", []) == 1
}

pub fn provisioning_without_fleet_enables_flags_but_does_not_invent_placement_test() {
  let env = setup()
  assert put(
      env,
      "wsp_cloud",
      Some(secret),
      body("Cloud", "usr_cloud", "cloud@cue.test"),
    ).status
    == 200
  assert count(
      env,
      "SELECT count(*) FROM networks WHERE browse_enabled = 1 AND cloud_hosted = 1 AND cloud_dp_id IS NULL",
      [],
    )
    == 1
}

pub fn rejected_backfill_rolls_back_flags_placement_and_collection_test() {
  let env =
    setup_seeded(fn(conn) {
      let assert Ok(_) =
        sqlite.exec(
          conn,
          "INSERT INTO data_planes (id, created_at) VALUES ('dp-cue', 0)",
          [],
        )
      Nil
    })
  let payload = body("Cloud", "usr_cloud", "cloud@cue.test")
  assert put(env, "wsp_cloud", Some(secret), payload).status == 200
  let assert Ok(conn) = db.open_primary(env.db_path)
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "UPDATE networks SET browse_enabled = 0, cloud_hosted = 0, cloud_dp_id = NULL",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO cloud_collect_queue (org_slug, network_name, disabled_at, dp_id) SELECT o.slug, n.name, 0, 'dp-cue' FROM networks n JOIN orgs o ON o.id = n.org_id",
      [],
    )
  sqlite.close(conn)
  let assert router.Writable(auth) = env.ctx.api
  let blocked_auth =
    auth_api.AuthContext(..auth, publish_in_tx: fn(_, _, _, _) {
      Error(publish.NoRekorRecord(1))
    })
  let blocked =
    Env(
      ..env,
      ctx: router.Context(..env.ctx, api: router.Writable(blocked_auth)),
    )
  assert put(blocked, "wsp_cloud", Some(secret), payload).status == 409
  assert count(
      env,
      "SELECT count(*) FROM networks WHERE browse_enabled = 0 AND cloud_hosted = 0 AND cloud_dp_id IS NULL",
      [],
    )
    == 1
  assert count(env, "SELECT count(*) FROM cloud_collect_queue", []) == 1
}

// --- API keys ----------------------------------------------------------------

fn key_body(subject: String, email: String) -> json.Json {
  json.object([
    #(
      "owner",
      json.object([
        #("subject", json.string(subject)),
        #("email", json.string(email)),
      ]),
    ),
  ])
}

fn key_body_with(
  subject: String,
  email: String,
  name: String,
  expires_in: Int,
) -> json.Json {
  json.object([
    #("name", json.string(name)),
    #("expires_in", json.int(expires_in)),
    #(
      "owner",
      json.object([
        #("subject", json.string(subject)),
        #("email", json.string(email)),
      ]),
    ),
  ])
}

fn post_key(
  env: Env,
  workspace_id: String,
  token: Option(String),
  payload: json.Json,
) -> wisp.Response {
  let base =
    simulate.request(
      Post,
      "/internal/v1/integrations/cue/workspaces/" <> workspace_id <> "/api-keys",
    )
    |> simulate.json_body(payload)
  let req = case token {
    Some(t) -> simulate.header(base, "authorization", "Bearer " <> t)
    None -> base
  }
  router.handle(req, env.ctx)
}

fn delete_key(
  env: Env,
  workspace_id: String,
  token: Option(String),
  key_id: String,
) -> wisp.Response {
  let base =
    simulate.request(
      Delete,
      "/internal/v1/integrations/cue/workspaces/"
        <> workspace_id
        <> "/api-keys/"
        <> key_id,
    )
  let req = case token {
    Some(t) -> simulate.header(base, "authorization", "Bearer " <> t)
    None -> base
  }
  router.handle(req, env.ctx)
}

/// A request carrying the minted key and no cookie — what Cue's backend sends.
fn keyed(env: Env, token: String, path: String) -> wisp.Response {
  simulate.request(Get, path)
  |> simulate.header("authorization", "Bearer " <> token)
  |> router.handle(env.ctx)
}

type Minted {
  Minted(key_id: String, token: String, org_slug: String, expires_at: Int)
}

fn minted_of(resp: wisp.Response) -> Minted {
  let decoder = {
    use key_id <- decode.subfield(["result", "key_id"], decode.string)
    use token <- decode.subfield(["result", "token"], decode.string)
    use org_slug <- decode.subfield(["result", "org_slug"], decode.string)
    use expires_at <- decode.subfield(["result", "expires_at"], decode.int)
    decode.success(Minted(key_id, token, org_slug, expires_at))
  }
  let assert Ok(minted) = json.parse(simulate.read_body(resp), decoder)
  minted
}

pub fn provisioning_reports_org_slug_and_network_test() {
  let env = setup()
  let created =
    put(env, "wsp_slug", Some(secret), body("S", "usr_slug", "s@cue.test"))
  assert created.status == 200
  let out = simulate.read_body(created)
  assert string.contains(out, "\"org_slug\":\"cue-")
  assert string.contains(out, "\"network\":\"default\"")

  let reused =
    put(env, "wsp_slug", Some(secret), body("S", "usr_slug", "s@cue.test"))
  assert reused.status == 200
  assert string.contains(simulate.read_body(reused), "\"org_slug\":\"cue-")
}

pub fn minted_key_is_a_member_key_that_reaches_the_org_api_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_key")

  let resp = post_key(env, "wsp_key", Some(secret), key_body(subject, email))
  assert resp.status == 200
  let out = simulate.read_body(resp)
  assert string.contains(out, "\"role\":\"member\"")
  assert string.contains(out, "\"name\":\"cue-backend\"")
  assert string.contains(out, "\"network\":\"default\"")
  let minted = minted_of(resp)
  assert string.starts_with(minted.token, "synch_")
  assert string.starts_with(minted.org_slug, "cue-")
  assert minted.expires_at == 0

  // The token reaches the Workspace's org at the member floor ...
  let org = keyed(env, minted.token, "/api/orgs/" <> minted.org_slug)
  assert org.status == 200
  assert string.contains(simulate.read_body(org), "\"role\":\"member\"")
  // ... and no further: a key cannot see, let alone mint, keys.
  assert keyed(
      env,
      minted.token,
      "/api/orgs/" <> minted.org_slug <> "/api-keys",
    ).status
    == 403

  // One row, a member key in the workspace's org, minted for its owner, with
  // the trail naming the service rather than a person.
  assert count(
      env,
      "SELECT count(*) FROM api_keys k
       JOIN cue_workspace_orgs w ON w.org_id = k.org_id
       JOIN auth_identities i ON i.user_id = k.created_by
       WHERE w.cue_workspace_id = ? AND k.role = 'member'
         AND k.network_id IS NULL AND i.subject = ?",
      [sqlite.Text("wsp_key"), sqlite.Text(subject)],
    )
    == 1
  assert count(
      env,
      "SELECT count(*) FROM audit_log
       WHERE action = 'apikey.create' AND actor = 'cue:provisioning'",
      [],
    )
    == 1
}

pub fn every_mint_is_a_new_key_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_two")
  let first = post_key(env, "wsp_two", Some(secret), key_body(subject, email))
  let second = post_key(env, "wsp_two", Some(secret), key_body(subject, email))
  assert first.status == 200
  assert second.status == 200
  assert minted_of(first).token != minted_of(second).token
  assert count(env, "SELECT count(*) FROM api_keys", []) == 2
  // Both are the one owner's; a retry mints, it does not mint a user.
  assert count(env, "SELECT count(*) FROM users WHERE email = ?", [
      sqlite.Text(email),
    ])
    == 1
}

pub fn mint_stores_a_named_expiring_key_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_exp")
  let resp =
    post_key(
      env,
      "wsp_exp",
      Some(secret),
      key_body_with(subject, email, "  agent  ", 3600),
    )
  assert resp.status == 200
  let minted = minted_of(resp)
  assert minted.expires_at > 0
  assert string.contains(simulate.read_body(resp), "\"name\":\"agent\"")
  assert count(
      env,
      "SELECT count(*) FROM api_keys WHERE name = 'agent' AND expires_at = ?",
      [sqlite.Int(minted.expires_at)],
    )
    == 1
}

pub fn mint_refuses_a_bad_name_or_expiry_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_bad")
  let unnamed =
    post_key(
      env,
      "wsp_bad",
      Some(secret),
      key_body_with(subject, email, " ", 0),
    )
  assert unnamed.status == 400
  assert string.contains(simulate.read_body(unnamed), "bad_name")
  let past =
    post_key(
      env,
      "wsp_bad",
      Some(secret),
      key_body_with(subject, email, "agent", -1),
    )
  assert past.status == 400
  assert string.contains(simulate.read_body(past), "bad_expiry")
  assert count(env, "SELECT count(*) FROM api_keys", []) == 0
}

pub fn mint_for_unprovisioned_workspace_is_not_found_test() {
  let env = setup()
  let resp =
    post_key(env, "wsp_none", Some(secret), key_body("usr_n", "n@cue.test"))
  assert resp.status == 404
  assert string.contains(simulate.read_body(resp), "workspace_not_provisioned")
  assert count(env, "SELECT count(*) FROM api_keys", []) == 0
}

pub fn mint_with_wrong_secret_is_unauthenticated_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_secret")
  let resp =
    post_key(
      env,
      "wsp_secret",
      Some("not-the-secret"),
      key_body(subject, email),
    )
  assert resp.status == 401
  assert post_key(env, "wsp_secret", None, key_body(subject, email)).status
    == 401
  assert count(env, "SELECT count(*) FROM api_keys", []) == 0
}

pub fn revoke_ends_access_and_stays_inside_the_workspace_org_test() {
  let env = setup()
  let #(subject_a, email_a) = provisioned_workspace(env, "wsp_ra")
  let #(subject_b, email_b) = provisioned_workspace(env, "wsp_rb")
  let a =
    minted_of(post_key(
      env,
      "wsp_ra",
      Some(secret),
      key_body(subject_a, email_a),
    ))
  let b =
    minted_of(post_key(
      env,
      "wsp_rb",
      Some(secret),
      key_body(subject_b, email_b),
    ))
  assert keyed(env, a.token, "/api/orgs/" <> a.org_slug).status == 200

  // Another workspace's key id is a miss, and that key keeps working.
  let cross = delete_key(env, "wsp_rb", Some(secret), a.key_id)
  assert cross.status == 404
  assert keyed(env, a.token, "/api/orgs/" <> a.org_slug).status == 200

  let revoked = delete_key(env, "wsp_ra", Some(secret), a.key_id)
  assert revoked.status == 200
  assert string.contains(simulate.read_body(revoked), "\"revoked\":true")
  assert keyed(env, a.token, "/api/orgs/" <> a.org_slug).status == 401
  assert keyed(env, b.token, "/api/orgs/" <> b.org_slug).status == 200

  // A repeat is a 404: the row is gone, and the trail says who ended it.
  assert delete_key(env, "wsp_ra", Some(secret), a.key_id).status == 404
  assert count(
      env,
      "SELECT count(*) FROM audit_log
       WHERE action = 'apikey.delete' AND actor = 'cue:provisioning'",
      [],
    )
    == 1
  assert count(env, "SELECT count(*) FROM api_keys", []) == 1
}

pub fn revoke_with_wrong_secret_is_unauthenticated_test() {
  let env = setup()
  let #(subject, email) = provisioned_workspace(env, "wsp_rs")
  let minted =
    minted_of(post_key(env, "wsp_rs", Some(secret), key_body(subject, email)))
  assert delete_key(env, "wsp_rs", Some("not-the-secret"), minted.key_id).status
    == 401
  assert keyed(env, minted.token, "/api/orgs/" <> minted.org_slug).status == 200
}
