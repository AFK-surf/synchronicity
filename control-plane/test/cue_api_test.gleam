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
import gleam/http.{Put}
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/string
import store/db
import store/migrate
import store/sqlite
import util/id
import wisp
import wisp/simulate

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
  setup_full(Some(cue_cfg()), fn(_conn) { Nil })
}

fn setup_seeded(seed: fn(sqlite.Connection) -> Nil) -> Env {
  setup_full(Some(cue_cfg()), seed)
}

/// A migrated database carrying the shared hub org + its OIDC provider (every
/// Cue identity anchors to this one provider); `seed` adds any extra rows,
/// before the pool opens so no second writer contends for the file.
fn setup_full(
  cue: Option(config.CueProvisioning),
  seed: fn(sqlite.Connection) -> Nil,
) -> Env {
  let db_path = tmp_db()
  let assert Ok(conn) = db.open_primary(db_path)
  let assert Ok(_) = migrate.migrate(conn)
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
      fn(_conn, _now, _actor, _change) { Ok(1) },
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
  let env = setup_full(None, fn(_conn) { Nil })
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
