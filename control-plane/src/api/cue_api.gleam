//// Cue integration: server-to-server per-Workspace provisioning.
////
//// Each Cue Workspace maps to one org and one default network here. When a
//// Workspace is created on the Cue side its convergence calls this endpoint,
//// which creates the org + network, ensures the owner's OIDC identity, and
//// makes the owner a member — so a later dashboard sign-in over Cue OIDC lands
//// on the pre-created account inside the Workspace's org.
////
//// Authenticated by a shared provisioning secret alone. The OIDC provider is
//// a single shared "hub" (`CP_CUE_OIDC_PROVIDER_ID`) that every Cue user's
//// identity anchors to; the org and network are created per Workspace and the
//// role is the owner's own.
////
//// Idempotent by workspace mapping. Every call enforces Cue's managed-network
//// policy: browsing and cloud hosting are on, even after an admin disabled
//// them. Creation and reuse both publish through the widening gate in one
//// transaction; a retry also cancels pending collection and preserves placement.
//// The paired remote/local retry lifecycle is modeled in the Cue repository at
//// `tla/cue_synchronicity/WorkspaceProvisioning.tla`.
////
//// The same secret also mints and revokes **member org keys** for a
//// Workspace's org (`mint_api_key`, `revoke_api_key`), which is how Cue's
//// backend reaches the org API — above all the network's file surface,
//// `…/browse/{ls,stat,file}` — on the Workspace's behalf with no person
//// signed in. `api/api_keys_api` refuses to let a key mint a key, because
//// revoking the key you knew about would not end the access it minted; the
//// provisioning secret is not a key and already holds wider authority over
//// these orgs (it creates them and enrolls their devices), so minting under
//// it widens nothing. What keeps the trail whole: every key minted here is
//// an ordinary row in the org's key list, revocable by its admins in the
//// dashboard, and its `apikey.create` audit row names `cue:provisioning` as
//// the actor — so an operator rotating the secret can find what it minted.

import api/api_keys_api
import api/auth_api.{type AuthContext, with_db}
import api/common.{
  audit, body_decoder, constraint_response, db_error, ok_json, transaction,
  zone_mutation,
}
import api/middleware.{Bearer, error_json, now_unix, presented}
import auth/api_key
import auth/principal
import cloud/dataplane
import config.{type CueProvisioning}
import dns/name
import gleam/dynamic/decode
import gleam/json.{type Json}
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Blob, Done, Int as VInt, Text}
import util/id
import wisp.{type Request, type Response}
import zone/model
import zone/publish

type Owner {
  Owner(subject: String, email: String, name: Option(String))
}

/// Every Workspace org holds exactly one network, and this is its name.
const default_network = "default"

/// The name a minted key carries when the caller gives none. Cue's backend is
/// the one holder, so the name only has to say which key this is in the
/// org's list beside keys people minted.
const default_key_name = "cue-backend"

/// The one role a Cue-minted key may hold. The file surface is `member`
/// floor everywhere, and `member` is what a Workspace member already has, so
/// a wider key would be authority nobody asked for.
const minted_role = "member"

/// `PUT /internal/v1/integrations/cue/workspaces/<cue_workspace_id>`.
pub fn provision_workspace(
  req: Request,
  ctx: AuthContext,
  cue_workspace_id: String,
) -> Response {
  case ctx.cue_provisioning {
    None -> not_configured()
    Some(cfg) -> {
      use <- authorized(req, cfg)
      use <- valid_id(cue_workspace_id, "invalid_workspace")
      let decoder = {
        use ws_name <- decode.field("name", decode.string)
        use owner <- decode.field("owner", owner_decoder())
        decode.success(#(ws_name, owner))
      }
      use #(ws_name, owner) <- body_decoder(req, decoder)
      use <- valid_id(owner.subject, "invalid_subject")
      case valid_email(owner.email) {
        False ->
          error_json(400, "invalid_email", "owner email is not a valid address")
        True ->
          with_db(ctx, fn(conn) {
            case hub_provider_exists(conn, cfg) {
              Error(response) -> response
              Ok(Nil) ->
                converge(conn, ctx, cfg, cue_workspace_id, ws_name, owner)
            }
          })
      }
    }
  }
}

/// Create or refresh a Cue-managed network under the same writer lock and
/// transparency gate. The caller reads the nested result in either case.
fn converge(
  conn: Connection,
  ctx: AuthContext,
  cfg: CueProvisioning,
  cue_workspace_id: String,
  ws_name: String,
  owner: Owner,
) -> Response {
  // A synthetic principal: the provisioning secret has already authenticated
  // the caller, so `who` is only the audit/zone actor here.
  let who = provisioning_principal()

  zone_mutation(conn, ctx, who, publish.Widening, fn() {
    // Resolve the mapping under the writer lock, including concurrent creates.
    case find_workspace_org(conn, cue_workspace_id) {
      Error(response) -> Error(response)
      Ok(Some(#(org_id, network_id))) -> {
        use sync_user_id <- result.try(ensure_owner(conn, cfg, org_id, owner))
        use _ <- result.try(enable_cloud_features(conn, network_id))
        use slug <- result.try(org_slug(conn, org_id))
        Ok(provisioned(org_id, slug, network_id, sync_user_id, False))
      }
      Ok(None) -> {
        let org_id = id.new()
        let network_id = id.new()

        use slug <- result.try(insert_org(conn, org_id, ws_name))
        use _ <- result.try(insert_network(conn, network_id, org_id))
        use sync_user_id <- result.try(ensure_owner(conn, cfg, org_id, owner))
        use _ <- result.try(insert_mapping(
          conn,
          cue_workspace_id,
          org_id,
          network_id,
        ))

        use _ <- result.try(enable_cloud_features(conn, network_id))
        Ok(provisioned(org_id, slug, network_id, sync_user_id, True))
      }
    }
  })
}

/// Match cloud-hosting enable semantics: cancel collection before placement,
/// retaining an existing data-plane assignment. An empty fleet leaves the
/// enabled network unassigned; it does not make the provisioning call fail.
fn enable_cloud_features(
  conn: Connection,
  network_id: String,
) -> Result(Nil, Response) {
  let work = {
    use _ <- result.try(
      sqlite.exec(
        conn,
        "UPDATE networks SET browse_enabled = 1, cloud_hosted = 1 WHERE id = ?",
        [Text(network_id)],
      ),
    )
    use _ <- result.try(
      sqlite.exec(
        conn,
        "DELETE FROM cloud_collect_queue
       WHERE (org_slug, network_name) IN
         (SELECT o.slug, n.name FROM networks n JOIN orgs o ON o.id = n.org_id
          WHERE n.id = ?)",
        [Text(network_id)],
      ),
    )
    use _ <- result.try(dataplane.place(conn, network_id, now_unix()))
    Ok(Nil)
  }
  result.map_error(work, constraint_response)
}

/// The provisioning secret, compared in constant time (SHA-256 of each side).
fn authorized(
  req: Request,
  cfg: CueProvisioning,
  next: fn() -> Response,
) -> Response {
  case presented(req.headers) {
    Bearer(token) ->
      case id.hash_token(token) == id.hash_token(cfg.secret) {
        True -> next()
        False -> unauthorized()
      }
    _ -> unauthorized()
  }
}

fn unauthorized() -> Response {
  error_json(
    401,
    "unauthenticated",
    "provisioning requires a valid Authorization: Bearer <secret>",
  )
}

fn valid_id(value: String, code: String, next: fn() -> Response) -> Response {
  case string.byte_size(value) >= 1 && string.byte_size(value) <= 255 {
    True -> next()
    False -> error_json(400, code, "id must be 1..255 bytes")
  }
}

fn valid_email(email: String) -> Bool {
  string.contains(email, "@") && string.byte_size(email) <= 254
}

/// Confirms the configured hub OIDC provider exists. A miss is a control-plane
/// misconfiguration, answered 503 like an absent configuration.
fn hub_provider_exists(
  conn: Connection,
  cfg: CueProvisioning,
) -> Result(Nil, Response) {
  case
    sqlite.query(conn, "SELECT 1 FROM oidc_providers WHERE id = ?", [
      Text(cfg.oidc_provider_id),
    ])
  {
    Ok([[_]]) -> Ok(Nil)
    Ok(_) ->
      Error(error_json(
        503,
        "provisioning_not_configured",
        "the configured cue oidc provider does not exist",
      ))
    Error(_) -> Error(db_error())
  }
}

fn find_workspace_org(
  conn: Connection,
  cue_workspace_id: String,
) -> Result(Option(#(String, String)), Response) {
  case
    sqlite.query(
      conn,
      "SELECT org_id, network_id FROM cue_workspace_orgs WHERE cue_workspace_id = ?",
      [Text(cue_workspace_id)],
    )
  {
    Ok([[Text(org_id), Text(network_id)]]) -> Ok(Some(#(org_id, network_id)))
    Ok([]) -> Ok(None)
    Ok(_) -> Error(db_error())
    Error(_) -> Error(db_error())
  }
}

/// Creates the org and returns its slug — the name the org API routes by.
fn insert_org(
  conn: Connection,
  org_id: String,
  ws_name: String,
) -> Result(String, Response) {
  // The slug is DNS-label safe by construction (`cue-` + lowercase hex).
  let slug = "cue-" <> id.new()

  case
    sqlite.exec(
      conn,
      "INSERT INTO orgs (id, slug, name, created_at) VALUES (?, ?, ?, ?)",
      [
        Text(org_id),
        Text(slug),
        Text(ws_name),
        VInt(now_unix()),
      ],
    )
  {
    Ok(_) -> Ok(slug)
    Error(e) -> Error(constraint_response(e))
  }
}

fn org_slug(conn: Connection, org_id: String) -> Result(String, Response) {
  scalar_text(conn, "SELECT slug FROM orgs WHERE id = ?", [Text(org_id)])
}

/// The owner every internal route carries: the Cue subject that anchors the
/// identity under the hub provider, and the email the trusted caller asserts
/// for it.
fn owner_decoder() -> decode.Decoder(Owner) {
  use subject <- decode.field("subject", decode.string)
  use email <- decode.field("email", decode.string)
  use name <- decode.optional_field(
    "name",
    None,
    decode.optional(decode.string),
  )
  decode.success(Owner(subject, email, name))
}

/// The synthetic actor of every write these routes make: the provisioning
/// secret has already authenticated the caller, so this names the service in
/// the audit trail and the zone's publish rows, never a person.
fn provisioning_principal() -> principal.Principal {
  principal.Principal("cue:provisioning", principal.Cookie(""))
}

fn insert_network(
  conn: Connection,
  network_id: String,
  org_id: String,
) -> Result(Nil, Response) {
  case
    sqlite.exec(
      conn,
      "INSERT INTO networks (id, org_id, name, created_at) VALUES (?, ?, 'default', ?)",
      [Text(network_id), Text(org_id), VInt(now_unix())],
    )
  {
    Ok(_) -> Ok(Nil)
    Error(e) -> Error(constraint_response(e))
  }
}

fn insert_mapping(
  conn: Connection,
  cue_workspace_id: String,
  org_id: String,
  network_id: String,
) -> Result(Nil, Response) {
  case
    sqlite.exec(
      conn,
      "INSERT INTO cue_workspace_orgs (cue_workspace_id, org_id, network_id, created_at)
       VALUES (?, ?, ?, ?)",
      [Text(cue_workspace_id), Text(org_id), Text(network_id), VInt(now_unix())],
    )
  {
    Ok(_) -> Ok(Nil)
    Error(e) -> Error(constraint_response(e))
  }
}

/// Ensures the owner's OIDC identity (under the hub provider) and their
/// membership of the org, returning the Synchronicity user id. The shared-secret
/// authenticated Cue service is trusted to assert its owner's email: an unbound
/// Cue identity reuses the existing account for that email. Existing subject
/// bindings take precedence; ordinary custom-OIDC login stays explicit-link only.
fn ensure_owner(
  conn: Connection,
  cfg: CueProvisioning,
  org_id: String,
  owner: Owner,
) -> Result(String, Response) {
  use sync_user_id <- result.try(ensure_identity(conn, cfg, owner))
  use _ <- result.try(ensure_membership(conn, org_id, sync_user_id))
  Ok(sync_user_id)
}

fn ensure_identity(
  conn: Connection,
  cfg: CueProvisioning,
  owner: Owner,
) -> Result(String, Response) {
  case find_identity(conn, cfg, owner.subject) {
    Error(response) -> Error(response)
    Ok(Some(user_id)) -> Ok(user_id)
    Ok(None) ->
      case user_id_for_email(conn, owner.email) {
        Error(response) -> Error(response)
        Ok(Some(user_id)) -> {
          use _ <- result.try(insert_identity(
            conn,
            id.new(),
            user_id,
            cfg,
            owner.subject,
          ))
          Ok(user_id)
        }
        Ok(None) -> {
          let user_id = id.new()
          let identity_id = id.new()
          use _ <- result.try(insert_user(conn, user_id, owner))
          use _ <- result.try(insert_identity(
            conn,
            identity_id,
            user_id,
            cfg,
            owner.subject,
          ))
          Ok(user_id)
        }
      }
  }
}

fn find_identity(
  conn: Connection,
  cfg: CueProvisioning,
  subject: String,
) -> Result(Option(String), Response) {
  case
    sqlite.query(
      conn,
      "SELECT user_id FROM auth_identities
       WHERE provider = 'oidc' AND oidc_provider_id = ? AND subject = ?",
      [Text(cfg.oidc_provider_id), Text(subject)],
    )
  {
    Ok([[Text(user_id)]]) -> Ok(Some(user_id))
    Ok([]) -> Ok(None)
    Ok(_) -> Error(db_error())
    Error(_) -> Error(db_error())
  }
}

fn user_id_for_email(
  conn: Connection,
  email: String,
) -> Result(Option(String), Response) {
  case
    sqlite.query(conn, "SELECT id FROM users WHERE email = ?", [Text(email)])
  {
    Ok([[Text(user_id)]]) -> Ok(Some(user_id))
    Ok([]) -> Ok(None)
    Ok(_) -> Error(db_error())
    Error(_) -> Error(db_error())
  }
}

fn insert_user(
  conn: Connection,
  user_id: String,
  owner: Owner,
) -> Result(Nil, Response) {
  case
    sqlite.exec(conn, "INSERT INTO users VALUES (?, ?, ?, ?)", [
      Text(user_id),
      Text(owner.email),
      sqlite.optional_text(owner.name),
      VInt(now_unix()),
    ])
  {
    Ok(_) -> Ok(Nil)
    Error(e) -> Error(constraint_response(e))
  }
}

fn insert_identity(
  conn: Connection,
  identity_id: String,
  user_id: String,
  cfg: CueProvisioning,
  subject: String,
) -> Result(Nil, Response) {
  case
    sqlite.exec(
      conn,
      "INSERT INTO auth_identities VALUES (?, ?, 'oidc', ?, ?, ?)",
      [
        Text(identity_id),
        Text(user_id),
        Text(cfg.oidc_provider_id),
        Text(subject),
        VInt(now_unix()),
      ],
    )
  {
    Ok(_) -> Ok(Nil)
    Error(e) -> Error(constraint_response(e))
  }
}

/// Adds the owner membership if absent, at the fixed `owner` role — the
/// Workspace creator owns their org. Idempotent.
fn ensure_membership(
  conn: Connection,
  org_id: String,
  user_id: String,
) -> Result(Bool, Response) {
  case
    sqlite.exec(
      conn,
      "INSERT OR IGNORE INTO org_members VALUES (?, ?, 'owner', ?)",
      [Text(org_id), Text(user_id), VInt(now_unix())],
    )
  {
    Ok(Done(changes, _)) -> Ok(changes > 0)
    Ok(_) -> Ok(False)
    Error(e) -> Error(constraint_response(e))
  }
}

/// `org_slug` and `network` beside the ids: the org API (`/api/orgs/<slug>/
/// networks/<network>/…`) routes by those, so a caller holding a key minted
/// below needs them to reach the Workspace's files without a second lookup.
fn provisioned(
  org_id: String,
  org_slug: String,
  network_id: String,
  sync_user_id: String,
  created: Bool,
) -> Json {
  json.object([
    #("org_id", json.string(org_id)),
    #("org_slug", json.string(org_slug)),
    #("network_id", json.string(network_id)),
    #("network", json.string(default_network)),
    #("sync_user_id", json.string(sync_user_id)),
    #("created", json.bool(created)),
  ])
}

/// `POST /internal/v1/integrations/cue/workspaces/<cue_workspace_id>/devices`.
///
/// Joins a device (its public node key `nk`) to the Workspace's assigned
/// network. The network is resolved server-side from the workspace mapping; the
/// caller never names it. Idempotent by the device key: because a live `nk` is
/// globally unique to one device, a repeat inside the owning org returns that
/// same device (ensuring its membership of this network), never a duplicate.
/// Reuse from another org is rejected: `devices.org_id` is the ownership
/// boundary used by every dashboard mutation. A new `nk` creates the device +
/// key + membership and republishes the zone.
pub fn enroll_device(
  req: Request,
  ctx: AuthContext,
  cue_workspace_id: String,
) -> Response {
  case ctx.cue_provisioning {
    None -> not_configured()
    Some(cfg) -> {
      use <- authorized(req, cfg)
      use <- valid_id(cue_workspace_id, "invalid_workspace")
      let decoder = {
        use nk <- decode.field("nk", decode.string)
        use label <- decode.field("label", decode.string)
        use owner <- decode.field("owner", owner_decoder())
        decode.success(#(nk, label, owner))
      }
      use #(nk, label, owner) <- body_decoder(req, decoder)
      use <- valid_id(owner.subject, "invalid_subject")
      case valid_email(owner.email) {
        False ->
          error_json(400, "invalid_email", "owner email is not a valid address")
        True ->
          case name.valid_device_label(label), model.validate_nk(nk) {
            False, _ ->
              error_json(
                400,
                "invalid_label",
                "device label must be a DNS label of 1..63 [a-z0-9-]",
              )
            _, Error(Nil) ->
              error_json(
                400,
                "invalid_nk",
                "nk must be a 52-char z-base-32 encoding of a 32-byte key",
              )
            True, Ok(nk_bytes) ->
              with_db(ctx, fn(conn) {
                case hub_provider_exists(conn, cfg) {
                  Error(response) -> response
                  Ok(Nil) ->
                    case find_workspace_org(conn, cue_workspace_id) {
                      Error(response) -> response
                      Ok(None) -> not_provisioned()
                      Ok(Some(#(org_id, network_id))) ->
                        enroll(
                          conn,
                          ctx,
                          cfg,
                          org_id,
                          network_id,
                          owner,
                          label,
                          nk,
                          nk_bytes,
                        )
                    }
                }
              })
          }
      }
    }
  }
}

fn enroll(
  conn: Connection,
  ctx: AuthContext,
  cfg: CueProvisioning,
  org_id: String,
  network_id: String,
  owner: Owner,
  label: String,
  nk: String,
  nk_bytes: BitArray,
) -> Response {
  case existing_device_for_nk(conn, nk_bytes) {
    Error(response) -> response
    Ok(Some(#(device_id, device_org_id))) ->
      case device_org_id == org_id {
        True -> ensure_member(conn, ctx, org_id, network_id, device_id)
        False ->
          error_json(
            409,
            "device_org_conflict",
            "this node key belongs to a device in another org",
          )
      }
    Ok(None) ->
      create_device(
        conn,
        ctx,
        cfg,
        org_id,
        network_id,
        owner,
        label,
        nk,
        nk_bytes,
      )
  }
}

/// The device already exists (its `nk` is live). Guarantee it is a member of
/// this network and return it. `enroll` has already verified that the device
/// and network share an org. An existing membership is a pure repeat and never
/// touches the zone; a new membership adds zone content and republishes.
fn ensure_member(
  conn: Connection,
  ctx: AuthContext,
  org_id: String,
  network_id: String,
  device_id: String,
) -> Response {
  case is_member(conn, network_id, device_id) {
    Error(response) -> response
    Ok(True) ->
      case build_domain(conn, org_id, network_id) {
        Error(response) -> response
        Ok(domain) ->
          ok_json(
            json.object([
              #("result", enrolled(device_id, network_id, domain, False)),
            ]),
          )
      }
    Ok(False) -> {
      let who = provisioning_principal()
      zone_mutation(conn, ctx, who, publish.Widening, fn() {
        use _ <- result.try(insert_network_device(conn, network_id, device_id))
        use domain <- result.try(build_domain(conn, org_id, network_id))
        Ok(enrolled(device_id, network_id, domain, False))
      })
    }
  }
}

/// A new device key: mint the device + key + network membership and publish the
/// zone. `created_by` must be a real user, so the owner's identity is ensured
/// first (it exists from provisioning; a miss creates it, or 409s on an email
/// already owned by a different, unlinked user).
fn create_device(
  conn: Connection,
  ctx: AuthContext,
  cfg: CueProvisioning,
  org_id: String,
  network_id: String,
  owner: Owner,
  label: String,
  nk: String,
  nk_bytes: BitArray,
) -> Response {
  let who = provisioning_principal()
  zone_mutation(conn, ctx, who, publish.Widening, fn() {
    use user_id <- result.try(ensure_identity(conn, cfg, owner))
    let device_id = id.new()
    use _ <- result.try(insert_device(conn, device_id, org_id, label, user_id))
    use _ <- result.try(insert_device_key(conn, device_id, nk, nk_bytes))
    use _ <- result.try(insert_network_device(conn, network_id, device_id))
    use domain <- result.try(build_domain(conn, org_id, network_id))
    Ok(enrolled(device_id, network_id, domain, True))
  })
}

fn existing_device_for_nk(
  conn: Connection,
  nk_bytes: BitArray,
) -> Result(Option(#(String, String)), Response) {
  case
    sqlite.query(
      conn,
      "SELECT d.id, d.org_id
       FROM device_keys k JOIN devices d ON d.id = k.device_id
       WHERE k.nk_bytes = ? AND k.state != 'revoked'",
      [Blob(nk_bytes)],
    )
  {
    Ok([[Text(device_id), Text(org_id)]]) -> Ok(Some(#(device_id, org_id)))
    Ok([]) -> Ok(None)
    Ok(_) -> Error(db_error())
    Error(_) -> Error(db_error())
  }
}

fn is_member(
  conn: Connection,
  network_id: String,
  device_id: String,
) -> Result(Bool, Response) {
  case
    sqlite.query(
      conn,
      "SELECT 1 FROM network_devices WHERE network_id = ? AND device_id = ?",
      [Text(network_id), Text(device_id)],
    )
  {
    Ok([_, ..]) -> Ok(True)
    Ok([]) -> Ok(False)
    Error(_) -> Error(db_error())
  }
}

fn insert_device(
  conn: Connection,
  device_id: String,
  org_id: String,
  label: String,
  created_by: String,
) -> Result(Nil, Response) {
  case
    sqlite.exec(conn, "INSERT INTO devices VALUES (?, ?, ?, NULL, NULL, ?, ?)", [
      Text(device_id),
      Text(org_id),
      Text(label),
      Text(created_by),
      VInt(now_unix()),
    ])
  {
    Ok(_) -> Ok(Nil)
    Error(e) -> Error(constraint_response(e))
  }
}

fn insert_device_key(
  conn: Connection,
  device_id: String,
  nk: String,
  nk_bytes: BitArray,
) -> Result(Nil, Response) {
  case
    sqlite.exec(
      conn,
      "INSERT INTO device_keys VALUES (?, ?, ?, ?, 'active', ?, NULL)",
      [
        Text(id.new()),
        Text(device_id),
        Text(nk),
        Blob(nk_bytes),
        VInt(now_unix()),
      ],
    )
  {
    Ok(_) -> Ok(Nil)
    Error(e) -> Error(constraint_response(e))
  }
}

fn insert_network_device(
  conn: Connection,
  network_id: String,
  device_id: String,
) -> Result(Nil, Response) {
  case
    sqlite.exec(conn, "INSERT INTO network_devices VALUES (?, ?, ?)", [
      Text(network_id),
      Text(device_id),
      VInt(now_unix()),
    ])
  {
    Ok(_) -> Ok(Nil)
    Error(e) -> Error(constraint_response(e))
  }
}

/// `<network>.<org-slug>.<apex>` — the daemon's `DomainSet` target.
fn build_domain(
  conn: Connection,
  org_id: String,
  network_id: String,
) -> Result(String, Response) {
  use slug <- result.try(
    scalar_text(conn, "SELECT slug FROM orgs WHERE id = ?", [Text(org_id)]),
  )
  use net_name <- result.try(
    scalar_text(conn, "SELECT name FROM networks WHERE id = ?", [
      Text(network_id),
    ]),
  )
  case model.read_meta(conn) {
    Ok(meta) ->
      Ok(
        net_name
        <> "."
        <> slug
        <> "."
        <> string.drop_end(name.to_string(meta.apex), 1),
      )
    Error(_) -> Error(db_error())
  }
}

fn scalar_text(
  conn: Connection,
  sql: String,
  params: List(sqlite.Value),
) -> Result(String, Response) {
  case sqlite.query(conn, sql, params) {
    Ok([[Text(value)]]) -> Ok(value)
    Ok(_) -> Error(db_error())
    Error(_) -> Error(db_error())
  }
}

fn enrolled(
  device_id: String,
  network_id: String,
  domain: String,
  created: Bool,
) -> Json {
  json.object([
    #("device_id", json.string(device_id)),
    #("network_id", json.string(network_id)),
    #("network", json.string(default_network)),
    #("domain", json.string(domain)),
    #("created", json.bool(created)),
  ])
}

// --- API keys ----------------------------------------------------------------

/// `POST /internal/v1/integrations/cue/workspaces/<cue_workspace_id>/api-keys`.
///
/// Mints a `member` org key for the Workspace's org and returns the token —
/// the only time it exists anywhere but the caller's hands, as with every
/// key. Body: `{"owner": {...}, "name"?: "…", "expires_in"?: seconds}`; the
/// owner is the same object the other internal routes take, and is what
/// `created_by` names (the column references `users`, and the Workspace
/// owner is the person this key acts for). `role` is not a field: see
/// `minted_role`.
///
/// Not idempotent, and cannot be: a retry after a lost reply has no token to
/// return, so every call is a new key. The caller keeps the one it received
/// and revokes any it can no longer name through `revoke_api_key`; the org's
/// admins see every one of them in the dashboard's key list meanwhile.
pub fn mint_api_key(
  req: Request,
  ctx: AuthContext,
  cue_workspace_id: String,
) -> Response {
  case ctx.cue_provisioning {
    None -> not_configured()
    Some(cfg) -> {
      use <- authorized(req, cfg)
      use <- valid_id(cue_workspace_id, "invalid_workspace")
      let decoder = {
        use name <- decode.optional_field(
          "name",
          default_key_name,
          decode.string,
        )
        use expires_in <- decode.optional_field("expires_in", 0, decode.int)
        use owner <- decode.field("owner", owner_decoder())
        decode.success(#(name, expires_in, owner))
      }
      use #(name_input, expires_in, owner) <- body_decoder(req, decoder)
      let name = string.trim(name_input)
      use <- valid_id(owner.subject, "invalid_subject")
      case
        valid_email(owner.email),
        api_keys_api.check_name(name),
        api_keys_api.expires_at_from(expires_in)
      {
        False, _, _ ->
          error_json(400, "invalid_email", "owner email is not a valid address")
        _, Error(refusal), _ | _, _, Error(refusal) -> refusal
        True, Ok(Nil), Ok(expires_at) ->
          with_db(ctx, fn(conn) {
            case hub_provider_exists(conn, cfg) {
              Error(response) -> response
              Ok(Nil) ->
                case find_workspace_org(conn, cue_workspace_id) {
                  Error(response) -> response
                  Ok(None) -> not_provisioned()
                  Ok(Some(#(org_id, _network_id))) ->
                    mint(conn, cfg, org_id, owner, name, expires_at)
                }
            }
          })
      }
    }
  }
}

/// The row and its trail together, or neither — the same bracket
/// `api_keys_api.create_key` puts around a mint, for the same reason: a live
/// key with no `apikey.create` row is a credential nobody knows exists.
fn mint(
  conn: Connection,
  cfg: CueProvisioning,
  org_id: String,
  owner: Owner,
  name: String,
  expires_at: Option(Int),
) -> Response {
  let key_id = id.new()
  let who = provisioning_principal()
  let minted =
    transaction(conn, fn() {
      use user_id <- result.try(ensure_identity(conn, cfg, owner))
      use #(token, prefix) <- result.try(
        api_key.create(
          conn,
          key_id,
          org_id,
          None,
          name,
          minted_role,
          user_id,
          expires_at,
          now_unix(),
        )
        |> result.map_error(constraint_response),
      )
      use _ <- result.try(
        audit(conn, who, org_id, "apikey.create", [
          #("key", json.string(key_id)),
          #("name", json.string(name)),
          #("role", json.string(minted_role)),
          #("network", json.string("")),
        ])
        |> result.map_error(fn(_) { db_error() }),
      )
      use slug <- result.try(org_slug(conn, org_id))
      Ok(#(token, prefix, slug))
    })
  case minted {
    Error(refusal) -> refusal
    Ok(#(token, prefix, slug)) ->
      ok_json(
        json.object([
          #(
            "result",
            json.object([
              #("key_id", json.string(key_id)),
              #("name", json.string(name)),
              #("role", json.string(minted_role)),
              #("prefix", json.string(prefix)),
              #("expires_at", json.int(option.unwrap(expires_at, 0))),
              #("token", json.string(token)),
              #("org_id", json.string(org_id)),
              #("org_slug", json.string(slug)),
              #("network", json.string(default_network)),
            ]),
          ),
        ]),
      )
  }
}

/// `DELETE /internal/v1/integrations/cue/workspaces/<cue_workspace_id>/api-keys/<key_id>`.
///
/// Revokes a key of the Workspace's org, which is deleting its row: the token
/// authenticates by the hash there, and the audit rows that minted and ended
/// it are what survive. Confined to the Workspace's own org in the `WHERE`,
/// as the dashboard's delete is, so another org's key id is a 404 rather
/// than a revocation. A repeat is a 404 too — the row is gone — which a
/// caller converging on "this key no longer works" reads as done.
pub fn revoke_api_key(
  req: Request,
  ctx: AuthContext,
  cue_workspace_id: String,
  key_id: String,
) -> Response {
  case ctx.cue_provisioning {
    None -> not_configured()
    Some(cfg) -> {
      use <- authorized(req, cfg)
      use <- valid_id(cue_workspace_id, "invalid_workspace")
      use <- valid_id(key_id, "invalid_key")
      with_db(ctx, fn(conn) {
        case find_workspace_org(conn, cue_workspace_id) {
          Error(response) -> response
          Ok(None) -> not_provisioned()
          Ok(Some(#(org_id, _network_id))) -> revoke(conn, org_id, key_id)
        }
      })
    }
  }
}

fn revoke(conn: Connection, org_id: String, key_id: String) -> Response {
  let who = provisioning_principal()
  let revoked =
    transaction(conn, fn() {
      case
        sqlite.exec(conn, "DELETE FROM api_keys WHERE id = ? AND org_id = ?", [
          Text(key_id),
          Text(org_id),
        ])
      {
        Ok(Done(1, _)) ->
          case
            audit(conn, who, org_id, "apikey.delete", [
              #("key", json.string(key_id)),
            ])
          {
            Ok(Nil) ->
              Ok(
                ok_json(
                  json.object([
                    #("result", json.object([#("revoked", json.bool(True))])),
                  ]),
                ),
              )
            // Rolls the delete back with it: a key that stopped working with
            // nothing saying when, or by whose hand, is where an incident
            // starts.
            Error(_) -> Error(db_error())
          }
        Ok(_) ->
          Error(error_json(
            404,
            "not_found",
            "no such API key in this workspace's org",
          ))
        Error(e) -> Error(constraint_response(e))
      }
    })
  case revoked {
    Ok(response) -> response
    Error(response) -> response
  }
}

fn not_configured() -> Response {
  error_json(
    503,
    "provisioning_not_configured",
    "cue provisioning is not enabled on this control plane",
  )
}

fn not_provisioned() -> Response {
  error_json(
    404,
    "workspace_not_provisioned",
    "this workspace has no synchronicity org yet",
  )
}
