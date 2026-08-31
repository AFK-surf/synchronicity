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
//// Idempotent by `cue_workspace_id` (unique in `cue_workspace_orgs`): a
//// repeat, a concurrent duplicate, or a retry converges on the one org. The
//// create path publishes the zone (a network is zone data); the ordinary reuse
//// path only backfills the owner's identity/membership and never republishes.
//// A duplicate that raced the create path rechecks after acquiring the writer
//// transaction and may perform one no-op republish rather than return a false
//// conflict.
//// The paired remote/local retry lifecycle is modeled in the Cue repository at
//// `tla/cue_synchronicity/WorkspaceProvisioning.tla`.

import api/auth_api.{type AuthContext, with_db}
import api/common.{
  body_decoder, constraint_response, db_error, ok_json, transaction,
  zone_mutation,
}
import api/middleware.{Bearer, error_json, now_unix, presented}
import auth/principal
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

/// `PUT /internal/v1/integrations/cue/workspaces/<cue_workspace_id>`.
pub fn provision_workspace(
  req: Request,
  ctx: AuthContext,
  cue_workspace_id: String,
) -> Response {
  case ctx.cue_provisioning {
    None ->
      error_json(
        503,
        "provisioning_not_configured",
        "cue provisioning is not enabled on this control plane",
      )
    Some(cfg) -> {
      use <- authorized(req, cfg)
      use <- valid_id(cue_workspace_id, "invalid_workspace")
      let owner_decoder = {
        use subject <- decode.field("subject", decode.string)
        use email <- decode.field("email", decode.string)
        use name <- decode.optional_field(
          "name",
          None,
          decode.optional(decode.string),
        )
        decode.success(Owner(subject, email, name))
      }
      let decoder = {
        use ws_name <- decode.field("name", decode.string)
        use owner <- decode.field("owner", owner_decoder)
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
                case find_workspace_org(conn, cue_workspace_id) {
                  Error(response) -> response
                  Ok(Some(#(org_id, network_id))) ->
                    reuse(conn, cfg, org_id, network_id, owner)
                  Ok(None) ->
                    create(conn, ctx, cfg, cue_workspace_id, ws_name, owner)
                }
            }
          })
      }
    }
  }
}

/// The reuse path: the Workspace already has an org. Only ensure the owner's
/// identity and membership are present (an earlier call whose identity write
/// is being retried), never touching the zone.
fn reuse(
  conn: Connection,
  cfg: CueProvisioning,
  org_id: String,
  network_id: String,
  owner: Owner,
) -> Response {
  case
    transaction(conn, fn() {
      use sync_user_id <- result.try(ensure_owner(conn, cfg, org_id, owner))
      Ok(provisioned(org_id, network_id, sync_user_id, False))
    })
  {
    Ok(payload) -> ok_json(json.object([#("result", payload)]))
    Error(response) -> response
  }
}

/// The create path: mint the org + default network + owner identity +
/// membership + the workspace mapping, and publish the zone in one
/// transaction (a network is zone data). `zone_mutation` returns
/// `{ok, soa_serial, result}`; the caller reads `result`.
fn create(
  conn: Connection,
  ctx: AuthContext,
  cfg: CueProvisioning,
  cue_workspace_id: String,
  ws_name: String,
  owner: Owner,
) -> Response {
  // A synthetic principal: the provisioning secret has already authenticated
  // the caller, so `who` is only the audit/zone actor here.
  let who = principal.Principal("cue:provisioning", principal.Cookie(""))

  zone_mutation(conn, ctx, who, publish.Widening, fn() {
    // The fast-path lookup happens before the transaction. Recheck after the
    // SQLite writer lock is held: another request may have committed the one
    // mapping while this request waited to enter `zone_mutation`.
    case find_workspace_org(conn, cue_workspace_id) {
      Error(response) -> Error(response)
      Ok(Some(#(org_id, network_id))) -> {
        use sync_user_id <- result.try(ensure_owner(conn, cfg, org_id, owner))
        Ok(provisioned(org_id, network_id, sync_user_id, False))
      }
      Ok(None) -> {
        let org_id = id.new()
        let network_id = id.new()

        use _ <- result.try(insert_org(conn, org_id, ws_name))
        use _ <- result.try(insert_network(conn, network_id, org_id))
        use sync_user_id <- result.try(ensure_owner(conn, cfg, org_id, owner))
        use _ <- result.try(insert_mapping(
          conn,
          cue_workspace_id,
          org_id,
          network_id,
        ))

        Ok(provisioned(org_id, network_id, sync_user_id, True))
      }
    }
  })
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

fn insert_org(
  conn: Connection,
  org_id: String,
  ws_name: String,
) -> Result(Nil, Response) {
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
    Ok(_) -> Ok(Nil)
    Error(e) -> Error(constraint_response(e))
  }
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
/// membership of the org, returning the Synchronicity user id. Never merges on
/// email: an email owned by a different user is a 409 for an explicit link.
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
        Ok(Some(_)) ->
          Error(error_json(
            409,
            "explicit_link_required",
            "a synchronicity user with this email already exists and is not "
              <> "linked to this cue identity",
          ))
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

fn provisioned(
  org_id: String,
  network_id: String,
  sync_user_id: String,
  created: Bool,
) -> Json {
  json.object([
    #("org_id", json.string(org_id)),
    #("network_id", json.string(network_id)),
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
    None ->
      error_json(
        503,
        "provisioning_not_configured",
        "cue provisioning is not enabled on this control plane",
      )
    Some(cfg) -> {
      use <- authorized(req, cfg)
      use <- valid_id(cue_workspace_id, "invalid_workspace")
      let owner_decoder = {
        use subject <- decode.field("subject", decode.string)
        use email <- decode.field("email", decode.string)
        use name <- decode.optional_field(
          "name",
          None,
          decode.optional(decode.string),
        )
        decode.success(Owner(subject, email, name))
      }
      let decoder = {
        use nk <- decode.field("nk", decode.string)
        use label <- decode.field("label", decode.string)
        use owner <- decode.field("owner", owner_decoder)
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
                      Ok(None) ->
                        error_json(
                          404,
                          "workspace_not_provisioned",
                          "this workspace has no synchronicity org yet",
                        )
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
      let who = principal.Principal("cue:provisioning", principal.Cookie(""))
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
  let who = principal.Principal("cue:provisioning", principal.Cookie(""))
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
    #("network", json.string("default")),
    #("domain", json.string(domain)),
    #("created", json.bool(created)),
  ])
}
