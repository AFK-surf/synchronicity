//// Shared plumbing for the product API: RBAC, slug resolution, the
//// zone-mutation transaction wrapper, and JSON helpers.

import api/auth_api.{type AuthContext}
import api/middleware.{error_json, now_unix}
import gleam/dynamic/decode
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Int as VInt, Text}
import wisp.{type Request, type Response}
import zone/build
import zone/publish

pub type Role {
  Owner
  Admin
  Member
}

fn rank(role: Role) -> Int {
  case role {
    Owner -> 3
    Admin -> 2
    Member -> 1
  }
}

pub fn role_to_string(role: Role) -> String {
  case role {
    Owner -> "owner"
    Admin -> "admin"
    Member -> "member"
  }
}

pub fn role_from_string(text: String) -> Result(Role, Nil) {
  case text {
    "owner" -> Ok(Owner)
    "admin" -> Ok(Admin)
    "member" -> Ok(Member)
    _ -> Error(Nil)
  }
}

/// Resolves an org slug to its id and the caller's role — non-members get
/// the same 404 as nonexistent orgs (no org enumeration).
pub fn require_org(
  conn: Connection,
  slug: String,
  user_id: String,
  minimum: Role,
  next: fn(String, Role) -> Response,
) -> Response {
  case check_org(conn, slug, user_id, minimum) {
    Ok(#(org_id, role)) -> next(org_id, role)
    Error(refusal) -> refusal
  }
}

/// `require_org` for a caller that must hand its connection back before it
/// does its work.
///
/// The browse API is that caller: its work is a round trip to a daemon on
/// somebody's LAN, and holding a pooled connection across one would put the
/// whole pool behind the slowest cluster on the internet — the same reasoning
/// `router.with_session` spells out for sessions.
pub fn check_org(
  conn: Connection,
  slug: String,
  user_id: String,
  minimum: Role,
) -> Result(#(String, Role), Response) {
  let lookup =
    sqlite.query(
      conn,
      "SELECT o.id, m.role FROM orgs o
       JOIN org_members m ON m.org_id = o.id AND m.user_id = ?
       WHERE o.slug = ?",
      [Text(user_id), Text(slug)],
    )
  case lookup {
    Ok([[Text(org_id), Text(role_text)]]) ->
      case role_from_string(role_text) {
        Ok(role) ->
          case rank(role) >= rank(minimum) {
            True -> Ok(#(org_id, role))
            False ->
              Error(error_json(
                403,
                "forbidden",
                "requires " <> role_to_string(minimum) <> " role",
              ))
          }
        Error(Nil) -> Error(error_json(500, "internal", "corrupt role"))
      }
    Ok(_) -> Error(error_json(404, "not_found", "no such org"))
    Error(_) -> Error(db_error())
  }
}

/// Runs `work` inside BEGIN IMMEDIATE / COMMIT with rollback on every
/// failure path — for multi-statement mutations that do not touch the
/// zone (org creation, invite acceptance, OIDC config removal). Partial
/// writes must be unrepresentable, not merely unlikely.
pub fn transaction(
  conn: Connection,
  work: fn() -> Result(a, Response),
) -> Result(a, Response) {
  sqlite.transaction(
    conn,
    fn(_) { error_json(500, "internal", "transaction failed") },
    work,
  )
}

/// Runs `work` and a full zone republish in one transaction. Every product
/// mutation goes through here — the zone on disk is never out of step with
/// the tables, and an invariant violation rolls the whole thing back.
/// DNS answers read the database directly, so the commit itself is what
/// makes the mutation visible — there is no cache to refresh.
///
/// `change` is the handler's own statement about what its mutation does to
/// the zone (`publish.Change`): a removal must reach the wire even while the
/// transparency gate is holding new claims back, since the alternative is a
/// revoked key that stays resolvable.
pub fn zone_mutation(
  conn: Connection,
  ctx: AuthContext,
  actor: String,
  change: publish.Change,
  work: fn() -> Result(Json, Response),
) -> Response {
  let outcome =
    transaction(conn, fn() {
      use payload <- result.try(work())
      use serial <- result.try(
        ctx.publish_in_tx(conn, now_unix(), actor, change)
        |> result.map_error(publish_error),
      )
      Ok(#(payload, serial))
    })
  case outcome {
    Ok(#(payload, serial)) -> {
      // After commit, never inside it: in external mode this pokes the
      // reconciler, and a provider API call must not hold the write lock.
      ctx.published()
      json.object([
        #("ok", json.bool(True)),
        #("soa_serial", json.int(serial)),
        #("result", payload),
      ])
      |> json.to_string
      |> wisp.json_response(200)
    }
    Error(response) -> response
  }
}

fn publish_error(e: publish.PublishError) -> Response {
  case e {
    publish.Build(build_error) -> {
      let #(code, message) = build_refusal(build_error)
      error_json(409, code, "zone build refused: " <> message)
    }
    // The transparency gate. Not a client mistake, but naming the ceremony
    // step that is missing is worth far more to whoever is looking at the
    // dashboard than a generic 500 would be.
    publish.NoRekorRecord(key_tag) ->
      error_json(
        409,
        "no_rekor_record",
        "the zone key (tag "
          <> int.to_string(key_tag)
          <> ") is not on the transparency record, so this change cannot be "
          <> "published: run `controlplane rekor-publish <keyfile>`",
      )
    // Db / Model / KeyMismatch are server faults, not client mistakes:
    // the detail goes to the log, never into a response body.
    _ -> {
      wisp.log_error("zone publish failed: " <> string.inspect(e))
      error_json(500, "internal", "publish failed")
    }
  }
}

/// Human text (and a stable error code) for every way a zone build can
/// refuse — constructor dumps never reach API clients.
///
/// Public because the API layer refuses the same three per-member rules up
/// front, before attempting a mutation (see api/devices_api). That check is
/// deliberately separate from this one, but the *vocabulary* is not: one
/// broken rule must name itself the same way whether it is caught at the
/// request or at the publish, or a client cannot write one handler for it.
/// Only the status differs — 400 for a malformed request, 409 because the
/// zone the request would produce is the malformed thing.
pub fn build_refusal(e: build.BuildError) -> #(String, String) {
  case e {
    build.NoNameservers -> #(
      "no_nameservers",
      "the zone has no nameservers configured",
    )
    build.OwnerOutsideZone(owner) -> #(
      "owner_outside_zone",
      "record owner " <> owner <> " is outside the zone",
    )
    build.DuplicateLabelInZone(label) -> #(
      "duplicate_label",
      "device label '"
        <> label
        <> "' appears more than twice in one network — beyond the two-key rotation window",
    )
    build.InvalidLabel(label) -> #(
      "invalid_label",
      "device label '"
        <> label
        <> "' is not valid — lowercase letters, digits and hyphens, at most 63 bytes",
    )
    build.InvalidNk(_) -> #(
      "invalid_nk",
      "a device key is not a 52-character z-base-32 ed25519 public key — the "
        <> "`nk` value printed by `synch id`",
    )
    build.AmbiguousNk(_) -> #(
      "ambiguous_nk",
      "one key is bound to two different device labels — a key may belong to one device only (§3.2 ambiguity rule)",
    )
    build.BadGlueAddress(address) -> #(
      "bad_glue",
      "nameserver glue address '" <> address <> "' is not a valid IP address",
    )
    build.InvalidHint(_) -> #(
      "bad_hint",
      "a relay or addr hint carries whitespace, a quote, or more than 255 characters — it would change the shape of the membership record it sits in",
    )
  }
}

/// Maps a SQLite constraint failure to a 409 that names the invariant.
pub fn constraint_response(error: sqlite.Error) -> Response {
  case error {
    sqlite.Sqlite(_, message) -> {
      let named = case
        string.contains(message, "device_keys.nk_bytes")
        || string.contains(message, "device_keys_live_nk"),
        string.contains(message, "label already used")
      {
        True, _ ->
          "this key is already bound to a device — a key may belong to one device only (§3.2 ambiguity rule)"
        _, True -> "a device with this label is already in the network"
        // Unmapped constraint: raw SQLite messages name tables and
        // columns — log the detail, answer generically.
        _, _ -> {
          wisp.log_error("unmapped constraint failure: " <> message)
          "the change conflicts with an existing record"
        }
      }
      error_json(409, "conflict", named)
    }
    _ -> db_error()
  }
}

/// The uniform 500 for any storage failure — details belong in the log,
/// never the response body.
pub fn db_error() -> Response {
  error_json(500, "internal", "database error")
}

pub fn audit(
  conn: Connection,
  actor: String,
  org_id: String,
  action: String,
  detail: Json,
) -> Result(Nil, sqlite.Error) {
  sqlite.exec(
    conn,
    "INSERT INTO audit_log (at, actor, org_id, action, detail)
     VALUES (?, ?, ?, ?, ?)",
    [
      VInt(now_unix()),
      Text(actor),
      Text(org_id),
      Text(action),
      Text(json.to_string(detail)),
    ],
  )
  |> result.replace(Nil)
}

/// Decodes a JSON request body, or answers 400.
pub fn body_decoder(
  req: Request,
  decoder: decode.Decoder(a),
  next: fn(a) -> Response,
) -> Response {
  use body <- wisp.require_string_body(req)
  case json.parse(body, decoder) {
    Ok(value) -> next(value)
    Error(_) -> error_json(400, "bad_request", "malformed JSON body")
  }
}

/// Resolves a network name within an org to its id.
pub fn find_network(
  conn: Connection,
  org_id: String,
  network: String,
) -> Result(String, Nil) {
  case
    sqlite.query(conn, "SELECT id FROM networks WHERE org_id = ? AND name = ?", [
      Text(org_id),
      Text(network),
    ])
  {
    Ok([[Text(network_id)]]) -> Ok(network_id)
    _ -> Error(Nil)
  }
}

/// Resolves a device id within an org to its label.
pub fn find_device(
  conn: Connection,
  org_id: String,
  device_id: String,
) -> Result(String, Nil) {
  case
    sqlite.query(conn, "SELECT label FROM devices WHERE id = ? AND org_id = ?", [
      Text(device_id),
      Text(org_id),
    ])
  {
    Ok([[Text(label)]]) -> Ok(label)
    _ -> Error(Nil)
  }
}

pub fn ok_json(payload: Json) -> Response {
  json.to_string(payload) |> wisp.json_response(200)
}

pub fn rows_json(
  rows: Result(List(List(sqlite.Value)), sqlite.Error),
  encode: fn(List(sqlite.Value)) -> Json,
) -> Response {
  case rows {
    Ok(items) -> ok_json(json.array(items, encode))
    Error(_) -> db_error()
  }
}

pub fn text_at(row: List(sqlite.Value), index: Int) -> String {
  case list.drop(row, index) {
    [Text(value), ..] -> value
    _ -> ""
  }
}

pub fn int_at(row: List(sqlite.Value), index: Int) -> Int {
  case list.drop(row, index) {
    [VInt(value), ..] -> value
    _ -> 0
  }
}
