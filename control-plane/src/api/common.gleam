//// Shared plumbing for the product API: RBAC, slug resolution, the
//// zone-mutation transaction wrapper, and JSON helpers.

import api/auth_api.{type AuthContext}
import api/middleware.{error_json, now_unix}
import gleam/json.{type Json}
import gleam/list
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Int as VInt, Text}
import wisp.{type Response}
import zone/publish
import zone/snapshot

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
            True -> next(org_id, role)
            False ->
              error_json(
                403,
                "forbidden",
                "requires " <> role_to_string(minimum) <> " role",
              )
          }
        Error(Nil) -> error_json(500, "internal", "corrupt role")
      }
    Ok(_) -> error_json(404, "not_found", "no such org")
    Error(_) -> error_json(500, "internal", "database error")
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
  case sqlite.exec(conn, "BEGIN IMMEDIATE", []) {
    Error(_) ->
      Error(error_json(500, "internal", "could not begin transaction"))
    Ok(_) ->
      case work() {
        Ok(value) ->
          case sqlite.exec(conn, "COMMIT", []) {
            Ok(_) -> Ok(value)
            Error(_) -> {
              let _ = sqlite.exec(conn, "ROLLBACK", [])
              Error(error_json(500, "internal", "commit failed"))
            }
          }
        Error(response) -> {
          let _ = sqlite.exec(conn, "ROLLBACK", [])
          Error(response)
        }
      }
  }
}

/// Runs `work` and a full zone republish in one transaction. Every product
/// mutation goes through here — the zone on disk is never out of step with
/// the tables, and an invariant violation rolls the whole thing back.
/// After commit the in-memory snapshot is reinstalled, so the primary's
/// own DNS/DoH answers reflect the mutation immediately, not at the next
/// restart or re-sign.
pub fn zone_mutation(
  conn: Connection,
  ctx: AuthContext,
  actor: String,
  work: fn() -> Result(Json, Response),
) -> Response {
  let outcome =
    transaction(conn, fn() {
      use payload <- result.try(work())
      use serial <- result.try(
        publish.publish_in_tx(conn, ctx.csk, now_unix(), actor)
        |> result.map_error(publish_error),
      )
      Ok(#(payload, serial))
    })
  case outcome {
    Ok(#(payload, serial)) -> {
      // Committed: the database is authoritative. Serving the fresh zone
      // is best-effort here — on failure the primary keeps the previous
      // snapshot (visible in /healthz) and replicas/resign still converge.
      case snapshot.load(conn, now_unix()) {
        Ok(snap) -> snapshot.install(snap)
        Error(_) ->
          wisp.log_error("zone_mutation: committed but snapshot reload failed")
      }
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
    publish.Build(build_error) ->
      error_json(
        409,
        "invariant",
        "zone build refused: " <> string.inspect(build_error),
      )
    _ -> error_json(500, "internal", "publish failed: " <> string.inspect(e))
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
        _, _ -> message
      }
      error_json(409, "conflict", named)
    }
    _ -> error_json(500, "internal", "database error")
  }
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

/// DNS-label grammar for org slugs and network names (no leading or
/// trailing hyphen — these become labels in the public zone).
pub fn valid_dns_label(label: String) -> Bool {
  let size = string.byte_size(label)
  size >= 1
  && size <= 63
  && !string.starts_with(label, "-")
  && !string.ends_with(label, "-")
  && chars_ok(<<label:utf8>>)
}

/// Device-label grammar ([a-z0-9-]{1,63}, hyphen position free).
pub fn valid_device_label(label: String) -> Bool {
  let size = string.byte_size(label)
  size >= 1 && size <= 63 && chars_ok(<<label:utf8>>)
}

fn chars_ok(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<b:int-size(8), rest:bits>> ->
      { { b >= 97 && b <= 122 } || { b >= 48 && b <= 57 } || b == 45 }
      && chars_ok(rest)
    _ -> False
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
    Error(_) -> error_json(500, "internal", "database error")
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

pub fn int_json(value: Int) -> Json {
  json.int(value)
}
