//// Shared plumbing for the product API: RBAC, slug resolution, the
//// zone-mutation transaction wrapper, and JSON helpers.

import api/auth_api.{type AuthContext}
import api/middleware.{error_json, now_unix}
import auth/principal.{type Principal}
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
  who: Principal,
  minimum: Role,
  next: fn(String, Role) -> Response,
) -> Response {
  case check_org(conn, slug, who, minimum) {
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
/// `router.with_principal` spells out for credential resolution.
///
/// **This is the one place a credential becomes a permission**, and the two
/// credentials answer differently on purpose. A person's role is looked up in
/// `org_members`, because it is a fact about a membership that can change
/// under them. A key's role rides on the key: it is checked against the org
/// the key names and nothing else, so no membership — not its minter's, not
/// anybody's — can widen what it may do. A key aimed at another org gets the
/// same 404 a person outside the org gets, for the same reason: an org is not
/// enumerable by whoever cannot see it.
///
/// A key is never an `owner` (the schema's role grammar stops at `admin` for
/// the kinds that have a rank at all), so every owner-gated route refuses one
/// without naming keys at all.
///
/// **A join key never gets past here.** It carries no role, because there is
/// no rank at which "may add a device to this one network" sits, and inventing
/// the lowest one for it would hand it every read a member has. Refusing the
/// whole family in the one function every org-scoped route goes through is
/// what makes that scope real: the join endpoint admits a join key by checking
/// the network itself, and nothing else in the service can.
///
/// **Neither does a data-plane key**, and here the stakes are the other way
/// round. That credential names *no* org on purpose — its job is to be told
/// which networks of every org have hosting on — so there is nothing for the
/// `ApiKey` arm's "the org this key names, and nothing else" comparison to
/// compare against, and any arm that tried would be inventing a scope. The
/// explicit refusal is what makes docs/CLOUD-DATAPLANE.md §3.2's promise
/// structural: a leaked data-plane key cannot touch the org API at all,
/// because every org-scoped route in the service resolves its caller through
/// this function and this function names the variant and turns it away.
pub fn check_org(
  conn: Connection,
  slug: String,
  who: Principal,
  minimum: Role,
) -> Result(#(String, Role), Response) {
  case who.credential {
    principal.Cookie(_) -> member_org(conn, slug, who.user_id, minimum)
    principal.JoinKey(_, _, _) -> Error(middleware.join_key_refused())
    principal.Dataplane(_) -> Error(middleware.dataplane_refused())
    principal.ApiKey(_, key_org_id, role_text) ->
      case
        sqlite.query(conn, "SELECT id FROM orgs WHERE slug = ?", [Text(slug)])
      {
        Ok([[Text(org_id)]]) if org_id == key_org_id ->
          admit(org_id, role_text, minimum)
        Ok(_) -> Error(error_json(404, "not_found", "no such org"))
        Error(_) -> Error(db_error())
      }
  }
}

/// The gate on the one endpoint a join key can reach, and the same gate for
/// everybody else who reaches it.
///
/// Resolves the org and network the path names, and answers whether this
/// credential may put a device into that network. The two families differ in
/// what they are allowed to *see*, not only in what they may do:
///
///   * A person or an org key is held to the ordinary `Member` floor, and to
///     the ordinary 404 for an org they are not in.
///   * A join key is held to one network — its own. Aimed anywhere else it
///     gets the same 404 the path would give a stranger, so a leaked key
///     cannot be used to find out what else an org has.
pub fn check_join_target(
  conn: Connection,
  slug: String,
  network: String,
  who: Principal,
) -> Result(#(String, String), Response) {
  case who.credential {
    principal.JoinKey(_, key_org_id, key_network_id) ->
      case resolve_network(conn, slug, network) {
        Ok(#(org_id, network_id))
          if org_id == key_org_id && network_id == key_network_id
        -> Ok(#(org_id, network_id))
        Ok(_) -> Error(error_json(404, "not_found", "no such network"))
        Error(refusal) -> Error(refusal)
      }
    _ -> {
      use #(org_id, _role) <- result.try(check_org(conn, slug, who, Member))
      case find_network(conn, org_id, network) {
        Ok(network_id) -> Ok(#(org_id, network_id))
        Error(Nil) -> Error(error_json(404, "not_found", "no such network"))
      }
    }
  }
}

/// A network by org slug and name, without asking who wants it — the lookup
/// `check_join_target` needs before it can compare a join key's own ids
/// against what the path named.
fn resolve_network(
  conn: Connection,
  slug: String,
  network: String,
) -> Result(#(String, String), Response) {
  let lookup =
    sqlite.query(
      conn,
      "SELECT o.id, n.id FROM orgs o
       JOIN networks n ON n.org_id = o.id AND n.name = ?
       WHERE o.slug = ?",
      [Text(network), Text(slug)],
    )
  case lookup {
    Ok([[Text(org_id), Text(network_id)]]) -> Ok(#(org_id, network_id))
    Ok(_) -> Error(error_json(404, "not_found", "no such network"))
    Error(_) -> Error(db_error())
  }
}

fn member_org(
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
    Ok([[Text(org_id), Text(role_text)]]) -> admit(org_id, role_text, minimum)
    Ok(_) -> Error(error_json(404, "not_found", "no such org"))
    Error(_) -> Error(db_error())
  }
}

/// The role floor, applied to a role that has already been established for
/// this org — by membership or by the key's own row.
fn admit(
  org_id: String,
  role_text: String,
  minimum: Role,
) -> Result(#(String, Role), Response) {
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
  who: Principal,
  change: publish.Change,
  work: fn() -> Result(Json, Response),
) -> Response {
  let outcome =
    transaction(conn, fn() {
      use payload <- result.try(work())
      use serial <- result.try(
        ctx.publish_in_tx(conn, now_unix(), principal.actor(who), change)
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

/// Records what was done and by whom.
///
/// `actor` is `principal.actor`'s answer rather than a user id: a request
/// made with an API key names the key, which stays true after its minter has
/// changed role or left. The column carries no foreign key, precisely so it
/// can hold something that is not a user.
///
/// **A row written *here* by a key also carries who that key was**, folded
/// into the detail: its name, and the address of whoever minted it. That is
/// denormalisation on purpose, and for the reason `org.delete` already copies
/// the slug into its detail — the row that would answer the question later is
/// about to stop existing. `key:<id>` alone is resolvable only by finding the
/// `apikey.create` row that named it, which survives revocation but sits an
/// unbounded number of pages back in a log served fifty at a time. An entry
/// that cannot be read without a second lookup nobody will make is an entry
/// that does not say what it appears to.
///
/// The qualifier matters: `zone/publish` writes its own `zone.publish` rows
/// straight to the table, so the publish that accompanies every zone-shaping
/// mutation carries the actor and nothing else. The mutation's own row, right
/// beside it, is the one that names the credential.
///
/// Takes fields rather than a finished object so it can add its own; a
/// handler that wants a bare row passes `[]`.
pub fn audit(
  conn: Connection,
  who: Principal,
  org_id: String,
  action: String,
  detail: List(#(String, Json)),
) -> Result(Nil, sqlite.Error) {
  sqlite.exec(
    conn,
    "INSERT INTO audit_log (at, actor, org_id, action, detail)
     VALUES (?, ?, ?, ?, ?)",
    [
      VInt(now_unix()),
      Text(principal.actor(who)),
      Text(org_id),
      Text(action),
      Text(
        json.to_string(
          json.object(list.append(detail, credential_fields(conn, who))),
        ),
      ),
    ],
  )
  |> result.replace(Nil)
}

/// Who the credential was, for a row a key wrote. Empty for a person: the
/// actor column already names them, and there is nothing else to say.
fn credential_fields(
  conn: Connection,
  who: Principal,
) -> List(#(String, Json)) {
  case who.credential {
    principal.Cookie(_) -> []
    principal.ApiKey(key_id, _, _) | principal.JoinKey(key_id, _, _) ->
      describe_key(conn, key_id)
    // A different table, so a different lookup — `describe_key` would find
    // nothing in `api_keys` and say nothing, which reads as "the key was
    // revoked" rather than "this was never an org key". There is no minter to
    // name: these are minted at the operator CLI, where the actor is the
    // machine somebody had a shell on.
    principal.Dataplane(key_id) -> describe_dataplane_key(conn, key_id)
  }
}

fn describe_key(conn: Connection, key_id: String) -> List(#(String, Json)) {
  let looked =
    sqlite.query(
      conn,
      "SELECT k.name, coalesce(u.email, '') FROM api_keys k
       LEFT JOIN users u ON u.id = k.created_by
       WHERE k.id = ?",
      [Text(key_id)],
    )
  case looked {
    Ok([[Text(name), Text(email)]]) -> [
      #("key_name", json.string(name)),
      #("key_minted_by", json.string(email)),
    ]
    // A miss is ordinary rather than impossible: an admin may have revoked
    // the key between the request authenticating and this write, and the
    // query itself can fail. Say nothing rather than guess — the actor column
    // still names the key, and a lookup is not worth failing a mutation for.
    _ -> []
  }
}

fn describe_dataplane_key(
  conn: Connection,
  key_id: String,
) -> List(#(String, Json)) {
  case
    sqlite.query(conn, "SELECT name FROM dataplane_keys WHERE id = ?", [
      Text(key_id),
    ])
  {
    Ok([[Text(name)]]) -> [#("key_name", json.string(name))]
    // A miss is ordinary rather than impossible, for `describe_key`'s reasons:
    // the row can go between the request authenticating and this write, and the
    // query itself can fail. Say nothing rather than guess.
    _ -> []
  }
}

/// The reserved device-label namespace, refused in one voice.
///
/// `cloud-<n>` labels belong to the cloud data plane's hosting slots
/// (docs/CLOUD-DATAPLANE.md §3.4): only the data-plane principal may create
/// one, and every customer-facing path that takes a label refuses them here.
/// 409 rather than 400 because the label is *well formed* — it is a perfectly
/// good device label that this deployment has already spoken for, which is a
/// conflict, not a malformed request.
///
/// Public and shared so the two device-create paths refuse it identically; a
/// namespace enforced in two wordings is a namespace a client has to test for
/// twice.
pub fn reserved_label(label: String) -> Response {
  error_json(
    409,
    "reserved-label",
    "device label '"
      <> label
      <> "' is reserved: 'cloud-<n>' names a cloud-hosted replica's hosting "
      <> "slot, which only the hosting service may create",
  )
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
