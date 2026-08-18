//// Devices and their keys. Every mutation here republishes the zone
//// inside its own transaction, so DNS contents and tables can never
//// disagree. Network membership lives in api/networks_api.

import api/agent
import api/auth_api.{type AuthContext, with_db}
import api/browse_api.{type Browse}
import api/common.{
  Admin, Member, audit, body_decoder, constraint_response, db_error, find_device,
  require_org, text_at, zone_mutation,
}
import api/middleware.{error_json, now_unix}
import auth/session.{type Session}
import dns/name
import gleam/dynamic/decode
import gleam/json
import gleam/option.{type Option, Some}
import gleam/result
import store/sqlite.{Blob, Int as VInt, Text}
import util/id
import wisp.{type Request, type Response}
import zone/build
import zone/model
import zone/publish

/// A per-member rule broken by the request itself. The code and the wording
/// come from `common.build_refusal`, so this refusal and the publish-time one
/// name the same fault identically; only the status says which of the two
/// caught it — 400 because the request is malformed, where the publish
/// answers 409 because the zone it would produce is.
fn refused(fault: build.BuildError) -> Response {
  let #(code, message) = common.build_refusal(fault)
  error_json(400, code, message)
}

/// Whichever hint is the invalid one, so the refusal quotes the offender
/// rather than both fields.
fn bad_hint(relay: String, addr: String) -> build.BuildError {
  case build.valid_hint(relay) {
    False -> build.InvalidHint(relay)
    True -> build.InvalidHint(addr)
  }
}

pub fn list_devices(ctx: AuthContext, live: Session, slug: String) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Member)
    let rows =
      sqlite.query(
        conn,
        "SELECT d.id, d.label, coalesce(d.relay, ''), coalesce(d.addr, ''),
                k.id, k.nk_z32, k.state,
                coalesce(group_concat(DISTINCT n.name), '')
         FROM devices d
         LEFT JOIN device_keys k ON k.device_id = d.id AND k.state != 'revoked'
         LEFT JOIN network_devices nd ON nd.device_id = d.id
         LEFT JOIN networks n ON n.id = nd.network_id
         WHERE d.org_id = ?
         GROUP BY d.id, k.id
         ORDER BY d.label, k.added_at",
        [Text(org_id)],
      )
    common.rows_json(rows, fn(row) {
      json.object([
        #("device_id", json.string(text_at(row, 0))),
        #("label", json.string(text_at(row, 1))),
        #("relay", json.string(text_at(row, 2))),
        #("addr", json.string(text_at(row, 3))),
        #("key_id", json.string(text_at(row, 4))),
        #("nk", json.string(text_at(row, 5))),
        #("state", json.string(text_at(row, 6))),
        #("networks", json.string(text_at(row, 7))),
      ])
    })
  })
}

pub fn create_device(
  req: Request,
  ctx: AuthContext,
  live: Session,
  slug: String,
) -> Response {
  let decoder = {
    use label <- decode.field("label", decode.string)
    use nk <- decode.field("nk", decode.string)
    use relay <- decode.optional_field("relay", "", decode.string)
    use addr <- decode.optional_field("addr", "", decode.string)
    decode.success(#(label, nk, relay, addr))
  }
  use #(label, nk, relay, addr) <- body_decoder(req, decoder)
  case
    name.valid_device_label(label),
    model.validate_nk(nk),
    build.valid_hint(relay) && build.valid_hint(addr)
  {
    False, _, _ -> refused(build.InvalidLabel(label))
    _, Error(Nil), _ -> refused(build.InvalidNk(nk))
    // Refused here as well as at publish. A membership record is
    // whitespace-separated key=value pairs, so a hint carrying whitespace
    // is extra fields rather than one value — and a second apex= makes the
    // client refuse the whole record.
    _, _, False -> refused(bad_hint(relay, addr))
    True, Ok(nk_bytes), True ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, live.user_id, Member)
        zone_mutation(conn, ctx, live.user_id, publish.Widening, fn() {
          let device_id = id.new()
          let work = {
            use _ <- result.try(
              sqlite.exec(
                conn,
                "INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                  Text(device_id),
                  Text(org_id),
                  Text(label),
                  sqlite.text_or_null(relay),
                  sqlite.text_or_null(addr),
                  Text(live.user_id),
                  VInt(now_unix()),
                ],
              ),
            )
            use _ <- result.try(
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
              ),
            )
            audit(
              conn,
              live.user_id,
              org_id,
              "device.create",
              json.object([
                #("label", json.string(label)),
                #("nk", json.string(nk)),
              ]),
            )
          }
          case work {
            Ok(Nil) -> Ok(json.object([#("device_id", json.string(device_id))]))
            Error(e) -> Error(constraint_response(e))
          }
        })
      })
  }
}

pub fn patch_device(
  req: Request,
  ctx: AuthContext,
  live: Session,
  slug: String,
  device_id: String,
) -> Response {
  let decoder = {
    use relay <- decode.optional_field("relay", "", decode.string)
    use addr <- decode.optional_field("addr", "", decode.string)
    decode.success(#(relay, addr))
  }
  use #(relay, addr) <- body_decoder(req, decoder)
  // Refused here as well as at publish: see the create handler above.
  case build.valid_hint(relay) && build.valid_hint(addr) {
    False -> refused(bad_hint(relay, addr))
    True ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, live.user_id, Member)
        case find_device(conn, org_id, device_id) {
          Error(Nil) -> error_json(404, "not_found", "no such device")
          Ok(_) ->
            zone_mutation(conn, ctx, live.user_id, publish.Widening, fn() {
              let update =
                sqlite.exec(
                  conn,
                  "UPDATE devices SET relay = ?, addr = ? WHERE id = ?",
                  [
                    sqlite.text_or_null(relay),
                    sqlite.text_or_null(addr),
                    Text(device_id),
                  ],
                )
              case update {
                Ok(_) -> {
                  let _ =
                    audit(
                      conn,
                      live.user_id,
                      org_id,
                      "device.update",
                      json.object([#("device", json.string(device_id))]),
                    )
                  Ok(json.object([#("device_id", json.string(device_id))]))
                }
                Error(e) -> Error(constraint_response(e))
              }
            })
        }
      })
  }
}

pub fn delete_device(
  ctx: AuthContext,
  live: Session,
  slug: String,
  device_id: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Admin)
    case find_device(conn, org_id, device_id) {
      Error(Nil) -> error_json(404, "not_found", "no such device")
      Ok(label) ->
        zone_mutation(conn, ctx, live.user_id, publish.Narrowing, fn() {
          let work = {
            use _ <- result.try(
              sqlite.exec(
                conn,
                "DELETE FROM network_devices WHERE device_id = ?",
                [Text(device_id)],
              ),
            )
            use _ <- result.try(
              sqlite.exec(conn, "DELETE FROM device_keys WHERE device_id = ?", [
                Text(device_id),
              ]),
            )
            use _ <- result.try(
              sqlite.exec(conn, "DELETE FROM devices WHERE id = ?", [
                Text(device_id),
              ]),
            )
            audit(
              conn,
              live.user_id,
              org_id,
              "device.delete",
              json.object([#("label", json.string(label))]),
            )
          }
          case work {
            Ok(Nil) -> Ok(json.object([#("deleted", json.string(label))]))
            Error(e) -> Error(constraint_response(e))
          }
        })
    }
  })
}

// -- keys -------------------------------------------------------------------

/// Opens a rotation window: the new key becomes active, the old active key
/// moves to retiring, both stay published until the old one is retired.
pub fn add_key(
  req: Request,
  ctx: AuthContext,
  live: Session,
  slug: String,
  device_id: String,
) -> Response {
  let decoder = {
    use nk <- decode.field("nk", decode.string)
    decode.success(nk)
  }
  use nk <- body_decoder(req, decoder)
  case model.validate_nk(nk) {
    Error(Nil) -> refused(build.InvalidNk(nk))
    Ok(nk_bytes) ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, live.user_id, Member)
        case find_device(conn, org_id, device_id) {
          Error(Nil) -> error_json(404, "not_found", "no such device")
          Ok(_) -> {
            let live_keys =
              sqlite.query(
                conn,
                "SELECT count(*) FROM device_keys
                 WHERE device_id = ? AND state != 'revoked'",
                [Text(device_id)],
              )
            case live_keys {
              Ok([[VInt(count)]]) if count >= 2 ->
                error_json(
                  409,
                  "rotation_open",
                  "a rotation window is already open — retire the old key first",
                )
              Ok(_) ->
                zone_mutation(conn, ctx, live.user_id, publish.Widening, fn() {
                  let work = {
                    use _ <- result.try(
                      sqlite.exec(
                        conn,
                        "UPDATE device_keys SET state = 'retiring'
                       WHERE device_id = ? AND state = 'active'",
                        [Text(device_id)],
                      ),
                    )
                    use _ <- result.try(
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
                      ),
                    )
                    audit(
                      conn,
                      live.user_id,
                      org_id,
                      "device.key.add",
                      json.object([
                        #("device", json.string(device_id)),
                        #("nk", json.string(nk)),
                      ]),
                    )
                  }
                  case work {
                    Ok(Nil) ->
                      Ok(json.object([#("rotation_open", json.bool(True))]))
                    Error(e) -> Error(constraint_response(e))
                  }
                })
              Error(_) -> db_error()
            }
          }
        }
      })
  }
}

/// The two ways a key leaves the zone. Both end in state 'revoked'; they
/// differ in who may do it, which states qualify, and what a miss means.
type KeyChange {
  /// Closes a rotation window (member): only a retiring key qualifies.
  Retire
  /// Revokes outright (admin): any live state, effective at the next
  /// resolver refresh — DNS is not a kill switch and the UI says so.
  Revoke
}

pub fn retire_key(
  ctx: AuthContext,
  live: Session,
  slug: String,
  device_id: String,
  key_id: String,
) -> Response {
  key_state_change(ctx, live, slug, device_id, key_id, Retire)
}

/// Revoking a key takes it out of the zone — and out of every tunnel
/// standing on it, in the same request.
///
/// Attach proofs verify only against `active` keys, so a revoked key cannot
/// attach again; without this a session that had already attached would keep
/// answering until it happened to reconnect, which is the one window the
/// revocation exists to close.
pub fn revoke_key(
  ctx: AuthContext,
  browse: Option(Browse),
  live: Session,
  slug: String,
  device_id: String,
  key_id: String,
) -> Response {
  let outcome = key_state_change(ctx, live, slug, device_id, key_id, Revoke)
  case outcome.status, browse {
    200, Some(browse) -> agent.drop_key(browse_api.registry(browse), key_id)
    _, _ -> Nil
  }
  outcome
}

fn key_state_change(
  ctx: AuthContext,
  live: Session,
  slug: String,
  device_id: String,
  key_id: String,
  change: KeyChange,
) -> Response {
  // The condition is one of two literals — never user input.
  let #(minimum, condition, action, done_field) = case change {
    Retire -> #(Member, "state = 'retiring'", "device.key.retire", "retired")
    Revoke -> #(Admin, "state != 'revoked'", "device.key.revoke", "revoked")
  }
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, minimum)
    case find_device(conn, org_id, device_id) {
      Error(Nil) -> error_json(404, "not_found", "no such device")
      Ok(_) ->
        zone_mutation(conn, ctx, live.user_id, publish.Narrowing, fn() {
          let update =
            sqlite.exec(
              conn,
              "UPDATE device_keys SET state = 'revoked', retired_at = ?
               WHERE id = ? AND device_id = ? AND " <> condition,
              [VInt(now_unix()), Text(key_id), Text(device_id)],
            )
          case update {
            Ok(sqlite.Done(1, _)) -> {
              let _ =
                audit(
                  conn,
                  live.user_id,
                  org_id,
                  action,
                  json.object([#("key", json.string(key_id))]),
                )
              Ok(json.object([#(done_field, json.string(key_id))]))
            }
            Ok(_) -> Error(no_qualifying_key(change))
            Error(e) -> Error(constraint_response(e))
          }
        })
    }
  })
}

fn no_qualifying_key(change: KeyChange) -> Response {
  case change {
    Retire ->
      error_json(
        409,
        "not_retiring",
        "only a retiring key can be retired — open a rotation first",
      )
    Revoke -> error_json(404, "not_found", "no such live key")
  }
}
