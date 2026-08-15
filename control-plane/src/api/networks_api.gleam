//// Networks, devices and device keys — the zone-shaping API. Every
//// mutation here republishes the zone inside its own transaction, so DNS
//// contents and tables can never disagree.

import api/auth_api.{type AuthContext, with_db}
import api/common.{
  Admin, Member, audit, constraint_response, ok_json, require_org, text_at,
  valid_device_label, valid_dns_label, zone_mutation,
}
import api/middleware.{error_json, now_unix}
import auth/session.{type Session}
import dns/name
import gleam/dynamic/decode
import gleam/json
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Blob, Int as VInt, Null, Text}
import util/id
import wisp.{type Request, type Response}
import zone/model

fn body_decoder(
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

// -- networks ---------------------------------------------------------------

pub fn list_networks(
  ctx: AuthContext,
  live: Session,
  slug: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Member)
    let rows =
      sqlite.query(
        conn,
        "SELECT n.name, count(nd.device_id)
         FROM networks n LEFT JOIN network_devices nd ON nd.network_id = n.id
         WHERE n.org_id = ? GROUP BY n.id ORDER BY n.name",
        [Text(org_id)],
      )
    common.rows_json(rows, fn(row) {
      json.object([
        #("name", json.string(text_at(row, 0))),
        #("device_count", json.int(common.int_at(row, 1))),
      ])
    })
  })
}

pub fn create_network(
  req: Request,
  ctx: AuthContext,
  live: Session,
  slug: String,
) -> Response {
  let decoder = {
    use network <- decode.field("name", decode.string)
    decode.success(network)
  }
  use network <- body_decoder(req, decoder)
  case valid_dns_label(network) {
    False -> error_json(400, "bad_name", "network name must be a DNS label")
    True ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, live.user_id, Admin)
        zone_mutation(conn, ctx, live.user_id, fn() {
          let insert =
            sqlite.exec(conn, "INSERT INTO networks VALUES (?, ?, ?, ?)", [
              Text(id.new()),
              Text(org_id),
              Text(network),
              VInt(now_unix()),
            ])
          case insert {
            Ok(_) -> {
              let _ =
                audit(
                  conn,
                  live.user_id,
                  org_id,
                  "network.create",
                  json.object([#("name", json.string(network))]),
                )
              Ok(json.object([#("name", json.string(network))]))
            }
            Error(e) -> Error(constraint_response(e))
          }
        })
      })
  }
}

fn find_network(
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

pub fn network_detail(
  ctx: AuthContext,
  live: Session,
  slug: String,
  network: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Member)
    case find_network(conn, org_id, network) {
      Error(Nil) -> error_json(404, "not_found", "no such network")
      Ok(network_id) -> {
        let meta = model.read_meta(conn)
        let devices =
          sqlite.query(
            conn,
            "SELECT d.id, d.label, coalesce(d.relay, ''), coalesce(d.addr, ''),
                    k.id, k.nk_z32, k.state, k.added_at
             FROM network_devices nd
             JOIN devices d ON d.id = nd.device_id
             LEFT JOIN device_keys k ON k.device_id = d.id AND k.state != 'revoked'
             WHERE nd.network_id = ?
             ORDER BY d.label, k.added_at",
            [Text(network_id)],
          )
        let zone_status =
          sqlite.query(
            conn,
            "SELECT coalesce(min(sig_expires_at), 0), coalesce(max(signed_at), 0)
             FROM presigned_rrsets",
            [],
          )
        case meta, devices, zone_status {
          Ok(zone_meta), Ok(device_rows), Ok([[VInt(expires), VInt(signed_at)]])
          ->
            ok_json(
              json.object([
                #(
                  "domain",
                  json.string(
                    network <> "." <> slug <> "." <> domain_of(zone_meta),
                  ),
                ),
                #("soa_serial", json.int(zone_meta.soa_serial)),
                #("sig_expires_at", json.int(expires)),
                #("last_published_at", json.int(signed_at)),
                #(
                  "devices",
                  json.array(device_rows, fn(row) {
                    json.object([
                      #("device_id", json.string(text_at(row, 0))),
                      #("label", json.string(text_at(row, 1))),
                      #("relay", json.string(text_at(row, 2))),
                      #("addr", json.string(text_at(row, 3))),
                      #("key_id", json.string(text_at(row, 4))),
                      #("nk", json.string(text_at(row, 5))),
                      #("state", json.string(text_at(row, 6))),
                      #("added_at", json.int(common.int_at(row, 7))),
                    ])
                  }),
                ),
              ]),
            )
          _, _, _ -> error_json(500, "internal", "database error")
        }
      }
    }
  })
}

fn domain_of(meta: model.ZoneMeta) -> String {
  // apex without the trailing dot, for display alongside slug/network.
  string.drop_end(name.to_string(meta.apex), 1)
}

pub fn delete_network(
  req: Request,
  ctx: AuthContext,
  live: Session,
  slug: String,
  network: String,
) -> Response {
  let decoder = {
    use confirm <- decode.field("confirm", decode.string)
    decode.success(confirm)
  }
  use confirm <- body_decoder(req, decoder)
  case confirm == network {
    False ->
      error_json(400, "confirm", "body confirm must equal the network name")
    True ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, live.user_id, Admin)
        case find_network(conn, org_id, network) {
          Error(Nil) -> error_json(404, "not_found", "no such network")
          Ok(network_id) ->
            zone_mutation(conn, ctx, live.user_id, fn() {
              let work = {
                use _ <- result.try(
                  sqlite.exec(
                    conn,
                    "DELETE FROM network_devices WHERE network_id = ?",
                    [Text(network_id)],
                  ),
                )
                use _ <- result.try(
                  sqlite.exec(conn, "DELETE FROM networks WHERE id = ?", [
                    Text(network_id),
                  ]),
                )
                audit(
                  conn,
                  live.user_id,
                  org_id,
                  "network.delete",
                  json.object([#("name", json.string(network))]),
                )
              }
              case work {
                Ok(Nil) -> Ok(json.object([#("deleted", json.string(network))]))
                Error(e) -> Error(constraint_response(e))
              }
            })
        }
      })
  }
}

// -- devices ----------------------------------------------------------------

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
  case valid_device_label(label), model.validate_nk(nk) {
    False, _ ->
      error_json(400, "bad_label", "device label must match [a-z0-9-]{1,63}")
    _, Error(Nil) ->
      error_json(
        400,
        "bad_nk",
        "nk must be the 52-character z-base-32 device key from `synch id`",
      )
    True, Ok(nk_bytes) ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, live.user_id, Member)
        zone_mutation(conn, ctx, live.user_id, fn() {
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
                  nullable(relay),
                  nullable(addr),
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

fn nullable(text: String) -> sqlite.Value {
  case text {
    "" -> Null
    _ -> Text(text)
  }
}

fn find_device(
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
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Member)
    case find_device(conn, org_id, device_id) {
      Error(Nil) -> error_json(404, "not_found", "no such device")
      Ok(_) ->
        zone_mutation(conn, ctx, live.user_id, fn() {
          let update =
            sqlite.exec(
              conn,
              "UPDATE devices SET relay = ?, addr = ? WHERE id = ?",
              [nullable(relay), nullable(addr), Text(device_id)],
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
        zone_mutation(conn, ctx, live.user_id, fn() {
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
    Error(Nil) -> error_json(400, "bad_nk", "not a z-base-32 device key")
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
                zone_mutation(conn, ctx, live.user_id, fn() {
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
              Error(_) -> error_json(500, "internal", "database error")
            }
          }
        }
      })
  }
}

/// Closes a rotation window: the retiring key becomes revoked and leaves
/// the RRset.
pub fn retire_key(
  ctx: AuthContext,
  live: Session,
  slug: String,
  device_id: String,
  key_id: String,
) -> Response {
  key_state_change(
    ctx,
    live,
    slug,
    device_id,
    key_id,
    "retiring",
    "device.key.retire",
  )
}

/// Revokes a key outright (admin): any live state, effective at the next
/// resolver refresh — DNS is not a kill switch and the UI says so.
pub fn revoke_key(
  ctx: AuthContext,
  live: Session,
  slug: String,
  device_id: String,
  key_id: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Admin)
    case find_device(conn, org_id, device_id) {
      Error(Nil) -> error_json(404, "not_found", "no such device")
      Ok(_) ->
        zone_mutation(conn, ctx, live.user_id, fn() {
          let update =
            sqlite.exec(
              conn,
              "UPDATE device_keys SET state = 'revoked', retired_at = ?
               WHERE id = ? AND device_id = ? AND state != 'revoked'",
              [VInt(now_unix()), Text(key_id), Text(device_id)],
            )
          case update {
            Ok(sqlite.Done(1, _)) -> {
              let _ =
                audit(
                  conn,
                  live.user_id,
                  org_id,
                  "device.key.revoke",
                  json.object([#("key", json.string(key_id))]),
                )
              Ok(json.object([#("revoked", json.string(key_id))]))
            }
            Ok(_) -> Error(error_json(404, "not_found", "no such live key"))
            Error(e) -> Error(constraint_response(e))
          }
        })
    }
  })
}

fn key_state_change(
  ctx: AuthContext,
  live: Session,
  slug: String,
  device_id: String,
  key_id: String,
  from_state: String,
  action: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Member)
    case find_device(conn, org_id, device_id) {
      Error(Nil) -> error_json(404, "not_found", "no such device")
      Ok(_) ->
        zone_mutation(conn, ctx, live.user_id, fn() {
          let update =
            sqlite.exec(
              conn,
              "UPDATE device_keys SET state = 'revoked', retired_at = ?
               WHERE id = ? AND device_id = ? AND state = ?",
              [
                VInt(now_unix()),
                Text(key_id),
                Text(device_id),
                Text(from_state),
              ],
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
              Ok(json.object([#("retired", json.string(key_id))]))
            }
            Ok(_) ->
              Error(error_json(
                409,
                "not_retiring",
                "only a retiring key can be retired — open a rotation first",
              ))
            Error(e) -> Error(constraint_response(e))
          }
        })
    }
  })
}

// -- assignment -------------------------------------------------------------

pub fn assign_device(
  ctx: AuthContext,
  live: Session,
  slug: String,
  network: String,
  device_id: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Member)
    case
      find_network(conn, org_id, network),
      find_device(conn, org_id, device_id)
    {
      Error(Nil), _ -> error_json(404, "not_found", "no such network")
      _, Error(Nil) -> error_json(404, "not_found", "no such device")
      Ok(network_id), Ok(label) ->
        zone_mutation(conn, ctx, live.user_id, fn() {
          // App-level label check first for a friendly message; the trigger
          // and zone build re-verify.
          let clash =
            sqlite.query(
              conn,
              "SELECT 1 FROM network_devices nd JOIN devices d ON d.id = nd.device_id
               WHERE nd.network_id = ? AND d.label = ? AND d.id != ?",
              [Text(network_id), Text(label), Text(device_id)],
            )
          case clash {
            Ok([_, ..]) ->
              Error(error_json(
                409,
                "conflict",
                "a device labeled '" <> label <> "' is already in this network",
              ))
            Ok([]) -> {
              let work = {
                use _ <- result.try(
                  sqlite.exec(
                    conn,
                    "INSERT INTO network_devices VALUES (?, ?, ?)",
                    [Text(network_id), Text(device_id), VInt(now_unix())],
                  ),
                )
                audit(
                  conn,
                  live.user_id,
                  org_id,
                  "network.assign",
                  json.object([
                    #("network", json.string(network)),
                    #("label", json.string(label)),
                  ]),
                )
              }
              case work {
                Ok(Nil) -> Ok(json.object([#("assigned", json.string(label))]))
                Error(e) -> Error(constraint_response(e))
              }
            }
            Error(_) -> Error(error_json(500, "internal", "database error"))
          }
        })
    }
  })
}

pub fn unassign_device(
  ctx: AuthContext,
  live: Session,
  slug: String,
  network: String,
  device_id: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, live.user_id, Member)
    case find_network(conn, org_id, network) {
      Error(Nil) -> error_json(404, "not_found", "no such network")
      Ok(network_id) ->
        zone_mutation(conn, ctx, live.user_id, fn() {
          let delete =
            sqlite.exec(
              conn,
              "DELETE FROM network_devices WHERE network_id = ? AND device_id = ?",
              [Text(network_id), Text(device_id)],
            )
          case delete {
            Ok(sqlite.Done(1, _)) -> {
              let _ =
                audit(
                  conn,
                  live.user_id,
                  org_id,
                  "network.unassign",
                  json.object([#("device", json.string(device_id))]),
                )
              Ok(json.object([#("unassigned", json.string(device_id))]))
            }
            Ok(_) -> Error(error_json(404, "not_found", "not assigned"))
            Error(e) -> Error(constraint_response(e))
          }
        })
    }
  })
}
