//// Networks and their device assignments — the zone-shaping API. Every
//// mutation here republishes the zone inside its own transaction, so DNS
//// contents and tables can never disagree. Devices and keys live in
//// api/devices_api.

import api/auth_api.{type AuthContext, with_db}
import api/common.{
  Admin, Member, audit, body_decoder, constraint_response, db_error, find_device,
  find_network, ok_json, require_org, text_at, zone_mutation,
}
import api/middleware.{error_json, now_unix}
import api/reads.{type Reads}
import auth/session.{type Session}
import dns/name
import gleam/dynamic/decode
import gleam/json
import gleam/result
import gleam/string
import store/sqlite.{Int as VInt, Text}
import util/id
import wisp.{type Request, type Response}
import zone/model
import zone/publish

pub fn list_networks(reads: Reads, live: Session, slug: String) -> Response {
  reads.with_db(reads, fn(conn) {
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
  case name.valid_dns_label(network) {
    False -> error_json(400, "bad_name", "network name must be a DNS label")
    True ->
      with_db(ctx, fn(conn) {
        use org_id, _ <- require_org(conn, slug, live.user_id, Admin)
        zone_mutation(conn, ctx, live.user_id, publish.Widening, fn() {
          let insert =
            sqlite.exec(
              conn,
              "INSERT INTO networks (id, org_id, name, created_at)
               VALUES (?, ?, ?, ?)",
              [
                Text(id.new()),
                Text(org_id),
                Text(network),
                VInt(now_unix()),
              ],
            )
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

pub fn network_detail(
  reads: Reads,
  live: Session,
  slug: String,
  network: String,
) -> Response {
  reads.with_db(reads, fn(conn) {
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
          _, _, _ -> db_error()
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
            zone_mutation(conn, ctx, live.user_id, publish.Narrowing, fn() {
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
        zone_mutation(conn, ctx, live.user_id, publish.Widening, fn() {
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
            Error(_) -> Error(db_error())
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
        zone_mutation(conn, ctx, live.user_id, publish.Narrowing, fn() {
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
