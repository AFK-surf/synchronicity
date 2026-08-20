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
import auth/principal.{type Principal}
import dns/name
import gleam/dynamic/decode
import gleam/json
import gleam/result
import gleam/string
import store/sqlite.{Blob, Int as VInt, Text}
import util/id
import wisp.{type Request, type Response}
import zone/build
import zone/model
import zone/publish

pub fn list_networks(reads: Reads, who: Principal, slug: String) -> Response {
  reads.with_db(reads, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Member)
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
  who: Principal,
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
        use org_id, _ <- require_org(conn, slug, who, Admin)
        zone_mutation(conn, ctx, who, publish.Widening, fn() {
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
                  who,
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
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  reads.with_db(reads, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Member)
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
  who: Principal,
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
        use org_id, _ <- require_org(conn, slug, who, Admin)
        case find_network(conn, org_id, network) {
          Error(Nil) -> error_json(404, "not_found", "no such network")
          Ok(network_id) ->
            zone_mutation(conn, ctx, who, publish.Narrowing, fn() {
              let work = {
                // Join keys name this network and nothing else, so they go
                // with it: a scope whose network is gone is not a narrower
                // credential, it is a token that can never be used again.
                use _ <- result.try(
                  sqlite.exec(
                    conn,
                    "DELETE FROM api_keys WHERE network_id = ?",
                    [Text(network_id)],
                  ),
                )
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
                  who,
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

/// `POST /api/orgs/:slug/networks/:net/devices` — a node joins a network.
///
/// One call for what was two, because joining *is* one act: a device that
/// exists in the org but sits in no network appears in no zone, so a caller
/// that stopped after creating it has enrolled nothing and its daemon is
/// still waiting. Creating and assigning share this transaction and the zone
/// republish at the end of it, so the answer is either a node that resolves
/// or a database that never heard of it.
///
/// **This is the one route a join key can take**, and the reason the route
/// exists in this shape. A join key is what goes into a provisioning image, a
/// cloud-init file, a QR code on a rack — so what it can do has to be exactly
/// the enrolment and nothing adjacent to it. Handing that job to the two
/// older routes would have meant a credential that can also put *any* device
/// into the network, and leave devices lying around the org attached to
/// nothing.
///
/// Everyone else reaches it too, at the `Member` floor the older routes carry:
/// it is the same act, and a person should not have to make two calls to do
/// what a machine does in one.
pub fn join_device(
  req: Request,
  ctx: AuthContext,
  who: Principal,
  slug: String,
  network: String,
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
    _, _, False -> refused(bad_hint(relay, addr))
    True, Ok(nk_bytes), True ->
      with_db(ctx, fn(conn) {
        case common.check_join_target(conn, slug, network, who) {
          Error(refusal) -> refusal
          Ok(#(org_id, network_id)) ->
            zone_mutation(conn, ctx, who, publish.Widening, fn() {
              // The label has to be free *in this network*; two devices under
              // one label is what the trigger and the zone build refuse next,
              // and saying so here is what makes the refusal readable.
              let clash =
                sqlite.query(
                  conn,
                  "SELECT 1 FROM network_devices nd
                   JOIN devices d ON d.id = nd.device_id
                   WHERE nd.network_id = ? AND d.label = ?",
                  [Text(network_id), Text(label)],
                )
              case clash {
                Error(_) -> Error(db_error())
                Ok([_, ..]) ->
                  Error(error_json(
                    409,
                    "conflict",
                    "a device labeled '"
                      <> label
                      <> "' is already in this network",
                  ))
                Ok([]) -> {
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
                          Text(who.user_id),
                          VInt(now_unix()),
                        ],
                      ),
                    )
                    use _ <- result.try(
                      sqlite.exec(
                        conn,
                        "INSERT INTO device_keys
                         VALUES (?, ?, ?, ?, 'active', ?, NULL)",
                        [
                          Text(id.new()),
                          Text(device_id),
                          Text(nk),
                          Blob(nk_bytes),
                          VInt(now_unix()),
                        ],
                      ),
                    )
                    use _ <- result.try(
                      sqlite.exec(
                        conn,
                        "INSERT INTO network_devices VALUES (?, ?, ?)",
                        [
                          Text(network_id),
                          Text(device_id),
                          VInt(now_unix()),
                        ],
                      ),
                    )
                    audit(
                      conn,
                      who,
                      org_id,
                      "network.join",
                      json.object([
                        #("network", json.string(network)),
                        #("label", json.string(label)),
                        #("nk", json.string(nk)),
                      ]),
                    )
                  }
                  case work {
                    Ok(Nil) ->
                      Ok(
                        json.object([
                          #("device_id", json.string(device_id)),
                          #("label", json.string(label)),
                          #("network", json.string(network)),
                        ]),
                      )
                    Error(e) -> Error(constraint_response(e))
                  }
                }
              }
            })
        }
      })
  }
}

/// A per-member rule broken by the request itself — the same vocabulary
/// `api/devices_api` refuses with, so one broken rule names itself the same
/// way whichever route caught it.
fn refused(fault: build.BuildError) -> Response {
  let #(code, message) = common.build_refusal(fault)
  error_json(400, code, message)
}

fn bad_hint(relay: String, addr: String) -> build.BuildError {
  case build.valid_hint(relay) {
    False -> build.InvalidHint(relay)
    True -> build.InvalidHint(addr)
  }
}

pub fn assign_device(
  ctx: AuthContext,
  who: Principal,
  slug: String,
  network: String,
  device_id: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Member)
    case
      find_network(conn, org_id, network),
      find_device(conn, org_id, device_id)
    {
      Error(Nil), _ -> error_json(404, "not_found", "no such network")
      _, Error(Nil) -> error_json(404, "not_found", "no such device")
      Ok(network_id), Ok(label) ->
        zone_mutation(conn, ctx, who, publish.Widening, fn() {
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
                  who,
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
  who: Principal,
  slug: String,
  network: String,
  device_id: String,
) -> Response {
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Member)
    case find_network(conn, org_id, network) {
      Error(Nil) -> error_json(404, "not_found", "no such network")
      Ok(network_id) ->
        zone_mutation(conn, ctx, who, publish.Narrowing, fn() {
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
                  who,
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
