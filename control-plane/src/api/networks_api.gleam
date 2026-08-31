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
import auth/dataplane_key
import auth/principal.{type Principal}
import dns/name
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Blob, Int as VInt, Text}
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
        "SELECT n.name, count(nd.device_id), n.cloud_hosted
         FROM networks n LEFT JOIN network_devices nd ON nd.network_id = n.id
         WHERE n.org_id = ? GROUP BY n.id ORDER BY n.name",
        [Text(org_id)],
      )
    common.rows_json(rows, fn(row) {
      json.object([
        #("name", json.string(text_at(row, 0))),
        #("device_count", json.int(common.int_at(row, 1))),
        // The stored column is an integer, as `browse_enabled` is; the API
        // answers a boolean, because a switch is a switch and every reader of
        // this list would otherwise write the same `!== 0` for itself.
        #("cloud_hosted", json.bool(common.int_at(row, 2) != 0)),
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
                audit(conn, who, org_id, "network.create", [
                  #("name", json.string(network)),
                ])
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
        // Its own statement rather than a column on the device join: that
        // query returns one row per device key, and a per-network fact
        // repeated down a device list is a fact somebody will read off the
        // wrong row when the list is empty.
        let hosting =
          sqlite.query(conn, "SELECT cloud_hosted FROM networks WHERE id = ?", [
            Text(network_id),
          ])
        let cloud_hosted = case hosting {
          Ok([[VInt(flag)]]) -> flag != 0
          _ -> False
        }
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
                #("cloud_hosted", json.bool(cloud_hosted)),
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
                // The metering heartbeat's row is a child of the network and
                // foreign keys are on, so it leaves before its parent — the
                // same order every other child here follows. Without this the
                // delete fails with an unmapped constraint error, and any
                // network the fleet has ever heartbeated for becomes
                // permanently undeletable.
                use _ <- result.try(
                  sqlite.exec(
                    conn,
                    "DELETE FROM network_hosting_status WHERE network_id = ?",
                    [Text(network_id)],
                  ),
                )
                // Deleting a hosted network is an offboarding: the bytes in
                // the bucket outlive the row, so the instruction to collect
                // them has to as well. `DO NOTHING` because a network deleted
                // *during* its hold already has a clock running and must not
                // have it restarted.
                use hosted <- result.try(is_hosted(conn, network_id))
                use _ <- result.try(case hosted {
                  False -> Ok(Nil)
                  True ->
                    sqlite.exec(
                      conn,
                      "INSERT INTO cloud_collect_queue
                         (org_slug, network_name, disabled_at)
                       VALUES (?, ?, ?)
                       ON CONFLICT (org_slug, network_name) DO NOTHING",
                      [Text(slug), Text(network), VInt(now_unix())],
                    )
                    |> result.replace(Nil)
                })
                use _ <- result.try(
                  sqlite.exec(conn, "DELETE FROM networks WHERE id = ?", [
                    Text(network_id),
                  ]),
                )
                audit(conn, who, org_id, "network.delete", [
                  #("name", json.string(network)),
                ])
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

// -- cloud hosting ----------------------------------------------------------

/// `PUT /api/orgs/:slug/networks/:net/cloud-hosting/enabled` — the org's
/// switch for managed replica hosting (docs/CLOUD-DATAPLANE.md §2, §3.1).
///
/// Admin-gated and audited, the shape `browse_api.set_enabled` set for the
/// browse switch, and off until an org admin turns it on: hosting means a
/// service-operated node joins the customer's network and holds a replica of
/// everything on it, which is an explicit grant or it is nothing. The two
/// toggles stay independent and independently fail-closed — hosting without
/// browse replicates but is observable only through the status heartbeat.
///
/// **Unlike the browse switch, this one is a `zone_mutation`**, and both
/// directions are, for two reasons that pull the same way:
///
///   * Turning it *off* deletes the network's `cloud-<n>` devices, which is a
///     zone change and must be the *same* commit — the flag and the membership
///     record it caused have to stop being true together, or the zone goes on
///     naming a hosted key the org has just withdrawn consent for.
///   * Turning it *on* changes nothing in the zone, but it does change the
///     data plane's desired-state document — and that document's `generation`
///     is the zone serial (`api/dataplane_api`), so a toggle that did not
///     publish would be a network the fleet's `If-None-Match` poll never
///     notices. Making the grant itself `Widening` also puts it behind the
///     transparency gate, which is honest: the very next thing that happens is
///     a device registration that widens the zone for real, and being refused
///     now rather than a minute later names the ceremony step that is missing.
///
/// A `cloud_collect_queue` row starts the retention clock over the tenant's
/// object storage, so one is written on the way out and removed on the way
/// back in: re-enabling within the hold is a cheap re-provision, and the date
/// is what the fleet's `collect` list later reads. It is keyed by slug and
/// name and carries no foreign key, because it has to outlive not only the
/// device rows this same transaction removes but the *network itself* — the
/// bytes in the bucket do not stop existing because somebody deleted the row
/// that pointed at them (`store/migrate` V12).
pub fn set_cloud_hosting(
  req: Request,
  ctx: AuthContext,
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  let decoder = {
    use enabled <- decode.field("enabled", decode.bool)
    decode.success(enabled)
  }
  use enabled <- body_decoder(req, decoder)
  with_db(ctx, fn(conn) {
    use org_id, _ <- require_org(conn, slug, who, Admin)
    case find_network(conn, org_id, network) {
      Error(Nil) -> error_json(404, "not_found", "no such network")
      Ok(network_id) -> {
        // The three things that differ between the two directions, decided
        // once: what the zone is told to expect, the stored flag, and what
        // the trail calls it.
        let #(change, flag, action) = case enabled {
          True -> #(publish.Widening, 1, "cloud-hosting.enable")
          False -> #(publish.Narrowing, 0, "cloud-hosting.disable")
        }
        zone_mutation(conn, ctx, who, change, fn() {
          let work = {
            // Read before the write: whether this network was *actually*
            // hosted a moment ago is what decides whether there is anything
            // to collect. Disabling a network that was already off must not
            // start a clock — a dashboard syncing its initial state, or an
            // IaC provider writing `cloud_hosted = false` explicitly, would
            // otherwise queue a deletion instruction for a prefix that never
            // existed.
            use was_hosted <- result.try(is_hosted(conn, network_id))
            use _ <- result.try(
              sqlite.exec(
                conn,
                "UPDATE networks SET cloud_hosted = ?1 WHERE id = ?2",
                [VInt(flag), Text(network_id)],
              ),
            )
            use _ <- result.try(case enabled, was_hosted {
              // Back on inside the hold: the tenant is re-provisioned rather
              // than collected, so the instruction to delete its bytes goes.
              True, _ ->
                sqlite.exec(
                  conn,
                  "DELETE FROM cloud_collect_queue
                    WHERE org_slug = ? AND network_name = ?",
                  [Text(slug), Text(network)],
                )
                |> result.replace(Nil)
              // `DO NOTHING`, so a repeated disable does not restart the
              // retention clock. A reconciler or a UI that re-sends
              // `{enabled: false}` is ordinary, and each restamp would push
              // the collection another 30 days out — storage retained, and
              // billed, for ever.
              False, True ->
                sqlite.exec(
                  conn,
                  "INSERT INTO cloud_collect_queue
                     (org_slug, network_name, disabled_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT (org_slug, network_name) DO NOTHING",
                  [Text(slug), Text(network), VInt(now_unix())],
                )
                |> result.replace(Nil)
              False, False -> Ok(Nil)
            })
            use removed <- result.try(case enabled {
              True -> Ok(0)
              False -> retire_hosted_devices(conn, network_id)
            })
            use _ <- result.try(
              audit(conn, who, org_id, action, [
                #("network", json.string(network)),
                #("devices_removed", json.int(removed)),
              ]),
            )
            Ok(removed)
          }
          case work {
            Ok(removed) ->
              Ok(
                json.object([
                  #("enabled", json.bool(enabled)),
                  #("devices_removed", json.int(removed)),
                ]),
              )
            Error(e) -> Error(constraint_response(e))
          }
        })
      }
    }
  })
}

/// Whether hosting is switched on for this network, read inside the
/// transaction that is about to switch it.
///
/// A missing row cannot happen — `find_network` established it a moment ago
/// on this same connection — and answering `False` for one is the safe way to
/// be wrong: it queues no deletion.
fn is_hosted(
  conn: Connection,
  network_id: String,
) -> Result(Bool, sqlite.Error) {
  use rows <- result.try(
    sqlite.query(conn, "SELECT cloud_hosted FROM networks WHERE id = ?", [
      Text(network_id),
    ]),
  )
  case rows {
    [[VInt(1)]] -> Ok(True)
    _ -> Ok(False)
  }
}

/// Removes the network's hosted devices, in the transaction that switched
/// hosting off. Answers how many devices went.
///
/// **The rows go rather than the keys being revoked.** A revoked key leaves a
/// device in the network holding nothing, which the dashboard would draw as a
/// broken member forever; and re-enabling later is a fresh provision with a
/// fresh key, so there is no identity here worth keeping. What is kept is the
/// `cloud_collect_queue` row, which is the only fact that has to outlive
/// them.
///
/// **What this deletes is decided by ownership, never by the label.**
/// `devices.created_by` is `system-dataplane` for exactly the devices the
/// data plane made, so that is the test. The label is not: the reserved
/// namespace is a rule about what may be *created* from now on, and a
/// customer device named `cloud-backup` that predates it is still theirs. A
/// toggle that deleted somebody's device because it happened to be named
/// after a cloud is not a toggle anyone can be asked to flip.
///
/// The `GLOB` stays as a narrowing — every device this can delete does carry
/// the prefix, because `dataplane_api.register_device` refuses to create one
/// that does not — but it is the ownership column that decides.
fn retire_hosted_devices(
  conn: Connection,
  network_id: String,
) -> Result(Int, sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT d.id, d.label FROM network_devices nd
       JOIN devices d ON d.id = nd.device_id
       WHERE nd.network_id = ? AND d.label GLOB 'cloud-*'
         AND d.created_by = ?",
      [Text(network_id), Text(dataplane_key.system_user_id)],
    ),
  )
  let hosted = list.map(rows, fn(row) { text_at(row, 0) })
  use _ <- result.try(
    list.try_fold(hosted, Nil, fn(_, device_id) {
      // The same three deletes, in the same order, that `devices_api` uses to
      // remove a device: assignments, then keys, then the row the two
      // reference.
      use _ <- result.try(
        sqlite.exec(conn, "DELETE FROM network_devices WHERE device_id = ?", [
          Text(device_id),
        ]),
      )
      use _ <- result.try(
        sqlite.exec(conn, "DELETE FROM device_keys WHERE device_id = ?", [
          Text(device_id),
        ]),
      )
      sqlite.exec(conn, "DELETE FROM devices WHERE id = ?", [Text(device_id)])
      |> result.replace(Nil)
    }),
  )
  Ok(list.length(hosted))
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
    // First, and ahead of the grammar: `cloud-<n>` is a *valid* device label
    // that this deployment has spoken for (docs/CLOUD-DATAPLANE.md §3.4), so
    // refusing it as malformed would be a lie. Only the data-plane principal
    // creates one, through `api/dataplane_api`, which is the reason a customer
    // holding a join key cannot displace or impersonate a hosted replica.
    name.reserved_device_label(label),
    name.valid_device_label(label),
    model.validate_nk(nk),
    build.valid_hint(relay) && build.valid_hint(addr)
  {
    True, _, _, _ -> common.reserved_label(label)
    _, False, _, _ -> refused(build.InvalidLabel(label))
    _, _, Error(Nil), _ -> refused(build.InvalidNk(nk))
    _, _, _, False -> refused(bad_hint(relay, addr))
    False, True, Ok(nk_bytes), True ->
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
                    audit(conn, who, org_id, "network.join", [
                      #("network", json.string(network)),
                      #("label", json.string(label)),
                      #("nk", json.string(nk)),
                    ])
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
                audit(conn, who, org_id, "network.assign", [
                  #("network", json.string(network)),
                  #("label", json.string(label)),
                ])
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
                audit(conn, who, org_id, "network.unassign", [
                  #("device", json.string(device_id)),
                ])
              Ok(json.object([#("unassigned", json.string(device_id))]))
            }
            Ok(_) -> Error(error_json(404, "not_found", "not assigned"))
            Error(e) -> Error(constraint_response(e))
          }
        })
    }
  })
}
