//// `/dp/v1` — the API the cloud data plane polls (docs/CLOUD-DATAPLANE.md
//// §3.3).
////
//// Four routes, and every one of them requires `principal.Dataplane` and
//// refuses everything else. The reverse holds too, and matters more:
//// `api/common.check_org` refuses `Dataplane` outright, so a leaked
//// data-plane key reaches exactly this module and no org-scoped route in the
//// service. The two halves of that promise are one `case` arm each, in two
//// places, rather than a table anybody maintains.
////
//// What this surface is *for* is the reason it exists at all: the product API
//// has no cross-org enumeration and no service credential, because every
//// credential there names one org and every handler leans on that. The data
//// plane needs the opposite — "which networks, of every org, have hosting
//// switched on" — and giving that answer inside the org API would have meant
//// bending the invariant everything else stands on. So it is a separate
//// prefix, a separate table of keys, and a separate principal, and the org
//// API is untouched.
////
//// **The GET is a read and a replica answers it**; the three writes are the
//// primary's, like every write. That split is `api/router`'s, and this module
//// only has to be honest about which handler is which: `desired_state` takes
//// `Reads`, the rest take `AuthContext` because their transaction publishes
//// the zone.

import api/auth_api.{type AuthContext, with_db}
import api/common.{
  audit, body_decoder, constraint_response, db_error, ok_json, text_at,
  zone_mutation,
}
import api/middleware.{error_json, now_unix}
import api/reads.{type Reads}
import auth/principal.{type Principal}
import dns/name
import gleam/dynamic/decode
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/result
import gleam/string
import store/sqlite.{type Connection, Blob, Int as VInt, Null, Text}
import util/id
import wisp.{type Request, type Response}
import zone/build
import zone/model
import zone/publish

/// The storage ceiling every hosted network is configured with, in bytes
/// (2 TiB).
///
/// Policy, decided control-plane side and handed to the data plane, which is
/// mechanism only — the same division the design draws for `retention`. It is
/// a constant here because there is no plan table in this schema yet: when
/// there is one, this becomes a column read per org and nothing in the data
/// plane changes, which is precisely why the number travels in the document
/// rather than in the fleet's configuration.
const default_budget_bytes = 2_199_023_255_552

/// The replica retention policy every hosted network gets: `current` (with the
/// standard grace) rather than `forever`.
///
/// "Replicate everything on the network" means what the network *has*, not
/// everything it has ever had. `forever` is a plan upgrade this service can
/// grant per network without any data-plane change, for the same reason the
/// budget is here.
const default_retention = "current"

/// The hosting slot a heartbeat is about when it does not say.
///
/// v1 hosts every network once, in slot 1, so the hosted device is always
/// `cloud-1` whichever shard happens to be running it (§3.4). The field is
/// accepted anyway because redundant hosting is a second *slot* rather than a
/// second anything else, and a heartbeat that could not name which one would
/// have to be re-designed on the day that ships.
const default_slot = 1

// -- the desired-state document ----------------------------------------------

/// `GET /dp/v1/networks` — every network of every org with hosting on.
///
/// The whole of the fleet's steady-state traffic, so it carries an `ETag` and
/// honours `If-None-Match`: one 304 per shard per poll interval is what this
/// costs when nothing has changed, which is almost always.
///
/// **`generation` is the zone serial**, and the choice is worth stating
/// because two other candidates are worse. There is no `updated_at` on
/// `networks` to take a `max` of, and adding one would mean a counter this
/// service has to remember to bump — the class of mistake that shows up as a
/// fleet quietly serving last week's tenant set. The zone serial is already
/// bumped, in the same transaction, by every mutation that can change this
/// document: a device registered or retired here, a network deleted, an org
/// renamed, and — because `networks_api.set_cloud_hosting` is deliberately a
/// `zone_mutation` in both directions — the hosting toggle itself. It is
/// strictly increasing and it is one column.
///
/// What it is not is *tight*. It is deployment-wide, so any zone change
/// anywhere moves it, and the hourly re-sign moves it too. The failure mode of
/// a loose generation is an extra full fetch of a small document; the failure
/// mode of a tight one that misses a change is a network that never gets
/// hosted. This errs in the direction that costs bytes.
pub fn desired_state(req: Request, reads: Reads, who: Principal) -> Response {
  use <- require_dataplane(who)
  reads.with_db(reads, fn(conn) {
    case model.read_meta(conn) {
      Error(_) -> db_error()
      Ok(meta) -> {
        let tag = etag(meta.soa_serial)
        case list.key_find(req.headers, "if-none-match") == Ok(tag) {
          True ->
            wisp.response(304)
            |> wisp.set_header("etag", tag)
          False -> document(conn, meta, tag)
        }
      }
    }
  })
}

fn document(conn: Connection, meta: model.ZoneMeta, tag: String) -> Response {
  let networks =
    sqlite.query(
      conn,
      "SELECT o.slug, n.name, n.id
       FROM networks n JOIN orgs o ON o.id = n.org_id
       WHERE n.cloud_hosted = 1
       ORDER BY o.slug, n.name",
      [],
    )
  // The hosted device of each network, in one statement rather than one per
  // network: the fleet polls this every minute and a query per tenant would
  // make the cost of the poll grow with the product.
  //
  // Only the `active` key is reported. A rotation window has two live keys and
  // exactly one active one (the `PUT` below is what opens the window, and it
  // opens it the way `devices_api.add_key` does), so this is the key the data
  // plane currently holds. A device whose keys have all been revoked reports
  // no `device` at all, which is the honest answer and the one that sends the
  // fleet down the key-replacement path rather than leaving it to guess.
  let devices =
    sqlite.query(
      conn,
      "SELECT nd.network_id, d.label, k.nk_z32, k.state
       FROM network_devices nd
       JOIN devices d ON d.id = nd.device_id
       JOIN device_keys k ON k.device_id = d.id
       JOIN networks n ON n.id = nd.network_id
       WHERE n.cloud_hosted = 1 AND k.state = 'active'
         AND d.label GLOB 'cloud-*'
       ORDER BY nd.network_id, d.label",
      [],
    )
  case networks, devices {
    Ok(network_rows), Ok(device_rows) -> {
      // GLOB cannot say "digits and nothing else", so the pattern above is a
      // narrowing and this is the decision — the same predicate that refuses
      // these labels at creation. A customer device called `cloud-nine` is not
      // a hosting slot and must never be reported as one.
      let hosted =
        list.filter(device_rows, fn(row) {
          name.reserved_device_label(text_at(row, 1))
        })
      // The apex without its trailing dot, which is what `domain` is built
      // from: the data plane hands the result straight to `Node::set_domain`
      // and never assembles a name itself.
      let apex = string.drop_end(name.to_string(meta.apex), 1)
      json.object([
        #("generation", json.int(meta.soa_serial)),
        #(
          "networks",
          json.array(network_rows, fn(row) {
            let slug = text_at(row, 0)
            let network = text_at(row, 1)
            json.object([
              #("org", json.string(slug)),
              #("network", json.string(network)),
              #("domain", json.string(network <> "." <> slug <> "." <> apex)),
              #("budget_bytes", json.int(default_budget_bytes)),
              #("retention", json.string(default_retention)),
              #("device", device_json(hosted, text_at(row, 2))),
            ])
          }),
        ),
      ])
      |> json.to_string
      |> wisp.json_response(200)
      |> wisp.set_header("etag", tag)
    }
    _, _ -> db_error()
  }
}

fn device_json(hosted: List(List(sqlite.Value)), network_id: String) -> Json {
  case list.find(hosted, fn(row) { text_at(row, 0) == network_id }) {
    Ok(row) ->
      json.object([
        #("label", json.string(text_at(row, 1))),
        #("nk", json.string(text_at(row, 2))),
        #("state", json.string(text_at(row, 3))),
      ])
    // Null rather than an absent field or an empty object: "this service has
    // never registered a key for that network" is the fact a disk-less data
    // plane boots on, and it should read the same way every time.
    Error(Nil) -> json.null()
  }
}

/// The document's `ETag`, from its generation. Strong rather than weak: the
/// body is byte-identical for a given serial, since every input to it is read
/// in one connection's snapshot of the same database.
fn etag(generation: Int) -> String {
  "\"dp-" <> int.to_string(generation) <> "\""
}

// -- device registration -----------------------------------------------------

/// What a `PUT …/device` finds already occupying the slot.
type Slot {
  /// Nothing under this label in this network — a first registration.
  Vacant
  /// This exact key is already bound and live: the idempotent no-op that a
  /// restored, re-provisioned pod makes on every boot.
  Bound(device_id: String, state: String)
  /// A device under this label with room for one more key: either one live key
  /// to rotate away from, or only revoked ones, which is the replacement path
  /// after a data-plane disk loss.
  Open(device_id: String)
  /// Two live keys already. A third would put three records under one label in
  /// the zone, which `zone/build` refuses — better to say so here.
  Crowded
}

/// `PUT /dp/v1/networks/:org/:net/device` — idempotent registration of the
/// hosted device's key.
///
/// The same transaction shape as `networks_api.join_device`, deliberately: a
/// `common.zone_mutation`, so **the commit is the publish** and the zone names
/// the key immediately. That is what turns the data plane's identify wait from
/// a propagation window into a DoH-cache-sized one.
///
/// The three outcomes the design asks for fall out of `read_slot`: the same
/// `(label, nk)` is a 200 no-op that writes nothing and publishes nothing —
/// which matters, because a republish per poll would churn the serial that is
/// also this document's `generation`; the same label with a new key opens the
/// standard rotation window when the old key is live, exactly as
/// `devices_api.add_key` does; and the same label with a new key over a
/// revoked one replaces outright, which is the recovery path after a lost
/// tenant database.
///
/// The design allows the body to carry the zone's optional `relay` and `addr`
/// hints. v1 does not accept them, and the omission is the design's own
/// reasoning made structural: an ephemeral pod has no stable address to
/// publish, the hosted node initiates its own fetches, and inbound reaches it
/// through discovery and relays like any NAT-bound peer. A field that must
/// always be empty is better absent than accepted and ignored.
pub fn register_device(
  req: Request,
  ctx: AuthContext,
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  use <- require_dataplane(who)
  let decoder = {
    use label <- decode.field("label", decode.string)
    use nk <- decode.field("nk", decode.string)
    decode.success(#(label, nk))
  }
  use #(label, nk) <- body_decoder(req, decoder)
  case name.reserved_device_label(label), model.validate_nk(nk) {
    // The mirror image of the refusal customers get: they may not take a
    // `cloud-<n>` label, and this credential may take *only* one. A
    // data-plane key that could name any label would be a credential that can
    // displace or impersonate a customer's device, which is the one thing §9
    // says a leak of it must not buy.
    False, _ ->
      error_json(
        400,
        "slot-label",
        "a hosted device's label is its hosting slot: 'cloud-<n>', digits only",
      )
    _, Error(Nil) -> refused(build.InvalidNk(nk))
    True, Ok(nk_bytes) ->
      with_db(ctx, fn(conn) {
        case hosted_network(conn, slug, network) {
          Error(refusal) -> refusal
          // The flag is enforced *here*, which is the whole reason it is not a
          // zone fact: an org that switched hosting off a second ago must not
          // gain a hosted member because a poll was in flight.
          Ok(#(_, _, False)) ->
            error_json(
              409,
              "cloud-hosting-disabled",
              "cloud hosting is not enabled for this network",
            )
          Ok(#(org_id, network_id, True)) ->
            case read_slot(conn, network_id, label, nk) {
              Error(refusal) -> refusal
              Ok(Bound(device_id, state)) ->
                unchanged(conn, registered(device_id, label, nk, state, False))
              Ok(Crowded) ->
                error_json(
                  409,
                  "rotation_open",
                  "a rotation window is already open — retire the old key first",
                )
              Ok(Vacant) ->
                create_slot(
                  conn,
                  ctx,
                  who,
                  org_id,
                  network_id,
                  network,
                  label,
                  nk,
                  nk_bytes,
                )
              Ok(Open(device_id)) ->
                rotate_slot(
                  conn,
                  ctx,
                  who,
                  org_id,
                  device_id,
                  network,
                  label,
                  nk,
                  nk_bytes,
                )
            }
        }
      })
  }
}

/// What is under `label` in this network, and how it relates to `nk`.
///
/// One statement rather than three, so the four outcomes are decided on one
/// consistent read: a device row, its live keys, and whether this key is
/// already one of them. The `LEFT JOIN` is what lets a device with every key
/// revoked still be found — that device is the *reason* the replacement path
/// exists.
fn read_slot(
  conn: Connection,
  network_id: String,
  label: String,
  nk: String,
) -> Result(Slot, Response) {
  let looked =
    sqlite.query(
      conn,
      "SELECT d.id, coalesce(k.id, ''), coalesce(k.nk_z32, ''),
              coalesce(k.state, '')
       FROM network_devices nd
       JOIN devices d ON d.id = nd.device_id
       LEFT JOIN device_keys k ON k.device_id = d.id AND k.state != 'revoked'
       WHERE nd.network_id = ? AND d.label = ?
       ORDER BY k.added_at",
      [Text(network_id), Text(label)],
    )
  case looked {
    Error(_) -> Error(db_error())
    Ok(rows) ->
      case rows {
        [] -> Ok(Vacant)
        [first, ..] -> {
          let device_id = text_at(first, 0)
          // A device with every key revoked still comes back — one row whose
          // key columns are the `coalesce`d empty strings — which is exactly
          // the state the replacement path has to be able to see.
          let live = list.filter(rows, fn(row) { text_at(row, 1) != "" })
          case list.find(live, fn(row) { text_at(row, 2) == nk }) {
            Ok(row) -> Ok(Bound(device_id, text_at(row, 3)))
            Error(Nil) ->
              case list.length(live) >= 2 {
                True -> Ok(Crowded)
                False -> Ok(Open(device_id))
              }
          }
        }
      }
  }
}

fn create_slot(
  conn: Connection,
  ctx: AuthContext,
  who: Principal,
  org_id: String,
  network_id: String,
  network: String,
  label: String,
  nk: String,
  nk_bytes: BitArray,
) -> Response {
  zone_mutation(conn, ctx, who, publish.Widening, fn() {
    let device_id = id.new()
    let work = {
      use _ <- result.try(
        sqlite.exec(conn, "INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?)", [
          Text(device_id),
          Text(org_id),
          Text(label),
          // No relay, no addr: see `register_device`.
          Null,
          Null,
          // `who.user_id` is the `system-dataplane` row migration v12 seeds —
          // `devices.created_by` references `users`, and a hosted device
          // should name the service rather than borrow some operator's id.
          Text(who.user_id),
          VInt(now_unix()),
        ]),
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
      use _ <- result.try(
        sqlite.exec(conn, "INSERT INTO network_devices VALUES (?, ?, ?)", [
          Text(network_id),
          Text(device_id),
          VInt(now_unix()),
        ]),
      )
      audit(conn, who, org_id, "cloud-hosting.device.register", [
        #("network", json.string(network)),
        #("label", json.string(label)),
        #("nk", json.string(nk)),
      ])
    }
    case work {
      Ok(Nil) -> Ok(registered(device_id, label, nk, "active", True))
      Error(e) -> Error(constraint_response(e))
    }
  })
}

/// The new key becomes active and any live key under this label moves to
/// `retiring` — `devices_api.add_key`'s two statements, for the same reason
/// and in the same order.
///
/// The `UPDATE` is a no-op on the replacement path (nothing is `active` when
/// every old key has been revoked), which is why one pair of statements covers
/// both: a rotation and a recovery differ in what they find, not in what they
/// do.
fn rotate_slot(
  conn: Connection,
  ctx: AuthContext,
  who: Principal,
  org_id: String,
  device_id: String,
  network: String,
  label: String,
  nk: String,
  nk_bytes: BitArray,
) -> Response {
  zone_mutation(conn, ctx, who, publish.Widening, fn() {
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
      audit(conn, who, org_id, "cloud-hosting.device.rotate", [
        #("network", json.string(network)),
        #("label", json.string(label)),
        #("nk", json.string(nk)),
      ])
    }
    case work {
      Ok(Nil) -> Ok(registered(device_id, label, nk, "active", True))
      Error(e) -> Error(constraint_response(e))
    }
  })
}

/// The no-op's answer, in `common.zone_mutation`'s envelope.
///
/// A reconciler should not have to parse two success shapes for one route, and
/// the field that would otherwise be missing is the one it wants either way:
/// the serial the zone is at. Nothing was published, so this is the serial as
/// found, and `result.changed` is what says so.
fn unchanged(conn: Connection, payload: Json) -> Response {
  case model.read_meta(conn) {
    Ok(meta) ->
      ok_json(
        json.object([
          #("ok", json.bool(True)),
          #("soa_serial", json.int(meta.soa_serial)),
          #("result", payload),
        ]),
      )
    Error(_) -> db_error()
  }
}

/// What every registration answers with, changed or not.
///
/// `changed` is the one field that distinguishes the no-op from the write, and
/// it is a field rather than a status code because both are 200 by design: a
/// reconciler that had to branch on 200-versus-201 to know whether its own
/// idempotent call did anything would be reading the wrong signal, since a pod
/// that crashed between the write and the response sees neither.
fn registered(
  device_id: String,
  label: String,
  nk: String,
  state: String,
  changed: Bool,
) -> Json {
  json.object([
    #("device_id", json.string(device_id)),
    #("label", json.string(label)),
    #("nk", json.string(nk)),
    #("state", json.string(state)),
    #("changed", json.bool(changed)),
  ])
}

// -- closing a rotation ------------------------------------------------------

/// `DELETE /dp/v1/networks/:org/:net/device/keys/:nk` — the other half of the
/// rotation.
///
/// Without it a window could be opened and never closed, and the zone would
/// carry two keys under one label forever: `zone/build` caps that at two, so
/// the *next* rotation would be refused rather than this one being wrong,
/// which is the kind of failure that surfaces a quarter later on somebody
/// else's shift.
///
/// Two dispositions. Plain, it moves the key to `retiring` — the state the
/// zone still publishes, which is the point: the old key stays resolvable
/// while customer bindings age out, and the ordinary retirement takes it the
/// rest of the way. With `?revoke=1` it goes straight to `revoked` and leaves
/// the zone at the next publish, which is what the data plane asks for when it
/// has reason to distrust the key.
///
/// **The last `active` key is refused unless revoking.** Retiring it would
/// leave a healthy tenant with a device the zone still names and no key it can
/// present — an orphan the data plane cannot repair without a human. Revoking
/// it is allowed, because "this key is compromised" outranks "this tenant
/// keeps working", and the recovery is the replacement `PUT` above.
///
/// Confined to `cloud-<n>` devices of the named network, so this route can
/// never touch a customer's key however the path is spelled.
pub fn retire_key(
  req: Request,
  ctx: AuthContext,
  who: Principal,
  slug: String,
  network: String,
  nk: String,
) -> Response {
  use <- require_dataplane(who)
  let revoking = query(req, "revoke") == "1"
  with_db(ctx, fn(conn) {
    // The `cloud_hosted` flag is deliberately *not* required here. Disabling
    // hosting deletes these devices in its own commit, so a key that is still
    // findable belongs to a tenant that is still hosted or to one mid-teardown
    // — and refusing to revoke a key because the switch already went off would
    // close the door on exactly the cleanup this route is for.
    case hosted_network(conn, slug, network) {
      Error(refusal) -> refusal
      Ok(#(org_id, network_id, _)) ->
        case find_slot_key(conn, network_id, nk) {
          Error(refusal) -> refusal
          Ok(#(device_id, key_id, state)) ->
            case revoking, state, sole_active(conn, device_id) {
              False, "active", True ->
                error_json(
                  409,
                  "last-active-key",
                  "this is the tenant's only active key: register a "
                    <> "replacement first, or pass ?revoke=1 to withdraw it "
                    <> "outright",
                )
              _, _, _ ->
                // `Narrowing` for both dispositions. A revoke plainly narrows;
                // a retire changes nothing the zone publishes, and neither is
                // ever a claim the transparency gate should be able to hold
                // back — a key this service has decided to withdraw must reach
                // the wire whatever the gate is doing.
                zone_mutation(conn, ctx, who, publish.Narrowing, fn() {
                  // Only a revocation is a retirement time; a `retiring` key
                  // has not left yet, and `devices_api` stamps the column at
                  // the same moment for the same reason.
                  let #(next, retired_at, action) = case revoking {
                    True -> #(
                      "revoked",
                      VInt(now_unix()),
                      "cloud-hosting.key.revoke",
                    )
                    False -> #("retiring", Null, "cloud-hosting.key.retire")
                  }
                  let update =
                    sqlite.exec(
                      conn,
                      "UPDATE device_keys SET state = ?, retired_at = ?
                       WHERE id = ?",
                      [Text(next), retired_at, Text(key_id)],
                    )
                  case update {
                    Ok(_) -> {
                      let _ =
                        audit(conn, who, org_id, action, [
                          #("network", json.string(network)),
                          #("nk", json.string(nk)),
                        ])
                      Ok(
                        json.object([
                          #("nk", json.string(nk)),
                          #("state", json.string(next)),
                        ]),
                      )
                    }
                    Error(e) -> Error(constraint_response(e))
                  }
                })
            }
        }
    }
  })
}

/// The named key, if it belongs to a hosting slot of this network.
///
/// Keyed on `nk` rather than on a key id because that is what the data plane
/// holds: it knows the public key it generated, and asking it to remember an
/// id this service minted would be a second thing to lose with the database.
fn find_slot_key(
  conn: Connection,
  network_id: String,
  nk: String,
) -> Result(#(String, String, String), Response) {
  let looked =
    sqlite.query(
      conn,
      "SELECT d.id, d.label, k.id, k.state
       FROM network_devices nd
       JOIN devices d ON d.id = nd.device_id
       JOIN device_keys k ON k.device_id = d.id
       WHERE nd.network_id = ? AND k.nk_z32 = ? AND k.state != 'revoked'
         AND d.label GLOB 'cloud-*'",
      [Text(network_id), Text(nk)],
    )
  case looked {
    Error(_) -> Error(db_error())
    Ok(rows) ->
      case
        list.find(rows, fn(row) { name.reserved_device_label(text_at(row, 1)) })
      {
        Ok(row) -> Ok(#(text_at(row, 0), text_at(row, 2), text_at(row, 3)))
        Error(Nil) -> Error(error_json(404, "not_found", "no such live key"))
      }
  }
}

/// Whether this device has exactly one `active` key.
///
/// A failed count answers `True`, which refuses the retirement. The alternative
/// — treating a database error as "there must be another key" — would let a
/// storage hiccup orphan a tenant, and this route has a safe direction.
fn sole_active(conn: Connection, device_id: String) -> Bool {
  case
    sqlite.query(
      conn,
      "SELECT count(*) FROM device_keys
       WHERE device_id = ? AND state = 'active'",
      [Text(device_id)],
    )
  {
    Ok([[VInt(count)]]) -> count <= 1
    _ -> True
  }
}

// -- the metering heartbeat --------------------------------------------------

/// `POST /dp/v1/networks/:org/:net/status` — one row per network, last write
/// wins.
///
/// Stored, unlike the browse tunnel's replication answer, and the difference
/// is what each is for. The tunnel's answer is a live view and is worthless
/// stale; this is the billing record, and its whole value is that it survives
/// the tenant being down — a heartbeat that has stopped moving *is* the alert.
///
/// Not audited. It arrives per tenant every few minutes, so a row per
/// heartbeat would bury every act a human took in a log of a machine breathing
/// — the same judgement that keeps browse reads out of the trail.
pub fn post_status(
  req: Request,
  ctx: AuthContext,
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  use <- require_dataplane(who)
  let decoder = {
    use held_roots <- decode.field("held_roots", decode.int)
    use held_bytes <- decode.field("held_bytes", decode.int)
    use wanted <- decode.field("wanted", decode.int)
    use last_sync_ns <- decode.field("last_sync_ns", decode.int)
    use shard <- decode.field("shard", decode.string)
    use slot <- decode.optional_field("slot", default_slot, decode.int)
    decode.success(#(held_roots, held_bytes, wanted, last_sync_ns, shard, slot))
  }
  use #(held_roots, held_bytes, wanted, last_sync_ns, shard, slot) <- body_decoder(
    req,
    decoder,
  )
  with_db(ctx, fn(conn) {
    case hosted_network(conn, slug, network) {
      Error(refusal) -> refusal
      Ok(#(_, network_id, _)) -> {
        let written =
          sqlite.exec(
            conn,
            "INSERT INTO network_hosting_status
               (network_id, slot, held_roots, held_bytes, wanted,
                last_sync_ns, shard, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (network_id) DO UPDATE SET
               slot = excluded.slot,
               held_roots = excluded.held_roots,
               held_bytes = excluded.held_bytes,
               wanted = excluded.wanted,
               last_sync_ns = excluded.last_sync_ns,
               shard = excluded.shard,
               updated_at = excluded.updated_at",
            [
              Text(network_id),
              VInt(slot),
              VInt(held_roots),
              VInt(held_bytes),
              VInt(wanted),
              VInt(last_sync_ns),
              Text(shard),
              VInt(now_unix()),
            ],
          )
        case written {
          Ok(_) ->
            ok_json(
              json.object([
                #("ok", json.bool(True)),
                #("network", json.string(network)),
              ]),
            )
          Error(e) -> constraint_response(e)
        }
      }
    }
  })
}

// -- plumbing ----------------------------------------------------------------

/// Runs `next` only for the data-plane principal.
///
/// The other half of `api/common.check_org`'s refusal: that one keeps a
/// data-plane key out of the org API, this one keeps everything else out of
/// `/dp/v1`. A session cookie is refused here as firmly as an org key is — the
/// hosting service's credential is minted at the operator CLI and the fleet
/// holds it, and a dashboard user who could register hosted devices by hand
/// would be a second, unaudited way into the reserved namespace.
fn require_dataplane(who: Principal, next: fn() -> Response) -> Response {
  case who.credential {
    principal.Dataplane(_) -> next()
    _ ->
      error_json(
        403,
        "dataplane_only",
        "this endpoint answers the hosting service's own credential "
          <> "(Authorization: Bearer synchdp_…) and no other",
      )
  }
}

/// The org, the network and whether hosting is on for it, without asking who
/// wants it.
///
/// `api/common`'s resolvers all run through `check_org`, which refuses this
/// principal by design, so the data plane needs its own lookup. That it is
/// separate is the point: the RBAC this skips is RBAC that has no answer for a
/// credential that names no org, and the scope it is missing is supplied by
/// the route prefix instead.
///
/// A network that does not exist gets the same 404 anybody gets. There is no
/// enumeration concern to weigh here — this credential is already entitled to
/// the whole hosted list — but a straight answer keeps the fleet's logs
/// readable.
fn hosted_network(
  conn: Connection,
  slug: String,
  network: String,
) -> Result(#(String, String, Bool), Response) {
  let looked =
    sqlite.query(
      conn,
      "SELECT o.id, n.id, n.cloud_hosted FROM orgs o
       JOIN networks n ON n.org_id = o.id AND n.name = ?
       WHERE o.slug = ?",
      [Text(network), Text(slug)],
    )
  case looked {
    Ok([[Text(org_id), Text(network_id), VInt(hosted)]]) ->
      Ok(#(org_id, network_id, hosted != 0))
    Ok(_) -> Error(error_json(404, "not_found", "no such network"))
    Error(_) -> Error(db_error())
  }
}

/// A per-member rule broken by the request itself, in the vocabulary
/// `api/common.build_refusal` fixes — so a malformed `nk` names itself the
/// same way here, at the dashboard, and at the publish.
fn refused(fault: build.BuildError) -> Response {
  let #(code, message) = common.build_refusal(fault)
  error_json(400, code, message)
}

fn query(req: Request, key: String) -> String {
  wisp.get_query(req) |> list.key_find(key) |> result.unwrap("")
}
