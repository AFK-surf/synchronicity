//// `/dp/v1` — the API the cloud data plane polls (docs/CLOUD-DATAPLANE.md
//// §3.3).
////
//// Five routes, and every one of them requires `principal.Dataplane` and
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
//// **The GET is a read and a replica answers it**; the four writes are the
//// primary's, like every write. That split is `api/router`'s, and this module
//// only has to be honest about which handler is which: `desired_state` takes
//// `Reads`, the rest take `AuthContext` because they write.

import api/auth_api.{type AuthContext, with_db}
import api/common.{
  audit, body_decoder, constraint_response, db_error, ok_json, text_at,
  transaction, zone_mutation,
}
import api/middleware.{error_json, now_unix}
import api/reads.{type Reads}
import auth/dataplane_key
import auth/principal.{type Principal}
import dns/name
import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/option
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
/// `cloud-1` whichever data plane happens to be running it (§3.4). The field is
/// accepted anyway because redundant hosting is a second *slot* rather than a
/// second anything else, and a heartbeat that could not name which one would
/// have to be re-designed on the day that ships.
const default_slot = 1

/// How long an offboarded network's object storage is kept before the data
/// plane is told to delete it: 30 days, in seconds.
///
/// Policy, like the budget and the retention above, and stated as policy in
/// docs/CLOUD-DATAPLANE.md §6: "the object-store prefix and DB replica enter
/// the **retention hold** (default 30 days, control-plane policy)". The hold
/// is what makes re-enabling hosting inside it a cheap re-provision that
/// restores the tenant database and re-adopts the prefix, rather than a fresh
/// replication of everything the network has.
///
/// It lives here, in the control plane, for the same reason the budget does:
/// the data plane is mechanism, holds no clock of its own about a tenant, and
/// must never be in a position to decide *when* a customer's bytes may go. It
/// deletes what this document tells it to delete, and nothing else.
const retention_hold_seconds = 2_592_000

// -- the desired-state document ----------------------------------------------

/// `GET /dp/v1/networks` — every network of every org with hosting on.
///
/// The whole of the fleet's steady-state traffic, so it carries an `ETag` and
/// honours `If-None-Match`: one 304 per data plane per poll interval is what this
/// costs when nothing has changed, which is almost always.
///
/// **The `ETag` is the SHA-256 of the response body.** That is the one
/// definition which cannot forget an input. In particular, assigning an
/// already-hosted network to another data plane changes `cloud_dp_id` without
/// publishing DNS and therefore without moving the zone serial; and a network
/// enters `collect` because a retention deadline passes, with no transaction
/// at all. A tag assembled from selected counters or fingerprints has to know
/// about both exceptions and every exception added later. Hashing the exact
/// bytes sent on a 200 makes the representation itself the authority.
///
/// Building the small document on a steady-state poll costs the ordered
/// network, device and collection queries plus one serialization. The 304
/// still avoids sending and parsing it across the fleet, and correctness is
/// not made to depend on maintaining a parallel invalidation scheme.
///
/// What remains, and is fine: a collection can be **up to one poll interval
/// late**. The body and therefore its tag move once the hold elapses, but
/// nothing pushes — the fleet finds out when it next asks. A deletion that
/// happens sixty seconds after it fell due is not a correctness problem; a
/// deletion that never happens is, and that is the one this closes.
pub fn desired_state(req: Request, reads: Reads, who: Principal) -> Response {
  use dp <- require_dataplane(who)
  reads.with_db(reads, fn(conn) {
    // One reading of the clock for the tag and the body both: two would let a
    // second tick between them and answer a `collect` list the `ETag` does not
    // describe.
    let due_before = now_unix() - retention_hold_seconds
    case model.read_meta(conn) {
      Ok(meta) ->
        case document(conn, dp, meta, due_before) {
          Ok(body) -> {
            let tag = etag(body)
            case list.key_find(req.headers, "if-none-match") == Ok(tag) {
              True ->
                wisp.response(304)
                |> wisp.set_header("etag", tag)
              False ->
                body
                |> wisp.json_response(200)
                |> wisp.set_header("etag", tag)
            }
          }
          Error(_) -> db_error()
        }
      Error(_) -> db_error()
    }
  })
}

fn document(
  conn: Connection,
  dp: String,
  meta: model.ZoneMeta,
  due_before: Int,
) -> Result(String, Nil) {
  // Assigned to *this* data plane, which since migration v14 is what decides
  // the fleet's division of labour. Two pods no longer derive overlapping
  // answers from a fleet size each read out of its own environment; each is
  // told, and the telling is one column.
  //
  // A hosted network with no assignment appears in nobody's document. That is
  // the safe direction and it is visible — `dataplane list` shows the fleet's
  // counts and `dataplane unassigned` names the gap — where the alternative,
  // handing an unassigned network to whoever asked first, is a placement
  // decision made by a race.
  let networks =
    sqlite.query(
      conn,
      "SELECT o.slug, n.name, n.id
       FROM networks n JOIN orgs o ON o.id = n.org_id
       WHERE n.cloud_hosted = 1 AND n.cloud_dp_id = ?
       ORDER BY o.slug, n.name",
      [Text(dp)],
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
       WHERE n.cloud_hosted = 1 AND n.cloud_dp_id = ? AND k.state = 'active'
         AND d.label GLOB 'cloud-*'
         AND d.created_by = ?
       ORDER BY nd.network_id, d.label",
      [Text(dp), Text(dataplane_key.system_user_id)],
    )
  let due = collectable(conn, dp, due_before)
  case networks, devices, due {
    Ok(network_rows), Ok(device_rows), Ok(due_rows) -> {
      // Already narrowed to devices this service created (`created_by`), which
      // is the only thing that makes a row a hosting slot. A customer device
      // called `cloud-backup` is not one and must never be reported as one —
      // and the label alone could not tell them apart.
      let hosted = device_rows
      // The apex without its trailing dot, which is what `domain` is built
      // from: the data plane hands the result straight to `Node::set_domain`
      // and never assembles a name itself.
      let apex = string.drop_end(name.to_string(meta.apex), 1)
      Ok(
        json.object([
          #("generation", json.int(meta.soa_serial)),
          // The data plane's own name, told to it by the authority rather than
          // configured into it. A pod that hosts nothing can then say which pod
          // it is, which is the first question asked of one, and the metering
          // heartbeat reports the id this service assigned by instead of a
          // string the deployment chose separately and could get wrong.
          #("dp", json.string(dp)),
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
          // Deliberately just the two names. Everything the fleet needs to build
          // the prefixes is here — `tenants/<org>/<net>/` and `db/<org>/<net>/`
          // are named by the same pair as the tenant itself (§5.1) — and adding
          // the stamp or the deadline would be handing a service that holds the
          // credentials a second opinion about whether the hold has run.
          #(
            "collect",
            json.array(due_rows, fn(row) {
              json.object([
                #("org", json.string(text_at(row, 0))),
                #("network", json.string(text_at(row, 1))),
              ])
            }),
          ),
        ])
        |> json.to_string,
      )
    }
    _, _, _ -> Error(Nil)
  }
}

/// The networks whose retention hold has run: hosting off, a stamp on the way
/// out, and `now >= cloud_disabled_at + retention_hold_seconds` — spelled as
/// `cloud_disabled_at <= now - hold` so the comparison happens on a column
/// SQLite can read straight out of the row.
///
/// A network re-enabled inside its hold cleared the stamp on the way back in
/// (`networks_api.set_cloud_hosting`), so `cloud_hosted = 0` and a live stamp
/// is exactly "offboarded and not since re-adopted". Both halves are checked
/// rather than just the stamp: they are written in one transaction and cannot
/// disagree, and a list that could ever name a *hosted* network is a list this
/// service must not be able to produce.
///
/// Scoped to the data plane that was hosting the network when it was
/// offboarded (`q.dp_id`, migration v14). The queue outlives the network row
/// on purpose, so the owner cannot be looked up when the deletion falls due —
/// it has to have been written down at disable time. Without it every data
/// plane in the fleet would be told to delete the same prefix on the same
/// tick: not wrong, exactly, since the sweep is idempotent, but N pods racing
/// on one customer's bytes is not a thing to arrange on purpose.
///
/// A row with no `dp_id` — queued before v14, or queued while the network sat
/// unassigned — is nobody's, and is therefore swept by nobody until an
/// operator gives it an owner. Storage retained is recoverable; storage
/// deleted by a pod that was never hosting it is not.
fn collectable(
  conn: Connection,
  dp: String,
  due_before: Int,
) -> Result(List(List(sqlite.Value)), sqlite.Error) {
  sqlite.query(
    conn,
    "SELECT q.org_slug, q.network_name
     FROM cloud_collect_queue q
     WHERE q.disabled_at <= ? AND q.dp_id = ?
       AND NOT EXISTS (
         SELECT 1 FROM networks n JOIN orgs o ON o.id = n.org_id
         WHERE o.slug = q.org_slug AND n.name = q.network_name
           AND n.cloud_hosted = 1
       )
     ORDER BY q.org_slug, q.network_name",
    [VInt(due_before), Text(dp)],
  )
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

/// A strong entity tag over the exact JSON representation returned on a 200.
///
/// The body is serialized once, hashed here, and the same string is sent below;
/// formatting changes therefore invalidate the tag too, as a strong ETag
/// requires. `sha256-` is only a human-readable algorithm label inside HTTP's
/// opaque quoted value.
fn etag(body: String) -> String {
  let digest =
    crypto.hash(crypto.Sha256, <<body:utf8>>)
    |> bit_array.base16_encode
    |> string.lowercase
  "\"sha256-" <> digest <> "\""
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
  use dp <- require_dataplane(who)
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
        "a hosted device's label is its hosting slot and must begin 'cloud-'",
      )
    _, Error(Nil) -> refused(build.InvalidNk(nk))
    True, Ok(nk_bytes) ->
      with_db(ctx, fn(conn) {
        case own_network(conn, dp, slug, network) {
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
/// Re-standing-down a key that is already `retiring` is a no-op that
/// publishes nothing, for the same reason a repeat registration is: the serial
/// this route would bump is the desired document's `generation`.
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
  use dp <- require_dataplane(who)
  let revoking = query(req, "revoke") == "1"
  with_db(ctx, fn(conn) {
    // The `cloud_hosted` flag is deliberately *not* required here. Disabling
    // hosting deletes these devices in its own commit, so a key that is still
    // findable belongs to a tenant that is still hosted or to one mid-teardown
    // — and refusing to revoke a key because the switch already went off would
    // close the door on exactly the cleanup this route is for.
    //
    // The *assignment* is required, unlike the flag: a key is a tenant's
    // identity, and standing one down is the one act on this surface that can
    // leave another data plane's running tenant unable to sign. Disabling
    // hosting does not clear `cloud_dp_id`, so the pod that was hosting the
    // network can still finish its own teardown here.
    case own_network(conn, dp, slug, network) {
      Error(refusal) -> refusal
      Ok(#(org_id, network_id, _)) ->
        case find_slot_key(conn, network_id, nk) {
          Error(refusal) -> refusal
          Ok(#(device_id, key_id, state)) ->
            case revoking, state, sole_active(conn, device_id) {
              // Already stood down, and asked to stand down again. The write
              // would change no row, so the only things it would do are the
              // two nobody wants: `register_device` routes a repeat
              // registration to `unchanged` for exactly this reason, and the
              // reason is the same here. This serial is also the desired
              // document's `generation` and the first half of its `ETag`, so a
              // republish per pass turns every data plane's 304 into a full
              // document and re-signs the whole zone for nothing — and the
              // audit trail fills with retirements that did not happen.
              False, "retiring", _ ->
                unchanged(
                  conn,
                  json.object([
                    #("nk", json.string(nk)),
                    #("state", json.string("retiring")),
                  ]),
                )
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
         AND d.label GLOB 'cloud-*'
         AND d.created_by = ?",
      [Text(network_id), Text(nk), Text(dataplane_key.system_user_id)],
    )
  case looked {
    Error(_) -> Error(db_error())
    Ok([row, ..]) -> Ok(#(text_at(row, 0), text_at(row, 2), text_at(row, 3)))
    Ok([]) -> Error(error_json(404, "not_found", "no such live key"))
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

// -- the retention hold ------------------------------------------------------

/// What a `DELETE …/storage` finds of the retention hold.
type Hold {
  /// Stamped, and the hold has run out: the offboarding this call is
  /// reporting the end of, and the only state in which it may proceed.
  Due(disabled_at: Int)
  /// Stamped, and still running. The customer's window to change their mind
  /// (§6), and the reason this route re-checks it rather than trusting the
  /// caller: the `collect` list already withholds a network that is not due,
  /// but a list is a hint and this is the write that destroys the bytes. A
  /// replayed instruction, a fleet bug, or a leaked `synchdp_` token must not
  /// be able to collect inside the hold, so the authority that owns the clock
  /// checks it here too.
  Running(disabled_at: Int)
  /// No queue row. Either this network was never offboarded, or a previous
  /// call already cleared it — which are the same thing to this route, and
  /// the reason it can be retried.
  Collected
  /// Hosting is on right now, so the storage is live and must not be touched
  /// whatever the queue says.
  Hosted
}

/// `DELETE /dp/v1/networks/:org/:net/storage` — the data plane reporting that
/// it has deleted an offboarded tenant's `tenants/<org>/<net>/` and
/// `db/<org>/<net>/` prefixes (§6).
///
/// The division of labour this route completes: the credentials for the bucket
/// live in the fleet and never here, so the control plane cannot delete
/// anything itself. What it can do is say what is *due* — the `collect` list
/// above — and record what came back. This is the second half, and without it
/// the first half would repeat the same instruction every poll forever.
///
/// **A still-hosted network is refused, 409, before anything else is read.**
/// Collecting a live tenant's storage is the catastrophic operation in this
/// design — it is the one that destroys a customer's data while they are
/// using it — and while this service does not perform the deletion, it must
/// never be able to *record* one. The refusal is not really about this call's
/// own write (clearing a stamp a hosted network does not have would be a
/// no-op); it is about the audit row, which would otherwise stand as this
/// service's own statement that a live tenant's bytes were collected. A claim
/// the API cannot make is a claim nobody has to disprove later.
///
/// **Idempotent, because a partial failure is the expected case.** The data
/// plane deletes a great many objects and then calls this; a pod that dies
/// between the last object and the call retries, and a retry after a call that
/// *did* land finds no stamp. Both answer 200; `collected` says which
/// happened, the same way `changed` does on the registration.
///
/// **Not a `zone_mutation`, and the choice is the interesting one here.** The
/// desired-state ETag hashes the response body, so removing this instruction
/// from `collect` is visible without borrowing the DNS serial as an unrelated
/// invalidation counter. Republishing would be actively worse than useless.
/// Nothing in the zone depends on
/// `cloud_disabled_at` — the hosted devices were deleted a month ago, in the
/// commit that stamped it — so the publish would re-sign and bump a
/// deployment-wide serial for a fact the zone does not carry, making *every*
/// data plane refetch the document because one tenant's bucket was emptied. And
/// `zone_mutation` runs the publish through the transparency gate, which can
/// hold a `Widening` back: a housekeeping call that could be refused because a
/// ceremony step is outstanding is a call that would leave the fleet asking to
/// collect the same prefix on every poll until a human noticed. So: an ordinary
/// `common.transaction`, the update and the audit row together, no publish.
pub fn collect_storage(
  ctx: AuthContext,
  who: Principal,
  slug: String,
  network: String,
) -> Response {
  use dp <- require_dataplane(who)
  with_db(ctx, fn(conn) {
    // Deliberately NOT `hosted_network`: the whole point of the queue is that
    // it outlives the network row, so a network deleted while offboarded has
    // bytes to collect and nothing left in `networks` to look them up by. The
    // hosting check that used to come from that lookup is folded into
    // `read_hold` instead, where it reads the live flag by slug and name.
    //
    // The assignment travels with the queue row for the same reason, and is
    // checked there: an offboarded network's owner cannot be read from a
    // `networks` row that may already be gone.
    case read_hold(conn, dp, slug, network) {
      Error(refusal) -> refusal
      Ok(Hosted) ->
        error_json(
          409,
          "cloud-hosting-enabled",
          "cloud hosting is enabled for this network: its storage is live and "
            <> "cannot be recorded as collected",
        )
      Ok(Collected) -> collected(network, False)
      Ok(Running(disabled_at)) ->
        error_json(
          409,
          "retention-hold",
          "this network's retention hold has not elapsed: it was offboarded "
            <> int.to_string(now_unix() - disabled_at)
            <> "s ago and is held for "
            <> int.to_string(retention_hold_seconds)
            <> "s",
        )
      Ok(Due(disabled_at)) -> {
        let done =
          transaction(conn, fn() {
            let cleared =
              sqlite.exec(
                conn,
                "DELETE FROM cloud_collect_queue
                  WHERE org_slug = ? AND network_name = ?",
                [Text(slug), Text(network)],
              )
            case cleared {
              Error(e) -> Error(constraint_response(e))
              Ok(_) ->
                // The queue row is about to stop existing, so the row that
                // would answer "how long was this held, and from when"
                // carries both — the same denormalisation `common.audit`
                // makes for a credential that is about to be revoked. The org
                // is named by slug because it, too, may already be gone.
                audit(
                  conn,
                  who,
                  org_slug_for_audit(conn, slug),
                  action_collect,
                  [
                    #("org", json.string(slug)),
                    #("network", json.string(network)),
                    #("disabled_at", json.int(disabled_at)),
                    #("held_seconds", json.int(now_unix() - disabled_at)),
                  ],
                )
                |> result.replace(Nil)
                |> result.map_error(fn(_) { db_error() })
            }
          })
        case done {
          Ok(Nil) -> collected(network, True)
          Error(refusal) -> refusal
        }
      }
    }
  })
}

/// What the audit row records as the org.
///
/// The org's id when it still exists, and its slug when it does not — a
/// collection can land after the org was deleted, and `audit.org_id` carries
/// no foreign key precisely so history survives that.
fn org_slug_for_audit(conn: Connection, slug: String) -> String {
  case sqlite.query(conn, "SELECT id FROM orgs WHERE slug = ?", [Text(slug)]) {
    Ok([[Text(org_id)]]) -> org_id
    _ -> slug
  }
}

const action_collect = "cloud-hosting.storage.collect"

/// Whether this network's retention clock is still running, read by slug and
/// name so a network whose row is gone can still be answered.
///
/// The live hosting flag is consulted in the same read: a network re-enabled
/// inside its hold — or a *different* network that has since taken the same
/// slug and name — is hosted, and its storage is live.
fn read_hold(
  conn: Connection,
  dp: String,
  slug: String,
  network: String,
) -> Result(Hold, Response) {
  let hosted =
    sqlite.query(
      conn,
      "SELECT count(*) FROM networks n JOIN orgs o ON o.id = n.org_id
       WHERE o.slug = ? AND n.name = ? AND n.cloud_hosted = 1",
      [Text(slug), Text(network)],
    )
  // Matched on the queue row's own `dp_id`, which is the owner recorded when
  // hosting went off (migration v14). A data plane that was never hosting
  // this network reads `Collected` — nothing here for it — rather than being
  // handed a stranger's prefix to confirm the deletion of.
  let queued =
    sqlite.query(
      conn,
      "SELECT disabled_at FROM cloud_collect_queue
       WHERE org_slug = ? AND network_name = ? AND dp_id = ?",
      [Text(slug), Text(network), Text(dp)],
    )
  case hosted, queued {
    Ok([[VInt(n)]]), _ if n > 0 -> Ok(Hosted)
    Ok(_), Ok([[VInt(disabled_at)]]) ->
      case now_unix() - disabled_at >= retention_hold_seconds {
        True -> Ok(Due(disabled_at))
        False -> Ok(Running(disabled_at))
      }
    Ok(_), Ok([]) -> Ok(Collected)
    _, _ -> Error(db_error())
  }
}

/// The heartbeat's success shape plus the one field that distinguishes the
/// write from the retry, for the reason `registered` gives: both are 200 by
/// design, since a pod that crashed between the commit and the response sees
/// neither and must be able to just ask again.
fn collected(network: String, changed: Bool) -> Response {
  ok_json(
    json.object([
      #("ok", json.bool(True)),
      #("network", json.string(network)),
      #("collected", json.bool(changed)),
    ]),
  )
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
  use dp <- require_dataplane(who)
  let decoder = {
    use held_roots <- decode.field("held_roots", decode.int)
    use held_bytes <- decode.field("held_bytes", decode.int)
    use wanted <- decode.field("wanted", decode.int)
    use last_sync_ns <- decode.field("last_sync_ns", decode.int)
    use dp_reported <- decode.field("dp", decode.string)
    use slot <- decode.optional_field("slot", default_slot, decode.int)
    decode.success(#(
      held_roots,
      held_bytes,
      wanted,
      last_sync_ns,
      dp_reported,
      slot,
    ))
  }
  use #(held_roots, held_bytes, wanted, last_sync_ns, dp_reported, slot) <- body_decoder(
    req,
    decoder,
  )
  with_db(ctx, fn(conn) {
    case own_network(conn, dp, slug, network) {
      Error(refusal) -> refusal
      Ok(#(_, network_id, _)) -> {
        let written =
          sqlite.exec(
            conn,
            "INSERT INTO network_hosting_status
               (network_id, slot, held_roots, held_bytes, wanted,
                last_sync_ns, dp_id, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (network_id) DO UPDATE SET
               slot = excluded.slot,
               held_roots = excluded.held_roots,
               held_bytes = excluded.held_bytes,
               wanted = excluded.wanted,
               last_sync_ns = excluded.last_sync_ns,
               dp_id = excluded.dp_id,
               updated_at = excluded.updated_at",
            [
              Text(network_id),
              VInt(slot),
              VInt(held_roots),
              VInt(held_bytes),
              VInt(wanted),
              VInt(last_sync_ns),
              Text(dp_reported),
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
fn require_dataplane(who: Principal, next: fn(String) -> Response) -> Response {
  case who.credential {
    principal.Dataplane(_, dp) -> next(dp)
    _ ->
      error_json(
        403,
        "dataplane_only",
        "this endpoint answers the hosting service's own credential "
          <> "(Authorization: Bearer synchdp_…) and no other",
      )
  }
}

/// The org, the network and its hosting state, refusing a network this data
/// plane is not the one assigned to.
///
/// The check is here rather than at each caller because it is the same
/// question every write on this surface asks, and because a route that forgot
/// to ask it would make the assignment advisory — a filter on the GET that
/// any pod could step around by naming a network directly. Two data planes
/// writing one tenant's device registrations, heartbeats and key retirements
/// is the confusion the assignment exists to remove.
///
/// A network assigned elsewhere answers 404 rather than 403, and that is
/// deliberate: from this caller's point of view it is not a network it can
/// see, and the honest shape of "not yours" on a surface that enumerates by
/// assignment is the same shape as "not there". The log line on the other side
/// says which data plane does own it.
fn own_network(
  conn: Connection,
  dp: String,
  slug: String,
  network: String,
) -> Result(#(String, String, Bool), Response) {
  case hosted_network(conn, slug, network) {
    Error(refusal) -> Error(refusal)
    Ok(#(org_id, network_id, hosted, assigned)) ->
      case assigned == option.Some(dp) {
        True -> Ok(#(org_id, network_id, hosted))
        False ->
          Error(error_json(
            404,
            "not_found",
            "no such network on this data plane",
          ))
      }
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
) -> Result(#(String, String, Bool, option.Option(String)), Response) {
  let looked =
    sqlite.query(
      conn,
      "SELECT o.id, n.id, n.cloud_hosted, n.cloud_dp_id FROM orgs o
       JOIN networks n ON n.org_id = o.id AND n.name = ?
       WHERE o.slug = ?",
      [Text(network), Text(slug)],
    )
  case looked {
    Ok([[Text(org_id), Text(network_id), VInt(hosted), assigned]]) -> {
      let assigned = case assigned {
        Text(dp) -> option.Some(dp)
        _ -> option.None
      }
      Ok(#(org_id, network_id, hosted != 0, assigned))
    }
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
