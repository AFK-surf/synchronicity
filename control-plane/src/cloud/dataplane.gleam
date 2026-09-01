//// The fleet: which data planes exist, and which network each one hosts
//// (docs/CLOUD-DATAPLANE.md §7.2).
////
//// This is the half of the cloud data plane that used to live nowhere. Until
//// migration v14 no shard was named: every pod was handed the same document
//// and worked out its own share by rendezvous-hashing the network id against
//// a shard count it read from its own environment. That has one failure the
//// hashing cannot fix — **two pods configured with different counts both
//// believe they own a network, and nothing detects it**. They both open its
//// database, both write its replica stream, and the loser's writes silently
//// leave the only durable copy. The lock that would catch it is a `flock` on
//// a data directory, which does not span pods.
////
//// So the decision moved here, where it is one row that two services cannot
//// disagree about. What that costs is a registry to keep and a placement
//// step to run; what it buys is that "who hosts this network" has exactly one
//// answer, and the answer is written down.
////
//// **Nothing in this module moves an assigned network.** Placement happens
//// once, when hosting is switched on, and an assignment is thereafter changed
//// only by an operator running `dataplane assign`. There is deliberately no
//// rebalancer: moving a tenant means draining one pod's database and
//// restoring it on another, and doing that automatically — on a signal as
//// noisy as "the fleet looks uneven" — reintroduces the two-writers case
//// above under a friendlier name.

import gleam/list
import gleam/result
import store/sqlite.{type Connection, Int as VInt, Text}

/// Registers a data plane under an operator-chosen id.
///
/// The id is the operator's own name for the pod (`dp-1`), not a generated
/// one: it appears in logs, in the metering heartbeat and in `dataplane
/// list`, and a name an operator chose is one they can match against their
/// own deployment. Re-registering an id is an error rather than a no-op —
/// `dataplane register` is a rare, deliberate act, and an operator who ran it
/// twice should learn that the fleet already knew about this pod rather than
/// be told nothing.
pub fn register(
  conn: Connection,
  dp_id: String,
  now: Int,
) -> Result(Nil, sqlite.Error) {
  sqlite.exec(conn, "INSERT INTO data_planes (id, created_at) VALUES (?, ?)", [
    Text(dp_id),
    VInt(now),
  ])
  |> result.replace(Nil)
}

/// Every registered data plane, with how many hosted networks it holds.
///
/// The count is what an operator places by, so it is part of the listing
/// rather than a second query they have to remember to run. A `LEFT JOIN`, so
/// a data plane registered a moment ago and holding nothing still appears —
/// which is exactly the row somebody is looking for when they are about to
/// place a network on it.
pub fn list(conn: Connection) -> Result(List(#(String, Int)), sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT d.id, count(n.id)
     FROM data_planes d
     LEFT JOIN networks n ON n.cloud_dp_id = d.id AND n.cloud_hosted = 1
     GROUP BY d.id
     ORDER BY d.id",
      [],
    ),
  )
  Ok(
    list.filter_map(rows, fn(row) {
      case row {
        [Text(id), VInt(count)] -> Ok(#(id, count))
        _ -> Error(Nil)
      }
    }),
  )
}

/// Whether this id names a registered data plane.
pub fn exists(conn: Connection, dp_id: String) -> Result(Bool, sqlite.Error) {
  use rows <- result.try(
    sqlite.query(conn, "SELECT count(*) FROM data_planes WHERE id = ?", [
      Text(dp_id),
    ]),
  )
  case rows {
    [[VInt(n)]] -> Ok(n > 0)
    _ -> Ok(False)
  }
}

/// Places a network on a data plane, if it is not already on one.
///
/// Answers the id it is assigned to afterwards, or `Error(Nil)` when the
/// fleet is empty — which is a real state and not a failure: a deployment
/// that has not registered a data plane yet can still switch hosting on, and
/// the network waits, unhosted, until one exists. That is the safe direction.
/// The alternative, refusing the toggle, would make an org-admin action fail
/// for a reason the org admin can neither see nor fix.
///
/// **Already assigned wins, always.** The guard is not an optimisation: it is
/// what makes placement happen once. A network that comes back inside its
/// retention hold returns to the data plane that still holds its database
/// stream and its bucket prefix, rather than to whichever pod happens to be
/// emptiest this minute — and a second pod restoring that stream is the
/// two-writers case this whole design exists to close.
///
/// Least-loaded rather than round-robin, because round-robin needs a cursor
/// somebody has to store and reason about, while "fewest hosted networks" is
/// derivable from the rows themselves and self-corrects after a manual
/// `assign`. Ties break on id, so the choice is deterministic and a test can
/// state it.
pub fn place(
  conn: Connection,
  network_id: String,
  now: Int,
) -> Result(Result(String, Nil), sqlite.Error) {
  use assigned <- result.try(assignment(conn, network_id))
  case assigned {
    Ok(dp_id) -> Ok(Ok(dp_id))
    Error(Nil) -> {
      use emptiest <- result.try(least_loaded(conn))
      case emptiest {
        Error(Nil) -> Ok(Error(Nil))
        Ok(dp_id) -> {
          use _ <- result.try(assign(conn, network_id, dp_id, now))
          Ok(Ok(dp_id))
        }
      }
    }
  }
}

/// The data plane a network is assigned to, if any.
pub fn assignment(
  conn: Connection,
  network_id: String,
) -> Result(Result(String, Nil), sqlite.Error) {
  use rows <- result.try(
    sqlite.query(conn, "SELECT cloud_dp_id FROM networks WHERE id = ?", [
      Text(network_id),
    ]),
  )
  case rows {
    [[Text(dp_id)]] -> Ok(Ok(dp_id))
    _ -> Ok(Error(Nil))
  }
}

/// Moves a network onto a data plane, whatever it was on before.
///
/// The one path that reassigns, and it is an operator's: `dataplane assign`,
/// run by somebody who knows the losing pod is not running the tenant. This
/// service will not do it on its own — see the module note.
pub fn assign(
  conn: Connection,
  network_id: String,
  dp_id: String,
  _now: Int,
) -> Result(Nil, sqlite.Error) {
  sqlite.exec(conn, "UPDATE networks SET cloud_dp_id = ? WHERE id = ?", [
    Text(dp_id),
    Text(network_id),
  ])
  |> result.replace(Nil)
}

/// The data plane holding the fewest hosted networks, ties broken by id.
///
/// `Error(Nil)` when none is registered, which is a real state — see
/// [`place`]. Ordered in the query rather than folded here: "fewest, then by
/// name" is what `ORDER BY` says, and a hand-rolled comparison would be a
/// second place for the rule to live.
fn least_loaded(conn: Connection) -> Result(Result(String, Nil), sqlite.Error) {
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT d.id
     FROM data_planes d
     LEFT JOIN networks n ON n.cloud_dp_id = d.id AND n.cloud_hosted = 1
     GROUP BY d.id
     ORDER BY count(n.id) ASC, d.id ASC
     LIMIT 1",
      [],
    ),
  )
  case rows {
    [[Text(dp_id)]] -> Ok(Ok(dp_id))
    _ -> Ok(Error(Nil))
  }
}
