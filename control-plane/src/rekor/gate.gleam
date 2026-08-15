//// The publish gate: whether this service will emit a zone whose key is
//// not on the public record.
////
//// `CP_REKOR_REQUIRE=true` turns it on. It is off by default because the
//// rollout is phased (§7): phase 0 publishes records while enforcement
//// stays off, so a control plane that has not run `rekor-publish` yet
//// keeps serving. With it on, publish refuses rather than emitting a zone
//// clients would reject — the same stance as the §3.2 build-time checks.
////
//// The environment is read here, at the check, rather than threaded from
//// boot configuration through every publish path (API mutation, resign
//// job, seed, boot). One posture, one place, and no call site that can
//// accidentally publish ungated.

import envoy
import gleam/list
import gleam/result
import rekor/store
import store/sqlite.{type Connection}

/// The environment variable that turns the gate on.
pub const require_env = "CP_REKOR_REQUIRE"

pub type GateError {
  /// The active key has no verified log record.
  NoRecord(key_tag: Int)
  Db(sqlite.Error)
}

/// Whether the gate is armed.
pub fn required() -> Bool {
  case envoy.get(require_env) {
    Ok("true") -> True
    _ -> False
  }
}

/// Refuses when the gate is armed and the active key tag has no verified,
/// servable record. Passes silently when it is not armed.
pub fn check(conn: Connection, key_tag: Int) -> Result(Nil, GateError) {
  case required() {
    False -> Ok(Nil)
    True -> {
      use records <- result.try(
        store.servable(conn, key_tag) |> result.map_error(Db),
      )
      case list.is_empty(records) {
        False -> Ok(Nil)
        True -> Error(NoRecord(key_tag))
      }
    }
  }
}
