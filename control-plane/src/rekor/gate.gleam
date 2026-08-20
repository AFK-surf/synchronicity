//// The publish gate: whether this service will emit a zone whose key is
//// not on the public record.
////
//// `CP_REKOR_REQUIRE=true` turns it on. With it on, publish refuses rather
//// than emitting a zone clients would reject.
////
//// The environment is read here, at the check, rather than threaded from
//// boot configuration through every publish path (API mutation, resign
//// job, seed, boot). One posture, one place, and no call site that can
//// accidentally publish ungated.

import envoy
import gleam/result
import rekor/store
import store/sqlite.{type Connection}

/// The environment variable that turns the gate on.
pub const require_env = "CP_REKOR_REQUIRE"

pub type GateError {
  /// The active key is claimed by no verified log record.
  NoRecord(key_tag: Int)
  Db(sqlite.Error)
}

/// Whether the gate is armed. Defaults to off.
///
/// **A spelling this does not recognise is refused, not read as off.**
pub fn required() -> Bool {
  case envoy.get(require_env) {
    Ok("true") -> True
    Error(Nil) | Ok("false") -> False
    Ok(other) ->
      panic as {
        require_env
        <> " must be \"true\" or \"false\" — got \""
        <> other
        <> "\". Refusing to guess: this decides whether the zone publishes "
        <> "device bindings under a key that is not on the public record."
      }
  }
}

/// Refuses when the gate is armed and the active key — named by the SHA-256
/// of its DNSKEY rdata, with the tag along for the error message — is not
/// claimed by any verified, servable record. Passes silently when the gate
/// is not armed.
pub fn check(
  conn: Connection,
  key_tag: Int,
  key_sha256: BitArray,
) -> Result(Nil, GateError) {
  case required() {
    False -> Ok(Nil)
    True -> {
      use covered <- result.try(
        store.covered(conn, key_sha256) |> result.map_error(Db),
      )
      case covered {
        True -> Ok(Nil)
        False -> Error(NoRecord(key_tag))
      }
    }
  }
}
