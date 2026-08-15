//// What a transparency log has to do for us, as a value.
////
//// Two operations, both over the entry bytes: find an entry that is
//// already logged, and add one that is not. Everything else this service
//// does with a proof — verifying it, storing it, serving it — is offline
//// and testable without a log at all, which is why the log arrives here as
//// an injected pair of functions rather than as a hardwired endpoint.
////
//// The HTTP implementation is a stub in v1: `rekor-publish` against a real
//// log is a ceremony step an operator performs with egress to Rekor, and
//// wiring the tile-log API is tracked separately. The stub refuses loudly
//// rather than pretending, so nothing can be stored that was never logged.

import envoy
import gleam/option.{type Option}
import gleam/result
import rekor/proof
import simplifile

/// Where the log put an entry.
pub type Entry {
  Entry(
    log_id: BitArray,
    log_index: Int,
    checkpoint: BitArray,
    inclusion_path: List(BitArray),
    integrated_at: Int,
  )
}

pub type Log {
  Log(
    /// The entry for these exact bytes, if the log already has it. Used
    /// first on every republish: the tree has grown, the entry has not
    /// changed, and minting a duplicate would be a second public claim
    /// about one key.
    lookup: fn(BitArray) -> Result(Option(Entry), String),
    /// Adds the entry and waits for integration.
    submit: fn(BitArray) -> Result(Entry, String),
  )
}

/// The log write endpoint (`CP_REKOR_URL`).
pub fn url() -> String {
  envoy.get("CP_REKOR_URL")
  |> result.unwrap("https://rekor.sigstore.dev")
}

/// The pinned log verification key (`CP_REKOR_KEY`): the DER
/// SubjectPublicKeyInfo and the raw point.
///
/// There is no embedded default in this build. A key that cannot be named
/// is a proof that cannot be checked, and storing an unchecked proof would
/// hand the client something it will refuse — the one outcome this whole
/// verify-before-store step exists to prevent.
pub fn log_key() -> Result(#(BitArray, BitArray), String) {
  use path <- result.try(
    envoy.get("CP_REKOR_KEY")
    |> result.replace_error(
      "CP_REKOR_KEY is required to publish or verify a log record: this build "
      <> "ships no embedded log key",
    ),
  )
  use text <- result.try(
    simplifile.read(path)
    |> result.map_error(fn(e) {
      "reading " <> path <> ": " <> simplifile.describe_error(e)
    }),
  )
  proof.parse_log_key(text)
  |> result.map_error(fn(e) {
    case e {
      proof.UnknownLog(why) -> path <> ": " <> why
      other -> path <> ": " <> string_of(other)
    }
  })
}

fn string_of(error: proof.ProofError) -> String {
  case error {
    proof.Malformed(why) -> why
    proof.Possession(why) -> why
    proof.Binding(why) -> why
    proof.Inclusion(why) -> why
    proof.CheckpointFailed(why) -> why
    proof.UnknownLog(why) -> why
  }
}

/// The HTTP log at `url` — not implemented in v1.
pub fn http(url: String) -> Log {
  let why =
    "talking to "
    <> url
    <> " is not implemented in this build; see ops/RUNBOOK.md for the "
    <> "zone-key logging ceremony"
  Log(lookup: fn(_entry) { Error(why) }, submit: fn(_entry) { Error(why) })
}
