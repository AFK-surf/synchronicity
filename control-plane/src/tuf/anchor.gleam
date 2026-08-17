//// The TUF root this service chains from (docs/REKOR-ZONE-KEY.md §10.3).
////
//// `priv/tuf/sigstore_tuf_root.json`, byte-identical to the root the client
//// embeds (`EMBEDDED_TUF_ROOT` in crates/synch-net/src/tuf.rs) — the two
//// sides verify the same repository against the same anchor, which is what
//// makes "the control plane relays what the client will accept" a checkable
//// statement rather than a hope.
////
//// It ships in `priv/` rather than compiled in because Gleam has no
//// include-bytes and a 5 KB JSON document escaped into a source constant is
//// a document nobody will ever review. `priv/` rides the Erlang shipment the
//// same way `csqlite` and the SPA do.
////
//// Replacing it is a deploy, deliberately, and that is the whole point of
//// §10: everything *below* the root — which logs exist, where they are
//// served, which keys sign their checkpoints — now refreshes without one, so
//// the only event that still costs a release is a root-level incident.

import envoy
import gleam/bit_array
import gleam/int
import gleam/result
import simplifile
import tuf/canonical

/// The anchor: the bytes to chain from, and the version they declare.
pub type Anchor {
  Anchor(bytes: BitArray, version: Int)
}

/// The file inside `priv/tuf`.
pub const file = "sigstore_tuf_root.json"

@external(erlang, "cp_sys_ffi", "priv_dir")
fn priv_dir(sub: String) -> Result(String, Nil)

/// Loads the anchor.
///
/// `CP_TUF_ROOT` replaces it entirely — the private-Sigstore case, with the
/// same "an override is a different universe" semantics `CP_REKOR_KEY` has.
/// An operator who points `CP_TUF_URL` at their own repository names its root
/// here, because a repository whose root this service does not hold is a
/// repository none of whose files it can check.
pub fn load() -> Result(Anchor, String) {
  use path <- result.try(case envoy.get("CP_TUF_ROOT") {
    Ok(path) -> Ok(path)
    Error(Nil) ->
      priv_dir("tuf")
      |> result.map(fn(dir) { dir <> "/" <> file })
      |> result.replace_error(
        "priv/tuf is missing from this build — the TUF anchor ships there, "
        <> "or CP_TUF_ROOT names one",
      )
  })
  use bytes <- result.try(
    simplifile.read_bits(path)
    |> result.map_error(fn(e) {
      "reading the TUF anchor " <> path <> ": " <> simplifile.describe_error(e)
    }),
  )
  use version <- result.try(
    version_of(bytes)
    |> result.replace_error(
      "the TUF anchor " <> path <> " is not a root.json with a version",
    ),
  )
  Ok(Anchor(bytes: bytes, version: version))
}

/// The version a `root.json` declares, without verifying anything about it —
/// enough to know where the walk starts.
pub fn version_of(bytes: BitArray) -> Result(Int, Nil) {
  use document <- result.try(
    canonical.parse(bytes) |> result.replace_error(Nil),
  )
  canonical.integer_at(document, ["signed", "version"])
}

/// The anchor's version as text, for the messages that name it.
pub fn describe(anchor: Anchor) -> String {
  int.to_string(anchor.version) <> ".root.json"
}

/// The anchor's size, for a boot line that proves it was found.
pub fn size(anchor: Anchor) -> Int {
  bit_array.byte_size(anchor.bytes)
}
