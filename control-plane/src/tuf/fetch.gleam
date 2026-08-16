//// Fetching Sigstore's TUF metadata and storing it verbatim
//// (docs/REKOR-ZONE-KEY.md §10.3).
////
//// This service is a **relay, not the verifier**. It walks the repository
//// the way TUF's consistent snapshots are meant to be walked — timestamp
//// names the snapshot version, the snapshot names the targets version, the
//// targets name the target's digest — and checks structure, versions,
//// expiries and the one digest the chain hands it. It checks no
//// signatures: the cryptographic gate is the client's, in
//// crates/synch-net/src/tuf.rs, and the e2e keeps this side honest by
//// running that verifier against what the zone serves.
////
//// Bad stored material therefore costs nothing but zone bytes — clients
//// ignore it and keep their pins — while a *regression* is refused here,
//// because serving a client older material than it already has is the one
//// thing a relay can do that a client cannot simply shrug off.
////
//// The repository arrives as an injected pair of functions rather than a
//// hardwired endpoint, the same shape as `rekor/client`: everything this
//// module decides is then testable without egress, and the HTTP leg stays
//// one small function.

import envoy
import gleam/bit_array
import gleam/crypto
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import store/sqlite.{type Connection}
import tuf/meta
import tuf/store.{Material}

/// The oldest `root.json` version this release's clients can chain from —
/// the floor §10.1 says is stated per release.
///
/// It is the version crates/synch-net embeds (`EMBEDDED_TUF_ROOT`), so the
/// chain the zone relays always starts exactly where a stock client starts.
/// Raising it is a release note: a client older than the floor keeps its
/// pins rather than following, which is the designed failure.
pub const root_floor = 15

/// How many root versions past the floor the walk will probe before giving
/// up. Sigstore rotates roughly yearly; this is decades of headroom and a
/// bound on a repository that answers 200 to everything.
const root_ceiling = 200

/// A TUF repository, as the two operations this needs.
///
/// `get` returns `Ok(None)` for a file the repository does not have — the
/// end of the root chain is exactly that answer — and `Error` for a
/// repository that could not be reached at all. The two are different
/// facts: one ends a walk, the other abandons it.
pub type Repo {
  Repo(get: fn(String) -> Result(Option(BitArray), String))
}

/// What a refresh established, for the CLI and the hourly job.
pub type Outcome {
  Outcome(
    root_version: Int,
    timestamp_version: Int,
    snapshot_version: Int,
    targets_version: Int,
    timestamp_expires: Int,
    /// Whether anything moved. A repository that has not published since
    /// the last fetch is the ordinary case, not news.
    changed: Bool,
  )
}

/// The repository to relay (`CP_TUF_URL`).
pub fn url() -> String {
  envoy.get("CP_TUF_URL")
  |> result.unwrap("https://tuf-repo-cdn.sigstore.dev")
}

/// The HTTP repository at `base`.
///
/// Plain GETs over verified TLS (gleam_httpc verifies certificates by
/// default), and the verification is *not* load-bearing here: every byte
/// fetched is self-authenticating and gets checked by the client against
/// its embedded root. A hostile transport can deny this fetch; it cannot
/// make it mean anything.
pub fn http(base: String) -> Repo {
  Repo(get: fn(path) {
    let url = strip_slash(base) <> "/" <> path
    use req <- result.try(
      request.to(url) |> result.replace_error("bad TUF URL " <> url),
    )
    use resp <- result.try(
      httpc.send_bits(request.set_body(req, <<>>))
      |> result.map_error(fn(e) { url <> " unreachable: " <> string.inspect(e) }),
    )
    case resp.status {
      200 -> Ok(Some(resp.body))
      403 | 404 -> Ok(None)
      status -> Error(url <> " answered " <> int.to_string(status))
    }
  })
}

/// Refetches the repository and stores it, refusing regressions.
///
/// Returns the versions now stored. `changed` is false when the repository
/// has published nothing since the last fetch, which is what most runs of
/// the hourly job find.
pub fn refresh(
  conn: Connection,
  repo: Repo,
  source: String,
  now: Int,
) -> Result(Outcome, String) {
  use stored <- result.try(
    store.get(conn)
    |> result.map_error(fn(e) { "reading tuf_material: " <> string.inspect(e) }),
  )
  let previous = option.from_result(stored)

  // The root chain, from the floor a stock client embeds up to whatever the
  // repository last published. The walk ends at the first version the
  // repository does not have — that is how TUF says "this is current".
  use roots <- result.try(root_chain(repo, root_floor, []))
  use #(root_version, _) <- result.try(case list.last(roots) {
    Ok(head) -> Ok(head)
    Error(Nil) ->
      Error(
        "the repository has no "
        <> int.to_string(root_floor)
        <> ".root.json, which is the root this build's clients embed",
      )
  })

  // Consistent snapshots: each file names the version of the one below it.
  use timestamp <- result.try(fetch(repo, "timestamp.json"))
  use timestamp_role <- result.try(meta.read_role(timestamp, "timestamp"))
  use snapshot_version <- result.try(meta.read_meta_version(
    timestamp,
    "snapshot.json",
  ))
  use snapshot <- result.try(fetch(
    repo,
    int.to_string(snapshot_version) <> ".snapshot.json",
  ))
  use snapshot_role <- result.try(meta.read_role(snapshot, "snapshot"))
  use Nil <- result.try(agrees(
    "snapshot.json",
    snapshot_role.version,
    snapshot_version,
  ))
  use targets_version <- result.try(meta.read_meta_version(
    snapshot,
    "targets.json",
  ))
  use targets <- result.try(fetch(
    repo,
    int.to_string(targets_version) <> ".targets.json",
  ))
  use targets_role <- result.try(meta.read_role(targets, "targets"))
  use Nil <- result.try(agrees(
    "targets.json",
    targets_role.version,
    targets_version,
  ))

  // The one target the whole chain exists to carry, named by its digest.
  use #(digest, length) <- result.try(meta.read_target(
    targets,
    trusted_root_target,
  ))
  use trusted_root <- result.try(fetch(
    repo,
    "targets/" <> digest <> "." <> trusted_root_target,
  ))
  use Nil <- result.try(
    case
      sha256_hex(trusted_root) == string.lowercase(digest)
      && bit_array.byte_size(trusted_root) == length
    {
      True -> Ok(Nil)
      False ->
        Error(
          trusted_root_target
          <> " does not match the digest targets.json names for it",
        )
    },
  )

  // Expiry: a relay that stores already-expired material is relaying
  // something no client will ever adopt. Refuse it and keep what is there.
  use Nil <- result.try(case timestamp_role.expires > now {
    True -> Ok(Nil)
    False ->
      Error(
        "timestamp.json expired at " <> int.to_string(timestamp_role.expires),
      )
  })

  // Regressions: serving a client older material than it already accepted
  // cannot help it and can only ever be someone trying to freeze it.
  use Nil <- result.try(case previous {
    None -> Ok(Nil)
    Some(old) ->
      list.try_fold(
        [
          #("root.json", root_version, old.root_version),
          #("timestamp.json", timestamp_role.version, old.timestamp_version),
          #("snapshot.json", snapshot_role.version, old.snapshot_version),
          #("targets.json", targets_role.version, old.targets_version),
        ],
        Nil,
        fn(_, triple) {
          let #(file, fetched, have) = triple
          case fetched >= have {
            True -> Ok(Nil)
            False ->
              Error(
                "refusing a regression: "
                <> file
                <> " fetched at version "
                <> int.to_string(fetched)
                <> ", stored is "
                <> int.to_string(have),
              )
          }
        },
      )
  })

  let material =
    Material(
      source: source,
      roots: list.map(roots, fn(pair) { pair.1 }),
      root_version: root_version,
      timestamp_json: timestamp,
      timestamp_version: timestamp_role.version,
      timestamp_expires: timestamp_role.expires,
      snapshot_json: snapshot,
      snapshot_version: snapshot_role.version,
      targets_json: targets,
      targets_version: targets_role.version,
      trusted_root: trusted_root,
      fetched_at: now,
    )
  use Nil <- result.try(
    store.put(conn, material)
    |> result.map_error(fn(e) { "storing tuf_material: " <> string.inspect(e) }),
  )
  let changed = case previous {
    None -> True
    Some(old) ->
      old.root_version != root_version
      || old.timestamp_version != timestamp_role.version
      || old.snapshot_version != snapshot_role.version
      || old.targets_version != targets_role.version
      || old.trusted_root != trusted_root
  }
  Ok(Outcome(
    root_version: root_version,
    timestamp_version: timestamp_role.version,
    snapshot_version: snapshot_role.version,
    targets_version: targets_role.version,
    timestamp_expires: timestamp_role.expires,
    changed: changed,
  ))
}

/// Whether the stored timestamp is close enough to expiry to refetch —
/// three days, per §10.3, against a Sigstore timestamp that lives about a
/// week. Absent material is always due: a zone that relays nothing is a
/// zone whose clients never refresh their pins.
pub fn due(conn: Connection, now: Int) -> Bool {
  case store.get(conn) {
    Ok(Ok(material)) -> material.timestamp_expires - now <= refetch_window
    _ -> True
  }
}

/// How close to expiry the hourly job refetches (§10.3).
pub const refetch_window = 259_200

/// The target the chain exists to authenticate.
pub const trusted_root_target = "trusted_root.json"

/// Walks `<version>.root.json` upward from `version` until the repository
/// has no more.
fn root_chain(
  repo: Repo,
  version: Int,
  acc: List(#(Int, BitArray)),
) -> Result(List(#(Int, BitArray)), String) {
  case version > root_floor + root_ceiling {
    True ->
      Error("the repository's root chain does not end; refusing to walk on")
    False -> {
      let path = int.to_string(version) <> ".root.json"
      use fetched <- result.try(repo.get(path))
      case fetched {
        None -> Ok(list.reverse(acc))
        Some(bytes) -> {
          use role <- result.try(meta.read_role(bytes, "root"))
          use Nil <- result.try(agrees(path, role.version, version))
          root_chain(repo, version + 1, [#(version, bytes), ..acc])
        }
      }
    }
  }
}

fn fetch(repo: Repo, path: String) -> Result(BitArray, String) {
  use fetched <- result.try(repo.get(path))
  case fetched {
    Some(bytes) -> Ok(bytes)
    None -> Error("the repository has no " <> path)
  }
}

/// A file whose own version disagrees with the version it was fetched as is
/// a repository contradicting itself; a relay should not smooth that over.
fn agrees(file: String, declared: Int, expected: Int) -> Result(Nil, String) {
  case declared == expected {
    True -> Ok(Nil)
    False ->
      Error(
        file
        <> " declares version "
        <> int.to_string(declared)
        <> " but was named as "
        <> int.to_string(expected),
      )
  }
}

/// One trailing slash on `CP_TUF_URL` should not become two in a path.
fn strip_slash(base: String) -> String {
  case string.ends_with(base, "/") {
    True -> strip_slash(string.drop_end(base, 1))
    False -> base
  }
}

fn sha256_hex(bytes: BitArray) -> String {
  string.lowercase(bit_array.base16_encode(crypto.hash(crypto.Sha256, bytes)))
}
