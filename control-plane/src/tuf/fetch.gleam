//// Fetching Sigstore's TUF metadata, verifying it, and storing it verbatim
//// (docs/REKOR-ZONE-KEY.md §10.3).
////
//// What the stored material is *for* is `rekor/client.discover`, which reads
//// the `trusted_root.json` out of it to decide **where this service
//// submits** — a decision no client ever sees, and so a decision no client
//// can re-verify (§10.6). That is why this side verifies what it stores
//// (`tuf/verify`), against the same anchor the client embeds, rather than
//// trusting TLS to a CDN.
////
//// So the walk is a walk — timestamp names the snapshot version, the
//// snapshot names the targets version, the targets name the target's digest
//// — and nothing it collects is stored until the whole chain verifies from
//// the anchor down: signatures over canonical JSON, thresholds, expiries,
//// monotonicity, and the target's digest. What is stored is therefore
//// material this side has checked, not merely material it received.
////
//// The repository arrives as an injected pair of functions rather than a
//// hardwired endpoint, the same shape as `rekor/client`: everything this
//// module decides is then testable without egress, and the HTTP leg stays
//// one small function.
////
//// One thing verification does *not* do is gate use. Stored material that
//// has since expired keeps naming the log, on §10.2's rule that expiry gates
//// updates and never operation. Expiry is checked at the moment of
//// ingestion, where refusing costs nothing but a retry.

import envoy
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import store/sqlite.{type Connection}
import tuf/anchor
import tuf/meta
import tuf/store.{Material}
import tuf/verify

/// The oldest `root.json` version this release's clients can chain from —
/// the floor §10.1 says is stated per release.
///
/// It is not a constant any more but the version of the anchor in
/// `priv/tuf`, which is byte-identical to the one crates/synch-net embeds
/// (`EMBEDDED_TUF_ROOT`). Reading it from the file rather than restating it
/// keeps the walk and the verification agreeing about where the bottom is by
/// construction — a floor written down twice is a floor that eventually
/// disagrees with itself.
///
/// Raising it is a release note: a client older than the floor keeps its
/// pins rather than following, which is the designed failure.
pub fn root_floor() -> Result(Int, String) {
  anchor.load() |> result.map(fn(loaded) { loaded.version })
}

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

/// What a refresh established, for the refresh job's log line.
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

/// The repository to follow (`CP_TUF_URL`).
pub fn url() -> String {
  envoy.get("CP_TUF_URL")
  |> result.unwrap("https://tuf-repo-cdn.sigstore.dev")
}

/// The HTTP repository at `base`.
///
/// Plain GETs over verified TLS (gleam_httpc verifies certificates by
/// default), and the TLS is *not* load-bearing: every byte fetched is
/// self-authenticating and gets checked against the anchor in `priv/tuf`
/// before it is stored, and again by the client against the identical root
/// it embeds. A hostile transport can deny this fetch; it cannot make it
/// mean anything. `tuf/verify` is what makes that true on this side.
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

/// Refetches the repository, verifies the chain, and stores it.
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
  use anchored <- result.try(anchor.load())

  // The root chain, from the anchor this build holds up to whatever the
  // repository last published. The walk ends at the first version the
  // repository does not have — that is how TUF says "this is current".
  use roots <- result.try(
    root_chain(repo, anchored.version, anchored.version, []),
  )
  use #(root_version, _) <- result.try(case list.last(roots) {
    Ok(head) -> Ok(head)
    Error(Nil) ->
      Error(
        "the repository has no "
        <> anchor.describe(anchored)
        <> ", which is the root this build chains from",
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
  // Read here only to name the file to fetch — that the bytes match the
  // digest is `verify`'s to say, where the digest itself has been checked
  // against a signature.
  use #(digest, _length) <- result.try(meta.read_target(
    targets,
    trusted_root_target,
  ))
  use trusted_root <- result.try(fetch(
    repo,
    "targets/" <> digest <> "." <> trusted_root_target,
  ))

  // The gate. Everything above this line is a walk — it decided which files
  // to ask for and nothing more. Signatures over canonical JSON, role
  // thresholds, expiries, monotonicity against what is stored, and the
  // target's digest are all checked here, from the anchor down, and nothing
  // is stored unless they all hold.
  let floors = case previous {
    None -> verify.no_floors()
    Some(old) ->
      verify.Floors(
        root: old.root_version,
        timestamp: old.timestamp_version,
        snapshot: old.snapshot_version,
        targets: old.targets_version,
      )
  }
  use _ <- result.try(
    verify.verify(
      anchored.bytes,
      list.map(roots, fn(pair) { pair.1 }),
      timestamp,
      snapshot,
      targets,
      trusted_root,
      floors,
      now,
    )
    |> result.map_error(fn(e) {
      "refusing material that does not verify: " <> verify.describe(e)
    }),
  )

  let material =
    Material(
      source: source,
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
/// week. Absent material is always due: with nothing stored, this service
/// does not know which log shard to submit to.
pub fn due(conn: Connection, now: Int) -> Bool {
  case store.get(conn) {
    Ok(Ok(material)) -> material.timestamp_expires - now <= refetch_window
    _ -> True
  }
}

/// How close to expiry the hourly job refetches (§10.3).
pub const refetch_window = 259_200

/// The target the chain exists to authenticate. Defined by `tuf/verify`,
/// which is the module that has to be right about it: the walk uses this
/// name to build a path, the verifier uses it to look up a signed digest,
/// and two spellings of it would mean fetching one file and checking
/// another.
pub const trusted_root_target = verify.trusted_root_target

/// Walks `<version>.root.json` upward from `version` until the repository
/// has no more, bounded relative to `floor`.
fn root_chain(
  repo: Repo,
  floor: Int,
  version: Int,
  acc: List(#(Int, BitArray)),
) -> Result(List(#(Int, BitArray)), String) {
  case version > floor + root_ceiling {
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
          root_chain(repo, floor, version + 1, [#(version, bytes), ..acc])
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
/// a repository contradicting itself, and nothing here should smooth that
/// over.
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
