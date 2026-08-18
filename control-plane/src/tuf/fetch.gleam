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
//// — and nothing it collects is stored until two gates pass. The chain must
//// verify from the anchor down: signatures over canonical JSON, thresholds,
//// expiries, monotonicity, and the target's digest. Then the trusted root's
//// *contents* must be material a client could use at all — logs it can read,
//// keys it recognises, one of them in service — because a signature makes
//// bytes authentic and not useful. What is stored is therefore material this
//// side has checked, not merely material it received.
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
import gleam/bit_array
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
import tuf/trusted_root
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

/// The most bytes one TUF file may be — the same 8 MiB the client applies
/// (`MAX_TUF_BYTES`, crates/synch-net/src/dns.rs). Sigstore's files are tens
/// of kilobytes.
///
/// **This is a bound on what is accepted, not on what is allocated**, and the
/// difference is worth stating because the obvious reading is wrong.
/// `gleam_httpc` returns a fully materialised body, so `spend` runs after the
/// bytes are already in memory: a repository answering with an endless body
/// exhausts the VM before this constant is consulted. The client reads
/// through a capped stream precisely so its own cap means something
/// (`dns.rs`: "a cap applied to the result of `bytes()` is a bound on
/// nothing").
///
/// What does bound this side today is `max_walk_ms` and the aggregate below —
/// time and accepted volume, not peak memory. Closing it properly needs a
/// streaming HTTP client on this leg; doing it by hand would mean restating
/// the TLS options `gleam_httpc` configures, and getting *those* wrong is a
/// worse failure than the one being fixed. Left as the follow-up it is rather
/// than described as a guarantee it is not.
pub const max_file_bytes = 8_388_608

/// The most bytes one whole walk may accept, across the root chain and the
/// four files below it — the same 8 MiB ceiling the client applies, rather
/// than the 4× larger number this used to carry for no stated reason.
///
/// A per-file cap alone bounds nothing here: the root chain probes up to
/// `root_ceiling` versions and holds every one of them until the gate below
/// runs, so the product of the two is what a hostile mirror would get to
/// allocate. Real material is a fraction of this.
pub const max_walk_bytes = 8_388_608

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
  use #(roots, budget) <- result.try(root_chain(
    repo,
    anchored.version,
    anchored.version,
    [],
    new_budget(),
  ))
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
  use #(timestamp, budget) <- result.try(fetch(repo, "timestamp.json", budget))
  use timestamp_role <- result.try(meta.read_role(timestamp, "timestamp"))
  use snapshot_version <- result.try(meta.read_meta_version(
    timestamp,
    "snapshot.json",
  ))
  use #(snapshot, budget) <- result.try(fetch(
    repo,
    int.to_string(snapshot_version) <> ".snapshot.json",
    budget,
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
  use #(targets, budget) <- result.try(fetch(
    repo,
    int.to_string(targets_version) <> ".targets.json",
    budget,
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
  use #(trusted_root, _budget) <- result.try(fetch(
    repo,
    "targets/" <> digest <> "." <> trusted_root_target,
    budget,
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

  // The second gate: the target's *contents*. A signature makes the trusted
  // root authentic, not usable — and the client refuses a trusted root that
  // names no tlogs, a tlog without a `baseUrl`, or a key that is not an SPKI
  // it recognises (`tlog_keys`, crates/synch-net/src/tuf.rs). Storing such
  // material would advance this service's versions past material clients
  // structurally refuse, and the failure would surface days later as proofs
  // from a log nobody pins.
  // Note what is *not* gated here: whether any shard's window is open right
  // now. Expiry gates updates, never operation (§10.2), and a window is the
  // same kind of fact — during a staged rotation the next shard's window may
  // start in the future while the previous one has ended, and refusing to
  // store then is refusing the very update that teaches this service the new
  // shard. `discover` asks that question at the moment of use, where it
  // belongs, and the Rust client's `update` has never asked it at all.
  use _logs <- result.try(
    trusted_root.tlogs(trusted_root)
    |> result.map_error(fn(why) {
      "refusing a trusted root no client could use: " <> why
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

/// How many bytes this walk has taken so far.
///
/// Threaded rather than global because it has to be: every fetch in one
/// refresh shares the bound, and none of them may be trusted until the
/// verification gate below has run over all of them.
/// The most wall-clock time one whole walk may take.
///
/// A per-request timeout is not a bound on a walk, and the arithmetic is the
/// point: `gleam_httpc` defaults to 30 s per request and `root_chain` probes
/// up to `root_ceiling` versions, so a mirror answering every probe just
/// inside the timeout costs ~1.7 hours per attempt. The refresh job re-arms
/// only after `run_once` returns, so that is a refresh that has effectively
/// stopped — stored material ages past its timestamp expiry and this service
/// keeps submitting into whichever shard it last knew, which is the silent
/// failure §10.6 exists to prevent. `rekor-publish` walks the same path and
/// blocks an operator standing at a terminal.
///
/// The client applies the same bound for the same reason (`tuf.rs`'s
/// `MAX_WALK_TIME`).
pub const max_walk_ms = 120_000

type Budget {
  Budget(used: Int, deadline: Int)
}

/// Walks `<version>.root.json` upward from `version` until the repository
/// has no more, bounded relative to `floor` and by the byte budget.
fn root_chain(
  repo: Repo,
  floor: Int,
  version: Int,
  acc: List(#(Int, BitArray)),
  budget: Budget,
) -> Result(#(List(#(Int, BitArray)), Budget), String) {
  case version > floor + root_ceiling {
    True ->
      Error("the repository's root chain does not end; refusing to walk on")
    False -> {
      let path = int.to_string(version) <> ".root.json"
      use fetched <- result.try(repo.get(path))
      case fetched {
        None -> Ok(#(list.reverse(acc), budget))
        Some(bytes) -> {
          use budget <- result.try(spend(budget, path, bytes))
          use role <- result.try(meta.read_role(bytes, "root"))
          use Nil <- result.try(agrees(path, role.version, version))
          root_chain(
            repo,
            floor,
            version + 1,
            [#(version, bytes), ..acc],
            budget,
          )
        }
      }
    }
  }
}

fn fetch(
  repo: Repo,
  path: String,
  budget: Budget,
) -> Result(#(BitArray, Budget), String) {
  use fetched <- result.try(repo.get(path))
  case fetched {
    Some(bytes) -> {
      use budget <- result.try(spend(budget, path, bytes))
      Ok(#(bytes, budget))
    }
    None -> Error("the repository has no " <> path)
  }
}

/// Charges one fetched file against the caps, or refuses it.
/// A fresh budget: no bytes spent, and a deadline `max_walk_ms` out.
fn new_budget() -> Budget {
  Budget(used: 0, deadline: now_ms() + max_walk_ms)
}

@external(erlang, "cp_sys_ffi", "monotonic_ms")
fn now_ms() -> Int

fn spend(
  budget: Budget,
  path: String,
  bytes: BitArray,
) -> Result(Budget, String) {
  use Nil <- result.try(case now_ms() > budget.deadline {
    True ->
      Error(
        "this refresh has been walking for longer than "
        <> int.to_string(max_walk_ms / 1000)
        <> " seconds; abandoning it with the material in force left standing",
      )
    False -> Ok(Nil)
  })
  let size = bit_array.byte_size(bytes)
  let used = budget.used + size
  case size > max_file_bytes, used > max_walk_bytes {
    True, _ ->
      Error(
        path
        <> " is "
        <> int.to_string(size)
        <> " bytes, past the "
        <> int.to_string(max_file_bytes)
        <> "-byte limit for one TUF file",
      )
    _, True ->
      Error(
        "this refresh has fetched "
        <> int.to_string(used)
        <> " bytes, past the "
        <> int.to_string(max_walk_bytes)
        <> "-byte limit for one walk",
      )
    False, False -> Ok(Budget(..budget, used: used))
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
