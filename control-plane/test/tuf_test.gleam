//// Fetching Sigstore's TUF metadata, and discovering the log to submit to
//// from what was stored (docs/REKOR-ZONE-KEY.md §10).
////
//// The material here decides one thing: which transparency log shard this
//// service writes its zone-key claim to, and which key it checks the
//// returned proof against. So the suite is about what this side owes around
//// that — refuse garbage, refuse regressions, refetch before the timestamp
//// expires, and read the endpoint out of the same signed artifact clients
//// derive their own pins from.
////
//// It runs against the shared fixture in test/fixtures/tuf: real Sigstore
//// metadata, the same files crates/synch-net/tests/tuf_pin_refresh.rs walks,
//// so the two implementations cannot drift into pinning one log and writing
//// to another.
////
//// The cryptographic gate those fetches pass through lives in
//// tuf_verify_test — every `refresh` below therefore also exercises the real
//// Sigstore chain through the real verifier, which is why a fixture that
//// stopped verifying would fail this file too.

import envoy
import fixtures
import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import rekor/client
import rekor/proof
import simplifile
import store/migrate
import store/sqlite
import tuf/fetch
import tuf/meta
import tuf/store as tuf_store
import tuf/trusted_root

const fixture_dir = "test/fixtures/tuf/"

fn fixture(file: String) -> BitArray {
  let assert Ok(bits) = simplifile.read_bits(fixture_dir <> file)
  bits
}

fn field(name: String) -> String {
  let assert Ok(text) = bit_array.to_string(fixture("meta.txt"))
  let assert Ok(value) =
    text
    |> string.split("\n")
    |> list.find_map(fn(line) {
      case string.split_once(line, "=") {
        Ok(#(key, value)) if key == name -> Ok(value)
        _ -> Error(Nil)
      }
    })
  value
}

fn number(name: String) -> Int {
  let assert Ok(value) = int.parse(field(name))
  value
}

// ------------------------------------------------------------ metadata

pub fn roles_are_read_from_the_real_metadata_test() {
  let assert Ok(timestamp) =
    meta.read_role(fixture("timestamp.json"), "timestamp")
  assert timestamp.version == number("timestamp_version")
  assert timestamp.expires > number("verify_at")
  let assert Ok(snapshot) = meta.read_role(fixture("snapshot.json"), "snapshot")
  assert snapshot.version == number("snapshot_version")
  let assert Ok(targets) = meta.read_role(fixture("targets.json"), "targets")
  assert targets.version == number("targets_version")
  let assert Ok(root) =
    meta.read_role(fixture("root-" <> field("root_version") <> ".json"), "root")
  assert root.version == number("root_version")

  // A file served as the wrong role is refused by name.
  let assert Error(_) = meta.read_role(fixture("snapshot.json"), "targets")
  let assert Error(_) = meta.read_role(<<"not json":utf8>>, "root")
}

pub fn the_chain_names_the_file_below_it_test() {
  assert meta.read_meta_version(fixture("timestamp.json"), "snapshot.json")
    == Ok(number("snapshot_version"))
  assert meta.read_meta_version(fixture("snapshot.json"), "targets.json")
    == Ok(number("targets_version"))
  let assert Error(_) =
    meta.read_meta_version(fixture("timestamp.json"), "targets.json")
}

pub fn the_targets_name_the_trusted_root_test() {
  let assert Ok(#(digest, length)) =
    meta.read_target(fixture("targets.json"), fetch.trusted_root_target)
  assert digest == field("trusted_root_sha256")
  assert length == bit_array.byte_size(fixture("trusted-root.json"))
}

pub fn expiry_timestamps_parse_in_every_shape_the_repository_writes_test() {
  assert meta.parse_rfc3339("1970-01-01T00:00:00Z") == Ok(0)
  assert meta.parse_rfc3339("2026-11-20T13:58:18Z") == Ok(1_795_183_098)
  // Fractional seconds are dropped, not misread; offsets move the instant.
  assert meta.parse_rfc3339("2022-05-11T19:09:02.663975009Z")
    == meta.parse_rfc3339("2022-05-11T19:09:02Z")
  assert meta.parse_rfc3339("2021-12-18T13:28:12.99008-06:00")
    == meta.parse_rfc3339("2021-12-18T19:28:12Z")
  assert meta.parse_rfc3339("2021-12-18T13:28:12+02:00")
    == meta.parse_rfc3339("2021-12-18T11:28:12Z")
  let assert Error(Nil) = meta.parse_rfc3339("2026-11-20")
  let assert Error(Nil) = meta.parse_rfc3339("2026-13-20T13:58:18Z")
  let assert Error(Nil) = meta.parse_rfc3339("not a time at all")
}

// ------------------------------------------------------------- fetching

/// The fixture repository, served as a `Repo`: the real files under the
/// consistent-snapshot names the walk asks for.
/// The moment the fixture chain was fetched — the `now` every test that
/// walks it must use, or the checked-in material expires out from under the
/// suite. Public because tuf_refresh_test drives the job with it.
pub fn verify_at() -> Int {
  number("verify_at")
}

/// A repository serving the checked-in fixture chain. Public because
/// tuf_refresh_test drives the job with it.
pub fn fake_repo() -> fetch.Repo {
  let digest = field("trusted_root_sha256")
  let files =
    list.append(
      list.map(string.split(field("root_versions"), ","), fn(version) {
        #(version <> ".root.json", fixture("root-" <> version <> ".json"))
      }),
      [
        #("timestamp.json", fixture("timestamp.json")),
        #(
          field("snapshot_version") <> ".snapshot.json",
          fixture("snapshot.json"),
        ),
        #(field("targets_version") <> ".targets.json", fixture("targets.json")),
        #(
          "targets/" <> digest <> "." <> fetch.trusted_root_target,
          fixture("trusted-root.json"),
        ),
      ],
    )
  fetch.Repo(get: fn(path) {
    case list.key_find(files, path) {
      Ok(bytes) -> Ok(Some(bytes))
      Error(Nil) -> Ok(None)
    }
  })
}

pub fn a_refresh_stores_the_walked_chain_test() {
  let conn = fixtures.fresh_conn()
  let now = number("verify_at")
  let assert Ok(outcome) =
    fetch.refresh(conn, fake_repo(), "https://tuf.test", now)
  assert outcome.changed
  assert outcome.root_version == number("root_version")
  assert outcome.timestamp_version == number("timestamp_version")
  assert outcome.snapshot_version == number("snapshot_version")
  assert outcome.targets_version == number("targets_version")
  assert outcome.timestamp_expires > now

  // And what was stored is the fixture's own bytes, verbatim.
  let assert Ok(Ok(material)) = tuf_store.get(conn)
  assert material.source == "https://tuf.test"
  assert material.timestamp_json == fixture("timestamp.json")
  assert material.snapshot_json == fixture("snapshot.json")
  assert material.targets_json == fixture("targets.json")
  assert material.trusted_root == fixture("trusted-root.json")

  // Re-running finds nothing new: the ordinary result of the hourly job.
  let assert Ok(again) =
    fetch.refresh(conn, fake_repo(), "https://tuf.test", now)
  assert !again.changed
  sqlite.close(conn)
}

pub fn a_refresh_refuses_a_version_regression_test() {
  let conn = fixtures.fresh_conn()
  let now = number("verify_at")
  let assert Ok(_) = fetch.refresh(conn, fake_repo(), "https://tuf.test", now)

  // The stored material is bumped past what the repository serves: the
  // next fetch would walk a client backwards, so it is refused and the
  // stored row is left exactly as it was.
  let assert Ok(Ok(material)) = tuf_store.get(conn)
  let ahead =
    tuf_store.Material(
      ..material,
      timestamp_version: material.timestamp_version + 1,
    )
  let assert Ok(Nil) = tuf_store.put(conn, ahead)
  let assert Error(why) =
    fetch.refresh(conn, fake_repo(), "https://tuf.test", now)
  assert string.contains(why, "older than the stored")
  let assert Ok(Ok(kept)) = tuf_store.get(conn)
  assert kept.timestamp_version == ahead.timestamp_version
  sqlite.close(conn)
}

pub fn a_refresh_refuses_expired_material_test() {
  // Expiry gates ingestion, where refusing costs a retry — not use, where
  // refusing would leave this service with no log to submit to at all.
  let conn = fixtures.fresh_conn()
  let assert Ok(timestamp) =
    meta.read_role(fixture("timestamp.json"), "timestamp")
  let assert Error(why) =
    fetch.refresh(conn, fake_repo(), "https://tuf.test", timestamp.expires + 1)
  assert string.contains(why, "expired")
  assert tuf_store.get(conn) == Ok(Error(Nil))
  sqlite.close(conn)
}

pub fn a_refresh_refuses_a_repository_missing_the_root_floor_test() {
  let conn = fixtures.fresh_conn()
  let empty = fetch.Repo(get: fn(_path) { Ok(None) })
  let assert Error(why) =
    fetch.refresh(conn, empty, "https://tuf.test", number("verify_at"))
  let assert Ok(floor) = fetch.root_floor()
  assert string.contains(why, int.to_string(floor))
  sqlite.close(conn)
}

pub fn a_refresh_refuses_a_tampered_target_test() {
  let conn = fixtures.fresh_conn()
  let honest = fake_repo()
  let tampered =
    fetch.Repo(get: fn(path) {
      case string.contains(path, fetch.trusted_root_target) {
        True -> Ok(Some(<<"{\"tlogs\":[]}":utf8>>))
        False -> honest.get(path)
      }
    })
  let assert Error(why) =
    fetch.refresh(conn, tampered, "https://tuf.test", number("verify_at"))
  // The class is what matters: the chain says what these bytes must be and
  // they are not it. Whether the length or the digest is the first thing to
  // disagree is not a promise worth pinning.
  assert string.contains(why, "target hash")
  sqlite.close(conn)
}

/// The material verifies and is still refused: a trusted root naming no log
/// in service leaves this service with nowhere to submit and clients with a
/// pin set they refuse, so storing it would advance the versions past what any
/// client will follow and go quiet for days.
pub fn a_refresh_refuses_a_trusted_root_with_no_log_in_service_test() {
  let conn = fixtures.fresh_conn()
  // An instant before the first shard opened. Nothing has expired, so the
  // whole chain verifies; the contents are what is unusable.
  let assert Error(why) =
    fetch.refresh(conn, fake_repo(), "https://tuf.test", 1)
  assert string.contains(why, "no log to submit to")
  assert tuf_store.get(conn) == Ok(Error(Nil))
  sqlite.close(conn)
}

/// A repository does not get to charge this service arbitrary memory for
/// material it has not verified yet.
pub fn a_refresh_refuses_an_oversized_file_test() {
  let conn = fixtures.fresh_conn()
  let honest = fake_repo()
  let huge = <<0:size(67_108_872)>>
  let fat =
    fetch.Repo(get: fn(path) {
      case path == "timestamp.json" {
        True -> Ok(Some(huge))
        False -> honest.get(path)
      }
    })
  let assert Error(why) =
    fetch.refresh(conn, fat, "https://tuf.test", number("verify_at"))
  assert string.contains(why, "limit for one TUF file")
  assert tuf_store.get(conn) == Ok(Error(Nil))
  sqlite.close(conn)
}

/// And the per-file cap alone is not a bound: the root chain probes up to two
/// hundred versions and holds every one of them until the gate runs, so a
/// mirror answering every probe with a file just inside the file cap would be
/// two orders of magnitude past what the walk is allowed to hold.
pub fn a_refresh_refuses_a_walk_past_the_total_budget_test() {
  let conn = fixtures.fresh_conn()
  let assert Ok(floor) = fetch.root_floor()
  // Each probe answers a root that parses and declares the version it was
  // asked for — the walk's own checks pass, so the budget is the only thing
  // that can stop it.
  let endless =
    fetch.Repo(get: fn(path) {
      case string.split_once(path, ".root.json") {
        Ok(#(version, "")) -> {
          let assert Ok(version) = int.parse(version)
          Ok(Some(padded_root(version, 4_194_304)))
        }
        _ -> Ok(None)
      }
    })
  let assert Error(why) =
    fetch.refresh(conn, endless, "https://tuf.test", number("verify_at"))
  assert string.contains(why, "limit for one walk")
  // Comfortably before the version ceiling: the byte budget is what stopped
  // the walk, not the 200-version one.
  assert fetch.max_walk_bytes / 4_194_304 < floor + 200
  assert tuf_store.get(conn) == Ok(Error(Nil))
  sqlite.close(conn)
}

/// A root that reads as TUF metadata for `version`, padded with whitespace to
/// `size` bytes.
fn padded_root(version: Int, size: Int) -> BitArray {
  let head =
    "{\"signed\":{\"_type\":\"root\",\"version\":"
    <> int.to_string(version)
    <> ",\"expires\":\"2099-01-01T00:00:00Z\"},\"signatures\":[]}"
  <<head:utf8, string.repeat(" ", size - string.length(head)):utf8>>
}

pub fn refetching_is_due_only_near_expiry_test() {
  let conn = fixtures.fresh_conn()
  // No material at all is always due: with nothing stored, this service
  // does not know which log shard to submit to.
  assert fetch.due(conn, number("verify_at"))
  let assert Ok(_) =
    fetch.refresh(conn, fake_repo(), "https://tuf.test", number("verify_at"))
  let assert Ok(Ok(material)) = tuf_store.get(conn)
  assert !fetch.due(conn, material.timestamp_expires - fetch.refetch_window - 1)
  assert fetch.due(conn, material.timestamp_expires - fetch.refetch_window)
  assert fetch.due(conn, material.timestamp_expires + 1)
  sqlite.close(conn)
}

// ---------------------------------------------------------- log discovery

/// A trusted root with three shards: one closed, one open, one not yet — the
/// shape a rotation actually has, which the real fixture only has a snapshot
/// of at one instant.
fn three_shards() -> BitArray {
  let assert Ok(real) = trusted_root.tlogs(fixture("trusted-root.json"))
  let assert [first, second, ..] = real
  let entry = fn(
    url: String,
    log: trusted_root.Tlog,
    window: List(#(String, String)),
  ) {
    json.object([
      #("baseUrl", json.string(url)),
      #(
        "publicKey",
        json.object([
          #("rawBytes", json.string(bit_array.base64_encode(log.spki, True))),
          #(
            "validFor",
            json.object(
              list.map(window, fn(pair) { #(pair.0, json.string(pair.1)) }),
            ),
          ),
        ]),
      ),
    ])
  }
  let text =
    json.object([
      #(
        "tlogs",
        json.preprocessed_array([
          entry("https://retired.test/", first, [
            #("start", "2021-01-12T11:53:27Z"),
            #("end", "2025-09-23T00:00:00Z"),
          ]),
          entry("https://open.test", second, [
            #("start", "2025-09-23T00:00:00Z"),
          ]),
          entry("https://next.test", second, [
            #("start", "2030-01-01T00:00:00Z"),
          ]),
        ]),
      ),
    ])
    |> json.to_string
  <<text:utf8>>
}

pub fn the_real_trusted_root_names_the_log_to_write_to_test() {
  let assert Ok(logs) = trusted_root.tlogs(fixture("trusted-root.json"))
  let assert Ok(open) = trusted_root.current(logs, number("verify_at"))
  // Asserted as a shape, never as a hostname: pinning the name here is the
  // thing this module exists to stop doing.
  assert string.starts_with(open.base_url, "https://")
  assert !string.ends_with(open.base_url, "/")
  assert trusted_root.valid_at(open, number("verify_at"))

  // And the log ids the client pins are the digests of the keys named
  // beside those URLs — the same crossval the Rust suite asserts, so the
  // two sides cannot drift into pinning one log and writing to another.
  let ids =
    logs
    |> list.map(fn(log) {
      string.lowercase(bit_array.base16_encode(proof.log_id(log.spki)))
    })
    |> list.sort(string.compare)
  assert ids == list.sort(string.split(field("log_ids"), ","), string.compare)
}

pub fn the_current_log_is_the_one_whose_window_is_open_test() {
  let assert Ok(logs) = trusted_root.tlogs(three_shards())
  // 2026-08: the middle shard. A trailing slash is not part of a base URL.
  let assert Ok(open) = trusted_root.current(logs, 1_786_854_774)
  assert open.base_url == "https://open.test"
  // 2023, before it opened; 2035, after the next one did.
  let assert Ok(before) = trusted_root.current(logs, 1_690_000_000)
  assert before.base_url == "https://retired.test"
  let assert Ok(after) = trusted_root.current(logs, 2_050_000_000)
  assert after.base_url == "https://next.test"
  // Every shard closed or not yet open is a fact to report, not a hostname
  // to guess.
  let assert Error(_) = trusted_root.current(logs, 0)

  // An operator redirecting to a shard the root already names gets its key
  // for free; one it does not name has to bring the key itself.
  let assert Ok(named) = trusted_root.for_url(logs, "https://retired.test/")
  assert named.valid_until != None
  let assert Error(_) = trusted_root.for_url(logs, "https://elsewhere.test")
}

pub fn a_trusted_root_that_does_not_parse_names_no_log_test() {
  let assert Error(_) = trusted_root.tlogs(<<"not json":utf8>>)
  let assert Error(_) = trusted_root.tlogs(<<"{\"tlogs\":[]}":utf8>>)
  // A log with a key but nowhere to reach it is half an answer, and the
  // half that is missing is the one discovery needs.
  let assert Error(_) =
    trusted_root.tlogs(<<
      "{\"tlogs\":[{\"publicKey\":{\"rawBytes\":\"MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=\"}}]}":utf8,
    >>)
}

pub fn the_log_to_submit_to_comes_from_the_stored_material_test() {
  let conn = fixtures.fresh_conn()
  let now = number("verify_at")
  envoy.unset("CP_REKOR_URL")
  envoy.unset("CP_REKOR_KEY")

  // Nothing stored: discovery fails saying where the material comes from
  // rather than falling back to a hostname this build was compiled with.
  let assert Error(why) = client.discover(conn, now)
  assert string.contains(why, "no TUF material stored")
  assert string.contains(why, "CP_REKOR_URL")

  let assert Ok(_) = fetch.refresh(conn, fake_repo(), "https://tuf.test", now)
  let assert Ok(target) = client.discover(conn, now)
  let assert Ok(logs) = trusted_root.tlogs(fixture("trusted-root.json"))
  let assert Ok(open) = trusted_root.current(logs, now)
  assert target.url == open.base_url
  assert target.key == #(open.spki, open.point)
  sqlite.close(conn)
}

pub fn a_first_ceremony_fetches_the_directory_it_needs_test() {
  let conn = fixtures.fresh_conn()
  let now = number("verify_at")
  envoy.unset("CP_REKOR_URL")
  envoy.unset("CP_REKOR_KEY")

  // Nothing stored, so resolving fetches: the first `rekor-publish` on a
  // fresh control plane does not have to be told to fetch first.
  let assert Ok(target) =
    client.resolve(conn, fake_repo(), "https://tuf.test", now)
  let assert Ok(logs) = trusted_root.tlogs(fixture("trusted-root.json"))
  let assert Ok(open) = trusted_root.current(logs, now)
  assert target.url == open.base_url
  let assert Ok(Ok(material)) = tuf_store.get(conn)
  assert material.trusted_root == fixture("trusted-root.json")
  sqlite.close(conn)

  // No material and no egress is two problems, and the message says both:
  // one is fixed by couriering a database, the other by opening a firewall.
  let offline = fixtures.fresh_conn()
  let dead = fetch.Repo(get: fn(_) { Error("no route to host") })
  let assert Error(why) = client.resolve(offline, dead, "https://tuf.test", now)
  assert string.contains(why, "no TUF material stored")
  assert string.contains(why, "no route to host")
  sqlite.close(offline)
}

pub fn a_named_log_and_key_are_taken_as_given_test() {
  let conn = fixtures.fresh_conn()
  let now = number("verify_at")
  // The self-hosted case: no trusted root has anything to say about this
  // log, and discovery must not go looking.
  envoy.set("CP_REKOR_URL", "https://log.test/")
  envoy.set("CP_REKOR_KEY", "test/fixtures/rekor/log-key.pem")
  let assert Ok(target) = client.discover(conn, now)
  assert target.url == "https://log.test"
  let assert Ok(pem) = simplifile.read("test/fixtures/rekor/log-key.pem")
  let assert Ok(pinned) = proof.parse_log_key(pem)
  assert target.key == pinned
  envoy.unset("CP_REKOR_URL")
  envoy.unset("CP_REKOR_KEY")
  sqlite.close(conn)
}

// ------------------------------------------------------------- migration

pub fn the_migration_chain_reaches_the_tuf_table_test() {
  let assert Ok(conn) = sqlite.open(":memory:", sqlite.ReadWrite)
  let assert Ok(version) = migrate.migrate(conn)
  assert version == migrate.build_version()
  // That the chain *reaches* the table is proven by the put below, not by a
  // version number: which migration introduced it is an implementation
  // detail, and pinning it here only breaks when the chain is squashed.
  // The single-row constraint is the schema's, not the application's.
  let assert Ok(Nil) =
    tuf_store.put(
      conn,
      tuf_store.Material(
        source: "https://tuf.test",
        root_version: 15,
        timestamp_json: <<"{}":utf8>>,
        timestamp_version: 1,
        timestamp_expires: 10,
        snapshot_json: <<"{}":utf8>>,
        snapshot_version: 1,
        targets_json: <<"{}":utf8>>,
        targets_version: 1,
        trusted_root: <<"{}":utf8>>,
        fetched_at: 1,
      ),
    )
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(conn, "SELECT count(*) FROM tuf_material", [])
  sqlite.close(conn)
}

// ------------------------------------------------- the redirection attack

pub fn a_mirror_that_rewrites_the_target_and_its_digest_is_refused_test() {
  // The attack §10.6 created and `tuf/verify` closes, in one test.
  //
  // A mirror that beats TLS serves its own `trusted_root.json` — naming a
  // transparency log it controls — *and* rewrites `targets.json` so the digest
  // and length match it. Every structural check then passes: the shape is
  // right, the versions agree, nothing regresses, and the target hashes to
  // exactly what the metadata says. Stored, that file would tell
  // `rekor/client.discover` to submit the zone-key claim into a log nobody
  // monitors.
  //
  // What refuses it is the signature over `targets.json`, which the mirror
  // cannot produce.
  let forged = <<"{\"tlogs\":[{\"baseUrl\":\"https://evil.test\"}]}":utf8>>
  let digest =
    string.lowercase(
      bit_array.base16_encode(crypto.hash(crypto.Sha256, forged)),
    )
  let assert Ok(honest_targets) = bit_array.to_string(fixture("targets.json"))
  let rewritten =
    honest_targets
    |> string.replace(field("trusted_root_sha256"), digest)
    |> string.replace(
      "\"length\": "
        <> int.to_string(bit_array.byte_size(fixture("trusted-root.json"))),
      "\"length\": " <> int.to_string(bit_array.byte_size(forged)),
    )
  let honest = fake_repo()
  let mirror =
    fetch.Repo(get: fn(path) {
      case
        string.contains(path, fetch.trusted_root_target),
        string.contains(path, ".targets.json")
      {
        True, _ -> Ok(Some(forged))
        _, True -> Ok(Some(<<rewritten:utf8>>))
        _, _ -> honest.get(path)
      }
    })
  let conn = fixtures.fresh_conn()
  let assert Error(why) =
    fetch.refresh(conn, mirror, "https://mirror.test", number("verify_at"))
  assert string.contains(why, "does not verify")
  assert string.contains(why, "threshold")
  // Nothing was stored, so nothing downstream can read it.
  assert tuf_store.get(conn) == Ok(Error(Nil))
  sqlite.close(conn)
}
