//// TUF-driven pin refresh, the relay half (docs/REKOR-ZONE-KEY.md §10).
////
//// The load-bearing test here is the shared fixture in test/fixtures/tuf:
//// real Sigstore metadata, framed into the bundle record, asserted against
//// the same bytes the Rust client's decoder is asserted against
//// (crates/synch-net/tests/tuf_pin_refresh.rs). Everything else in this
//// suite is about what a *relay* owes: refuse garbage, refuse regressions,
//// serve what it has, and be absent quietly when it has nothing.

import dns/name
import dns/wire
import dnssec/keys
import fixtures
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import simplifile
import store/migrate
import store/sqlite
import tuf/bundle.{type Bundle, Bundle}
import tuf/fetch
import tuf/meta
import tuf/store as tuf_store
import zone/build
import zone/model.{type ZoneInput, Member, NsHost, TxtName, ZoneInput, ZoneMeta}

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

/// The bundle the control plane relays: the root chain from the floor a
/// stock client embeds. The fixture also carries the two roots below it,
/// which the repository serves and the *client's* chain walk uses — which
/// of them a bundle carries is the relay's choice, and this is that choice.
fn fixture_bundle() -> Bundle {
  Bundle(
    roots: list.map(string.split(field("bundle_roots"), ","), fn(version) {
      fixture("root-" <> version <> ".json")
    }),
    timestamp: fixture("timestamp.json"),
    snapshot: fixture("snapshot.json"),
    targets: fixture("targets.json"),
    trusted_root: fixture("trusted-root.json"),
  )
}

// ---------------------------------------------------------------- framing

pub fn bundle_encoding_matches_the_fixture_test() {
  assert bundle.encode(fixture_bundle()) == fixture("bundle.bin")
}

pub fn bundle_txt_is_base64url_test() {
  let text = bundle.to_txt(fixture_bundle())
  let assert Ok(decoded) = bit_array.base64_url_decode(text)
  assert decoded == fixture("bundle.bin")
  assert !string.contains(text, "=")
}

pub fn the_wire_layout_is_pinned_test() {
  // Field offsets are load-bearing across two implementations; assert them
  // rather than trusting the encoder to agree with itself.
  let assert [first, ..] = fixture_bundle().roots
  let size = bit_array.byte_size(first)
  let assert <<version:int-size(8), count:int-size(8), len:int-size(32)>> =
    bit_array.slice(fixture("bundle.bin"), 0, 6) |> unwrap_bits
  assert version == bundle.version
  assert count == list.length(fixture_bundle().roots)
  assert len == size
}

pub fn root_chains_round_trip_through_their_stored_form_test() {
  let roots = fixture_bundle().roots
  assert bundle.split_roots(bundle.join_roots(roots)) == Ok(roots)
  assert bundle.split_roots(<<0, 0>>) == Error(Nil)
  assert bundle.split_roots(<<>>) == Ok([])
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
/// suite. Public because resign_test drives the job's TUF leg with it.
pub fn verify_at() -> Int {
  number("verify_at")
}

/// A repository serving the checked-in fixture chain. Public because
/// resign_test drives the job's TUF leg with it.
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

  // What was stored frames up to exactly the bytes the client decodes.
  let assert Ok(Ok(material)) = tuf_store.get(conn)
  assert material.source == "https://tuf.test"
  assert bundle.encode(tuf_store.to_bundle(material)) == fixture("bundle.bin")

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
  assert string.contains(why, "regression")
  let assert Ok(Ok(kept)) = tuf_store.get(conn)
  assert kept.timestamp_version == ahead.timestamp_version
  sqlite.close(conn)
}

pub fn a_refresh_refuses_expired_material_test() {
  // A relay that stores already-expired material is relaying something no
  // client will ever adopt.
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
  assert string.contains(why, int.to_string(fetch.root_floor))
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
  assert string.contains(why, "digest")
  sqlite.close(conn)
}

pub fn refetching_is_due_only_near_expiry_test() {
  let conn = fixtures.fresh_conn()
  // No material at all is always due: a zone that relays nothing is a zone
  // whose clients never refresh their pins.
  assert fetch.due(conn, number("verify_at"))
  let assert Ok(_) =
    fetch.refresh(conn, fake_repo(), "https://tuf.test", number("verify_at"))
  let assert Ok(Ok(material)) = tuf_store.get(conn)
  assert !fetch.due(conn, material.timestamp_expires - fetch.refetch_window - 1)
  assert fetch.due(conn, material.timestamp_expires - fetch.refetch_window)
  assert fetch.due(conn, material.timestamp_expires + 1)
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
        roots: [<<"{}":utf8>>],
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

// --------------------------------------------------------------- serving

fn zone_input(tuf_bundle: String) -> ZoneInput {
  let assert Ok(apex) = name.parse("sync.test.")
  let assert Ok(ns1) = name.parse("ns1.sync.test.")
  let assert Ok(owner) = name.parse("_synchronicity.prod.acme.sync.test.")
  let csk = keys.generate()
  ZoneInput(
    ZoneMeta(
      apex,
      7,
      csk.public,
      keys.key_tag(keys.dnskey_rdata(csk)),
      3600,
      1_209_600,
      604_800,
    ),
    [NsHost(ns1, "127.0.0.1", "")],
    [TxtName(owner, [Member("nas", fixtures.nk(), "", "")])],
    [],
    tuf_bundle,
  )
}

pub fn the_zone_serves_the_tuf_bundle_test() {
  let text = bundle.to_txt(fixture_bundle())
  let assert Ok(rrsets) = build.build(zone_input(text))
  let assert Ok(owner) = name.parse("_synchronicity-tuf.sync.test.")
  let assert Ok(rrset) =
    list.find(rrsets, fn(r) { r.owner == owner && r.rtype == wire.type_txt })
  assert rrset.ttl == build.ttl_rekor
  let assert [rd] = rrset.rdatas
  // TXT rdata is a run of ≤255-byte character-strings; the client
  // concatenates them before decoding.
  assert chunks(rd) == Ok(text)
  // And the name is in the NSEC chain like any other owner.
  assert list.contains(build.owners_in_order(rrsets), owner)
}

pub fn a_zone_without_tuf_material_has_no_such_name_test() {
  let assert Ok(rrsets) = build.build(zone_input(""))
  let assert Ok(owner) = name.parse("_synchronicity-tuf.sync.test.")
  assert !list.contains(build.owners_in_order(rrsets), owner)
}

pub fn a_published_zone_carries_what_was_fetched_test() {
  // The whole relay path in one: fetch into the database, read the zone
  // back out of it, and get the fixture bytes at the owner name a client
  // will ask for.
  let conn = fixtures.fresh_conn()
  let _csk = fixtures.zone_boot(conn)
  let assert Ok(_) =
    fetch.refresh(conn, fake_repo(), "https://tuf.test", number("verify_at"))
  let assert Ok(input) = model.read(conn)
  assert input.tuf_bundle == bundle.to_txt(fixture_bundle())
  let assert Ok(rrsets) = build.build(input)
  let assert Ok(owner) = name.parse("_synchronicity-tuf.sync.test.")
  assert list.contains(build.owners_in_order(rrsets), owner)
  sqlite.close(conn)
}

/// Re-joins TXT character-strings.
fn chunks(rdata: BitArray) -> Result(String, Nil) {
  case rdata {
    <<>> -> Ok("")
    <<len:int-size(8), chunk:bytes-size(len), rest:bits>> -> {
      use head <- result.try(bit_array.to_string(chunk))
      use tail <- result.try(chunks(rest))
      Ok(head <> tail)
    }
    _ -> Error(Nil)
  }
}

fn unwrap_bits(sliced: Result(BitArray, Nil)) -> BitArray {
  let assert Ok(bits) = sliced
  bits
}
