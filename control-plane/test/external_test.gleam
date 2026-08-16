//// External DNS provider mode (docs/EXTERNAL-DNS-PROVIDER.md): the
//// renderer, the diff's refusal rules, the reconciler against a fake
//// provider, and the provider legs' pure edges.

import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import jobs/provider_sync
import provider/bunny
import provider/cloudflare
import provider/diff
import provider/provider.{
  type Existing, type Provider, Existing, Provider, Record,
}
import provider/state
import store/sqlite
import zone/build
import zone/model.{type ZoneInput, Member, TxtName, ZoneInput, ZoneMeta}
import zone/publish
import zone/render_external

import dns/name
import fixtures
import gleam/string

/// An external-mode zone input: no NS hosts, no zone key — the shape
/// `model.read` produces from an `ensure_meta_external` database.
fn input(txt_names: List(model.TxtName)) -> ZoneInput {
  let assert Ok(apex) = name.parse("sync.test.")
  ZoneInput(
    ZoneMeta(apex, 7, <<>>, 0, 3600, 1_209_600, 604_800),
    [],
    txt_names,
    ["proofblob"],
    "tufblob",
  )
}

fn member_owner() -> name.Name {
  let assert Ok(owner) = name.parse("_synchronicity.prod.acme.sync.test.")
  owner
}

pub fn the_renderer_emits_data_records_and_the_marker_test() {
  let nk = fixtures.nk()
  let assert Ok(records) =
    render_external.render(
      input([TxtName(member_owner(), [Member("nas", nk, "", "")])]),
    )
  let names = list.map(records, fn(r) { r.name })
  assert list.contains(names, "_synchronicity-owner.sync.test")
  assert list.contains(names, "_synchronicity-rekor.sync.test")
  assert list.contains(names, "_synchronicity-tuf.sync.test")
  assert list.contains(names, "_synchronicity.prod.acme.sync.test")
  // The member record value is the §3.2 grammar, unchunked.
  let assert Ok(member) =
    list.find(records, fn(r) { r.name == "_synchronicity.prod.acme.sync.test" })
  assert member.value == "v=sync1 id=nas nk=" <> nk
  assert member.ttl == render_external.ttl_data
  // No SOA/NS/DNSKEY shape anywhere: every record is TXT by type.
  assert list.all(records, fn(r) { r.rtype == provider.Txt })

  // Managed names cover every name the set can occupy — including ones
  // currently empty, so stopped records still get found and deleted.
  let managed = render_external.managed_names(input([]))
  assert list.contains(managed, "_synchronicity-rekor.sync.test")
  assert list.contains(managed, "_synchronicity-owner.sync.test")
}

pub fn the_renderer_refuses_what_the_builder_refuses_test() {
  // One nk under two labels — the §3.2 ambiguity rule, enforced by the
  // same `build.validate` the serving builder runs.
  let nk = fixtures.nk()
  let bad =
    input([
      TxtName(member_owner(), [
        Member("nas", nk, "", ""),
        Member("laptop", nk, "", ""),
      ]),
    ])
  let assert Error(build.AmbiguousNk(_)) = render_external.render(bad)
}

pub fn the_desired_hash_is_stable_test() {
  let nk = fixtures.nk()
  let zone = input([TxtName(member_owner(), [Member("nas", nk, "", "")])])
  let assert Ok(one) = render_external.render(zone)
  let assert Ok(two) = render_external.render(zone)
  assert render_external.desired_hash(one) == render_external.desired_hash(two)
  let assert Ok(other) = render_external.render(input([]))
  assert render_external.desired_hash(one)
    != render_external.desired_hash(other)
}

// ------------------------------------------------------------------ diff

fn desired() -> List(provider.Record) {
  [
    diff.owner_record("sync.test"),
    Record("_synchronicity.prod.acme.sync.test", provider.Txt, 300, "v=sync1 …"),
  ]
}

fn as_existing(records: List(provider.Record)) -> List(Existing) {
  list.index_map(records, fn(record, index) {
    Existing("id-" <> int_to_string(index), record)
  })
}

fn int_to_string(i: Int) -> String {
  case i {
    0 -> "0"
    1 -> "1"
    _ -> "n"
  }
}

pub fn a_first_sync_is_all_creates_test() {
  let assert Ok(changes) = diff.diff(desired(), [])
  assert changes.create == desired()
  assert changes.replace == []
  assert changes.delete == []
}

pub fn a_converged_zone_yields_no_changes_test() {
  let assert Ok(changes) = diff.diff(desired(), as_existing(desired()))
  assert provider.no_changes(changes)
}

pub fn byte_equal_records_are_adopted_without_a_marker_test() {
  // The provider already holds exactly what we want (minus the marker):
  // adopt silently; the marker is created, nothing else is touched.
  let existing =
    as_existing([
      Record(
        "_synchronicity.prod.acme.sync.test",
        provider.Txt,
        300,
        "v=sync1 …",
      ),
    ])
  let assert Ok(changes) = diff.diff(desired(), existing)
  assert changes.create == [diff.owner_record("sync.test")]
  assert changes.delete == []
}

pub fn foreign_data_without_a_marker_is_a_conflict_test() {
  let existing =
    as_existing([
      Record(
        "_synchronicity.prod.acme.sync.test",
        provider.Txt,
        300,
        "v=spf1 -all",
      ),
    ])
  let assert Error(diff.Foreign(name, value)) = diff.diff(desired(), existing)
  assert name == "_synchronicity.prod.acme.sync.test"
  assert value == "v=spf1 -all"
}

pub fn foreign_data_with_the_marker_is_deleted_test() {
  // The marker says the zone is ours to correct, so a stale record we no
  // longer render is deleted rather than refused.
  let existing =
    as_existing([
      diff.owner_record("sync.test"),
      Record(
        "_synchronicity.prod.acme.sync.test",
        provider.Txt,
        300,
        "v=sync1 id=gone nk=stale",
      ),
    ])
  let assert Ok(changes) = diff.diff(desired(), existing)
  let deleted = list.map(changes.delete, fn(e) { e.record.value })
  assert deleted == ["v=sync1 id=gone nk=stale"]
}

pub fn a_ttl_change_is_a_replace_not_a_foreign_record_test() {
  let existing =
    as_existing([
      diff.owner_record("sync.test"),
      Record(
        "_synchronicity.prod.acme.sync.test",
        provider.Txt,
        3600,
        "v=sync1 …",
      ),
    ])
  let assert Ok(changes) = diff.diff(desired(), existing)
  let assert [#(_, replacement)] = changes.replace
  assert replacement.ttl == 300
  assert changes.delete == []
}

// ------------------------------------------------------------ reconciler

/// A fake provider over a preset listing, reporting every call into the
/// test's mailbox — which is also how "the sweep's common case makes no
/// provider calls" is asserted: an empty mailbox.
fn fake_provider(
  listing: List(Existing),
  calls: process.Subject(String),
) -> Provider {
  Provider(
    list: fn(_names) {
      process.send(calls, "list")
      Ok(listing)
    },
    apply: fn(changes) {
      process.send(calls, "apply " <> describe(changes))
      Ok(Nil)
    },
    describe: "fake",
  )
}

fn describe(changes: provider.Changes) -> String {
  int_to_string(list.length(changes.create))
  <> "/"
  <> int_to_string(list.length(changes.replace))
  <> "/"
  <> int_to_string(list.length(changes.delete))
}

fn broken_provider(reason: String) -> Provider {
  Provider(
    list: fn(_names) { Error(reason) },
    apply: fn(_changes) { Error(reason) },
    describe: "broken",
  )
}

/// A migrated external-mode database with one member record.
fn external_conn() -> sqlite.Connection {
  let conn = fixtures.fresh_conn()
  let assert Ok(Nil) = publish.ensure_meta_external(conn, "sync.test")
  let assert Ok(_) =
    sqlite.script(
      conn,
      "INSERT INTO users VALUES ('u1', 'a@example.com', NULL, 0);
       INSERT INTO orgs VALUES ('o1', 'acme', 'Acme', 0);
       INSERT INTO networks VALUES ('n1', 'o1', 'prod', 0);
       INSERT INTO devices VALUES ('d1', 'o1', 'nas', NULL, NULL, 'u1', 0);
       INSERT INTO network_devices VALUES ('n1', 'd1', 0);",
    )
  fixtures.add_key(conn, "k1", "d1", "active", 1)
  let assert Ok(_) = publish.publish_external(conn, 1000, "test:boot")
  conn
}

pub fn the_reconciler_converges_then_goes_quiet_test() {
  let conn = external_conn()
  let calls = process.new_subject()
  let prov = fake_provider([], calls)

  provider_sync.run_once_with(conn, prov, "log-only", "z1", 2000)
  let assert Ok("list") = process.receive(calls, 100)
  let assert Ok("apply " <> _) = process.receive(calls, 100)
  let assert Ok(Ok(synced)) = state.get(conn)
  assert synced.last_error == None
  assert synced.last_synced_serial == Some(1)

  // Converged: the second pass answers from the stored hash — one SELECT,
  // no provider traffic at all.
  provider_sync.run_once_with(conn, prov, "log-only", "z1", 3000)
  let assert Error(Nil) = process.receive(calls, 100)

  // A mutation moves the serial, so the next pass applies again.
  let assert Ok(_) = publish.publish_external(conn, 4000, "test:mutation")
  provider_sync.run_once_with(conn, prov, "log-only", "z1", 5000)
  let assert Ok("list") = process.receive(calls, 100)
  sqlite.close(conn)
}

pub fn a_conflict_stops_the_pass_and_is_reported_test() {
  let conn = external_conn()
  let calls = process.new_subject()
  let foreign =
    Existing(
      "их-1",
      Record("_synchronicity-rekor.sync.test", provider.Txt, 300, "not ours"),
    )
  provider_sync.run_once_with(
    conn,
    fake_provider([foreign], calls),
    "log-only",
    "z1",
    2000,
  )
  // Listed, refused, nothing applied.
  let assert Ok("list") = process.receive(calls, 100)
  let assert Error(Nil) = process.receive(calls, 100)
  let assert Ok(Ok(synced)) = state.get(conn)
  let assert Some(reason) = synced.last_error
  assert string_contains(reason, "conflict")
  sqlite.close(conn)
}

pub fn a_provider_outage_is_recorded_and_recovered_from_test() {
  let conn = external_conn()
  provider_sync.run_once_with(
    conn,
    broken_provider("api down"),
    "log-only",
    "z1",
    2000,
  )
  let assert Ok(Ok(stale)) = state.get(conn)
  let assert Some(_) = stale.last_error

  let calls = process.new_subject()
  provider_sync.run_once_with(
    conn,
    fake_provider([], calls),
    "log-only",
    "z1",
    3000,
  )
  let assert Ok(Ok(healed)) = state.get(conn)
  assert healed.last_error == None
  sqlite.close(conn)
}

pub fn external_publish_bumps_the_serial_and_audits_test() {
  let conn = external_conn()
  let assert Ok(serial) = publish.publish_external(conn, 2000, "test:again")
  assert serial == 2
  let assert Ok([[sqlite.Int(rows)]]) =
    sqlite.query(
      conn,
      "SELECT count(*) FROM audit_log WHERE action = 'zone.publish'",
      [],
    )
  assert rows >= 2
  sqlite.close(conn)
}

pub fn an_external_database_refuses_a_serve_mode_zone_test() {
  // A database that carries a real zone key was a serve-mode zone; flipping
  // the mode must not quietly abandon it.
  let conn = fixtures.fresh_conn()
  let _csk = fixtures.zone_boot(conn)
  let assert Error(reason) = publish.ensure_meta_external(conn, "sync.test")
  assert string_contains(reason, "serve-mode")
  sqlite.close(conn)
}

// -------------------------------------------------------- provider edges

pub fn cloudflare_txt_presentation_is_folded_down_test() {
  assert cloudflare.unquote_txt("plain") == "plain"
  assert cloudflare.unquote_txt("\"one\"") == "one"
  assert cloudflare.unquote_txt("\"one\" \"two\"") == "onetwo"
}

pub fn bunny_names_are_relative_and_come_back_qualified_test() {
  assert bunny.relativize("sync.test", "sync.test") == ""
  assert bunny.relativize("_synchronicity-rekor.sync.test", "sync.test")
    == "_synchronicity-rekor"
  assert bunny.qualify("", "sync.test") == "sync.test"
  assert bunny.qualify("_synchronicity-rekor", "sync.test")
    == "_synchronicity-rekor.sync.test"
}

fn string_contains(haystack: String, needle: String) -> Bool {
  string.contains(haystack, needle)
}
