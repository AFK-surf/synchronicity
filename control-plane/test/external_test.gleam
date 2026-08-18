//// External DNS provider mode (docs/EXTERNAL-DNS-PROVIDER.md): the
//// renderer, the diff's refusal rules, the reconciler against a fake
//// provider, and the provider legs' pure edges.

import dnssec/keys
import gleam/crypto
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import jobs/provider_sync
import jobs/zonekey_watch
import provider/bunny
import provider/cloudflare
import provider/diff
import provider/provider.{
  type Existing, type Provider, Existing, Provider, Record,
}
import provider/state
import rekor/client
import rekor/store as rekor_store
import store/sqlite
import zone/build
import zone/model.{type ZoneInput, Member, TxtName, ZoneInput, ZoneMeta}
import zone/publish
import zone/render_external

import dns/name
import fixtures
import gleam/int
import gleam/string
import rekor_test

/// An external-mode zone input: no NS hosts, no zone key — the shape
/// `model.read` produces from an `ensure_meta_external` database.
fn input(txt_names: List(model.TxtName)) -> ZoneInput {
  let assert Ok(apex) = name.parse("sync.test.")
  ZoneInput(
    ZoneMeta(apex, 7, <<>>, 0, <<>>, 0, 3600, 1_209_600, 604_800),
    [],
    txt_names,
    [#(1, "proofblob")],
    0,
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
  assert list.contains(names, "_synchronicity.prod.acme.sync.test")
  // The member record value is the §3.2 grammar, unchunked.
  let assert Ok(member) =
    list.find(records, fn(r) { r.name == "_synchronicity.prod.acme.sync.test" })
  assert member.value == "v=sync1 id=nas nk=" <> nk <> " apex=sync.test"
  assert member.ttl == render_external.ttl_data
  // No SOA/NS/DNSKEY shape anywhere: every record is TXT by type.
  assert list.all(records, fn(r) { r.rtype == provider.Txt })

  // The proof records are as short-lived as the data they guard: a resolver
  // holding a stale proof set is the tail of the window a rotation makes a
  // client fail closed for.
  let assert Ok(proof_record) =
    list.find(records, fn(r) { r.name == "_synchronicity-rekor.sync.test" })
  assert proof_record.ttl == render_external.ttl_proof
  // The declaration's content never changes, so nothing is bought by
  // re-fetching it.
  let assert Ok(declaration) =
    list.find(records, fn(r) {
      r.name == "_synchronicity-transparency.sync.test"
    })
  assert declaration.ttl == render_external.ttl_declaration
}

/// The timing relation of `render_external.ttl_proof`, asserted so that
/// moving one term fails here rather than in a rotation.
///
/// The window a client fails closed for after an unannounced provider
/// rotation is the watch cadence plus publication plus the resolver's cached
/// proof, and it has to fit inside the lifetime of the membership that client
/// is already holding — else a routine rotation costs bindings rather than a
/// few refreshes. The client's half of the relation (a 60 s re-resolution
/// floor and a 600 s trust grace) is asserted in `crates/synch-net`.
pub fn the_rotation_window_fits_inside_a_binding_lifetime_test() {
  let watch_cadence = 300
  let publish_slack = 60
  let client_trust_grace = 600
  assert watch_cadence + publish_slack + render_external.ttl_proof
    < render_external.ttl_data + client_trust_grace
}

/// The budget at the shared base name, held still without standing up a log.
///
/// Every proof has a part 1 and they all land at
/// `_synchronicity-rekor.<apex>`, so that name is what fills up. The serving
/// filter keeps the set to two or three; this is what makes a pathological
/// set shed history instead of handing the provider a write it refuses.
pub fn the_proof_budget_sheds_the_oldest_test() {
  let part = fn(index: Int) {
    [string.repeat("x", 2000) <> "-" <> int.to_string(index)]
  }
  // Three fit at ~2028 wire bytes each.
  let #(kept, shed) = model.proofs_within_budget([part(0), part(1), part(0)])
  assert list.length(kept) == 3
  assert shed == 0
  // The fourth does not, and everything behind it is older still.
  let #(kept, shed) =
    model.proofs_within_budget([part(0), part(1), part(0), part(1), part(0)])
  assert list.length(kept) == 3
  assert shed == 2
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
    // Distinct ids for every index: these tests are *about* record
    // identity, so an id generator that collapsed indices past the second
    // onto one string would hand two records the same id in exactly the
    // tests whose subject that is.
    Existing("id-" <> int.to_string(index), record)
  })
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

pub fn the_scope_is_everything_strictly_below_the_apex_test() {
  // The apex is a name this deployment owns outright, so everything under it
  // is ours — and the apex itself is not, because that is where the zone's
  // own SOA, NS and DNSKEY live along with whatever a registrar asks for.
  assert provider.below("_synchronicity-rekor.sync.test", "sync.test")
  assert provider.below("_synchronicity.prod.acme.sync.test", "sync.test")
  assert !provider.below("sync.test", "sync.test")
  // A sibling of the apex is somebody else's — the dashboard's own name, for
  // one, which external mode never publishes.
  assert !provider.below("dashboard.test", "sync.test")
  assert !provider.below("notsync.test", "sync.test")
  // Providers hand names back lowercased and configuration need not be.
  assert provider.below("_synchronicity-rekor.SYNC.test", "sync.TEST")
}

pub fn a_marker_of_another_scope_authorizes_nothing_test() {
  // The marker's value carries the scope it authorizes. One that does not
  // name this scope leaves a record below the apex a conflict rather than a
  // delete: a reconciler that widened its reach on the strength of a marker
  // it does not recognise would be removing records it was never told it
  // could.
  let existing =
    as_existing([
      Record(
        "_synchronicity-owner.sync.test",
        provider.Txt,
        300,
        "heritage=synchronicity-cp",
      ),
      Record("_synchronicity-rekor-6.sync.test", provider.Txt, 300, "stale"),
    ])
  // Reported as the marker it is, not as one of the records it made foreign:
  // it is the reason the pass cannot proceed, and the only conflict an
  // operator fixes by deleting rather than by moving.
  let assert Error(diff.MarkerMismatch(name, value)) =
    diff.diff(desired(), existing)
  assert name == "_synchronicity-owner.sync.test"
  assert value == "heritage=synchronicity-cp"
}

pub fn a_proof_part_we_stopped_rendering_is_deleted_test() {
  // A proof that shrank from six parts to five leaves a record at a name the
  // renderer no longer produces. Under a structural scope it is still found,
  // which is the whole reason the scope is structural.
  let part = fn(label: String, value: String) {
    Record(label <> ".sync.test", provider.Txt, 60, value)
  }
  let publishing = [
    diff.owner_record("sync.test"),
    part("_synchronicity-rekor", "sync1p abcdabcd 1/5 one"),
    part("_synchronicity-rekor-5", "sync1p abcdabcd 5/5 five"),
  ]
  let existing =
    as_existing(
      list.append(publishing, [part("_synchronicity-rekor-6", "orphan")]),
    )
  let assert Ok(changes) = diff.diff(publishing, existing)
  let deleted = list.map(changes.delete, fn(e) { e.record.name })
  assert deleted == ["_synchronicity-rekor-6.sync.test"]
}

pub fn published_proofs_survive_a_pass_with_none_to_publish_test() {
  // Rendering *no* proofs is what a transparency gap looks like: no live key
  // is covered by a verified record, so `servable` answers nothing. That is not
  // a reason to take the zone's existing proofs out — refuse to emit, leave
  // what is published standing, exactly as serve mode's gate does.
  let existing =
    as_existing([
      diff.owner_record("sync.test"),
      Record(
        "_synchronicity.prod.acme.sync.test",
        provider.Txt,
        300,
        "v=sync1 …",
      ),
      Record(
        "_synchronicity-rekor.sync.test",
        provider.Txt,
        60,
        "sync1p abcdabcd 1/1 published",
      ),
    ])
  let assert Ok(changes) = diff.diff(desired(), existing)
  assert changes.delete == []

  // Everything else below the apex is still drift, and still removed.
  let stale =
    as_existing([
      diff.owner_record("sync.test"),
      Record(
        "_synchronicity.old.acme.sync.test",
        provider.Txt,
        300,
        "v=sync1 id=gone nk=stale",
      ),
    ])
  let assert Ok(changes) = diff.diff(desired(), stale)
  assert list.map(changes.delete, fn(e) { e.record.name })
    == ["_synchronicity.old.acme.sync.test"]
}

pub fn creates_go_out_marker_first_and_proofs_last_test() {
  // Dependency order, not name order: the marker authorizes everything else,
  // the declaration is the bottom link of every chain this service logs,
  // membership is the product, and the proofs are the only records big enough
  // for a provider to refuse on size — so they can never be the reason a
  // device add did not land.
  let wanted = [
    Record("_synchronicity-rekor.sync.test", provider.Txt, 300, "sync1p …"),
    Record("_synchronicity.prod.acme.sync.test", provider.Txt, 300, "v=sync1 …"),
    Record(
      "_synchronicity-transparency.sync.test",
      provider.Txt,
      86_400,
      "v=sync1 transparency",
    ),
    diff.owner_record("sync.test"),
  ]
  let assert Ok(changes) = diff.diff(wanted, [])
  assert list.map(changes.create, fn(r) { r.name })
    == [
      "_synchronicity-owner.sync.test",
      "_synchronicity-transparency.sync.test",
      "_synchronicity.prod.acme.sync.test",
      "_synchronicity-rekor.sync.test",
    ]
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
    list: fn() {
      process.send(calls, "list")
      Ok(listing)
    },
    apply: fn(changes) {
      process.send(calls, "apply " <> describe(changes))
      Ok(provider.Applied(list.length(changes.create), []))
    },
    describe: "fake",
  )
}

/// A provider that refuses exactly one name and takes everything else — a
/// proof record too big for its owner name, which is the shape that must not
/// take the membership records behind it down with it.
fn picky_provider(refuses: String, calls: process.Subject(String)) -> Provider {
  Provider(
    list: fn() {
      process.send(calls, "list")
      Ok([])
    },
    apply: fn(changes) {
      let outcomes =
        list.map(changes.create, fn(record) {
          case record.name == refuses {
            True -> #(record.name, Error("content too long for this name"))
            False -> {
              process.send(calls, "applied " <> record.name)
              #(record.name, Ok(Nil))
            }
          }
        })
      Ok(provider.tally(outcomes))
    },
    describe: "picky",
  )
}

fn describe(changes: provider.Changes) -> String {
  int.to_string(list.length(changes.create))
  <> "/"
  <> int.to_string(list.length(changes.replace))
  <> "/"
  <> int.to_string(list.length(changes.delete))
}

fn broken_provider(reason: String) -> Provider {
  Provider(
    list: fn() { Error(reason) },
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

pub fn a_refused_record_does_not_hold_back_the_others_test() {
  let conn = external_conn()
  let calls = process.new_subject()
  let prov = picky_provider("_synchronicity.prod.acme.sync.test", calls)

  provider_sync.run_once_with(conn, prov, "log-only", "z1", 2000)
  let assert Ok("list") = process.receive(calls, 100)
  // One refused record is reported, not fatal: every other record still goes
  // out, in dependency order, and the pass says which one the provider took.
  let applied = drain(calls, [])
  assert list.contains(applied, "applied _synchronicity-owner.sync.test")
  assert list.contains(applied, "applied _synchronicity-transparency.sync.test")

  // Recorded as partial, and the applied hash deliberately did not advance:
  // the zone is not the set we rendered.
  let assert Ok(Ok(partial)) = state.get(conn)
  let assert Some(failures) = partial.last_failures
  assert string_contains(failures, "_synchronicity.prod.acme.sync.test")
  assert partial.last_partial_at == Some(2000)
  assert partial.applied_hash == None

  // So the next pass does not short-circuit on the hash: it lists again and
  // retries what is still missing.
  provider_sync.run_once_with(conn, prov, "log-only", "z1", 3000)
  let assert Ok("list") = process.receive(calls, 100)
  sqlite.close(conn)
}

fn drain(calls: process.Subject(String), seen: List(String)) -> List(String) {
  case process.receive(calls, 50) {
    Ok(message) -> drain(calls, [message, ..seen])
    Error(Nil) -> seen
  }
}

// ---------------------------------------------------------- the key watcher

/// The watcher is external mode's whole rotation loop: it follows the
/// provider's keys because nobody tells us when they move.
pub fn the_watcher_logs_a_changed_key_set_and_stays_quiet_otherwise_test() {
  let conn = external_conn()
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = rekor_test.fake_log(keys.generate())
  let first = keys.dnskey_rdata(keys.generate())
  let second = keys.dnskey_rdata(keys.generate())

  // A first look at a zone whose key is not on the record logs a claim.
  assert watch(conn, apex, [first], log, #(spki, point), 1000)
  let assert Ok(logged) = state.observed_keys(conn)
  assert list.length(logged) == 1
  assert list.all(logged, fn(key) { key.logged_at == Some(1000) })

  // The same set on the next tick is silent: nothing has moved, so there is
  // nothing to say and no entry to mint.
  assert !watch(conn, apex, [first], log, #(spki, point), 2000)

  // A provider pre-publishing its next key changes the set, so the claim is
  // re-made covering *both* — which is what makes the eventual cut a
  // non-event: the incoming key is on the public record before it signs.
  assert watch(conn, apex, [first, second], log, #(spki, point), 3000)
  let assert Ok(both) = state.observed_keys(conn)
  assert list.length(both) == 2
  assert list.all(both, fn(key) { key.logged_at == Some(3000) })

  // And the retirement of the outgoing key is a change like any other.
  assert watch(conn, apex, [second], log, #(spki, point), 4000)
  let assert Ok([survivor]) = state.observed_keys(conn)
  assert survivor.key_sha256 == crypto.hash(crypto.Sha256, second)
  sqlite.close(conn)
}

pub fn the_watcher_retries_after_a_logging_failure_test() {
  let conn = external_conn()
  let assert Ok(apex) = name.parse("sync.test.")
  let rdata = keys.dnskey_rdata(keys.generate())
  let dead = client.Log(submit: fn(_submission) { Error("log unreachable") })
  let #(log, spki, point) = rekor_test.fake_log(keys.generate())

  // A log that cannot be reached is a log line, never a crash — and the key
  // stays unlogged, which is what `/healthz` reports as an age.
  assert !watch(conn, apex, [rdata], dead, #(spki, point), 1000)
  let assert Ok([seen]) = state.observed_keys(conn)
  assert seen.logged_at == None
  let assert Ok(Some(age)) = state.oldest_unlogged_age(conn, 1300)
  assert age == 300

  // The set has not changed, but it is still uncovered, so the next tick
  // tries again rather than mistaking "already seen" for "already logged".
  assert watch(conn, apex, [rdata], log, #(spki, point), 2000)
  let assert Ok(None) = state.oldest_unlogged_age(conn, 2000)
  sqlite.close(conn)
}

fn watch(
  conn: sqlite.Connection,
  apex: name.Name,
  dnskey_rdatas: List(BitArray),
  log: client.Log,
  log_key: #(BitArray, BitArray),
  now: Int,
) -> Bool {
  case
    zonekey_watch.run_once_with(
      conn,
      apex,
      apex,
      rekor_test.fake_resolver_serving(dnskey_rdatas),
      log,
      log_key,
      now,
    )
  {
    zonekey_watch.Logged -> True
    zonekey_watch.WaitingForDeclaration | zonekey_watch.Quiet -> False
  }
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

  // Apex under a broader signing zone: convert against the signing zone,
  // not the apex, or the record is stored at the wrong name.
  let fqdn = "_synchronicity-rekor.sync.example.com"
  assert bunny.relativize(fqdn, "example.com") == "_synchronicity-rekor.sync"
  assert bunny.qualify("_synchronicity-rekor.sync", "example.com") == fqdn
  assert bunny.qualify(bunny.relativize(fqdn, "example.com"), "example.com")
    == fqdn
  assert bunny.relativize(fqdn, "sync.example.com") == "_synchronicity-rekor"
}

pub fn require_rekor_omits_members_until_a_key_is_logged_test() {
  let zone =
    input([TxtName(member_owner(), [Member("nas", fixtures.nk(), "", "")])])
  let assert Ok(gated) = render_external.render_gated(zone, True)
  let gated_names = list.map(gated, fn(r) { r.name })
  assert !list.contains(gated_names, "_synchronicity.prod.acme.sync.test")
  assert list.contains(gated_names, "_synchronicity-transparency.sync.test")
  assert list.contains(gated_names, "_synchronicity-owner.sync.test")
  assert list.contains(gated_names, "_synchronicity-rekor.sync.test")

  let assert Ok(open) = render_external.render(zone)
  assert list.contains(
    list.map(open, fn(r) { r.name }),
    "_synchronicity.prod.acme.sync.test",
  )
}

/// The armed gate holds membership TXT back until the key the provider is
/// actually serving has been logged, and keeps publishing the declaration
/// while it does — the watcher needs that record on the wire to build a chain
/// at all.
///
/// The gate asks about the *observed* keys rather than whether anything has
/// ever been logged, which is what makes it still a gate after the first
/// publish: a provider that later rotates to an unlogged key is held back
/// again, instead of riding on a record about a key it no longer uses.
pub fn require_rekor_keeps_the_declaration_and_drops_members_on_the_wire_test() {
  let conn = external_conn()
  use <- fixtures.with_gate_armed
  let created = process.new_subject()
  let prov =
    Provider(
      list: fn() { Ok([]) },
      apply: fn(changes) {
        process.send(created, list.map(changes.create, fn(r) { r.name }))
        Ok(provider.Applied(list.length(changes.create), []))
      },
      describe: "fake",
    )
  let member = "_synchronicity.prod.acme.sync.test"
  let names = applied_names(conn, prov, created, 2000)
  assert !list.contains(names, member)
  assert list.contains(names, "_synchronicity-transparency.sync.test")

  // The watcher sees the provider's key on the validated wire...
  let key = keys.dnskey_rdata(keys.generate())
  let digest = crypto.hash(crypto.Sha256, key)
  let assert Ok(Nil) =
    state.record_observed(conn, [#(digest, keys.key_tag(key), key)], 2500)
  // ...and it is still held back until that key is the one on the record.
  let other = keys.dnskey_rdata(keys.generate())
  let assert Ok(Nil) =
    record_covering(conn, "rollover", [crypto.hash(crypto.Sha256, other)])
  assert !list.contains(applied_names(conn, prov, created, 2800), member)
  // Logging the key it actually serves opens the gate.
  let assert Ok(Nil) = record_covering(conn, "create", [digest])
  assert list.contains(applied_names(conn, prov, created, 3000), member)
  sqlite.close(conn)
}

/// A pass that has no proofs to publish must not delete the ones that are
/// published.
///
/// "No servable proof" is what `rekor/store.servable` answers when no live key
/// is covered — a transparency gap — and taking the existing proofs out of the
/// provider zone at that moment is the one thing that makes the gap worse. The
/// posture is serve mode's: refuse to emit, leave what is published standing.
pub fn a_pass_with_no_proofs_leaves_the_published_ones_alone_test() {
  let conn = external_conn()
  let deleted = process.new_subject()
  let existing = [
    Existing("id-owner", diff.owner_record("sync.test")),
    Existing(
      "id-proof",
      Record(
        "_synchronicity-rekor.sync.test",
        provider.Txt,
        60,
        "sync1p abcdabcd 1/1 old",
      ),
    ),
    Existing(
      "id-proof-2",
      Record(
        "_synchronicity-rekor-2.sync.test",
        provider.Txt,
        60,
        "sync1p abcdabcd 2/2 older",
      ),
    ),
  ]
  let prov =
    Provider(
      list: fn() { Ok(existing) },
      apply: fn(changes) {
        process.send(
          deleted,
          list.map(changes.delete, fn(e: Existing) { e.record.name }),
        )
        Ok(provider.Applied(0, []))
      },
      describe: "fake",
    )
  // The database has no proof rows at all, so the desired set carries none.
  provider_sync.run_once_with(conn, prov, "log-only", "z1", 2000)
  let assert Ok(names) = process.receive(deleted, 100)
  assert names == []
  sqlite.close(conn)
}

/// The record names one reconciler pass sends to the provider.
///
/// The serial is bumped first, because a pass whose desired set and serial both
/// match what is stored short-circuits without touching the provider — which is
/// correct, and would make every pass after the first one invisible here.
fn applied_names(
  conn: sqlite.Connection,
  prov: Provider,
  created: process.Subject(List(String)),
  now: Int,
) -> List(String) {
  let assert Ok(_) = publish.publish_external(conn, now, "test")
  provider_sync.run_once_with(conn, prov, "log-only", "z1", now)
  let assert Ok(names) = process.receive(created, 100)
  names
}

/// A verified record claiming exactly these key digests.
fn record_covering(
  conn: sqlite.Connection,
  action: String,
  digests: List(BitArray),
) -> Result(Nil, sqlite.Error) {
  rekor_store.put(
    conn,
    rekor_store.Record(
      keyset_sha256: crypto.hash(crypto.Sha256, <<action:utf8>>),
      apex: "sync.test.",
      action: action,
      statement: <<"{}":utf8>>,
      canonicalized_body: <<0:size(512)>>,
      log_id: <<0:size(256)>>,
      log_index: 0,
      checkpoint: <<>>,
      inclusion_path: <<>>,
      chainless: False,
      integrated_at: 1,
      verified_at: 1,
      keys: list.map(digests, fn(digest) { #(digest, 1) }),
    ),
  )
}

pub fn record_logged_stamps_only_the_named_keys_test() {
  let conn = fixtures.fresh_conn()
  let a = #(crypto.hash(crypto.Sha256, <<"a":utf8>>), 1, <<"adata":utf8>>)
  let b = #(crypto.hash(crypto.Sha256, <<"b":utf8>>), 2, <<"bdata":utf8>>)
  let assert Ok(Nil) = state.record_observed(conn, [a, b], 10)
  let assert Ok(Nil) = state.record_logged(conn, [a.0], 20)
  let assert Ok(keys) = state.observed_keys(conn)
  let logged =
    list.filter_map(keys, fn(key) {
      case key.logged_at {
        Some(_) -> Ok(key.key_sha256)
        None -> Error(Nil)
      }
    })
  assert logged == [a.0]
  sqlite.close(conn)
}

fn string_contains(haystack: String, needle: String) -> Bool {
  string.contains(haystack, needle)
}
