//// External DNS provider mode (docs/EXTERNAL-DNS-PROVIDER.md): the
//// renderer, the diff's refusal rules, the reconciler against a fake
//// provider, and the provider legs' pure edges.

import dnssec/keys
import gleam/crypto
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import gleam/otp/static_supervisor as sup
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
import store/db
import store/migrate
import store/sqlite
import zone/build
import zone/model.{type ZoneInput, Member, TxtName, ZoneInput, ZoneMeta}
import zone/publish
import zone/render_external

import dns/name
import fixtures.{tmp_db}
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
    "",
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
/// floor and a 900 s trust grace) is asserted in `crates/synch-net`.
///
/// The grace is `DEFAULT_TRUST_GRACE` in `crates/synch-net/src/dns.rs` and it
/// is 15 minutes, not the 600 this test and the constant's own comment used
/// to carry. The direction is worth noting: the wrong number *understated*
/// the margin, so the relation was being maintained against a tighter budget
/// than the real one. It holds either way — but a relation written down to be
/// checked should be the one that is true.
pub fn the_rotation_window_fits_inside_a_binding_lifetime_test() {
  let watch_cadence = 300
  let publish_slack = 60
  let client_trust_grace = 900
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

/// The require-gate withholds membership; it does not retract it.
///
/// The trigger is `omit_members`, which is armed by *any* uncovered observed
/// key — including a next key pre-published for an RFC 6781 rollover that is
/// not signing anything yet. The zone is still signed by the covered key it
/// was always signed by, and every client is still happy. Deleting the member
/// records there would take the product down during a routine rotation, and
/// take it down for `RekorPolicy::Off` clients too, which opted out of the
/// requirement the gate enforces. Fail-closed for a publisher is "do not emit
/// new claims", not "retract correct ones already standing".
pub fn published_members_survive_a_pass_the_gate_withheld_test() {
  let member =
    Record("_synchronicity.prod.acme.sync.test", provider.Txt, 300, "v=sync1 …")
  let published = as_existing([diff.owner_record("sync.test"), member])
  // What `render_gated(input, True)` produces: everything but the members.
  let gated_desired = [
    diff.owner_record("sync.test"),
    Record(
      "_synchronicity-transparency.sync.test",
      provider.Txt,
      86_400,
      "v=sync1 transparency",
    ),
  ]

  // The withheld set is what the ungated render produced, so the published
  // member is in it and survives.
  let assert Ok(gated) =
    diff.diff_gated(gated_desired, published, [member], adopted: False)
  assert gated.delete == []

  // And the distinction is real: the same desired set with nothing withheld
  // means the last device was revoked, which must still delete.
  let assert Ok(revoked) =
    diff.diff_gated(gated_desired, published, [], adopted: False)
  assert list.map(revoked.delete, fn(e) { e.record.name })
    == ["_synchronicity.prod.acme.sync.test"]
}

/// The shield covers the withheld *records*, never the name shape.
///
/// This is the difference between "hold back what we would have published"
/// and "stop deleting anything that looks like membership". A revoked
/// device's record and one an attacker planted both carry a
/// membership-shaped name and neither is in the withheld set, because the
/// renderer did not produce them. Shielding by shape would freeze both for as
/// long as the gate stayed armed, which is unbounded.
pub fn the_gate_shields_withheld_records_not_membership_shaped_names_test() {
  let live =
    Record("_synchronicity.prod.acme.sync.test", provider.Txt, 300, "v=sync1 …")
  let revoked =
    Record(
      "_synchronicity.prod.acme.sync.test",
      provider.Txt,
      300,
      "v=sync1 …ᴿ",
    )
  let forged =
    Record(
      "_synchronicity.attacker.acme.sync.test",
      provider.Txt,
      300,
      "v=sync1 l=attacker",
    )
  let existing =
    as_existing([diff.owner_record("sync.test"), live, revoked, forged])
  let gated_desired = [diff.owner_record("sync.test")]

  // The gate is armed and `live` is what this pass rendered and held back.
  let assert Ok(changes) =
    diff.diff_gated(gated_desired, existing, [live], adopted: False)
  let deleted =
    list.sort(
      list.map(changes.delete, fn(e) { e.record.value }),
      string.compare,
    )
  // Both the revoked record and the forgery go; only the withheld one stays.
  assert deleted == ["v=sync1 l=attacker", "v=sync1 …ᴿ"]
}

/// The shield is membership only — other drift is still drift.
pub fn the_gate_does_not_shield_anything_but_membership_test() {
  let member =
    Record("_synchronicity.prod.acme.sync.test", provider.Txt, 300, "v=sync1 …")
  let existing =
    as_existing([
      diff.owner_record("sync.test"),
      Record("_synchronicity-rekor.sync.test", provider.Txt, 60, "sync1p old"),
      Record("_unrelated.sync.test", provider.Txt, 300, "junk"),
    ])
  let desired_now = [
    diff.owner_record("sync.test"),
    Record("_synchronicity-rekor.sync.test", provider.Txt, 60, "sync1p new"),
  ]
  let assert Ok(changes) =
    diff.diff_gated(desired_now, existing, [member], adopted: False)
  let deleted =
    list.sort(list.map(changes.delete, fn(e) { e.record.name }), string.compare)
  assert deleted == ["_synchronicity-rekor.sync.test", "_unrelated.sync.test"]
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
  external_conn_at(fixtures.tmp_db())
}

/// The same at a named path, for a test that hands the path to a job.
fn external_conn_at(path: String) -> sqlite.Connection {
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)
  let assert Ok(Nil) = publish.ensure_meta_external(conn, "sync.test")
  let assert Ok(_) =
    sqlite.script(
      conn,
      "INSERT INTO users VALUES ('u1', 'a@example.com', NULL, 0);
       INSERT INTO orgs VALUES ('o1', 'acme', 'Acme', 0);
       INSERT INTO networks (id, org_id, name, created_at)
         VALUES ('n1', 'o1', 'prod', 0);
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

  // Converged, and inside `reconcile_interval`: the second pass answers from
  // the stored hash — one SELECT, no provider traffic at all.
  provider_sync.run_once_with(conn, prov, "log-only", "z1", 2100)
  let assert Error(Nil) = process.receive(calls, 100)

  // A mutation moves the serial, so the next pass applies again.
  let assert Ok(_) = publish.publish_external(conn, 4000, "test:mutation")
  provider_sync.run_once_with(conn, prov, "log-only", "z1", 5000)
  let assert Ok("list") = process.receive(calls, 100)
  sqlite.close(conn)
}

/// Quiet is not forever: the skip expires and the provider is read again.
///
/// Every input to the hash short-circuit is this control plane's own state,
/// so without a time bound a deployment that stops mutating stops looking at
/// the zone it holds delete authority over — and drift introduced at the
/// provider survives exactly as long as nobody here writes anything. The
/// module doc claims the sweep self-heals that; this is the term that makes
/// it true.
pub fn a_converged_reconciler_still_reads_the_provider_eventually_test() {
  let conn = external_conn()
  let calls = process.new_subject()
  let prov = fake_provider([], calls)

  provider_sync.run_once_with(conn, prov, "log-only", "z1", 2000)
  let assert Ok("list") = process.receive(calls, 100)
  let assert Ok("apply " <> _) = process.receive(calls, 100)

  // Well inside the interval: still quiet, so the cheap path is intact.
  provider_sync.run_once_with(conn, prov, "log-only", "z1", 2100)
  let assert Error(Nil) = process.receive(calls, 100)

  // Past it, with nothing whatever changed on our side — no mutation, no
  // serial bump, the same hash — and the provider is listed again.
  provider_sync.run_once_with(conn, prov, "log-only", "z1", 2000 + 901)
  let assert Ok("list") = process.receive(calls, 100)
  sqlite.close(conn)
}

/// And what that read is *for*: a record nobody here wrote is removed, from a
/// zone that had already converged and has had no local change since.
///
/// The reconciler holds delete authority below the apex, and this is the case
/// that authority exists for — an API token, not the provider itself, adding
/// a membership record for a key the control plane never issued. It has to be
/// driven through a *converged* pass: on a first pass `state.get` is
/// `Error(Nil)` and the short-circuit is already false, so the interval term
/// is never consulted and the test would pass with the fix reverted.
pub fn drift_introduced_at_the_provider_is_repaired_without_a_local_change_test() {
  let conn = external_conn()
  let calls = process.new_subject()
  // The marker has to be there, or the pass refuses the whole zone rather
  // than editing one record in it — that guard is orthogonal to this one.
  let owner = Existing("owner-1", diff.owner_record("sync.test"))
  let forged =
    Existing(
      "forged-1",
      Record(
        "_synchronicity.attacker.acme.sync.test",
        provider.Txt,
        300,
        "v=sync1 l=attacker k=zzzz",
      ),
    )

  // Converge, then let the pass go quiet.
  provider_sync.run_once_with(
    conn,
    fake_provider([], calls),
    "log-only",
    "z1",
    2000,
  )
  let assert Ok("list") = process.receive(calls, 100)
  let assert Ok("apply " <> _) = process.receive(calls, 100)
  provider_sync.run_once_with(
    conn,
    fake_provider([], calls),
    "log-only",
    "z1",
    2100,
  )
  let assert Error(Nil) = process.receive(calls, 100)

  // Now the record appears at the provider. Nothing changes on our side: no
  // mutation, no serial bump, the same hash. Only the clock moves.
  provider_sync.run_once_with(
    conn,
    fake_provider([owner, forged], calls),
    "log-only",
    "z1",
    2000 + 901,
  )
  let assert Ok("list") = process.receive(calls, 100)
  let assert Ok("apply " <> applied) = process.receive(calls, 100)
  // `describe` is create/replace/delete: exactly one delete, and it is the
  // record this control plane never rendered.
  assert string.ends_with(applied, "/1")
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

// -------------------------------------------------- the reconciler's actor

/// A poke at a name nothing is registered under is a no-op, not a crash.
///
/// `process.send` to a `NamedSubject` is
/// `let assert Ok(pid) = named(name) as "Sending to unregistered name"` — it
/// raises. The caller is `zone_mutation`, *after* its transaction has
/// committed and *before* the response is built, so a raise there turns a
/// committed revocation into a 500 whose follow-up work (dropping the revoked
/// key's live tunnels) never runs, while the row is already revoked so the
/// retry answers 404. Two windows reach it: boot, before the reconciler has
/// registered its name, and any restart of the reconciler.
pub fn a_poke_at_no_reconciler_is_a_no_op_test() {
  let missing = process.new_name("t_absent_reconciler")
  let assert Error(Nil) = process.named(missing)
  // The assertion is that this line returns at all.
  provider_sync.poke(missing)
  let assert Error(Nil) = process.named(missing)
}

/// A poke does not fork a second sweep timer chain.
///
/// `handle` re-arms after a `Tick`, and a poke arrives at the same named
/// subject. Handled as a `Tick` it would arm an additional timer that is
/// never cancelled — one per poke, for the life of the process — so the
/// steady-state sweep rate becomes one pass per interval per poke ever
/// received. Any authenticated member can drive that by editing a device in
/// a loop, and a revocation's own poke then queues behind the backlog.
///
/// Measured rather than reasoned: the sweep interval is named here so the
/// chain is observable in a test. Ten pokes at the head of the window; with
/// the bug the passes over the window are ~11 per interval instead of one.
/// The bound is deliberately loose (pokes and boot tick included, plus one
/// interval of slack) so it fails on the defect and not on scheduling jitter.
pub fn a_poke_does_not_fork_a_second_sweep_timer_test() {
  let path = tmp_db()
  let conn = external_conn_at(path)
  sqlite.close(conn)
  let calls = process.new_subject()
  let name = process.new_name("t_reconciler_timer")
  let assert Ok(_) =
    sup.new(sup.OneForOne)
    |> sup.restart_tolerance(intensity: 10, period: 5)
    |> sup.add(provider_sync.supervised_every(
      name,
      path,
      counting_provider(calls),
      "log-only",
      "z1",
      100,
    ))
    |> sup.start

  // Ten pokes inside the first interval.
  list.each(list.repeat(Nil, 10), fn(_) { provider_sync.poke(name) })
  process.sleep(1000)
  let passes = drain_passes(calls, 0)

  // One boot tick + ten pokes + about ten timer ticks over the second, so
  // roughly twenty-one. Eleven concurrent chains would be about a hundred
  // and twenty. The bounds are loose enough that scheduling jitter cannot
  // reach either of them.
  assert passes >= 11
  assert passes < 60
}

/// Counts every pass by reporting one message per `list` call, and then
/// fails.
///
/// The failure is what makes the count a count. A converged reconciler
/// short-circuits on its stored hash and makes no provider call at all, so a
/// provider that succeeded would be listed once and never again; a pass that
/// ends in `record_error` leaves `last_error` set, which `fresh` requires to
/// be `None`, so every subsequent pass lists.
fn counting_provider(calls: process.Subject(String)) -> Provider {
  Provider(
    list: fn() {
      process.send(calls, "pass")
      Error("counting")
    },
    apply: fn(_changes) { Error("counting") },
    describe: "counting",
  )
}

fn drain_passes(calls: process.Subject(String), seen: Int) -> Int {
  case process.receive(calls, 0) {
    Ok(_) -> drain_passes(calls, seen + 1)
    Error(Nil) -> seen
  }
}

/// A marker overwritten after convergence is drift, not a foreign apex.
///
/// Both refusal arms of `diff_gated` return before `create` is computed, so a
/// reconciler that has lost its marker cannot re-assert one. Whoever holds
/// the provider API token — the party the ownership rule exists to defend
/// against — overwrites `_synchronicity-owner.<apex>` with one write, and
/// every pass afterwards refuses: no create, no replace, and above all no
/// delete, so a revocation committed in the product never reaches the wire.
///
/// The guard's real subject is a *first* sync against an apex somebody else
/// is using, and that case is asserted below to still refuse.
pub fn a_marker_changed_after_convergence_is_repaired_test() {
  let conn = external_conn()
  let calls = process.new_subject()
  let _owner = Existing("m", diff.owner_record("sync.test"))

  // Converge, so the deployment has an applied set for this provider+zone.
  provider_sync.run_once_with(
    conn,
    fake_provider([], calls),
    "log-only",
    "z1",
    2000,
  )
  let assert Ok("list") = process.receive(calls, 100)
  let assert Ok("apply " <> _) = process.receive(calls, 100)
  let assert Ok(Ok(before)) = state.get(conn)
  assert before.last_error == None

  // The token holder rewrites the marker's value and plants a record.
  let hijacked =
    Existing(
      "m",
      Record(
        "_synchronicity-owner.sync.test",
        provider.Txt,
        300,
        "heritage=someone-else",
      ),
    )
  let forged =
    Existing(
      "f",
      Record(
        "_synchronicity.prod.acme.sync.test",
        provider.Txt,
        300,
        "v=sync1 id=evil nk=" <> fixtures.nk() <> " apex=sync.test",
      ),
    )
  provider_sync.run_once_with(
    conn,
    fake_provider([hijacked, forged], calls),
    "log-only",
    "z1",
    2000 + 901,
  )
  let assert Ok("list") = process.receive(calls, 100)
  // The pass proceeds: the marker is re-created and the forgery deleted.
  let assert Ok("apply " <> applied) = process.receive(calls, 100)
  assert string.ends_with(applied, "/2")
  let assert Ok(Ok(after)) = state.get(conn)
  assert after.last_error == None
  sqlite.close(conn)

  // And a deployment that has never applied anything still refuses, which is
  // the case the rule was written for.
  let fresh = external_conn()
  provider_sync.run_once_with(
    fresh,
    fake_provider([hijacked], calls),
    "log-only",
    "z1",
    2000,
  )
  let assert Ok("list") = process.receive(calls, 100)
  let assert Error(Nil) = process.receive(calls, 100)
  let assert Ok(Ok(refused)) = state.get(fresh)
  let assert Some(reason) = refused.last_error
  assert string_contains(reason, "conflict")
  sqlite.close(fresh)
}

/// A device edited while the gate is armed keeps its published record.
///
/// Byte equality alone shields only what did not change, so the gate turned a
/// replace into a delete: the old record removed, the new one withheld, and
/// the device out of the zone entirely until the gate disarmed. The trigger is
/// an ordinary dashboard edit, with the gate armed by somebody else's routine
/// key rotation.
pub fn a_device_edited_while_the_gate_is_armed_keeps_its_record_test() {
  let nk = fixtures.nk()
  let owner = "_synchronicity.prod.acme.sync.test"
  let published =
    Existing(
      "d1",
      Record(
        owner,
        provider.Txt,
        300,
        "v=sync1 id=nas nk=" <> nk <> " apex=sync.test",
      ),
    )
  let marker = Existing("m", diff.owner_record("sync.test"))
  // The gate is armed, so the desired set carries no membership at all; the
  // ungated render — the withheld set — carries the *edited* record.
  let gated = [diff.owner_record("sync.test")]
  let edited =
    Record(
      owner,
      provider.Txt,
      300,
      "v=sync1 id=nas nk="
        <> nk
        <> " relay=https://relay.example apex=sync.test",
    )
  let assert Ok(changes) =
    diff.diff_gated(gated, [marker, published], [edited], adopted: True)
  assert changes.delete == []

  // A revoked device is still deleted: nothing in the withheld set names it.
  let assert Ok(revoked) =
    diff.diff_gated(gated, [marker, published], [], adopted: True)
  assert list.map(revoked.delete, fn(e) { e.record.value })
    == [published.record.value]

  // And a forgery that copies the label and key to change the hints does not
  // ride in on the fallback: it doubles the identity, so neither record is
  // shielded by it and the forgery is deleted, while the genuine one stays
  // shielded by value.
  let forgery =
    Existing(
      "f",
      Record(
        owner,
        provider.Txt,
        300,
        "v=sync1 id=nas nk=" <> nk <> " addr=198.51.100.9:9999 apex=sync.test",
      ),
    )
  let assert Ok(both) =
    diff.diff_gated(
      gated,
      [marker, published, forgery],
      [published.record],
      adopted: True,
    )
  assert list.map(both.delete, fn(e) { e.id }) == ["f"]
}
