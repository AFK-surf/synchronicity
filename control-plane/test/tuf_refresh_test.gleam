//// The TUF refresh job (docs/REKOR-ZONE-KEY.md §10.3): a fresh control
//// plane fetches on its first tick, a steady one fetches only when the
//// stored timestamp nears expiry, and no fetch ever touches the zone. The
//// chain itself is verified in `tuf/verify` and walked in tuf_test; here
//// the question is when the job asks for it and what it leaves alone.

import fixtures
import jobs/tuf_refresh
import store/db
import store/migrate
import store/sqlite
import tuf/fetch
import tuf/store as tuf_store
import tuf_test
import zone/publish

pub fn the_first_tick_fetches_and_the_zone_does_not_move_test() {
  let path = fixtures.tmp_db()
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)
  let csk = fixtures.zone_boot(conn)
  let assert Ok(1) = publish.publish(conn, csk, fixtures.now_unix(), "test")

  // Nothing stored, so the boot tick is a fetch. Nothing in the zone
  // depends on TUF material — it names the log shard this service submits
  // to and nothing else — so storing a whole new chain must leave the
  // serial exactly where it was.
  tuf_refresh.run_once_at(path, tuf_test.fake_repo(), tuf_test.verify_at())
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(conn, "SELECT count(*) FROM tuf_material", [])
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(conn, "SELECT soa_serial FROM zone_meta", [])
  sqlite.close(conn)
}

pub fn a_pass_that_is_not_due_consults_no_repository_test() {
  let path = fixtures.tmp_db()
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)

  // Store the fixture chain once, at the moment it verifies.
  tuf_refresh.run_once_at(path, tuf_test.fake_repo(), tuf_test.verify_at())
  let assert Ok(Ok(stored)) = tuf_store.get(conn)
  assert stored.fetched_at == tuf_test.verify_at()

  // Fresh material: the hourly pass does not even ask the repository — a
  // repository that can only fail proves it was not consulted, and
  // `fetched_at` staying put proves nothing was stored either.
  let unusable = fetch.Repo(get: fn(_) { Error("must not be consulted") })
  let fresh_at = stored.timestamp_expires - fetch.refetch_window - 1
  tuf_refresh.run_once_at(path, unusable, fresh_at)
  let assert Ok(Ok(kept)) = tuf_store.get(conn)
  assert kept.fetched_at == tuf_test.verify_at()

  // Inside the refetch window the same pass fetches and stores again.
  let due_at = stored.timestamp_expires - fetch.refetch_window
  tuf_refresh.run_once_at(path, tuf_test.fake_repo(), due_at)
  let assert Ok(Ok(again)) = tuf_store.get(conn)
  assert again.fetched_at == due_at
  sqlite.close(conn)
}

pub fn a_failed_fetch_keeps_what_was_stored_test() {
  let path = fixtures.tmp_db()
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)

  tuf_refresh.run_once_at(path, tuf_test.fake_repo(), tuf_test.verify_at())
  let assert Ok(Ok(stored)) = tuf_store.get(conn)

  // Due, but the repository is gone: the failure is a log line, and the
  // material that named a shard yesterday still names it (§10.2).
  let down = fetch.Repo(get: fn(_) { Error("no route to host") })
  tuf_refresh.run_once_at(path, down, stored.timestamp_expires)
  let assert Ok(Ok(kept)) = tuf_store.get(conn)
  assert kept == stored
  sqlite.close(conn)
}
