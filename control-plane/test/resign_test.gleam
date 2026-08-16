import fixtures.{now_unix, tmp_db}
import gleam/option.{None}
import jobs/resign
import store/db
import store/migrate
import store/sqlite
import tuf/fetch
import tuf_test
import zone/publish

/// A repository with nothing in it. The re-sign job's TUF leg is exercised
/// in tuf_test; here it must simply not reach the network.
fn no_repo() -> fetch.Repo {
  fetch.Repo(get: fn(_path) { Ok(None) })
}

pub fn resign_republishes_near_expiry_test() {
  let path = tmp_db()
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)
  let csk = fixtures.zone_boot(conn)
  let assert Ok(1) = publish.publish(conn, csk, now_unix(), "test")

  // Fresh signatures: the job leaves the zone alone.
  resign.run_once_with(path, csk, no_repo())
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(conn, "SELECT soa_serial FROM zone_meta", [])

  // Age the signatures to the refresh threshold: republish fires.
  let assert Ok(_) =
    sqlite.exec(conn, "UPDATE presigned_rrsets SET sig_expires_at = ?", [
      sqlite.Int(now_unix() + 3600),
    ])
  resign.run_once_with(path, csk, no_repo())
  let assert Ok([[sqlite.Int(2)]]) =
    sqlite.query(conn, "SELECT soa_serial FROM zone_meta", [])
  // And the new signatures are far in the future again.
  let assert Ok([[sqlite.Int(expires)]]) =
    sqlite.query(conn, "SELECT min(sig_expires_at) FROM presigned_rrsets", [])
  assert expires > now_unix() + 1_000_000
  sqlite.close(conn)
}

pub fn a_tuf_refetch_republishes_in_the_same_tick_test() {
  let path = tmp_db()
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)
  let csk = fixtures.zone_boot(conn)
  let assert Ok(1) = publish.publish(conn, csk, now_unix(), "test")

  // The zone is presigned: stored TUF material a client can see only
  // exists after a publish. Signatures are nowhere near their refresh
  // window, so the serial moving means the refetch itself republished.
  resign.run_once_at(path, csk, tuf_test.fake_repo(), tuf_test.verify_at())
  let assert Ok([[sqlite.Int(2)]]) =
    sqlite.query(conn, "SELECT soa_serial FROM zone_meta", [])
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(
      conn,
      "SELECT count(*) FROM presigned_rrsets
       WHERE name LIKE '_synchronicity-tuf.%' AND rtype = 16",
      [],
    )

  // The next tick finds nothing new and leaves the zone alone.
  resign.run_once_at(path, csk, tuf_test.fake_repo(), tuf_test.verify_at())
  let assert Ok([[sqlite.Int(2)]]) =
    sqlite.query(conn, "SELECT soa_serial FROM zone_meta", [])
  sqlite.close(conn)
}
