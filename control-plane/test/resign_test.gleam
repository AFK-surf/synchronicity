import fixtures.{now_unix, tmp_db}
import jobs/resign
import store/db
import store/migrate
import store/sqlite
import zone/publish

pub fn resign_republishes_near_expiry_test() {
  let path = tmp_db()
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)
  let csk = fixtures.zone_boot(conn)
  let assert Ok(1) = publish.publish(conn, csk, now_unix(), "test")

  // Fresh signatures: the job leaves the zone alone.
  resign.run_once(path, csk)
  let assert Ok([[sqlite.Int(1)]]) =
    sqlite.query(conn, "SELECT soa_serial FROM zone_meta", [])

  // Age the signatures to the refresh threshold: republish fires.
  let assert Ok(_) =
    sqlite.exec(conn, "UPDATE presigned_rrsets SET sig_expires_at = ?", [
      sqlite.Int(now_unix() + 3600),
    ])
  resign.run_once(path, csk)
  let assert Ok([[sqlite.Int(2)]]) =
    sqlite.query(conn, "SELECT soa_serial FROM zone_meta", [])
  // And the new signatures are far in the future again.
  let assert Ok([[sqlite.Int(expires)]]) =
    sqlite.query(conn, "SELECT min(sig_expires_at) FROM presigned_rrsets", [])
  assert expires > now_unix() + 1_000_000
  sqlite.close(conn)
}
