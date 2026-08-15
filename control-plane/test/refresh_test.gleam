import dnssec/keys
import gleam/int
import gleam/string
import simplifile
import store/db
import store/migrate
import store/sqlite
import zone/publish
import zone/refresh
import zone/snapshot

@external(erlang, "test_ffi", "tmp_db")
fn tmp_db() -> String

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

/// The refresh contract end to end, with the external replication tool
/// simulated by copy + atomic rename: mutate the "primary" file, hand a
/// copy to the "replica" path, reload, observe the new serial. A database
/// stamped by a newer build is refused and the old snapshot keeps serving.
pub fn refresh_contract_test() {
  let primary_path = tmp_db()
  let replica_path = tmp_db()

  // Primary: zone with serial 1.
  let assert Ok(primary) = db.open_primary(primary_path)
  let assert Ok(_) = migrate.migrate(primary)
  let csk = keys.generate()
  let assert Ok(Nil) = publish.ensure_meta(primary, "sync.test", csk)
  let assert Ok(Nil) =
    publish.set_ns_hosts(primary, [#("ns1", "127.0.0.1", "")])
  let assert Ok(1) = publish.publish(primary, csk, now_unix(), "test")

  // External refresh: copy-new + atomic rename.
  hand_over(primary_path, replica_path)
  let assert Ok(1) = refresh.reload(replica_path)
  let assert Ok(snap) = snapshot.current()
  assert snap.serial == 1

  // Primary publishes serial 2; replica picks it up on the next refresh.
  let assert Ok(2) = publish.publish(primary, csk, now_unix(), "test")
  hand_over(primary_path, replica_path)
  let assert Ok(2) = refresh.reload(replica_path)
  let assert Ok(snap2) = snapshot.current()
  assert snap2.serial == 2

  // A newer-schema database is refused; the serial-2 snapshot survives.
  let assert Ok(writer) = db.open_primary(replica_path)
  let assert Ok(_) = sqlite.script(writer, "PRAGMA user_version = 99")
  sqlite.close(writer)
  let assert Error(message) = refresh.reload(replica_path)
  assert string.contains(message, "refusing")
  let assert Ok(still) = snapshot.current()
  assert still.serial == 2

  sqlite.close(primary)
}

fn hand_over(from: String, to: String) -> Nil {
  // WAL means the live -wal file may hold recent frames; checkpoint first
  // so the copied main file is complete (litestream restore yields a
  // checkpointed file too).
  let assert Ok(conn) = db.open_primary(from)
  let assert Ok(_) = sqlite.query(conn, "PRAGMA wal_checkpoint(FULL)", [])
  sqlite.close(conn)
  let staging = to <> ".new." <> int.to_string(now_unix())
  let assert Ok(Nil) = simplifile.copy_file(from, staging)
  let assert Ok(Nil) = simplifile.rename(staging, to)
  Nil
}
