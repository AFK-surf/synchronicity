import gleam/string
import store/db
import store/migrate
import store/sqlite.{Blob, Done, Float, Int, Null, Rows, Text}

@external(erlang, "test_ffi", "tmp_db")
fn tmp_db() -> String

@external(erlang, "test_ffi", "kill9")
fn kill9(os_pid: Int) -> Nil

pub fn value_round_trip_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Ok(_) = sqlite.script(conn, "CREATE TABLE t(a,b,c,d,e);")
  let assert Ok(Done(1, 1)) =
    sqlite.exec(conn, "INSERT INTO t VALUES (?,?,?,?,?)", [
      Int(-42),
      Float(3.5),
      Text("héllo ✓"),
      Blob(<<0, 255, 7>>),
      Null,
    ])
  let assert Ok(Rows(["a", "b", "c", "d", "e"], [row])) =
    sqlite.exec(conn, "SELECT a, b, c, d, e FROM t", [])
  assert row
    == [Int(-42), Float(3.5), Text("héllo ✓"), Blob(<<0, 255, 7>>), Null]
  sqlite.close(conn)
}

pub fn large_int_and_empty_blob_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let big = 4_611_686_018_427_387_904
  let assert Ok([[Int(got)]]) = sqlite.query(conn, "SELECT ?", [Int(big)])
  assert got == big
  let assert Ok([[Int(neg)]]) = sqlite.query(conn, "SELECT ?", [Int(-1)])
  assert neg == -1
  let assert Ok([[Blob(<<>>)]]) = sqlite.query(conn, "SELECT ?", [Blob(<<>>)])
  sqlite.close(conn)
}

pub fn sql_error_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Error(sqlite.Sqlite(_, message)) =
    sqlite.exec(conn, "SELECT * FROM missing", [])
  assert string.contains(message, "missing")
  sqlite.close(conn)
}

pub fn multi_statement_exec_rejected_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Error(sqlite.Sqlite(_, message)) =
    sqlite.exec(conn, "SELECT 1; SELECT 2", [])
  assert string.contains(message, "single statement")
  sqlite.close(conn)
}

pub fn param_count_mismatch_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Error(sqlite.Sqlite(_, message)) =
    sqlite.exec(conn, "SELECT ?, ?", [Int(1)])
  assert string.contains(message, "mismatch")
  sqlite.close(conn)
}

pub fn transaction_rollback_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Ok(_) = sqlite.script(conn, "CREATE TABLE t(a);")
  let assert Ok(_) = sqlite.exec(conn, "BEGIN IMMEDIATE", [])
  let assert Ok(_) = sqlite.exec(conn, "INSERT INTO t VALUES (1)", [])
  let assert Ok(_) = sqlite.exec(conn, "ROLLBACK", [])
  let assert Ok([[Int(0)]]) = sqlite.query(conn, "SELECT count(*) FROM t", [])
  sqlite.close(conn)
}

pub fn read_only_rejects_writes_test() {
  let path = tmp_db()
  let assert Ok(writer) = db.open_primary(path)
  let assert Ok(_) = sqlite.script(writer, "CREATE TABLE t(a);")
  sqlite.close(writer)
  let assert Ok(reader) = db.open_read(path)
  let assert Error(sqlite.Sqlite(_, _)) =
    sqlite.exec(reader, "INSERT INTO t VALUES (1)", [])
  sqlite.close(reader)
}

pub fn crash_isolation_test() {
  let path = tmp_db()
  let assert Ok(conn) = db.open_primary(path)
  let os_pid = sqlite.os_pid(conn)
  assert os_pid > 0
  kill9(os_pid)
  // The port process is gone; the connection reports it and nothing else
  // in the VM is harmed — a fresh connection works immediately.
  let assert Error(sqlite.ConnectionClosed) = sqlite.exec(conn, "SELECT 1", [])
  let assert Ok(conn2) = db.open_primary(path)
  let assert Ok([[Int(1)]]) = sqlite.query(conn2, "SELECT 1", [])
  sqlite.close(conn2)
}

pub fn migrate_fresh_and_idempotent_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let target = migrate.build_version()
  let assert Ok(v) = migrate.migrate(conn)
  assert v == target
  let assert Ok(current) = migrate.current_version(conn)
  assert current == target
  let assert Ok(again) = migrate.migrate(conn)
  assert again == target
  sqlite.close(conn)
}

pub fn migrate_refuses_newer_db_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Ok(_) = sqlite.script(conn, "PRAGMA user_version = 99")
  let assert Error(migrate.DbNewerThanBuild(99, _)) = migrate.migrate(conn)
  sqlite.close(conn)
}

fn seeded_conn() -> sqlite.Connection {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Ok(_) = migrate.migrate(conn)
  let assert Ok(_) =
    sqlite.script(
      conn,
      "INSERT INTO users VALUES ('u1', 'a@example.com', NULL, 0);
       INSERT INTO orgs VALUES ('o1', 'acme', 'Acme', 0);
       INSERT INTO devices VALUES ('d1', 'o1', 'nas', NULL, NULL, 'u1', 0);
       INSERT INTO devices VALUES ('d2', 'o1', 'nas', NULL, NULL, 'u1', 0);
       INSERT INTO networks VALUES ('n1', 'o1', 'prod', 0);",
    )
  conn
}

pub fn ambiguity_unrepresentable_test() {
  let conn = seeded_conn()
  let nk = <<1:size(256)>>
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO device_keys VALUES ('k1', 'd1', 'z32', ?, 'active', 0, NULL)",
      [Blob(nk)],
    )
  // The same live nk on a second device is the §3.2 ambiguity — refused by
  // the partial unique index, so an ambiguous zone can never exist.
  let assert Error(sqlite.Sqlite(_, message)) =
    sqlite.exec(
      conn,
      "INSERT INTO device_keys VALUES ('k2', 'd2', 'z32', ?, 'active', 0, NULL)",
      [Blob(nk)],
    )
  assert string.contains(message, "device_keys")
  // Revoking frees the nk for a legitimate fresh binding.
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "UPDATE device_keys SET state='revoked' WHERE id='k1'",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO device_keys VALUES ('k2', 'd2', 'z32', ?, 'active', 0, NULL)",
      [Blob(nk)],
    )
  sqlite.close(conn)
}

pub fn duplicate_label_per_network_rejected_test() {
  let conn = seeded_conn()
  let assert Ok(_) =
    sqlite.exec(conn, "INSERT INTO network_devices VALUES ('n1', 'd1', 0)", [])
  // d2 shares the label 'nas'; the trigger refuses the assignment.
  let assert Error(sqlite.Sqlite(_, message)) =
    sqlite.exec(conn, "INSERT INTO network_devices VALUES ('n1', 'd2', 0)", [])
  assert string.contains(message, "label already used")
  sqlite.close(conn)
}
