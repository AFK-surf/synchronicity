import fixtures.{tmp_db}
import gleam/bit_array
import gleam/string
import store/db
import store/migrate
import store/sqlite.{Blob, Done, Float, Int, Null, Rows, Text}

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
       INSERT INTO networks (id, org_id, name, created_at)
         VALUES ('n1', 'o1', 'prod', 0);",
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

pub fn empty_path_refused_test() {
  // Fail-open guard: "" would open an anonymous temp DB and discard
  // every write on exit. Refused on both sides of the protocol.
  let assert Error(sqlite.Sqlite(_, message)) =
    sqlite.open("", sqlite.ReadWriteCreate)
  assert string.contains(message, "empty database path")
}

pub fn embedded_nul_sql_refused_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Ok(nul) = bit_array.to_string(<<0>>)
  let assert Error(sqlite.Sqlite(_, message)) =
    sqlite.exec(conn, "SELECT 1; " <> nul <> "DROP TABLE x", [])
  assert string.contains(message, "NUL")
  sqlite.close(conn)
}

pub fn hostile_schema_defenses_active_test() {
  // TRUSTED_SCHEMA off and DEFENSIVE on: writable_schema is refused, so
  // a hostile replicated file cannot rewrite its own schema through us.
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Ok(_) = sqlite.script(conn, "CREATE TABLE t(a);")
  let assert Ok(_) = sqlite.exec(conn, "PRAGMA writable_schema=ON", [])
  let assert Error(sqlite.Sqlite(_, _)) =
    sqlite.exec(
      conn,
      "UPDATE sqlite_schema SET sql='CREATE TABLE t(evil)' WHERE name='t'",
      [],
    )
  sqlite.close(conn)
}

pub fn oversized_value_refused_test() {
  // SQLITE_LIMIT_LENGTH is capped at 16 MiB: a value that would balloon
  // the response comes back as a clean error, not a giant frame.
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Error(sqlite.Sqlite(_, _)) =
    sqlite.query(conn, "SELECT zeroblob(32*1024*1024)", [])
  sqlite.close(conn)
}

/// An existing database gains the rollover staging columns without losing
/// its zone.
///
/// Every other migration test starts from an empty file, which exercises
/// the v6 `ALTER TABLE` against a table one statement old. The case that
/// matters is the deployed one: a zone_meta row with a real key and serial
/// in it, written before these columns existed. It must come back
/// unchanged, with an empty staging slot meaning "no rollover in flight".
pub fn migrate_adds_the_rollover_slot_to_an_existing_zone_test() {
  let path = tmp_db()
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)

  // A zone as a pre-v6 build would have left it: named columns, so this
  // insert says nothing about the columns v6 adds.
  let key = <<7:size(512)>>
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO zone_meta
         (id, base_domain, soa_serial, dnskey_public, key_tag,
          sig_inception_skew, sig_validity, sig_refresh_before)
       VALUES (1, 'sync.test', 42, ?, 4242, 3600, 1209600, 604800)",
      [sqlite.Blob(key)],
    )
  // Rewind to before the staging columns and re-run the migration, which
  // is what an upgrade of a running deployment does.
  let assert Ok(_) = sqlite.script(conn, "PRAGMA user_version = 5")
  let assert Ok(_) =
    sqlite.exec(conn, "ALTER TABLE zone_meta DROP COLUMN dnskey_incoming", [])
  let assert Ok(_) =
    sqlite.exec(conn, "ALTER TABLE zone_meta DROP COLUMN key_tag_incoming", [])
  // Everything the rewind skipped past has to come off too, or the re-run
  // re-adds a column that is already there.
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "ALTER TABLE provider_sync_state DROP COLUMN last_failures",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "ALTER TABLE provider_sync_state DROP COLUMN last_partial_at",
      [],
    )
  let assert Ok(_) =
    sqlite.exec(conn, "ALTER TABLE networks DROP COLUMN browse_enabled", [])
  let assert Ok(_) = sqlite.exec(conn, "DROP TABLE api_keys", [])
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "ALTER TABLE oauth_states DROP COLUMN binding_token_hash",
      [],
    )
  let assert Ok(_) = sqlite.exec(conn, "DROP INDEX networks_cloud_hosted", [])
  let assert Ok(_) =
    sqlite.exec(conn, "ALTER TABLE networks DROP COLUMN cloud_hosted", [])
  let assert Ok(_) = sqlite.exec(conn, "DROP TABLE cloud_collect_queue", [])
  let assert Ok(_) = sqlite.exec(conn, "DROP TABLE dataplane_keys", [])
  let assert Ok(_) = sqlite.exec(conn, "DROP TABLE network_hosting_status", [])
  // The system user v12 inserts comes off too: re-running the insert over a
  // row that is already there is a primary-key violation, which is the same
  // shape of problem as re-adding a column.
  let assert Ok(_) =
    sqlite.exec(conn, "DELETE FROM users WHERE id = 'system-dataplane'", [])
  let assert Ok(v) = migrate.migrate(conn)
  assert v == migrate.build_version()

  let assert Ok([
    [
      Int(serial),
      sqlite.Blob(stored),
      Int(tag),
      sqlite.Blob(incoming),
      Int(incoming_tag),
    ],
  ]) =
    sqlite.query(
      conn,
      "SELECT soa_serial, dnskey_public, key_tag,
              dnskey_incoming, key_tag_incoming
         FROM zone_meta WHERE id = 1",
      [],
    )
  assert serial == 42
  assert stored == key
  assert tag == 4242
  // No rollover in flight, which is every zone until somebody starts one.
  assert incoming == <<>>
  assert incoming_tag == 0
  sqlite.close(conn)
}

/// The staging slot's length constraint survives `ALTER TABLE`.
///
/// SQLite restricts what `ADD COLUMN` may carry, and a constraint that is
/// quietly not applied is worse than none: `dnskey_incoming` would accept a
/// truncated key, `zone/build` would publish it as a DNSKEY, and the zone
/// would serve a key nothing can validate. Checked rather than assumed.
pub fn the_staging_slot_refuses_a_key_of_the_wrong_length_test() {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Ok(_) = migrate.migrate(conn)
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO zone_meta
         (id, base_domain, soa_serial, dnskey_public, key_tag,
          sig_inception_skew, sig_validity, sig_refresh_before)
       VALUES (1, 'sync.test', 1, ?, 1, 3600, 1209600, 604800)",
      [sqlite.Blob(<<7:size(512)>>)],
    )
  // A P-256 public key is 64 bytes; empty means no rollover in flight.
  let assert Ok(_) =
    sqlite.exec(conn, "UPDATE zone_meta SET dnskey_incoming = ?", [
      sqlite.Blob(<<9:size(512)>>),
    ])
  let assert Ok(_) =
    sqlite.exec(conn, "UPDATE zone_meta SET dnskey_incoming = ?", [
      sqlite.Blob(<<>>),
    ])
  // Anything else is refused by the database itself.
  let assert Error(_) =
    sqlite.exec(conn, "UPDATE zone_meta SET dnskey_incoming = ?", [
      sqlite.Blob(<<1, 2, 3, 4, 5>>),
    ])
  sqlite.close(conn)
}
