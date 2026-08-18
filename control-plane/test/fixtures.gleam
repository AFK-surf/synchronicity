//// Shared test fixtures: temp databases, fresh device keys, and the one
//// canonical demo zone (org acme, network prod, device nas with one key,
//// device laptop mid-rotation) that zone, API and DNS tests all read.
//// One copy here, so the demo shape cannot drift between suites.

import dns/name.{type Name}
import dnssec/keys.{type Csk}
import envoy
import exception
import rekor/gate
import store/db
import store/migrate
import store/sqlite.{type Connection}
import thirtytwo
import zone/publish

/// Runs `body` with the publish gate armed, and disarms it afterwards —
/// including when the body fails, because the setting is process-wide and one
/// broken assertion would otherwise arm the gate under every test that happens
/// to run after it.
pub fn with_gate_armed(body: fn() -> a) -> a {
  gate_armed()
  use <- exception.defer(fn() { gate_disarmed() })
  body()
}

pub fn gate_armed() -> Nil {
  envoy.set(gate.require_env, "true")
}

pub fn gate_disarmed() -> Nil {
  envoy.unset(gate.require_env)
}

/// A unique temp database path (also usable as a generic temp file base).
@external(erlang, "test_ffi", "tmp_db")
pub fn tmp_db() -> String

@external(erlang, "cp_sys_ffi", "now_unix")
pub fn now_unix() -> Int

@external(erlang, "cp_crypto_ffi", "ed25519_generate_public")
fn ed25519_generate_public() -> BitArray

/// A fresh z-base-32 device key.
pub fn nk() -> String {
  thirtytwo.z_base_32_encode(ed25519_generate_public())
}

/// A migrated read-write connection on a fresh temp database.
pub fn fresh_conn() -> Connection {
  let assert Ok(conn) = db.open_primary(tmp_db())
  let assert Ok(_) = migrate.migrate(conn)
  conn
}

/// Creates and migrates a database at `path`, then closes it — for tests
/// that reopen through a pool.
pub fn ready_db(path: String) -> Nil {
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)
  sqlite.close(conn)
}

/// Bootstraps the `sync.test` zone identity on a migrated connection:
/// zone_meta, one NS host, a fresh CSK. Nothing is published yet.
pub fn zone_boot(conn: Connection) -> Csk {
  let csk = keys.generate()
  let assert Ok(Nil) = publish.ensure_meta(conn, "sync.test", csk)
  let assert Ok(Nil) = publish.set_ns_hosts(conn, [#("ns1", "127.0.0.1", "")])
  csk
}

/// A published demo zone in a fresh database: org acme, network prod,
/// device nas (one key) and laptop (rotation window, two keys). Answer
/// tests read it exactly the way the servers do.
pub fn demo_conn() -> #(Connection, Name) {
  let conn = fresh_conn()
  let csk = zone_boot(conn)
  let assert Ok(_) =
    sqlite.script(
      conn,
      "INSERT INTO users VALUES ('u1', 'a@example.com', NULL, 0);
       INSERT INTO orgs VALUES ('o1', 'acme', 'Acme', 0);
       INSERT INTO networks (id, org_id, name, created_at)
         VALUES ('n1', 'o1', 'prod', 0);
       INSERT INTO devices VALUES ('d1', 'o1', 'nas', NULL, NULL, 'u1', 0);
       INSERT INTO devices VALUES ('d2', 'o1', 'laptop', NULL, NULL, 'u1', 0);
       INSERT INTO network_devices VALUES ('n1', 'd1', 0);
       INSERT INTO network_devices VALUES ('n1', 'd2', 0);",
    )
  add_key(conn, "k1", "d1", "active", 1)
  add_key(conn, "k2", "d2", "active", 2)
  add_key(conn, "k3", "d2", "retiring", 3)
  let assert Ok(_) = publish.publish(conn, csk, 1000, "test")
  let assert Ok(apex) = name.parse("sync.test.")
  #(conn, apex)
}

/// Inserts one device key row with a fresh random key.
pub fn add_key(
  conn: Connection,
  id: String,
  device: String,
  state: String,
  at: Int,
) -> Nil {
  let key = nk()
  let assert Ok(bytes) = thirtytwo.z_base_32_decode(key)
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "INSERT INTO device_keys VALUES (?, ?, ?, ?, ?, ?, NULL)",
      [
        sqlite.Text(id),
        sqlite.Text(device),
        sqlite.Text(key),
        sqlite.Blob(bytes),
        sqlite.Text(state),
        sqlite.Int(at),
      ],
    )
  Nil
}
