import dns/name as dns_name
import dns/serve
import dns/server_udp
import fixtures.{ready_db, tmp_db}
import gleam/bit_array
import gleam/erlang/process
import gleam/otp/static_supervisor as sup
import store/db
import store/migrate
import store/pool
import store/sqlite
import zone/publish

@external(erlang, "test_ffi", "udp_roundtrip")
fn udp_roundtrip(port: Int, packet: BitArray) -> Result(BitArray, Nil)

pub fn pool_restarts_under_supervision_test() {
  let path = tmp_db()
  ready_db(path)
  let pool_name = process.new_name("t_sup_pool")
  let assert Ok(_) =
    sup.new(sup.OneForOne)
    |> sup.restart_tolerance(intensity: 10, period: 5)
    |> sup.add(pool.supervised(
      pool_name,
      path,
      sqlite.ReadWrite,
      db.primary_pragmas,
      2,
    ))
    |> sup.start
  let p = pool.handle(pool_name, db.primary_pragmas)
  let assert Ok(Ok(_)) =
    pool.with_connection(p, fn(conn) { sqlite.query(conn, "SELECT 1", []) })
  // Kill the dispatcher; the supervisor restarts it under the same name,
  // and the same handle keeps working.
  let assert Ok(pid) = process.named(pool_name)
  process.kill(pid)
  process.sleep(300)
  let assert Ok(Ok(_)) =
    pool.with_connection(p, fn(conn) { sqlite.query(conn, "SELECT 1", []) })
}

pub fn udp_server_rebinds_after_crash_test() {
  // A published (empty) zone so answers are real.
  let path = tmp_db()
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)
  let csk = fixtures.zone_boot(conn)
  let assert Ok(_) = publish.publish(conn, csk, 1000, "test")
  sqlite.close(conn)
  let assert Ok(read_pool) = db.start_read_pool(path, 1)
  let assert Ok(apex) = dns_name.parse("sync.test.")
  let serving = serve.Serving(read_pool, apex)
  let udp_name = process.new_name("t_sup_udp")
  let port = 55_953
  let assert Ok(_) =
    sup.new(sup.OneForOne)
    |> sup.restart_tolerance(intensity: 10, period: 5)
    |> sup.add(server_udp.supervised(udp_name, "127.0.0.1", port, serving))
    |> sup.start
  let question = <<
    7:int-size(16),
    0:int-size(16),
    1:int-size(16),
    0:int-size(48),
    dns_name.encode(apex):bits,
    6:int-size(16),
    1:int-size(16),
  >>
  let assert Ok(first) = udp_roundtrip(port, question)
  assert bit_array.byte_size(first) > 12
  // Kill the server; the supervisor rebinds the socket and answers again.
  let assert Ok(pid) = process.named(udp_name)
  process.kill(pid)
  process.sleep(300)
  let assert Ok(second) = udp_roundtrip(port, question)
  assert bit_array.byte_size(second) > 12
}
