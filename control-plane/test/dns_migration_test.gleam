import dnssec/keys
import fixtures
import gleam/list
import store/sqlite
import zone/model
import zone/publish

fn external_db() -> sqlite.Connection {
  // A populated membership database, converted to the same metadata shape
  // as an external deployment, retaining device rotation state.
  let #(conn, _) = fixtures.demo_conn()
  let assert Ok(_) =
    sqlite.exec(
      conn,
      "UPDATE zone_meta SET dnskey_public = X'', key_tag = 0",
      [],
    )
  let assert Ok(_) = sqlite.exec(conn, "DELETE FROM presigned_rrsets", [])
  let assert Ok(_) = sqlite.exec(conn, "DELETE FROM zone_ns", [])
  conn
}

pub fn adoption_preserves_membership_and_publishes_under_new_key_test() {
  let conn = external_db()
  let assert Ok(before) = model.read(conn)
  let csk = keys.generate()
  let assert Error(_) = publish.ensure_meta(conn, "sync.test", csk)
  let assert Ok(serial) =
    publish.adopt_serve(
      conn,
      "sync.test",
      csk,
      [#("ns1", "192.0.2.1", "")],
      2000,
    )
  let assert Ok(after) = model.read(conn)
  assert after.txt_names == before.txt_names
  assert serial == before.meta.soa_serial + 1
  assert after.meta.dnskey_public == csk.public
  let assert Ok(Nil) = publish.ensure_meta(conn, "sync.test", csk)
  let assert Error(_) = publish.ensure_meta_external(conn, "sync.test")
  let assert Ok(rows) =
    sqlite.query(
      conn,
      "SELECT rrset_wire, rrsig_wire FROM presigned_rrsets WHERE rtype = 48",
      [],
    )
  assert list.length(rows) == 1
  let assert Error(_) =
    publish.adopt_serve(
      conn,
      "sync.test",
      csk,
      [#("ns1", "192.0.2.1", "")],
      2001,
    )
  fixtures.with_gate_armed(fn() {
    let assert Error(publish.NoRekorRecord(_)) =
      publish.publish(conn, csk, 2002, "test")
    let assert Ok(meta) = model.read_meta(conn)
    assert meta.soa_serial == serial
  })
  sqlite.close(conn)
}

pub fn failed_adoption_rolls_back_key_serial_and_nameservers_test() {
  let conn = external_db()
  let assert Ok(before) = model.read(conn)
  let assert Error(_) =
    publish.adopt_serve(
      conn,
      "sync.test",
      keys.generate(),
      [#("ns1", "invalid-ip", "")],
      2000,
    )
  let assert Ok(after) = model.read(conn)
  assert after == before
  let assert Ok(rows) = sqlite.query(conn, "SELECT * FROM presigned_rrsets", [])
  assert rows == []
  sqlite.close(conn)
}

pub fn adoption_rejects_wrong_apex_and_missing_nameservers_test() {
  let conn = external_db()
  let csk = keys.generate()
  let assert Error(_) =
    publish.adopt_serve(
      conn,
      "wrong.test",
      csk,
      [#("ns1", "192.0.2.1", "")],
      2000,
    )
  let assert Error(_) = publish.adopt_serve(conn, "sync.test", csk, [], 2000)
  let assert Ok(Nil) = publish.ensure_meta_external(conn, "sync.test")
  sqlite.close(conn)
}
