import dns/name
import dns/rdata
import dns/wire
import dnssec/keys
import dnssec/sign
import fixtures
import gleam/bit_array
import gleam/list
import gleam/result
import store/sqlite
import zone/build
import zone/model
import zone/publish

/// Enough owners to cross several insertion batches, with multiple members
/// and a rotating device at every owner.
fn fleet() -> #(sqlite.Connection, keys.Csk) {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(_) =
    sqlite.script(
      conn,
      "INSERT INTO users VALUES ('u1', 'a@example.test', NULL, 0);
       INSERT INTO orgs VALUES ('o1', 'acme', 'Acme', 0);
       INSERT INTO devices VALUES ('d1', 'o1', 'nas', NULL, NULL, 'u1', 0);
       INSERT INTO devices VALUES ('d2', 'o1', 'laptop', NULL, NULL, 'u1', 0);
       WITH RECURSIVE n(i) AS
         (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 128)
       INSERT INTO networks (id, org_id, name, created_at)
         SELECT 'n-' || i, 'o1', 'network-' || i, 0 FROM n;
       INSERT INTO network_devices SELECT id, 'd1', 0 FROM networks;
       INSERT INTO network_devices SELECT id, 'd2', 0 FROM networks;",
    )
  fixtures.add_key(conn, "k1", "d1", "active", 1)
  fixtures.add_key(conn, "k2", "d2", "active", 2)
  fixtures.add_key(conn, "k3", "d2", "retiring", 3)
  #(conn, csk)
}

pub fn fleet_publication_preserves_members_nsec_and_signatures_test() {
  let #(conn, csk) = fleet()
  let assert Ok(1) = publish.publish(conn, csk, 1000, "test")
  let assert Ok(input) = model.read(conn)
  assert list.length(input.txt_names) == 128
  let assert Ok(expected_members) =
    sqlite.query(
      conn,
      "SELECT d.label, k.nk_z32 FROM devices d
       JOIN device_keys k ON k.device_id = d.id ORDER BY d.label, k.added_at",
      [],
    )
  list.each(input.txt_names, fn(txt) {
    assert list.map(txt.members, fn(m) {
        [sqlite.Text(m.label), sqlite.Text(m.nk_z32)]
      })
      == expected_members
  })
  let owners = list.map(input.txt_names, fn(txt) { txt.owner })
  assert owners == list.sort(owners, name.compare)

  let assert Ok(rrsets) = build.build(input)
  let chain =
    rrsets
    |> list.filter(fn(r) { r.rtype == wire.type_nsec })
    |> build.sort_rrsets
  let chain_owners = list.map(chain, fn(r) { r.owner })
  let assert [first, ..rest] = chain_owners
  list.each(list.zip(chain, list.append(rest, [first])), fn(pair) {
    let #(rr, next) = pair
    let assert [rd] = rr.rdatas
    let assert Ok(#(decoded_next, offset)) = wire.decode_name(rd, 0, 0)
    assert decoded_next == next
    let assert Ok(bitmap) =
      bit_array.slice(rd, offset, bit_array.byte_size(rd) - offset)
    // Independent wire expectations: NS/SOA/DNSKEY at the apex, A at
    // the nameserver, TXT elsewhere; every owner also has RRSIG/NSEC.
    let expected = case rr.owner {
      ["sync", "test"] -> <<0, 7, 0x22, 0, 0, 0, 0, 3, 0x80>>
      ["ns1", "sync", "test"] -> <<0, 6, 0x40, 0, 0, 0, 0, 3>>
      _ -> <<0, 6, 0, 0, 0x80, 0, 0, 3>>
    }
    assert bitmap == expected
  })

  let assert Ok([[sqlite.Int(count)]]) =
    sqlite.query(conn, "SELECT count(*) FROM presigned_rrsets", [])
  assert count == list.length(rrsets)
  list.each(rrsets, fn(rr) {
    let assert Ok([[sqlite.Blob(data), sqlite.Blob(sig)]]) =
      sqlite.query(
        conn,
        "SELECT rrset_wire, rrsig_wire FROM presigned_rrsets
         WHERE name = ? AND rtype = ? AND soa_serial = 1
           AND signed_at = 1000 AND sig_expires_at = ?",
        [
          sqlite.Text(name.to_string(rr.owner)),
          sqlite.Int(rr.rtype),
          sqlite.Int(1000 + input.meta.sig_validity),
        ],
      )
    assert data
      == rr.rdatas
      |> list.sort(bit_array.compare)
      |> list.map(fn(rd) { rdata.rr(rr.owner, rr.rtype, rr.ttl, rd) })
      |> bit_array.concat
    let assert Ok(signature) =
      bit_array.slice(sig, bit_array.byte_size(sig) - 64, 64)
    assert sign.verify_rrset(
      csk,
      input.meta.key_tag,
      input.meta.apex,
      rr.owner,
      rr.rtype,
      rr.ttl,
      rr.rdatas,
      1000 - input.meta.sig_inception_skew,
      1000 + input.meta.sig_validity,
      signature,
    )
  })
  sqlite.close(conn)
}

pub fn failed_later_batch_rolls_back_zone_and_product_mutation_test() {
  let #(conn, csk) = fleet()
  let assert Ok(1) = publish.publish(conn, csk, 1000, "test")
  let snapshot = "SELECT * FROM presigned_rrsets ORDER BY name, rtype"
  let assert Ok(before) = sqlite.query(conn, snapshot, [])
  // ns1 sorts after all 128 networks. Fail only after earlier batches have
  // inserted their rows, so this exercises rollback of the whole emission.
  let assert Ok(_) =
    sqlite.script(
      conn,
      "CREATE TRIGGER reject_late_rrset BEFORE INSERT ON presigned_rrsets
       WHEN NEW.name = 'ns1.sync.test.'
         AND (SELECT count(*) FROM presigned_rrsets) > 64
       BEGIN SELECT RAISE(ABORT, 'late batch rejected'); END;",
    )
  let attempt =
    sqlite.transaction(conn, publish.Db, fn() {
      use _ <- result.try(
        sqlite.exec(
          conn,
          "UPDATE devices SET label = 'renamed' WHERE id = 'd1'",
          [],
        )
        |> result.map_error(publish.Db),
      )
      publish.publish_in_tx(conn, csk, 2000, "test", publish.Widening)
    })
  let assert Error(publish.Db(sqlite.Sqlite(_, "late batch rejected"))) =
    attempt
  assert sqlite.query(conn, snapshot, []) == Ok(before)
  assert sqlite.query(conn, "SELECT soa_serial FROM zone_meta", [])
    == Ok([[sqlite.Int(1)]])
  assert sqlite.query(conn, "SELECT label FROM devices WHERE id = 'd1'", [])
    == Ok([[sqlite.Text("nas")]])
  sqlite.close(conn)
}
