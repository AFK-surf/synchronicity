//// Zone-key transparency: the statement bytes, the proof encoding, the
//// local verification, and the publish gate.
////
//// The load-bearing half of this suite is the shared fixture in
//// test/fixtures/rekor: the same bytes the Rust client's verifier is
//// asserted against (crates/synch-net/tests/rekor_zone_key.rs). Two
//// implementations of one format drift silently unless something outside
//// both of them holds the bytes still — this is that something.

import dns/name
import dns/wire
import dnssec/keys
import envoy
import fixtures
import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import rekor/client
import rekor/gate
import rekor/proof.{type Proof, Proof}
import rekor/publish as rekor_publish
import rekor/statement
import rekor/store
import simplifile
import store/sqlite
import zone/build
import zone/model.{Member, NsHost, TxtName, ZoneInput, ZoneMeta}
import zone/publish

@external(erlang, "cp_crypto_ffi", "ecdsa_sign_raw")
fn ecdsa_sign_raw(message: BitArray, private: BitArray) -> BitArray

const fixture_dir = "test/fixtures/rekor/"

fn fixture(file: String) -> BitArray {
  let assert Ok(bits) = simplifile.read_bits(fixture_dir <> file)
  bits
}

fn meta(field: String) -> String {
  let assert Ok(text) = bit_array.to_string(fixture("meta.txt"))
  let assert Ok(value) =
    text
    |> string.split("\n")
    |> list.find_map(fn(line) {
      case string.split_once(line, "=") {
        Ok(#(key, value)) if key == field -> Ok(value)
        _ -> Error(Nil)
      }
    })
  value
}

fn fixture_proof() -> Proof {
  let assert Ok(path) = proof.split_path(fixture("inclusion-path.bin"))
  let assert Ok(key_tag) = int.parse(meta("key_tag"))
  let assert Ok(log_index) = int.parse(meta("log_index"))
  Proof(
    key_tag: key_tag,
    log_id: fixture("log-id.bin"),
    log_index: log_index,
    dsse_payload: fixture("statement.json"),
    dsse_signature: fixture("dsse-signature.bin"),
    checkpoint: fixture("checkpoint.txt"),
    inclusion_path: path,
  )
}

/// The zone key the fixture is about: the DNSKEY rdata minus its four-byte
/// header is exactly the algorithm 13 public key.
fn fixture_public() -> BitArray {
  let rd = fixture("dnskey.bin")
  let assert Ok(public) = bit_array.slice(rd, 4, 64)
  public
}

pub fn statement_bytes_match_the_fixture_test() {
  let assert Ok(apex) = name.parse(meta("apex"))
  let built =
    statement.to_json(statement.for_key(
      apex,
      fixture_public(),
      meta("action"),
      None,
    ))
  // Byte-exact: the signature and the Merkle leaf both commit to these
  // bytes, so "equivalent JSON" is not equivalent.
  assert built == fixture("statement.json")
}

pub fn statement_fields_are_the_observed_key_test() {
  let assert Ok(apex) = name.parse(meta("apex"))
  let built = statement.for_key(apex, fixture_public(), "create", None)
  assert built.key_tag == keys.key_tag(fixture("dnskey.bin"))
  assert built.algorithm == 13
  assert built.flags == 257
  assert built.ds == meta("ds")
  assert built.subject_sha256
    == string.lowercase(
      bit_array.base16_encode(crypto.hash(crypto.Sha256, fixture("dnskey.bin"))),
    )
}

pub fn statement_renders_a_rollover_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let text =
    statement.to_json(statement.for_key(
      apex,
      fixture_public(),
      "rollover",
      Some(1234),
    ))
  let assert Ok(json) = bit_array.to_string(text)
  assert string.contains(json, "\"action\":\"rollover\"")
  assert string.ends_with(json, "\"replacesKeyTag\":1234}}")
}

pub fn dsse_pae_is_the_dsse_pae_test() {
  // DSSE §2: "DSSEv1 SP len(type) SP type SP len(body) SP body".
  assert statement.pae("application/example", <<"hello":utf8>>)
    == <<"DSSEv1 19 application/example 5 hello":utf8>>
}

pub fn the_fixture_signature_verifies_test() {
  assert statement.verify(
    fixture_public(),
    fixture("statement.json"),
    fixture("dsse-signature.bin"),
  )
  // One flipped bit and possession fails — the check is doing work.
  let assert Ok(<<first:int-size(8), rest:bits>>) =
    Ok(fixture("dsse-signature.bin"))
  let tampered = <<int.bitwise_exclusive_or(first, 1):int-size(8), rest:bits>>
  assert !statement.verify(
    fixture_public(),
    fixture("statement.json"),
    tampered,
  )
}

pub fn proof_encoding_matches_the_fixture_test() {
  assert proof.encode(fixture_proof()) == fixture("proof.bin")
}

pub fn proof_txt_is_base64url_test() {
  let text = proof.to_txt(fixture_proof())
  let assert Ok(decoded) = bit_array.base64_url_decode(text)
  assert decoded == fixture("proof.bin")
  assert !string.contains(text, "=")
}

pub fn the_fixture_verifies_against_its_log_test() {
  let assert Ok(text) = bit_array.to_string(fixture("log-key.pem"))
  let assert Ok(#(spki, point)) = proof.parse_log_key(text)
  assert proof.log_id(spki) == fixture("log-id.bin")
  let assert Ok(checkpoint) =
    proof.verify_against_log(fixture_proof(), spki, point)
  assert checkpoint.tree_size >= 1
}

pub fn a_proof_from_another_log_is_refused_test() {
  let assert Ok(text) = bit_array.to_string(fixture("log-key.pem"))
  let assert Ok(#(spki, point)) = proof.parse_log_key(text)
  let stranger = keys.generate()
  let stranger_spki = proof.p256_spki(stranger.public)

  // A proof that names a log we do not hold the key for.
  let assert Error(proof.UnknownLog(_)) =
    proof.verify_against_log(fixture_proof(), stranger_spki, stranger.public)

  // The right log id, the wrong signing key: the log's signature is what
  // "the log vouches" means.
  let assert Error(proof.CheckpointFailed(_)) =
    proof.verify_against_log(fixture_proof(), spki, stranger.public)

  // A tampered audit path reaches no root.
  let broken =
    Proof(..fixture_proof(), inclusion_path: [<<0:size(256)>>, <<0:size(256)>>])
  let assert Error(proof.Inclusion(_)) =
    proof.verify_against_log(broken, spki, point)
}

pub fn merkle_paths_verify_against_a_known_tree_test() {
  // Four leaves: root = H(H(a,b), H(c,d)); leaf 2's path is [d, H(a,b)].
  let leaves =
    list.map([1, 2, 3, 4], fn(i) { proof.leaf_hash(<<i:int-size(8)>>) })
  let assert [a, b, c, d] = leaves
  let ab = proof.node_hash(a, b)
  let cd = proof.node_hash(c, d)
  let root = proof.node_hash(ab, cd)
  let assert Ok(Nil) = proof.verify_inclusion(2, 4, c, [d, ab], root)
  let assert Ok(Nil) = proof.verify_inclusion(0, 4, a, [b, cd], root)
  let assert Error(_) = proof.verify_inclusion(2, 4, c, [ab, d], root)
  let assert Error(_) = proof.verify_inclusion(2, 4, c, [d], root)
  let assert Error(_) = proof.verify_inclusion(4, 4, a, [], root)
  // A one-leaf tree: the leaf is the root, with an empty path.
  let assert Ok(Nil) = proof.verify_inclusion(0, 1, a, [], a)
}

pub fn checkpoints_parse_or_are_refused_test() {
  let assert Ok(checkpoint) = proof.parse_checkpoint(fixture("checkpoint.txt"))
  assert checkpoint.origin == "rekor.sim"
  assert bit_array.byte_size(checkpoint.root_hash) == 32
  // The signed bytes stop at the blank line.
  let assert Ok(signed) = bit_array.to_string(checkpoint.signed)
  assert !string.contains(signed, "\u{2014}")

  let assert Error(_) = proof.parse_checkpoint(<<"origin\n1\nAAAA\n":utf8>>)
  let assert Error(_) =
    proof.parse_checkpoint(<<
      "origin\nnope\nAAAA\n\n\u{2014} n AAAAAAEC\n":utf8,
    >>)
}

// ---------------------------------------------------------------- publishing

/// A log a test can hold in its hand: one earlier entry, then ours, with a
/// checkpoint signed by a key the test also holds. The shapes are exactly
/// the ones `rekor/proof` parses, which is the point — the publisher is
/// exercised against the format, not against a mock of itself.
fn fake_log(log_csk: keys.Csk) -> #(client.Log, BitArray, BitArray) {
  let spki = proof.p256_spki(log_csk.public)
  let neighbour = proof.leaf_hash(<<"an earlier entry":utf8>>)
  let entry_of = fn(entry: BitArray) {
    let leaf = proof.leaf_hash(entry)
    let root = proof.node_hash(neighbour, leaf)
    let body = "rekor.test\n2\n" <> bit_array.base64_encode(root, True) <> "\n"
    let signature = ecdsa_sign_raw(<<body:utf8>>, log_csk.private)
    let assert Ok(hint) = bit_array.slice(proof.log_id(spki), 0, 4)
    let note =
      body
      <> "\n\u{2014} rekor.test "
      <> bit_array.base64_encode(bit_array.concat([hint, signature]), True)
      <> "\n"
    client.Entry(
      log_id: proof.log_id(spki),
      log_index: 1,
      checkpoint: <<note:utf8>>,
      inclusion_path: [neighbour],
      integrated_at: 1000,
    )
  }
  #(
    client.Log(lookup: fn(_entry) { Ok(None) }, submit: fn(entry) {
      Ok(entry_of(entry))
    }),
    spki,
    log_csk.public,
  )
}

/// A log that has already seen every entry: the republish path.
fn seen_log(log_csk: keys.Csk) -> client.Log {
  let #(log, _, _) = fake_log(log_csk)
  client.Log(
    lookup: fn(entry) { result.map(log.submit(entry), Some) },
    submit: fn(_entry) {
      Error("the entry was already logged; submitting again would duplicate it")
    },
  )
}

pub fn publish_stores_a_verified_record_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())

  let assert Ok(outcome) =
    rekor_publish.run(conn, apex, csk, log, #(spki, point), 1000)
  assert outcome.action == "create"
  assert outcome.refreshed == False
  assert outcome.key_tag == keys.key_tag(keys.dnskey_rdata(csk))

  let assert Ok([record]) = store.for_key_tag(conn, outcome.key_tag)
  assert record.apex == "sync.test."
  assert record.verified_at == 1000
  // What was stored is what a client will be handed, and it verifies.
  let assert Ok(stored) = rekor_publish.to_proof(record)
  let assert Ok(_) = proof.verify_against_log(stored, spki, point)
  assert statement.verify(
    csk.public,
    record.dsse_payload,
    record.dsse_signature,
  )
  sqlite.close(conn)
}

pub fn publish_is_idempotent_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let log_csk = keys.generate()
  let #(log, spki, point) = fake_log(log_csk)

  let assert Ok(first) =
    rekor_publish.run(conn, apex, csk, log, #(spki, point), 1000)
  let assert Ok(second) =
    rekor_publish.run(conn, apex, csk, seen_log(log_csk), #(spki, point), 2000)
  // The second run found the entry already logged and refreshed the proof;
  // a log that refuses duplicate submissions proves nothing was minted.
  assert second.refreshed
  assert second.log_index == first.log_index

  let assert Ok(records) = store.for_key_tag(conn, first.key_tag)
  assert list.length(records) == 1
  let assert [record] = records
  assert record.verified_at == 2000
  sqlite.close(conn)
}

pub fn publish_refuses_an_unverifiable_proof_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, _) = fake_log(keys.generate())
  let stranger = keys.generate()

  // The log's own key is not the key we pin: nothing is stored.
  let assert Error(rekor_publish.Unverified(_)) =
    rekor_publish.run(conn, apex, csk, log, #(spki, stranger.public), 1000)
  let assert Ok([]) =
    store.for_key_tag(conn, keys.key_tag(keys.dnskey_rdata(csk)))
  sqlite.close(conn)
}

// --------------------------------------------------------------- the gate

pub fn publish_gate_refuses_an_unlogged_key_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))
  // Phase 0/1: off by default, so a control plane that has not logged its
  // key yet keeps serving.
  let assert Ok(_) = publish.publish(conn, csk, 1000, "test")

  envoy.set(gate.require_env, "true")
  let assert Error(publish.NoRekorRecord(refused)) =
    publish.publish(conn, csk, 1000, "test")
  assert refused == key_tag

  // With a record in hand the same publish goes through.
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())
  let assert Ok(_) =
    rekor_publish.run(conn, apex, csk, log, #(spki, point), 1000)
  let assert Ok(_) = publish.publish(conn, csk, 1000, "test")
  envoy.unset(gate.require_env)
  sqlite.close(conn)
}

pub fn a_retire_record_does_not_satisfy_the_gate_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))
  let assert Ok(Nil) =
    store.put(
      conn,
      store.Record(
        key_tag: key_tag,
        apex: "sync.test.",
        action: "retire",
        dsse_payload: <<"{}":utf8>>,
        dsse_signature: <<0:size(512)>>,
        log_id: <<0:size(256)>>,
        log_index: 0,
        checkpoint: <<>>,
        inclusion_path: <<>>,
        integrated_at: 1,
        verified_at: 1,
      ),
    )
  // A retirement is a monitor breadcrumb, never a licence to serve (§2).
  assert store.servable(conn, key_tag) == Ok([])
  envoy.set(gate.require_env, "true")
  let assert Error(publish.NoRekorRecord(_)) =
    publish.publish(conn, csk, 1000, "test")
  envoy.unset(gate.require_env)
  sqlite.close(conn)
}

// ---------------------------------------------------------------- serving

pub fn the_zone_serves_the_proof_record_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let assert Ok(ns1) = name.parse("ns1.sync.test.")
  let assert Ok(owner) = name.parse("_synchronicity.prod.acme.sync.test.")
  let csk = keys.generate()
  let text = proof.to_txt(fixture_proof())
  let input =
    ZoneInput(
      ZoneMeta(
        apex,
        7,
        csk.public,
        keys.key_tag(keys.dnskey_rdata(csk)),
        3600,
        1_209_600,
        604_800,
      ),
      [NsHost(ns1, "127.0.0.1", "")],
      [TxtName(owner, [Member("nas", fixtures.nk(), "", "")])],
      [text],
      "",
    )
  let assert Ok(rrsets) = build.build(input)
  let assert Ok(rekor_owner) = name.parse("_synchronicity-rekor.sync.test.")
  let assert Ok(rrset) =
    list.find(rrsets, fn(r) {
      r.owner == rekor_owner && r.rtype == wire.type_txt
    })
  assert rrset.ttl == build.ttl_rekor
  let assert [rd] = rrset.rdatas
  // TXT rdata is a run of ≤255-byte character-strings; the client
  // concatenates them before decoding.
  assert chunks(rd) == Ok(text)
  // And the name is in the NSEC chain like any other owner.
  assert list.contains(build.owners_in_order(rrsets), rekor_owner)
}

pub fn a_zone_without_a_proof_has_no_such_name_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let assert Ok(ns1) = name.parse("ns1.sync.test.")
  let csk = keys.generate()
  let input =
    ZoneInput(
      ZoneMeta(
        apex,
        7,
        csk.public,
        keys.key_tag(keys.dnskey_rdata(csk)),
        3600,
        1_209_600,
        604_800,
      ),
      [NsHost(ns1, "127.0.0.1", "")],
      [],
      [],
      "",
    )
  let assert Ok(rrsets) = build.build(input)
  let assert Ok(rekor_owner) = name.parse("_synchronicity-rekor.sync.test.")
  assert !list.contains(build.owners_in_order(rrsets), rekor_owner)
}

/// Re-joins TXT character-strings.
fn chunks(rdata: BitArray) -> Result(String, Nil) {
  case rdata {
    <<>> -> Ok("")
    <<len:int-size(8), chunk:bytes-size(len), rest:bits>> -> {
      use head <- result.try(bit_array.to_string(chunk))
      use tail <- result.try(chunks(rest))
      case len <= 255 {
        True -> Ok(head <> tail)
        False -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}
