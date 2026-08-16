//// Zone-key transparency: the statement bytes, the proof encoding, the
//// local verification, and the publish gate.
////
//// The load-bearing half of this suite is the shared fixture in
//// test/fixtures/rekor: the same bytes the Rust client's verifier is
//// asserted against (crates/synch-net/tests/rekor_zone_key.rs). Two
//// implementations of one format drift silently unless something outside
//// both of them holds the bytes still — this is that something.

import dns/name
import dns/rdata
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
import rekor/cert
import rekor/chain
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
    statement: fixture("statement.json"),
    canonicalized_body: fixture("canonicalized-body.bin"),
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
  // The entry signature now lives inside the canonicalized body; read it out
  // and verify it as the client does — DER over the DSSE PAE.
  let assert Ok(#(_digest, signature, _verifier)) =
    proof.parse_body(fixture("canonicalized-body.bin"))
  assert statement.verify(
    fixture_public(),
    fixture("statement.json"),
    signature,
  )
  // One flipped bit and possession fails — the check is doing work.
  let assert Ok(<<first:int-size(8), rest:bits>>) = Ok(signature)
  let tampered = <<int.bitwise_exclusive_or(first, 1):int-size(8), rest:bits>>
  assert !statement.verify(
    fixture_public(),
    fixture("statement.json"),
    tampered,
  )
}

pub fn the_body_binds_to_the_statement_and_key_test() {
  // The body's digest is the SHA-256 of the Statement's PAE, and its
  // verifier is the zone key's DER SubjectPublicKeyInfo.
  let assert Ok(#(digest, _signature, verifier)) =
    proof.parse_body(fixture("canonicalized-body.bin"))
  assert digest
    == crypto.hash(
      crypto.Sha256,
      statement.pae(statement.dsse_payload_type, fixture("statement.json")),
    )
  // The verifier is the apex-naming certificate, and the key inside it is
  // the zone key — the binding the client checks, checked here too.
  let assert Ok(#(spki, san)) = cert_spki_and_san(verifier)
  assert spki == proof.p256_spki(fixture_public())
  assert san == cert.san_name(meta("apex"))
}

pub fn proof_encoding_matches_the_fixture_test() {
  assert proof.encode(fixture_proof()) == Ok(fixture("proof.bin"))
}

pub fn proof_txt_is_base64url_test() {
  let assert Ok(text) = proof.to_txt(fixture_proof())
  let assert Ok(decoded) = bit_array.base64_url_decode(text)
  assert decoded == fixture("proof.bin")
  assert !string.contains(text, "=")
}

/// A record that does not fit the format is refused, not mangled.
///
/// Both sides refuse now. They used to fail *differently* — this side
/// wrapped the 16-bit length modulo 65536, the Rust side clamped it and
/// truncated the blob — which in a format whose whole purpose is that two
/// implementations agree byte for byte is worse than not encoding at all.
pub fn an_oversized_proof_is_refused_rather_than_mangled_test() {
  let base = fixture_proof()
  let assert Error(_) =
    proof.encode(Proof(..base, statement: <<0:size(524_288)>>))
  let assert Error(_) =
    proof.encode(Proof(..base, checkpoint: <<0:size(524_288)>>))
  let assert Error(_) =
    proof.to_txt(Proof(..base, canonicalized_body: <<0:size(524_288)>>))
  let assert Error(_) =
    proof.encode(
      Proof(..base, inclusion_path: list.repeat(<<0:size(256)>>, 256)),
    )
  // 255 hops is the last that fits.
  let assert Ok(_) =
    proof.encode(
      Proof(..base, inclusion_path: list.repeat(<<0:size(256)>>, 255)),
    )
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

/// A resolver that answers with structurally correct but cryptographically
/// meaningless RRsets.
///
/// Deliberate: this side never validates a chain — the cryptographic walk
/// lives in crates/synch-net/src/chain.rs and is run by every client and
/// every monitor, and the e2e crossval is what keeps this side honest. What
/// the publisher owes is *collection*: ask for the right RRsets at the right
/// names, refuse when one is missing, and carry the bytes verbatim. That is
/// what this fake exercises.
fn fake_resolver() -> chain.Resolver {
  chain.Resolver(query: fn(zone, rtype) {
    let rdata_of = fn(rtype: Int) {
      case rtype {
        48 -> rdata.dnskey(257, 13, <<7:size(512)>>)
        _ -> <<1234:int-size(16), 13:int-size(8), 2:int-size(8), 9:size(256)>>
      }
    }
    Ok([
      wire.Rr(zone, rtype, wire.class_in, 3600, rdata_of(rtype)),
      wire.Rr(
        zone,
        wire.type_rrsig,
        wire.class_in,
        3600,
        <<rtype:int-size(16), 13:int-size(8), 2:int-size(8), 0:size(512)>>,
      ),
    ])
  })
}

/// A resolver with nothing to say — the DS is not live in the parent yet,
/// which is the one failure the inverted ceremony makes common.
fn silent_resolver() -> chain.Resolver {
  chain.Resolver(query: fn(_zone, _rtype) { Ok([]) })
}

fn publish_run(
  conn: sqlite.Connection,
  apex: name.Name,
  csk: keys.Csk,
  log: client.Log,
  log_key: #(BitArray, BitArray),
  now: Int,
) {
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))
  let assert Ok(action) = rekor_publish.action_for(conn, key_tag)
  rekor_publish.run(
    conn,
    apex,
    csk,
    log,
    log_key,
    now,
    fake_resolver(),
    action,
    None,
  )
}

/// A log a test can hold in its hand: one earlier entry, then ours, with a
/// checkpoint signed by a key the test also holds. It builds a real
/// `hashedrekord` body from the submission, exactly as Sigstore returns one,
/// so the publisher is exercised against the format, not against a mock of
/// itself.
fn fake_log(log_csk: keys.Csk) -> #(client.Log, BitArray, BitArray) {
  let spki = proof.p256_spki(log_csk.public)
  let neighbour = proof.leaf_hash(<<"an earlier entry":utf8>>)
  let entry_of = fn(sub: client.Submission) {
    let body =
      proof.hashedrekord_body(sub.digest, sub.signature, sub.certificate)
    let leaf = proof.leaf_hash(body)
    let root = proof.node_hash(neighbour, leaf)
    let note_body =
      "rekor.test\n2\n" <> bit_array.base64_encode(root, True) <> "\n"
    let signature = ecdsa_sign_raw(<<note_body:utf8>>, log_csk.private)
    let assert Ok(hint) = bit_array.slice(proof.log_id(spki), 0, 4)
    let note =
      note_body
      <> "\n\u{2014} rekor.test "
      <> bit_array.base64_encode(bit_array.concat([hint, signature]), True)
      <> "\n"
    client.Entry(
      log_index: 1,
      canonicalized_body: body,
      checkpoint: <<note:utf8>>,
      inclusion_path: [neighbour],
      integrated_at: 1000,
    )
  }
  #(client.Log(submit: fn(sub) { Ok(entry_of(sub)) }), spki, log_csk.public)
}

pub fn publish_stores_a_verified_record_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())

  let assert Ok(outcome) =
    publish_run(conn, apex, csk, log, #(spki, point), 1000)
  assert outcome.action == "create"
  assert outcome.refreshed == False
  assert outcome.key_tag == keys.key_tag(keys.dnskey_rdata(csk))

  let assert Ok([record]) = store.for_key_tag(conn, outcome.key_tag)
  assert record.apex == "sync.test."
  assert record.verified_at == 1000
  // What was stored is what a client will be handed, and it verifies.
  let assert Ok(stored) = rekor_publish.to_proof(record)
  let assert Ok(_) = proof.verify_against_log(stored, spki, point)
  // Possession: the signature the log indexed is inside the stored body.
  let assert Ok(#(_digest, signature, _certificate)) =
    proof.parse_body(record.canonicalized_body)
  assert statement.verify(csk.public, record.statement, signature)
  sqlite.close(conn)
}

pub fn publish_is_idempotent_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())

  let assert Ok(first) =
    publish_run(conn, apex, csk, log, #(spki, point), 1000)
  let assert Ok(second) =
    publish_run(conn, apex, csk, log, #(spki, point), 2000)
  // The second run reused the signature the log already indexed, so Rekor's
  // content addressing returns the same entry — a refresh, not a new claim.
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
    publish_run(conn, apex, csk, log, #(spki, stranger.public), 1000)
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
    publish_run(conn, apex, csk, log, #(spki, point), 1000)
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
        spki_sha256: crypto.hash(crypto.Sha256, proof.p256_spki(csk.public)),
        key_tag: key_tag,
        apex: "sync.test.",
        action: "retire",
        statement: <<"{}":utf8>>,
        canonicalized_body: <<0:size(512)>>,
        log_id: <<0:size(256)>>,
        log_index: 0,
        checkpoint: <<>>,
        inclusion_path: <<>>,
        chainless: True,
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
  let assert Ok(text) = proof.to_txt(fixture_proof())
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

// ------------------------------------------------- the certificate crossval

/// The certificate encoders, against bytes the Rust side asserts too.
///
/// Two implementations of one DER format drift silently. These fixtures are
/// deterministic — fixed inputs, no signatures — so both suites can hold the
/// same bytes still: crates/synch-net/tests/rekor_zone_key.rs reads exactly
/// these files.
pub fn the_chain_extension_encodes_the_crossval_bytes_test() {
  let links = [
    cert.Link("sync.test.", <<0xaa, 0xbb, 0xcc>>),
    cert.Link(".", <<0x01, 0x02>>),
  ]
  assert cert.encode_chain(links) == fixture("crossval/chain.der")
}

pub fn the_succession_extension_encodes_the_crossval_bytes_test() {
  let succession =
    cert.Succession(
      predecessor_key_tag: 34_918,
      predecessor_spki: <<0x30, 0x59, 0x11>>,
      signature: <<0x30, 0x44, 0x02>>,
    )
  assert cert.encode_succession(succession) == fixture("crossval/succession.der")
}

pub fn the_succession_payload_is_the_crossval_bytes_test() {
  // The bytes the *previous* zone key signs. The apex is written without its
  // root dot so the two halves cannot disagree about a character nobody can
  // see, and the successor is named by the SHA-256 of its SubjectPublicKeyInfo
  // rather than by a 16-bit key tag.
  let payload = cert.succession_payload("sync.test.", 34_918, <<"spki":utf8>>)
  assert payload == fixture("crossval/succession-payload.json")
  assert cert.succession_payload("sync.test", 34_918, <<"spki":utf8>>) == payload
}

/// A certificate this side builds, read back by this side and — from the
/// checked-in copy — by the Rust parser.
pub fn a_built_certificate_carries_its_key_its_name_and_its_extensions_test() {
  let csk = keys.generate()
  let links = [cert.Link("sync.test.", <<0xaa, 0xbb>>)]
  let succession =
    cert.Succession(
      predecessor_key_tag: 1234,
      predecessor_spki: <<0x30, 0x59>>,
      signature: <<0x30, 0x44>>,
    )
  let der =
    cert.build(
      "sync.test.",
      csk.public,
      csk.private,
      1_786_866_288,
      1_786_866_288 + 3_155_760_000,
      Some(links),
      Some(succession),
    )
  let assert Ok(#(spki, san)) = cert_spki_and_san(der)
  assert spki == proof.p256_spki(csk.public)
  // The SAN is the apex without its root dot: a dNSName is a hostname.
  assert san == "sync.test"
  let assert Ok(chain_value) = cert_extension(der, cert.oid_dnssec_chain)
  assert chain_value == cert.encode_chain(links)
  let assert Ok(succession_value) = cert_extension(der, cert.oid_succession)
  assert succession_value == cert.encode_succession(succession)

  // A chainless certificate has no chain extension at all — the shape a
  // `retire` breadcrumb takes, and the shape a client refuses.
  let bare =
    cert.build("sync.test.", csk.public, csk.private, 0, 1, None, None)
  let assert Error(Nil) = cert_extension(bare, cert.oid_dnssec_chain)
  let assert Error(Nil) = cert_extension(bare, cert.oid_succession)
}

/// The certificate the Rust suite parses: built here, checked in, read
/// there. This is the crossval that a hand-rolled DER reader on one side and
/// OTP's ASN.1 encoder on the other actually agree.
pub fn the_checked_in_certificate_is_this_encoders_output_test() {
  let der = fixture("crossval/certificate.der")
  let assert Ok(#(spki, san)) = cert_spki_and_san(der)
  assert bit_array.byte_size(spki) == 91
  assert san == "sync.test"
  let assert Ok(chain_value) = cert_extension(der, cert.oid_dnssec_chain)
  assert chain_value == fixture("crossval/chain.der")
  let assert Ok(succession_value) = cert_extension(der, cert.oid_succession)
  assert succession_value == fixture("crossval/succession.der")
}

/// The publisher refuses when the chain cannot be built.
///
/// Which is the ordinary failure of the inverted ceremony (§5.2): logging
/// now happens *after* the DS is live in the parent, so "the DS is not there
/// yet" is the error an operator meets, and it says so.
pub fn publish_refuses_when_the_ds_is_not_live_yet_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))

  let assert Error(rekor_publish.NoChain(why)) =
    rekor_publish.run(
      conn,
      apex,
      csk,
      log,
      #(spki, point),
      1000,
      silent_resolver(),
      "create",
      None,
    )
  assert string.contains(why, "DS")
  let assert Ok([]) = store.for_key_tag(conn, key_tag)
  sqlite.close(conn)
}

/// A retire may be chainless; a create may not.
pub fn a_retire_may_be_chainless_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())

  let assert Ok(outcome) =
    rekor_publish.run(
      conn,
      apex,
      csk,
      log,
      #(spki, point),
      1000,
      silent_resolver(),
      "retire",
      None,
    )
  assert outcome.action == "retire"
  assert outcome.chainless
  // And it is never served to a client: a retire is a monitor breadcrumb.
  let assert Ok([]) = store.servable(conn, outcome.key_tag)
  sqlite.close(conn)
}

/// Naming the previous key adds the countersignature that separates a
/// rotation from a substitution in every monitor watching the zone.
pub fn a_countersigned_publish_names_its_predecessor_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let previous = keys.generate()
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())

  let assert Ok(outcome) =
    rekor_publish.run(
      conn,
      apex,
      csk,
      log,
      #(spki, point),
      1000,
      fake_resolver(),
      "create",
      Some(previous),
    )
  assert outcome.countersigned_by
    == Some(keys.key_tag(keys.dnskey_rdata(previous)))
  assert !outcome.chainless

  // The countersignature is the previous key's, over the successor's SPKI.
  let assert Ok([record]) = store.for_key_tag(conn, outcome.key_tag)
  let assert Ok(#(_digest, _signature, certificate)) =
    proof.parse_body(record.canonicalized_body)
  let assert Ok(value) = cert_extension(certificate, cert.oid_succession)
  let assert Ok(succession) = cert.decode_succession(value)
  assert succession.predecessor_spki == proof.p256_spki(previous.public)
  assert statement.verify_bytes(
    previous.public,
    cert.succession_signed_bytes(
      "sync.test.",
      succession.predecessor_key_tag,
      proof.p256_spki(csk.public),
    ),
    succession.signature,
  )
  sqlite.close(conn)
}

@external(erlang, "cp_crypto_ffi", "cert_spki_and_san")
fn cert_spki_and_san(der: BitArray) -> Result(#(BitArray, String), Nil)

@external(erlang, "cp_crypto_ffi", "cert_extension")
fn cert_extension(der: BitArray, oid: #(Int, Int, Int)) -> Result(BitArray, Nil)

/// The OID arcs must stay inside 31 bits, and OTP must encode them to exactly
/// the bytes the Rust constants carry.
///
/// Rekor is Go: `encoding/asn1` rejects OID components that overflow `int32`,
/// so `x509.ParseCertificate` fails on a wider arc and the log refuses the
/// whole submission with an opaque `400`. Nothing local caught the original
/// 128-bit UUID arcs — OTP's `public_key` writes them and OpenSSL reads them
/// back without complaint — so this suite passed for a certificate the log
/// would not accept. That failure mode is why the bytes are asserted here
/// rather than merely commented, and why the two encoders are compared
/// through what OTP *actually emitted* into a certificate.
pub fn the_oid_arcs_stay_inside_an_int32_test() {
  let int32_max = 2_147_483_647
  assert oid_arc(cert.oid_dnssec_chain) <= int32_max
  assert oid_arc(cert.oid_succession) <= int32_max

  // The DER an OID gets: tag 0x06, length 6, then 0x69 (= 40 × 2 + 25) and
  // the arc in base-128. Byte-identical to crates/synch-net/src/zonecert.rs.
  let der = fixture("crossval/certificate.der")
  assert contains(der, <<0x06, 0x06, 0x69, 0x85, 0xe5, 0xe9, 0xb2, 0x07>>)
  assert contains(der, <<0x06, 0x06, 0x69, 0x84, 0x9e, 0xe8, 0xd2, 0x32>>)

  // And each arc is the first four bytes of its UUID masked to 31 bits, so a
  // future edit cannot pick a new number and keep the explanation.
  assert oid_arc(cert.oid_dnssec_chain) == int.bitwise_and(0xdcba5907, int32_max)
  assert oid_arc(cert.oid_succession) == int.bitwise_and(0x43da2932, int32_max)
}

fn oid_arc(oid: #(Int, Int, Int)) -> Int {
  oid.2
}

fn contains(haystack: BitArray, needle: BitArray) -> Bool {
  let size = bit_array.byte_size(needle)
  scan_for(haystack, needle, size, bit_array.byte_size(haystack) - size)
}

fn scan_for(
  haystack: BitArray,
  needle: BitArray,
  size: Int,
  at: Int,
) -> Bool {
  case at < 0 {
    True -> False
    False ->
      case bit_array.slice(haystack, at, size) == Ok(needle) {
        True -> True
        False -> scan_for(haystack, needle, size, at - 1)
      }
  }
}

/// Re-running with the predecessor keyfile you forgot the first time is not
/// a no-op.
///
/// The §5.4 recovery for "you published without naming the old key, and every
/// monitor is now alerting" is to re-run with it. The Statement bytes are
/// identical either way — the predecessor lives in the certificate, not the
/// Statement — so a reuse rule keyed on the Statement alone silently threw
/// the countersignature away and reported success, leaving the zone tier B
/// forever with no way out short of editing the database.
pub fn republishing_with_a_predecessor_adds_the_countersignature_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let previous = keys.generate()
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())

  // First publish: the operator forgets the predecessor. Tier B everywhere.
  let assert Ok(first) =
    rekor_publish.run(
      conn, apex, csk, log, #(spki, point), 1000, fake_resolver(), "create",
      None,
    )
  assert first.countersigned_by == None

  // Re-run naming it. The Statement is byte-identical, so the old rule would
  // have reused the stored certificate and reported success unchanged.
  let assert Ok(second) =
    rekor_publish.run(
      conn, apex, csk, log, #(spki, point), 2000, fake_resolver(), "create",
      Some(previous),
    )
  assert second.countersigned_by
    == Some(keys.key_tag(keys.dnskey_rdata(previous)))
  assert second.refreshed == False

  // And what is stored now carries it, verifiably.
  let assert Ok([record]) = store.for_key_tag(conn, second.key_tag)
  let assert Ok(#(_digest, _signature, certificate)) =
    proof.parse_body(record.canonicalized_body)
  let assert Ok(value) = cert_extension(certificate, cert.oid_succession)
  let assert Ok(succession) = cert.decode_succession(value)
  assert succession.predecessor_spki == proof.p256_spki(previous.public)

  // A third run naming the *same* predecessor changes nothing: the stored
  // entry already says what this run would say, so it stays one claim.
  let assert Ok(third) =
    rekor_publish.run(
      conn, apex, csk, log, #(spki, point), 3000, fake_resolver(), "create",
      Some(previous),
    )
  assert third.refreshed
  sqlite.close(conn)
}

/// A body whose kind or apiVersion is not the one entry type Rekor v2 takes
/// is refused here, as it is by the client.
pub fn parse_body_refuses_a_foreign_entry_kind_test() {
  let good = fixture("canonicalized-body.bin")
  let assert Ok(_) = proof.parse_body(good)
  let assert Ok(text) = bit_array.to_string(good)

  let swapped =
    string.replace(text, "\"kind\":\"hashedrekord\"", "\"kind\":\"dsse\"")
  let assert Error(proof.Binding(_)) = proof.parse_body(<<swapped:utf8>>)

  let older =
    string.replace(text, "\"apiVersion\":\"0.0.2\"", "\"apiVersion\":\"0.0.1\"")
  let assert Error(proof.Binding(_)) = proof.parse_body(<<older:utf8>>)
}

/// A chain that stops below the root is refused before it is ever published.
pub fn a_chain_that_does_not_reach_the_root_is_refused_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let full = [
    chain.Link("sync.test.", <<1>>),
    chain.Link("test.", <<2>>),
    chain.Link(".", <<3>>),
  ]
  let assert Ok(Nil) = chain.check_shape(full, apex)

  // The shape CP_DNSSEC_CHAIN_ROOT_DNSKEY=false used to emit: a TLD DNSKEY on
  // top, anchoring against nothing any reader holds.
  let rootless = [chain.Link("sync.test.", <<1>>), chain.Link("test.", <<2>>)]
  let assert Error(why) = chain.check_shape(rootless, apex)
  assert string.contains(why, "root")

  // A ladder with a rung missing.
  let spliced = [chain.Link("sync.test.", <<1>>), chain.Link(".", <<3>>)]
  let assert Error(_) = chain.check_shape(spliced, apex)

  // A chain that is not about this apex at all.
  let assert Error(_) =
    chain.check_shape([chain.Link("other.test.", <<1>>), chain.Link(".", <<3>>)], apex)
  let assert Error(_) = chain.check_shape([], apex)
}
