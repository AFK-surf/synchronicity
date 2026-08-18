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
import fixtures
import gleam/bit_array
import gleam/crypto
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import jobs/zonekey_watch
import provider/state
import rekor/cert
import rekor/chain
import rekor/client
import rekor/proof.{type Proof, Proof}
import rekor/publish as rekor_publish
import rekor/statement
import rekor/store
import simplifile
import store/sqlite
import tools/gen_crossval
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
  let assert Ok(log_index) = int.parse(meta("log_index"))
  Proof(
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
    statement.to_json(statement.for_keys(
      apex,
      [fixture("dnskey.bin")],
      meta("action"),
    ))
  // Byte-exact: the signature and the Merkle leaf both commit to these
  // bytes, so "equivalent JSON" is not equivalent.
  assert built == fixture("statement.json")
}

pub fn statement_fields_are_the_observed_key_set_test() {
  let assert Ok(apex) = name.parse(meta("apex"))
  let built = statement.for_keys(apex, [fixture("dnskey.bin")], "create")
  let assert [key] = built.keys
  assert key.key_tag == keys.key_tag(fixture("dnskey.bin"))
  assert key.algorithm == 13
  assert key.flags == 257
  assert key.sha256
    == string.lowercase(
      bit_array.base16_encode(crypto.hash(crypto.Sha256, fixture("dnskey.bin"))),
    )
}

pub fn a_key_set_has_one_canonical_rendering_test() {
  // Two keys supplied in either order render to the same bytes: ascending
  // key tag, ties broken by digest. One set, one rendering — the same rule
  // the Rust renderer applies.
  let assert Ok(apex) = name.parse("sync.test.")
  let ksk = rdata.dnskey(257, 13, <<7:size(512)>>)
  let zsk = rdata.dnskey(256, 13, <<9:size(512)>>)
  let one = statement.to_json(statement.for_keys(apex, [ksk, zsk], "rollover"))
  let two = statement.to_json(statement.for_keys(apex, [zsk, ksk], "rollover"))
  assert one == two
  let assert Ok(json) = bit_array.to_string(one)
  assert string.contains(json, "\"action\":\"rollover\"")
  assert string.contains(
    json,
    "\"predicateType\":\"https://synchronicity.sh/zone-key/v2\"",
  )
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
  // One flipped bit and attribution fails — the check is doing work.
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

/// A proof is served in self-describing pieces, each inside the tightest
/// provider limit, and they reassemble to exactly the encoded record.
pub fn proof_txt_is_chunked_base64url_test() {
  let assert Ok(records) = proof.to_txt(fixture_proof())
  // Every record names the same group and its place in it.
  let assert [first, ..] = records
  let assert [prefix, group, counter, _payload] = string.split(first, " ")
  assert prefix == proof.txt_prefix
  assert string.length(group) == 8
  assert string.ends_with(counter, "/" <> int.to_string(list.length(records)))

  list.each(records, fn(record) {
    // Comfortably inside Cloudflare's 4096 wire-format bytes, which is the
    // limit that decides this size.
    assert string.length(record) < 4096
    assert string.starts_with(record, proof.txt_prefix <> " " <> group <> " ")
  })

  // The payloads, in order, are the base64url of the encoded proof.
  let payload =
    records
    |> list.map(fn(r) {
      let assert [_, _, _, chunk] = string.split(r, " ")
      chunk
    })
    |> string.join("")
  let assert Ok(decoded) = bit_array.base64_url_decode(payload)
  assert decoded == fixture("proof.bin")
  assert !string.contains(payload, "=")
}

/// A record that does not fit the format is refused, not mangled.
///
/// Both sides refuse, and that is the assertion: in a format whose whole
/// purpose is that two implementations agree byte for byte, wrapping a 16-bit
/// length or truncating a blob is worse than not encoding at all.
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

@external(erlang, "cp_crypto_ffi", "ecdsa_sign_der")
fn ecdsa_sign_der(message: BitArray, private: BitArray) -> BitArray

/// A P-256 checkpoint signature verifies in **either** ECDSA encoding.
///
/// Sigstore signs its notes in DER, and a DER signature can never satisfy a
/// fixed-width `r || s` verifier. Accepting only the fixed form here meant
/// that the day Sigstore serves a P-256-keyed shard, `rekor-publish` writes
/// the entry to the public log and then rejects the proof the log hands back
/// — a zone that can never satisfy its own publish gate, over an encoding
/// difference. The Rust client accepts both; so does this side.
///
/// Both fixtures in this repo come from the Ed25519 shard, which is exactly
/// why this case has to be built rather than captured.
pub fn a_p256_checkpoint_verifies_in_either_ecdsa_encoding_test() {
  let keys.Csk(private, public) = keys.generate()
  let note =
    "log.example\n7\n" <> "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
  let signed = <<note:utf8>>

  // The signature Sigstore actually produces: ASN.1/DER, ~70 bytes.
  let der = ecdsa_sign_der(signed, private)
  assert bit_array.byte_size(der) > 64
  // And the same signature written the fixed-width way.
  let raw = ecdsa_sign_raw(signed, private)
  assert bit_array.byte_size(raw) == 64

  // A note carrying each, with the four-byte key hint every signature line
  // is prefixed with.
  let line = fn(signature: BitArray) {
    let blob = bit_array.base64_encode(<<0, 0, 0, 0, signature:bits>>, True)
    <<note:utf8, "\n\u{2014} log.example ":utf8, blob:utf8, "\n":utf8>>
  }

  let assert Ok(with_der) = proof.parse_checkpoint(line(der))
  let assert Ok(Nil) = proof.verify_checkpoint(with_der, public)

  let assert Ok(with_raw) = proof.parse_checkpoint(line(raw))
  let assert Ok(Nil) = proof.verify_checkpoint(with_raw, public)

  // And a signature by some other key still fails, in both encodings, so the
  // acceptance above is not simply a verifier that says yes.
  let keys.Csk(other, _) = keys.generate()
  let assert Ok(forged) =
    proof.parse_checkpoint(line(ecdsa_sign_der(signed, other)))
  let assert Error(_) = proof.verify_checkpoint(forged, public)
}

/// Only the line naming the note's own origin can vouch for the tree.
///
/// A real checkpoint carries the log's signature plus a line per witness that
/// cosigned it, and in a C2SP cosigning arrangement a key signs *other* logs'
/// notes as a witness. Without this check, log Y's checkpoint cosigned by
/// pinned key X verifies here and is stored against `log_id = id(X)` with an
/// inclusion path into Y's tree — and the log id is the only thing that says
/// which log an entry is in. The client refuses exactly this shape; so does
/// this side, which is the one deciding whether to store a permanent record.
pub fn only_the_line_naming_the_origin_vouches_for_a_checkpoint_test() {
  let keys.Csk(private, public) = keys.generate()
  let note =
    "log-Y.example\n7\n" <> "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
  let signed = <<note:utf8>>
  let signature = ecdsa_sign_der(signed, private)
  let blob = bit_array.base64_encode(<<0, 0, 0, 0, signature:bits>>, True)

  // The pinned key really did sign these bytes — but as a witness for some
  // other log, not as log-Y speaking about its own tree.
  let as_witness = <<
    note:utf8, "\n\u{2014} witness-X.example ":utf8, blob:utf8, "\n":utf8,
  >>
  let assert Ok(cosigned) = proof.parse_checkpoint(as_witness)
  let assert Error(_) = proof.verify_checkpoint(cosigned, public)

  // The identical signature on a line that names the origin is the log
  // vouching for itself, and is accepted.
  let as_origin = <<
    note:utf8, "\n\u{2014} log-Y.example ":utf8, blob:utf8, "\n":utf8,
  >>
  let assert Ok(own) = proof.parse_checkpoint(as_origin)
  let assert Ok(Nil) = proof.verify_checkpoint(own, public)

  // And a witness line sitting *beside* the log's own is tolerated, because
  // every real Sigstore checkpoint carries several.
  let both = <<
    note:utf8, "\n\u{2014} witness-X.example ":utf8, blob:utf8,
    "\n\u{2014} log-Y.example ":utf8, blob:utf8, "\n":utf8,
  >>
  let assert Ok(beside) = proof.parse_checkpoint(both)
  let assert Ok(Nil) = proof.verify_checkpoint(beside, public)
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
/// An RRSIG the collector's rules accept: owned by the queried name, covering
/// the queried type, with that name's own label count — a shorter one is a
/// wildcard expansion, which the collector refuses — and the signer a real
/// zone would have used. A zone signs its own DNSKEY RRset; the parent signs a
/// DS; the zone one label up signs the declaration, and the collector checks
/// that last one against the signing zone it was given.
fn fake_rrsig(zone: name.Name, rtype: Int) -> wire.Rr {
  let signer = case rtype == wire.type_dnskey {
    True -> zone
    False -> list.drop(zone, 1)
  }
  wire.Rr(
    zone,
    wire.type_rrsig,
    wire.class_in,
    3600,
    rdata.rrsig(rtype, 13, list.length(zone), 3600, 0, 0, 1234, signer, <<
      0:size(512),
    >>),
  )
}

fn fake_resolver(dnskey_rd: BitArray) -> chain.Resolver {
  fake_resolver_serving([dnskey_rd])
}

/// A resolver whose apex answers a DNSKEY RRset of several keys — what the
/// zone actually serves mid-rollover, and what `rekor-publish` must claim
/// in full so the incoming key is on the record before it signs anything.
pub fn fake_resolver_serving(dnskey_rds: List(BitArray)) -> chain.Resolver {
  chain.Resolver(query: fn(zone, rtype) {
    let rrsig = fake_rrsig(zone, rtype)
    case rtype {
      48 ->
        Ok(
          list.append(
            list.map(dnskey_rds, fn(rd) {
              wire.Rr(zone, rtype, wire.class_in, 3600, rd)
            }),
            [rrsig],
          ),
        )
      // The declaration, spelled the way every reader checks for it. A
      // fixture answering something else here builds a chain that verifies
      // nowhere, and does it silently.
      w if w == wire.type_txt ->
        Ok([
          wire.Rr(
            zone,
            wire.type_txt,
            wire.class_in,
            300,
            rdata.txt(rdata.transparency_text),
          ),
          rrsig,
        ])
      // And a DS that actually covers a key the zone serves, rather than a
      // constant. The publisher checks this before writing to the log, so a
      // fixture with an unrelated digest is a fixture of a chain no client
      // would walk.
      _ -> Ok([ds_rr(zone, dnskey_rds), rrsig])
    }
  })
}

/// A DS RRset covering the first key of `dnskey_rds`, as its parent would
/// publish it: `<tag> <algorithm> 2 <sha256(owner ‖ rdata)>`.
pub fn ds_rr(zone: name.Name, dnskey_rds: List(BitArray)) -> wire.Rr {
  let rd = case dnskey_rds {
    [first, ..] -> first
    [] -> <<257:int-size(16), 3:int-size(8), 13:int-size(8), 0:size(512)>>
  }
  let algorithm = case rd {
    <<_flags:int-size(16), _proto:int-size(8), alg:int-size(8), _:bits>> -> alg
    _ -> 13
  }
  wire.Rr(
    zone,
    chain.type_ds,
    wire.class_in,
    3600,
    bit_array.concat([
      <<keys.key_tag(rd):int-size(16), algorithm:int-size(8), 2:int-size(8)>>,
      keys.ds_digest(zone, rd),
    ]),
  )
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
  rekor_publish.run(
    conn,
    apex,
    apex,
    log,
    log_key,
    now,
    fake_resolver(keys.dnskey_rdata(csk)),
    rekor_publish.Current,
  )
}

/// `publish_run` for a zone serving more than one DNSKEY — the mid-rollover
/// state, where the claim has to cover both the outgoing and incoming keys.
fn publish_run_claiming(
  conn: sqlite.Connection,
  apex: name.Name,
  dnskey_rds: List(BitArray),
  log: client.Log,
  log_key: #(BitArray, BitArray),
  now: Int,
) {
  rekor_publish.run(
    conn,
    apex,
    apex,
    log,
    log_key,
    now,
    fake_resolver_serving(dnskey_rds),
    rekor_publish.Current,
  )
}

/// A log a test can hold in its hand: one earlier entry, then ours, with a
/// checkpoint signed by a key the test also holds. It builds a real
/// `hashedrekord` body from the submission, exactly as Sigstore returns one,
/// so the publisher is exercised against the format, not against a mock of
/// itself.
pub fn fake_log(log_csk: keys.Csk) -> #(client.Log, BitArray, BitArray) {
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
  // The claimed set is what the resolver's apex DNSKEY RRset holds — the
  // CSK, observed on the (fake) wire rather than named from memory.
  let csk_rdata = keys.dnskey_rdata(csk)
  assert outcome.key_tags == [keys.key_tag(csk_rdata)]

  let assert Ok([record]) = store.servable(conn, [])
  assert record.apex == "sync.test."
  assert record.verified_at == 1000
  let assert [#(key_sha256, key_tag)] = record.keys
  assert key_sha256 == crypto.hash(crypto.Sha256, csk_rdata)
  assert key_tag == keys.key_tag(csk_rdata)
  // What was stored is what a client will be handed, and it verifies.
  let assert Ok(stored) = rekor_publish.to_proof(record)
  let assert Ok(_) = proof.verify_against_log(stored, spki, point)
  // Attribution: the signature the log indexed verifies under the entry\'s
  // own certificate — an ephemeral signer nothing holds a key file for.
  let assert Ok(#(_digest, signature, certificate)) =
    proof.parse_body(record.canonicalized_body)
  let assert Ok(#(cert_spki, _san)) = cert_spki_and_san(certificate)
  let assert Ok(signer_public) = bit_array.slice(cert_spki, 27, 64)
  assert statement.verify(signer_public, record.statement, signature)
  // And it is NOT the zone key\'s signature: the signer is ephemeral, so
  // the CSK never signs entries — possession is nobody\'s claim to make.
  assert !statement.verify(csk.public, record.statement, signature)
  sqlite.close(conn)
}

pub fn publish_is_idempotent_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())

  let assert Ok(first) = publish_run(conn, apex, csk, log, #(spki, point), 1000)
  let assert Ok(second) =
    publish_run(conn, apex, csk, log, #(spki, point), 2000)
  // The second run reused the signature the log already indexed, so Rekor's
  // content addressing returns the same entry — a refresh, not a new claim.
  assert second.refreshed
  assert second.log_index == first.log_index

  let _ = first
  let assert Ok(records) = store.servable(conn, [])
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
  let assert Ok([]) = store.servable(conn, [])
  sqlite.close(conn)
}

// --------------------------------------------------------------- the gate

pub fn publish_gate_refuses_an_unlogged_key_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))
  // Disarmed, a control plane that has not logged its key still serves.
  let assert Ok(_) = publish.publish(conn, csk, 1000, "test")

  use <- fixtures.with_gate_armed
  let assert Error(publish.NoRekorRecord(refused)) =
    publish.publish(conn, csk, 1000, "test")
  assert refused == key_tag

  // With a record in hand the same publish goes through.
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())
  let assert Ok(_) = publish_run(conn, apex, csk, log, #(spki, point), 1000)
  let assert Ok(_) = publish.publish(conn, csk, 1000, "test")
  sqlite.close(conn)
}

/// The gate must never turn a transparency gap into a DNS outage.
///
/// A boot emission re-emits what is already in the database, so like the
/// hourly re-sign it says nothing new and is ungated. Gating it meant that a
/// primary whose key was not yet logged failed `prepare_primary`, halted, and
/// never started the nameserver at all — taking the re-sign job that exists to
/// keep the zone resolvable down with it, and leaving a greenfield zone with
/// no way to boot.
pub fn a_boot_emission_is_ungated_but_widening_is_not_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))

  use <- fixtures.with_gate_armed
  // What `prepare_primary` runs at boot: the zone comes up.
  let assert Ok(_) = publish.publish_resign(conn, csk, 1000, "system:boot")
  // And keeps coming up, so a restart weeks later is not a landmine.
  let assert Ok(_) = publish.publish_resign(conn, csk, 2000, "system:boot")

  // But the gate is untouched where it matters: emitting new content under
  // an unlogged key is still refused, naming the key.
  let assert Error(publish.NoRekorRecord(refused)) =
    publish.publish(conn, csk, 1000, "test")
  assert refused == key_tag
  sqlite.close(conn)
}

pub fn a_retire_record_does_not_satisfy_the_gate_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let csk_rdata = keys.dnskey_rdata(csk)
  let assert Ok(Nil) =
    store.put(
      conn,
      store.Record(
        keyset_sha256: crypto.hash(crypto.Sha256, csk_rdata),
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
        keys: [
          #(crypto.hash(crypto.Sha256, csk_rdata), keys.key_tag(csk_rdata)),
        ],
      ),
    )
  // A retirement is a monitor breadcrumb, never a licence to serve (§2) —
  // and never a licence for the gate either: the key is claimed only by a
  // retire, which covers nothing.
  assert store.servable(conn, []) == Ok([])
  use <- fixtures.with_gate_armed
  let assert Error(publish.NoRekorRecord(_)) =
    publish.publish(conn, csk, 1000, "test")
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
        <<>>,
        0,
        3600,
        1_209_600,
        604_800,
      ),
      [NsHost(ns1, "127.0.0.1", "")],
      [TxtName(owner, [Member("nas", fixtures.nk(), "", "")])],
      list.index_map(text, fn(t, i) { #(i + 1, t) }),
      0,
    )
  let assert Ok(rrsets) = build.build(input)
  // One part per owner name: part 1 at the base, part n one label along.
  let assert Ok(rekor_owner) = name.parse("_synchronicity-rekor.sync.test.")
  let assert Ok(rrset) =
    list.find(rrsets, fn(r) {
      r.owner == rekor_owner && r.rtype == wire.type_txt
    })
  assert rrset.ttl == build.ttl_rekor
  let assert [first, ..rest] = text
  let assert [rd] = rrset.rdatas
  assert chunks(rd) == Ok(first)
  // Every later part has its own name, and its own place in the NSEC chain.
  list.index_map(rest, fn(part, i) {
    let label = build.rekor_part_label(i + 2)
    let assert Ok(owner) = name.parse(label <> ".sync.test.")
    let assert Ok(set) =
      list.find(rrsets, fn(r) { r.owner == owner && r.rtype == wire.type_txt })
    let assert [one] = set.rdatas
    assert chunks(one) == Ok(part)
    assert list.contains(build.owners_in_order(rrsets), owner)
  })
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
        <<>>,
        0,
        3600,
        1_209_600,
        604_800,
      ),
      [NsHost(ns1, "127.0.0.1", "")],
      [],
      [],
      0,
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
///
/// The link list comes from the generator rather than being restated here,
/// so editing `gen_crossval` without re-running it fails this test instead
/// of leaving the checked-in bytes describing a chain nobody builds. The
/// Rust suite restates the structure independently — that restatement, not
/// this one, is the cross-language check.
pub fn the_chain_extension_encodes_the_crossval_bytes_test() {
  assert cert.encode_chain(gen_crossval.links())
    == fixture("crossval/chain.der")
}

/// The long-form DER lengths, which the fixture reaches only because two of
/// its links are deliberately large.
///
/// A chain of real DNSKEY/DS/RRSIG sets is kilobytes, so long-form lengths
/// are what production uses everywhere and short-form is the case that
/// almost never runs. An earlier fixture was 30 bytes — two links of 3 and
/// 2 rdata bytes — so both sides' long-form encoders were untested by the
/// thing whose whole job is keeping them together.
pub fn the_crossval_chain_exercises_both_der_length_forms_test() {
  let der = fixture("crossval/chain.der")
  // 200 bytes of rdata: OCTET STRING, one-byte long form.
  assert contains(der, <<0x04, 0x81, 0xc8>>)
  // 256: two-byte long form.
  assert contains(der, <<0x04, 0x82, 0x01, 0x00>>)
  // And the short form is still present, so neither replaced the other.
  assert contains(der, <<0x04, 0x03, 0xaa, 0xbb, 0xcc>>)
  // The outer SEQUENCE is over 255 bytes, so its own length is long-form.
  let assert <<0x30, first_len_byte:8, _:bits>> = der
  assert int.bitwise_and(first_len_byte, 0x80) == 0x80
}

/// A certificate this side builds, read back by this side and — from the
/// checked-in copy — by the Rust parser.
pub fn a_built_certificate_carries_its_key_its_name_and_its_extensions_test() {
  let csk = keys.generate()
  let links = [cert.Link("sync.test.", <<0xaa, 0xbb>>)]
  let der =
    cert.build(
      "sync.test.",
      csk.public,
      csk.private,
      1_786_866_288,
      1_786_866_288 + 3_155_760_000,
      Some(links),
    )
  let assert Ok(#(spki, san)) = cert_spki_and_san(der)
  assert spki == proof.p256_spki(csk.public)
  // The SAN is the apex without its root dot: a dNSName is a hostname.
  assert san == "sync.test"
  let assert Ok(chain_value) = cert_extension(der, cert.oid_dnssec_chain)
  assert chain_value == cert.encode_chain(links)

  // A chainless certificate has no chain extension at all — the shape a
  // `retire` breadcrumb takes, and the shape a client refuses.
  let bare = cert.build("sync.test.", csk.public, csk.private, 0, 1, None)
  let assert Error(Nil) = cert_extension(bare, cert.oid_dnssec_chain)
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
}

/// The publisher refuses when the chain cannot be built.
///
/// Which is the ordinary failure of the inverted ceremony (§5.2): logging
/// now happens *after* the DS is live in the parent, so "the DS is not there
/// yet" is the error an operator meets, and it says so.
pub fn publish_refuses_when_the_chain_cannot_be_collected_test() {
  let conn = fixtures.fresh_conn()
  let _csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())

  let assert Error(rekor_publish.NoChain(why)) =
    rekor_publish.run(
      conn,
      apex,
      apex,
      log,
      #(spki, point),
      1000,
      silent_resolver(),
      rekor_publish.Current,
    )
  // Against a resolver that answers nothing, the first thing missing is the
  // chain's bottom link — the declaration — and the refusal names it rather
  // than reaching for the DS, which is a later link's problem.
  assert string.contains(why, "_synchronicity-transparency")
  let assert Ok([]) = store.servable(conn, [])
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
      apex,
      log,
      #(spki, point),
      1000,
      silent_resolver(),
      rekor_publish.Retire([keys.dnskey_rdata(csk)]),
    )
  assert outcome.action == "retire"
  assert outcome.chainless
  assert outcome.key_tags == [keys.key_tag(keys.dnskey_rdata(csk))]
  // And it is never served to a client: a retire is a monitor breadcrumb.
  let assert Ok([]) = store.servable(conn, [])
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

  // The DER an OID gets: tag 0x06, length 6, then 0x69 (= 40 × 2 + 25) and
  // the arc in base-128. Byte-identical to crates/synch-net/src/zonecert.rs.
  let der = fixture("crossval/certificate.der")
  assert contains(der, <<0x06, 0x06, 0x69, 0x85, 0xe5, 0xe9, 0xb2, 0x07>>)

  // And the arc is the first four bytes of its UUID masked to 31 bits, so a
  // future edit cannot pick a new number and keep the explanation.
  assert oid_arc(cert.oid_dnssec_chain)
    == int.bitwise_and(0xdcba5907, int32_max)
}

fn oid_arc(oid: #(Int, Int, Int)) -> Int {
  oid.2
}

fn contains(haystack: BitArray, needle: BitArray) -> Bool {
  let size = bit_array.byte_size(needle)
  scan_for(haystack, needle, size, bit_array.byte_size(haystack) - size)
}

fn scan_for(haystack: BitArray, needle: BitArray, size: Int, at: Int) -> Bool {
  case at < 0 {
    True -> False
    False ->
      case bit_array.slice(haystack, at, size) == Ok(needle) {
        True -> True
        False -> scan_for(haystack, needle, size, at - 1)
      }
  }
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

/// A chain that is not declaration-then-ladder-to-root is refused before it
/// is ever published — while an operator is still standing there to read why.
pub fn a_malformed_chain_is_refused_before_publishing_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let declaration = chain.Link("_synchronicity-transparency.sync.test.", <<0>>)
  let full = [
    declaration,
    chain.Link("sync.test.", <<1>>),
    chain.Link("test.", <<2>>),
    chain.Link(".", <<3>>),
  ]
  let assert Ok(Nil) = chain.check_shape(full, apex, apex)

  // No declaration: a bare ladder is public data anyone could have collected,
  // so it is not this zone's statement about itself.
  let bare = [
    chain.Link("sync.test.", <<1>>),
    chain.Link("test.", <<2>>),
    chain.Link(".", <<3>>),
  ]
  let assert Error(why) = chain.check_shape(bare, apex, apex)
  assert string.contains(why, "_synchronicity-transparency")

  // A TLD DNSKEY on top, anchoring against nothing any reader holds.
  let rootless = [
    declaration,
    chain.Link("sync.test.", <<1>>),
    chain.Link("test.", <<2>>),
  ]
  let assert Error(why) = chain.check_shape(rootless, apex, apex)
  assert string.contains(why, "root")

  // A ladder link that is not an ancestor of the link below it at all.
  let assert Ok(other) = name.parse("other.test.")
  let sideways = [
    declaration,
    chain.Link("sync.test.", <<1>>),
    chain.Link("other.test.", <<2>>),
    chain.Link(".", <<3>>),
  ]
  let assert Error(why) = chain.check_shape(sideways, apex, apex)
  assert string.contains(why, "not an ancestor")

  // A signing zone that does not contain the apex is not the authority for
  // it, whatever else the chain carries — the rule chain.rs:305 enforces.
  let assert Error(why) =
    chain.check_shape(
      [
        chain.Link("_synchronicity-transparency.sync.test.", <<0>>),
        chain.Link("other.test.", <<1>>),
        chain.Link("test.", <<2>>),
        chain.Link(".", <<3>>),
      ],
      apex,
      other,
    )
  assert string.contains(why, "does not contain the apex")

  // A declaration for somebody else's zone.
  let assert Error(_) =
    chain.check_shape(
      [
        chain.Link("_synchronicity-transparency.other.test.", <<0>>),
        chain.Link("other.test.", <<1>>),
        chain.Link(".", <<3>>),
      ],
      apex,
      apex,
    )
  let assert Error(_) = chain.check_shape([declaration], apex, apex)
  let assert Error(_) = chain.check_shape([], apex, apex)
}

// ------------------------------------------- what a record must be to serve

/// The publisher's part bound is the reader's part bound.
///
/// A proof in seventeen parts publishes perfectly well and then no client can
/// assemble it: `MAX_PROOF_PARTS` fetches parts 2..=16 and stops. One number,
/// named once, refused on this side too.
pub fn a_proof_needing_more_parts_than_a_reader_fetches_is_refused_test() {
  let base = fixture_proof()
  let biggest =
    Proof(..base, statement: <<
      0:size(
        8
        * proof.max_parts
        * proof.txt_chunk_chars
      ),
    >>)
  let assert Error(why) = proof.to_txt(biggest)
  assert string.contains(why, int.to_string(proof.max_parts))

  // And what fits is unaffected: the fixture is a handful of parts.
  let assert Ok(records) = proof.to_txt(base)
  assert list.length(records) <= proof.max_parts
}

/// The gate asks whether a row exists; a client asks whether the proof name
/// exists. Those are the same question only if a row that cannot be rendered
/// is never stored.
pub fn publish_refuses_a_record_the_zone_could_not_serve_test() {
  let conn = fixtures.fresh_conn()
  let _csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())
  // A zone serving an enormous DNSKEY RRset: the chain goes into the entry's
  // certificate, so the record this would become needs far more TXT parts
  // than any reader assembles.
  let huge = rdata.dnskey(257, 13, <<0:size(80_000)>>)
  let assert Error(rekor_publish.Unservable(why)) =
    rekor_publish.run(
      conn,
      apex,
      apex,
      log,
      #(spki, point),
      1000,
      fake_resolver_serving([huge]),
      rekor_publish.Current,
    )
  assert string.contains(why, "records")
  // Nothing stored, so nothing for the gate to pass on.
  let assert Ok([]) = store.servable(conn, [])
  sqlite.close(conn)
}

/// And at serve time a row that will not render is a loud failure rather than
/// a quiet omission: dropping it published a zone whose own gate said it was
/// fine while every client failed closed on a proof name that did not exist.
pub fn a_damaged_proof_row_fails_the_read_rather_than_vanishing_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let rd = keys.dnskey_rdata(csk)
  let assert Ok(Nil) =
    store.put(
      conn,
      store.Record(
        keyset_sha256: crypto.hash(crypto.Sha256, rd),
        apex: "sync.test.",
        action: "create",
        statement: <<"{}":utf8>>,
        canonicalized_body: <<0:size(512)>>,
        log_id: <<0:size(256)>>,
        log_index: 0,
        checkpoint: <<>>,
        // Not a run of 32-byte hashes: this row cannot become a proof.
        inclusion_path: <<0:size(120)>>,
        chainless: False,
        integrated_at: 1,
        verified_at: 1,
        keys: [#(crypto.hash(crypto.Sha256, rd), keys.key_tag(rd))],
      ),
    )
  let assert Error(model.UnservableProof(_)) = model.read(conn)
  sqlite.close(conn)
}

// --------------------------------------------- agreeing with the client

/// Log key material is one key per PEM block or per line, which is what the
/// client's `LogKeys::parse` accepts: a file that names two keys reads as two
/// keys, and a PEM body wrapped across lines reads as one.
pub fn log_key_material_reads_a_key_per_block_test() {
  let first = proof.p256_spki(keys.generate().public)
  let second = proof.p256_spki(keys.generate().public)
  let encoded = fn(spki) { bit_array.base64_encode(spki, True) }
  let wrapped = fn(spki) {
    let text = encoded(spki)
    "-----BEGIN PUBLIC KEY-----\n"
    <> string.slice(text, 0, 64)
    <> "\n"
    <> string.drop_start(text, 64)
    <> "\n-----END PUBLIC KEY-----\n"
  }
  let file =
    "# the log keys this deployment pins\n"
    <> wrapped(first)
    <> encoded(second)
    <> "\n"
  let assert Ok([one, two]) = proof.parse_log_keys(file)
  assert one.0 == first
  assert two.0 == second

  // A publisher writes to one log and stores the proof under that log's id,
  // so two keys is an error rather than a silent choice between them.
  let assert Error(_) = proof.parse_log_key(file)
  let assert Ok(#(der, _point)) = proof.parse_log_key(encoded(second))
  assert der == second
  let assert Error(_) = proof.parse_log_keys("# nothing but a comment\n")
}

/// The two canonical renderers escape the same bytes the same way
/// (`json_string`, crates/synch-net/src/rekor.rs): quote, backslash, the three
/// named control escapes, and `\u00xx` in lowercase hex for the rest below
/// U+0020.
pub fn the_canonical_renderer_escapes_control_characters_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let rd = keys.dnskey_rdata(keys.generate())
  let rendered =
    statement.to_json(statement.for_keys(apex, [rd], "cre\u{1}ate\n\t\"\\"))
  let assert Ok(text) = bit_array.to_string(rendered)
  assert string.contains(text, "\"action\":\"cre\\u0001ate\\n\\t\\\"\\\\\"")
}

/// A DNSKEY rdata too short to hold the four-byte header renders as flags 0 and
/// algorithm 0 — both of them, rather than whatever partial values could be
/// read out of it. One rule, because the two renderers commit to one byte
/// string, and the collector refuses such a rdata long before this.
pub fn a_truncated_dnskey_rdata_has_no_flags_and_no_algorithm_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let assert [key] = statement.for_keys(apex, [<<1, 2, 3>>], "create").keys
  assert key.flags == 0
  assert key.algorithm == 0
}

/// An inclusion-proof hash is a 32-byte SHA-256 node. The stored form is a flat
/// run of them, so a short one would be re-split at the wrong boundary on the
/// way back out — the one place to refuse it is where the log's answer arrives.
pub fn a_short_inclusion_hash_is_refused_where_it_arrives_test() {
  let entry = fn(hash: BitArray) {
    "{\"logIndex\":\"7\",\"canonicalizedBody\":\"AAAA\",\"inclusionProof\":{"
    <> "\"hashes\":[\""
    <> bit_array.base64_encode(hash, True)
    <> "\"],\"checkpoint\":{\"envelope\":\"note\"}}}"
  }
  let assert Ok(parsed) = client.parse_entry(entry(<<0:size(256)>>))
  assert parsed.log_index == 7
  let assert Error(why) = client.parse_entry(entry(<<0:size(128)>>))
  assert string.contains(why, "32-byte")
}

// --------------------------------------------------- collecting the chain

/// A resolver over a described delegation: `zones` are the names that really
/// are zones, and every other name answers nothing at all — which is exactly
/// what an empty non-terminal looks like on the wire.
fn delegation_resolver(
  zones: List(String),
  declaration_owner: name.Name,
  dnskey_rd: BitArray,
) -> chain.Resolver {
  chain.Resolver(query: fn(zone, rtype) {
    let is_zone = list.contains(zones, name.to_string(zone))
    case rtype == wire.type_txt, rtype == wire.type_dnskey, is_zone {
      True, _, _ ->
        case zone == declaration_owner {
          True ->
            Ok([
              wire.Rr(
                zone,
                wire.type_txt,
                wire.class_in,
                300,
                rdata.txt(rdata.transparency_text),
              ),
              fake_rrsig(zone, wire.type_txt),
            ])
          False -> Ok([])
        }
      _, True, True -> Ok(dnskey_rrs(zone, [dnskey_rd]))
      // A DS that really covers the key this zone serves — the relation the
      // publisher checks before writing to a public log, and the one a
      // reader's ladder walk turns on.
      _, False, True ->
        Ok([ds_rr(zone, [dnskey_rd]), fake_rrsig(zone, chain.type_ds)])
      _, _, False -> Ok([])
    }
  })
}

/// A delegation can cross more than one label, and then the names in between
/// are empty non-terminals: no DNSKEY, no DS, nothing a link could carry.
///
/// The ladder is zone cuts, so the walk skips the name that is not a zone. A
/// link for an empty non-terminal carries no RRsets and every reader refuses
/// it, so a chain for such a zone has exactly one valid shape and this is it.
pub fn the_collector_walks_zone_cuts_not_labels_test() {
  let assert Ok(apex) = name.parse("cp.acme.sync.test.")
  let owner = name.parse("_synchronicity-transparency.cp.acme.sync.test.")
  let assert Ok(owner) = owner
  let rd = keys.dnskey_rdata(keys.generate())
  // `sync.test` delegates `cp.acme.sync.test` directly: there is no zone at
  // `acme.sync.test` for anybody to ask about.
  let resolver =
    delegation_resolver(
      ["cp.acme.sync.test.", "sync.test.", "test.", "."],
      owner,
      rd,
    )
  let assert Ok(#(links, rdatas)) = chain.collect(resolver, apex, apex)
  assert rdatas == [rd]
  assert list.map(links, fn(link) { link.zone })
    == [
      "_synchronicity-transparency.cp.acme.sync.test.", "cp.acme.sync.test.",
      "sync.test.", "test.", ".",
    ]
  // And the shape rules agree with the walk that produced it.
  let assert Ok(Nil) = chain.check_shape(links, apex, apex)
}

/// The two halves of a zone cut have to arrive together. A DS with no DNSKEY
/// is a delegation to an unsigned zone; a DNSKEY with no DS is a signed zone
/// its parent delegates insecurely. Either way no reader can walk past that
/// name, so the collection fails where somebody is watching it.
pub fn the_collector_refuses_a_broken_delegation_test() {
  let assert Ok(apex) = name.parse("cp.sync.test.")
  let assert Ok(owner) = name.parse("_synchronicity-transparency.cp.sync.test.")
  let rd = keys.dnskey_rdata(keys.generate())
  let whole =
    delegation_resolver(
      ["cp.sync.test.", "sync.test.", "test.", "."],
      owner,
      rd,
    )

  // `sync.test` answers a DS but no DNSKEY.
  let unsigned =
    chain.Resolver(query: fn(zone, rtype) {
      case name.to_string(zone) == "sync.test." && rtype == wire.type_dnskey {
        True -> Ok([])
        False -> whole.query(zone, rtype)
      }
    })
  let assert Error(why) = chain.collect(unsigned, apex, apex)
  assert string.contains(why, "unsigned")

  // `sync.test` answers a DNSKEY but its parent holds no DS for it.
  let islanded =
    chain.Resolver(query: fn(zone, rtype) {
      case name.to_string(zone) == "sync.test." && rtype == chain.type_ds {
        True -> Ok([])
        False -> whole.query(zone, rtype)
      }
    })
  let assert Error(why) = chain.collect(islanded, apex, apex)
  assert string.contains(why, "insecure")
}

/// Only the records a link owns go into it: `ParsedLink::parse` refuses a link
/// holding a record its own name does not own, so an extra RR a resolver
/// decided to include would make the whole entry unverifiable.
pub fn the_collector_copies_only_what_the_link_owns_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let rd = keys.dnskey_rdata(keys.generate())
  let clean = fake_resolver_serving([rd])
  let assert Ok(stray_owner) = name.parse("stray.example.")
  let padded =
    chain.Resolver(query: fn(zone, rtype) {
      use answers <- result.try(clean.query(zone, rtype))
      Ok(
        list.append(answers, [
          wire.Rr(stray_owner, rtype, wire.class_in, 3600, <<
            7:int-size(16),
            13:int-size(8),
            2:int-size(8),
            9:size(256),
          >>),
          fake_rrsig(stray_owner, rtype),
        ]),
      )
    })
  let assert Ok(#(honest, _)) = chain.collect(clean, apex, apex)
  let assert Ok(#(collected, _)) = chain.collect(padded, apex, apex)
  assert list.map(collected, fn(link) { link.rrs })
    == list.map(honest, fn(link) { link.rrs })
}

/// The two rules a reader applies to the declaration, applied here too: an
/// RRSIG covering fewer labels than its owner was expanded from a wildcard, so
/// the zone published no declaration of its own; and an RRSIG signed by
/// anything but the signing zone was not made by the authority the chain
/// claims holds the record.
pub fn the_collector_refuses_a_declaration_no_reader_would_take_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let assert Ok(owner) = name.parse("_synchronicity-transparency.sync.test.")
  let rd = keys.dnskey_rdata(keys.generate())
  let clean = fake_resolver_serving([rd])

  let with_declaration_sig = fn(sig: BitArray) {
    chain.Resolver(query: fn(zone, rtype) {
      case zone == owner && rtype == wire.type_txt {
        True ->
          Ok([
            wire.Rr(
              zone,
              wire.type_txt,
              wire.class_in,
              300,
              rdata.txt(rdata.transparency_text),
            ),
            wire.Rr(zone, wire.type_rrsig, wire.class_in, 300, sig),
          ])
        False -> clean.query(zone, rtype)
      }
    })
  }

  let wildcard =
    rdata.rrsig(wire.type_txt, 13, 2, 300, 0, 0, 1234, apex, <<0:size(512)>>)
  let assert Error(why) =
    chain.collect(with_declaration_sig(wildcard), apex, apex)
  assert string.contains(why, "wildcard")

  let assert Ok(stranger) = name.parse("other.test.")
  let wrong_signer =
    rdata.rrsig(wire.type_txt, 13, 3, 300, 0, 0, 1234, stranger, <<0:size(512)>>)
  let assert Error(why) =
    chain.collect(with_declaration_sig(wrong_signer), apex, apex)
  assert string.contains(why, "as its signer")
}

/// A DNSKEY the claim's digests are computed over has to be reconstructible by
/// a reader, which rebuilds the rdata as flags ‖ 3 ‖ algorithm ‖ key. RFC 4034
/// §2.1.2 permits no other protocol byte, so one is a rdata this side will not
/// claim rather than a rdata the two sides would digest differently.
pub fn the_collector_refuses_a_dnskey_it_could_not_reconstruct_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let wrong_protocol = <<
    257:int-size(16),
    4:int-size(8),
    13:int-size(8),
    0:size(512),
  >>
  let assert Error(why) =
    chain.collect(fake_resolver_serving([wrong_protocol]), apex, apex)
  assert string.contains(why, "protocol 3")

  let truncated = <<257:int-size(16)>>
  let assert Error(_) =
    chain.collect(fake_resolver_serving([truncated]), apex, apex)
}

/// A resolver that declines to answer (SERVFAIL & co.) is not saying the
/// RRset is absent, and must never be read that way: the key watch's quiet
/// wait and the collector's "published yet?" hint are only truthful answers
/// to an answer that genuinely says nothing is there.
pub fn response_answers_reads_only_real_answers_test() {
  let assert Ok(owner) = name.parse("sync.test.")
  let rr = wire.Rr(owner, wire.type_txt, wire.class_in, 300, <<"v=sync1">>)
  let message = fn(flags, answers) {
    wire.Message(0, flags, [], answers, [], [])
  }

  // NOERROR, with and without records.
  let assert Ok([_]) = chain.response_answers("doh.test", message(0x8000, [rr]))
  let assert Ok([]) = chain.response_answers("doh.test", message(0x8000, []))
  // NXDOMAIN is a genuine absence too, not a fault.
  let assert Ok([]) = chain.response_answers("doh.test", message(0x8003, []))

  // SERVFAIL: a validating resolver's verdict — an error, never an RRset.
  let assert Error(why) =
    chain.response_answers("doh.test", message(0x8002, []))
  assert string.contains(why, "SERVFAIL")
  assert string.contains(why, "doh.test")

  let assert Error(why) =
    chain.response_answers("doh.test", message(0x8005, []))
  assert string.contains(why, "REFUSED")
}

// ------------------------------------------------------ the key rollover

/// The deadlock the staging slot exists to break.
///
/// With the gate armed, a zone key could not be replaced at all. The gate
/// demands the active key already be on the public record; `rekor-publish`
/// claims the key set it reads out of *live DNS*; and a key cannot be in
/// live DNS before the zone serves it. Replacing the key therefore required
/// publishing it, which required having logged it, which required having
/// published it.
///
/// Staging breaks the cycle by letting the incoming key be *published*
/// without being *active*: it rides in the DNSKEY RRset, where the parent
/// and the log can both see it, while the outgoing key keeps signing.
pub fn a_staged_key_is_published_without_becoming_the_signer_test() {
  let conn = fixtures.fresh_conn()
  let active = fixtures.zone_boot(conn)
  let incoming = keys.generate()

  let assert Ok(_) =
    publish.stage_incoming(conn, active, incoming.public, 1000, "test")

  // Both keys are in the RRset the zone serves...
  let assert Ok(meta) = model.read_meta(conn)
  assert meta.dnskey_public == active.public
  assert meta.dnskey_incoming == incoming.public
  assert meta.key_tag_incoming == keys.key_tag(keys.dnskey_rdata(incoming))
  let assert Ok(input) = model.read(conn)
  let assert Ok(rrsets) = build.build(input)
  let assert Ok(dnskey) =
    list.find(rrsets, fn(r) { r.rtype == wire.type_dnskey })
  assert list.length(dnskey.rdatas) == 2

  // ...but the active key is still the only signer, so the zone stays
  // valid under the DS the parent already published.
  assert meta.key_tag == keys.key_tag(keys.dnskey_rdata(active))
  sqlite.close(conn)
}

/// Staging is not gated, and it must not be: the signing key is unchanged
/// and already on the record, so there is no new claim for the gate to
/// hold back — and if staging *were* gated the deadlock would simply move.
pub fn staging_is_allowed_while_the_gate_is_armed_test() {
  let conn = fixtures.fresh_conn()
  let active = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())
  let assert Ok(_) = publish_run(conn, apex, active, log, #(spki, point), 1000)

  use <- fixtures.with_gate_armed
  let incoming = keys.generate()
  let assert Ok(_) =
    publish.stage_incoming(conn, active, incoming.public, 1000, "test")
  sqlite.close(conn)
}

/// Promotion *is* gated, and refuses the incoming key until it has been
/// logged — which is the ordering the whole sequence exists to enforce.
pub fn promotion_refuses_a_key_that_was_never_logged_test() {
  let conn = fixtures.fresh_conn()
  let active = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())
  let assert Ok(_) = publish_run(conn, apex, active, log, #(spki, point), 1000)

  let incoming = keys.generate()
  let assert Ok(_) =
    publish.stage_incoming(conn, active, incoming.public, 1000, "test")

  use <- fixtures.with_gate_armed
  // The record covers the outgoing key, not the incoming one.
  let assert Error(publish.NoRekorRecord(tag)) =
    publish.promote_incoming(conn, incoming, 1000, "test")
  assert tag == keys.key_tag(keys.dnskey_rdata(incoming))

  // Nothing moved: a refused promotion must not half-apply.
  let assert Ok(meta) = model.read_meta(conn)
  assert meta.dnskey_public == active.public
  assert meta.dnskey_incoming == incoming.public
  sqlite.close(conn)
}

/// The whole sequence, in the order an operator runs it.
pub fn a_logged_staged_key_can_be_promoted_test() {
  let conn = fixtures.fresh_conn()
  let active = fixtures.zone_boot(conn)
  let incoming = keys.generate()
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())

  // 1. stage, 2. (parent publishes the DS), 3. log the set that now
  // contains both keys.
  let assert Ok(_) =
    publish.stage_incoming(conn, active, incoming.public, 1000, "test")
  let assert Ok(_) =
    publish_run_claiming(
      conn,
      apex,
      [keys.dnskey_rdata(active), keys.dnskey_rdata(incoming)],
      log,
      #(spki, point),
      1000,
    )

  // 4. promote — accepted now, because the log entry covers the incoming key.
  use <- fixtures.with_gate_armed
  let assert Ok(_) = publish.promote_incoming(conn, incoming, 1000, "test")

  let assert Ok(meta) = model.read_meta(conn)
  assert meta.dnskey_public == incoming.public
  assert meta.key_tag == keys.key_tag(keys.dnskey_rdata(incoming))
  // The outgoing key has left the RRset, so the zone stops asking the world
  // to trust a key it no longer signs with.
  assert meta.dnskey_incoming == <<>>
  assert meta.key_tag_incoming == 0
  let assert Ok(input) = model.read(conn)
  let assert Ok(rrsets) = build.build(input)
  let assert Ok(dnskey) =
    list.find(rrsets, fn(r) { r.rtype == wire.type_dnskey })
  assert list.length(dnskey.rdatas) == 1
  sqlite.close(conn)
}

/// Promotion with nothing staged, and staging the key already in service:
/// both are operator slips that must not silently do something.
pub fn the_rollover_commands_refuse_incoherent_input_test() {
  let conn = fixtures.fresh_conn()
  let active = fixtures.zone_boot(conn)
  let assert Error(publish.NoIncomingKey) =
    publish.promote_incoming(conn, active, 1000, "test")
  let assert Error(publish.IncomingIsActive) =
    publish.stage_incoming(conn, active, active.public, 1000, "test")

  // And promoting with the wrong key file is a mismatch, not a promotion
  // of whatever happens to be staged.
  let incoming = keys.generate()
  let assert Ok(_) =
    publish.stage_incoming(conn, active, incoming.public, 1000, "test")
  let assert Error(publish.KeyMismatch) =
    publish.promote_incoming(conn, keys.generate(), 1000, "test")
  sqlite.close(conn)
}

/// Booting with the staged key file says which step is missing.
///
/// The generic "does not match the key this zone was created with" sends an
/// operator mid-rollover looking for a key file that is not the problem.
pub fn booting_with_the_staged_key_names_the_missing_step_test() {
  let conn = fixtures.fresh_conn()
  let active = fixtures.zone_boot(conn)
  let incoming = keys.generate()
  let assert Ok(_) =
    publish.stage_incoming(conn, active, incoming.public, 1000, "test")
  let assert Error(message) = publish.ensure_meta(conn, "sync.test", incoming)
  assert string.contains(message, "staged incoming key")
  assert string.contains(message, "zone-key promote")
  sqlite.close(conn)
}

// ---------------------------------------------------------- zonekey watch

fn dnskey_rrs(zone: name.Name, rdatas: List(BitArray)) -> List(wire.Rr) {
  list.append(
    list.map(rdatas, fn(rd) {
      wire.Rr(zone, wire.type_dnskey, wire.class_in, 3600, rd)
    }),
    [fake_rrsig(zone, wire.type_dnskey)],
  )
}

/// One tick is three DNSKEY queries at the signing zone: two for the
/// corroborated observation, one for the chain the claim carries. The mailbox
/// is preloaded in that order.
/// `ds_key` is the key the apex's DS covers — a key present in every
/// scripted answer, so the delegation the collector checks is intact across
/// the whole sequence rather than only on the tick that happened to observe
/// it.
fn split_resolver(
  zone: name.Name,
  answers: process.Subject(List(BitArray)),
  ds_key: BitArray,
) -> chain.Resolver {
  chain.Resolver(query: fn(qzone, rtype) {
    let rrsig = fake_rrsig(qzone, rtype)
    case rtype == wire.type_dnskey && qzone == zone {
      True -> {
        let rdatas = case process.receive(answers, 0) {
          Ok(rds) -> rds
          Error(Nil) -> []
        }
        Ok(dnskey_rrs(qzone, rdatas))
      }
      False ->
        case rtype == wire.type_txt {
          // The declaration, spelled the way every reader checks for it.
          True ->
            Ok([
              wire.Rr(
                qzone,
                wire.type_txt,
                wire.class_in,
                300,
                rdata.txt(rdata.transparency_text),
              ),
              rrsig,
            ])
          // A DS covering whatever key this zone is currently serving. The
          // subject is drained by the observation reads, so the DS is built
          // from the zone's own key rather than a constant that covers
          // nothing.
          // Every other name answers as a signed zone would: its own DNSKEY
          // RRset, and a DS covering a key that RRset actually holds.
          False ->
            case rtype == wire.type_dnskey {
              True -> Ok(dnskey_rrs(qzone, [dnskey_for(qzone)]))
              False ->
                case qzone == zone {
                  True -> Ok([ds_rr(qzone, [ds_key]), rrsig])
                  False -> Ok([ds_rr(qzone, [dnskey_for(qzone)]), rrsig])
                }
            }
        }
    }
  })
}

/// A stable per-zone DNSKEY rdata for fixtures that need a DS to cover
/// *something* without consuming a scripted answer.
fn dnskey_for(zone: name.Name) -> BitArray {
  bit_array.concat([
    <<257:int-size(16), 3:int-size(8), 13:int-size(8)>>,
    crypto.hash(crypto.Sha256, bit_array.from_string(name.to_string(zone))),
    crypto.hash(crypto.Sha256, bit_array.from_string(name.to_string(zone))),
  ])
}

pub fn the_watcher_waits_quietly_for_the_declaration_test() {
  let conn = fixtures.fresh_conn()
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki, point) = fake_log(keys.generate())
  assert zonekey_watch.run_once_with(
      conn,
      apex,
      apex,
      silent_resolver(),
      log,
      #(spki, point),
      1000,
    )
    == zonekey_watch.WaitingForDeclaration
  sqlite.close(conn)
}

/// A declaration that does not read `v=sync1 transparency` stops the publish.
///
/// Every reader checks the *text* rather than counting records, so an entry
/// whose bottom link carries anything else verifies at no client and
/// classifies tier B at every monitor. Publishing is a permanent, public,
/// irreversible write, so the place to find this out is here.
pub fn a_declaration_that_says_nothing_is_refused_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let rd = keys.dnskey_rdata(keys.generate())
  let resolver =
    chain.Resolver(query: fn(zone, rtype) {
      case rtype == wire.type_txt {
        // A TXT at the right name saying the wrong thing — a leftover record,
        // or a zone that has not published its declaration yet.
        True ->
          Ok([
            wire.Rr(
              zone,
              wire.type_txt,
              wire.class_in,
              300,
              rdata.txt("v=spf1 -all"),
            ),
            fake_rrsig(zone, wire.type_txt),
          ])
        False ->
          case rtype == wire.type_dnskey {
            True -> Ok(dnskey_rrs(zone, [rd]))
            False -> Ok([ds_rr(zone, [rd]), fake_rrsig(zone, chain.type_ds)])
          }
      }
    })
  let assert Error(why) = chain.collect(resolver, apex, apex)
  assert string.contains(why, "v=sync1 transparency")
}

/// A DS that covers none of the keys the zone serves stops the publish.
///
/// Both RRsets are individually well-formed and individually signed, so
/// nothing else in the collector notices — this is what a rollover caught
/// mid-propagation looks like from a resolver, and the chain it produces
/// walks at no reader.
pub fn a_ds_that_covers_no_served_key_is_refused_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let served = keys.dnskey_rdata(keys.generate())
  let other = keys.dnskey_rdata(keys.generate())
  let resolver =
    chain.Resolver(query: fn(zone, rtype) {
      case rtype == wire.type_txt {
        True ->
          Ok([
            wire.Rr(
              zone,
              wire.type_txt,
              wire.class_in,
              300,
              rdata.txt(rdata.transparency_text),
            ),
            fake_rrsig(zone, wire.type_txt),
          ])
        False ->
          case rtype == wire.type_dnskey {
            True -> Ok(dnskey_rrs(zone, [served]))
            // The parent's DS names a key this zone does not serve.
            False ->
              Ok([ds_rr(zone, [other]), fake_rrsig(zone, chain.type_ds)])
          }
      }
    })
  let assert Error(why) = chain.collect(resolver, apex, apex)
  assert string.contains(why, "covered by a DS")
}

pub fn the_watcher_stamps_only_keys_the_claim_covers_test() {
  let conn = fixtures.fresh_conn()
  let assert Ok(apex) = name.parse("sync.test.")
  let a = keys.dnskey_rdata(keys.generate())
  let b = keys.dnskey_rdata(keys.generate())
  let answers = process.new_subject()
  // Per tick: observe {A,B} twice — the two reads have to agree before the
  // watcher acts — then collect {A}, so the claim covers A alone.
  process.send(answers, [a, b])
  process.send(answers, [a, b])
  process.send(answers, [a])
  process.send(answers, [a, b])
  process.send(answers, [a, b])
  process.send(answers, [a])
  let resolver = split_resolver(apex, answers, a)
  let submits = process.new_subject()
  let #(inner, spki, point) = fake_log(keys.generate())
  let log =
    client.Log(submit: fn(sub) {
      process.send(submits, "submit")
      inner.submit(sub)
    })

  assert zonekey_watch.run_once_with(
      conn,
      apex,
      apex,
      resolver,
      log,
      #(spki, point),
      1000,
    )
    == zonekey_watch.Logged
  let assert Ok("submit") = process.receive(submits, 100)

  let assert Ok(keys) = state.observed_keys(conn)
  let logged =
    list.filter_map(keys, fn(key) {
      case key.logged_at {
        Some(_) -> Ok(key.key_sha256)
        None -> Error(Nil)
      }
    })
  assert logged == [crypto.hash(crypto.Sha256, a)]
  assert list.length(keys) == 2

  // B is still unlogged, so the next tick is not treated as fully covered.
  assert zonekey_watch.run_once_with(
      conn,
      apex,
      apex,
      resolver,
      log,
      #(spki, point),
      2000,
    )
    == zonekey_watch.Logged
  let assert Ok("submit") = process.receive(submits, 100)
  sqlite.close(conn)
}

/// The observation prunes the stored key set, and the stored key set is what
/// the served proofs are held to — so one bad answer would delete a live key's
/// proof records. Two reads that disagree are not an answer to act on.
pub fn the_watcher_will_not_act_on_an_unconfirmed_answer_test() {
  let conn = fixtures.fresh_conn()
  let assert Ok(apex) = name.parse("sync.test.")
  let a = keys.dnskey_rdata(keys.generate())
  let b = keys.dnskey_rdata(keys.generate())
  let answers = process.new_subject()
  // A first tick that agrees with itself: {A} is observed and logged.
  process.send(answers, [a])
  process.send(answers, [a])
  process.send(answers, [a])
  // Then an answer that says {B}, contradicted by the read beside it.
  process.send(answers, [b])
  process.send(answers, [a])
  let resolver = split_resolver(apex, answers, a)
  let #(log, spki, point) = fake_log(keys.generate())
  let tick = fn(now) {
    zonekey_watch.run_once_with(
      conn,
      apex,
      apex,
      resolver,
      log,
      #(spki, point),
      now,
    )
  }

  assert tick(1000) == zonekey_watch.Logged
  let assert Ok([logged]) = state.observed_keys(conn)
  assert logged.key_sha256 == crypto.hash(crypto.Sha256, a)

  // Nothing is logged and — the point — nothing is deleted: A's row survives,
  // and with it the proof the zone serves for A.
  assert tick(2000) == zonekey_watch.Quiet
  let assert Ok([survivor]) = state.observed_keys(conn)
  assert survivor.key_sha256 == crypto.hash(crypto.Sha256, a)
  assert survivor.logged_at == Some(1000)
  sqlite.close(conn)
}

/// The claim names the keys the RRset authorizes, and nothing else.
///
/// A reader's chain walk excludes a key without the Zone Key flag and a key
/// carrying RFC 5011's REVOKE bit — neither may verify an RRSIG, so neither is
/// part of the authorized set. A claim naming one would describe a set no
/// client derives, and every client would refuse the entry as a set its chain
/// does not prove. The RRset itself still travels whole, because its RRSIG
/// covers all of it.
pub fn the_claim_names_only_the_keys_the_rrset_authorizes_test() {
  let assert Ok(apex) = name.parse("cp.sync.test.")
  let owner = name.parse("_synchronicity-transparency.cp.sync.test.")
  let assert Ok(owner) = owner
  let csk = keys.generate()
  let usable = keys.dnskey_rdata(csk)
  let not_a_zone_key = rdata.dnskey(0x0001, keys.algorithm, csk.public)
  let revoked = rdata.dnskey(0x0181, keys.algorithm, csk.public)

  let base =
    delegation_resolver(
      ["cp.sync.test.", "sync.test.", "test.", "."],
      owner,
      usable,
    )
  let resolver =
    chain.Resolver(query: fn(zone, rtype) {
      case rtype == wire.type_dnskey && zone == apex {
        True -> Ok(dnskey_rrs(zone, [usable, not_a_zone_key, revoked]))
        False -> base.query(zone, rtype)
      }
    })

  let assert Ok(#(links, rdatas)) = chain.collect(resolver, apex, apex)
  assert rdatas == [usable]
  // The link still carries all three, or the RRSIG over the RRset would not
  // verify for any reader.
  let assert [_declaration, apex_link, ..] = links
  assert bit_array.byte_size(apex_link.rrs) > bit_array.byte_size(usable) * 3
}

/// A zone whose apex RRset authorizes nothing cannot publish a claim.
pub fn a_zone_with_no_usable_key_has_nothing_to_claim_test() {
  let assert Ok(apex) = name.parse("cp.sync.test.")
  let owner = name.parse("_synchronicity-transparency.cp.sync.test.")
  let assert Ok(owner) = owner
  let csk = keys.generate()
  let revoked = rdata.dnskey(0x0181, keys.algorithm, csk.public)

  let base =
    delegation_resolver(
      ["cp.sync.test.", "sync.test.", "test.", "."],
      owner,
      keys.dnskey_rdata(csk),
    )
  let resolver =
    chain.Resolver(query: fn(zone, rtype) {
      case rtype == wire.type_dnskey && zone == apex {
        True -> Ok(dnskey_rrs(zone, [revoked]))
        False -> base.query(zone, rtype)
      }
    })

  let assert Error(why) = chain.collect(resolver, apex, apex)
  assert string.contains(why, "usable zone key")
}
