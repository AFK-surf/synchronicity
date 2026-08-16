//// Zone-key transparency, from this side of the port program.
////
//// The wire formats themselves are no longer implemented here, so they are
//// no longer tested here: the Statement rendering, the DER, the Merkle walk
//// and the checkpoint parser live in crates/synch-net and are asserted
//// against a genuinely published Rekor entry
//// (crates/synch-net/tests/rekor_zone_key.rs). What is still this side's is
//// the ceremony — which action, which predecessor, what to reuse, what to
//// store, what to serve — and the framed protocol that reaches the formats.
////
//// The load-bearing test is the first one: the checked-in proof
//// (test/fixtures/rekor, written by the Rust sim) goes through the port
//// program and comes back verified, and re-encoded to exactly the bytes on
//// disk. It exercises the whole path this refactor introduced — framing,
//// key pinning, trust anchors, verification, encoding — against bytes
//// neither side can quietly regenerate.

import dns/name
import dns/rdata
import dns/wire
import dnssec/keys
import dnssec/sign
import envoy
import fixtures
import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import rekor/chain
import rekor/client
import rekor/gate
import rekor/port
import rekor/publish as rekor_publish
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

/// The zone key the fixture is about: the DNSKEY rdata minus its four-byte
/// header is exactly the algorithm 13 public key.
fn fixture_public() -> BitArray {
  let rd = fixture("dnskey.bin")
  let assert Ok(public) = bit_array.slice(rd, 4, 64)
  public
}

fn open_port() -> port.Session {
  let assert Ok(session) = port.open()
  session
}

/// Writes a temp file and returns its path — the port program takes key
/// material and trust anchors by path, never as bytes.
fn temp_file(suffix: String, contents: BitArray) -> String {
  let path = fixtures.tmp_db() <> suffix
  let assert Ok(Nil) = simplifile.write_bits(path, contents)
  path
}

/// Splits a stored audit path into its 32-byte hashes.
fn split32(blob: BitArray) -> List(BitArray) {
  case blob {
    <<hash:bytes-size(32), rest:bits>> -> [hash, ..split32(rest)]
    _ -> []
  }
}

// ------------------------------------------------------------- the fixture

/// The checked-in entry, verified and re-encoded through the port program.
pub fn the_fixture_verifies_and_re_encodes_test() {
  let session = open_port()
  let assert Ok(#(spki, log_id)) =
    port.log_key(session, temp_file(".pem", fixture("log-key.pem")))
  // The log id convention is SHA-256 over the DER SubjectPublicKeyInfo — not
  // the C2SP note key id Rekor returns beside the checkpoint, which is
  // exactly as long and looks exactly as plausible.
  assert log_id == fixture("log-id.bin")

  let assert Ok(key_tag) = int.parse(meta("key_tag"))
  let assert Ok(log_index) = int.parse(meta("log_index"))
  let assert Ok(verified) =
    port.verify(
      session,
      apex: meta("apex"),
      public: fixture_public(),
      key_tag: key_tag,
      log_index: log_index,
      statement: fixture("statement.json"),
      canonicalized_body: fixture("canonicalized-body.bin"),
      checkpoint: fixture("checkpoint.txt"),
      inclusion_path: split32(fixture("inclusion-path.bin")),
      log_spki: spki,
      action: meta("action"),
      anchor_file: temp_file(".key", fixture("anchor.key")),
    )
  // The record the zone would serve is the checked-in one, byte for byte —
  // and it is base64url with no padding, because that is what a TXT record
  // carries.
  assert verified.proof_txt
    == bit_array.base64_url_encode(fixture("proof.bin"), False)
  assert !string.contains(verified.proof_txt, "=")
  assert verified.log_id == fixture("log-id.bin")
  assert verified.action == meta("action")
  assert !verified.chainless
  assert verified.countersigned_by == None
  assert verified.tree_size >= 1
  port.close(session)
}

/// The verification has teeth: break one thing at a time.
pub fn the_fixture_is_refused_when_anything_is_broken_test() {
  let session = open_port()
  let assert Ok(#(spki, _)) =
    port.log_key(session, temp_file(".pem", fixture("log-key.pem")))
  let anchor = temp_file(".key", fixture("anchor.key"))
  let assert Ok(key_tag) = int.parse(meta("key_tag"))
  let assert Ok(log_index) = int.parse(meta("log_index"))
  let attempt = fn(public, path, log_spki) {
    port.verify(
      session,
      apex: meta("apex"),
      public: public,
      key_tag: key_tag,
      log_index: log_index,
      statement: fixture("statement.json"),
      canonicalized_body: fixture("canonicalized-body.bin"),
      checkpoint: fixture("checkpoint.txt"),
      inclusion_path: path,
      log_spki: log_spki,
      action: meta("action"),
      anchor_file: anchor,
    )
  }
  let path = split32(fixture("inclusion-path.bin"))

  // A tampered audit path reaches no root.
  let assert Error(port.Refused(_, why)) =
    attempt(fixture_public(), [<<0:size(256)>>, <<0:size(256)>>], spki)
  assert string.contains(why, "inclusion")

  // The right log id, the wrong signing key: the log id is derived from the
  // key pinned here, so a substituted key is caught by the signature it
  // cannot produce rather than by an id lookup.
  let assert Ok(<<head:bytes-size(90), last:int-size(8)>>) = Ok(spki)
  let stranger_spki = <<
    head:bits,
    int.bitwise_exclusive_or(last, 1):int-size(8),
  >>
  let assert Error(port.Refused(_, why)) =
    attempt(fixture_public(), path, stranger_spki)
  assert string.contains(why, "checkpoint")

  // Somebody else's key, under this entry: the certificate the log recorded
  // is not about it.
  let stranger = keys.generate()
  let assert Error(port.Refused(_, why)) = attempt(stranger.public, path, spki)
  assert string.contains(why, "binding")
  port.close(session)
}

/// The OID arcs must stay inside 31 bits, and the certificate that was
/// actually logged must carry exactly those bytes.
///
/// Rekor is Go: `encoding/asn1` rejects OID components that overflow
/// `int32`, so `x509.ParseCertificate` fails on a wider arc and the log
/// refuses the whole submission with an opaque `400`. Nothing local caught
/// the original 128-bit UUID arcs — OTP's `public_key` wrote them and OpenSSL
/// read them back without complaint — so this was found by live submission.
/// Asserted here against a certificate that went through the encoder, not
/// against a constant.
pub fn the_oid_arcs_are_the_narrowed_ones_test() {
  // Tag 0x06, length 6, then 0x69 (= 40 × 2 + 25, the UUID arc) and the arc
  // in base-128. Byte-identical to crates/synch-net/src/zonecert.rs.
  let der = fixture("certificate.der")
  assert contains(der, <<0x06, 0x06, 0x69, 0x85, 0xe5, 0xe9, 0xb2, 0x07>>)
  // And the chain extension's value is the one the entry carries.
  assert contains(der, fixture("dnssec-chain.der"))
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

// --------------------------------------------------------- Rekor's own half
//
// Everything in this section simulates the *log*, not this service. A test
// log has to produce the bytes Sigstore produces — a `hashedrekord` body, a
// Merkle tree, a signed note, a key published as a DER SubjectPublicKeyInfo —
// and none of that is a format this service implements any more. The port
// program reads these with the same parser a client uses, so a mistake here
// shows up as a refused publish rather than as a test that passes for the
// wrong reason.

/// The DER SubjectPublicKeyInfo prefix of an uncompressed P-256 key.
const p256_spki_prefix = <<
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  0x04,
>>

fn spki_of(public: BitArray) -> BitArray {
  bit_array.concat([p256_spki_prefix, public])
}

/// A `hashedrekord` v0.0.2 body, as the log serializes one.
fn hashedrekord_body(
  digest: BitArray,
  signature: BitArray,
  certificate: BitArray,
) -> BitArray {
  <<
    "{\"apiVersion\":\"0.0.2\",\"kind\":\"hashedrekord\",\"spec\":{\"hashedRekordV002\":{\"data\":{\"algorithm\":\"SHA2_256\",\"digest\":\"":utf8,
    bit_array.base64_encode(digest, True):utf8,
    "\"},\"signature\":{\"content\":\"":utf8,
    bit_array.base64_encode(signature, True):utf8,
    "\",\"verifier\":{\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\",\"x509Certificate\":{\"rawBytes\":\"":utf8,
    bit_array.base64_encode(certificate, True):utf8,
    "\"}}}}}}":utf8,
  >>
}

/// RFC 6962 §2.1 hashing.
fn leaf_hash(entry: BitArray) -> BitArray {
  crypto.hash(crypto.Sha256, bit_array.concat([<<0>>, entry]))
}

fn node_hash(left: BitArray, right: BitArray) -> BitArray {
  crypto.hash(crypto.Sha256, bit_array.concat([<<1>>, left, right]))
}

/// A log a test can hold in its hand: one earlier entry, then ours, with a
/// checkpoint signed by a key the test also holds. Returns the log and the
/// DER SubjectPublicKeyInfo an operator would pin it by.
fn fake_log(log_csk: keys.Csk) -> #(client.Log, BitArray) {
  let spki = spki_of(log_csk.public)
  let neighbour = leaf_hash(<<"an earlier entry":utf8>>)
  let entry_of = fn(sub: client.Submission) {
    let body = hashedrekord_body(sub.digest, sub.signature, sub.certificate)
    let leaf = leaf_hash(body)
    let root = node_hash(neighbour, leaf)
    let note_body =
      "rekor.test\n2\n" <> bit_array.base64_encode(root, True) <> "\n"
    let signature = ecdsa_sign_raw(<<note_body:utf8>>, log_csk.private)
    let assert Ok(hint) =
      bit_array.slice(crypto.hash(crypto.Sha256, spki), 0, 4)
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
  #(client.Log(submit: fn(sub) { Ok(entry_of(sub)) }), spki)
}

// ---------------------------------------------------------------- the zone

/// The one-link DNSSEC chain a self-anchored zone carries: its own DNSKEY
/// RRset, self-signed.
///
/// The shape a real zone carries is a DS ladder to the ICANN root, which no
/// test can mint; this is the degenerate shape an explicit trust anchor
/// permits — "an override is a different universe" — and it is the same one
/// the Rust sim uses. Both go through the identical walk, and the point here
/// is that the walk *runs*: these are real RRSIGs over a real RRset, and a
/// publish with a chain that does not verify is refused.
fn self_anchored_chain(apex: name.Name, csk: keys.Csk) -> List(port.ChainLink) {
  let rd = keys.dnskey_rdata(csk)
  let key_tag = keys.key_tag(rd)
  let rrsig =
    sign.sign_rrset(
      csk,
      key_tag,
      apex,
      apex,
      wire.type_dnskey,
      3600,
      [rd],
      1_700_000_000,
      2_000_000_000,
    )
  [
    port.ChainLink(
      name.to_string(apex),
      bit_array.concat([
        rdata.rr(apex, wire.type_dnskey, 3600, rd),
        rrsig,
      ]),
    ),
  ]
}

fn anchor_for(apex: name.Name, csk: keys.Csk) -> String {
  temp_file(".anchor", <<{ keys.anchor_line(apex, csk.public) }:utf8>>)
}

fn key_file_for(csk: keys.Csk) -> String {
  let path = fixtures.tmp_db() <> ".key"
  let assert Ok(Nil) = keys.save(path, csk)
  path
}

/// One publish, with everything a real run has: a chain that verifies, a
/// pinned log key, and the trust anchor the chain is under.
fn publish_run(
  conn: sqlite.Connection,
  session: port.Session,
  apex: name.Name,
  csk: keys.Csk,
  log: client.Log,
  log_spki: BitArray,
  now: Int,
  action: String,
  predecessor: String,
  links: List(port.ChainLink),
) {
  rekor_publish.run(
    conn,
    session,
    apex,
    csk,
    key_file_for(csk),
    log,
    log_spki,
    now,
    action,
    predecessor,
    links,
    anchor_for(apex, csk),
  )
}

pub fn publish_stores_a_verified_record_test() {
  let conn = fixtures.fresh_conn()
  let session = open_port()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki) = fake_log(keys.generate())

  let assert Ok(outcome) =
    publish_run(
      conn,
      session,
      apex,
      csk,
      log,
      spki,
      1000,
      "create",
      "",
      self_anchored_chain(apex, csk),
    )
  assert outcome.action == "create"
  assert outcome.refreshed == False
  assert outcome.chainless == False
  assert outcome.key_tag == keys.key_tag(keys.dnskey_rdata(csk))

  let assert Ok([record]) = store.for_key_tag(conn, outcome.key_tag)
  assert record.apex == "sync.test."
  assert record.verified_at == 1000
  // The row identifies the key by its key, not by a 16-bit checksum of it.
  assert record.spki_sha256 == crypto.hash(crypto.Sha256, spki_of(csk.public))
  // What was stored is what a client will be handed: the record the port
  // program encoded from the entry it had just verified.
  assert record.proof_txt != ""
  let assert Ok(decoded) = bit_array.base64_url_decode(record.proof_txt)
  assert bit_array.slice(decoded, 0, 1) == Ok(<<3>>)
  sqlite.close(conn)
  port.close(session)
}

pub fn publish_is_idempotent_test() {
  let conn = fixtures.fresh_conn()
  let session = open_port()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki) = fake_log(keys.generate())
  let links = self_anchored_chain(apex, csk)

  let assert Ok(first) =
    publish_run(conn, session, apex, csk, log, spki, 1000, "create", "", links)
  let assert Ok(second) =
    publish_run(conn, session, apex, csk, log, spki, 2000, "create", "", links)
  // The second run reused the signature the log already indexed, so Rekor's
  // content addressing returns the same entry — a refresh, not a new claim.
  assert second.refreshed
  assert second.log_index == first.log_index

  let assert Ok(records) = store.for_key_tag(conn, first.key_tag)
  assert list.length(records) == 1
  let assert [record] = records
  assert record.verified_at == 2000
  sqlite.close(conn)
  port.close(session)
}

pub fn publish_refuses_an_unverifiable_proof_test() {
  let conn = fixtures.fresh_conn()
  let session = open_port()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki) = fake_log(keys.generate())
  // The log's own key is not the key we pin: the checkpoint it signed
  // verifies under nothing this run trusts, so nothing is stored.
  let stranger = spki_of(keys.generate().public)

  let assert Error(rekor_publish.Unverified(_)) =
    publish_run(
      conn,
      session,
      apex,
      csk,
      log,
      stranger,
      1000,
      "create",
      "",
      self_anchored_chain(apex, csk),
    )
  assert spki != stranger
  let assert Ok([]) =
    store.for_key_tag(conn, keys.key_tag(keys.dnskey_rdata(csk)))
  sqlite.close(conn)
  port.close(session)
}

/// A chain that does not authorize this key never reaches the log.
///
/// The old shape check could only see whether the ladder reached the root,
/// and a chain that stopped at the TLD once got past it into a permanent
/// public record. The walk now runs before the certificate is built, against
/// the same anchor a monitor uses, so an unanchorable chain is a publish that
/// fails at the terminal.
pub fn publish_refuses_a_chain_that_does_not_verify_test() {
  let conn = fixtures.fresh_conn()
  let session = open_port()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki) = fake_log(keys.generate())
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))

  // A chain for the right zone whose RRSIG is a fabrication.
  let rd = keys.dnskey_rdata(csk)
  let forged = [
    port.ChainLink(
      "sync.test.",
      bit_array.concat([
        rdata.rr(apex, wire.type_dnskey, 3600, rd),
        rdata.rr(
          apex,
          wire.type_rrsig,
          3600,
          rdata.rrsig(
            wire.type_dnskey,
            13,
            2,
            3600,
            2_000_000_000,
            1_700_000_000,
            key_tag,
            apex,
            <<0:size(512)>>,
          ),
        ),
      ]),
    ),
  ]
  let assert Error(rekor_publish.Unverified(port.Refused(_, why))) =
    publish_run(conn, session, apex, csk, log, spki, 1000, "create", "", forged)
  assert string.contains(why, "chain")

  // And a create with no chain at all is refused before anything is signed.
  let assert Error(rekor_publish.Unverified(port.Refused(_, bare))) =
    publish_run(conn, session, apex, csk, log, spki, 1000, "create", "", [])
  assert string.contains(bare, "DS")

  let assert Ok([]) = store.for_key_tag(conn, key_tag)
  sqlite.close(conn)
  port.close(session)
}

/// A retire may be chainless; a create may not.
pub fn a_retire_may_be_chainless_test() {
  let conn = fixtures.fresh_conn()
  let session = open_port()
  let csk = fixtures.zone_boot(conn)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki) = fake_log(keys.generate())

  let assert Ok(outcome) =
    publish_run(conn, session, apex, csk, log, spki, 1000, "retire", "", [])
  assert outcome.action == "retire"
  assert outcome.chainless
  // And it is never served to a client: a retire is a monitor breadcrumb.
  let assert Ok([]) = store.servable(conn, outcome.key_tag)
  sqlite.close(conn)
  port.close(session)
}

/// Naming the previous key adds the countersignature that separates a
/// rotation from a substitution in every monitor watching the zone.
pub fn a_countersigned_publish_names_its_predecessor_test() {
  let conn = fixtures.fresh_conn()
  let session = open_port()
  let csk = fixtures.zone_boot(conn)
  let previous = keys.generate()
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki) = fake_log(keys.generate())

  let assert Ok(outcome) =
    publish_run(
      conn,
      session,
      apex,
      csk,
      log,
      spki,
      1000,
      "create",
      key_file_for(previous),
      self_anchored_chain(apex, csk),
    )
  assert outcome.countersigned_by
    == Some(keys.key_tag(keys.dnskey_rdata(previous)))
  assert !outcome.chainless
  sqlite.close(conn)
  port.close(session)
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
  let session = open_port()
  let csk = fixtures.zone_boot(conn)
  let previous = keys.generate()
  let previous_file = key_file_for(previous)
  let assert Ok(apex) = name.parse("sync.test.")
  let #(log, spki) = fake_log(keys.generate())
  let links = self_anchored_chain(apex, csk)

  // First publish: the operator forgets the predecessor. Tier B everywhere.
  let assert Ok(first) =
    publish_run(conn, session, apex, csk, log, spki, 1000, "create", "", links)
  assert first.countersigned_by == None

  // Re-run naming it. The Statement is byte-identical, so the old rule would
  // have reused the stored certificate and reported success unchanged.
  let assert Ok(second) =
    publish_run(
      conn,
      session,
      apex,
      csk,
      log,
      spki,
      2000,
      "create",
      previous_file,
      links,
    )
  assert second.countersigned_by
    == Some(keys.key_tag(keys.dnskey_rdata(previous)))
  assert second.refreshed == False

  // A third run naming the *same* predecessor changes nothing: the stored
  // entry already says what this run would say, so it stays one claim.
  let assert Ok(third) =
    publish_run(
      conn,
      session,
      apex,
      csk,
      log,
      spki,
      3000,
      "create",
      previous_file,
      links,
    )
  assert third.refreshed
  sqlite.close(conn)
  port.close(session)
}

// --------------------------------------------------------------- the gate

pub fn publish_gate_refuses_an_unlogged_key_test() {
  let conn = fixtures.fresh_conn()
  let session = open_port()
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
  let #(log, spki) = fake_log(keys.generate())
  let assert Ok(_) =
    publish_run(
      conn,
      session,
      apex,
      csk,
      log,
      spki,
      1000,
      "create",
      "",
      self_anchored_chain(apex, csk),
    )
  let assert Ok(_) = publish.publish(conn, csk, 1000, "test")
  envoy.unset(gate.require_env)
  sqlite.close(conn)
  port.close(session)
}

pub fn a_retire_record_does_not_satisfy_the_gate_test() {
  let conn = fixtures.fresh_conn()
  let csk = fixtures.zone_boot(conn)
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))
  let assert Ok(Nil) =
    store.put(
      conn,
      store.Record(
        spki_sha256: crypto.hash(crypto.Sha256, spki_of(csk.public)),
        key_tag: key_tag,
        apex: "sync.test.",
        action: "retire",
        statement: <<"{}":utf8>>,
        canonicalized_body: <<0:size(512)>>,
        log_id: <<0:size(256)>>,
        log_index: 0,
        checkpoint: <<>>,
        inclusion_path: <<>>,
        proof_txt: "not served",
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

// --------------------------------------------------------------- collection

/// The collector asks for the right RRsets at the right names, and refuses
/// when one is missing — which is the ordinary failure of the inverted
/// ceremony (§5.2): logging now happens *after* the DS is live in the
/// parent, so "the DS is not there yet" is the error an operator meets.
pub fn the_chain_collector_walks_to_the_root_test() {
  let assert Ok(apex) = name.parse("prod.sync.test.")
  let assert Ok(links) = chain.collect(fake_resolver(), apex)
  assert list.map(links, fn(link) { link.zone })
    == ["prod.sync.test.", "sync.test.", "test.", "."]

  let assert Error(why) = chain.collect(silent_resolver(), apex)
  assert string.contains(why, "DS")
}

/// A resolver that answers with structurally correct but cryptographically
/// meaningless RRsets — enough to exercise *collection*, which is all that
/// is left on this side. The signatures are the port program's business, and
/// `publish_refuses_a_chain_that_does_not_verify_test` is where they are
/// checked.
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
      wire.Rr(zone, wire.type_rrsig, wire.class_in, 3600, <<
        rtype:int-size(16),
        13:int-size(8),
        2:int-size(8),
        0:size(512),
      >>),
    ])
  })
}

/// A resolver with nothing to say — the DS is not live in the parent yet.
fn silent_resolver() -> chain.Resolver {
  chain.Resolver(query: fn(_zone, _rtype) { Ok([]) })
}

/// A retire collects nothing: a retired zone may have no DS left, and
/// clients refuse a retire as authorization outright.
pub fn a_retire_collects_no_chain_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let assert Ok([]) =
    rekor_publish.collect_links(silent_resolver(), apex, "retire")
  let assert Error(rekor_publish.NoChain(_)) =
    rekor_publish.collect_links(silent_resolver(), apex, "create")
}

// ---------------------------------------------------------------- serving

pub fn the_zone_serves_the_proof_record_test() {
  let assert Ok(apex) = name.parse("sync.test.")
  let assert Ok(ns1) = name.parse("ns1.sync.test.")
  let assert Ok(owner) = name.parse("_synchronicity.prod.acme.sync.test.")
  let csk = keys.generate()
  let text = bit_array.base64_url_encode(fixture("proof.bin"), False)
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
