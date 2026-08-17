//// The TUF client workflow on this side, against the real repository's
//// bytes (docs/REKOR-ZONE-KEY.md §10.3).
////
//// This suite exists because a verifier that only ever sees material it
//// accepts is a verifier nobody has tested. So it runs three ways.
////
//// **Conformance.** The checked-in Sigstore chain — roots 13 → 14 → 15, then
//// timestamp, snapshot, targets and the `trusted_root.json` target — through
//// this verifier at the instant it was fetched. Everything about it is
//// somebody else's bytes: if canonical JSON, the DER signatures, the PEM key
//// parsing or the RFC 3339 shapes were wrong in any way, none of it can
//// pass. The same fixture goes through the Rust verifier in
//// crates/synch-net/tests/tuf_pin_refresh.rs, which is what keeps two
//// implementations of one spec from drifting apart quietly.
////
//// **Canonical JSON against a third implementation.** The digests below were
//// produced by a Python canonicalizer written from the OLPC rules, not by
//// either implementation in this repository. A test where the checker and
//// the checked share an author proves less than one where they do not.
////
//// **Negatives.** A broken signature block, a tampered body, signatures by
//// keys the root does not authorize, a gap in the root chain, expiry,
//// rollback, a file served as the wrong role, and a target that does not
//// hash to its digest. Each breaks exactly one thing, so a pass above cannot
//// be an accident of the harness — and one broken signature out of five is
//// asserted to still *pass*, because a threshold nobody counts is a
//// threshold that would refuse a late signer as readily as an attacker.

import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import simplifile
import tuf/anchor
import tuf/canonical
import tuf/verify

const fixture_dir = "test/fixtures/tuf/"

fn fixture(file: String) -> BitArray {
  let assert Ok(bits) = simplifile.read_bits(fixture_dir <> file)
  bits
}

fn text_of(bytes: BitArray) -> String {
  let assert Ok(text) = bit_array.to_string(bytes)
  text
}

fn field(name: String) -> String {
  let assert Ok(value) =
    text_of(fixture("meta.txt"))
    |> string.split("\n")
    |> list.find_map(fn(line) {
      case string.split_once(line, "=") {
        Ok(#(key, value)) if key == name -> Ok(value)
        _ -> Error(Nil)
      }
    })
  value
}

fn number(name: String) -> Int {
  let assert Ok(value) = int.parse(field(name))
  value
}

fn root(version: Int) -> BitArray {
  fixture("root-" <> int.to_string(version) <> ".json")
}

/// The whole checked-in chain, from `anchor`, at the moment it was fetched.
fn verify_from(anchor: BitArray, roots: List(BitArray)) {
  verify.verify(
    anchor,
    roots,
    fixture("timestamp.json"),
    fixture("snapshot.json"),
    fixture("targets.json"),
    fixture("trusted-root.json"),
    verify.no_floors(),
    number("verify_at"),
  )
}

// ------------------------------------------------------------ conformance

pub fn the_real_sigstore_chain_verifies_test() {
  // The anchor this build ships is the one the client embeds, so the walk
  // starts where a stock client starts and needs no rotation to arrive.
  let assert Ok(anchored) = anchor.load()
  assert anchored.version == number("root_version")
  let assert Ok(accepted) =
    verify_from(anchored.bytes, [root(anchored.version)])
  assert accepted.root_version == number("root_version")
  assert accepted.timestamp_version == number("timestamp_version")
  assert accepted.snapshot_version == number("snapshot_version")
  assert accepted.targets_version == number("targets_version")
  assert accepted.timestamp_expires > number("verify_at")
}

pub fn the_real_root_rotation_walks_test() {
  // Anchored two rotations back: roots 13 → 14 → 15, each endorsed by both
  // the root before it and its own role, with Sigstore's real signatures.
  let floor = number("chain_floor")
  let head = number("root_version")
  let chain =
    string.split(field("root_versions"), ",")
    |> list.filter_map(int.parse)
    |> list.map(root)
  let assert Ok(accepted) = verify_from(root(floor), chain)
  assert accepted.root_version == head

  // A gap is refused rather than jumped: 13 to 15 with nothing bridging.
  let assert Error(verify.Chain(_)) = verify_from(root(floor), [root(head)])

  // And material for a root already passed travels without moving anything.
  let assert Ok(same) = verify_from(root(head), [root(floor), root(head)])
  assert same.root_version == head
}

pub fn key_ids_are_the_digest_of_the_key_object_test() {
  // The sharpest canonical-JSON test available: every id in the table is a
  // SHA-256 Sigstore computed over the canonical form of the key object, so
  // reproducing all six means reproducing their canonicalizer exactly.
  list.each([13, 14, 15], fn(version) {
    let assert Ok(document) = canonical.parse(root(version))
    let assert Ok(keys) =
      canonical.at(document, ["signed", "keys"])
      |> result.try(canonical.members)
    assert keys != []
    list.each(keys, fn(entry) {
      let #(id, key) = entry
      assert verify.key_id(key) == id
    })
  })
}

pub fn canonical_json_matches_a_third_implementation_test() {
  // Digests from a Python canonicalizer written from the OLPC rules —
  // neither of this repository's two implementations. If both of ours were
  // wrong the same way, this is what would still notice.
  [
    #(
      "root-15.json",
      3722,
      "aa5f5ce25e7701ccd06f2aab1b76d6ae89fb98bda9d7c55318149d665820af2c",
    ),
    #(
      "timestamp.json",
      130,
      "f34b29ac720538ef602eba6abceb8169cf125cd3492dddce0e82364a7c3b84fc",
    ),
    #(
      "targets.json",
      2810,
      "a9f06d26b0acb3211dbbaa3a8c382138e422ce3d31c7175c2b1806c76b921659",
    ),
  ]
  |> list.each(fn(expected) {
    let #(file, length, digest) = expected
    let assert Ok(document) = canonical.parse(fixture(file))
    let assert Ok(signed) = canonical.field(document, "signed")
    let bytes = canonical.encode(signed)
    assert bit_array.byte_size(bytes) == length
    assert sha256_hex(bytes) == digest
  })
}

// --------------------------------------------------------------- negatives

pub fn the_anchor_is_trusted_and_everything_after_it_is_not_test() {
  // The anchor's own signatures are never checked — it *is* the trust
  // anchor, exactly as the client's embedded root is, and a root that had to
  // prove itself to something would just move the question. Breaking every
  // signature on the anchor therefore changes nothing, and that is the
  // property that makes replacing priv/tuf a deploy-level decision.
  let all_broken = replace(text_of(root(15)), "\"sig\": \"", "\"sig\": \"00")
  let assert Ok(_) = verify_from(all_broken, [all_broken])

  // Its successor is a different matter: a root arriving over the wire has
  // to carry the thresholds of both the root before it and its own role.
  let assert Ok(_) = verify_from(root(14), [root(15)])
  let assert Error(verify.Threshold(_)) = verify_from(root(14), [all_broken])
}

pub fn a_threshold_counts_distinct_keys_that_actually_signed_test() {
  // Root 15 carries five signatures and requires three, so breaking one must
  // *not* refuse it — a verifier that failed here would be one that never
  // really counted, and it would refuse a late Sigstore signer as readily as
  // an attacker.
  let one_broken = swap(text_of(root(15)), "\"sig\": \"3", "\"sig\": \"4")
  let assert Ok(accepted) = verify_from(root(14), [one_broken])
  assert accepted.root_version == 15
}

pub fn one_flipped_byte_in_the_signed_body_is_refused_test() {
  // A verifier that canonicalized loosely — dropping a member it did not
  // recognise, say — would keep accepting this.
  let assert Ok(anchored) = anchor.load()
  let broken =
    swap(text_of(fixture("timestamp.json")), "\"version\":", "\"Version\":")
  let assert Error(_) =
    verify.verify(
      anchored.bytes,
      [root(anchored.version)],
      broken,
      fixture("snapshot.json"),
      fixture("targets.json"),
      fixture("trusted-root.json"),
      verify.no_floors(),
      number("verify_at"),
    )
}

pub fn signatures_by_keys_the_root_does_not_authorize_are_refused_test() {
  // Every signature on the incoming root reattributed to a key id no table
  // has heard of. The signatures are Sigstore's own and still verify under
  // the keys that made them — but nothing says those keys may sign a root,
  // and "signed by somebody" is not what a threshold asks.
  let unattributed =
    replace(text_of(root(15)), "\"keyid\": \"", "\"keyid\": \"0")
  let assert Error(verify.Threshold(_)) = verify_from(root(14), [unattributed])
}

pub fn expiry_gates_the_update_test() {
  let assert Ok(anchored) = anchor.load()
  let assert Ok(accepted) =
    verify_from(anchored.bytes, [root(anchored.version)])
  let assert Error(verify.Expiry(_)) =
    verify.verify(
      anchored.bytes,
      [root(anchored.version)],
      fixture("timestamp.json"),
      fixture("snapshot.json"),
      fixture("targets.json"),
      fixture("trusted-root.json"),
      verify.no_floors(),
      accepted.timestamp_expires + 1,
    )
}

pub fn a_rollback_below_what_is_stored_is_refused_test() {
  let assert Ok(anchored) = anchor.load()
  let floors =
    verify.Floors(
      root: number("root_version"),
      timestamp: number("timestamp_version") + 1,
      snapshot: 0,
      targets: 0,
    )
  let assert Error(verify.Rollback(_)) =
    verify.verify(
      anchored.bytes,
      [root(anchored.version)],
      fixture("timestamp.json"),
      fixture("snapshot.json"),
      fixture("targets.json"),
      fixture("trusted-root.json"),
      floors,
      number("verify_at"),
    )
}

pub fn a_file_served_as_the_wrong_role_is_refused_test() {
  let assert Ok(anchored) = anchor.load()
  let assert Error(verify.Chain(_)) =
    verify.verify(
      anchored.bytes,
      [root(anchored.version)],
      fixture("timestamp.json"),
      // The targets, served where the snapshot belongs.
      fixture("targets.json"),
      fixture("targets.json"),
      fixture("trusted-root.json"),
      verify.no_floors(),
      number("verify_at"),
    )
}

pub fn a_target_that_does_not_hash_to_its_digest_is_refused_test() {
  let assert Ok(anchored) = anchor.load()
  let assert Error(verify.TargetHash(_)) =
    verify.verify(
      anchored.bytes,
      [root(anchored.version)],
      fixture("timestamp.json"),
      fixture("snapshot.json"),
      fixture("targets.json"),
      <<"{\"tlogs\":[]}":utf8>>,
      verify.no_floors(),
      number("verify_at"),
    )
}

// ---------------------------------------------------- canonical JSON units

pub fn canonical_json_sorts_escapes_and_refuses_fractions_test() {
  let render = fn(text: String) {
    let assert Ok(document) = canonical.parse(<<text:utf8>>)
    text_of(canonical.encode(document))
  }
  // Members sorted by key, whitespace gone, nesting preserved.
  assert render("{\"b\": 1, \"a\": [2, {\"d\": true, \"c\": null}]}")
    == "{\"a\":[2,{\"c\":null,\"d\":true}],\"b\":1}"
  // Sorting is by code point, which is what comparing the UTF-8 bytes does.
  assert render("{\"b\":0,\"B\":0,\"a\":0,\"A\":0}")
    == "{\"A\":0,\"B\":0,\"a\":0,\"b\":0}"
  // Only the quote and the backslash are escaped; a tab travels raw, which
  // ordinary JSON would never write.
  assert render("{\"k\":\"a\\\"b\\\\c\\td\"}") == "{\"k\":\"a\\\"b\\\\c\td\"}"
  // Non-ASCII is UTF-8, not \u escapes.
  assert render("{\"k\":\"\\u00e9\"}") == "{\"k\":\"é\"}"
  // A fraction has no canonical rendering, so it is refused at the parse
  // rather than silently rounded into one.
  let assert Error(_) = canonical.parse(<<"{\"k\":1.5}":utf8>>)
  let assert Error(_) = canonical.parse(<<"not json":utf8>>)
}

// ------------------------------------------------------------------ tools

/// Replaces the first occurrence of `from` with `to`, as bytes.
fn swap(text: String, from: String, to: String) -> BitArray {
  let assert Ok(#(before, after)) = string.split_once(text, from)
  let replaced = before <> to <> after
  <<replaced:utf8>>
}

/// Replaces every occurrence, for the tampering that has to reach a whole
/// signature block rather than one entry in it.
fn replace(text: String, from: String, to: String) -> BitArray {
  let replaced = string.replace(text, from, to)
  <<replaced:utf8>>
}

fn sha256_hex(bytes: BitArray) -> String {
  string.lowercase(bit_array.base16_encode(crypto.hash(crypto.Sha256, bytes)))
}
