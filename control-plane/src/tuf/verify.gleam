//// The TUF client workflow, on this side of the wire
//// (docs/REKOR-ZONE-KEY.md §10.3).
////
//// This service used to check no signatures at all, and said so: it was a
//// relay, the client was the verifier, and material that did not verify cost
//// nothing but zone bytes because clients ignore it and keep their pins.
////
//// That argument stopped covering everything the moment the same material
//// began deciding **where this service submits** and **which key it checks
//// the returned proof against** (`rekor/client.discover`, §10.6). That
//// decision is consumed here and nowhere else — no client ever sees it, so
//// no client can re-verify it. Left unverified, TLS to the TUF CDN would be
//// the only thing standing between a hostile mirror and a control plane that
//// publishes its zone-key claim into a log nobody monitors, believes the
//// proof it gets back, and satisfies its own `CP_REKOR_REQUIRE` gate while
//// doing it. So the gate moved here.
////
//// It is the same workflow the client runs (crates/synch-net/src/tuf.rs),
//// deliberately: chain the roots, then timestamp → snapshot → targets, each
//// endorsed by the role the *current* root names, each bounded by what is
//// already stored, ending at the one target the chain exists to
//// authenticate. Two implementations of one spec drift silently unless
//// something outside both holds them still, which is what the shared
//// fixture in test/fixtures/tuf is for — the same bytes, the same instant,
//// the same answer on both sides.
////
//// The anchor is `priv/tuf/sigstore_tuf_root.json`, byte-identical to the
//// root the client embeds. Replacing it is a deploy, deliberately: that is
//// what makes everything below it refreshable without one.

import gleam/bit_array
import gleam/crypto
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/result
import gleam/set
import gleam/string
import tuf/canonical.{type Json}
import tuf/meta

/// Why material was refused. The variants are the failure *classes*, the
/// same split the client reports, so an operator reading a log line and a
/// client reading `synch doctor` are told the same thing in the same words.
pub type Error {
  /// Not the JSON shape TUF metadata has.
  Malformed(String)
  /// The chain does not connect: a gap in the versions, a role the root does
  /// not define, a file claiming to be something else.
  Chain(String)
  /// Too few of a role's keys signed.
  Threshold(String)
  /// A signature does not verify over the canonical JSON of what it covers.
  Signature(String)
  /// A role's `expires` is in the past.
  Expiry(String)
  /// A version is lower than the one already stored.
  Rollback(String)
  /// A file does not hash to what the metadata above it says it does.
  TargetHash(String)
}

/// The one-word class, and the sentence, for a log line.
pub fn describe(error: Error) -> String {
  case error {
    Malformed(why) -> "malformed: " <> why
    Chain(why) -> "chain: " <> why
    Threshold(why) -> "threshold: " <> why
    Signature(why) -> "signature: " <> why
    Expiry(why) -> "expiry: " <> why
    Rollback(why) -> "rollback: " <> why
    TargetHash(why) -> "target hash: " <> why
  }
}

/// The versions already stored, which nothing verified here may go below.
///
/// Zero everywhere is a first fetch: monotonicity has nothing to say yet.
pub type Floors {
  Floors(root: Int, timestamp: Int, snapshot: Int, targets: Int)
}

/// A first fetch, with nothing to roll back from.
pub fn no_floors() -> Floors {
  Floors(root: 0, timestamp: 0, snapshot: 0, targets: 0)
}

/// What verification established.
pub type Accepted {
  Accepted(
    root_version: Int,
    timestamp_version: Int,
    timestamp_expires: Int,
    snapshot_version: Int,
    targets_version: Int,
  )
}

/// Verifies a fetched chain, anchored on `anchor`.
///
/// The order is TUF's own (spec §5.3–§5.6), and every step is a refusal
/// rather than a warning: material that does not verify is not stored, so
/// whatever was stored before keeps being served and keeps deciding where
/// this service submits.
pub fn verify(
  anchor: BitArray,
  roots: List(BitArray),
  timestamp_json: BitArray,
  snapshot_json: BitArray,
  targets_json: BitArray,
  trusted_root: BitArray,
  floors: Floors,
  now: Int,
) -> Result(Accepted, Error) {
  // 1. Walk the root chain. Each step must be signed by the thresholds of
  //    *both* the old root and the new one: the old root says who may
  //    succeed it, the new one proves it holds the keys it claims.
  use anchor_root <- result.try(parse_root(anchor))
  use trusted <- result.try(list.try_fold(roots, anchor_root, step))
  use Nil <- result.try(case trusted.version >= floors.root {
    True -> Ok(Nil)
    False ->
      Error(Rollback(
        "root "
        <> int.to_string(trusted.version)
        <> " is older than the stored root "
        <> int.to_string(floors.root),
      ))
  })
  // Only the *final* root's expiry is checked (TUF §5.3.11). Intermediates
  // in a chain are expected to be expired — the real Sigstore chain has
  // been, every time a rotation ran late.
  use Nil <- result.try(check_expiry(trusted.meta, now))

  // 2. timestamp → snapshot → targets, each signed by the role the current
  //    root names, each no older than what is already stored.
  use timestamp <- result.try(parse_meta(timestamp_json, "timestamp"))
  use Nil <- result.try(check_role(trusted, "timestamp", timestamp))
  use Nil <- result.try(check_expiry(timestamp, now))
  use Nil <- result.try(check_rollback(timestamp, floors.timestamp))

  use snapshot <- result.try(parse_meta(snapshot_json, "snapshot"))
  use Nil <- result.try(check_listed(
    timestamp,
    "snapshot.json",
    snapshot_json,
    snapshot.version,
  ))
  use Nil <- result.try(check_role(trusted, "snapshot", snapshot))
  use Nil <- result.try(check_expiry(snapshot, now))
  use Nil <- result.try(check_rollback(snapshot, floors.snapshot))

  use targets <- result.try(parse_meta(targets_json, "targets"))
  use Nil <- result.try(check_listed(
    snapshot,
    "targets.json",
    targets_json,
    targets.version,
  ))
  use Nil <- result.try(check_role(trusted, "targets", targets))
  use Nil <- result.try(check_expiry(targets, now))
  use Nil <- result.try(check_rollback(targets, floors.targets))

  // 3. The one target the whole chain exists to authenticate.
  use Nil <- result.try(check_target(targets, trusted_root_target, trusted_root))

  Ok(Accepted(
    root_version: trusted.version,
    timestamp_version: timestamp.version,
    timestamp_expires: timestamp.expires,
    snapshot_version: snapshot.version,
    targets_version: targets.version,
  ))
}

/// The target the chain exists to carry.
pub const trusted_root_target = "trusted_root.json"

/// One step of the root walk.
fn step(trusted: Root, bytes: BitArray) -> Result(Root, Error) {
  use candidate <- result.try(parse_root(bytes))
  case candidate.version <= trusted.version {
    // Material for a root already passed. Old-but-valid is allowed to
    // travel; it just does not move anything.
    True -> Ok(trusted)
    False ->
      case candidate.version == trusted.version + 1 {
        False ->
          Error(Chain(
            "root "
            <> int.to_string(candidate.version)
            <> " follows root "
            <> int.to_string(trusted.version)
            <> ", and nothing bridges them",
          ))
        True -> {
          use Nil <- result.try(check_role(trusted, "root", candidate.meta))
          use Nil <- result.try(check_role(candidate, "root", candidate.meta))
          Ok(candidate)
        }
      }
  }
}

// ---------------------------------------------------------------- metadata

/// One parsed metadata file: what it says about itself, the canonical bytes
/// its signatures cover, and those signatures.
type Meta {
  Meta(
    role: String,
    version: Int,
    expires: Int,
    signed: Json,
    canonical: BitArray,
    signatures: List(#(String, BitArray)),
  )
}

fn parse_meta(bytes: BitArray, role: String) -> Result(Meta, Error) {
  let bad = fn(why: String) { Malformed(role <> ".json: " <> why) }
  use document <- result.try(
    canonical.parse(bytes) |> result.map_error(fn(why) { bad(why) }),
  )
  use signed <- result.try(
    canonical.field(document, "signed")
    |> result.replace_error(bad("no signed object")),
  )
  use declared <- result.try(
    canonical.string_at(signed, ["_type"])
    |> result.replace_error(bad("signed._type is not a string")),
  )
  use Nil <- result.try(case declared == role {
    True -> Ok(Nil)
    False ->
      Error(Chain(
        "a file served as " <> role <> ".json declares itself " <> declared,
      ))
  })
  // `spec_version` is `MAJOR.MINOR.FIX`; a major bump is a format this build
  // does not claim to read.
  use spec <- result.try(
    canonical.string_at(signed, ["spec_version"])
    |> result.replace_error(bad("no spec_version")),
  )
  use Nil <- result.try(case string.starts_with(spec, "1.") {
    True -> Ok(Nil)
    False -> Error(bad("spec version " <> spec <> " is not 1.x"))
  })
  use version <- result.try(
    canonical.integer_at(signed, ["version"])
    |> result.replace_error(bad("version is not a whole number")),
  )
  use expires_text <- result.try(
    canonical.string_at(signed, ["expires"])
    |> result.replace_error(bad("expires is not a string")),
  )
  use expires <- result.try(
    meta.parse_rfc3339(expires_text)
    |> result.replace_error(bad("expires is not an RFC 3339 timestamp")),
  )
  use entries <- result.try(
    canonical.field(document, "signatures")
    |> result.try(canonical.array)
    |> result.replace_error(bad("signatures is not an array")),
  )
  use signatures <- result.try(
    list.try_map(entries, fn(entry) {
      use keyid <- result.try(
        canonical.string_at(entry, ["keyid"])
        |> result.replace_error(bad("a signature has no keyid")),
      )
      use hex <- result.try(
        canonical.string_at(entry, ["sig"])
        |> result.replace_error(bad("a signature has no sig")),
      )
      use signature <- result.try(
        unhex(hex) |> result.replace_error(bad("a signature is not hex")),
      )
      Ok(#(keyid, signature))
    }),
  )
  Ok(Meta(
    role: role,
    version: version,
    expires: expires,
    signed: signed,
    canonical: canonical.encode(signed),
    signatures: signatures,
  ))
}

fn check_expiry(file: Meta, now: Int) -> Result(Nil, Error) {
  case file.expires > now {
    True -> Ok(Nil)
    False ->
      Error(Expiry(
        file.role
        <> ".json version "
        <> int.to_string(file.version)
        <> " expired at "
        <> int.to_string(file.expires),
      ))
  }
}

fn check_rollback(file: Meta, stored: Int) -> Result(Nil, Error) {
  case file.version >= stored {
    True -> Ok(Nil)
    False ->
      Error(Rollback(
        file.role
        <> ".json version "
        <> int.to_string(file.version)
        <> " is older than the stored "
        <> int.to_string(stored),
      ))
  }
}

/// Checks a file this one lists in `meta`: version exactly, hashes and
/// length when they are given.
///
/// Sigstore's timestamp lists `snapshot.json` by version alone, and its
/// snapshot does the same for `targets.json` — hashes are optional in the
/// spec and this repository omits them for the files that change on every
/// publish. The version equality is what still binds them.
fn check_listed(
  file: Meta,
  named: String,
  bytes: BitArray,
  version: Int,
) -> Result(Nil, Error) {
  use entry <- result.try(
    canonical.at(file.signed, ["meta", named])
    |> result.replace_error(Chain(file.role <> ".json does not list " <> named)),
  )
  use listed <- result.try(
    canonical.integer_at(entry, ["version"])
    |> result.replace_error(Chain(file.role <> ".json does not list " <> named)),
  )
  use Nil <- result.try(case listed == version {
    True -> Ok(Nil)
    False ->
      Error(Rollback(
        file.role
        <> ".json names "
        <> named
        <> " version "
        <> int.to_string(listed)
        <> ", the fetch carries "
        <> int.to_string(version),
      ))
  })
  check_hashes(named, entry, bytes)
}

/// Checks the target file the chain exists to authenticate.
///
/// Unlike `meta`, a target entry's `hashes` are not optional: without them
/// nothing in the chain says anything about these bytes.
fn check_target(
  targets: Meta,
  named: String,
  bytes: BitArray,
) -> Result(Nil, Error) {
  use entry <- result.try(
    canonical.at(targets.signed, ["targets", named])
    |> result.replace_error(TargetHash(
      "targets.json version "
      <> int.to_string(targets.version)
      <> " names no "
      <> named,
    )),
  )
  use _ <- result.try(
    canonical.string_at(entry, ["hashes", "sha256"])
    |> result.replace_error(TargetHash(
      "targets.json gives no sha256 digest for " <> named,
    )),
  )
  check_hashes(named, entry, bytes)
}

fn check_hashes(
  named: String,
  entry: Json,
  bytes: BitArray,
) -> Result(Nil, Error) {
  use Nil <- result.try(case canonical.integer_at(entry, ["length"]) {
    Error(Nil) -> Ok(Nil)
    Ok(length) ->
      case length == bit_array.byte_size(bytes) {
        True -> Ok(Nil)
        False ->
          Error(TargetHash(
            named
            <> " is "
            <> int.to_string(bit_array.byte_size(bytes))
            <> " bytes, the metadata says "
            <> int.to_string(length),
          ))
      }
  })
  case canonical.string_at(entry, ["hashes", "sha256"]) {
    Error(Nil) -> Ok(Nil)
    Ok(expected) -> {
      let actual = sha256_hex(bytes)
      case string.lowercase(expected) == actual {
        True -> Ok(Nil)
        False ->
          Error(TargetHash(
            named
            <> " hashes to "
            <> actual
            <> ", the metadata says its digest is "
            <> expected,
          ))
      }
    }
  }
}

// -------------------------------------------------------------------- root

/// A parsed `root.json`: the metadata plus the role and key tables that make
/// it the thing every other file is checked against.
type Root {
  Root(
    version: Int,
    meta: Meta,
    /// Role name → the key ids it authorizes and how many must sign.
    roles: Dict(String, #(List(String), Int)),
    /// Key id → the key, for the ids this build can actually use.
    keys: Dict(String, Key),
  )
}

fn parse_root(bytes: BitArray) -> Result(Root, Error) {
  let bad = fn(why: String) { Malformed("root.json: " <> why) }
  use file <- result.try(parse_meta(bytes, "root"))
  use role_members <- result.try(
    canonical.field(file.signed, "roles")
    |> result.try(canonical.members)
    |> result.replace_error(bad("roles is not an object")),
  )
  use roles <- result.try(
    list.try_map(role_members, fn(entry) {
      let #(name, role) = entry
      use threshold <- result.try(
        canonical.integer_at(role, ["threshold"])
        |> result.replace_error(bad("role " <> name <> " has no threshold")),
      )
      // A zero threshold is a role anything satisfies.
      use Nil <- result.try(case threshold > 0 {
        True -> Ok(Nil)
        False -> Error(bad("role " <> name <> " has threshold 0"))
      })
      use keyids <- result.try(
        canonical.field(role, "keyids")
        |> result.try(canonical.array)
        |> result.replace_error(bad("role " <> name <> " has no keyids")),
      )
      Ok(#(name, #(list.filter_map(keyids, canonical.string), threshold)))
    }),
  )
  use key_members <- result.try(
    canonical.field(file.signed, "keys")
    |> result.try(canonical.members)
    |> result.replace_error(bad("keys is not an object")),
  )
  // A key this build cannot use is not an error here: it becomes a threshold
  // failure only if a role actually needs it.
  let keys =
    key_members
    |> list.filter_map(fn(entry) {
      let #(id, key) = entry
      parse_key(key) |> result.map(fn(parsed) { #(id, parsed) })
    })
    |> dict.from_list
  Ok(Root(
    version: file.version,
    meta: file,
    roles: dict.from_list(roles),
    keys: keys,
  ))
}

/// Checks that `file` carries signatures from at least `threshold` distinct
/// keys of this root's `role`.
///
/// Distinct is doing work: a file that repeats one key's signature five
/// times must not satisfy a threshold of three.
fn check_role(root: Root, role: String, file: Meta) -> Result(Nil, Error) {
  use pair <- result.try(
    dict.get(root.roles, role)
    |> result.replace_error(Chain(
      "root "
      <> int.to_string(root.version)
      <> " defines no "
      <> role
      <> " role",
    )),
  )
  let #(keyids, threshold) = pair
  let authorized = set.from_list(keyids)
  let signed =
    list.fold(file.signatures, set.new(), fn(signed, entry) {
      let #(keyid, signature) = entry
      case set.contains(signed, keyid) || !set.contains(authorized, keyid) {
        True -> signed
        False ->
          case dict.get(root.keys, keyid) {
            Error(Nil) -> signed
            Ok(key) ->
              case verify_signature(key, file.canonical, signature) {
                True -> set.insert(signed, keyid)
                False -> signed
              }
          }
      }
    })
  case set.size(signed) >= threshold {
    True -> Ok(Nil)
    False ->
      Error(Threshold(
        file.role
        <> ".json version "
        <> int.to_string(file.version)
        <> " carries "
        <> int.to_string(set.size(signed))
        <> " of the "
        <> int.to_string(threshold)
        <> " "
        <> role
        <> " signatures root "
        <> int.to_string(root.version)
        <> " requires",
      ))
  }
}

// -------------------------------------------------------------------- keys

/// The signature scheme a TUF key uses.
type Scheme {
  EcdsaP256Sha256
  Ed25519
}

/// One key from a root's key table. `point` is the raw material the FFI
/// takes: an uncompressed P-256 point *without* its `0x04` prefix (which
/// `cp_crypto_ffi` puts back), or 32 Ed25519 bytes.
type Key {
  Key(scheme: Scheme, point: BitArray)
}

/// Parses one entry of `signed.keys`.
///
/// Dispatch is on `scheme`, never `keytype`: Sigstore's roots write the same
/// P-256 key as keytype `ecdsa-sha2-nistp256` up to version 8 and `ecdsa`
/// from version 9, while the scheme stayed `ecdsa-sha2-nistp256` throughout.
/// `keyval.public` is a PEM SubjectPublicKeyInfo in every root from version 5
/// on, and hex-encoded raw key material before that.
fn parse_key(key: Json) -> Result(Key, Nil) {
  use scheme <- result.try(case canonical.string_at(key, ["scheme"]) {
    Ok("ecdsa-sha2-nistp256") -> Ok(EcdsaP256Sha256)
    Ok("ed25519") -> Ok(Ed25519)
    _ -> Error(Nil)
  })
  use public <- result.try(canonical.string_at(key, ["keyval", "public"]))
  use point <- result.try(case string.contains(public, "-----BEGIN") {
    True -> result.try(pem_body(public), spki_point(_, scheme))
    False -> result.try(unhex(string.trim(public)), raw_point(_, scheme))
  })
  Ok(Key(scheme: scheme, point: point))
}

/// The base64 body of a PEM block, whatever its label.
fn pem_body(pem: String) -> Result(BitArray, Nil) {
  pem
  |> string.split("\n")
  |> list.map(string.trim)
  |> list.filter(fn(line) { !string.starts_with(line, "-----") && line != "" })
  |> string.join("")
  |> bit_array.base64_decode
}

/// The DER SubjectPublicKeyInfo prefix of an uncompressed P-256 key.
const p256_spki_prefix = <<
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  0x04,
>>

/// The DER SubjectPublicKeyInfo prefix of an Ed25519 key.
const ed25519_spki_prefix = <<
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
>>

/// The raw key inside a DER SubjectPublicKeyInfo.
///
/// Deliberately narrow, the same stance as `rekor/proof.parse_log_key` (whose
/// prefixes these are): two shapes are recognized and everything else is
/// refused, rather than a general ASN.1 reader parsing whatever it is handed.
fn spki_point(der: BitArray, scheme: Scheme) -> Result(BitArray, Nil) {
  case scheme, der {
    EcdsaP256Sha256, <<prefix:bytes-size(27), point:bytes-size(64)>>
      if prefix == p256_spki_prefix
    -> Ok(point)
    Ed25519, <<prefix:bytes-size(12), point:bytes-size(32)>>
      if prefix == ed25519_spki_prefix
    -> Ok(point)
    _, _ -> Error(Nil)
  }
}

/// The pre-PEM form: hex key material, as Sigstore's roots 1–4 wrote it.
fn raw_point(bytes: BitArray, scheme: Scheme) -> Result(BitArray, Nil) {
  case scheme, bytes {
    EcdsaP256Sha256, <<0x04, point:bytes-size(64)>> -> Ok(point)
    EcdsaP256Sha256, <<point:bytes-size(64)>> -> Ok(point)
    Ed25519, <<point:bytes-size(32)>> -> Ok(point)
    _, _ -> Error(Nil)
  }
}

@external(erlang, "cp_crypto_ffi", "ecdsa_verify_any_safe")
fn ecdsa_verify_any(
  message: BitArray,
  signature: BitArray,
  public: BitArray,
) -> Bool

@external(erlang, "cp_crypto_ffi", "ed25519_verify_safe")
fn ed25519_verify_safe(
  message: BitArray,
  signature: BitArray,
  public: BitArray,
) -> Bool

/// Verifies one signature over the canonical bytes.
///
/// Sigstore's TUF signatures are DER; the fixed-width `r‖s` form is accepted
/// too, being the same signature written the other way — conceding nothing
/// beyond the malleability ASN.1 already has, and matching what the client
/// accepts.
fn verify_signature(key: Key, message: BitArray, signature: BitArray) -> Bool {
  case key.scheme {
    Ed25519 -> ed25519_verify_safe(message, signature, key.point)
    EcdsaP256Sha256 -> ecdsa_verify_any(message, signature, key.point)
  }
}

// ------------------------------------------------------------------- bytes

/// The key id TUF derives for a key object: SHA-256 over its canonical JSON.
///
/// Informational, not a lookup path — the id a role names is the key table's
/// own key. Sigstore's roots agree with this derivation for every key in
/// every root but one (root 11 kept a key's id while editing an
/// `x-tuf-on-ci-online-uri` member inside it), which is why the table is
/// authoritative and this exists for a fixture test to say so.
pub fn key_id(key: Json) -> String {
  sha256_hex(canonical.encode(key))
}

/// Lowercase hex, the encoding TUF writes digests and signatures in.
fn unhex(text: String) -> Result(BitArray, Nil) {
  bit_array.base16_decode(string.uppercase(text))
}

fn sha256_hex(bytes: BitArray) -> String {
  string.lowercase(bit_array.base16_encode(crypto.hash(crypto.Sha256, bytes)))
}
