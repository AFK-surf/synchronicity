//// The zone's CSK: a single ECDSA P-256 key (DNSSEC algorithm 13) with
//// flags 257 — one key signs everything, one DS at the parent, one anchor
//// line. The private scalar lives in a flat key file on the primary's
//// disk and never enters the database, so replication never carries it.

import dns/name.{type Name}
import dns/rdata
import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import simplifile

/// ECDSA P-256 with SHA-256 (RFC 6605).
pub const algorithm = 13

/// ZONE + SEP: the single-key (CSK) convention.
pub const flags = 257

pub type Csk {
  Csk(private: BitArray, public: BitArray)
}

@external(erlang, "cp_crypto_ffi", "ec_generate")
fn ec_generate() -> #(BitArray, BitArray)

pub fn generate() -> Csk {
  let #(private, public) = ec_generate()
  Csk(private, public)
}

pub fn dnskey_rdata(csk: Csk) -> BitArray {
  rdata.dnskey(flags, algorithm, csk.public)
}

/// RFC 4034 Appendix B key tag over the DNSKEY rdata.
pub fn key_tag(dnskey_rdata: BitArray) -> Int {
  let sum = tag_fold(dnskey_rdata, 0, 0)
  let carried = sum + int.bitwise_and(int.bitwise_shift_right(sum, 16), 0xffff)
  int.bitwise_and(carried, 0xffff)
}

fn tag_fold(bytes: BitArray, index: Int, acc: Int) -> Int {
  case bytes {
    <<>> -> acc
    <<b:int-size(8), rest:bits>> -> {
      let contribution = case index % 2 == 0 {
        True -> int.bitwise_shift_left(b, 8)
        False -> b
      }
      tag_fold(rest, index + 1, acc + contribution)
    }
    _ -> acc
  }
}

/// SHA-256 DS digest: hash(owner wire form || DNSKEY rdata).
pub fn ds_digest(apex: Name, dnskey_rdata: BitArray) -> BitArray {
  crypto.hash(
    crypto.Sha256,
    bit_array.concat([name.encode(apex), dnskey_rdata]),
  )
}

/// The DS record for the parent zone, presentation form. Takes the public
/// key alone — replicas hold no private material and still serve this.
pub fn ds_line(apex: Name, public: BitArray) -> String {
  let rd = rdata.dnskey(flags, algorithm, public)
  name.to_string(apex)
  <> " IN DS "
  <> int.to_string(key_tag(rd))
  <> " "
  <> int.to_string(algorithm)
  <> " 2 "
  <> string.lowercase(bit_array.base16_encode(ds_digest(apex, rd)))
}

/// The trust-anchor line, in the exact file syntax the synchronicity
/// client's `--dnssec-anchor` reads (see synch-net's sim::anchor_record).
pub fn anchor_line(apex: Name, public: BitArray) -> String {
  name.to_string(apex)
  <> " IN DNSKEY "
  <> int.to_string(flags)
  <> " 3 "
  <> int.to_string(algorithm)
  <> " "
  <> bit_array.base64_encode(public, True)
}

/// Writes the key file; refuses to overwrite an existing one — replacing
/// a zone key is a rollover ceremony, not a file write.
pub fn save(path: String, csk: Csk) -> Result(Nil, String) {
  case simplifile.is_file(path) {
    Ok(True) -> Error("refusing to overwrite existing key file " <> path)
    _ -> {
      let content =
        "# synchronicity control-plane zone key: CSK, ECDSA P-256, DNSSEC algorithm "
        <> int.to_string(algorithm)
        <> ".\n"
        <> "# The private line is the zone's whole secret. Primary only; never replicate.\n"
        <> "private: "
        <> bit_array.base64_encode(csk.private, True)
        <> "\npublic: "
        <> bit_array.base64_encode(csk.public, True)
        <> "\n"
      simplifile.write(path, content)
      |> result.map_error(fn(e) {
        "writing " <> path <> ": " <> simplifile.describe_error(e)
      })
    }
  }
}

pub fn load(path: String) -> Result(Csk, String) {
  use content <- result.try(
    simplifile.read(path)
    |> result.map_error(fn(e) {
      "reading " <> path <> ": " <> simplifile.describe_error(e)
    }),
  )
  let lines = string.split(content, "\n")
  use private <- result.try(field(lines, "private: ", path))
  use public <- result.try(field(lines, "public: ", path))
  case bit_array.byte_size(private), bit_array.byte_size(public) {
    32, 64 -> Ok(Csk(private, public))
    _, _ -> Error("malformed key material in " <> path)
  }
}

fn field(
  lines: List(String),
  prefix: String,
  path: String,
) -> Result(BitArray, String) {
  let found =
    list.find_map(lines, fn(line) {
      case string.starts_with(line, prefix) {
        True ->
          bit_array.base64_decode(string.drop_start(line, string.length(prefix)))
        False -> Error(Nil)
      }
    })
  result.replace_error(found, "no '" <> prefix <> "' line in " <> path)
}
