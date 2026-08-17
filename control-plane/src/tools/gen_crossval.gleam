//// Writes the deterministic certificate-crossval fixtures
//// (test/fixtures/rekor/crossval), which both this suite and the Rust one
//// assert against. Run deliberately, never as part of a test:
////
////     gleam run -m tools/gen_crossval
////
//// Two implementations of one DER format drift silently unless something
//// outside both of them holds the bytes still. These are those bytes.

import dnssec/keys
import gleam/io
import gleam/option.{Some}
import rekor/cert
import simplifile

const dir = "test/fixtures/rekor/crossval/"

/// `n` bytes of `i * 7 mod 256`, which is a permutation (7 is odd, so it
/// generates Z/256) — every byte value appears before any repeats, and a
/// reader that drops or reorders one shifts the whole tail rather than
/// landing on a plausible-looking value.
pub fn pattern(n: Int) -> BitArray {
  build_pattern(0, n, <<>>)
}

fn build_pattern(i: Int, n: Int, acc: BitArray) -> BitArray {
  case i >= n {
    True -> acc
    False -> build_pattern(i + 1, n, <<acc:bits, { i * 7 % 256 }:8>>)
  }
}

/// The chain the fixture pins, and the single Gleam-side definition of it:
/// `rekor_test` asserts *this* list encodes to the checked-in bytes, so a
/// generator edit that is never regenerated fails instead of drifting. The
/// Rust suite restates the same structure independently — that restatement
/// is the actual cross-language check.
///
/// The two long links are the point. A chain of real DNSKEY/DS/RRSIG sets
/// is kilobytes, so every link in production uses DER's *long form* length;
/// a fixture of only short-form links leaves both sides' long-form encoders
/// untested, and an off-by-one there passes the whole suite and fails on
/// the first live submission. 200 bytes takes the one-byte long form
/// (`0x81 0xc8`), 256 takes the two-byte form (`0x82 0x01 0x00`), and
/// together they push the outer SEQUENCE over 255 so its own length is
/// long-form too.
pub fn links() -> List(cert.Link) {
  [
    cert.Link("sync.test.", <<0xaa, 0xbb, 0xcc>>),
    cert.Link(".", <<0x01, 0x02>>),
    cert.Link("long.sync.test.", pattern(200)),
    cert.Link("longer.sync.test.", pattern(256)),
  ]
}

pub fn main() {
  let links = links()
  let write = fn(name, bits) {
    let assert Ok(Nil) = simplifile.write_bits(dir <> name, bits)
    io.println("wrote " <> dir <> name)
  }
  write("chain.der", cert.encode_chain(links))
  // The certificate: a fresh key, because its private half is never needed
  // again — what is checked in is the DER, and what both sides assert is
  // that they read the same SAN, the same SubjectPublicKeyInfo and the same
  // extension value out of it.
  let csk = keys.generate()
  write(
    "certificate.der",
    cert.build(
      "sync.test.",
      csk.public,
      csk.private,
      1_786_866_288,
      1_786_866_288 + 3_155_760_000,
      Some(links),
    ),
  )
}
