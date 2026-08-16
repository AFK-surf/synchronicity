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

pub fn main() {
  let links = [
    cert.Link("sync.test.", <<0xaa, 0xbb, 0xcc>>),
    cert.Link(".", <<0x01, 0x02>>),
  ]
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
