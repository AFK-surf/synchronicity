//// Writes the deterministic certificate-crossval fixtures
//// (test/fixtures/rekor/crossval), which both this suite and the Rust one
//// assert against. Run deliberately, never as part of a test:
////
////     gleam run -m tools/gen_crossval
////
//// Two implementations of one DER format drift silently unless something
//// outside both of them holds the bytes still. These are those bytes.

import dns/name.{type Name}
import dns/rdata
import dns/wire
import dnssec/keys.{type Csk}
import dnssec/sign
import gleam/io
import gleam/list
import gleam/option.{Some}
import rekor/cert
import rekor/chain
import simplifile

const dir = "test/fixtures/rekor/crossval/"

/// The DNSKEY rdata the DS-digest fixture is taken over.
///
/// A fixed, boring key: what is being pinned is the *digest construction*
/// (lowercased owner name in wire form, then the rdata, then the hash), not
/// anything about the key. Both digest types are written, because `covers`
/// on the Rust side dispatches on the type and the publisher has to agree
/// with it on both arms.
pub fn ds_digest_key() -> BitArray {
  <<257:int-size(16), 3:int-size(8), 13:int-size(8), 7:size(512)>>
}

/// The zone the DS-digest fixture is taken over — mixed case deliberately,
/// since the construction lowercases and a reader that does not would pass
/// every same-case test.
pub const ds_digest_zone = "Sync.Test."

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

/// A seeded two-zone universe — root and `sync.test.` — served by a resolver
/// that signs for real, so `rekor/chain.collect` produces a chain the client's
/// own walk can be run over.
///
/// This is the one duplication in the design that had no cross-language check
/// at all. `crossval/chain.der` pins the DER *container*; the chain
/// `chain.collect` actually builds — the declaration and its three rules, the
/// DNSKEY and DS RRsets, the RRSIG canonical form, the wire RRs the links
/// carry, the ladder's shape — reached the Rust reader nowhere. So a change on
/// either side that made the two disagree shipped green on both suites and
/// surfaced as a permanent, un-withdrawable public log entry that no client
/// accepts.
///
/// The ladder is deliberately a **real descent**: the root signs a DS for
/// `sync.test.`, so a reader has to verify that DS under the root's key and
/// then match its digest against the apex's DNSKEY rdata. `test.` answers
/// nothing, which is the ordinary empty-non-terminal shape and the one a
/// label-counting ladder rule cannot encode.
pub fn seeded_chain() -> #(List(cert.Link), Csk, Csk) {
  let root = keys.generate()
  let apex_csk = keys.generate()
  let apex = seeded_apex()
  let #(inception, expiration) = #(1_786_866_288, 1_786_866_288 + 3_155_760_000)

  let dnskey_rd = fn(csk: Csk) { keys.dnskey_rdata(csk) }
  let tag = fn(csk: Csk) { keys.key_tag(dnskey_rd(csk)) }
  let signed = fn(
    csk: Csk,
    signer: Name,
    owner: Name,
    rtype: Int,
    rdatas: List(BitArray),
  ) {
    let rrsig =
      sign.sign_rrset_rdata(
        csk,
        tag(csk),
        signer,
        owner,
        rtype,
        3600,
        rdatas,
        inception,
        expiration,
      )
    list.append(
      list.map(rdatas, fn(rd) { wire.Rr(owner, rtype, wire.class_in, 3600, rd) }),
      [wire.Rr(owner, wire.type_rrsig, wire.class_in, 3600, rrsig)],
    )
  }

  // The DS the root publishes for the apex: tag, algorithm, digest type 2,
  // and the SHA-256 over the owner name and the DNSKEY rdata.
  let ds_rd = <<
    tag(apex_csk):int-size(16),
    keys.algorithm:int-size(8),
    2:int-size(8),
    keys.ds_digest(apex, dnskey_rd(apex_csk)):bits,
  >>

  let resolver =
    chain.Resolver(query: fn(zone: Name, rtype: Int) {
      let declaration = [rdata.transparency_label, ..apex]
      case zone, rtype {
        z, t if z == declaration && t == wire.type_txt ->
          Ok(
            signed(apex_csk, apex, z, wire.type_txt, [
              rdata.txt(rdata.transparency_text),
            ]),
          )
        z, t if z == apex && t == wire.type_dnskey ->
          Ok(signed(apex_csk, apex, z, wire.type_dnskey, [dnskey_rd(apex_csk)]))
        // Signed by the **root**: a DS lives in the parent, and the RRSIG's
        // signer name is what says so.
        z, 43 if z == apex -> Ok(signed(root, [], z, 43, [ds_rd]))
        [], t if t == wire.type_dnskey ->
          Ok(signed(root, [], [], wire.type_dnskey, [dnskey_rd(root)]))
        // `test.` is an empty non-terminal, and every other name is absent.
        _, _ -> Ok([])
      }
    })

  let assert Ok(#(links, _rdatas)) = chain.collect(resolver, apex, apex)
  // `rekor/chain` and `rekor/cert` name the same shape separately; the
  // publisher converts between them at exactly this point.
  let links = list.map(links, fn(l: chain.Link) { cert.Link(l.zone, l.rrs) })
  #(links, root, apex_csk)
}

/// The apex the seeded chain is built for.
pub fn seeded_apex() -> Name {
  let assert Ok(apex) = name.parse("sync.test.")
  apex
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

  // A chain this side actually collected, from a seeded zone with real
  // signatures, plus the anchor a reader of it installs. The Rust suite runs
  // `chain::authorize` over exactly these bytes — the only place either
  // implementation's chain *semantics* meet the other's.
  let #(collected, root, _apex_csk) = seeded_chain()
  write("chain-collected.der", cert.encode_chain(collected))
  let assert Ok(Nil) =
    simplifile.write(
      dir <> "chain-anchor.key",
      keys.anchor_line([], root.public),
    )
  io.println("wrote " <> dir <> "chain-anchor.key")

  // The DS digests, both types, over one fixed key at a mixed-case owner.
  // `chain.rs`'s `covers` recomputes these to decide whether a delegation
  // walks, and `rekor/chain.check_ds_covers` recomputes them to decide
  // whether a chain is publishable — two implementations of one hash input,
  // with nothing outside either of them holding it still until now.
  let assert Ok(zone) = name.parse(ds_digest_zone)
  write("ds-digest-sha256.bin", keys.ds_digest(zone, ds_digest_key()))
  write("ds-digest-sha384.bin", keys.ds_digest_384(zone, ds_digest_key()))
}
