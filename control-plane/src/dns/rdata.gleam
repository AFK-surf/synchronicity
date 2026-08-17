//// RDATA builders for the record types this zone serves — and only those.
//// Everything is emitted in canonical form (names lowercase, uncompressed)
//// so the same bytes feed both responses and RRSIG signing input.

import dns/name.{type Name}
import dns/wire
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string

@external(erlang, "cp_udp_ffi", "parse_ip")
fn parse_ip(text: String) -> Result(BitArray, Nil)

/// A full uncompressed RR: owner, type, class IN, ttl, rdata.
pub fn rr(owner: Name, rtype: Int, ttl: Int, rdata: BitArray) -> BitArray {
  <<
    name.encode(owner):bits,
    rtype:int-size(16),
    wire.class_in:int-size(16),
    ttl:int-size(32),
    bit_array.byte_size(rdata):int-size(16),
    rdata:bits,
  >>
}

/// TXT rdata: the record text as character-strings. Strings over 255 bytes
/// are split into consecutive chunks — the synchronicity client
/// concatenates chunks before parsing.
pub fn txt(text: String) -> BitArray {
  let bits = <<text:utf8>>
  chunk_txt(bits, [])
}

fn chunk_txt(bits: BitArray, acc: List(BitArray)) -> BitArray {
  let size = bit_array.byte_size(bits)
  case size <= 255 {
    True ->
      bit_array.concat(list.reverse([<<size:int-size(8), bits:bits>>, ..acc]))
    False -> {
      let assert Ok(head) = bit_array.slice(bits, 0, 255)
      let assert Ok(rest) = bit_array.slice(bits, 255, size - 255)
      chunk_txt(rest, [<<255:int-size(8), head:bits>>, ..acc])
    }
  }
}

pub fn soa(
  mname: Name,
  rname: Name,
  serial: Int,
  refresh: Int,
  retry: Int,
  expire: Int,
  minimum: Int,
) -> BitArray {
  <<
    name.encode(mname):bits,
    name.encode(rname):bits,
    serial:int-size(32),
    refresh:int-size(32),
    retry:int-size(32),
    expire:int-size(32),
    minimum:int-size(32),
  >>
}

pub fn ns(host: Name) -> BitArray {
  name.encode(host)
}

/// A or AAAA rdata from a presentation-form address; the byte length
/// decides the type (4 → A, 16 → AAAA).
pub fn address(text: String) -> Result(#(Int, BitArray), Nil) {
  case parse_ip(text) {
    Ok(bytes) ->
      case bit_array.byte_size(bytes) {
        4 -> Ok(#(wire.type_a, bytes))
        16 -> Ok(#(wire.type_aaaa, bytes))
        _ -> Error(Nil)
      }
    Error(Nil) -> Error(Nil)
  }
}

/// DNSKEY rdata. `public_key` is the algorithm-specific key material —
/// for ECDSA P-256 (alg 13) the 64-byte uncompressed point without the
/// 0x04 prefix (RFC 6605 §4).
pub fn dnskey(flags: Int, algorithm: Int, public_key: BitArray) -> BitArray {
  <<flags:int-size(16), 3:int-size(8), algorithm:int-size(8), public_key:bits>>
}

/// RRSIG rdata (RFC 4034 §3.1). `signature` may be empty while building
/// the signing input — the signed data is exactly this rdata sans
/// signature, followed by the canonical RRset.
pub fn rrsig(
  type_covered: Int,
  algorithm: Int,
  labels: Int,
  original_ttl: Int,
  expiration: Int,
  inception: Int,
  key_tag: Int,
  signer: Name,
  signature: BitArray,
) -> BitArray {
  <<
    type_covered:int-size(16),
    algorithm:int-size(8),
    labels:int-size(8),
    original_ttl:int-size(32),
    expiration:int-size(32),
    inception:int-size(32),
    key_tag:int-size(16),
    name.encode(signer):bits,
    signature:bits,
  >>
}

/// NSEC rdata: next owner plus the type bitmap of the types present at
/// this owner (RFC 4034 §4.1.2 window-block encoding).
pub fn nsec(next: Name, types: List(Int)) -> BitArray {
  <<name.encode(next):bits, type_bitmap(types):bits>>
}

/// The RFC 4034 type bitmap, standalone for testability.
pub fn type_bitmap(types: List(Int)) -> BitArray {
  let sorted = list.sort(list.unique(types), int.compare)
  windows(sorted, [])
}

fn windows(types: List(Int), acc: List(BitArray)) -> BitArray {
  case types {
    [] -> bit_array.concat(list.reverse(acc))
    [first, ..] -> {
      let window = first / 256
      let #(mine, rest) = list.split_while(types, fn(t) { t / 256 == window })
      let in_window = list.map(mine, fn(t) { t % 256 })
      let max = case list.last(in_window) {
        Ok(m) -> m
        Error(_) -> 0
      }
      let len = max / 8 + 1
      let bitmap = bitmap_bytes(0, len, in_window, <<>>)
      windows(rest, [
        <<window:int-size(8), len:int-size(8), bitmap:bits>>,
        ..acc
      ])
    }
  }
}

fn bitmap_bytes(
  byte_index: Int,
  len: Int,
  in_window: List(Int),
  acc: BitArray,
) -> BitArray {
  case byte_index == len {
    True -> acc
    False -> {
      let byte =
        list.fold(in_window, 0, fn(acc, t) {
          case t / 8 == byte_index {
            True -> int.bitwise_or(acc, int.bitwise_shift_left(1, 7 - t % 8))
            False -> acc
          }
        })
      bitmap_bytes(byte_index + 1, len, in_window, <<
        acc:bits,
        byte:int-size(8),
      >>)
    }
  }
}

/// The OPT pseudo-RR for responses: our advertised UDP size, DO echoed.
pub fn opt(udp_size: Int, do_bit: Bool) -> wire.Section {
  let do_int = case do_bit {
    True -> 1
    False -> 0
  }
  wire.Section(
    <<
      0:int-size(8),
      wire.type_opt:int-size(16),
      udp_size:int-size(16),
      0:int-size(8),
      0:int-size(8),
      do_int:int-size(1),
      0:int-size(15),
      0:int-size(16),
    >>,
    1,
  )
}

/// The label the zone's transparency declaration lives under, one below the
/// apex (docs/REKOR-ZONE-KEY.md §2.1).
///
/// This record is what makes a log entry the zone's own statement. A
/// delegation chain is public data anybody can collect, so an entry proving
/// only that would be something a stranger could mint about a zone that never
/// heard of them; the declaration is the part only somebody who can write to
/// the zone can produce. It is signed like every other RRset, and a copy of
/// it — with its RRSIG — is the bottom link of every chain this service logs.
///
/// It lives here, beside `sync1_text`, because both the zone builder and the
/// chain collector need it and they sit on opposite sides of an import cycle.
pub const transparency_label = "_synchronicity-transparency"

/// What the declaration says.
pub const transparency_text = "v=sync1 transparency"

/// Renders a `v=sync1` membership TXT record's text. Field order matters
/// only for v=; the client ignores unknown fields and order otherwise.
pub fn sync1_text(
  label: String,
  nk_z32: String,
  relay: String,
  addr: String,
  apex: String,
) -> String {
  // `apex=` is how a client finds the transparency records for *this*
  // control plane. It cannot derive the name: the zone that signed the
  // answer may hold several control planes, and every one of them owns its
  // own records. The client checks the value at both ends rather than
  // trusting it — it must contain the domain and sit inside the signing
  // zone — so it is a pointer, not an authority.
  let base =
    "v=sync1 id=" <> label <> " nk=" <> nk_z32 <> " apex=" <> strip_dot(apex)
  let with_relay = case relay {
    "" -> base
    r -> base <> " relay=" <> r
  }
  case addr {
    "" -> with_relay
    a -> with_relay <> " addr=" <> a
  }
}

fn strip_dot(text: String) -> String {
  case string.ends_with(text, ".") {
    True -> string.drop_end(text, 1)
    False -> text
  }
}
