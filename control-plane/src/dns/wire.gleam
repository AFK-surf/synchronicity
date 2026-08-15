//// DNS message codec — exactly the surface an authoritative server needs.
//// Decoding handles compression pointers (resolvers may compress);
//// everything we emit is uncompressed, which is always legal.

import dns/name.{type Name}
import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result

pub const type_a = 1

pub const type_ns = 2

pub const type_soa = 6

pub const type_txt = 16

pub const type_aaaa = 28

pub const type_opt = 41

pub const type_rrsig = 46

pub const type_nsec = 47

pub const type_dnskey = 48

pub const class_in = 1

/// The EDNS0 state of a query.
pub type Edns {
  Edns(udp_size: Int, do_bit: Bool)
}

/// One parsed query (QDCOUNT must be 1, as it is in practice).
pub type Query {
  Query(
    id: Int,
    opcode: Int,
    rd: Bool,
    qname: Name,
    qtype: Int,
    qclass: Int,
    edns: Option(Edns),
  )
}

/// One resource record, rdata left raw.
pub type Rr {
  Rr(name: Name, rtype: Int, class: Int, ttl: Int, rdata: BitArray)
}

/// A decoded message — used by tests and debugging tools; the serving path
/// only ever decodes queries and emits responses.
pub type Message {
  Message(
    id: Int,
    flags: Int,
    questions: List(#(Name, Int, Int)),
    answers: List(Rr),
    authority: List(Rr),
    additional: List(Rr),
  )
}

pub type DecodeError {
  Malformed
  /// Parsed enough to reply FORMERR/NOTIMP with the right id.
  Unsupported(id: Int)
}

const max_pointer_hops = 32

/// Decodes an incoming query datagram.
pub fn decode_query(msg: BitArray) -> Result(Query, DecodeError) {
  case msg {
    <<
      id:int-size(16),
      qr:int-size(1),
      opcode:int-size(4),
      _aa:int-size(1),
      _tc:int-size(1),
      rd:int-size(1),
      _ra:int-size(1),
      _z:int-size(3),
      _rcode:int-size(4),
      qdcount:int-size(16),
      ancount:int-size(16),
      nscount:int-size(16),
      arcount:int-size(16),
      _rest:bits,
    >> -> {
      use <- require(qr == 0 && qdcount == 1, Unsupported(id))
      use #(qname, offset) <- result.try(
        decode_name(msg, 12, 0) |> result.replace_error(Malformed),
      )
      case bit_array.slice(msg, offset, 4) {
        Ok(<<qtype:int-size(16), qclass:int-size(16)>>) -> {
          // Skip answer/authority, then look for OPT among the additionals.
          use offset <- result.try(
            skip_rrs(msg, offset + 4, ancount + nscount)
            |> result.replace_error(Malformed),
          )
          use edns <- result.try(
            find_opt(msg, offset, arcount) |> result.replace_error(Malformed),
          )
          Ok(Query(id, opcode, rd == 1, qname, qtype, qclass, edns))
        }
        _ -> Error(Malformed)
      }
    }
    _ -> Error(Malformed)
  }
}

fn require(
  condition: Bool,
  error: DecodeError,
  next: fn() -> Result(a, DecodeError),
) -> Result(a, DecodeError) {
  case condition {
    True -> next()
    False -> Error(error)
  }
}

/// Decodes a name starting at `offset`; returns labels and the offset just
/// past the name (in its non-pointer prefix).
pub fn decode_name(
  msg: BitArray,
  offset: Int,
  hops: Int,
) -> Result(#(Name, Int), Nil) {
  use <- bool_guard(hops > max_pointer_hops)
  case bit_array.slice(msg, offset, 1) {
    Ok(<<0>>) -> Ok(#([], offset + 1))
    Ok(<<len:int-size(8)>>) if len < 64 -> {
      use label_bytes <- result.try(bit_array.slice(msg, offset + 1, len))
      use label <- result.try(
        bit_array.to_string(label_bytes) |> result.replace_error(Nil),
      )
      use #(rest, end) <- result.try(decode_name(msg, offset + 1 + len, hops))
      Ok(#([lowercase_ascii(label), ..rest], end))
    }
    Ok(<<tag:int-size(2), _:int-size(6)>>) if tag == 3 -> {
      // Compression pointer: 2 bytes, must point backwards.
      case bit_array.slice(msg, offset, 2) {
        Ok(<<3:int-size(2), target:int-size(14)>>) -> {
          use <- bool_guard(target >= offset)
          use #(labels, _) <- result.try(decode_name(msg, target, hops + 1))
          Ok(#(labels, offset + 2))
        }
        _ -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}

fn bool_guard(fail: Bool, next: fn() -> Result(a, Nil)) -> Result(a, Nil) {
  case fail {
    True -> Error(Nil)
    False -> next()
  }
}

fn lowercase_ascii(s: String) -> String {
  // Labels are ASCII; string.lowercase is correct and cheap for them.
  case s {
    "" -> ""
    _ ->
      s
      |> bit_array.from_string
      |> lowercase_bytes(<<>>)
  }
}

fn lowercase_bytes(bytes: BitArray, acc: BitArray) -> String {
  case bytes {
    <<>> ->
      case bit_array.to_string(acc) {
        Ok(s) -> s
        Error(_) -> ""
      }
    <<b:int-size(8), rest:bits>> -> {
      let lower = case b >= 65 && b <= 90 {
        True -> b + 32
        False -> b
      }
      lowercase_bytes(rest, <<acc:bits, lower:int-size(8)>>)
    }
    _ -> ""
  }
}

fn skip_rrs(msg: BitArray, offset: Int, count: Int) -> Result(Int, Nil) {
  case count {
    0 -> Ok(offset)
    _ -> {
      use #(_, offset) <- result.try(decode_name(msg, offset, 0))
      case bit_array.slice(msg, offset, 10) {
        Ok(<<
          _:int-size(16),
          _:int-size(16),
          _:int-size(32),
          rdlen:int-size(16),
        >>) -> skip_rrs(msg, offset + 10 + rdlen, count - 1)
        _ -> Error(Nil)
      }
    }
  }
}

fn find_opt(
  msg: BitArray,
  offset: Int,
  count: Int,
) -> Result(Option(Edns), Nil) {
  case count {
    0 -> Ok(None)
    _ -> {
      use #(_, offset) <- result.try(decode_name(msg, offset, 0))
      case bit_array.slice(msg, offset, 10) {
        Ok(<<
          rtype:int-size(16),
          class:int-size(16),
          _ext:int-size(8),
          _version:int-size(8),
          do_bit:int-size(1),
          _z:int-size(15),
          rdlen:int-size(16),
        >>) ->
          case rtype == type_opt {
            True -> Ok(Some(Edns(class, do_bit == 1)))
            False -> find_opt(msg, offset + 10 + rdlen, count - 1)
          }
        _ -> Error(Nil)
      }
    }
  }
}

/// Fully decodes a message (tests / debug tooling).
pub fn decode_message(msg: BitArray) -> Result(Message, Nil) {
  case msg {
    <<
      id:int-size(16),
      flags:int-size(16),
      qdcount:int-size(16),
      ancount:int-size(16),
      nscount:int-size(16),
      arcount:int-size(16),
      _:bits,
    >> -> {
      use #(questions, offset) <- result.try(
        decode_questions(msg, 12, qdcount, []),
      )
      use #(answers, offset) <- result.try(decode_rrs(msg, offset, ancount, []))
      use #(authority, offset) <- result.try(
        decode_rrs(msg, offset, nscount, []),
      )
      use #(additional, _) <- result.try(decode_rrs(msg, offset, arcount, []))
      Ok(Message(id, flags, questions, answers, authority, additional))
    }
    _ -> Error(Nil)
  }
}

fn decode_questions(
  msg: BitArray,
  offset: Int,
  count: Int,
  acc: List(#(Name, Int, Int)),
) -> Result(#(List(#(Name, Int, Int)), Int), Nil) {
  case count {
    0 -> Ok(#(list.reverse(acc), offset))
    _ -> {
      use #(qname, offset) <- result.try(decode_name(msg, offset, 0))
      case bit_array.slice(msg, offset, 4) {
        Ok(<<qtype:int-size(16), qclass:int-size(16)>>) ->
          decode_questions(msg, offset + 4, count - 1, [
            #(qname, qtype, qclass),
            ..acc
          ])
        _ -> Error(Nil)
      }
    }
  }
}

fn decode_rrs(
  msg: BitArray,
  offset: Int,
  count: Int,
  acc: List(Rr),
) -> Result(#(List(Rr), Int), Nil) {
  case count {
    0 -> Ok(#(list.reverse(acc), offset))
    _ -> {
      use #(rname, offset) <- result.try(decode_name(msg, offset, 0))
      case bit_array.slice(msg, offset, 10) {
        Ok(<<
          rtype:int-size(16),
          class:int-size(16),
          ttl:int-size(32),
          rdlen:int-size(16),
        >>) -> {
          use rdata <- result.try(bit_array.slice(msg, offset + 10, rdlen))
          decode_rrs(msg, offset + 10 + rdlen, count - 1, [
            Rr(rname, rtype, class, ttl, rdata),
            ..acc
          ])
        }
        _ -> Error(Nil)
      }
    }
  }
}

/// One section's worth of preassembled RRs: wire bytes + how many RRs.
pub type Section {
  Section(wire: BitArray, count: Int)
}

pub fn empty_section() -> Section {
  Section(<<>>, 0)
}

pub fn append(a: Section, b: Section) -> Section {
  Section(bit_array.concat([a.wire, b.wire]), a.count + b.count)
}

/// Assembles a response to `query`. The question is echoed; sections are
/// preassembled wire blobs (uncompressed RRs).
pub fn encode_response(
  query: Query,
  rcode: Int,
  aa: Bool,
  tc: Bool,
  answers: Section,
  authority: Section,
  additional: Section,
) -> BitArray {
  let question = <<
    name.encode(query.qname):bits,
    query.qtype:int-size(16),
    query.qclass:int-size(16),
  >>
  let aa_bit = bool_to_int(aa)
  let tc_bit = bool_to_int(tc)
  let rd_bit = bool_to_int(query.rd)
  <<
    query.id:int-size(16),
    1:int-size(1),
    query.opcode:int-size(4),
    aa_bit:int-size(1),
    tc_bit:int-size(1),
    rd_bit:int-size(1),
    0:int-size(1),
    0:int-size(3),
    rcode:int-size(4),
    1:int-size(16),
    answers.count:int-size(16),
    authority.count:int-size(16),
    additional.count:int-size(16),
    question:bits,
    answers.wire:bits,
    authority.wire:bits,
    additional.wire:bits,
  >>
}

fn bool_to_int(b: Bool) -> Int {
  case b {
    True -> 1
    False -> 0
  }
}

/// Counts RRs in an uncompressed wire blob (as stored in presigned_rrsets).
pub fn count_rrs(blob: BitArray) -> Result(Int, Nil) {
  count_rrs_from(blob, 0, 0)
}

fn count_rrs_from(blob: BitArray, offset: Int, acc: Int) -> Result(Int, Nil) {
  case offset == bit_array.byte_size(blob) {
    True -> Ok(acc)
    False -> {
      use #(_, offset) <- result.try(decode_name(blob, offset, 0))
      case bit_array.slice(blob, offset, 10) {
        Ok(<<_:int-size(48), _:int-size(16), rdlen:int-size(16)>>) ->
          count_rrs_from(blob, offset + 10 + rdlen, acc + 1)
        _ -> Error(Nil)
      }
    }
  }
}
