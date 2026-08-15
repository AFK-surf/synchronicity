//// DNS over TCP (RFC 1035 §4.2.2): 2-byte length framing over glisten.
//// No truncation here — TCP is where truncated UDP clients retry.

import dns/query
import dns/wire
import gleam/bit_array
import gleam/bytes_tree
import gleam/option.{None}
import glisten
import zone/snapshot

pub fn start(port: Int) -> Result(Nil, String) {
  let started =
    glisten.new(fn(_conn) { #(<<>>, None) }, loop)
    |> glisten.bind("0.0.0.0")
    |> glisten.start(port)
  case started {
    Ok(_) -> Ok(Nil)
    Error(_) ->
      Error(
        "could not bind TCP port — privileged ports need CAP_NET_BIND_SERVICE",
      )
  }
}

fn loop(
  buffer: BitArray,
  message: glisten.Message(a),
  conn: glisten.Connection(a),
) -> glisten.Next(BitArray, glisten.Message(a)) {
  case message {
    glisten.Packet(data) -> {
      let buffer = bit_array.concat([buffer, data])
      glisten.continue(drain(buffer, conn))
    }
    glisten.User(_) -> glisten.continue(buffer)
  }
}

fn drain(buffer: BitArray, conn: glisten.Connection(a)) -> BitArray {
  case buffer {
    <<size:int-size(16), message:bytes-size(size), rest:bits>> -> {
      case handle(message) {
        Ok(response) -> {
          let framed = <<
            bit_array.byte_size(response):int-size(16),
            response:bits,
          >>
          let _ = glisten.send(conn, bytes_tree.from_bit_array(framed))
          Nil
        }
        Error(Nil) -> Nil
      }
      drain(rest, conn)
    }
    _ -> buffer
  }
}

fn handle(message: BitArray) -> Result(BitArray, Nil) {
  case wire.decode_query(message) {
    Ok(q) ->
      case snapshot.current() {
        Ok(snap) -> Ok(query.answer(snap, q))
        Error(Nil) -> Ok(query.error_stub(q.id, 2))
      }
    Error(wire.Unsupported(id)) -> Ok(query.error_stub(id, query.rcode_notimp))
    Error(wire.Malformed) -> Error(Nil)
  }
}
