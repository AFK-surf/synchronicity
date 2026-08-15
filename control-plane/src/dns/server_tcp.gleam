//// DNS over TCP (RFC 1035 §4.2.2): 2-byte length framing over glisten.
//// No truncation here — TCP is where truncated UDP clients retry.

import dns/serve.{type Serving}
import gleam/bit_array
import gleam/bytes_tree
import gleam/option.{None}
import gleam/otp/static_supervisor
import gleam/otp/supervision
import glisten

/// DNS-over-TCP as a supervised child (glisten brings its own subtree).
pub fn supervised(
  port: Int,
  serving: Serving,
) -> supervision.ChildSpecification(static_supervisor.Supervisor) {
  glisten.new(fn(_conn) { #(#(<<>>, serving), None) }, loop)
  |> glisten.bind("0.0.0.0")
  |> glisten.supervised(port)
}

fn loop(
  state: #(BitArray, Serving),
  message: glisten.Message(a),
  conn: glisten.Connection(a),
) -> glisten.Next(#(BitArray, Serving), glisten.Message(a)) {
  let #(buffer, serving) = state
  case message {
    glisten.Packet(data) -> {
      let buffer = bit_array.concat([buffer, data])
      glisten.continue(#(drain(buffer, serving, conn), serving))
    }
    glisten.User(_) -> glisten.continue(state)
  }
}

fn drain(
  buffer: BitArray,
  serving: Serving,
  conn: glisten.Connection(a),
) -> BitArray {
  case buffer {
    <<size:int-size(16), message:bytes-size(size), rest:bits>> -> {
      case serve.handle_packet(serving, message, serve.Stream) {
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
      drain(rest, serving, conn)
    }
    _ -> buffer
  }
}
