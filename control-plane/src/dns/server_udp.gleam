//// DNS over UDP: a passive-recv loop on one socket. Datagram in, answer
//// out, truncating to the query's EDNS limit. Answers come straight from
//// pooled SQLite reads; the loop is serial, which is ample for this
//// service's QPS.

import dns/serve.{type Serving}
import gleam/erlang/process

/// gen_udp socket (opaque).
pub type Socket

/// Peer address (opaque {ip, port} pair, passed straight back to send).
pub type Peer

pub type RecvError {
  Timeout
  Closed
}

@external(erlang, "cp_udp_ffi", "udp_open")
fn udp_open(port: Int) -> Result(Socket, Nil)

@external(erlang, "cp_udp_ffi", "udp_recv")
fn udp_recv(
  socket: Socket,
  timeout_ms: Int,
) -> Result(#(Peer, BitArray), RecvError)

@external(erlang, "cp_udp_ffi", "udp_send")
fn udp_send(socket: Socket, peer: Peer, packet: BitArray) -> Result(Nil, Nil)

/// Binds the port and starts the serving loop in its own process.
pub fn start(port: Int, serving: Serving) -> Result(Nil, String) {
  case udp_open(port) {
    Ok(socket) -> {
      process.spawn(fn() { loop(socket, serving) })
      Ok(Nil)
    }
    Error(Nil) ->
      Error(
        "could not bind UDP port — privileged ports need CAP_NET_BIND_SERVICE",
      )
  }
}

fn loop(socket: Socket, serving: Serving) -> Nil {
  case udp_recv(socket, 30_000) {
    Error(Timeout) -> loop(socket, serving)
    Error(Closed) -> Nil
    Ok(#(peer, packet)) -> {
      case serve.handle_packet(serving, packet, True) {
        Ok(response) -> {
          let _ = udp_send(socket, peer, response)
          Nil
        }
        Error(Nil) -> Nil
      }
      loop(socket, serving)
    }
  }
}
