//// DNS over UDP: a passive-recv loop on one socket. Datagram in, answer
//// out, truncating to the query's EDNS limit; the snapshot read is
//// zero-copy so the single loop keeps up far past this service's QPS.

import dns/query
import dns/wire
import gleam/erlang/process
import zone/snapshot

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
pub fn start(port: Int) -> Result(Nil, String) {
  case udp_open(port) {
    Ok(socket) -> {
      process.spawn(fn() { loop(socket) })
      Ok(Nil)
    }
    Error(Nil) ->
      Error(
        "could not bind UDP port — privileged ports need CAP_NET_BIND_SERVICE",
      )
  }
}

fn loop(socket: Socket) -> Nil {
  case udp_recv(socket, 30_000) {
    Error(Timeout) -> loop(socket)
    Error(Closed) -> Nil
    Ok(#(peer, packet)) -> {
      case handle(packet) {
        Ok(response) -> {
          let _ = udp_send(socket, peer, response)
          Nil
        }
        Error(Nil) -> Nil
      }
      loop(socket)
    }
  }
}

/// One datagram's worth of work; pure given the installed snapshot.
pub fn handle(packet: BitArray) -> Result(BitArray, Nil) {
  case wire.decode_query(packet) {
    Ok(q) ->
      case snapshot.current() {
        Ok(snap) -> Ok(query.fit_udp(q, query.answer(snap, q)))
        // No snapshot loaded yet: SERVFAIL (rcode 2) beats silence.
        Error(Nil) -> Ok(query.error_stub(q.id, 2))
      }
    Error(wire.Unsupported(id)) -> Ok(query.error_stub(id, query.rcode_notimp))
    Error(wire.Malformed) -> Error(Nil)
  }
}
