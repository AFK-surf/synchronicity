//// DNS over UDP as a supervised actor over an active-once socket.
//// Datagram in, answer out, truncating to the query's EDNS limit.
//// The socket dying is an abnormal actor exit — the supervisor restarts
//// the child and the socket is rebound. UDP serving can degrade loudly,
//// never silently.

import dns/serve.{type Serving}
import gleam/dynamic.{type Dynamic}
import gleam/erlang/atom
import gleam/erlang/process
import gleam/int
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result

/// gen_udp socket (opaque).
pub type Socket

/// Peer address (opaque {ip, port} pair, passed straight back to send).
pub type Peer

/// One classified active-mode socket message — named Event rather than
/// Msg because these arrive from the socket, not from actor mail.
pub type Event {
  Packet(peer: Peer, data: BitArray)
  SocketClosed
  SocketError
}

@external(erlang, "cp_udp_ffi", "udp_open_active")
fn udp_open_active(listen: String, port: Int) -> Result(Socket, Nil)

@external(erlang, "cp_udp_ffi", "udp_active_once")
fn udp_active_once(socket: Socket) -> Result(Nil, Nil)

@external(erlang, "cp_udp_ffi", "udp_send")
fn udp_send(socket: Socket, peer: Peer, packet: BitArray) -> Result(Nil, Nil)

@external(erlang, "cp_udp_ffi", "udp_event")
fn udp_event(message: Dynamic) -> Event

type State {
  State(socket: Socket, serving: Serving)
}

/// The UDP server as a supervised child.
pub fn supervised(
  name: process.Name(Event),
  listen: String,
  port: Int,
  serving: Serving,
) -> supervision.ChildSpecification(Nil) {
  supervision.worker(fn() {
    let builder =
      actor.new_with_initialiser(10_000, fn(_subject) {
        case udp_open_active(listen, port) {
          Error(Nil) ->
            Error("could not bind UDP " <> listen <> ":" <> int.to_string(port))
          Ok(socket) -> {
            let selector =
              process.new_selector()
              |> process.select_record(atom.create("udp"), 4, udp_event)
              |> process.select_record(atom.create("udp_closed"), 1, udp_event)
              |> process.select_record(atom.create("udp_error"), 2, udp_event)
            actor.initialised(State(socket, serving))
            |> actor.selecting(selector)
            |> Ok
          }
        }
      })
      |> actor.named(name)
      |> actor.on_message(handle)
    use started <- result.try(actor.start(builder))
    Ok(actor.Started(started.pid, Nil))
  })
}

fn handle(state: State, event: Event) -> actor.Next(State, Event) {
  case event {
    Packet(peer, data) -> {
      case serve.handle_packet(state.serving, data, serve.Udp) {
        Ok(response) -> {
          let _ = udp_send(state.socket, peer, response)
          Nil
        }
        Error(Nil) -> Nil
      }
      case udp_active_once(state.socket) {
        Ok(Nil) -> actor.continue(state)
        Error(Nil) -> actor.stop_abnormal("udp socket lost")
      }
    }
    // Never die silently: the supervisor restarts us with a fresh bind.
    SocketClosed -> actor.stop_abnormal("udp socket closed")
    SocketError -> actor.stop_abnormal("udp socket error")
  }
}
