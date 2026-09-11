//// Bearer-only socket gateway. CP routes bytes; the hosted DP is the caller.
//// Cookie upgrades are intentionally unsupported: opening a socket is an
//// effect, despite the HTTP GET handshake, and must not be ambient authority.

import api/browse_api
import api/cloud_writer as writer
import api/middleware
import auth/api_key
import gleam/bit_array
import gleam/bytes_tree
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/result
import gleam/uri
import mist
import store/pool.{type Pool}

pub fn authorize(
  headers: List(#(String, String)),
  db: Pool,
  slug: String,
  network: String,
) -> Result(String, #(Int, String)) {
  use token <- result.try(case middleware.presented(headers) {
    middleware.Bearer(token) -> Ok(token)
    _ -> Error(#(401, "a bearer API key is required"))
  })
  use who <- result.try(
    case
      pool.with_connection(db, fn(conn) {
        api_key.authenticate(conn, token, middleware.now_unix())
      })
    {
      Ok(Ok(who)) -> Ok(who)
      _ -> Error(#(401, "invalid or expired API key"))
    },
  )
  case browse_api.for_download(db, who, slug, network) {
    Ok(#(_, id, _, True)) -> Ok(id)
    Ok(_) -> Error(#(409, "hosting is disabled"))
    Error(_) -> Error(#(404, "no such managed network"))
  }
}

pub fn handle(
  req: Request(mist.Connection),
  browse: browse_api.Browse,
  db: Pool,
  slug: String,
  network: String,
  connect: Bool,
) -> Response(mist.ResponseData) {
  let params =
    uri.parse_query(option.unwrap(req.query, "")) |> result.unwrap([])
  let origin = list.key_find(params, "origin") |> result.unwrap("")
  let socket = list.key_find(params, "socket") |> result.unwrap("")
  case authorize(req.headers, db, slug, network) {
    Error(#(status, message)) -> deny(status, message)
    Ok(network_id) -> {
      let sessions = writer.sessions_for(browse_api.writers(browse), network_id)
      case writer.pick(sessions) {
        Error(_) -> deny(503, "no managed data plane attached")
        Ok(session) if session.version < 3 ->
          deny(409, "managed tunnel v3 required")
        Ok(session) ->
          case connect && { origin == "" || socket == "" } {
            True -> deny(400, "origin and, for connect, socket are required")
            False ->
              case connect {
                False -> query(session, origin)
                True -> upgrade(req, session, origin, socket, db, slug, network)
              }
          }
      }
    }
  }
}

fn query(
  session: writer.Session,
  origin: String,
) -> Response(mist.ResponseData) {
  let reply = process.new_subject()
  process.send(session.inbox, writer.SocketList(origin, reply))
  case process.receive(reply, 2000) {
    Ok(writer.Assigned(id)) -> {
      let answer = process.receive(reply, 20_000)
      process.send(session.inbox, writer.Cancel(id))
      case answer {
        Ok(writer.SocketInfo(body)) -> response(200, body)
        Ok(writer.Failed(_, message)) -> deny(502, message)
        _ -> deny(504, "socket listing timed out")
      }
    }
    _ -> deny(503, "managed tunnel unavailable")
  }
}

type Message {
  Event(writer.Event)
  Tick
}

type State {
  State(
    session: writer.Session,
    inbox: process.Subject(Message),
    headers: List(#(String, String)),
    db: Pool,
    slug: String,
    network: String,
    id: Int,
    ready: Bool,
    input_credit: Int,
    input_eof: Bool,
    output_pending: Bool,
    input_seq: Int,
    output_seq: Int,
  )
}

fn upgrade(
  req: Request(mist.Connection),
  session: writer.Session,
  origin: String,
  socket: String,
  db: Pool,
  slug: String,
  network: String,
) -> Response(mist.ResponseData) {
  mist.websocket(
    req,
    on_init: fn(_) {
      let inbox = process.new_subject()
      let reply = process.new_subject()
      process.send(session.inbox, writer.SocketOpen(origin, socket, reply))
      process.send_after(inbox, 20_000, Tick)
      #(
        State(
          session,
          inbox,
          req.headers,
          db,
          slug,
          network,
          0,
          False,
          0,
          False,
          False,
          0,
          0,
        ),
        Some(
          process.new_selector()
          |> process.select(inbox)
          |> process.select_map(reply, Event),
        ),
      )
    },
    on_close: fn(state) {
      case state.id > 0 {
        True -> process.send(session.inbox, writer.Cancel(state.id))
        False -> Nil
      }
    },
    handler: handle_socket,
  )
}

fn handle_socket(
  state: State,
  message: mist.WebsocketMessage(Message),
  conn: mist.WebsocketConnection,
) -> mist.Next(State, Message) {
  case message {
    mist.Custom(Event(writer.Assigned(id))) ->
      mist.continue(State(..state, id: id))
    mist.Custom(Event(writer.SocketInfo(body))) ->
      case
        json.parse(body, {
          use t <- decode.field("t", decode.string)
          decode.success(t)
        })
      {
        Ok("socketopened") -> {
          let _ = mist.send_text_frame(conn, body)
          mist.continue(State(..state, ready: True, input_credit: 1))
        }
        Ok("socketeof") -> {
          let _ = mist.send_text_frame(conn, body)
          mist.continue(state)
        }
        _ -> stop(conn, "invalid managed socket response")
      }
    mist.Custom(Event(writer.SocketData(seq, data))) -> {
      case
        state.output_pending
        || seq != state.output_seq
        || bit_array.byte_size(data) > 65_536
      {
        True -> stop(conn, "invalid managed socket output")
        False -> {
          case mist.send_binary_frame(conn, data) {
            Error(_) -> mist.stop()
            Ok(_) ->
              mist.continue(
                State(
                  ..state,
                  output_pending: True,
                  output_seq: state.output_seq + 1,
                ),
              )
          }
        }
      }
    }
    mist.Custom(Event(writer.Credit(_, 1))) -> {
      let _ = mist.send_text_frame(conn, "{\"t\":\"credit\",\"n\":1}")
      mist.continue(State(..state, input_credit: 1))
    }
    mist.Custom(Event(writer.SocketEnd(body))) -> {
      let _ = mist.send_text_frame(conn, body)
      mist.stop()
    }
    mist.Custom(Event(writer.Failed(_, message))) -> stop(conn, message)
    mist.Custom(Tick) -> {
      // Re-check long-lived bearer authority and hosting; upgrades do not
      // turn an expiring API key into a permanent credential.
      case
        state.ready,
        authorize(state.headers, state.db, state.slug, state.network)
      {
        True, Ok(_) -> {
          process.send_after(state.inbox, 30_000, Tick)
          mist.continue(state)
        }
        _, _ -> stop(conn, "socket opening timed out or authorization ended")
      }
    }
    mist.Binary(data) ->
      case
        state.ready
        && !state.input_eof
        && state.input_credit == 1
        && bit_array.byte_size(data) > 0
        && bit_array.byte_size(data) <= 65_536
      {
        True -> {
          process.send(
            state.session.inbox,
            writer.Chunk(state.id, state.input_seq, data),
          )
          mist.continue(
            State(..state, input_credit: 0, input_seq: state.input_seq + 1),
          )
        }
        False -> stop(conn, "input requires one credit and 1..65536 bytes")
      }
    mist.Text(body) ->
      case
        json.parse(body, {
          use t <- decode.field("t", decode.string)
          decode.success(t)
        })
      {
        Ok("ack") if state.output_pending -> {
          process.send(state.session.inbox, writer.SocketAck(state.id))
          mist.continue(State(..state, output_pending: False))
        }
        Ok("eof") if state.ready && !state.input_eof -> {
          process.send(state.session.inbox, writer.SocketEof(state.id))
          mist.continue(State(..state, input_eof: True))
        }
        _ -> stop(conn, "expected ack for output or eof for input")
      }
    mist.Closed | mist.Shutdown -> mist.stop()
    _ -> stop(conn, "unexpected socket event")
  }
}

fn stop(
  conn: mist.WebsocketConnection,
  message: String,
) -> mist.Next(State, Message) {
  let _ =
    mist.send_text_frame(
      conn,
      json.to_string(
        json.object([
          #("t", json.string("err")),
          #("message", json.string(message)),
        ]),
      ),
    )
  mist.stop()
}

fn response(status: Int, body: String) -> Response(mist.ResponseData) {
  response.new(status)
  |> response.set_header("content-type", "application/json")
  |> response.set_header("cache-control", "no-store")
  |> response.set_body(mist.Bytes(bytes_tree.from_string(body)))
}

fn deny(status: Int, message: String) -> Response(mist.ResponseData) {
  response(
    status,
    json.to_string(json.object([#("error", json.string(message))])),
  )
}
