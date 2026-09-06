//// A streamed response of known length, below mist.
////
//// mist's one streaming body is `mist.chunked`, and it is chunked transfer
//// coding: the head leaves with `Transfer-Encoding: chunked`, which rules
//// out a `Content-Length` (RFC 9112 §6.2 — a message carries one or the
//// other, never both). Every download here knows its size before its first
//// byte, since the daemon's resolve names it, and a client is owed that
//// number: a browser shows progress and a time remaining, a download manager
//// preallocates and resumes, and a body cut short fails loudly at every
//// client instead of only at one that noticed there was no last chunk.
////
//// So this writes the head itself — `Content-Length` and all — relays the
//// body as raw bytes, and answers mist with a response whose body is the
//// `mist.Chunked` marker. mist reads that marker as "already on the wire": it
//// sends nothing more and stops the connection (`mist/internal/http/handler.
//// call`). The relay runs in the connection's own process, which owns the
//// socket, so nothing is handed off and the connection ends when the process
//// does; `Connection: close` in the head says so up front.

import exception
import gleam/bytes_tree.{type BytesTree}
import gleam/http/request.{type Request as HttpRequest}
import gleam/http/response.{type Response as HttpResponse}
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import glisten/transport
import mist
import wisp

/// Puts one piece of the body on the wire. `Error` means the client stopped
/// reading, and whoever is producing the bytes should stop too.
pub type Sink =
  fn(BitArray) -> Result(Nil, Nil)

/// How the body ended.
pub type Outcome {
  /// Exactly the announced length went out.
  Complete
  /// Less did, and why.
  Aborted(reason: String)
}

/// Writes the head, runs `body` to put exactly `length` bytes through the
/// sink it is handed, and ends the connection.
///
/// `body` is what decides the outcome, and it is trusted to count: a
/// `Complete` short of `length` leaves the client waiting on bytes that never
/// come, until its own timeout says so. An `Aborted` body closes the socket at
/// once, so the client sees a body shorter than its `Content-Length` — the
/// one signal every HTTP client treats as a broken transfer, which is what
/// keeps a truncated file from ever being saved as a complete one.
pub fn respond(
  request req: HttpRequest(mist.Connection),
  status status: Int,
  headers headers: List(#(String, String)),
  length length: Int,
  body body: fn(Sink) -> Outcome,
) -> HttpResponse(mist.ResponseData) {
  let conn = req.body
  let send = fn(bytes: BytesTree) {
    transport.send(conn.transport, conn.socket, bytes)
    |> result.replace_error(Nil)
  }
  // A head that cannot be sent means the client is already gone. The body
  // runs anyway: its first write fails the same way, and that is the path on
  // which the producer is cancelled and the caller releases what it holds.
  let _ = send(head(status, length, headers))
  let sink = fn(data: BitArray) { send(bytes_tree.from_bit_array(data)) }
  case exception.rescue(fn() { body(sink) }) {
    Ok(Complete) -> Nil
    // Closed before anything else on both paths, the logging included: were a
    // step after the close to raise, mist's own rescue would put a 500 on
    // this socket — bytes a client counting to `length` would take for the
    // tail of the file. Closed first, that 500 has nowhere to go.
    Ok(Aborted(reason)) -> {
      let _ = transport.close(conn.transport, conn.socket)
      wisp.log_warning("download aborted: " <> reason)
      Nil
    }
    Error(crash) -> {
      let _ = transport.close(conn.transport, conn.socket)
      wisp.log_error("download crashed: " <> string.inspect(crash))
      Nil
    }
  }
  handled()
}

/// The response mist is handed once the body is on the wire or given up on.
/// Its body is the marker mist reads as "already sent": nothing more goes out
/// and the connection is stopped.
fn handled() -> HttpResponse(mist.ResponseData) {
  response.new(200) |> response.set_body(mist.Chunked)
}

/// The status line and headers, as they go on the wire.
///
/// `Content-Length` and `Connection` are this module's to set, and there is
/// no `Transfer-Encoding`: a caller's copy of any of the three is dropped
/// rather than doubled or contradicted. Header names and values lose any CR
/// or LF, so no value — a filename, a device label — can end the head early
/// or smuggle a header of its own.
pub fn head(
  status: Int,
  length: Int,
  headers: List(#(String, String)),
) -> BytesTree {
  let theirs =
    list.filter(headers, fn(header) {
      case string.lowercase(header.0) {
        "content-length" | "connection" | "transfer-encoding" -> False
        _ -> True
      }
    })
  let all = [
    #("content-length", int.to_string(length)),
    #("connection", "close"),
    ..theirs
  ]
  let status_line =
    "HTTP/1.1 " <> int.to_string(status) <> " " <> reason(status) <> "\r\n"
  list.fold(all, bytes_tree.from_string(status_line), fn(acc, header) {
    acc
    |> bytes_tree.append_string(clean(header.0))
    |> bytes_tree.append_string(": ")
    |> bytes_tree.append_string(clean(header.1))
    |> bytes_tree.append_string("\r\n")
  })
  |> bytes_tree.append_string("\r\n")
}

/// The reason phrase, for the statuses a body of known length is sent with.
/// RFC 9112 §4 lets it be empty, so an unlisted status carries none.
fn reason(status: Int) -> String {
  case status {
    200 -> "OK"
    206 -> "Partial Content"
    _ -> ""
  }
}

/// By codepoint, not by `string.replace`: a string treats `\r\n` as one
/// grapheme, which a lone `\r` pattern does not match, and the pair is
/// exactly what ends a head.
fn clean(text: String) -> String {
  text
  |> string.to_utf_codepoints
  |> list.filter(fn(point) {
    let code = string.utf_codepoint_to_int(point)
    code != 0x0D && code != 0x0A
  })
  |> string.from_utf_codepoints
}
