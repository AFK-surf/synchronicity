//// The streamed response of known length that a file download rides on:
//// what its head says, and what a client on a real mist connection receives.

import api/sized_body
import gleam/bit_array
import gleam/bytes_tree
import gleam/erlang/process
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/string
import mist

/// The wire a GET brought back, and whether the server closed behind it.
@external(erlang, "test_ffi", "http_get")
fn http_get(port: Int, path: String) -> #(BitArray, Bool)

// -- the head ----------------------------------------------------------------

/// The head announces the body's length and no transfer coding, and the two
/// are never both present: a caller's own `Content-Length` or
/// `Transfer-Encoding` is dropped rather than doubled or contradicted.
pub fn the_head_carries_the_length_and_no_transfer_coding_test() {
  let head =
    text_of(
      sized_body.head(206, 5, [
        #("x-synch-root", "abc"),
        #("Transfer-Encoding", "chunked"),
        #("Content-Length", "99"),
        #("connection", "keep-alive"),
      ]),
    )
  assert string.starts_with(head, "HTTP/1.1 206 Partial Content\r\n")
  assert string.contains(head, "\r\ncontent-length: 5\r\n")
  assert string.contains(head, "\r\nconnection: close\r\n")
  assert string.contains(head, "\r\nx-synch-root: abc\r\n")
  assert !string.contains(string.lowercase(head), "transfer-encoding")
  assert !string.contains(head, "content-length: 99")
  assert !string.contains(head, "keep-alive")
  assert string.ends_with(head, "\r\n\r\n")
}

/// A header value cannot end the head early or add a header of its own: a
/// filename or a device label is a value, whatever it contains.
pub fn a_header_value_cannot_end_the_head_early_test() {
  let head =
    text_of(
      sized_body.head(200, 0, [#("x-synch-device", "nas\r\nx-evil: yes\n")]),
    )
  assert string.contains(head, "\r\nx-synch-device: nasx-evil: yes\r\n")
  assert !string.contains(head, "\r\nx-evil")
}

// -- the wire ----------------------------------------------------------------

/// A client on a real connection gets a `Content-Length` equal to the body
/// it then receives, and the connection closes behind it.
pub fn a_download_carries_its_content_length_test() {
  let port =
    serve(fn(req) {
      sized_body.respond(
        request: req,
        status: 200,
        headers: [#("content-type", "application/octet-stream")],
        length: 11,
        body: fn(sink) {
          let assert Ok(Nil) = sink(<<"hello ":utf8>>)
          let assert Ok(Nil) = sink(<<"world":utf8>>)
          sized_body.Complete
        },
      )
    })
  let #(head, body, closed) = fetch(port)
  assert string.starts_with(head, "HTTP/1.1 200 OK\r\n")
  assert string.contains(head, "\r\ncontent-length: 11\r\n")
  assert string.contains(head, "\r\ncontent-type: application/octet-stream\r\n")
  assert !string.contains(string.lowercase(head), "transfer-encoding")
  assert body == "hello world"
  assert closed
}

/// A body given up on is cut short of the length its head promised — the one
/// signal every client reads as a broken transfer — never padded or closed as
/// if complete.
pub fn an_aborted_download_falls_short_of_its_length_test() {
  let port =
    serve(fn(req) {
      sized_body.respond(
        request: req,
        status: 200,
        headers: [],
        length: 11,
        body: fn(sink) {
          let assert Ok(Nil) = sink(<<"hello ":utf8>>)
          sized_body.Aborted("the daemon stopped producing")
        },
      )
    })
  let #(head, body, closed) = fetch(port)
  assert string.contains(head, "\r\ncontent-length: 11\r\n")
  assert body == "hello "
  // Closed, not left open: the client learns at once, not at its own timeout.
  assert closed
}

/// A body that crashes mid-stream is cut the same way, and nothing else — no
/// error page of mist's own — lands on the socket where a client counting to
/// the length would take it for the file's tail.
pub fn a_crashed_download_falls_short_of_its_length_test() {
  let port =
    serve(fn(req) {
      sized_body.respond(
        request: req,
        status: 200,
        headers: [],
        length: 11,
        body: fn(sink) {
          let assert Ok(Nil) = sink(<<"hello ":utf8>>)
          panic as "the relay fell over"
        },
      )
    })
  let #(head, body, closed) = fetch(port)
  assert string.contains(head, "\r\ncontent-length: 11\r\n")
  assert body == "hello "
  assert closed
}

// -- plumbing ----------------------------------------------------------------

/// A mist server on an ephemeral loopback port, answering with `handler`.
fn serve(
  handler: fn(Request(mist.Connection)) -> Response(mist.ResponseData),
) -> Int {
  let ready = process.new_subject()
  let assert Ok(_) =
    mist.new(handler)
    |> mist.bind("127.0.0.1")
    |> mist.port(0)
    |> mist.after_start(fn(port, _scheme, _ip) { process.send(ready, port) })
    |> mist.start
  let assert Ok(port) = process.receive(ready, 5000)
  port
}

fn text_of(bytes: bytes_tree.BytesTree) -> String {
  let assert Ok(text) = bytes |> bytes_tree.to_bit_array |> bit_array.to_string
  text
}

/// One GET of `/file`, cut at the blank line: the head with its terminator,
/// the body as text, and whether the server closed the connection.
fn fetch(port: Int) -> #(String, String, Bool) {
  let #(wire, closed) = http_get(port, "/file")
  let assert Ok(text) = bit_array.to_string(wire)
  let assert Ok(#(head, body)) = string.split_once(text, "\r\n\r\n")
  #(head <> "\r\n\r\n", body, closed)
}
