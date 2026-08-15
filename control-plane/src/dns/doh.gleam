//// RFC 8484 DoH. POST with application/dns-message is the path the
//// synchronicity client actually uses (see synch-net's DohHandle);
//// GET ?dns= exists for `dig +https` style debugging.

import dns/query
import dns/wire
import gleam/bit_array
import gleam/bytes_tree
import gleam/http.{Get, Post}
import gleam/list
import gleam/result
import wisp.{type Request, type Response}
import zone/snapshot

pub fn handle(req: Request) -> Response {
  case req.method {
    Post -> handle_post(req)
    Get -> handle_get(req)
    _ -> wisp.method_not_allowed([Post, Get])
  }
}

fn handle_post(req: Request) -> Response {
  case list.key_find(req.headers, "content-type") {
    Ok("application/dns-message") ->
      case wisp.read_body_bits(req) {
        Ok(body) -> respond(body)
        Error(Nil) -> wisp.bad_request("unreadable body")
      }
    _ -> wisp.response(415)
  }
}

fn handle_get(req: Request) -> Response {
  let queries = wisp.get_query(req)
  case list.key_find(queries, "dns") {
    Ok(encoded) ->
      case base64url_decode(encoded) {
        Ok(message) -> respond(message)
        Error(Nil) -> wisp.bad_request("bad dns= encoding")
      }
    Error(Nil) -> wisp.bad_request("missing dns= parameter")
  }
}

fn base64url_decode(text: String) -> Result(BitArray, Nil) {
  // RFC 8484 uses unpadded base64url; accept padded too.
  bit_array.base64_url_decode(text)
  |> result.lazy_or(fn() { bit_array.base64_url_decode(text <> "=") })
  |> result.lazy_or(fn() { bit_array.base64_url_decode(text <> "==") })
}

fn respond(message: BitArray) -> Response {
  case wire.decode_query(message) {
    Ok(q) ->
      case snapshot.current() {
        Ok(snap) -> dns_body(query.answer(snap, q))
        Error(Nil) -> dns_body(query.error_stub(q.id, 2))
      }
    Error(wire.Unsupported(id)) ->
      dns_body(query.error_stub(id, query.rcode_notimp))
    Error(wire.Malformed) -> wisp.bad_request("not a DNS message")
  }
}

fn dns_body(response: BitArray) -> Response {
  wisp.response(200)
  |> wisp.set_header("content-type", "application/dns-message")
  |> wisp.set_body(wisp.Bytes(bytes_tree.from_bit_array(response)))
}
