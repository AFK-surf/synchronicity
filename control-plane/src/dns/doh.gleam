//// RFC 8484 DoH. POST with application/dns-message is the path the
//// synchronicity client actually uses (see synch-net's DohHandle);
//// GET ?dns= exists for `dig +https` style debugging.

import dns/serve.{type Serving}
import gleam/bit_array
import gleam/bytes_tree
import gleam/http.{Get, Post}
import gleam/list
import gleam/result
import wisp.{type Request, type Response}

pub fn handle(req: Request, serving: Serving) -> Response {
  case req.method {
    Post -> handle_post(req, serving)
    Get -> handle_get(req, serving)
    _ -> wisp.method_not_allowed([Post, Get])
  }
}

fn handle_post(req: Request, serving: Serving) -> Response {
  case list.key_find(req.headers, "content-type") {
    Ok("application/dns-message") ->
      case wisp.read_body_bits(req) {
        Ok(body) -> respond(body, serving)
        Error(Nil) -> wisp.bad_request("unreadable body")
      }
    _ -> wisp.response(415)
  }
}

fn handle_get(req: Request, serving: Serving) -> Response {
  let queries = wisp.get_query(req)
  case list.key_find(queries, "dns") {
    Ok(encoded) ->
      case base64url_decode(encoded) {
        Ok(message) -> respond(message, serving)
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

fn respond(message: BitArray, serving: Serving) -> Response {
  case serve.handle_packet(serving, message, False) {
    Ok(response) -> dns_body(response)
    Error(Nil) -> wisp.bad_request("not a DNS message")
  }
}

fn dns_body(response: BitArray) -> Response {
  wisp.response(200)
  |> wisp.set_header("content-type", "application/dns-message")
  |> wisp.set_body(wisp.Bytes(bytes_tree.from_bit_array(response)))
}
