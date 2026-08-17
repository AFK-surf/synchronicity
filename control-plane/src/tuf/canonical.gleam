//// OLPC canonical JSON — the byte string a TUF signature actually covers.
////
//// A TUF signature is over `signed` **canonicalized**, not over the bytes as
//// served, so a verifier that cannot reproduce the canonical form byte for
//// byte cannot check a signature at all. The rules are few and every one of
//// them is load-bearing: object members sorted by key, no whitespace
//// anywhere, strings escaping only `"` and `\` (control characters travel
//// raw, unlike in ordinary JSON), and integers only — a float has no
//// canonical rendering, so canonical JSON has none either and this refuses
//// rather than inventing one.
////
//// This is where TUF implementations historically break, which is why it is
//// checked against the real repository's bytes (test/fixtures/tuf) rather
//// than against a hand-written example, and against the same fixture the
//// Rust verifier's canonicalizer is checked against
//// (crates/synch-net/src/tuf.rs).
////
//// The value type exists because `gleam/json` decodes into shapes chosen
//// ahead of time and canonicalization needs the document as it is: every
//// member, in whatever order, re-emitted in one prescribed order. Sorting is
//// by code point, which on this target is the same as comparing the UTF-8
//// bytes, which is what the Rust side's `String: Ord` does.

import gleam/bit_array
import gleam/dict
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string

/// A JSON document, as canonicalization needs to see it.
///
/// No float arm on purpose: a document carrying one is refused at the parse,
/// where the reason is still visible, rather than at the point where a
/// signature mysteriously fails to verify.
pub type Json {
  Null
  Bool(Bool)
  Int(Int)
  Str(String)
  Arr(List(Json))
  Obj(List(#(String, Json)))
}

/// Parses a JSON document.
pub fn parse(bytes: BitArray) -> Result(Json, String) {
  use text <- result.try(
    bit_array.to_string(bytes) |> result.replace_error("not UTF-8"),
  )
  json.parse(text, decoder())
  |> result.replace_error(
    "not JSON this build can canonicalize (a fractional number would do it)",
  )
}

/// The canonical bytes of a value — what a signature over it covers.
pub fn encode(value: Json) -> BitArray {
  let text = render(value)
  <<text:utf8>>
}

fn decoder() -> decode.Decoder(Json) {
  decode.recursive(fn() {
    decode.one_of(decode.string |> decode.map(Str), [
      decode.int |> decode.map(Int),
      decode.bool |> decode.map(Bool),
      decode.list(decoder()) |> decode.map(Arr),
      decode.dict(decode.string, decoder())
        |> decode.map(fn(members) { Obj(dict.to_list(members)) }),
      // `optional` answers None for every representation of null this runtime
      // has, and the decoder inside it is one nothing satisfies — so this
      // branch matches null and only null.
      decode.optional(decode.failure(Null, "nothing"))
        |> decode.map(fn(_) { Null }),
    ])
  })
}

fn render(value: Json) -> String {
  case value {
    Null -> "null"
    Bool(True) -> "true"
    Bool(False) -> "false"
    Int(number) -> int.to_string(number)
    Str(text) -> quote(text)
    Arr(items) -> "[" <> string.join(list.map(items, render), ",") <> "]"
    Obj(members) ->
      "{"
      <> {
        members
        |> list.sort(fn(a, b) { string.compare(a.0, b.0) })
        |> list.map(fn(member) { quote(member.0) <> ":" <> render(member.1) })
        |> string.join(",")
      }
      <> "}"
  }
}

/// Two escapes and no others. The backslash first, or the escape this adds
/// for a quote would be escaped again by the pass after it.
fn quote(text: String) -> String {
  let escaped =
    text
    |> string.replace("\\", "\\\\")
    |> string.replace("\"", "\\\"")
  "\"" <> escaped <> "\""
}

// ------------------------------------------------------------- accessors

/// One member of an object, or `Error` for anything else.
pub fn field(value: Json, key: String) -> Result(Json, Nil) {
  case value {
    Obj(members) -> list.key_find(members, key)
    _ -> Error(Nil)
  }
}

/// A path of nested members, for the reads that are three deep.
pub fn at(value: Json, path: List(String)) -> Result(Json, Nil) {
  case path {
    [] -> Ok(value)
    [key, ..rest] -> {
      use inner <- result.try(field(value, key))
      at(inner, rest)
    }
  }
}

pub fn string(value: Json) -> Result(String, Nil) {
  case value {
    Str(text) -> Ok(text)
    _ -> Error(Nil)
  }
}

/// A whole number that is not negative — every count TUF carries.
pub fn integer(value: Json) -> Result(Int, Nil) {
  case value {
    Int(number) if number >= 0 -> Ok(number)
    _ -> Error(Nil)
  }
}

pub fn array(value: Json) -> Result(List(Json), Nil) {
  case value {
    Arr(items) -> Ok(items)
    _ -> Error(Nil)
  }
}

pub fn members(value: Json) -> Result(List(#(String, Json)), Nil) {
  case value {
    Obj(members) -> Ok(members)
    _ -> Error(Nil)
  }
}

/// The string at `path`, the read this module is asked for most.
pub fn string_at(value: Json, path: List(String)) -> Result(String, Nil) {
  at(value, path) |> result.try(string)
}

/// The whole number at `path`.
pub fn integer_at(value: Json, path: List(String)) -> Result(Int, Nil) {
  at(value, path) |> result.try(integer)
}
