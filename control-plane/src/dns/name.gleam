//// Domain names as label lists, in the lowercase canonical form DNSSEC
//// wants everywhere (RFC 4034 §6.2): names are lowercased once, on entry,
//// and every comparison and wire encoding works on that form.

import gleam/bit_array
import gleam/list
import gleam/order.{type Order}
import gleam/string

/// Labels, root omitted: "a.b.c." is ["a", "b", "c"]. The root name is [].
pub type Name =
  List(String)

/// Parses a presentation-form name. Accepts letters, digits, hyphen and
/// underscore (service labels like `_synchronicity` are names too),
/// lowercases, and enforces the 63-byte label / 255-byte name limits.
pub fn parse(text: String) -> Result(Name, Nil) {
  let trimmed = case string.ends_with(text, ".") {
    True -> string.drop_end(text, 1)
    False -> text
  }
  case trimmed {
    "" -> Ok([])
    _ -> {
      let labels = string.split(string.lowercase(trimmed), ".")
      let valid = list.all(labels, valid_label)
      let total =
        list.fold(labels, 1, fn(acc, l) { acc + string.byte_size(l) + 1 })
      case valid && total <= 255 {
        True -> Ok(labels)
        False -> Error(Nil)
      }
    }
  }
}

fn valid_label(label: String) -> Bool {
  let bytes = <<label:utf8>>
  let size = bit_array.byte_size(bytes)
  size >= 1 && size <= 63 && valid_bytes(bytes)
}

fn valid_bytes(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<b:int-size(8), rest:bits>> ->
      {
        { b >= 97 && b <= 122 } || { b >= 48 && b <= 57 } || b == 45 || b == 95
      }
      && valid_bytes(rest)
    _ -> False
  }
}

/// Presentation form, always absolute: ["a", "b"] is "a.b.".
pub fn to_string(name: Name) -> String {
  case name {
    [] -> "."
    _ -> string.join(name, ".") <> "."
  }
}

/// Uncompressed wire form. We never emit compression pointers.
pub fn encode(name: Name) -> BitArray {
  let labels =
    list.map(name, fn(label) {
      let bits = <<label:utf8>>
      <<bit_array.byte_size(bits):int-size(8), bits:bits>>
    })
  bit_array.concat(list.append(labels, [<<0>>]))
}

/// Canonical name order (RFC 4034 §6.1): compare from the rightmost label,
/// each label as a byte string.
pub fn compare(a: Name, b: Name) -> Order {
  compare_reversed(list.reverse(a), list.reverse(b))
}

fn compare_reversed(a: List(String), b: List(String)) -> Order {
  case a, b {
    [], [] -> order.Eq
    [], _ -> order.Lt
    _, [] -> order.Gt
    [x, ..xs], [y, ..ys] ->
      case bit_array.compare(<<x:utf8>>, <<y:utf8>>) {
        order.Eq -> compare_reversed(xs, ys)
        other -> other
      }
  }
}

/// Is `name` equal to or under `apex`?
pub fn in_zone(name: Name, apex: Name) -> Bool {
  let apex_len = list.length(apex)
  let name_len = list.length(name)
  name_len >= apex_len && list.drop(name, name_len - apex_len) == apex
}
