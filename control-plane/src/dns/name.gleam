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

/// Hostname-style label grammar for org slugs and network names —
/// [a-z0-9-]{1,63} with no leading or trailing hyphen. These become
/// labels in the public zone; the product layer validates with this and
/// zone building re-checks device labels via `valid_device_label`.
pub fn valid_dns_label(label: String) -> Bool {
  valid_device_label(label)
  && !string.starts_with(label, "-")
  && !string.ends_with(label, "-")
}

/// Device-label grammar (the client's normalize_label): [a-z0-9-]{1,63},
/// hyphen position free — unlike hostname labels.
pub fn valid_device_label(label: String) -> Bool {
  let bytes = <<label:utf8>>
  let size = bit_array.byte_size(bytes)
  size >= 1 && size <= 63 && plain_bytes_ok(bytes)
}

fn plain_bytes_ok(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<b:int-size(8), rest:bits>> ->
      { { b >= 97 && b <= 122 } || { b >= 48 && b <= 57 } || b == 45 }
      && plain_bytes_ok(rest)
    _ -> False
  }
}

/// Whether a device label is in the reserved `cloud-` namespace
/// (docs/CLOUD-DATAPLANE.md §3.4): the hosting slots the cloud data plane's
/// devices occupy, which only the data-plane principal may create.
///
/// It lives beside `valid_device_label` rather than in the API layer because
/// it is the same kind of fact — a grammar over a label — and because both
/// device-create paths and the data-plane API need it, and the one module all
/// three can import without a cycle is this one.
///
/// **The whole prefix, not just `cloud-<digits>`.** An earlier version
/// reserved only the digit form, on the reasoning that a namespace should
/// take no more names than it can explain. That is the wrong trade for a
/// namespace whose purpose is to keep one identity unambiguous: it left
/// `cloud-1a`, `cloud-01` and `cloud-1-2` available as customer labels that
/// read, to a human scanning a device list, exactly like the hosting slot
/// beside them. Reserving the prefix costs a handful of names nobody has a
/// strong claim to and buys a device list in which "starts with `cloud-`"
/// means one thing.
///
/// This is a rule about **creation**. It deliberately does not decide which
/// existing device the data plane owns — that is `devices.created_by`, and
/// every path that acts on a device already present uses it, so widening this
/// grammar can neither delete nor lock a customer out of a device they made
/// before the namespace existed.
pub fn reserved_device_label(label: String) -> Bool {
  string.starts_with(label, "cloud-")
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

/// A byte string whose plain byte order equals canonical DNS order
/// (RFC 4034 §6.1): labels reversed, each terminated by 0x00 — which
/// sorts below every permitted label byte, so ancestors sort before
/// descendants and label boundaries compare correctly. This is what lets
/// SQLite BLOB comparison answer NSEC predecessor queries.
pub fn sort_key(name: Name) -> BitArray {
  name
  |> list.reverse
  |> list.map(fn(label) { <<label:utf8, 0>> })
  |> bit_array.concat
}

/// The exclusive upper bound of `name`'s descendant range: every name at
/// or under `name` has a sort_key in [sort_key(name), sort_key_upper(name)).
/// A key with this key as prefix is either the name itself (nothing after
/// the prefix) or a descendant (next byte is a label byte, ≤ 0x7a) — so
/// appending 0xff bounds exactly that set and nothing else.
pub fn sort_key_upper(name: Name) -> BitArray {
  bit_array.concat([sort_key(name), <<0xff>>])
}
