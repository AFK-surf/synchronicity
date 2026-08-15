//// Sortable random identifiers: seconds-since-epoch prefix (hex, fixed
//// width) + 80 random bits. Time-ordered like UUIDv7, without the
//// ceremony.

import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/string

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

pub fn new() -> String {
  let time =
    now_unix()
    |> int.to_base16
    |> string.lowercase
    |> string.pad_start(10, "0")
  let random =
    crypto.strong_random_bytes(10)
    |> bit_array.base16_encode
    |> string.lowercase
  time <> random
}

/// A URL-safe random secret (tokens, states, verifiers).
pub fn secret() -> String {
  bit_array.base64_url_encode(crypto.strong_random_bytes(32), False)
}
