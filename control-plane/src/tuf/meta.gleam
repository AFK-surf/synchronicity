//// The few fields of a TUF metadata file the **walk** reads
//// (docs/REKOR-ZONE-KEY.md §10.3).
////
//// Deliberately shallow, and deliberately not the gate: a role's `_type`,
//// `version` and `expires`, the version a role lists for the file below it,
//// and the digest `targets.json` gives for `trusted_root.json` — exactly
//// enough to know which file to ask the repository for next. Nothing read
//// here is trusted on the strength of having been read here.
////
//// The gate is `tuf/verify`, which re-reads all of it from the same bytes
//// with the signatures checked. Keeping the two apart is what stops a
//// convenience read during the walk from quietly becoming a security
//// decision: this module can be wrong about a file and the worst it can do
//// is fetch the wrong one, which then fails to verify.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/result
import gleam/string

/// One role's identity: what it says it is, which version, and until when.
pub type Role {
  Role(kind: String, version: Int, expires: Int)
}

/// Reads a metadata file and checks it declares the role it was fetched as.
///
/// A snapshot served where the targets belong is the sort of confusion a
/// relay should refuse to pass on, even though a client would catch it.
pub fn read_role(bytes: BitArray, expected: String) -> Result(Role, String) {
  use text <- result.try(utf8(bytes, expected))
  let decoder = {
    use kind <- decode.subfield(["signed", "_type"], decode.string)
    use version <- decode.subfield(["signed", "version"], decode.int)
    use expires <- decode.subfield(["signed", "expires"], decode.string)
    decode.success(#(kind, version, expires))
  }
  use #(kind, version, expires) <- result.try(
    json.parse(text, decoder)
    |> result.replace_error(expected <> ".json: not TUF metadata"),
  )
  use Nil <- result.try(case kind == expected {
    True -> Ok(Nil)
    False ->
      Error("a file served as " <> expected <> ".json declares itself " <> kind)
  })
  use Nil <- result.try(case version > 0 {
    True -> Ok(Nil)
    False -> Error(expected <> ".json has version " <> int.to_string(version))
  })
  use at <- result.try(
    parse_rfc3339(expires)
    |> result.replace_error(
      expected <> ".json: expires " <> expires <> " is not RFC 3339",
    ),
  )
  Ok(Role(kind, version, at))
}

/// The version a role lists for the file below it — `snapshot.json` in a
/// timestamp, `targets.json` in a snapshot.
///
/// Only the version: Sigstore's timestamp lists the snapshot without
/// hashes, and its snapshot does the same for the targets, so the version
/// equality is what binds them here and the client re-checks whatever
/// hashes are present.
pub fn read_meta_version(bytes: BitArray, file: String) -> Result(Int, String) {
  use text <- result.try(utf8(bytes, file))
  let decoder = {
    use version <- decode.subfield(
      ["signed", "meta", file, "version"],
      decode.int,
    )
    decode.success(version)
  }
  json.parse(text, decoder)
  |> result.replace_error("the metadata does not list " <> file)
}

/// The digest and length `targets.json` gives for one target.
pub fn read_target(
  bytes: BitArray,
  name: String,
) -> Result(#(String, Int), String) {
  use text <- result.try(utf8(bytes, name))
  let decoder = {
    use digest <- decode.subfield(
      ["signed", "targets", name, "hashes", "sha256"],
      decode.string,
    )
    use length <- decode.subfield(
      ["signed", "targets", name, "length"],
      decode.int,
    )
    decode.success(#(digest, length))
  }
  json.parse(text, decoder)
  |> result.replace_error("targets.json names no " <> name <> " with a sha256")
}

fn utf8(bytes: BitArray, what: String) -> Result(String, String) {
  bit_array.to_string(bytes)
  |> result.replace_error(what <> ": not UTF-8")
}

/// Parses the RFC 3339 timestamps TUF `expires` fields carry, as seconds
/// since the epoch.
///
/// Narrow, and wider than the current repository needs: Sigstore's roots
/// have written plain `Z` times, fractional seconds and numeric offsets at
/// different points in their history, and a relay that refused an old shape
/// would stop refetching for a reason nobody could see.
pub fn parse_rfc3339(text: String) -> Result(Int, Nil) {
  use year <- result.try(number(text, 0, 4))
  use month <- result.try(number(text, 5, 7))
  use day <- result.try(number(text, 8, 10))
  use hour <- result.try(number(text, 11, 13))
  use minute <- result.try(number(text, 14, 16))
  use second <- result.try(number(text, 17, 19))
  use Nil <- result.try(
    case
      string.slice(text, 4, 1) == "-"
      && string.slice(text, 7, 1) == "-"
      && string.slice(text, 10, 1) == "T"
      && string.slice(text, 13, 1) == ":"
      && string.slice(text, 16, 1) == ":"
      && month >= 1
      && month <= 12
      && day >= 1
      && day <= 31
      && hour <= 23
      && minute <= 59
    {
      True -> Ok(Nil)
      False -> Error(Nil)
    },
  )
  // Whatever follows the seconds is a fraction, a zone, or both.
  let rest = string.drop_start(text, 19)
  let rest = case string.starts_with(rest, ".") {
    True -> drop_digits(string.drop_start(rest, 1))
    False -> rest
  }
  use offset <- result.try(case rest, string.length(rest) {
    "Z", _ | "z", _ | "", _ -> Ok(0)
    _, 6 -> {
      use hours <- result.try(number(rest, 1, 3))
      use minutes <- result.try(number(rest, 4, 6))
      case string.slice(rest, 0, 1), string.slice(rest, 3, 1) {
        "+", ":" -> Ok(hours * 3600 + minutes * 60)
        "-", ":" -> Ok(0 - { hours * 3600 + minutes * 60 })
        _, _ -> Error(Nil)
      }
    }
    _, _ -> Error(Nil)
  })
  Ok(
    days_from_civil(year, month, day)
    * 86_400
    + hour
    * 3600
    + minute
    * 60
    + second
    - offset,
  )
}

fn number(text: String, from: Int, to: Int) -> Result(Int, Nil) {
  let slice = string.slice(text, from, to - from)
  case string.length(slice) == to - from {
    True -> int.parse(slice)
    False -> Error(Nil)
  }
}

fn drop_digits(text: String) -> String {
  case int.parse(string.slice(text, 0, 1)) {
    Ok(_) -> drop_digits(string.drop_start(text, 1))
    Error(Nil) -> text
  }
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: Int, month: Int, day: Int) -> Int {
  let year = case month <= 2 {
    True -> year - 1
    False -> year
  }
  let era = floor_div(year, 400)
  let year_of_era = year - era * 400
  let shift = case month > 2 {
    True -> -3
    False -> 9
  }
  let day_of_year = { 153 * { month + shift } + 2 } / 5 + day - 1
  let day_of_era =
    year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year
  era * 146_097 + day_of_era - 719_468
}

/// Integer division that rounds toward negative infinity, which is what the
/// era calculation above assumes and what Gleam's `/` does not do.
fn floor_div(a: Int, b: Int) -> Int {
  case a < 0 && a % b != 0 {
    True -> a / b - 1
    False -> a / b
  }
}
