//// Reading `trusted_root.json`: which transparency log to write to, and the
//// key whose signature on a checkpoint this service will believe
//// (docs/REKOR-ZONE-KEY.md §10).
////
//// The target the TUF chain exists to authenticate is a **directory of
//// logs**, not just a bag of keys: each entry names where a log is served,
//// the key its checkpoints are signed with, and the window it was in service
//// for. So the endpoint follows Sigstore for exactly the reason the key set
//// does — a build that pinned the key but hardcoded `log2025-1…` would still
//// have to ship a release the day the next shard opens, and would submit
//// into a closed log until it did.
////
//// This is the mirror of the tlog reader in crates/synch-net/src/tuf.rs, and
//// the two must agree about which log is current, because the client
//// verifies proofs from whichever log this side wrote to. Both select on the
//// same field (`publicKey.validFor`) with the same rule, and both derive the
//// log id from `publicKey.rawBytes` rather than reading the `logId.keyId`
//// beside it — that value is the C2SP note key id, a different 32 bytes that
//// matches no pin (see `rekor/proof.log_id`).
////
//// Nothing here verifies anything — the file ships with the image, and only
//// verified material is ever stored. What this reads out of that material
//// decides where the service submits, and a submission that went somewhere
//// unexpected fails at the next step anyway, when the returned proof is
//// checked against the key named beside that endpoint.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import rekor/proof
import simplifile

/// One transparency log the trusted root names.
/// The file inside `priv/tuf` holding Sigstore's trusted root.
pub const file = "sigstore_trusted_root.json"

@external(erlang, "cp_sys_ffi", "priv_dir")
fn priv_dir(sub: String) -> Result(String, Nil)

/// The trusted root this build ships, as bytes.
///
/// **This service reads Sigstore's directory from its own shipment, not from
/// Sigstore.** The material answers exactly two questions — which shard to
/// submit an entry to, and which key checks the proof that comes back — and
/// neither reaches a client: a client pins its own log keys from its own
/// walk of the TUF repository, verified against its own embedded root. So a
/// trusted root this service got wrong produces a stored proof whose `log_id`
/// no client pins, which is `UnknownLog` at every client and a zone that
/// fails closed. Loud, local, and not a trust bypass.
///
/// That is what makes fetching it unnecessary rather than merely optional.
/// A fetched-and-verified copy bought a better error location; a
/// fetched-and-*unverified* copy would buy that while making TLS load-bearing
/// for the first time in this design. Shipping it buys the same answer with
/// no network, no untrusted parsing, and no second implementation of TUF.
///
/// The cost is a redeploy when Sigstore opens a shard — the same cost
/// `--no-tuf` already carries on the client side, and one this service can
/// actually pay: it ships as a container image with a release pipeline, where
/// a client daemon on somebody's NAS does not. That asymmetry is the whole
/// reason the client still walks the repository and this side does not. When
/// a rotation outruns a deploy, `rekor-publish` fails naming the missing
/// shard, and `CP_REKOR_URL` + `CP_REKOR_KEY` name it directly in the
/// meantime.
pub fn shipped() -> Result(BitArray, String) {
  use dir <- result.try(
    priv_dir("tuf")
    |> result.replace_error(
      "priv/tuf is missing from this build — Sigstore's trusted root ships "
      <> "there, or name a log with CP_REKOR_URL and CP_REKOR_KEY",
    ),
  )
  simplifile.read_bits(dir <> "/" <> file)
  |> result.map_error(fn(e) {
    "reading " <> dir <> "/" <> file <> ": " <> simplifile.describe_error(e)
  })
}

pub type Tlog {
  Tlog(
    /// Where the log is served, without a trailing slash.
    base_url: String,
    /// Its verification key as a DER SubjectPublicKeyInfo.
    spki: BitArray,
    /// The raw point of that key, which is what a signature check takes.
    point: BitArray,
    /// `validFor.start`, seconds since the epoch. Absent means "always".
    valid_from: Int,
    /// `validFor.end`, once the shard has been closed.
    valid_until: Option(Int),
  )
}

/// The logs a trusted root names, in the order it lists them.
pub fn tlogs(trusted_root: BitArray) -> Result(List(Tlog), String) {
  use text <- result.try(
    bit_array.to_string(trusted_root)
    |> result.replace_error("trusted_root.json is not UTF-8"),
  )
  let window_decoder = {
    use start <- decode.optional_field("start", "", decode.string)
    use end <- decode.optional_field("end", "", decode.string)
    decode.success(#(start, end))
  }
  let key_decoder = {
    use raw <- decode.field("rawBytes", decode.string)
    use window <- decode.optional_field("validFor", #("", ""), window_decoder)
    decode.success(#(raw, window))
  }
  let entry_decoder = {
    use base_url <- decode.field("baseUrl", decode.string)
    use key <- decode.field("publicKey", key_decoder)
    decode.success(#(base_url, key))
  }
  let decoder = {
    use entries <- decode.field("tlogs", decode.list(entry_decoder))
    decode.success(entries)
  }
  use entries <- result.try(
    json.parse(text, decoder)
    |> result.replace_error("trusted_root.json names no tlogs it can read"),
  )
  use logs <- result.try(list.try_map(entries, decode_tlog))
  case logs {
    // A trusted root with no logs in it would leave this service with
    // nowhere to submit and no key to check the answer with. That is not a
    // configuration to adopt silently.
    [] -> Error("trusted_root.json names no transparency logs")
    _ -> Ok(logs)
  }
}

fn decode_tlog(
  entry: #(String, #(String, #(String, String))),
) -> Result(Tlog, String) {
  let #(base_url, #(raw, #(start, end))) = entry
  use #(spki, point) <- result.try(
    proof.parse_log_key(raw)
    |> result.map_error(fn(_) {
      "the key for " <> base_url <> " is not an SPKI this build recognises"
    }),
  )
  use valid_from <- result.try(instant(start, 0, base_url, "start"))
  use valid_until <- result.try(case end {
    "" -> Ok(None)
    _ -> instant(end, 0, base_url, "end") |> result.map(Some)
  })
  Ok(Tlog(
    base_url: strip_slash(base_url),
    spki: spki,
    point: point,
    valid_from: valid_from,
    valid_until: valid_until,
  ))
}

fn instant(
  text: String,
  absent: Int,
  base_url: String,
  field: String,
) -> Result(Int, String) {
  case text {
    "" -> Ok(absent)
    _ ->
      parse_rfc3339(text)
      |> result.replace_error(
        "validFor." <> field <> " for " <> base_url <> " is not RFC 3339",
      )
  }
}

/// Whether a log was in service at `now`.
pub fn valid_at(log: Tlog, now: Int) -> Bool {
  log.valid_from <= now
  && case log.valid_until {
    None -> True
    Some(end) -> now < end
  }
}

/// The log in service at `now` — the latest-started of those whose window
/// contains it, and the one a submission goes to.
///
/// Sigstore keeps retired shards listed so old proofs stay checkable, so
/// "the current log" is a question about windows rather than about list
/// order. Every listed shard being closed or not yet open is an error and
/// not a guess: submitting into a shard that is not accepting writes fails
/// anyway, and failing here says why.
pub fn current(logs: List(Tlog), now: Int) -> Result(Tlog, String) {
  logs
  |> list.filter(valid_at(_, now))
  // Latest-started wins, and **ties go to the last listed** — which is what
  // `Iterator::max_by_key` returns, so `tuf::current_tlog` and this pick the
  // same shard. §10.6 says both implementations select with one rule because
  // the control plane writes to whichever shard it picks and a monitor reads
  // whichever *it* picks; a tie resolved differently on the two sides is the
  // control plane submitting where nobody is watching, which reads exactly
  // like a log with nothing new in it.
  |> list.fold(None, fn(best, log) {
    case best {
      Some(Tlog(valid_from: from, ..)) if from > log.valid_from -> best
      _ -> Some(log)
    }
  })
  |> option.to_result(
    "trusted_root.json names no transparency log in service at "
    <> int.to_string(now)
    <> " — set CP_REKOR_URL and CP_REKOR_KEY to name one",
  )
}

/// The log served at `base_url`, for an operator who redirected the write
/// endpoint to a shard the trusted root already names.
pub fn for_url(logs: List(Tlog), base_url: String) -> Result(Tlog, String) {
  let wanted = strip_slash(base_url)
  list.find(logs, fn(log) { log.base_url == wanted })
  |> result.replace_error(
    "trusted_root.json names no log at "
    <> wanted
    <> " — set CP_REKOR_KEY to the key it is signed with",
  )
}

/// One trailing slash on a base URL should not become two in a path, and a
/// URL that differs from another only by one is the same log.
pub fn strip_slash(url: String) -> String {
  case string.ends_with(url, "/") {
    True -> strip_slash(string.drop_end(url, 1))
    False -> url
  }
}

/// Parses the RFC 3339 timestamps a `validFor` window carries, as seconds
/// since the epoch.
///
/// Narrow, and wider than the shipped root needs: Sigstore has written plain
/// `Z` times, fractional seconds and numeric offsets at different points, and
/// a reader that refused an old shape would refuse a window it should have
/// read.
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
      // Bounded like every other field, and like the client's own parser
      // (`tuf.rs`'s `parse_rfc3339`). 60 admits the leap second RFC 3339
      // permits; anything past it is a timestamp neither side should read the
      // same way, and an expiry the two implementations disagree about is a
      // signature one accepts and the other does not.
      && second <= 60
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
