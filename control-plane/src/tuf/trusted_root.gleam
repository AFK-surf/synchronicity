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
//// Nothing here verifies anything. This service is a TUF relay, not the
//// verifier (`tuf/fetch`); what it reads out of the stored material decides
//// where it submits, and a submission that went somewhere unexpected fails
//// at the next step, when the returned proof is checked against the key
//// named beside that endpoint.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import rekor/proof
import tuf/meta

/// One transparency log the trusted root names.
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
      meta.parse_rfc3339(text)
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
  |> list.fold(None, fn(best, log) {
    case best {
      Some(Tlog(valid_from: from, ..)) if from >= log.valid_from -> best
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
