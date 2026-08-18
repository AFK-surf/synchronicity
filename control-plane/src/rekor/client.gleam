//// What a transparency log has to do for us, as a value.
////
//// One operation: submit a `hashedrekord` entry and get back the proof the
//// log integrated it into. Everything else this service does with a proof —
//// verifying it, storing it, serving it — is offline and testable without a
//// log at all, which is why the log arrives here as an injected function
//// rather than as a hardwired endpoint. Tests drive it with a fake; the real
//// HTTP leg below is what `rekor-publish` runs against the public log.
////
//// Rekor v2 accepts only `hashedrekord` (docs/REKOR-ZONE-KEY.md §2): a
//// DSSE-signed Statement is logged as a `hashedrekord` v0.0.2 over the DSSE
//// PAE, with a certificate as its verifier. The write API is
//// `POST /api/v2/log/entries` with a protojson `CreateEntryRequest`, and the
//// response is a `TransparencyLogEntry` carrying the `canonicalizedBody`
//// (the Merkle leaf preimage), the inclusion proof and the signed
//// checkpoint.
////
//// *Which* log that is, and which key its checkpoints are signed with, come
//// from the `trusted_root.json` this service ships in `priv/tuf` — the same
//// directory the client embeds. It is read at the moment of use rather than
//// at boot, so a deploy carrying a newer one takes effect on the next tick
//// (§10.3).

import envoy
import gleam/bit_array
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import rekor/proof
import simplifile

import tuf/trusted_root

/// What is submitted for one entry: the SHA-256 of the DSSE PAE, the DER
/// ECDSA signature over that PAE, and the signer's **certificate**.
///
/// A certificate rather than a raw key because Rekor copies it verbatim into
/// the Merkle leaf without validating any of it, which is the only way the
/// apex gets somewhere a monitor can see it (`rekor/cert`).
pub type Submission {
  Submission(digest: BitArray, signature: BitArray, certificate: BitArray)
}

/// Where the log put an entry — the parts of a `TransparencyLogEntry` a proof
/// carries. `canonicalized_body` is the leaf preimage, verbatim.
pub type Entry {
  Entry(
    log_index: Int,
    canonicalized_body: BitArray,
    checkpoint: BitArray,
    inclusion_path: List(BitArray),
    integrated_at: Int,
  )
}

pub type Log {
  Log(
    /// Adds the entry and waits for integration. Rekor v2 is content
    /// addressed by leaf, so re-submitting a byte-identical entry returns the
    /// same `logIndex` with a fresh proof — the idempotency `rekor-publish`
    /// relies on, so a republish refreshes rather than mints a second claim.
    submit: fn(Submission) -> Result(Entry, String),
  )
}

/// Where to submit, and the key whose signature on the returned checkpoint
/// this service will believe. The two travel together because they have to
/// agree: a proof stored against the wrong key is a proof the client refuses.
pub type Target {
  Target(url: String, key: #(BitArray, BitArray))
}

/// Discovers the log to write to from the stored TUF material (§10).
///
/// **Nothing about the public log is compiled in.** The `trusted_root.json`
/// this service fetches is a directory of transparency logs — where each is served, its key, and the window it was in service for
/// — so the shard to submit to is read from the same signed artifact the
/// client derives its pins from, at the moment of use. Sigstore opening the
/// next shard is then a TUF refresh on both sides, not a release on either.
///
/// Two escape hatches, and both are all-or-nothing on purpose:
///
/// - `CP_REKOR_URL` redirects the endpoint. If the trusted root names that
///   URL, its key comes along; otherwise `CP_REKOR_KEY` must name one,
///   because a key that cannot be named is a proof that cannot be checked.
/// - `CP_REKOR_KEY` replaces the key entirely — the self-hosted or simulated
///   log case, where no trusted root has anything to say.
///
/// With neither set, the answer comes from the trusted root this build ships
/// (`tuf/trusted_root.shipped`). If that names no shard whose window contains
/// now — Sigstore has rotated and this image has not been redeployed — this
/// fails saying so rather than guessing a hostname.
pub fn discover(now: Int) -> Result(Target, String) {
  let override_url = envoy.get("CP_REKOR_URL") |> option.from_result
  use override_key <- result.try(case envoy.get("CP_REKOR_KEY") {
    Error(Nil) -> Ok(None)
    Ok(path) -> read_key(path) |> result.map(Some)
  })
  case override_url, override_key {
    // Fully configured: an operator naming both is describing a log this
    // service has no other way to know about, so nothing else is consulted.
    Some(url), Some(key) -> Ok(Target(trusted_root.strip_slash(url), key))
    _, _ -> {
      use logs <- result.try(shipped_tlogs())
      use log <- result.try(case override_url {
        Some(url) -> trusted_root.for_url(logs, url)
        None -> trusted_root.current(logs, now)
      })
      let key = case override_key {
        Some(key) -> key
        None -> #(log.spki, log.point)
      }
      Ok(Target(log.base_url, key))
    }
  }
}

/// The logs the shipped `trusted_root.json` names.
fn shipped_tlogs() -> Result(List(trusted_root.Tlog), String) {
  use bytes <- result.try(trusted_root.shipped())
  trusted_root.tlogs(bytes)
}

/// Reads a pinned log key file (`CP_REKOR_KEY`): the DER
/// SubjectPublicKeyInfo and the raw point, since a checkpoint check needs
/// one and the log id the other.
fn read_key(path: String) -> Result(#(BitArray, BitArray), String) {
  use text <- result.try(
    simplifile.read(path)
    |> result.map_error(fn(e) {
      "reading " <> path <> ": " <> simplifile.describe_error(e)
    }),
  )
  proof.parse_log_key(text)
  |> result.map_error(fn(e) { path <> ": " <> string_of(e) })
}

fn string_of(error: proof.ProofError) -> String {
  case error {
    proof.Malformed(why) -> why
    proof.Attribution(why) -> why
    proof.Binding(why) -> why
    proof.Inclusion(why) -> why
    proof.CheckpointFailed(why) -> why
    proof.UnknownLog(why) -> why
  }
}

/// The HTTP log at `base` — `POST <base>/api/v2/log/entries`.
///
/// The request is a protojson `CreateEntryRequest`; the response, on 200 or
/// 201, is a `TransparencyLogEntry` this parses down to the parts a proof
/// carries. The submitted entry's integrity is not trusted from the
/// transport: `rekor/publish` re-verifies the returned body, inclusion and
/// checkpoint before anything is stored.
pub fn http(base: String) -> Log {
  Log(submit: fn(sub: Submission) { submit_http(base, sub) })
}

fn submit_http(base: String, sub: Submission) -> Result(Entry, String) {
  // The same normalization `resolve` applies at the other end (:110), so a
  // configured URL and a stored one agree: this is the key `for_url` matches
  // a log's pinned key on, and it strips *every* trailing slash, not one.
  let endpoint = trusted_root.strip_slash(base) <> "/api/v2/log/entries"
  let body =
    json.object([
      #(
        "hashedRekordRequestV002",
        json.object([
          #("digest", json.string(b64(sub.digest))),
          #(
            "signature",
            json.object([
              #("content", json.string(b64(sub.signature))),
              #(
                "verifier",
                json.object([
                  #(
                    "x509Certificate",
                    json.object([
                      #("rawBytes", json.string(b64(sub.certificate))),
                    ]),
                  ),
                  #("keyDetails", json.string("PKIX_ECDSA_P256_SHA_256")),
                ]),
              ),
            ]),
          ),
        ]),
      ),
    ])
    |> json.to_string
  use req <- result.try(
    request.to(endpoint)
    |> result.replace_error("bad Rekor URL " <> endpoint),
  )
  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/json")
    |> request.set_header("accept", "application/json")
    |> request.set_body(body)
  use resp <- result.try(
    httpc.send(req)
    |> result.map_error(fn(e) {
      endpoint <> " unreachable: " <> string.inspect(e)
    }),
  )
  case resp.status {
    200 | 201 -> parse_entry(resp.body)
    status ->
      Error(
        endpoint
        <> " answered "
        <> int.to_string(status)
        <> ": "
        <> string.slice(resp.body, 0, 200),
      )
  }
}

/// Parses a `TransparencyLogEntry` into the parts a proof carries.
///
/// The strings arrive base64 and the indices as decimal strings (protojson
/// renders 64-bit integers as strings); this decodes the shape and then
/// converts, so a malformed field is a parse error, not a crash. Public
/// because it is the whole of what this module decides about a log's answer,
/// and the suite drives it directly rather than through HTTP.
pub fn parse_entry(body: String) -> Result(Entry, String) {
  let decoder = {
    use log_index <- decode.field("logIndex", decode.string)
    use canonicalized_body <- decode.field("canonicalizedBody", decode.string)
    use integrated <- decode.optional_field(
      "integratedTime",
      "0",
      decode.string,
    )
    use hashes <- decode.subfield(
      ["inclusionProof", "hashes"],
      decode.list(decode.string),
    )
    use envelope <- decode.subfield(
      ["inclusionProof", "checkpoint", "envelope"],
      decode.string,
    )
    decode.success(#(
      log_index,
      canonicalized_body,
      integrated,
      hashes,
      envelope,
    ))
  }
  use #(log_index, body_b64, integrated, hashes, envelope) <- result.try(
    json.parse(body, decoder)
    |> result.replace_error("the log response is not a TransparencyLogEntry"),
  )
  use log_index <- result.try(
    int.parse(log_index)
    |> result.replace_error("logIndex " <> log_index <> " is not a number"),
  )
  use canonicalized_body <- result.try(
    bit_array.base64_decode(body_b64)
    |> result.replace_error("canonicalizedBody is not base64"),
  )
  // Each hash is a 32-byte SHA-256 node. Checked here because the proof
  // format stores the path as a flat run of 32-byte hashes: a short one would
  // be silently re-split at the wrong boundary on the way back out, so the
  // one place to refuse it is where it arrives.
  use inclusion_path <- result.try(
    list.try_map(hashes, fn(h) {
      case bit_array.base64_decode(h) {
        Error(Nil) -> Error("an inclusion-proof hash is not base64")
        Ok(hash) ->
          case bit_array.byte_size(hash) == 32 {
            True -> Ok(hash)
            False ->
              Error(
                "an inclusion-proof hash is "
                <> int.to_string(bit_array.byte_size(hash))
                <> " bytes, not a 32-byte SHA-256 node",
              )
          }
      }
    }),
  )
  let integrated_at = result.unwrap(int.parse(integrated), 0)
  Ok(Entry(
    log_index: log_index,
    canonicalized_body: canonicalized_body,
    checkpoint: <<envelope:utf8>>,
    inclusion_path: inclusion_path,
    integrated_at: integrated_at,
  ))
}

/// Standard padded base64, the encoding a Rekor `CreateEntryRequest` carries.
fn b64(bytes: BitArray) -> String {
  bit_array.base64_encode(bytes, True)
}
