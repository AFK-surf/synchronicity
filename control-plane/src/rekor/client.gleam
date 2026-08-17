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

import envoy
import gleam/bit_array
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import rekor/proof
import simplifile

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

/// The log write endpoint (`CP_REKOR_URL`).
pub fn url() -> String {
  envoy.get("CP_REKOR_URL")
  |> result.unwrap("https://log2025-1.rekor.sigstore.dev")
}

/// The verification key of the default log at [`url`]:
/// log2025-1.rekor.sigstore.dev's Ed25519 key, snapshotted from Sigstore's
/// TUF `trusted_root.json` — the same snapshot the client embeds (see
/// EMBEDDED_LOG_KEYS in crates/synch-net/src/rekor.rs, which carries the
/// provenance note). One key, not the client's whole set: this side submits
/// to one log and must verify what that log returns.
const embedded_log_key = "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244="

/// The pinned log verification key (`CP_REKOR_KEY`): the DER
/// SubjectPublicKeyInfo and the raw point.
///
/// Unset, it is the embedded key for the default public log. Set, the file
/// replaces it entirely — an operator who redirects `CP_REKOR_URL` names
/// the matching key here, because a key that cannot be named is a proof
/// that cannot be checked, and storing an unchecked proof would hand the
/// client something it will refuse.
pub fn log_key() -> Result(#(BitArray, BitArray), String) {
  case envoy.get("CP_REKOR_KEY") {
    Error(Nil) ->
      proof.parse_log_key(embedded_log_key)
      |> result.map_error(fn(e) { "embedded log key: " <> string_of(e) })
    Ok(path) -> {
      use text <- result.try(
        simplifile.read(path)
        |> result.map_error(fn(e) {
          "reading " <> path <> ": " <> simplifile.describe_error(e)
        }),
      )
      proof.parse_log_key(text)
      |> result.map_error(fn(e) { path <> ": " <> string_of(e) })
    }
  }
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
  let endpoint = strip_slash(base) <> "/api/v2/log/entries"
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
/// converts, so a malformed field is a parse error, not a crash.
fn parse_entry(body: String) -> Result(Entry, String) {
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
  use inclusion_path <- result.try(
    list.try_map(hashes, fn(h) {
      bit_array.base64_decode(h)
      |> result.replace_error("an inclusion-proof hash is not base64")
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

fn strip_slash(base: String) -> String {
  case string.ends_with(base, "/") {
    True -> string.drop_end(base, 1)
    False -> base
  }
}
