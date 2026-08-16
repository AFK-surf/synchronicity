//// The Cloudflare leg: the reference provider
//// (docs/EXTERNAL-DNS-PROVIDER.md §6).
////
//// v4 REST, one Bearer token — scopable to Zone:DNS:Edit on one zone, and
//// the runbook says to scope it. The zone id is taken from configuration
//// or discovered once by name at connect time; the per-record ids
//// Cloudflare assigns ride in `Existing.id` and drive updates and deletes.
////
//// TXT normalization: Cloudflare's API returns TXT content in
//// presentation form — quoted, and split into quoted 255-byte
//// character-strings when long. The values this deployment compares are
//// the unquoted, concatenated strings, so `unquote_txt` folds the
//// presentation back down on the way in and content is sent unquoted on
//// the way out (Cloudflare chunks it server-side).

import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import provider/provider.{
  type Existing, type Provider, Existing, Provider, Record,
}

const real_api = "https://api.cloudflare.com/client/v4"

/// Builds the leg, discovering the zone id by name when none is
/// configured. `api_url` empty means the real endpoint; the e2e stub and
/// the tests override it, exactly as `CP_REKOR_URL` overrides the log.
pub fn connect(
  api_token: String,
  zone_id: String,
  api_url: String,
  apex: String,
) -> Result(Provider, String) {
  let base = case api_url {
    "" -> real_api
    url -> strip_slash(url)
  }
  use zone_id <- result.try(case zone_id {
    "" -> discover_zone(base, api_token, apex)
    id -> Ok(id)
  })
  Ok(Provider(
    list: fn(names) { list_records(base, api_token, zone_id, names) },
    apply: fn(changes) { apply_changes(base, api_token, zone_id, changes) },
    describe: "cloudflare zone " <> zone_id,
  ))
}

fn discover_zone(
  base: String,
  token: String,
  apex: String,
) -> Result(String, String) {
  let decoder = {
    use ids <- decode.subfield(
      ["result"],
      decode.list({
        use id <- decode.field("id", decode.string)
        decode.success(id)
      }),
    )
    decode.success(ids)
  }
  use ids <- result.try(get_json(base <> "/zones?name=" <> apex, token, decoder))
  case ids {
    [id] -> Ok(id)
    [] -> Error("cloudflare has no zone named " <> apex)
    _ -> Error("cloudflare has more than one zone named " <> apex)
  }
}

fn list_records(
  base: String,
  token: String,
  zone_id: String,
  names: List(String),
) -> Result(List(Existing), String) {
  // One request per managed name. The managed set is a handful of names
  // and the filter keeps every response small and unpaginated in practice;
  // per_page=100 covers a rollover-window's worth of member records under
  // one owner with room to spare.
  names
  |> list.try_map(fn(name) {
    let decoder = {
      use records <- decode.subfield(
        ["result"],
        decode.list({
          use id <- decode.field("id", decode.string)
          use rtype <- decode.field("type", decode.string)
          use record_name <- decode.field("name", decode.string)
          use content <- decode.field("content", decode.string)
          use ttl <- decode.field("ttl", decode.int)
          decode.success(#(id, rtype, record_name, content, ttl))
        }),
      )
      decode.success(records)
    }
    use rows <- result.try(get_json(
      base <> "/zones/" <> zone_id <> "/dns_records?per_page=100&name=" <> name,
      token,
      decoder,
    ))
    rows
    |> list.filter(fn(row) { row.1 == "TXT" })
    |> list.map(fn(row) {
      let #(id, _, record_name, content, ttl) = row
      Existing(id, Record(record_name, provider.Txt, ttl, unquote_txt(content)))
    })
    |> Ok
  })
  |> result.map(list.flatten)
}

fn apply_changes(
  base: String,
  token: String,
  zone_id: String,
  changes: provider.Changes,
) -> Result(Nil, String) {
  let records = base <> "/zones/" <> zone_id <> "/dns_records"
  use Nil <- result.try(
    changes.create
    |> list.try_each(fn(record) {
      send_json(http.Post, records, token, record_body(record))
    }),
  )
  use Nil <- result.try(
    changes.replace
    |> list.try_each(fn(pair) {
      let #(existing, record) = pair
      send_json(
        http.Put,
        records <> "/" <> existing.id,
        token,
        record_body(record),
      )
    }),
  )
  changes.delete
  |> list.try_each(fn(existing) {
    send_json(http.Delete, records <> "/" <> existing.id, token, "")
  })
}

fn record_body(record: provider.Record) -> String {
  json.to_string(
    json.object([
      #("type", json.string("TXT")),
      #("name", json.string(record.name)),
      #("content", json.string(record.value)),
      #("ttl", json.int(record.ttl)),
      // Meaningless for TXT, pinned anyway as a matter of policy: nothing
      // this leg writes is ever proxied.
      #("proxied", json.bool(False)),
    ]),
  )
}

/// Folds Cloudflare's TXT presentation form — `"chunk" "chunk"` — back to
/// the raw value. Content that never had quotes passes through untouched.
pub fn unquote_txt(content: String) -> String {
  case string.starts_with(content, "\"") {
    False -> content
    True ->
      content
      |> string.split("\"")
      |> list.index_map(fn(part, index) { #(index, part) })
      // Split on quotes: odd indexes are the quoted chunks, even indexes
      // the whitespace between them.
      |> list.filter_map(fn(pair) {
        case pair.0 % 2 == 1 {
          True -> Ok(pair.1)
          False -> Error(Nil)
        }
      })
      |> string.join("")
      |> string.replace("\\\"", "\"")
  }
}

// ------------------------------------------------------------------ HTTP

fn get_json(
  url: String,
  token: String,
  decoder: decode.Decoder(a),
) -> Result(a, String) {
  use req <- result.try(
    request.to(url) |> result.replace_error("bad cloudflare URL " <> url),
  )
  let req =
    req
    |> request.set_header("authorization", "Bearer " <> token)
    |> request.set_header("accept", "application/json")
  use resp <- result.try(
    httpc.send(req)
    |> result.map_error(fn(e) { url <> " unreachable: " <> string.inspect(e) }),
  )
  use Nil <- result.try(check_status(url, resp.status))
  json.parse(resp.body, decoder)
  |> result.replace_error(url <> " answered a shape this leg cannot read")
}

fn send_json(
  method: http.Method,
  url: String,
  token: String,
  body: String,
) -> Result(Nil, String) {
  use req <- result.try(
    request.to(url) |> result.replace_error("bad cloudflare URL " <> url),
  )
  let req =
    req
    |> request.set_method(method)
    |> request.set_header("authorization", "Bearer " <> token)
    |> request.set_header("content-type", "application/json")
    |> request.set_body(body)
  use resp <- result.try(
    httpc.send(req)
    |> result.map_error(fn(e) { url <> " unreachable: " <> string.inspect(e) }),
  )
  check_status(url, resp.status)
}

fn check_status(url: String, status: Int) -> Result(Nil, String) {
  case status >= 200 && status < 300 {
    True -> Ok(Nil)
    False -> Error(url <> " answered " <> int.to_string(status))
  }
}

fn strip_slash(url: String) -> String {
  case string.ends_with(url, "/") {
    True -> string.drop_end(url, 1)
    False -> url
  }
}
