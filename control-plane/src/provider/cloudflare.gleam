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
    list: fn() { list_records(base, api_token, zone_id, apex) },
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

const per_page = 100

/// Cloudflare paginates and this leg walks every page, so a zone that holds
/// the apex among a great many other names still lists completely. The cap
/// is a runaway guard, not a policy: a zone with more than this many TXT
/// records is a zone this leg has misunderstood, and saying so beats
/// looping.
const max_pages = 50

fn list_records(
  base: String,
  token: String,
  zone_id: String,
  apex: String,
) -> Result(List(Existing), String) {
  // Every TXT record strictly below the apex — the whole scope, in one
  // structural rule, so a name the renderer has stopped producing is still
  // found and removed. Filtering server-side by type keeps the pages small;
  // the suffix is applied here because not every provider offers it.
  list_page(base, token, zone_id, apex, 1, [])
}

fn list_page(
  base: String,
  token: String,
  zone_id: String,
  apex: String,
  page: Int,
  acc: List(Existing),
) -> Result(List(Existing), String) {
  use <- page_guard(page, zone_id)
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
    base
      <> "/zones/"
      <> zone_id
      <> "/dns_records?type=TXT&per_page="
      <> int.to_string(per_page)
      <> "&page="
      <> int.to_string(page),
    token,
    decoder,
  ))
  let kept =
    rows
    |> list.filter(fn(row) { row.1 == "TXT" && provider.below(row.2, apex) })
    |> list.map(fn(row) {
      let #(id, _, record_name, content, ttl) = row
      Existing(id, Record(record_name, provider.Txt, ttl, unquote_txt(content)))
    })
  let acc = list.append(acc, kept)
  case list.length(rows) < per_page {
    True -> Ok(acc)
    False -> list_page(base, token, zone_id, apex, page + 1, acc)
  }
}

fn page_guard(
  page: Int,
  zone_id: String,
  next: fn() -> Result(List(Existing), String),
) -> Result(List(Existing), String) {
  case page > max_pages {
    True ->
      Error(
        "cloudflare zone "
        <> zone_id
        <> " has more than "
        <> int.to_string(max_pages * per_page)
        <> " TXT records; refusing to keep paging",
      )
    False -> next()
  }
}

/// Creates, then replaces, then deletes — and every one of them attempted.
///
/// The order matters in one direction: creating before deleting means a
/// proof's old and new parts briefly coexist, which a client handles by
/// trying each proof it can reassemble, where deleting first would expose a
/// window in which the zone serves an incomplete one.
///
/// Nothing aborts. A record the API refuses is reported by name and the rest
/// of the change set still goes out, because the alternative is one
/// oversized proof record holding back every membership change behind it.
fn apply_changes(
  base: String,
  token: String,
  zone_id: String,
  changes: provider.Changes,
) -> Result(provider.Applied, String) {
  let records = base <> "/zones/" <> zone_id <> "/dns_records"
  let created =
    changes.create
    |> list.map(fn(record) {
      #(record.name, send_json(http.Post, records, token, record_body(record)))
    })
  let replaced =
    changes.replace
    |> list.map(fn(pair) {
      let #(existing, record) = pair
      #(
        record.name,
        send_json(
          http.Put,
          records <> "/" <> existing.id,
          token,
          record_body(record),
        ),
      )
    })
  let deleted =
    changes.delete
    |> list.map(fn(existing) {
      #(
        existing.record.name,
        send_json(http.Delete, records <> "/" <> existing.id, token, ""),
      )
    })
  Ok(provider.tally(list.flatten([created, replaced, deleted])))
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
  check_body(url, resp.status, resp.body)
}

fn check_status(url: String, status: Int) -> Result(Nil, String) {
  check_body(url, status, "")
}

/// A refusal carries the provider's own words.
///
/// Cloudflare answers a rejected change with a JSON body naming the reason —
/// a record that is too long, a name outside the zone, a duplicate. Dropping
/// it left `provider-sync` reporting a bare "answered 400", which says only
/// that something is wrong and never what, and an operator then has to
/// reconstruct the request by hand to find out.
fn check_body(url: String, status: Int, body: String) -> Result(Nil, String) {
  case status >= 200 && status < 300 {
    True -> Ok(Nil)
    False ->
      Error(
        url
        <> " answered "
        <> int.to_string(status)
        <> case body {
          "" -> ""
          text -> ": " <> string.slice(text, 0, 400)
        },
      )
  }
}

fn strip_slash(url: String) -> String {
  case string.ends_with(url, "/") {
    True -> string.drop_end(url, 1)
    False -> url
  }
}
