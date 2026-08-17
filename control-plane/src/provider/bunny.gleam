//// The Bunny leg (docs/EXTERNAL-DNS-PROVIDER.md §6).
////
//// Simple `AccessKey`-header API: one GET returns the whole zone with its
//// records, adds are PUT, updates POST, deletes DELETE, all by numeric
//// record id. Two impedance points this leg absorbs:
////
////   - names are **relative** to the zone in Bunny's model (`""` for the
////     apex itself), so the leg converts against the apex both ways and
////     the rest of the reconciler only ever sees fully qualified names;
////   - record types are numeric — TXT is 3 — and everything else at a
////     managed name is simply not listed, which the diff reads as foreign
////     data and refuses to touch. Correct both ways: this leg never
////     deletes what it could not have created.
////
//// The caution the design states plainly: a Bunny API key is
//// account-scoped — its blast radius is every zone on the account — and
//// whether a Bunny-hosted zone can be DNSSEC-signed at all gates whether
//// external mode is *usable* there; the boot log says which zone this leg
//// found, and the delegation checklist in the design doc is what verifies
//// the signing half.

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

const real_api = "https://api.bunny.net"

const txt_type = 3

/// Builds the leg, discovering the zone id by domain when none is
/// configured.
pub fn connect(
  api_key: String,
  zone_id: String,
  api_url: String,
  apex: String,
) -> Result(Provider, String) {
  let base = case api_url {
    "" -> real_api
    url -> strip_slash(url)
  }
  use zone_id <- result.try(case zone_id {
    "" -> discover_zone(base, api_key, apex)
    id -> Ok(id)
  })
  Ok(Provider(
    list: fn(names) { list_records(base, api_key, zone_id, apex, names) },
    apply: fn(changes) { apply_changes(base, api_key, zone_id, apex, changes) },
    describe: "bunny zone " <> zone_id,
  ))
}

fn discover_zone(
  base: String,
  key: String,
  apex: String,
) -> Result(String, String) {
  let decoder = {
    use items <- decode.subfield(
      ["Items"],
      decode.list({
        use id <- decode.field("Id", decode.int)
        use domain <- decode.field("Domain", decode.string)
        decode.success(#(id, domain))
      }),
    )
    decode.success(items)
  }
  use items <- result.try(get_json(
    base <> "/dnszone?search=" <> apex,
    key,
    decoder,
  ))
  case list.filter(items, fn(item) { item.1 == apex }) {
    [#(id, _)] -> Ok(int.to_string(id))
    [] -> Error("bunny has no zone named " <> apex)
    _ -> Error("bunny has more than one zone named " <> apex)
  }
}

fn list_records(
  base: String,
  key: String,
  zone_id: String,
  apex: String,
  names: List(String),
) -> Result(List(Existing), String) {
  let decoder = {
    use records <- decode.subfield(
      ["Records"],
      decode.list({
        use id <- decode.field("Id", decode.int)
        use rtype <- decode.field("Type", decode.int)
        use name <- decode.field("Name", decode.string)
        use value <- decode.field("Value", decode.string)
        use ttl <- decode.field("Ttl", decode.int)
        decode.success(#(id, rtype, name, value, ttl))
      }),
    )
    decode.success(records)
  }
  use rows <- result.try(get_json(base <> "/dnszone/" <> zone_id, key, decoder))
  rows
  |> list.filter(fn(row) { row.1 == txt_type })
  |> list.map(fn(row) {
    let #(id, _, name, value, ttl) = row
    Existing(
      int.to_string(id),
      Record(qualify(name, apex), provider.Txt, ttl, value),
    )
  })
  // The whole zone came back; scope discipline is enforced here, so the
  // diff never sees — and so can never delete — a record outside the
  // managed set.
  |> list.filter(fn(existing) { list.contains(names, existing.record.name) })
  |> Ok
}

fn apply_changes(
  base: String,
  key: String,
  zone_id: String,
  apex: String,
  changes: provider.Changes,
) -> Result(Nil, String) {
  let records = base <> "/dnszone/" <> zone_id <> "/records"
  use Nil <- result.try(
    changes.create
    |> list.try_each(fn(record) {
      send_json(http.Put, records, key, record_body(record, apex))
    }),
  )
  use Nil <- result.try(
    changes.replace
    |> list.try_each(fn(pair) {
      let #(existing, record) = pair
      send_json(
        http.Post,
        records <> "/" <> existing.id,
        key,
        record_body(record, apex),
      )
    }),
  )
  changes.delete
  |> list.try_each(fn(existing) {
    send_json(http.Delete, records <> "/" <> existing.id, key, "")
  })
}

fn record_body(record: provider.Record, apex: String) -> String {
  json.to_string(
    json.object([
      #("Type", json.int(txt_type)),
      #("Name", json.string(relativize(record.name, apex))),
      #("Value", json.string(record.value)),
      #("Ttl", json.int(record.ttl)),
    ]),
  )
}

/// Bunny's relative name for a fully qualified one: `""` at the apex.
pub fn relativize(name: String, apex: String) -> String {
  case name == apex {
    True -> ""
    False ->
      case string.ends_with(name, "." <> apex) {
        True -> string.drop_end(name, string.length(apex) + 1)
        False -> name
      }
  }
}

/// And back.
pub fn qualify(name: String, apex: String) -> String {
  case name {
    "" -> apex
    _ -> name <> "." <> apex
  }
}

// ------------------------------------------------------------------ HTTP

fn get_json(
  url: String,
  key: String,
  decoder: decode.Decoder(a),
) -> Result(a, String) {
  use req <- result.try(
    request.to(url) |> result.replace_error("bad bunny URL " <> url),
  )
  let req =
    req
    |> request.set_header("accesskey", key)
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
  key: String,
  body: String,
) -> Result(Nil, String) {
  use req <- result.try(
    request.to(url) |> result.replace_error("bad bunny URL " <> url),
  )
  let req =
    req
    |> request.set_method(method)
    |> request.set_header("accesskey", key)
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
