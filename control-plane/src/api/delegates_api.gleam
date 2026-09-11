//// Thin authenticated routing to the hosted member's delegation operations.
//// State and validation belong to the data plane and existing signed records.

import api/browse_api.{type Browse}
import api/cloud_writer
import api/common
import api/middleware
import api/reads.{type Reads}
import auth/principal.{type Principal}
import gleam/dynamic/decode
import gleam/json
import gleam/result
import store/pool
import store/sqlite.{Int, Text}
import wisp.{type Request, type Response}

pub fn put(
  req: Request,
  reads: Reads,
  browse: Browse,
  who: Principal,
  slug: String,
  net: String,
  key: String,
) -> Response {
  let decoder = {
    use spaces <- decode.field("spaces", decode.list(decode.string))
    use expires <- decode.field("expires_at", decode.int)
    decode.success(#(spaces, expires))
  }
  use #(spaces, expires) <- common.body_decoder(req, decoder)
  mutate(
    reads,
    browse,
    who,
    slug,
    net,
    json.object([
      #("action", json.string("put")),
      #("key", json.string(key)),
      #("spaces", json.array(spaces, json.string)),
      #("expires_at", json.int(expires)),
    ]),
  )
}

pub fn delete(
  reads: Reads,
  browse: Browse,
  who: Principal,
  slug: String,
  net: String,
  key: String,
) -> Response {
  mutate(
    reads,
    browse,
    who,
    slug,
    net,
    json.object([
      #("action", json.string("delete")),
      #("key", json.string(key)),
    ]),
  )
}

fn mutate(
  reads: Reads,
  browse: Browse,
  who: Principal,
  slug: String,
  net: String,
  mutation: json.Json,
) -> Response {
  // Return the connection before any network wait, including a one-slot pool.
  let target =
    pool.with_connection(reads.pool, fn(conn) {
      use #(org, _) <- result.try(common.check_org(
        conn,
        slug,
        who,
        common.Member,
      ))
      case
        sqlite.query(
          conn,
          "SELECT id, cloud_hosted FROM networks WHERE org_id = ? AND name = ?",
          [Text(org), Text(net)],
        )
      {
        Ok([[Text(id), Int(1)]]) -> Ok(id)
        Ok([[_, Int(0)]]) ->
          Error(middleware.error_json(
            409,
            "hosting_disabled",
            "cloud hosting is not enabled",
          ))
        Ok(_) -> Error(wisp.not_found())
        Error(_) -> Error(common.db_error())
      }
    })
  case target {
    Error(_) -> common.db_error()
    Ok(Error(response)) -> response
    Ok(Ok(network_id)) -> {
      let registry = browse_api.writers(browse)
      // Bound anonymous-to-the-tunnel pressure per network, not per device key.
      let holder = "delegates:" <> network_id
      case cloud_writer.claim_slot(registry, holder) {
        False ->
          middleware.error_json(429, "busy", "too many delegation requests")
        True -> {
          let response = case
            cloud_writer.pick(cloud_writer.sessions_for(registry, network_id))
          {
            Error(_) ->
              middleware.error_json(
                503,
                "unavailable",
                "no hosted writer attached",
              )
            Ok(session) ->
              case cloud_writer.mutate_delegate(session, mutation) {
                cloud_writer.Delegated ->
                  common.ok_json(
                    json.object([
                      #("ok", json.bool(True)),
                      #("issuer", json.string(session.origin)),
                    ]),
                  )
                cloud_writer.Failed(code, message) ->
                  middleware.error_json(
                    case code {
                      "invalid" -> 400
                      "unsupported" -> 409
                      _ -> 503
                    },
                    code,
                    message,
                  )
                _ ->
                  middleware.error_json(
                    502,
                    "invalid_response",
                    "unexpected hosted writer response",
                  )
              }
          }
          cloud_writer.release_slot(registry, holder)
          response
        }
      }
    }
  }
}
