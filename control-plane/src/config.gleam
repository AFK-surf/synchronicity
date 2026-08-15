//// Boot configuration from the environment. Missing required
//// configuration names itself and refuses to start — no defaults for
//// anything that changes what the service *is*.

import envoy
import gleam/int
import gleam/list
import gleam/result
import gleam/string

pub type Role {
  Primary
  Replica
}

pub type Config {
  Config(
    role: Role,
    /// The zone apex, e.g. "sync.example.dev" (no trailing dot).
    base_domain: String,
    db_path: String,
    /// Primary only; replicas must not have key material.
    key_file: String,
    http_port: Int,
    dns_port: Int,
    /// (hostname, ipv4, ipv6) — hostname relative to apex unless dotted.
    ns_hosts: List(#(String, String, String)),
    public_url: String,
  )
}

pub fn load() -> Result(Config, String) {
  use role <- result.try(case envoy.get("CP_ROLE") {
    Ok("primary") -> Ok(Primary)
    Ok("replica") -> Ok(Replica)
    Ok(other) -> Error("CP_ROLE must be primary or replica, got " <> other)
    Error(Nil) -> Error("CP_ROLE is required (primary | replica)")
  })
  use base_domain <- result.try(required("CP_BASE_DOMAIN"))
  use db_path <- result.try(required("CP_DB_PATH"))
  use key_file <- result.try(case role {
    Primary -> required("CP_KEY_FILE")
    Replica ->
      case envoy.get("CP_KEY_FILE") {
        Ok(_) -> Error("CP_KEY_FILE must NOT be set on a replica")
        Error(Nil) -> Ok("")
      }
  })
  use http_port <- result.try(port_from("CP_HTTP_PORT", 8080))
  use dns_port <- result.try(port_from("CP_DNS_PORT", 53))
  use ns_hosts <- result.try(ns_hosts())
  let public_url =
    envoy.get("CP_PUBLIC_URL")
    |> result.unwrap("http://127.0.0.1:" <> int.to_string(http_port))
  Ok(Config(
    role,
    base_domain,
    db_path,
    key_file,
    http_port,
    dns_port,
    ns_hosts,
    public_url,
  ))
}

fn required(key: String) -> Result(String, String) {
  envoy.get(key) |> result.replace_error(key <> " is required")
}

fn port_from(key: String, default: Int) -> Result(Int, String) {
  case envoy.get(key) {
    Error(Nil) -> Ok(default)
    Ok(text) ->
      int.parse(text) |> result.replace_error(key <> " must be a port number")
  }
}

/// CP_NS_HOSTS: semicolon-separated `host=ipv4[,ipv6]` entries, e.g.
/// "ns1=192.0.2.1;ns2=192.0.2.53,2001:db8::53". Hostnames without dots
/// are relative to the base domain. Required on the primary — a zone
/// without NS records is not a zone.
fn ns_hosts() -> Result(List(#(String, String, String)), String) {
  case envoy.get("CP_NS_HOSTS") {
    Error(Nil) -> Ok([])
    Ok(text) ->
      text
      |> string.split(";")
      |> list.filter(fn(entry) { entry != "" })
      |> list.try_map(fn(entry) {
        case string.split_once(entry, "=") {
          Ok(#(host, addresses)) ->
            case string.split(addresses, ",") {
              [ipv4] -> Ok(#(host, ipv4, ""))
              [ipv4, ipv6] -> Ok(#(host, ipv4, ipv6))
              _ -> Error("CP_NS_HOSTS entry not host=ipv4[,ipv6]: " <> entry)
            }
          Error(Nil) -> Ok(#(entry, "", ""))
        }
      })
  }
}
